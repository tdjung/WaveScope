"""Signal candidate scanner: suggest likely PC and clock signals in a waveform.

Real SoC waveforms contain thousands of signals and the core-internal PC
is rarely something the user knows by name.  This module streams the
waveform once, gathers cheap statistics per signal, and ranks candidates.

PC scoring (weights sum to 1.0):
  0.55  text-ratio : fraction of sampled values inside the ELF's
                     executable sections (strongest; requires --elf)
  0.20  stride     : fraction of consecutive deltas equal to insn sizes
  0.15  name       : "pc" token, or fetch/commit/retire/instr/addr hints
  0.10  width      : 32- or 64-bit vector

Clock scoring: 1-bit signals ranked by toggle count x period regularity
x name hints (clk/clock).

Diagnostics: ScanResult keeps per-signal raw stats and global parse
counters so `wavescope signals` / `scan --explain` can show exactly why
a signal was or wasn't picked.
"""

import re
from typing import Dict, List, Optional, Tuple

from .vcd_reader import VcdSignal, open_vcd_text, read_header

_NAME_PC_STRONG = ("pc",)
_NAME_PC_WEAK = ("epc", "iaddr", "instaddr", "instr", "inst", "fetch",
                 "commit", "retire", "wb", "addr")
_NAME_CLK = ("clk", "clock", "ck")

MAX_TRACKED_VALUES = 4096
DEFAULT_MAX_CHANGES = 2_000_000
MIN_CHANGES = 8
SCORE_FLOOR = 0.05


class SigStats(object):
    __slots__ = ("sig", "changes", "bad_lines", "prev_int", "stride_hits",
                 "stride_total", "text_hits", "text_total", "distinct",
                 "first_values", "last_value", "last_time", "deltas")

    def __init__(self, sig):
        self.sig = sig
        self.changes = 0
        self.bad_lines = 0           # x/z or unparseable values
        self.prev_int = None
        self.stride_hits = 0
        self.stride_total = 0
        self.text_hits = 0
        self.text_total = 0
        self.distinct = set()
        self.first_values = []
        self.last_value = None
        # clock-specific
        self.last_time = None
        self.deltas = {}


class Candidate(object):
    __slots__ = ("name", "width", "score", "reasons")

    def __init__(self, name, width, score, reasons):
        self.name = name
        self.width = width
        self.score = score
        self.reasons = reasons

    def to_dict(self) -> dict:
        return {"name": self.name, "width": self.width,
                "score": round(self.score, 4), "reasons": self.reasons}


class ParseStats(object):
    __slots__ = ("n_signals", "n_vector_tracked", "n_scalar_tracked",
                 "value_lines_seen", "value_lines_matched",
                 "budget_exhausted")

    def __init__(self):
        self.n_signals = 0
        self.n_vector_tracked = 0
        self.n_scalar_tracked = 0
        self.value_lines_seen = 0
        self.value_lines_matched = 0
        self.budget_exhausted = False


class ScanResult(object):
    __slots__ = ("pc_candidates", "clock_candidates", "epc_candidates",
                 "vec_stats", "clk_stats", "parse")

    def __init__(self, pc_candidates, clock_candidates, vec_stats,
                 clk_stats, parse, epc_candidates=None):
        self.pc_candidates = pc_candidates
        self.clock_candidates = clock_candidates
        self.epc_candidates = epc_candidates if epc_candidates is not None else []
        self.vec_stats = vec_stats       # signal full name -> stats
        self.clk_stats = clk_stats
        self.parse = parse

    def __iter__(self):                 # allows: pcs, clks = scan(...)
        yield self.pc_candidates
        yield self.clock_candidates


def _name_score_pc(name: str) -> Tuple[float, Optional[str]]:
    last = name.split(".")[-1].lower()
    toks = re.split(r"[^a-z0-9]+", last)
    if "pc" in toks or last.endswith("pc"):
        return 1.0, f"name contains 'pc' ({last})"
    for w in _NAME_PC_WEAK:
        if w in last:
            return 0.5, f"name hints '{w}' ({last})"
    return 0.0, None


def _name_score_clk(name: str) -> float:
    last = name.split(".")[-1].lower()
    return 1.0 if any(k in last for k in _NAME_CLK) else 0.0


def scan(vcd_path: str,
         text_ranges: Optional[List[Tuple[int, int]]] = None,
         top_n: int = 5,
         max_changes: int = DEFAULT_MAX_CHANGES,
         isa_strides: Tuple[int, ...] = (2, 4),
         min_width: int = 8,
         ) -> ScanResult:
    ps = ParseStats()
    with open_vcd_text(vcd_path) as f:
        signals, _ = read_header(f)
        ps.n_signals = len(signals)

        vec: Dict[str, SigStats] = {}
        clk: Dict[str, SigStats] = {}
        for s in signals:
            if s.width >= min_width:
                vec[s.ident] = SigStats(sig=s)
            elif s.width == 1:
                clk[s.ident] = SigStats(sig=s)
        ps.n_vector_tracked = len(vec)
        ps.n_scalar_tracked = len(clk)

        t = 0
        budget = max_changes

        def feed_vector(st: SigStats, v: Optional[int]) -> None:
            if v is None:
                st.bad_lines += 1
                return
            st.changes += 1
            if len(st.first_values) < 4:
                st.first_values.append(v)
            st.last_value = v
            if len(st.distinct) < MAX_TRACKED_VALUES:
                st.distinct.add(v)
            if st.prev_int is not None:
                st.stride_total += 1
                if (v - st.prev_int) in isa_strides:
                    st.stride_hits += 1
            st.prev_int = v
            if text_ranges is not None:
                st.text_total += 1
                for lo, hi in text_ranges:
                    if lo <= v < hi:
                        st.text_hits += 1
                        break

        for raw in f:
            line = raw.strip()
            if not line:
                continue
            c0 = line[0]
            if c0 == "#":
                try:
                    t = int(line[1:].split()[0])
                except (ValueError, IndexError):
                    pass
                continue
            if c0 in "bB":
                ps.value_lines_seen += 1
                parts = line.split()
                if len(parts) < 2:
                    continue
                st = vec.get(parts[1])
                if st is None:
                    continue
                ps.value_lines_matched += 1
                bits = parts[0][1:].lower()
                if "x" in bits or "z" in bits:
                    feed_vector(st, None)
                else:
                    try:
                        feed_vector(st, int(bits, 2))
                    except ValueError:
                        feed_vector(st, None)
            elif c0 in "rR":
                ps.value_lines_seen += 1
                parts = line.split()
                if len(parts) < 2:
                    continue
                st = vec.get(parts[1])
                if st is None:
                    continue
                ps.value_lines_matched += 1
                try:
                    feed_vector(st, int(float(parts[0][1:])))
                except (ValueError, OverflowError):
                    feed_vector(st, None)
            elif c0 in "01xXzZ":
                ps.value_lines_seen += 1
                st = clk.get(line[1:])
                if st is None:
                    continue
                ps.value_lines_matched += 1
                if c0 in "xXzZ":
                    st.bad_lines += 1
                    continue
                st.changes += 1
                if st.last_time is not None:
                    d = t - st.last_time
                    st.deltas[d] = st.deltas.get(d, 0) + 1
                    if len(st.deltas) > 64:
                        st.deltas.pop(min(st.deltas, key=st.deltas.get))
                st.last_time = t
            else:
                continue
            budget -= 1
            if budget <= 0:
                ps.budget_exhausted = True
                break

    pcs = _rank_pcs(vec, text_ranges, isa_strides)
    clks = _rank_clks(clk)
    epcs = _rank_epcs(vec, text_ranges)
    return ScanResult(pc_candidates=pcs[:top_n],
                      clock_candidates=clks[:top_n],
                      vec_stats={s.sig.name: s for s in vec.values()},
                      clk_stats={s.sig.name: s for s in clk.values()},
                      parse=ps, epc_candidates=epcs[:top_n])


def score_vector(st: SigStats,
                 have_elf: bool,
                 isa_strides: Tuple[int, ...]) -> Tuple[float, List[str]]:
    reasons: List[str] = []
    text_r = (st.text_hits / st.text_total) if (have_elf and st.text_total) else 0.0
    stride_r = (st.stride_hits / st.stride_total) if st.stride_total else 0.0
    name_s, why = _name_score_pc(st.sig.name)
    width_s = 1.0 if st.sig.width in (32, 64) else \
        (0.5 if 24 <= st.sig.width <= 64 else 0.0)

    if have_elf:
        score = 0.55 * text_r + 0.20 * stride_r + 0.15 * name_s + 0.10 * width_s
        if st.text_total:
            reasons.append(f"{text_r * 100:.0f}% of values in ELF text sections")
    else:
        score = 0.45 * stride_r + 0.35 * name_s + 0.20 * width_s
    if stride_r > 0.05:
        reasons.append(f"{stride_r * 100:.0f}% sequential strides "
                       f"(+{'/'.join(map(str, isa_strides))})")
    if why:
        reasons.append(why)
    reasons.append(f"width={st.sig.width}, {st.changes} changes, "
                   f"{len(st.distinct)}"
                   f"{'+' if len(st.distinct) >= MAX_TRACKED_VALUES else ''}"
                   f" distinct values")
    return score, reasons


def _rank_pcs(vec: Dict[str, SigStats],
              text_ranges: Optional[List[Tuple[int, int]]],
              isa_strides: Tuple[int, ...]) -> List[Candidate]:
    have_elf = text_ranges is not None
    out: List[Candidate] = []
    fallback: List[Candidate] = []
    for st in vec.values():
        if st.changes < MIN_CHANGES:
            continue
        score, reasons = score_vector(st, have_elf, isa_strides)
        c = Candidate(st.sig.name, st.sig.width, score, reasons)
        (out if score > SCORE_FLOOR else fallback).append(c)
    out.sort(key=lambda c: c.score, reverse=True)
    if not out:                     # nothing above floor: show best anyway
        fallback.sort(key=lambda c: c.score, reverse=True)
        return fallback
    return out


def _rank_epcs(vec: Dict[str, SigStats],
               text_ranges: Optional[List[Tuple[int, int]]]) -> List[Candidate]:
    """Rank likely exception-PC CSR signals (mepc/sepc/epc) for --epc.

    Unlike the PC itself an epc register changes RARELY (once per trap)
    and holds code addresses, so: name is required ('epc' token), text
    ratio dominates when an ELF is given, and the MIN_CHANGES gate is
    NOT applied (a run with a handful of interrupts is normal)."""
    out: List[Candidate] = []
    for st in vec.values():
        last = st.sig.name.split(".")[-1].lower()
        toks = re.split(r"[^a-z0-9]+", last)
        strong = any(t in ("mepc", "sepc", "uepc") for t in toks)
        weak = "epc" in toks or last.endswith("epc")
        if not (strong or weak):
            continue
        name_s = 1.0 if strong else 0.7
        text_r = (st.text_hits / st.text_total) \
            if (text_ranges is not None and st.text_total) else 0.0
        width_s = 1.0 if st.sig.width in (32, 64) else \
            (0.5 if 24 <= st.sig.width <= 64 else 0.0)
        if text_ranges is not None:
            score = 0.5 * text_r + 0.35 * name_s + 0.15 * width_s
        else:
            score = 0.7 * name_s + 0.3 * width_s
        reasons = [f"name hints exception PC ({last})"]
        if st.text_total:
            reasons.append(f"{text_r * 100:.0f}% of values in ELF text "
                           f"sections")
        reasons.append(f"width={st.sig.width}, {st.changes} changes "
                       f"(traps are rare: low counts are expected)")
        if st.changes == 0:
            reasons.append("never changed in this dump (no traps, or "
                           "value section not parsed)")
        out.append(Candidate(st.sig.name, st.sig.width, score, reasons))
    out.sort(key=lambda c: c.score, reverse=True)
    return out


def _rank_clks(clk: Dict[str, SigStats]) -> List[Candidate]:
    out: List[Candidate] = []
    max_toggles = max((s.changes for s in clk.values()), default=0) or 1
    for st in clk.values():
        if st.changes < MIN_CHANGES:
            continue
        total_d = sum(st.deltas.values())
        regular = (max(st.deltas.values()) / total_d) if total_d else 0.0
        toggle = st.changes / max_toggles
        name_s = _name_score_clk(st.sig.name)
        score = 0.4 * toggle + 0.4 * regular + 0.2 * name_s
        reasons = [f"{st.changes} toggles"]
        if regular > 0.5:
            reasons.append(f"{regular * 100:.0f}% regular period")
        if name_s:
            reasons.append("name hints clock")
        out.append(Candidate(st.sig.name, 1, score, reasons))
    out.sort(key=lambda c: c.score, reverse=True)
    return out


def explain(result: ScanResult, pattern: str,
            text_ranges: Optional[List[Tuple[int, int]]],
            isa_strides: Tuple[int, ...] = (2, 4)) -> str:
    """Human-readable breakdown of how `pattern`'s signal was scored."""
    pool = {**result.vec_stats, **result.clk_stats}
    matches = [n for n in pool
               if n == pattern or n.endswith("." + pattern) or pattern in n]
    if not matches:
        return (f"signal '{pattern}' not found among {len(pool)} parsed "
                f"signals.\nThe VCD header may use an unexpected $var "
                f"form -- run 'wavescope signals' to list what was parsed.")
    lines = []
    for name in matches[:5]:
        st = pool[name]
        lines.append(f"signal: {name}  (width={st.sig.width}, "
                     f"id='{st.sig.ident}')")
        lines.append(f"  value changes parsed : {st.changes}")
        lines.append(f"  unparseable/x/z lines: {st.bad_lines}")
        if st.changes == 0:
            lines.append("  -> no value changes were parsed for this signal.")
            lines.append("     Its value lines are probably in a format the "
                         "parser doesn't recognize;")
            lines.append("     please share a few raw lines: "
                         f"grep -m5 -F \" {st.sig.ident}\" <file>.vcd")
            continue
        if st.sig.width == 1:
            lines.append(f"  (1-bit signal: evaluated as clock candidate)")
            continue
        if st.first_values:
            fv = ", ".join(f"0x{v:x}" for v in st.first_values)
            lines.append(f"  first values         : {fv}")
        if st.last_value is not None:
            lines.append(f"  last value           : 0x{st.last_value:x}")
        if text_ranges is not None and st.text_total:
            r = st.text_hits / st.text_total
            lines.append(f"  in ELF text range    : {r * 100:.1f}% "
                         f"({st.text_hits}/{st.text_total})")
        if st.stride_total:
            r = st.stride_hits / st.stride_total
            lines.append(f"  sequential strides   : {r * 100:.1f}%")
        score, _ = score_vector(st, text_ranges is not None, isa_strides)
        lines.append(f"  final score          : {score:.3f} "
                     f"(floor {SCORE_FLOOR}, min changes {MIN_CHANGES})")
        if st.changes < MIN_CHANGES:
            lines.append(f"  -> EXCLUDED: fewer than {MIN_CHANGES} changes")
    return "\n".join(lines)
