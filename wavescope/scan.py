"""Signal candidate scanner: suggest likely PC and clock signals in a waveform.

Real SoC waveforms contain thousands of signals and the core-internal PC
is rarely something the user knows by name.  This module streams the
waveform once, gathers cheap statistics per signal, and ranks candidates.

PC scoring (weights sum to 1.0):
  0.55  text-ratio : fraction of sampled values inside the ELF's
                     executable sections (by far the strongest signal;
                     requires --elf, otherwise weight is redistributed)
  0.20  stride     : fraction of consecutive deltas equal to +2/+4
                     (sequential fetch pattern)
  0.15  name       : "pc" token, or fetch/commit/retire/instr/addr hints
  0.10  width      : 32- or 64-bit vector

Clock scoring: 1-bit signals ranked by toggle count x period regularity
x name hints (clk/clock).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .vcd_reader import VcdSignal, read_header

_NAME_PC_STRONG = ("pc",)
_NAME_PC_WEAK = ("epc", "iaddr", "instaddr", "instr", "inst", "fetch",
                 "commit", "retire", "wb", "addr")
_NAME_CLK = ("clk", "clock", "ck")

MAX_TRACKED_VALUES = 4096          # per-signal distinct-value cap
DEFAULT_MAX_CHANGES = 2_000_000    # global value-change budget


@dataclass
class SigStats:
    sig: VcdSignal
    changes: int = 0
    prev_int: Optional[int] = None
    stride_hits: int = 0
    stride_total: int = 0
    text_hits: int = 0
    text_total: int = 0
    distinct: set = field(default_factory=set)
    # clock-specific
    last_time: Optional[int] = None
    deltas: Dict[int, int] = field(default_factory=dict)


@dataclass
class Candidate:
    name: str
    width: int
    score: float
    reasons: List[str]

    def to_dict(self) -> dict:
        return {"name": self.name, "width": self.width,
                "score": round(self.score, 4), "reasons": self.reasons}


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
         ) -> Tuple[List[Candidate], List[Candidate]]:
    """Returns (pc_candidates, clock_candidates), best first."""

    with open(vcd_path, "r", errors="replace") as f:
        signals, _ = read_header(f)

        vec: Dict[str, SigStats] = {}
        clk: Dict[str, SigStats] = {}
        for s in signals:
            if s.width >= 16:
                vec[s.ident] = SigStats(sig=s)
            elif s.width == 1:
                clk[s.ident] = SigStats(sig=s)

        t = 0
        budget = max_changes
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            c0 = line[0]
            if c0 == "#":
                try:
                    t = int(line[1:])
                except ValueError:
                    pass
                continue
            if c0 in "bB":
                sp = line.find(" ")
                if sp < 0:
                    continue
                st = vec.get(line[sp + 1:])
                if st is None:
                    continue
                bits = line[1:sp].lower()
                if "x" in bits or "z" in bits:
                    continue
                try:
                    v = int(bits, 2)
                except ValueError:
                    continue
                st.changes += 1
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
            elif c0 in "01":
                st = clk.get(line[1:])
                if st is None:
                    continue
                st.changes += 1
                if st.last_time is not None:
                    d = t - st.last_time
                    st.deltas[d] = st.deltas.get(d, 0) + 1
                    if len(st.deltas) > 64:
                        st.deltas.pop(min(st.deltas, key=st.deltas.get))
                st.last_time = t
            budget -= 1
            if budget <= 0:
                break

    # ---- rank PC candidates ------------------------------------------
    pcs: List[Candidate] = []
    have_elf = text_ranges is not None
    for st in vec.values():
        if st.changes < 8:
            continue
        reasons: List[str] = []
        text_r = (st.text_hits / st.text_total) if (have_elf and st.text_total) else 0.0
        stride_r = (st.stride_hits / st.stride_total) if st.stride_total else 0.0
        name_s, why = _name_score_pc(st.sig.name)
        width_s = 1.0 if st.sig.width in (32, 64) else \
            (0.5 if 24 <= st.sig.width <= 64 else 0.0)

        if have_elf:
            score = 0.55 * text_r + 0.20 * stride_r + 0.15 * name_s + 0.10 * width_s
            if text_r > 0:
                reasons.append(f"{text_r * 100:.0f}% of values in ELF text sections")
        else:
            score = 0.45 * stride_r + 0.35 * name_s + 0.20 * width_s
        if stride_r > 0.05:
            reasons.append(f"{stride_r * 100:.0f}% sequential strides (+{'/'.join(map(str, isa_strides))})")
        if why:
            reasons.append(why)
        reasons.append(f"width={st.sig.width}, {st.changes} changes, "
                       f"{len(st.distinct)}{'+' if len(st.distinct) >= MAX_TRACKED_VALUES else ''} distinct values")
        if score > 0.05:
            pcs.append(Candidate(st.sig.name, st.sig.width, score, reasons))
    pcs.sort(key=lambda c: c.score, reverse=True)

    # ---- rank clock candidates ---------------------------------------
    clks: List[Candidate] = []
    max_toggles = max((s.changes for s in clk.values()), default=0) or 1
    for st in clk.values():
        if st.changes < 8:
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
        clks.append(Candidate(st.sig.name, 1, score, reasons))
    clks.sort(key=lambda c: c.score, reverse=True)

    return pcs[:top_n], clks[:top_n]
