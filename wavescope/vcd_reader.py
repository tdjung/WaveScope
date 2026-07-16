"""Lightweight VCD reader: extracts a PC-like vector signal sampled on clock edges.

No external dependencies. Handles standard VCD produced by Verilator,
Icarus, VCS (vcdplus converted), GTKWave re-save, etc.

Output: an iterator of (tick_index, pc_value) committed samples, where
tick_index counts rising edges of the chosen clock signal.
"""

import sys
import bz2
import gzip
import io
import lzma
import os
import shutil
import subprocess
import tempfile
from typing import Dict, Iterator, List, Optional, Tuple


class VcdSignal(object):
    __slots__ = ("ident", "name", "width")

    def __init__(self, ident, name, width):
        self.ident = ident          # short id code used in value-change section
        self.name = name            # full hierarchical name (dot separated)
        self.width = width


class VcdError(Exception):
    pass


_FST_MAGIC_HINT = None  # FST has no stable ASCII magic; detected by exclusion


def open_vcd_text(path: str) -> io.TextIOBase:
    """Open a VCD for text reading, transparently handling compression and
    binary waveform formats saved with a .vcd name.

    - gzip / bzip2 / xz compressed VCD: decompressed on the fly
      (GTKWave opens these transparently, so they are common in the wild)
    - FST / LXT2 / VZT binaries: converted via fst2vcd / lxt2vcd / vzt2vcd
      if available in PATH (all ship with GTKWave)
    """
    with open(path, "rb") as f:
        head = f.read(512)

    if head[:2] == b"\x1f\x8b":
        return io.TextIOWrapper(gzip.open(path, "rb"), errors="replace")
    if head[:3] == b"BZh":
        return io.TextIOWrapper(bz2.open(path, "rb"), errors="replace")
    if head[:6] == b"\xfd7zXZ\x00":
        return io.TextIOWrapper(lzma.open(path, "rb"), errors="replace")

    # plain text? VCD headers are ASCII with $ keywords
    if b"\x00" not in head and (b"$" in head or not head):
        return open(path, "r", errors="replace")

    # binary, not a known compression: try GTKWave converters
    converted = _try_binary_converters(path)
    if converted:
        return open(converted, "r", errors="replace")

    raise VcdError(
        f"'{path}' is not a text VCD (binary content detected) and no "
        f"converter succeeded.\n"
        f"It is likely an FST/LXT2/VZT waveform saved with a .vcd name.\n"
        f"  - identify it:  file {path}\n"
        f"  - convert it :  fst2vcd {path} -o out.vcd   (ships with GTKWave)\n"
        f"                  or lxt2vcd / vzt2vcd\n"
        f"then pass the converted file, or install the converter in PATH "
        f"so WaveScope can do this automatically.")


def _try_binary_converters(path: str) -> Optional[str]:
    out = os.path.join(tempfile.gettempdir(),
                       os.path.basename(path) + ".wavescope.vcd")
    for tool, argv in (("fst2vcd", [path, "-o", out]),
                       ("lxt2vcd", [path]),
                       ("vzt2vcd", [path])):
        exe = shutil.which(tool)
        if not exe:
            continue
        try:
            if tool == "fst2vcd":
                r = subprocess.run([exe] + argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, timeout=3600)
                ok = r.returncode == 0 and os.path.exists(out) \
                    and os.path.getsize(out) > 0
            else:   # lxt2vcd/vzt2vcd write to stdout
                with open(out, "w") as fo:
                    r = subprocess.run([exe] + argv, stdout=fo,
                                       stderr=subprocess.PIPE, universal_newlines=True,
                                       timeout=3600)
                ok = r.returncode == 0 and os.path.getsize(out) > 0
            if ok:
                import sys
                print(f"[wavescope] binary waveform converted with {tool} "
                      f"-> {out}", file=sys.stderr)
                return out
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


def _tokens(f: io.TextIOBase) -> Iterator[str]:
    for line in f:
        for tok in line.split():
            yield tok


def read_header(f: io.TextIOBase) -> Tuple[List[VcdSignal], int]:
    """Parse VCD header up to $enddefinitions.

    Returns (signals, timescale_fs). File handle is left positioned at
    the start of the value-change section.
    """
    signals: List[VcdSignal] = []
    scope: List[str] = []
    timescale_fs = 1

    tok_iter = _tokens(f)
    for tok in tok_iter:
        if tok == "$scope":
            next(tok_iter)                     # module/begin/...
            scope.append(next(tok_iter))       # scope name
            _consume_until_end(tok_iter)
        elif tok == "$upscope":
            if scope:
                scope.pop()
            _consume_until_end(tok_iter)
        elif tok == "$var":
            next(tok_iter)                     # var type (wire/reg/...)
            try:
                width = int(next(tok_iter))
            except ValueError:
                _consume_until_end(tok_iter)
                continue
            ident = next(tok_iter)
            name_parts = []
            for t in tok_iter:
                if t == "$end":
                    break
                name_parts.append(t)
            # name may be "pc [31:0]" or "pc[31:0]" -> keep base name only
            base = name_parts[0] if name_parts else "?"
            br = base.find("[")
            if br > 0:
                base = base[:br]
            full = ".".join(scope + [base])
            signals.append(VcdSignal(ident=ident, name=full, width=width))
        elif tok == "$timescale":
            parts = []
            for t in tok_iter:
                if t == "$end":
                    break
                parts.append(t)
            timescale_fs = _parse_timescale("".join(parts))
        elif tok == "$enddefinitions":
            _consume_until_end(tok_iter)
            break
        elif tok.startswith("$"):
            _consume_until_end(tok_iter)
    return signals, timescale_fs


def _consume_until_end(tok_iter: Iterator[str]) -> None:
    for t in tok_iter:
        if t == "$end":
            return


_UNIT_FS = {"s": 10**15, "ms": 10**12, "us": 10**9,
            "ns": 10**6, "ps": 10**3, "fs": 1}


def _parse_timescale(text: str) -> int:
    text = text.strip()
    num = ""
    i = 0
    while i < len(text) and (text[i].isdigit()):
        num += text[i]
        i += 1
    unit = text[i:].strip()
    return int(num or "1") * _UNIT_FS.get(unit, 1)


def find_signal(signals: List[VcdSignal], pattern: str) -> VcdSignal:
    """Find a signal by exact full name, then by suffix match, then substring."""
    for s in signals:
        if s.name == pattern:
            return s
    matches = [s for s in signals if s.name.endswith("." + pattern) or s.name.split(".")[-1] == pattern]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        names = ", ".join(m.name for m in matches[:8])
        raise VcdError(f"signal pattern '{pattern}' is ambiguous: {names}")
    subs = [s for s in signals if pattern in s.name]
    if len(subs) == 1:
        return subs[0]
    raise VcdError(f"signal '{pattern}' not found in VCD"
                   + (f" (candidates: {', '.join(s.name for s in subs[:8])})" if subs else ""))


def iter_pc_samples(path: str, clock_name: str, pc_name: str,
                    sample_edge: str = "rising",
                    valid_name: Optional[str] = None) -> Iterator[Tuple[int, int]]:
    """Yield (clock_tick_index, pc_value) at each sampled clock edge.

    - clock_tick_index: number of sampled edges seen so far (0-based)
    - pc_value: integer value of the PC vector at that edge
    - If valid_name is given, samples are only emitted while that signal == 1
      (useful for commit/retire-valid qualified PCs).
    Samples with X/Z bits in PC are skipped.
    """
    with open_vcd_text(path) as f:
        signals, _ = read_header(f)
        clk = find_signal(signals, clock_name)
        pc = find_signal(signals, pc_name)
        valid = find_signal(signals, valid_name) if valid_name else None

        clk_id, pc_id = clk.ident, pc.ident
        valid_id = valid.ident if valid else None

        cur: Dict[str, str] = {clk_id: "x", pc_id: "x"}
        if valid_id:
            cur[valid_id] = "x"

        prev_clk = "x"
        tick = 0
        want_rise = sample_edge == "rising"

        for raw in f:
            line = raw.strip()
            if not line:
                continue
            c0 = line[0]
            if c0 == "#":
                continue
            if c0 in "01xXzZ":
                ident = line[1:]
                if ident in cur:
                    cur[ident] = c0.lower()
                    if ident == clk_id:
                        v = c0.lower()
                        edge = (prev_clk == "0" and v == "1") if want_rise \
                            else (prev_clk == "1" and v == "0")
                        if edge:
                            if valid_id is None or cur.get(valid_id) == "1":
                                pcv = _vec_to_int(cur.get(pc_id, "x"))
                                if pcv is not None:
                                    yield tick, pcv
                            tick += 1
                        prev_clk = v
            elif c0 in "bB":
                parts = line.split()
                if len(parts) < 2:
                    continue
                ident = parts[1]
                if ident in cur:
                    cur[ident] = parts[0][1:]
            elif c0 in "rR":
                # some ISS dumps emit integer-valued signals as reals
                parts = line.split()
                if len(parts) >= 2 and parts[1] in cur:
                    try:
                        cur[parts[1]] = bin(int(float(parts[0][1:])))[2:]
                    except (ValueError, OverflowError):
                        pass
            elif c0 == "$":
                continue  # $dumpvars / $end blocks; value lines inside are handled above


def _vec_to_int(bits: str) -> Optional[int]:
    if not bits:
        return None
    b = bits.lower()
    if b in ("x", "z") or "x" in b or "z" in b:
        return None
    if b in ("0", "1"):
        return int(b)
    try:
        return int(b, 2)
    except ValueError:
        return None


# ----------------------------------------------------------------------
# Multi-signal extraction: PC commits with attached auxiliary values
# (epc/mepc, mispredict, ... -- anything the profiler wants to read
# "as of this commit").
# ----------------------------------------------------------------------
def _parse_value_line(c0: str, line: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse one VCD value-change line -> (ident, int_value|None)."""
    if c0 in "bBrR":
        parts = line.split()
        if len(parts) < 2:
            return None, None
        tok = parts[0][1:]
        if c0 in "rR":
            try:
                return parts[1], int(float(tok))
            except (ValueError, OverflowError):
                return parts[1], None
        return parts[1], _vec_to_int(tok)
    # scalar: 0/1/x/z immediately followed by the ident
    return line[1:], _vec_to_int(c0)


def iter_commit_changes(path: str, pc_name: str,
                        aux_names: Tuple[str, ...] = (),
                        valid_name: Optional[str] = None,
                        ) -> Iterator[Tuple]:
    """Yield (time, pc_value, *aux_values) at each PC commit (clockless).

    Commit points are PC value changes (valid-gated like
    iter_pc_changes).  Aux values are the signal values in effect AFTER
    all value changes at the emission timestamp have been applied: a
    trap that writes mepc in the same cycle as the PC redirect is
    therefore already visible at the first handler instruction's sample,
    matching a simulator that reads CSR state at commit time.  Aux
    values are None while the signal is x/z or has not changed yet.
    """
    with open_vcd_text(path) as f:
        signals, _ = read_header(f)
        pc = find_signal(signals, pc_name)
        valid = find_signal(signals, valid_name) if valid_name else None
        aux = [find_signal(signals, n) for n in aux_names]

        pc_id = pc.ident
        valid_id = valid.ident if valid else None
        aux_idx: Dict[str, int] = {}
        for i, s in enumerate(aux):
            aux_idx[s.ident] = i
        aux_cur: List[Optional[int]] = [None] * len(aux)

        t = 0
        cur_pc: Optional[int] = None
        cur_valid: Optional[int] = 1 if valid_id is None else None
        pend: List[int] = []       # pc values committed at timestamp t

        for raw in f:
            line = raw.strip()
            if not line:
                continue
            c0 = line[0]
            if c0 == "#":
                if pend:           # timestamp advances: aux is now final
                    snap = tuple(aux_cur)
                    for v in pend:
                        yield (t, v) + snap
                    pend = []
                try:
                    t = int(line[1:].split()[0])
                except (ValueError, IndexError):
                    pass
                continue
            if c0 == "$":
                continue
            ident, v = _parse_value_line(c0, line)
            if ident is None:
                continue
            if ident == pc_id:
                if v is not None:
                    cur_pc = v
                    if cur_valid == 1:
                        pend.append(v)
            elif ident in aux_idx:
                aux_cur[aux_idx[ident]] = v
            elif valid_id is not None and ident == valid_id:
                if v == 1 and cur_valid != 1 and cur_pc is not None:
                    pend.append(cur_pc)   # rising valid re-commits current PC
                cur_valid = v
        if pend:
            snap = tuple(aux_cur)
            for v in pend:
                yield (t, v) + snap


def iter_samples_multi(path: str, clock_name: str, pc_name: str,
                       aux_names: Tuple[str, ...] = (),
                       sample_edge: str = "rising",
                       valid_name: Optional[str] = None,
                       ) -> Iterator[Tuple]:
    """Clocked variant: yield (tick, pc_value, *aux_values) at sampled
    clock edges (valid-gated like iter_pc_samples).  Aux values are the
    ones seen up to the edge; a same-edge CSR write dumped after the
    clock line lands on the next sample, which the profiler's
    change-based detection tolerates (one commit of latency at worst)."""
    with open_vcd_text(path) as f:
        signals, _ = read_header(f)
        clk = find_signal(signals, clock_name)
        pc = find_signal(signals, pc_name)
        valid = find_signal(signals, valid_name) if valid_name else None
        aux = [find_signal(signals, n) for n in aux_names]

        clk_id, pc_id = clk.ident, pc.ident
        valid_id = valid.ident if valid else None
        aux_idx: Dict[str, int] = {}
        for i, s in enumerate(aux):
            aux_idx[s.ident] = i
        aux_cur: List[Optional[int]] = [None] * len(aux)

        cur_pc: Optional[str] = "x"
        cur_valid: Optional[int] = 1 if valid_id is None else None
        prev_clk = "x"
        tick = 0
        want_rise = sample_edge == "rising"

        for raw in f:
            line = raw.strip()
            if not line:
                continue
            c0 = line[0]
            if c0 == "#" or c0 == "$":
                continue
            if c0 in "01xXzZ" and line[1:] == clk_id:
                v = c0.lower()
                edge = (prev_clk == "0" and v == "1") if want_rise \
                    else (prev_clk == "1" and v == "0")
                if edge:
                    if valid_id is None or cur_valid == 1:
                        pcv = _vec_to_int(cur_pc or "x")
                        if pcv is not None:
                            yield (tick, pcv) + tuple(aux_cur)
                    tick += 1
                prev_clk = v
                continue
            ident, v = _parse_value_line(c0, line)
            if ident is None:
                continue
            if ident == pc_id:
                # keep raw bits so x/z propagation matches iter_pc_samples
                cur_pc = line.split()[0][1:] if c0 in "bB" else \
                    (bin(v)[2:] if v is not None else "x")
            elif ident in aux_idx:
                aux_cur[aux_idx[ident]] = v
            elif valid_id is not None and ident == valid_id:
                cur_valid = v


# ----------------------------------------------------------------------
# Clockless operation: derive cycles from event times
# ----------------------------------------------------------------------
def iter_pc_changes(path: str, pc_name: str,
                    valid_name: Optional[str] = None
                    ) -> Iterator[Tuple[int, int]]:
    """Yield (time, pc_value) at each PC value change (no clock needed).

    If valid_name is given, a change is emitted only while valid == 1,
    and a rising valid edge re-emits the current PC (instruction becomes
    architecturally valid at that time).
    """
    with open_vcd_text(path) as f:
        signals, _ = read_header(f)
        pc = find_signal(signals, pc_name)
        valid = find_signal(signals, valid_name) if valid_name else None
        pc_id = pc.ident
        valid_id = valid.ident if valid else None

        t = 0
        cur_pc: Optional[int] = None
        cur_valid = 1 if valid_id is None else None

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
            elif c0 in "bB" or c0 in "rR":
                parts = line.split()
                if len(parts) < 2:
                    continue
                ident = parts[1]
                if ident == pc_id:
                    tok = parts[0][1:]
                    if c0 in "rR":
                        try:
                            v: Optional[int] = int(float(tok))
                        except (ValueError, OverflowError):
                            v = None
                    else:
                        v = _vec_to_int(tok)
                    if v is not None:
                        cur_pc = v
                        if cur_valid == 1:
                            yield t, v
                elif valid_id and ident == valid_id:
                    nv = _vec_to_int(parts[0][1:])
                    if nv == 1 and cur_valid != 1 and cur_pc is not None:
                        yield t, cur_pc
                    cur_valid = nv
            elif c0 in "01xXzZ":
                if valid_id and line[1:] == valid_id:
                    nv = 1 if c0 == "1" else (0 if c0 == "0" else None)
                    if nv == 1 and cur_valid != 1 and cur_pc is not None:
                        yield t, cur_pc
                    cur_valid = nv


def parse_period(spec: str, timescale_fs: int) -> int:
    """'10ns' / '20000ps' / plain int (dump time units) -> dump time units."""
    s = spec.strip().lower()
    num = ""
    i = 0
    while i < len(s) and (s[i].isdigit() or s[i] == "."):
        num += s[i]
        i += 1
    unit = s[i:].strip()
    if not unit:
        return int(float(num))
    if unit not in _UNIT_FS:
        raise VcdError(f"unknown time unit '{unit}' in --clock-period")
    fs = float(num) * _UNIT_FS[unit]
    units = fs / timescale_fs
    if units < 1:
        raise VcdError(f"--clock-period {spec} is below the dump timescale")
    return int(round(units))


def get_timescale(path: str) -> int:
    with open_vcd_text(path) as f:
        _, ts = read_header(f)
    return ts


def changes_to_ticks(changes: Iterator[Tuple],
                     period: Optional[int] = None,
                     warmup: int = 256,
                     adapt: Optional[bool] = None,
                     relock_window: int = 64,
                     on_relock=None,
                     ) -> Tuple[int, Iterator[Tuple]]:
    """Convert (time, value, ...) changes to (clock_tick, value, ...)
    samples.  Any elements after the leading timestamp (e.g. an attached
    epc value) are passed through untouched.

    If period is None it is auto-detected as the GCD of the time deltas
    of the first `warmup` changes (all RTL events sit on the clock grid,
    so the GCD converges to the period after a handful of samples).

    Adaptive re-locking (CMU/DVFS): a clock-manager can change the core
    frequency mid-trace.  A delta that is NOT a multiple of the current
    period is impossible under a fixed clock (stalls are always whole
    cycles), so it is hard evidence of a new grid: we buffer the next
    `relock_window` deltas, re-derive the period from their GCD, and
    continue on the new grid from the change point.  Detected changes
    are reported (on_relock(time, old, new) or a stderr note).
    Limitation: a switch to a SLOWER clock whose period is an exact
    multiple of the old one is indistinguishable from stalls without the
    clock signal itself -- dump the clock and use --clock if the CMU can
    also slow the core down.

    adapt defaults to True when the period is auto-detected and False
    when an explicit period is given (then a single warning is printed
    if off-grid deltas show up).  Returns (initial_period, iterator).
    """
    import itertools
    import math

    explicit = period is not None
    if adapt is None:
        adapt = not explicit

    buf: list = []
    if period is None:
        prev_t: Optional[int] = None
        deltas: list = []
        for ch in changes:
            buf.append(ch)
            t = ch[0]
            if prev_t is not None and t > prev_t:
                deltas.append(t - prev_t)
            prev_t = t
            if len(deltas) >= warmup:
                break
        if not deltas:
            raise VcdError(
                "cannot auto-detect clock period: fewer than 2 PC value "
                "changes found. Pass --clock-period explicitly.")
        # lock onto the grid of the FIRST deltas only (the GCD converges
        # within a few dozen 1-cycle-apart commits): if a CMU frequency
        # change falls inside the warmup, a whole-window GCD would mix
        # two grids and silently misticks the first region -- with a
        # head-only lock the change point instead shows up as off-grid
        # deltas and the adaptive relock handles it like any other
        head = deltas[:64] if adapt else deltas
        g = 0
        for d in head:
            g = math.gcd(g, d)
        period = g

    p0 = period

    def notify(t, old, new):
        if on_relock is not None:
            on_relock(t, old, new)
        else:
            print(f"[wavescope] clockless: clock period change detected "
                  f"at t={t}: {old} -> {new} dump time units per cycle "
                  f"(CMU/DVFS reconfiguration?)", file=sys.stderr)

    def gen() -> Iterator[Tuple]:
        # integer round-half-up: float division loses precision for
        # large timestamps (fs-scale dumps exceed float53 quickly)
        p = p0
        base_t: Optional[int] = None    # segment origin (time)
        base_tick = 0                   # segment origin (ticks)
        prev_t: Optional[int] = None
        warned_offgrid = False

        def tick(t):
            return base_tick + (t - base_t + p // 2) // p

        stream = itertools.chain(buf, changes)
        for ch in stream:
            t = ch[0]
            if base_t is None:
                base_t = prev_t = t
            d = t - prev_t
            if d > 0 and d % p != 0:
                if not adapt:
                    if not warned_offgrid:
                        warned_offgrid = True
                        print(f"[wavescope] WARNING: PC change at t={t} is "
                              f"off the {p}-unit clock grid -- the clock "
                              f"frequency may change mid-trace (CMU/DVFS). "
                              f"Omit --clock-period to enable adaptive "
                              f"period detection, or dump the clock signal "
                              f"and pass --clock for exact cycles.",
                              file=sys.stderr)
                elif d > 0:
                    # --- relock: gather a window of deltas on the new grid
                    rbuf = [ch]
                    rdeltas = [d]
                    lt = t
                    for ch2 in stream:
                        rbuf.append(ch2)
                        if ch2[0] > lt:
                            rdeltas.append(ch2[0] - lt)
                        lt = ch2[0]
                        if len(rdeltas) >= relock_window:
                            break
                    # the triggering delta may straddle the transition
                    # (tail of an old cycle + head of a new one), which
                    # poisons the GCD -- try without it as a fallback
                    newp = None
                    for ds in (rdeltas, rdeltas[1:]):
                        if not ds:
                            continue
                        g = 0
                        for x in ds:
                            g = math.gcd(g, x)
                        support = sum(1 for x in ds if x == g)
                        ambiguous_slower = g >= p and g % p == 0
                        if g > 0 and g != p and not ambiguous_slower \
                                and support >= max(2, len(ds) // 16):
                            newp = g
                            break
                    if newp is not None:
                        # new segment starts at the last on-grid change;
                        # the straddling gap itself is charged on the new
                        # grid (one-off, bounded by old_p/new_p cycles)
                        base_tick = tick(prev_t)
                        base_t = prev_t
                        notify(prev_t, p, newp)
                        p = newp
                    for ch2 in rbuf:
                        yield (tick(ch2[0]),) + tuple(ch2[1:])
                        prev_t = ch2[0]
                    continue
            yield (tick(t),) + tuple(ch[1:])
            prev_t = t

    return p0, gen()
