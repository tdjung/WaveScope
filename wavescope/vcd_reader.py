"""Lightweight VCD reader: extracts a PC-like vector signal sampled on clock edges.

No external dependencies. Handles standard VCD produced by Verilator,
Icarus, VCS (vcdplus converted), GTKWave re-save, etc.

Output: an iterator of (tick_index, pc_value) committed samples, where
tick_index counts rising edges of the chosen clock signal.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple


@dataclass
class VcdSignal:
    ident: str          # short id code used in value-change section
    name: str           # full hierarchical name (dot separated)
    width: int


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
                r = subprocess.run([exe] + argv, capture_output=True,
                                   text=True, timeout=3600)
                ok = r.returncode == 0 and os.path.exists(out) \
                    and os.path.getsize(out) > 0
            else:   # lxt2vcd/vzt2vcd write to stdout
                with open(out, "w") as fo:
                    r = subprocess.run([exe] + argv, stdout=fo,
                                       stderr=subprocess.PIPE, text=True,
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


def changes_to_ticks(changes: Iterator[Tuple[int, int]],
                     period: Optional[int] = None,
                     warmup: int = 2048,
                     ) -> Tuple[int, Iterator[Tuple[int, int]]]:
    """Convert (time, value) changes to (clock_tick, value) samples.

    If period is None it is auto-detected as the GCD of the time deltas
    of the first `warmup` changes (all RTL events sit on the clock grid,
    so the GCD converges to the period after a handful of samples).
    Returns (period_used, sample_iterator).
    """
    import itertools
    import math

    buf: list = []
    if period is None:
        prev_t: Optional[int] = None
        g = 0
        for t, v in changes:
            buf.append((t, v))
            if prev_t is not None and t > prev_t:
                g = math.gcd(g, t - prev_t)
            prev_t = t
            if len(buf) >= warmup and g > 0:
                break
        if g == 0:
            raise VcdError(
                "cannot auto-detect clock period: fewer than 2 PC value "
                "changes found. Pass --clock-period explicitly.")
        period = g

    p = period

    def gen() -> Iterator[Tuple[int, int]]:
        # integer round-half-up: float division loses precision for
        # large timestamps (fs-scale dumps exceed float53 quickly)
        t0: Optional[int] = None
        for t, v in itertools.chain(buf, changes):
            if t0 is None:
                t0 = t
            yield (t - t0 + p // 2) // p, v

    return p, gen()
