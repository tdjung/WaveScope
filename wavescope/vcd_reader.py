"""Lightweight VCD reader: extracts a PC-like vector signal sampled on clock edges.

No external dependencies. Handles standard VCD produced by Verilator,
Icarus, VCS (vcdplus converted), GTKWave re-save, etc.

Output: an iterator of (tick_index, pc_value) committed samples, where
tick_index counts rising edges of the chosen clock signal.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple


@dataclass
class VcdSignal:
    ident: str          # short id code used in value-change section
    name: str           # full hierarchical name (dot separated)
    width: int


class VcdError(Exception):
    pass


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
            width = int(next(tok_iter))
            ident = next(tok_iter)
            name_parts = []
            for t in tok_iter:
                if t == "$end":
                    break
                name_parts.append(t)
            # name may be "pc [31:0]" -> keep base name only
            base = name_parts[0] if name_parts else "?"
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
    with open(path, "r", errors="replace") as f:
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
                sp = line.find(" ")
                if sp < 0:
                    continue
                ident = line[sp + 1:]
                if ident in cur:
                    cur[ident] = line[1:sp]
            elif c0 in "rR":
                continue  # real values: not applicable to pc/clk
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
