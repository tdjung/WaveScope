"""Binary-side knowledge: disassembly, function symbols, source lines.

Uses the standard binutils toolchain (objdump / addr2line) so it works
for any target ISA for which a cross toolchain exists on the Linux host.
Default prefix targets RISC-V; override with --toolchain-prefix.
"""

from __future__ import annotations

import bisect
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Insn:
    addr: int
    size: int
    mnemonic: str
    operands: str
    encoding: Optional[int] = None   # raw instruction bits (listing order)


@dataclass
class Func:
    name: str
    start: int
    end: int          # exclusive


@dataclass
class BinaryInfo:
    insns: Dict[int, Insn] = field(default_factory=dict)
    funcs: List[Func] = field(default_factory=list)     # sorted by start
    _starts: List[int] = field(default_factory=list)
    lines: Dict[int, Tuple[str, int]] = field(default_factory=dict)  # addr -> (file, line)

    def func_at(self, addr: int) -> Optional[Func]:
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0:
            f = self.funcs[i]
            if f.start <= addr < f.end:
                return f
        return None

    def is_func_entry(self, addr: int) -> bool:
        i = bisect.bisect_left(self._starts, addr)
        return i < len(self._starts) and self._starts[i] == addr

    def line_at(self, addr: int) -> Tuple[str, int]:
        return self.lines.get(addr, ("??", 0))


_DISASM_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2,8}\s+)+)\s*(\S+)?\s*(.*)$")
_SYM_RE = re.compile(
    r"^([0-9a-fA-F]+)\s+([lgw!\s])([w\s])([C\s])([W\s])([Ii\s])([dD\s])([FfO\s])\s+(\S+)\s+([0-9a-fA-F]+)\s+(.*)$")


def _tool(prefix: str, name: str) -> str:
    cand = f"{prefix}{name}" if prefix else name
    if shutil.which(cand):
        return cand
    if shutil.which(name):
        return name
    raise FileNotFoundError(
        f"'{cand}' not found in PATH. Install binutils for your target "
        f"or pass --toolchain-prefix (e.g. riscv64-unknown-elf-).")


def load_binary(elf_path: str, toolchain_prefix: str = "",
                with_lines: bool = True) -> BinaryInfo:
    info = BinaryInfo()
    objdump = _tool(toolchain_prefix, "objdump")

    # --- disassembly -------------------------------------------------
    out = subprocess.run([objdump, "-d", "--no-show-raw-insn=0", elf_path],
                         capture_output=True, text=True)
    if out.returncode != 0:
        # some objdump versions don't accept the raw-insn flag form
        out = subprocess.run([objdump, "-d", elf_path],
                             capture_output=True, text=True, check=True)
    addrs: List[int] = []
    for line in out.stdout.splitlines():
        m = _DISASM_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = m.group(2).split()
        size = sum(len(b) // 2 for b in raw)
        try:
            encoding = int("".join(raw), 16)
        except ValueError:
            encoding = None
        mnem = (m.group(3) or "").lower()
        if not mnem:
            continue
        info.insns[addr] = Insn(addr=addr, size=size, mnemonic=mnem,
                                operands=m.group(4).strip(),
                                encoding=encoding)
        addrs.append(addr)

    # --- function symbols --------------------------------------------
    sym = subprocess.run([objdump, "-t", elf_path],
                         capture_output=True, text=True, check=True)
    raw_funcs: List[Tuple[int, int, str]] = []
    for line in sym.stdout.splitlines():
        m = _SYM_RE.match(line)
        if not m:
            continue
        if "F" not in m.group(8):
            continue
        start = int(m.group(1), 16)
        size = int(m.group(10), 16)
        name = m.group(11).strip()
        raw_funcs.append((start, size, name))
    raw_funcs.sort()
    for i, (start, size, name) in enumerate(raw_funcs):
        end = start + size
        if size == 0:  # size-less symbols: extend to next symbol
            end = raw_funcs[i + 1][0] if i + 1 < len(raw_funcs) else start + 4
        info.funcs.append(Func(name=name, start=start, end=end))
    info._starts = [f.start for f in info.funcs]

    # --- source line mapping (DWARF) ----------------------------------
    if with_lines and info.insns:
        _load_lines(info, elf_path, toolchain_prefix)
    return info


def _load_lines(info: BinaryInfo, elf_path: str, prefix: str) -> None:
    try:
        addr2line = _tool(prefix, "addr2line")
    except FileNotFoundError:
        return
    addr_list = sorted(info.insns)
    CHUNK = 4000
    for i in range(0, len(addr_list), CHUNK):
        chunk = addr_list[i:i + CHUNK]
        inp = "\n".join(hex(a) for a in chunk)
        out = subprocess.run([addr2line, "-e", elf_path],
                             input=inp, capture_output=True, text=True)
        if out.returncode != 0:
            return
        for addr, line in zip(chunk, out.stdout.splitlines()):
            if ":" not in line:
                continue
            fname, _, lno = line.rpartition(":")
            lno = lno.split()[0] if lno else "0"
            try:
                n = int(lno)
            except ValueError:
                n = 0
            info.lines[addr] = (fname if fname != "??" else "??", n)


def text_ranges(elf_path: str, toolchain_prefix: str = "") -> List[Tuple[int, int]]:
    """Executable section address ranges [(start, end), ...] via objdump -h."""
    objdump = _tool(toolchain_prefix, "objdump")
    out = subprocess.run([objdump, "-h", elf_path],
                         capture_output=True, text=True, check=True)
    ranges: List[Tuple[int, int]] = []
    lines = out.stdout.splitlines()
    for i, line in enumerate(lines):
        parts = line.split()
        if len(parts) >= 7 and parts[0].isdigit():
            flags = lines[i + 1] if i + 1 < len(lines) else ""
            if "CODE" in flags:
                try:
                    size = int(parts[2], 16)
                    vma = int(parts[3], 16)
                    if size:
                        ranges.append((vma, vma + size))
                except ValueError:
                    pass
    return sorted(ranges)
