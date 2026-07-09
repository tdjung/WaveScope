"""Binary-side knowledge: disassembly, function symbols, source lines.

Uses the standard binutils toolchain (objdump / addr2line) so it works
for any target ISA for which a cross toolchain exists on the Linux host.
Default prefix targets RISC-V; override with --toolchain-prefix.
"""

import bisect
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple


class Insn(object):
    __slots__ = ("addr", "size", "mnemonic", "operands", "encoding")

    def __init__(self, addr, size, mnemonic, operands, encoding=None):
        self.addr = addr
        self.size = size
        self.mnemonic = mnemonic
        self.operands = operands
        self.encoding = encoding     # raw instruction bits (listing order)


class Func(object):
    __slots__ = ("name", "start", "end")

    def __init__(self, name, start, end):
        self.name = name
        self.start = start
        self.end = end               # exclusive


class BinaryInfo(object):
    def __init__(self):
        self.insns = {}              # type: Dict[int, Insn]
        self.funcs = []              # type: List[Func]  (sorted by start)
        self._starts = []            # type: List[int]
        self.lines = {}              # type: Dict[int, Tuple[str, int]]  addr -> (file, line)

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
_LABEL_RE = re.compile(r"^([0-9a-fA-F]+) <(.+)>:\s*$")
_SYM_RE = re.compile(
    r"^([0-9a-fA-F]+)\s+([lgw!\s])([w\s])([C\s])([W\s])([Ii\s])([dD\s])([FfO\s])\s+(\S+)\s+([0-9a-fA-F]+)\s+(.*)$")


def strip_params(name: str) -> str:
    """Drop the parameter list a demangler appends: 'foo(unsigned long)'
    -> 'foo', 'ns::bar(int, char*) const' -> 'ns::bar'. Keeps operator
    names intact ('operator()(int)' -> 'operator()')."""
    s = name.strip()
    # trailing qualifiers after the arg list
    for suf in (" const", " volatile", " &", " &&"):
        if s.endswith(suf):
            s = s[: -len(suf)]
    if not s.endswith(")"):
        return s
    depth = 0
    for i in range(len(s) - 1, -1, -1):
        if s[i] == ")":
            depth += 1
        elif s[i] == "(":
            depth -= 1
            if depth == 0:
                head = s[:i]
                # operator() / operator(): keep the parens that ARE the name
                if head.endswith("operator"):
                    return s
                return head or s
    return s


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
                with_lines: bool = True, demangle: bool = True) -> BinaryInfo:
    info = BinaryInfo()
    objdump = _tool(toolchain_prefix, "objdump")
    dm = ["-C"] if demangle else []

    # --- disassembly -------------------------------------------------
    out = subprocess.run([objdump, "-d", *dm, elf_path],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
    addrs: List[int] = []
    labels: Dict[int, str] = {}          # objdump's own display labels
    for line in out.stdout.splitlines():
        lm = _LABEL_RE.match(line)
        if lm:
            labels[int(lm.group(1), 16)] = strip_params(lm.group(2))
            continue
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
    sym = subprocess.run([objdump, "-t", *dm, elf_path],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
    raw_funcs: List[Tuple[int, int, str]] = []
    for line in sym.stdout.splitlines():
        m = _SYM_RE.match(line)
        if not m:
            continue
        if "F" not in m.group(8):
            continue
        start = int(m.group(1), 16)
        size = int(m.group(10), 16)
        name = strip_params(m.group(11).strip())
        raw_funcs.append((start, size, name))
    # Function universe = every label objdump -d prints (this includes
    # .S routines lacking .type/.size, hence absent from F-flagged
    # symtab entries) UNION F-flagged symbols. Aliased symbols sharing
    # one start (e.g. -msave-restore __riscv_save_4..7) collapse to a
    # single Func named after the label objdump itself displays, so
    # calls/cfn match the listing. Every range is capped at the next
    # known start: a sized symbol must never swallow a following asm
    # routine that the symbol table does not describe.
    by_start: Dict[int, Tuple[int, str]] = {}
    for start, size, name in sorted(raw_funcs):
        cur = by_start.get(start)
        if cur is None or size > cur[0]:
            by_start[start] = (size, name)
    for addr, name in labels.items():
        if addr not in by_start:
            by_start[addr] = (0, name)
    starts = sorted(by_start)
    for i, start in enumerate(starts):
        size, name = by_start[start]
        name = labels.get(start, name)
        nxt = starts[i + 1] if i + 1 < len(starts) else None
        end = start + size if size else (nxt if nxt is not None else start + 4)
        if nxt is not None:
            end = min(end, nxt) if size else end
            if end <= start:
                end = nxt
        info.funcs.append(Func(name=name, start=start, end=max(end, start + 2)))
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
                             input=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
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


_TARGET_RE = re.compile(r"^([0-9a-fA-F]+)\b")


def direct_target(insn: Insn) -> Optional[int]:
    """Resolved target address of a DIRECT branch/jump, parsed from the
    objdump operand text (e.g. 'a0,a1,1014 <foo+0x8>' -> 0x1014).

    Only meaningful for direct transfers -- callers must not use this
    for indirect jumps (register operands like 'a5' parse as hex!).
    """
    ops = insn.operands
    if not ops:
        return None
    last = ops.split(",")[-1].strip()
    m = _TARGET_RE.match(last)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except ValueError:
        return None


def text_ranges(elf_path: str, toolchain_prefix: str = "") -> List[Tuple[int, int]]:
    """Executable section address ranges [(start, end), ...] via objdump -h."""
    objdump = _tool(toolchain_prefix, "objdump")
    out = subprocess.run([objdump, "-h", elf_path],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
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
