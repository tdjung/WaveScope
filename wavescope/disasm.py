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
        self.data_syms = {}          # type: Dict[int, str]  in-text data objects (excluded from funcs)

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
    r"^\s*([0-9a-fA-F]+):\s+((?:(?:[0-9a-fA-F]{2}){1,4}\s+)+)\s*(\S+)?\s*(.*)$")
_ADDR_RE = re.compile(r"^\s*([0-9a-fA-F]+):(.*)$")


def _parse_disasm_fields(line):
    """(addr, enc_tokens, mnemonic, operands) from one objdump -d line.

    GNU/LLVM objdump separate the fields with TABS:
        ADDR:<tab>ENCODING<tab>MNEMONIC<tab>OPERANDS
    (x86 puts mnemonic+operands in one space-separated tab field; the
    encoding field itself may hold space-separated bytes).  Splitting on
    whitespace alone is WRONG: hex-looking mnemonics ("add" = 0xadd!)
    get consumed as encoding bytes, inflating the instruction size --
    which corrupts every fallthrough computation (false unreachable-
    successor exceptions, false flow anomalies, wrong taken/Bcm).
    A tab-less dialect falls back to the regex, whose encoding tokens
    are restricted to even lengths so 3-char mnemonics stay safe."""
    m = _ADDR_RE.match(line)
    if m is None or "\t" not in m.group(2):
        m2 = _DISASM_RE.match(line)
        if not m2:
            return None
        return (int(m2.group(1), 16), m2.group(2).split(),
                (m2.group(3) or "").lower(), m2.group(4).strip())
    parts = [p for p in m.group(2).split("\t")]
    if parts and not parts[0].strip():
        parts = parts[1:]
    if not parts:
        return None
    enc_tokens = parts[0].split()
    if not enc_tokens or any(c not in "0123456789abcdefABCDEF"
                             for t in enc_tokens for c in t):
        return None
    rest = "\t".join(parts[1:]).strip()
    if not rest:
        return (int(m.group(1), 16), enc_tokens, "", "")
    sp = rest.split(None, 1)
    return (int(m.group(1), 16), enc_tokens, sp[0].lower(),
            sp[1].strip() if len(sp) > 1 else "")
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
        m = _parse_disasm_fields(line)
        if m is None:
            continue
        addr, raw, mnem, ops = m
        size = sum(len(b) // 2 for b in raw)
        try:
            encoding = int("".join(raw), 16)
        except ValueError:
            encoding = None
        if not mnem:
            continue
        info.insns[addr] = Insn(addr=addr, size=size, mnemonic=mnem,
                                operands=ops,
                                encoding=encoding)
        addrs.append(addr)

    # --- function symbols --------------------------------------------
    sym = subprocess.run([objdump, "-t", *dm, elf_path],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
    raw_funcs: List[Tuple[int, int, str]] = []
    data_syms: Dict[int, str] = {}       # objects placed in code sections
    for line in sym.stdout.splitlines():
        m = _SYM_RE.match(line)
        if not m:
            continue
        if "O" in m.group(8):
            # data object: switch tables (CSWTCH.*), const arrays etc.
            # emitted into .text by the compiler.  objdump -d prints a
            # label for these too, so remember them BOTH to exclude
            # them from the function universe AND to cap the previous
            # function's range at their start.
            name = m.group(11).strip()
            for vis in (".hidden ", ".protected ", ".internal "):
                if name.startswith(vis):
                    name = name[len(vis):]
            data_syms[int(m.group(1), 16)] = strip_params(name)
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
    # only objects the disassembler actually labeled live in code
    # sections; objects in .data/.rodata never become funcs and must not
    # act as range boundaries either
    data_syms = {a: n for a, n in data_syms.items() if a in labels}
    by_start: Dict[int, Tuple[int, str]] = {}
    for start, size, name in sorted(raw_funcs):
        cur = by_start.get(start)
        if cur is None or size > cur[0]:
            by_start[start] = (size, name)
    for addr, name in labels.items():
        if addr not in by_start and addr not in data_syms:
            by_start[addr] = (0, name)
    # boundaries include data objects so an unsized asm routine directly
    # followed by an in-text table does not swallow the table
    bounds = sorted(set(by_start) | set(data_syms))
    nxt_of = {}
    for i, a in enumerate(bounds):
        nxt_of[a] = bounds[i + 1] if i + 1 < len(bounds) else None
    starts = sorted(by_start)
    for start in starts:
        size, name = by_start[start]
        name = labels.get(start, name)
        nxt = nxt_of[start]
        end = start + size if size else (nxt if nxt is not None else start + 4)
        if nxt is not None:
            end = min(end, nxt) if size else end
            if end <= start:
                end = nxt
        info.funcs.append(Func(name=name, start=start, end=max(end, start + 2)))
    info._starts = [f.start for f in info.funcs]
    info.data_syms = data_syms

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


def check_disasm(elf_path: str, toolchain_prefix: str = "",
                 demangle: bool = True, max_show: int = 20) -> dict:
    """Diagnose disassembly-parsing / function-range drops on THIS
    machine's objdump dialect (wavescope checkelf).

    Re-runs objdump -d, extracts the ground-truth instruction address
    set with a minimal matcher, and reports -- with the offending RAW
    LINES -- every address that (a) failed to parse into insns, or
    (b) parsed but is excluded from every function range (and would
    therefore be missing from the full-coverage callgrind emission),
    plus per-function tiling gaps and end-vs-last-insn mismatches.
    """
    b = load_binary(elf_path, toolchain_prefix, with_lines=False,
                    demangle=demangle)
    objdump = _tool(toolchain_prefix, "objdump")
    dm = ["-C"] if demangle else []
    out = subprocess.run([objdump, "-d", *dm, elf_path],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         universal_newlines=True, check=True)
    addr_re = re.compile(r"^\s*([0-9a-fA-F]+):")
    raw_by_addr: Dict[int, str] = {}
    for line in out.stdout.splitlines():
        if _LABEL_RE.match(line):
            continue
        m = addr_re.match(line)
        if m:
            a = int(m.group(1), 16)
            raw_by_addr.setdefault(a, line)

    # alias groups: several symtab names at one address (millicode
    # __riscv_restore_0..3 style) -- only ONE name can be canonical, and
    # if the simulator's symbolizer picks a different alias, its calls
    # appear "missing" under the expected name
    symout = subprocess.run([objdump, "-t", *dm, elf_path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True, check=True)
    by_addr: Dict[int, List[str]] = {}
    for line in symout.stdout.splitlines():
        m = _SYM_RE.match(line)
        if m and "F" in (m.group(8) or "") + (m.group(6) or ""):
            nm = m.group(11).strip() if m.lastindex >= 11 else ""
            if nm:
                by_addr.setdefault(int(m.group(1), 16), []).append(
                    nm.replace(".hidden ", ""))
    aliases = []
    canon = {f.start: f.name for f in b.funcs}
    for a, names in sorted(by_addr.items()):
        if len(names) > 1:
            aliases.append((a, sorted(set(names)), canon.get(a)))

    parse_missing = sorted(a for a in raw_by_addr if a not in b.insns)
    covered = set()
    for f in b.funcs:
        for a in b.insns:
            if f.start <= a < f.end:
                covered.add(a)
    range_dropped = sorted(a for a in b.insns if a not in covered)

    gaps = []
    end_mismatch = []
    for f in b.funcs:
        pcs = sorted(a for a in b.insns if f.start <= a < f.end)
        for a, nxt in zip(pcs, pcs[1:]):
            if a + b.insns[a].size != nxt:
                gaps.append((f.name, a, b.insns[a].size, nxt))
        if pcs:
            last = pcs[-1]
            true_end = last + b.insns[last].size
            nxt_start = min((g.start for g in b.funcs
                             if g.start > f.start), default=None)
            if true_end != f.end and (nxt_start is None
                                      or true_end <= nxt_start):
                end_mismatch.append((f.name, f.start, f.end, last,
                                     b.insns[last].size))

    return {
        "n_raw": len(raw_by_addr), "n_parsed": len(b.insns),
        "n_funcs": len(b.funcs), "n_data_syms": len(b.data_syms),
        "parse_missing": [(a, raw_by_addr[a])
                          for a in parse_missing[:max_show]],
        "n_parse_missing": len(parse_missing),
        "range_dropped": [
            (a, b.insns[a].mnemonic,
             (lambda f: f"prev func {f.name} ends {f.end:#x}"
              if f else "no containing func")(
                 max((g for g in b.funcs if g.start <= a),
                     key=lambda g: g.start, default=None)))
            for a in range_dropped[:max_show]],
        "n_range_dropped": len(range_dropped),
        "gaps": gaps[:max_show], "n_gaps": len(gaps),
        "end_mismatch": end_mismatch[:max_show],
        "n_end_mismatch": len(end_mismatch),
        "aliases": aliases[:max_show], "n_aliases": len(aliases),
    }
