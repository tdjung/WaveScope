"""Table-driven instruction classification.

ISA knowledge lives in JSON data files under wavescope/isa/ -- the code
here is a generic engine that interprets those tables.  This keeps
per-ISA quirks (RISC-V operand-based link detection, Thumb-2 condition
suffixes and PC-writing loads, AArch64 "b.cond") in data, and lets users
extend an ISA with custom instructions via an overlay file (--isa-ext).

Overlay file example (RISC-V custom load recognised by a vendor objdump):

    { "classes": { "load": ["myvendor.ldx"] } }

Overlay for an instruction objdump can NOT disassemble (shows ".word"):

    { "custom_encodings": [
        { "name": "cust_dma_ld", "mask": "0x7f", "match": "0x0b",
          "classes": ["load"], "size": 4 } ] }
"""

import json
import os
import re
from typing import Dict, List, Optional, Set

from .disasm import Insn

ISA_DIR = os.path.join(os.path.dirname(__file__), "isa")

ISA_ALIASES = {
    "riscv": "riscv", "rv": "riscv", "rv32": "riscv", "rv64": "riscv",
    "riscv32": "riscv", "riscv64": "riscv",
    "arm": "armv7m", "thumb": "armv7m", "thumb2": "armv7m",
    "cortex-m": "armv7m", "cortexm": "armv7m", "armv7m": "armv7m",
    "arm64": "aarch64", "aarch64": "aarch64", "armv8": "aarch64",
}


class InsnClass(object):
    __slots__ = ("is_cond_branch", "is_jump", "is_indirect", "is_load",
                 "is_store", "writes_link", "is_return")

    def __init__(self, is_cond_branch=False, is_jump=False,
                 is_indirect=False, is_load=False, is_store=False,
                 writes_link=False, is_return=False):
        self.is_cond_branch = is_cond_branch
        self.is_jump = is_jump
        self.is_indirect = is_indirect
        self.is_load = is_load
        self.is_store = is_store
        self.writes_link = writes_link
        self.is_return = is_return


class EncodingRule(object):
    def __init__(self, name, mask, match, classes, size=4):
        self.name = name
        self.mask = mask
        self.match = match
        self.classes = classes
        self.size = size


_TOKEN_RE = re.compile(r"[a-z0-9_.]+")


class TableClassifier:
    def __init__(self, spec: dict):
        self.spec = spec
        self.strip_suffixes: List[str] = spec.get("normalize", {}).get("strip_suffixes", [])
        self.cond_suffixes: List[str] = sorted(
            spec.get("cond_suffixes", []), key=len, reverse=True)
        self.cond_branch_prefixes: List[str] = spec.get("cond_branch_prefixes", [])

        cls = spec.get("classes", {})
        self.cond_branch: Set[str] = set(cls.get("cond_branch", []))
        self.direct_jump: Set[str] = set(cls.get("direct_jump", []))
        self.indirect_jump: Set[str] = set(cls.get("indirect_jump", []))
        self.load: Set[str] = set(cls.get("load", []))
        self.store: Set[str] = set(cls.get("store", []))
        self.returns: Set[str] = set(cls.get("return", []))
        self.prefix_classes: Dict[str, List[str]] = spec.get("prefix_classes", {})

        link = spec.get("link", {})
        self.link_convention: str = link.get("convention", "operand")
        self.link_registers: Set[str] = set(link.get("registers", []))
        self.link_mnemonics: Set[str] = set(link.get("mnemonics", []))
        self.implied_link: Set[str] = set(link.get("implied_link_mnemonics", []))
        self.no_link: Set[str] = set(link.get("no_link_mnemonics", []))
        self.single_op_link: Set[str] = set(link.get("single_operand_implies_link", []))

        self.indirect_if_reg: Set[str] = set(spec.get("indirect_if_reg_operand", []))
        self.return_if_operand: Dict[str, List[str]] = spec.get("return_if_operand", {})

        pw = spec.get("pc_write", {})
        self.pc_write_enabled: bool = pw.get("enabled", False)
        self.pc_reg: str = pw.get("register", "pc")
        self.pc_ret_prefixes: List[str] = pw.get("return_mnemonic_prefixes", [])
        self.pc_jmp_prefixes: List[str] = pw.get("jump_mnemonic_prefixes", [])

        self.unknown_mnemonics: Set[str] = set(spec.get("unknown_mnemonics", []))
        # sleep/idle instructions (wfi/wfe/...): the profiler treats a
        # clock gap after one of these as a sleep, not a stall
        self.idle_mnemonics: Set[str] = set(
            spec.get("idle_mnemonics", ["wfi"]))
        self.encodings: List[EncodingRule] = [
            EncodingRule(name=e.get("name", "?"),
                         mask=int(str(e["mask"]), 0),
                         match=int(str(e["match"]), 0),
                         classes=e.get("classes", []),
                         size=e.get("size", 4))
            for e in spec.get("custom_encodings", [])
        ]

    # ------------------------------------------------------------------
    def classify(self, insn: Insn) -> InsnClass:
        m = self._normalize(insn.mnemonic)
        ops = insn.operands.lower()
        c = InsnClass()

        if m in self.unknown_mnemonics:
            if self._apply_encoding(insn, c):
                return c
            return c

        conditional = False
        base = self._lookup_base(m)
        if base is None and self.cond_suffixes:
            stripped = self._strip_cond(m)
            if stripped is not None:
                base, conditional = stripped, True
        if base is None:
            for p in self.cond_branch_prefixes:
                if m.startswith(p):
                    c.is_cond_branch = True
                    return c
            # completely unknown mnemonic: try encoding rules as last resort
            self._apply_encoding(insn, c)
            return c

        # --- memory ------------------------------------------------------
        if base in self.load:
            c.is_load = True
        if base in self.store:
            c.is_store = True
        for pfx, classes in self.prefix_classes.items():
            if base.startswith(pfx):
                if "load" in classes:
                    c.is_load = True
                if "store" in classes:
                    c.is_store = True

        # --- control flow --------------------------------------------------
        is_direct = base in self.direct_jump
        is_indirect = base in self.indirect_jump
        if base in self.cond_branch:
            c.is_cond_branch = True

        if base in self.indirect_if_reg and ops:
            first = _TOKEN_RE.findall(ops.split(",")[0])
            if first and (first[0].startswith("r") or first[0] in ("lr", "sp", self.pc_reg)):
                is_indirect, is_direct = True, False
            else:
                is_indirect, is_direct = False, True

        if is_direct or is_indirect:
            if conditional:
                c.is_cond_branch = True       # e.g. Thumb "bne", "bxne"
                c.is_indirect = is_indirect
            else:
                c.is_jump = True
                c.is_indirect = is_indirect

        # --- link (call) ----------------------------------------------------
        if base in self.no_link:
            # mnemonics whose FIRST operand is the transfer TARGET, not a
            # destination register (RISC-V "jr t0" = jalr x0,0(t0)): the
            # operand heuristic below would misread a link-register-named
            # target as a link write.  Millicode __riscv_save returns via
            # "jr t0" -- misclassifying it broke return matching and
            # inflated the save arc's inclusive cost with the caller body.
            c.writes_link = False
        elif self.link_convention == "mnemonic":
            c.writes_link = base in self.link_mnemonics
        else:  # operand
            if base in self.implied_link:
                c.writes_link = True
            elif (is_direct or is_indirect) and base in self.single_op_link:
                if "," not in ops:
                    c.writes_link = bool(ops)      # "jal off" / "jalr rs"
                else:
                    first = ops.split(",")[0].strip()
                    c.writes_link = first in self.link_registers
            elif is_direct or is_indirect:
                first = ops.split(",")[0].strip() if ops else ""
                c.writes_link = first in self.link_registers

        # --- returns --------------------------------------------------------
        if base in self.returns:
            c.is_return = True
        want = self.return_if_operand.get(base)
        if want is not None:
            flat = ops.replace(" ", "")
            if any(flat == w or flat.startswith(w) for w in want):
                c.is_return = True
                c.is_jump, c.is_indirect = (not conditional), True
                if conditional:
                    c.is_cond_branch = True

        # --- PC-writing instructions (Thumb: pop {pc}, ldr pc, ...) ---------
        if self.pc_write_enabled and not (c.is_jump or c.is_cond_branch):
            if self._writes_pc(base, ops):
                c.is_indirect = True
                if conditional:
                    c.is_cond_branch = True
                else:
                    c.is_jump = True
                if any(base.startswith(p) for p in self.pc_ret_prefixes):
                    c.is_return = True

        return c

    # ------------------------------------------------------------------
    def _normalize(self, m: str) -> str:
        for s in self.strip_suffixes:
            if m.endswith(s):
                m = m[: -len(s)]
        return m

    def _known(self, m: str) -> bool:
        if m in self.cond_branch or m in self.direct_jump or \
           m in self.indirect_jump or m in self.load or m in self.store or \
           m in self.returns or m in self.return_if_operand:
            return True
        return any(m.startswith(p) for p in self.prefix_classes)

    def _lookup_base(self, m: str) -> Optional[str]:
        return m if self._known(m) else None

    def _strip_cond(self, m: str) -> Optional[str]:
        for s in self.cond_suffixes:
            if m.endswith(s) and len(m) > len(s):
                base = m[: -len(s)]
                if self._known(base):
                    return base
        return None

    def _writes_pc(self, base: str, ops: str) -> bool:
        if not any(base.startswith(p)
                   for p in self.pc_ret_prefixes + self.pc_jmp_prefixes):
            return False
        toks = _TOKEN_RE.findall(ops)
        if self.pc_reg not in toks:
            return False
        if base.startswith(("ldr", "mov", "add")):
            return bool(toks) and toks[0] == self.pc_reg   # pc must be dest
        return True                                        # pop/ldm reglist

    def _apply_encoding(self, insn: Insn, c: InsnClass) -> bool:
        enc = insn.encoding
        if enc is None:
            return False
        for r in self.encodings:
            if (enc & r.mask) == r.match:
                for k in r.classes:
                    if k == "cond_branch":
                        c.is_cond_branch = True
                    elif k == "direct_jump":
                        c.is_jump = True
                    elif k == "indirect_jump":
                        c.is_jump = c.is_indirect = True
                    elif k == "load":
                        c.is_load = True
                    elif k == "store":
                        c.is_store = True
                    elif k == "call":
                        c.is_jump = c.writes_link = True
                    elif k == "return":
                        c.is_return = c.is_jump = c.is_indirect = True
                return True
        return False


# ----------------------------------------------------------------------
def _merge(base: dict, ext: dict) -> dict:
    out = dict(base)
    for k, v in ext.items():
        if k == "classes" and isinstance(v, dict):
            merged = {kk: list(vv) for kk, vv in base.get("classes", {}).items()}
            for kk, vv in v.items():
                merged.setdefault(kk, [])
                merged[kk] = list(dict.fromkeys(merged[kk] + list(vv)))
            out["classes"] = merged
        elif k in ("custom_encodings", "unknown_mnemonics") and isinstance(v, list):
            out[k] = list(base.get(k, [])) + list(v)
        elif k == "prefix_classes" and isinstance(v, dict):
            pc = dict(base.get("prefix_classes", {}))
            pc.update(v)
            out[k] = pc
        else:
            out[k] = v
    return out


def load_isa_spec(isa: str, ext_paths: Optional[List[str]] = None) -> dict:
    key = ISA_ALIASES.get(isa.lower())
    if key is None:
        avail = ", ".join(sorted(set(ISA_ALIASES.values())))
        raise ValueError(f"unsupported ISA '{isa}' (available: {avail})")
    with open(os.path.join(ISA_DIR, f"{key}.json")) as f:
        spec = json.load(f)
    for p in ext_paths or []:
        with open(p) as f:
            spec = _merge(spec, json.load(f))
    return spec


def get_classifier(isa: str, ext_paths: Optional[List[str]] = None) -> TableClassifier:
    return TableClassifier(load_isa_spec(isa, ext_paths))
