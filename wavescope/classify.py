"""Instruction classification: mnemonic -> event kind.

Given only the PC stream from a waveform, the *instruction identity* comes
from disassembly.  This module maps a disassembled instruction to the
event categories used by the profiler (branch / jump / call / load / store),
mirroring the simulator-side update_profile() pseudo code.

Default tables cover RISC-V (RV32/RV64 IMAFDC + pseudo-instructions as
emitted by binutils objdump).  Other ISAs can be added by implementing a
Classifier subclass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .disasm import Insn


@dataclass
class InsnClass:
    is_cond_branch: bool = False
    is_jump: bool = False          # unconditional control transfer
    is_indirect: bool = False      # target from register
    is_load: bool = False
    is_store: bool = False
    writes_link: bool = False      # rd == ra (call convention)
    is_return: bool = False        # ret / jr ra


class RiscvClassifier:
    COND_BRANCH = {
        "beq", "bne", "blt", "bge", "bltu", "bgeu",
        "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
        "bgt", "ble", "bgtu", "bleu",
        # compressed
        "c.beqz", "c.bnez",
    }
    DIRECT_JUMP = {"j", "jal", "c.j", "c.jal", "tail", "call"}
    INDIRECT_JUMP = {"jr", "jalr", "ret", "c.jr", "c.jalr", "mret", "sret", "uret"}
    LOAD = {
        "lb", "lh", "lw", "ld", "lbu", "lhu", "lwu",
        "flw", "fld", "flh", "flq",
        "c.lw", "c.ld", "c.lwsp", "c.ldsp", "c.flw", "c.fld",
        "c.flwsp", "c.fldsp",
        "lr.w", "lr.d",
    }
    STORE = {
        "sb", "sh", "sw", "sd",
        "fsw", "fsd", "fsh", "fsq",
        "c.sw", "c.sd", "c.swsp", "c.sdsp", "c.fsw", "c.fsd",
        "c.fswsp", "c.fsdsp",
        "sc.w", "sc.d",
    }
    # atomics touch memory both ways
    AMO_PREFIX = "amo"

    def classify(self, insn: Insn) -> InsnClass:
        m = insn.mnemonic
        ops = insn.operands
        c = InsnClass()

        if m in self.COND_BRANCH:
            c.is_cond_branch = True
            return c

        if m.startswith(self.AMO_PREFIX):
            c.is_load = True
            c.is_store = True
            return c

        if m in self.LOAD:
            c.is_load = True
            return c
        if m in self.STORE:
            c.is_store = True
            return c

        if m in ("ret", "c.jr", "jr"):
            c.is_jump = True
            c.is_indirect = True
            c.is_return = m == "ret" or ops.replace(" ", "") in ("ra",)
            if m == "ret":
                c.is_return = True
            return c

        if m in ("jalr", "c.jalr"):
            c.is_jump = True
            c.is_indirect = True
            # objdump forms: "jalr rd, off(rs)" | "jalr rs" (rd=ra implied)
            first = ops.split(",")[0].strip() if ops else ""
            if m == "c.jalr":
                c.writes_link = True
            elif "," not in ops:
                c.writes_link = True          # jalr rs  => rd = ra
                c.is_return = False
            else:
                c.writes_link = first == "ra"
                if first in ("zero", "x0"):
                    c.writes_link = False
            return c

        if m in ("jal", "c.jal"):
            c.is_jump = True
            first = ops.split(",")[0].strip() if ops else ""
            if m == "c.jal":
                c.writes_link = True
            elif "," not in ops:
                c.writes_link = True          # "jal offset" => rd = ra
            else:
                c.writes_link = first == "ra"
                if first in ("zero", "x0"):
                    c.writes_link = False
            return c

        if m in ("j", "c.j"):
            c.is_jump = True
            return c

        if m == "call":
            c.is_jump = True
            c.writes_link = True
            return c
        if m == "tail":
            c.is_jump = True
            return c
        if m in ("mret", "sret", "uret"):
            c.is_jump = True
            c.is_indirect = True
            c.is_return = True
            return c

        return c


def get_classifier(isa: str):
    if isa.lower() in ("riscv", "rv", "rv32", "rv64", "riscv32", "riscv64"):
        return RiscvClassifier()
    raise ValueError(f"unsupported ISA '{isa}' (currently: riscv)")
