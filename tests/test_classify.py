"""Classifier tests for the table-driven engine: RISC-V, Thumb-2 (Cortex-M),
AArch64, and custom-instruction overlays."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import Insn


def I(mnem, ops="", enc=None, size=4):
    return Insn(addr=0x1000, size=size, mnemonic=mnem, operands=ops,
                encoding=enc)


class TestRiscv(unittest.TestCase):
    def setUp(self):
        self.c = get_classifier("riscv")

    def test_basics(self):
        self.assertTrue(self.c.classify(I("beq", "a0,a1,1014")).is_cond_branch)
        self.assertTrue(self.c.classify(I("lw", "a0,0(sp)")).is_load)
        self.assertTrue(self.c.classify(I("sw", "a0,0(sp)")).is_store)
        amo = self.c.classify(I("amoswap.w", "a0,a1,(a2)"))
        self.assertTrue(amo.is_load and amo.is_store)

    def test_call_link(self):
        c = self.c.classify(I("jal", "ra,2000 <f>"))
        self.assertTrue(c.is_jump and c.writes_link and not c.is_indirect)
        c = self.c.classify(I("jal", "2000 <f>"))       # single-operand form
        self.assertTrue(c.writes_link)
        c = self.c.classify(I("jalr", "a5"))            # jalr rs => rd=ra
        self.assertTrue(c.is_indirect and c.writes_link)
        c = self.c.classify(I("jal", "zero,2000"))
        self.assertFalse(c.writes_link)

    def test_ret(self):
        c = self.c.classify(I("ret"))
        self.assertTrue(c.is_return and c.is_indirect)


class TestThumb(unittest.TestCase):
    def setUp(self):
        self.c = get_classifier("armv7m")

    def test_cond_branch_suffix(self):
        for m in ("beq.n", "bne.w", "bhi", "bls"):
            c = self.c.classify(I(m, "800012c <f>", size=2))
            self.assertTrue(c.is_cond_branch, m)
            self.assertFalse(c.is_jump, m)
        self.assertTrue(self.c.classify(I("cbz", "r0,8000100")).is_cond_branch)

    def test_uncond_and_call(self):
        c = self.c.classify(I("b.n", "8000200 <loop>", size=2))
        self.assertTrue(c.is_jump and not c.is_indirect and not c.writes_link)
        c = self.c.classify(I("bl", "8000300 <func>"))
        self.assertTrue(c.is_jump and c.writes_link)
        c = self.c.classify(I("blx", "r3", size=2))     # register: indirect call
        self.assertTrue(c.is_indirect and c.writes_link)

    def test_conditional_call(self):
        c = self.c.classify(I("bleq", "8000300 <func>"))
        self.assertTrue(c.is_cond_branch and c.writes_link)

    def test_returns(self):
        c = self.c.classify(I("bx", "lr", size=2))
        self.assertTrue(c.is_return and c.is_indirect and c.is_jump)
        c = self.c.classify(I("pop", "{r4, r5, pc}", size=2))
        self.assertTrue(c.is_return and c.is_jump and c.is_indirect)
        self.assertTrue(c.is_load)
        c = self.c.classify(I("mov", "pc, lr", size=2))
        self.assertTrue(c.is_return)

    def test_pc_write_jump(self):
        c = self.c.classify(I("ldr.w", "pc, [r2, r0, lsl #2]"))  # switch table
        self.assertTrue(c.is_jump and c.is_indirect and c.is_load)
        self.assertFalse(c.is_return)
        c = self.c.classify(I("ldr", "r0, [r1]", size=2))        # plain load
        self.assertTrue(c.is_load and not c.is_jump)

    def test_mem(self):
        self.assertTrue(self.c.classify(I("ldmia.w", "r0!, {r1,r2}")).is_load)
        self.assertTrue(self.c.classify(I("push", "{r4, lr}", size=2)).is_store)
        self.assertTrue(self.c.classify(I("strb", "r0, [r1]", size=2)).is_store)
        self.assertTrue(self.c.classify(I("ldreq", "r0, [r1]")).is_load)

    def test_table_branch(self):
        c = self.c.classify(I("tbb", "[pc, r0]"))
        self.assertTrue(c.is_jump and c.is_indirect)


class TestAarch64(unittest.TestCase):
    def setUp(self):
        self.c = get_classifier("aarch64")

    def test_control(self):
        self.assertTrue(self.c.classify(I("b.ne", "400123 <f>")).is_cond_branch)
        self.assertTrue(self.c.classify(I("cbz", "x0, 400200")).is_cond_branch)
        self.assertTrue(self.c.classify(I("tbnz", "w0, #3, 400200")).is_cond_branch)
        c = self.c.classify(I("bl", "400300 <func>"))
        self.assertTrue(c.is_jump and c.writes_link and not c.is_indirect)
        c = self.c.classify(I("blr", "x3"))
        self.assertTrue(c.is_jump and c.writes_link and c.is_indirect)
        c = self.c.classify(I("ret"))
        self.assertTrue(c.is_return and c.is_indirect)
        c = self.c.classify(I("br", "x16"))
        self.assertTrue(c.is_jump and c.is_indirect and not c.writes_link)

    def test_mem(self):
        self.assertTrue(self.c.classify(I("ldp", "x29, x30, [sp], #16")).is_load)
        self.assertTrue(self.c.classify(I("stp", "x29, x30, [sp, #-16]!")).is_store)
        self.assertTrue(self.c.classify(I("ldrsw", "x0, [x1]")).is_load)
        self.assertTrue(self.c.classify(I("stur", "w0, [x1, #-4]")).is_store)


class TestCustomExt(unittest.TestCase):
    def test_mnemonic_overlay(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump({"classes": {"load": ["cust.vld"],
                                   "store": ["cust.vst"]}}, f)
            path = f.name
        try:
            c = get_classifier("riscv", [path])
            self.assertTrue(c.classify(I("cust.vld", "v0,(a0)")).is_load)
            self.assertTrue(c.classify(I("cust.vst", "v0,(a0)")).is_store)
            # base tables still intact
            self.assertTrue(c.classify(I("lw", "a0,0(sp)")).is_load)
        finally:
            os.unlink(path)

    def test_encoding_overlay(self):
        # custom-0 opcode space (0x0b): objdump shows ".word"
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump({"custom_encodings": [
                {"name": "cust_dma_ld", "mask": "0x7f", "match": "0x0b",
                 "classes": ["load"], "size": 4}]}, f)
            path = f.name
        try:
            c = get_classifier("riscv", [path])
            unk = I(".word", "0x0000200b", enc=0x0000200B)
            cls = c.classify(unk)
            self.assertTrue(cls.is_load)
            other = I(".word", "0xdeadbeef", enc=0xDEADBEEF)
            self.assertFalse(c.classify(other).is_load)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
