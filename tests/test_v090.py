"""v0.9.0: -msave-restore millicode inclusive fix (jr t0 link
misclassification), jcnd=/jump= callgrind emission, DebugTrace,
in-text data symbol exclusion."""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.callgrind import write as write_callgrind
from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn, load_binary
from wavescope.profiler import DebugTrace, E_CY, E_IR, run

CL = get_classifier("riscv")


def millicode_binary():
    b = BinaryInfo()
    prog = [
        (0x1000, "jal", "ra,2000 <foo>"),
        (0x1004, "j", "1004"),
        # foo: -msave-restore prologue/epilogue
        (0x2000, "jal", "t0,5000 <__riscv_save_0>"),
        (0x2004, "addi", "s0,a0,1"),
        (0x2008, "addi", "s1,a1,1"),
        (0x200c, "jal", "ra,3000 <bar>"),
        (0x2010, "j", "5010 <__riscv_restore_0>"),   # tail
        # bar
        (0x3000, "addi", "a0,a0,2"),
        (0x3004, "ret", ""),
        # millicode
        (0x5000, "sw", "s0,4(sp)"),
        (0x5004, "sw", "s1,0(sp)"),
        (0x5008, "jr", "t0"),
        (0x5010, "lw", "s0,4(sp)"),
        (0x5014, "lw", "s1,0(sp)"),
        (0x5018, "ret", ""),
    ]
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("main", 0x1000, 0x1008), Func("foo", 0x2000, 0x2014),
               Func("bar", 0x3000, 0x3008),
               Func("__riscv_save_0", 0x5000, 0x500c),
               Func("__riscv_restore_0", 0x5010, 0x501c)]
    b._starts = [f.start for f in b.funcs]
    return b


MILLI_TRACE = [
    (0, 0x1000), (1, 0x2000), (2, 0x5000), (3, 0x5004), (4, 0x5008),
    (5, 0x2004), (6, 0x2008), (7, 0x200c), (8, 0x3000), (9, 0x3004),
    (10, 0x2010), (11, 0x5010), (12, 0x5014), (13, 0x5018), (14, 0x1004),
]


class TestMillicodeSaveRestore(unittest.TestCase):
    """__riscv_save is entered via `jal t0` and left via `jr t0`; its
    inclusive cost must be its OWN body only.  Before the no_link fix,
    `jr t0` was misread as writing a link, the return match never
    fired, and the caller's whole body flowed into the save arc."""

    def setUp(self):
        self.prof = run(iter(MILLI_TRACE), millicode_binary(), CL)

    def test_jr_t0_not_link(self):
        c = CL.classify(Insn(0, 4, "jr", "t0"))
        self.assertFalse(c.writes_link)
        self.assertTrue(c.is_indirect and c.is_jump)

    def test_save_arc_inclusive_is_body_only(self):
        cs = self.prof.calls[(0x2000, 0x5000)]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 3)       # sw, sw, jr t0

    def test_restore_tail_arc(self):
        cs = self.prof.calls[(0x2010, 0x5010)]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 3)

    def test_caller_arc_covers_everything(self):
        cs = self.prof.calls[(0x1000, 0x2000)]
        self.assertEqual(cs.count, 1)
        # foo(5) + save(3) + bar(2) + restore(3)
        self.assertEqual(cs.inclusive[E_IR], 13)

    def test_clean_unwind(self):
        self.assertEqual(self.prof.unmatched_returns, 0)
        self.assertEqual(self.prof.drained_frames, 0)
        self.assertEqual(self.prof.healed_returns, 0)


class TestJumpCollection(unittest.TestCase):
    def _binary(self):
        b = BinaryInfo()
        prog = [
            (0x1000, "addi", "a0,a0,1"),
            (0x1004, "beq", "a0,a1,100c <main+0xc>"),
            (0x1008, "j", "1000 <main>"),
            (0x100c, "ret", ""),
        ]
        for a, m, o in prog:
            b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
        b.funcs = [Func("main", 0x1000, 0x1010)]
        b._starts = [0x1000]
        return b

    TRACE = [(0, 0x1000), (1, 0x1004), (2, 0x1008), (3, 0x1000),
             (4, 0x1004), (5, 0x100c)]

    def test_cond_and_uncond_maps(self):
        prof = run(iter(self.TRACE), self._binary(), CL)
        self.assertEqual(prof.cond_jumps[(0x1004, 0x100c)], 1)
        self.assertEqual(prof.uncond_jumps[(0x1008, 0x1000)], 1)

    def test_callgrind_emission(self):
        prof = run(iter(self.TRACE), self._binary(), CL)
        out = io.StringIO()
        write_callgrind(prof, out, "fw.elf")
        lines = out.getvalue().splitlines()
        # split branch: cost line first, then each jcnd= followed by a
        # position-only line; per-direction counts sum to the executions
        i = next(k for k, l in enumerate(lines) if l.startswith("0x1004 0 2 "))
        self.assertEqual(sorted(lines[i + 1:i + 5]),
                         sorted(["jcnd=1/2 0x1008 0", "0x1004 0",
                                 "jcnd=1/2 0x100c 0", "0x1004 0"]))
        self.assertTrue(lines[i + 1].startswith("jcnd="))
        self.assertEqual(lines[i + 2], "0x1004 0")
        j = lines.index("jump=1 0x1000 0")
        self.assertTrue(lines[j - 1].startswith("0x1008 0 "))
        self.assertEqual(lines[j + 1], "0x1008 0")

    def test_branch_both_directions_recorded(self):
        prof = run(iter(self.TRACE), self._binary(), CL)
        # 2 executions: one fall-through (0x1008), one taken (0x100c)
        self.assertEqual(prof.cond_jumps[(0x1004, 0x1008)], 1)
        self.assertEqual(prof.cond_jumps[(0x1004, 0x100c)], 1)

    def test_full_coverage_zero_lines(self):
        # never-executed instructions of the ELF appear at zero cost
        # (coverage: distinguishes unexecuted code from compiled-out code)
        b = self._binary()
        b.insns[0x1010] = Insn(0x1010, 4, "nop", "")
        b.funcs[0].end = 0x1014
        prof = run(iter(self.TRACE), b, CL)
        out = io.StringIO()
        write_callgrind(prof, out, "fw.elf")
        self.assertIn("0x1010 0 0 0 0 0 0 0 0\n", out.getvalue())
        out2 = io.StringIO()
        write_callgrind(prof, out2, "fw.elf", all_functions=False)
        self.assertNotIn("0x1010 0 0", out2.getvalue())

    def test_interrupted_branch_not_recorded(self):
        # heuristic ISR entry between beq and its landing: no jcnd entry
        b = self._binary()
        b.funcs.append(Func("isr", 0x9000, 0x9008))
        b._starts.append(0x9000)
        b.insns[0x9000] = Insn(0x9000, 4, "mret", "")
        trace = [(0, 0x1000), (1, 0x1004), (2, 0x9000), (3, 0x100c)]
        prof = run(iter(trace), b, CL)
        self.assertEqual(len(prof.cond_jumps), 0)


class TestDebugTrace(unittest.TestCase):
    def test_events_and_summary(self):
        b = millicode_binary()
        save = next(f for f in b.funcs if f.name == "__riscv_save_0")
        out = io.StringIO()
        dbg = DebugTrace(b, [save], out)
        prof = run(iter(MILLI_TRACE), b, CL, debug=dbg)
        log = out.getvalue()
        self.assertIn("push CALL foo -> __riscv_save_0 ret=0x2004", log)
        self.assertIn("commit __riscv_save_0+0x8 jr", log)
        self.assertIn("ret-match jr@0x5008", log)
        self.assertIn("arc n=1 Ir=3", log)
        self.assertIn("__riscv_save_0: self Ir=3", log)
        self.assertIn("TOTAL incoming: n=1 Ir=3", log)
        # the debug accumulator must agree with the profile
        self.assertEqual(dbg.acc[save.start][E_IR], 3)
        self.assertEqual(prof.calls[(0x2000, 0x5000)].inclusive[E_CY],
                         dbg.acc[save.start][E_CY])

    def test_zero_overhead_when_disabled(self):
        prof = run(iter(MILLI_TRACE), millicode_binary(), CL)
        self.assertIsNone(prof.debug)


HAVE_CC = shutil.which("gcc") and shutil.which("objdump")


@unittest.skipUnless(HAVE_CC, "host gcc/objdump not available")
class TestDataSymbolExclusion(unittest.TestCase):
    """In-text data objects (CSWTCH.* switch tables, const arrays the
    compiler places in .text) get objdump -d labels but must not become
    functions."""

    def test_object_symbols_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "t.c")
            elf = os.path.join(d, "t.elf")
            with open(src, "w") as f:
                f.write("""
__attribute__((section(".text"), used, aligned(4)))
static const int CSWTCH_74[4] = {1, 2, 3, 4};
int leaf(int x) { return x + CSWTCH_74[x & 3]; }
int main(void) { return leaf(1); }
""")
            subprocess.run(["gcc", "-g", "-O0", "-o", elf, src], check=True)
            b = load_binary(elf, with_lines=False)
            names = {f.name for f in b.funcs}
            self.assertIn("main", names)
            self.assertIn("leaf", names)
            self.assertNotIn("CSWTCH_74", names)
            self.assertIn("CSWTCH_74", set(b.data_syms.values()))
            # no function range may cover the data blob
            addr = next(a for a, n in b.data_syms.items()
                        if n == "CSWTCH_74")
            self.assertIsNone(b.func_at(addr))


if __name__ == "__main__":
    unittest.main()
