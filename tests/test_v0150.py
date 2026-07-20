"""v0.15.0: jal-entered millicode restore (tracked and untracked
callers), helper-ret unconditional pop, loop-closure helper exemption,
end-of-trace drain feeding _start's inclusive, simulator-diff output
format (event order, fl compression), multi-callee call sites, and the
inclusive-consistency checker."""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.callgrind import write as write_callgrind
from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import (E_CY, E_IR, inclusive_consistency, run)

CL = get_classifier("riscv")


def B():
    b = BinaryInfo()
    prog = [
        # _start
        (0x0500, "jal", "ra,1000 <main>"),
        (0x0504, "j", "504"),
        # main
        (0x1000, "addi", "a0,a0,1"),
        (0x1004, "jal", "ra,2000 <aa>"),
        (0x1008, "addi", "a0,a0,2"),
        (0x100c, "j", "100c"),
        # aa: body then jal-entered restore epilogue (the user's case)
        (0x2000, "addi", "s0,s0,1"),
        (0x2004, "addi", "s1,s1,1"),
        (0x2008, "jal", "3000 <__riscv_restore_0>"),   # jal ra, restore!
        # restore_0: lw x4, addi, ret  (6 insns, like the real one)
        (0x3000, "lw", "s1,4(sp)"),
        (0x3002, "lw", "s0,8(sp)"),
        (0x3004, "lw", "ra,12(sp)"),
        (0x3006, "lw", "t1,0(sp)"),
        (0x3008, "addi", "sp,sp,16"),
        (0x300a, "ret", ""),
        # bb: indirect call site with two targets
        (0x4000, "jalr", "ra,0(a5)"),
        (0x4004, "ret", ""),
        (0x5000, "addi", "a0,a0,3"),
        (0x5004, "ret", ""),
        (0x6000, "addi", "a0,a0,4"),
        (0x6004, "ret", ""),
    ]
    for a, m, o in prog:
        sz = 2 if 0x3000 <= a < 0x300c else 4
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func("_start", 0x500, 0x508), Func("main", 0x1000, 0x1010),
               Func("aa", 0x2000, 0x200c),
               Func("__riscv_restore_0", 0x3000, 0x300c),
               Func("bb", 0x4000, 0x4008), Func("t1_fn", 0x5000, 0x5008),
               Func("t2_fn", 0x6000, 0x6008)]
    b._starts = [f.start for f in b.funcs]
    return b


REST = [0x3000, 0x3002, 0x3004, 0x3006, 0x3008, 0x300a]


class TestJalRestoreTracked(unittest.TestCase):
    """aa entered by a tracked jal; its epilogue enters restore via
    `jal ra` (link!).  The restore ret lands at aa's caller: both the
    restore frame and aa's frame must close there, and the caller's
    view of aa (arc inclusive) must equal aa's self + outgoing."""

    TRACE = [(i, pc) for i, pc in enumerate(
        [0x0500, 0x1000, 0x1004,
         0x2000, 0x2004, 0x2008] + REST + [0x1008, 0x100c])]

    def setUp(self):
        self.prof = run(iter(self.TRACE), B(), CL)

    def test_restore_arc(self):
        cs = self.prof.calls[(0x2008, 0x3000)]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 6)

    def test_caller_view_equals_callee_total(self):
        # the user's item 6: arc(main->aa) must equal aa self (3) +
        # aa's outgoing (restore 6) = 9
        cs = self.prof.calls[(0x1004, 0x2000)]
        self.assertEqual(cs.inclusive[E_IR], 9)
        rows, roots = inclusive_consistency(self.prof, B())
        self.assertEqual(rows, [])           # fully consistent
        self.assertEqual(roots[0][0], "_start")

    def test_start_inclusive_is_maximal(self):
        # item 2: _start's inclusive (self + outgoing) tops everything
        cs = self.prof.calls[(0x0500, 0x1000)]
        # everything from main's entry on (main never returns; the
        # end-of-trace drain flushes its open frame)
        self.assertEqual(cs.inclusive[E_IR], len(self.TRACE) - 1)


class TestJalRestoreUntracked(unittest.TestCase):
    """Trace begins INSIDE aa (no caller frame).  The jal-pushed restore
    frame's ret_addr (jal+4) never commits; the helper-ret rule must
    close it AT the ret with exactly the 6-insn body -- previously it
    strand-accumulated until the end-of-trace drain."""

    TRACE = [(i, pc) for i, pc in enumerate(
        [0x2000, 0x2004, 0x2008] + REST
        + [0x1008, 0x100c] + [0x100c] * 4)]

    def test_arc_exact_and_clean(self):
        prof = run(iter(self.TRACE), B(), CL)
        cs = prof.calls[(0x2008, 0x3000)]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 6)      # NOT rest-of-trace
        self.assertEqual(cs.inclusive[E_CY], 6)
        self.assertEqual(prof.unmatched_returns, 0)  # helper-ret-pop
        self.assertEqual(prof.drained_frames, 0)


class TestDrainFeedsStart(unittest.TestCase):
    def test_trace_ends_mid_execution(self):
        # item 2: the waveform ends while deep in the call tree; the
        # drain must still flush every open frame's inclusive so
        # _start's outgoing arc covers the whole run
        trace = [(i, pc) for i, pc in enumerate(
            [0x0500, 0x1000, 0x1004, 0x2000, 0x2004])]  # ends inside aa
        prof = run(iter(trace), B(), CL)
        self.assertEqual(prof.calls[(0x0500, 0x1000)].inclusive[E_IR], 4)
        self.assertEqual(prof.calls[(0x1004, 0x2000)].inclusive[E_IR], 2)
        rows, roots = inclusive_consistency(prof, B())
        self.assertEqual(rows, [])


class TestOutputFormat(unittest.TestCase):
    def _text(self, prof):
        out = io.StringIO()
        write_callgrind(prof, out, "fw.elf")
        return out.getvalue()

    def test_event_order_and_no_bcm(self):
        prof = run(iter(TestJalRestoreTracked.TRACE), B(), CL)
        text = self._text(prof)
        self.assertIn("events: Ir Dr Dw Bc Bi Bim Cy\n", text)
        self.assertNotIn("Bcm", text)

    def test_fl_compression(self):
        prof = run(iter(TestJalRestoreTracked.TRACE), B(), CL)
        lines = self._text(prof).splitlines()
        fls = [ln for ln in lines if ln.startswith("fl=")]
        fns = [ln for ln in lines if ln.startswith("fn=")]
        # every function has the same (unknown) file: fl emitted ONCE
        self.assertEqual(len(fls), 1)
        self.assertGreater(len(fns), 3)

    def test_multi_callee_site_emits_both_calls(self):
        # bb's jalr hits t1_fn then t2_fn: two calls= lines at one pc
        trace = [(i, pc) for i, pc in enumerate(
            [0x4000, 0x5000, 0x5004,      # jalr -> t1_fn; ret
             0x4000, 0x6000, 0x6004,      # jalr -> t2_fn; ret
             0x4004])]
        prof = run(iter(trace), B(), CL)
        text = self._text(prof)
        self.assertIn("cfn=t1_fn\ncalls=1 0x5000 0\n", text)
        self.assertIn("cfn=t2_fn\ncalls=1 0x6000 0\n", text)


class TestConsistencyChecker(unittest.TestCase):
    def test_flags_inconsistent_function(self):
        prof = run(iter(TestJalRestoreTracked.TRACE), B(), CL)
        # sabotage: shrink the main->aa arc as if aa's frame was cut
        prof.calls[(0x1004, 0x2000)].inclusive[E_CY] -= 5
        rows, _ = inclusive_consistency(prof, B())
        # a wrong arc surfaces on BOTH sides: the callee (incoming too
        # small) and the caller (outgoing too small vs its incoming)
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["aa"]["d_cy"], -5)
        self.assertEqual(by_name["main"]["d_cy"], +5)


if __name__ == "__main__":
    unittest.main()
