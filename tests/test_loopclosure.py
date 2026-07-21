"""Loops whose backward edge targets another asm label (= function entry
in the label-union universe) must not stack one frame per iteration."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_IR, run


def B():
    b = BinaryInfo()
    prog = [
        (0x1000, "jal", "ra,2000 <outer>"),
        (0x1004, "j", "1004"),
        # outer: falls into .Lloop_lbl (an asm label => its own "func")
        (0x2000, "addi", "a0,a0,4"),
        # loop_lbl:
        (0x2004, "sw", "a1,0(a0)"),
        (0x2008, "addi", "a2,a2,-1"),
        (0x200c, "bnez", "a2,2004 <loop_lbl>"),   # backward to the label
        (0x2010, "ret", ""),
    ]
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("main", 0x1000, 0x1008),
               Func("outer", 0x2000, 0x2004),
               Func("loop_lbl", 0x2004, 0x2014)]
    b._starts = [f.start for f in b.funcs]
    return b


def make_trace(n_iter):
    t = 0
    tr = [(t, 0x1000)]
    t += 1
    tr.append((t, 0x2000)); t += 1
    for _ in range(n_iter):
        for pc in (0x2004, 0x2008, 0x200c):
            tr.append((t, pc)); t += 1
    tr.append((t, 0x2010)); t += 1
    tr.append((t, 0x1004)); t += 1
    return tr


class TestLoopClosure(unittest.TestCase):
    def test_bounded_inclusive(self):
        n = 200
        prof = run(iter(make_trace(n)), B(), get_classifier("riscv"))
        # loop body executed n times
        self.assertEqual(prof.self_cost[0x2004][E_IR], n)
        # sum of ALL arc inclusives must stay linear in n, not O(n^2):
        total_incl = sum(cs.inclusive[E_IR] for cs in prof.calls.values())
        self.assertLess(total_incl, 12 * n,
                        f"inclusive sum {total_incl} suggests per-iteration "
                        f"frame stacking")
        # simulator parity (v0.19.0): fall-through into the label makes
        # NO arc; the loop's cost stays inside the caller's open frame,
        # so main->outer absorbs everything and loop_lbl is a root with
        # self only
        self.assertNotIn((0x2000, 0x2004), prof.calls)
        self.assertEqual(prof.calls[(0x1000, 0x2000)].inclusive[E_IR],
                         3 * n + 2)   # outer entry + loop body + ret

    def test_stack_stays_bounded(self):
        prof = run(iter(make_trace(500)), B(), get_classifier("riscv"),
                   max_stack=32)
        self.assertLessEqual(prof.drained_frames, 4)


if __name__ == "__main__":
    unittest.main()
