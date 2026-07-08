"""Tail-call inclusive semantics, target-based taken judgement, and
trap detection at direct-transfer boundaries."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn, direct_target
from wavescope.profiler import (E_BC, E_BCM, E_CY, E_IR, run)


def B():
    b = BinaryInfo()
    prog = [
        # A
        (0x1000, "jal", "ra,2000 <b_fn>"),
        (0x1004, "addi", "a0,a0,1"),
        (0x1008, "j", "1008"),
        # B: does some work then TAIL-calls C
        (0x2000, "addi", "a1,a1,1"),
        (0x2004, "tail", "3000 <c_fn>"),
        # C: work then ret -> must return to A
        (0x3000, "addi", "a2,a2,1"),
        (0x3004, "addi", "a2,a2,2"),
        (0x3008, "ret", ""),
        # branch playground
        (0x4000, "beq", "a0,a1,4010 <target>"),
    ]
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("a_fn", 0x1000, 0x100c), Func("b_fn", 0x2000, 0x2008),
               Func("c_fn", 0x3000, 0x300c), Func("br", 0x4000, 0x4004)]
    b._starts = [f.start for f in b.funcs]
    return b


TRACE = [
    (0, 0x1000),   # A calls B
    (1, 0x2000),
    (2, 0x2004),   # B tail-calls C
    (3, 0x3000),
    (4, 0x3004),
    (5, 0x3008),   # C ret -> straight back to A (0x1004)
    (6, 0x1004),
    (7, 0x1008),
]


class TestTailInclusive(unittest.TestCase):
    def setUp(self):
        self.prof = run(iter(TRACE), B(), get_classifier("riscv"))

    def test_tail_arc_exists(self):
        self.assertIn((0x2004, 0x3000), self.prof.calls)

    def test_caller_inclusive_covers_tail_continuation(self):
        """A->B inclusive must include C's cost (callgrind semantics)."""
        key = (0x1000, 0x2000)                  # a_fn @0x1000 -> b_fn
        self.assertIn(key, self.prof.calls)
        inc = self.prof.calls[key].inclusive
        # B: 2 insns + C: 3 insns = 5
        self.assertEqual(inc[E_IR], 5)
        self.assertEqual(inc[E_CY], 5)

    def test_tail_arc_recorded(self):
        key = (0x2004, 0x3000)                  # b_fn @tail -> c_fn
        self.assertIn(key, self.prof.calls)
        self.assertEqual(self.prof.calls[key].count, 1)
        self.assertEqual(self.prof.calls[key].inclusive[E_IR], 3)  # C only

    def test_stack_fully_unwound(self):
        # after C's ret, A continues; nothing pending -> A never re-flushed
        self.assertEqual(self.prof.calls[(0x1000, 0x2000)].count, 1)


class TestTargetTaken(unittest.TestCase):
    def test_direct_target_parse(self):
        i = Insn(0x4000, 4, "beq", "a0,a1,4010 <target>")
        self.assertEqual(direct_target(i), 0x4010)
        i2 = Insn(0x1000, 4, "jal", "ra,2000 <b_fn>")
        self.assertEqual(direct_target(i2), 0x2000)
        i3 = Insn(0x1008, 4, "j", "1008")
        self.assertEqual(direct_target(i3), 0x1008)

    def test_taken_only_when_next_is_target(self):
        b = B()
        cl = get_classifier("riscv")
        # taken: next == 0x4010... use trace fragment on branch insn
        prof = run(iter([(0, 0x4000), (1, 0x4010)]), b, cl)
        # 0x4010 not in insns -> unknown, but branch itself counted
        self.assertEqual(prof.self_cost[0x4000][E_BC], 1)
        self.assertEqual(prof.self_cost[0x4000][E_BCM], 1)
        # not taken: next == fallthrough 0x4004
        prof2 = run(iter([(0, 0x4000), (1, 0x4004)]), b, cl)
        self.assertEqual(prof2.self_cost[0x4000][E_BC], 1)
        self.assertEqual(prof2.self_cost[0x4000][E_BCM], 0)

    def test_trap_at_branch_boundary(self):
        """next is neither target nor fallthrough -> exception, not taken."""
        b = B()
        prof = run(iter([(0, 0x4000), (1, 0x9000)]), b,
                   get_classifier("riscv"))
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.self_cost[0x4000][E_BCM], 0)

    def test_trap_at_direct_jump_boundary(self):
        b = B()
        # j 1008 (self-loop) but next commit lands in a handler
        prof = run(iter([(0, 0x1008), (1, 0x9000)]), b,
                   get_classifier("riscv"))
        self.assertEqual(prof.exceptions, 1)


if __name__ == "__main__":
    unittest.main()
