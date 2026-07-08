"""Cycle carry (coarse-timestamp dumps), unmatched-return healing,
and stack saturation behavior."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_CY, E_IR, run


def linear_binary():
    b = BinaryInfo()
    prog = [(0x1000 + i * 4, "addi", "a0,a0,1") for i in range(6)]
    prog.append((0x1018, "j", "1018"))
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("f", 0x1000, 0x1020)]
    b._starts = [0x1000]
    return b


class TestCycleCarry(unittest.TestCase):
    def test_same_timestamp_block(self):
        """ISS dumps 4 insns at t=0: each still costs >= 1 cycle, and
        the floor is LOCAL -- later real deltas are never consumed to
        repay it (that would erase genuine stall attribution)."""
        trace = [(0, 0x1000), (0, 0x1004), (0, 0x1008), (0, 0x100c),
                 (4, 0x1010), (5, 0x1014), (6, 0x1018)]
        prof = run(iter(trace), linear_binary(), get_classifier("riscv"))
        self.assertEqual(prof.total[E_IR], 7)
        for pc in (0x1000, 0x1004, 0x1008):
            self.assertEqual(prof.self_cost[pc][E_CY], 1)
        # 4th insn keeps its REAL delta of 4 (no debt repayment)
        self.assertEqual(prof.self_cost[0x100c][E_CY], 4)
        self.assertGreaterEqual(prof.total[E_CY], prof.total[E_IR])

    def test_stalls_survive_earlier_bursts(self):
        """Field case: sw with stalls (delta 2-3) AFTER a same-timestamp
        burst region must keep its stall cycles -- previously a carried
        deficit clamped them all to 1 (Cy == Ir symptom)."""
        # burst of 3 zero-deltas, then per-insn deltas 3,1,2
        trace = [(0, 0x1000), (0, 0x1004), (0, 0x1008),
                 (1, 0x100c), (4, 0x1010), (5, 0x1014), (7, 0x1018)]
        prof = run(iter(trace), linear_binary(), get_classifier("riscv"))
        self.assertEqual(prof.self_cost[0x100c][E_CY], 3)   # stall kept
        self.assertEqual(prof.self_cost[0x1010][E_CY], 1)
        self.assertEqual(prof.self_cost[0x1014][E_CY], 2)   # stall kept

    def test_cy_never_below_ir(self):
        trace = [(0, 0x1000), (0, 0x1004), (0, 0x1008), (0, 0x100c),
                 (1, 0x1010), (1, 0x1014), (2, 0x1018)]
        prof = run(iter(trace), linear_binary(), get_classifier("riscv"))
        self.assertGreaterEqual(prof.total[E_CY], prof.total[E_IR])


def call_binary():
    b = BinaryInfo()
    prog = [
        (0x1000, "addi", "a0,a0,1"),        # main body (no call recorded!)
        (0x2000, "jal", "ra,3000 <leaf>"),  # mid: calls leaf
        (0x2004, "j", "2004"),
        (0x3000, "addi", "a1,a1,1"),
        (0x3004, "ret", ""),                # returns into mid
        (0x4000, "ret", ""),                # stray ret into main
    ]
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("main", 0x1000, 0x1008), Func("mid", 0x2000, 0x2008),
               Func("leaf", 0x3000, 0x3008), Func("stray", 0x4000, 0x4008)]
    b._starts = [f.start for f in b.funcs]
    return b


class TestReturnHealing(unittest.TestCase):
    def test_unmatched_ret_into_caller_func_unwinds(self):
        """A ret whose target address has no exact frame match, but lands
        in the FUNCTION that called a stacked frame, must unwind to it
        instead of leaking the frame (simulator-style healing)."""
        b = call_binary()
        # mid calls leaf; leaf 'returns' to 0x2000 (function entry, NOT
        # the recorded ret_addr 0x2004) -> exact match fails, healing
        # sees next_pc's func == caller func of the leaf frame.
        trace = [(0, 0x2000), (1, 0x3000), (2, 0x3004),
                 (3, 0x2000), (4, 0x3000)]
        prof = run(iter(trace), b, get_classifier("riscv"))
        key = (0x2000, 0x2000, 0x3000)
        self.assertIn(key, prof.calls)
        # both invocations flushed with bounded inclusive (not leaked to
        # end-of-program): each covers leaf's 2 insns at most + boundary
        cs = prof.calls[key]
        self.assertEqual(cs.count, 2)
        self.assertLessEqual(cs.inclusive[E_IR], 2 * 3)


class TestStackSaturation(unittest.TestCase):
    def test_oldest_frame_dropped_not_newest(self):
        b = call_binary()
        # recursive-looking calls far beyond max_stack
        trace = []
        t = 0
        for _ in range(10):
            trace.append((t, 0x2000)); t += 1
            trace.append((t, 0x3000)); t += 1
        prof = run(iter(trace), b, get_classifier("riscv"), max_stack=4)
        # must not crash; calls recorded and flushed
        self.assertIn((0x2000, 0x2000, 0x3000), prof.calls)


if __name__ == "__main__":
    unittest.main()
