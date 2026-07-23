"""v0.20.11: boot-boundary cycle clamp, ISA-generic idle (wfi/wfe)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profdata import E_CY
from wavescope.simcore import run_sim

CL = get_classifier("riscv")
CL_ARM = get_classifier("armv7m")


def _bin(prog, funcs, ):
    b = BinaryInfo()
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func(*f) for f in funcs]
    b._starts = [f.start for f in b.funcs]
    return b


class TestBootCycleClamp(unittest.TestCase):
    def test_first_instruction_takes_one_cycle(self):
        b = _bin([(0x100, 4, "addi", "a0,a0,1"),
                  (0x104, 4, "addi", "a1,a1,1"),
                  (0x108, 4, "addi", "a2,a2,1"),
                  (0x10c, 4, "j", "100")],
                 [("f", 0x100, 0x110)])
        # clock on at t=0; the core spends 5000 cycles in reset/fetch
        # (pc holds 0x100), then commits normally every cycle
        tr = [(0, 0x100), (5000, 0x104), (5001, 0x108), (5002, 0x10c)]
        prof = run_sim(iter(tr), b, CL)
        self.assertEqual(prof.self_cost[0x100][E_CY], 1)
        self.assertEqual(prof.self_cost[0x104][E_CY], 1)   # boot gap dropped
        self.assertEqual(prof.self_cost[0x108][E_CY], 1)
        self.assertEqual(prof.total[E_CY], 4)

    def test_later_gaps_still_charged(self):
        b = _bin([(0x100, 4, "addi", "a0,a0,1"),
                  (0x104, 4, "wfi", ""),
                  (0x108, 4, "addi", "a1,a1,1"),
                  (0x10c, 4, "j", "100")],
                 [("f", 0x100, 0x110)])
        tr = [(0, 0x100), (900, 0x104), (901, 0x108), (2000, 0x10c)]
        prof = run_sim(iter(tr), b, CL)
        self.assertEqual(prof.self_cost[0x104][E_CY], 1)   # boot clamp (n==1)
        self.assertEqual(prof.self_cost[0x10c][E_CY], 1099)  # sleep charged


class TestIdleIsaGeneric(unittest.TestCase):
    def test_riscv_wfi_flagged(self):
        b = _bin([(0x100, 4, "addi", "a0,a0,1"), (0x104, 4, "wfi", ""),
                  (0x108, 4, "j", "100")], [("f", 0x100, 0x10c)])
        tr = [(0, 0x100), (1, 0x104), (2, 0x108), (3, 0x100)]
        run_sim(iter(tr), b, CL)      # smoke: no exception
        self.assertIn("wfi", CL.idle_mnemonics)

    def test_arm_wfe_flagged(self):
        self.assertIn("wfe", CL_ARM.idle_mnemonics)
        self.assertIn("wfi", CL_ARM.idle_mnemonics)
        b = _bin([(0x100, 2, "adds", "r0,#1"), (0x102, 2, "wfe.n", ""),
                  (0x104, 2, "b", "100")], [("f", 0x100, 0x106)])
        tr = [(0, 0x100), (1, 0x102), (500, 0x104), (501, 0x100)]
        prof = run_sim(iter(tr), b, CL_ARM)
        # the flag reached the info via the .n-normalized mnemonic
        from wavescope.simcore import SimProfiler
        p = SimProfiler(b)
        idle = CL_ARM.idle_mnemonics
        a = p.infos_[0x102].assembly
        self.assertIn(a.split(None, 1)[0].split(".")[0], idle)


if __name__ == "__main__":
    unittest.main()
