"""v0.20.9: A9 empty-stack tail frames (the reported ISR `j`-dispatch
inclusive loss) and auipc Bi/Bim parity."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profdata import E_BI, E_BIM, E_IR
from wavescope.simcore import run_sim

CL = get_classifier("riscv")


def isr_dispatch_binary():
    """The user-reported shape: FUNC_WFI wfi-loops; ISR_A (under a
    stub) dispatches FUNC_A then FUNC_B with plain `j` (tail) on the
    fresh ISR stack; the workers come back with computed jumps."""
    b = BinaryInfo()
    prog = [
        (0x300, 4, "addi", "a0,a0,1"),                 # FUNC_WFI
        (0x304, 4, "wfi", ""),
        (0x308, 4, "j", "300"),
        (0x900, 4, "addi", "t2,t2,1"),   # ISR_A: DIRECT vector entry
        (0x904, 4, "j", "c00 <FUNC_A>"),  # (no stub jal -> the handler
        (0x908, 4, "j", "d00 <FUNC_B>"),  #  itself is FRAMELESS, so
        (0x90c, 4, "mret", ""),           #  tails land on depth 0)
        (0xc00, 4, "addi", "a3,a3,1"),                 # FUNC_A
        (0xc04, 4, "addi", "a4,a4,1"),
        (0xc08, 4, "jr", "a5"),                        # computed return
        (0xd00, 4, "addi", "a6,a6,1"),                 # FUNC_B
        (0xd04, 4, "jr", "a5"),
    ]
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func("FUNC_WFI", 0x300, 0x30c),
               Func("ISR_A", 0x900, 0x910),
               Func("FUNC_A", 0xc00, 0xc0c),
               Func("FUNC_B", 0xd00, 0xd08)]
    b._starts = [f.start for f in b.funcs]
    return b


ISR_PASS = [0x900, 0x904,
            0xc00, 0xc04, 0xc08,       # FUNC_A, jr a5 -> ISR_A@0x908
            0x908,
            0xd00, 0xd04,              # FUNC_B, jr a5 -> ISR_A@0x90c
            0x90c]                     # mret


def stream():
    R = 0x308                          # wfi resume; SAME for both irqs
    flow = [(0x300, 0x111), (0x304, 0x111)]
    flow += [(pc, R) for pc in ISR_PASS]           # 1st: epc change
    flow += [(0x308, R), (0x300, R), (0x304, R)]
    flow += [(pc, R) for pc in ISR_PASS]           # 2nd: A4 forced
    flow += [(0x308, R), (0x300, R)]
    return [(10 + 7 * i, pc, e) for i, (pc, e) in enumerate(flow)]


class TestIsrTailDispatch(unittest.TestCase):
    def setUp(self):
        self.prof = run_sim(iter(stream()), isr_dispatch_binary(), CL,
                            trace_roots=4,
                            debug_funcs={"FUNC_A", "FUNC_B"})

    def test_worker_arcs_have_inclusive(self):
        # BOTH interrupt passes, including the A4-forced second one
        a = self.prof.calls[(0x904, 0xc00)]
        self.assertEqual(a.count, 2)
        self.assertEqual(a.inclusive[E_IR], 2 * 3)     # FUNC_A body x2
        bb = self.prof.calls[(0x908, 0xd00)]
        self.assertEqual(bb.count, 2)
        self.assertEqual(bb.inclusive[E_IR], 2 * 2)    # FUNC_B body x2

    def test_tail_frames_synthesized_no_noframe(self):
        kinds = self.prof.root_log["n"]
        self.assertNotIn("tail-noframe", kinds)
        self.assertGreaterEqual(self.prof.tail_frames, 2)

    def test_func_trace_shows_pops(self):
        evs = self.prof.func_log["ev"]
        pops = [e for e in evs if e[1] == "pop" and e[3] in (0xc00, 0xd00)]
        self.assertGreaterEqual(len(pops), 4)          # 2 workers x 2 irqs

    def test_no_zero_inclusive_anywhere(self):
        for (cp, ce), cs in self.prof.calls.items():
            if cs.count:
                self.assertGreater(cs.inclusive[E_IR], 0,
                                   f"arc {hex(cp)}->{hex(ce)}")


class TestAuipcBranchEvents(unittest.TestCase):
    def test_auipc_counts_no_branch_events(self):
        # v0.20.10: the v0.20.9 auipc->Bi/Bim rule was withdrawn (the
        # user confirmed their simulator does NOT count it; it was
        # confused with something else) -- auipc is a plain ALU insn
        b = BinaryInfo()
        prog = [(0x100, 4, "auipc", "t1,0xf1000"),
                (0x104, 4, "addi", "a0,a0,1"),
                (0x108, 4, "j", "100")]
        for a, sz, m, o in prog:
            b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
        b.funcs = [Func("f", 0x100, 0x10c)]
        b._starts = [0x100]
        tr = [(0, 0x100), (1, 0x104), (2, 0x108), (3, 0x100), (4, 0x104)]
        prof = run_sim(iter(tr), b, CL)
        self.assertEqual(prof.self_cost[0x100][E_BI], 0)
        self.assertEqual(prof.self_cost[0x100][E_BIM], 0)
        self.assertEqual(prof.self_cost[0x104][E_BI], 0)
        self.assertEqual(prof.self_cost[0x104][E_BIM], 0)


if __name__ == "__main__":
    unittest.main()
