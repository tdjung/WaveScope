"""EPC (mepc) signal parsing: exact ISR entry/exit, deferred resolution
of interrupted branches, nested interrupts, WFI wake without an epc
change, spurious same-function epc suppression, and the multi-signal
VCD extraction path."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_BCM, E_CY, E_IR, run
from wavescope.vcd_reader import changes_to_ticks, iter_commit_changes


def B():
    b = BinaryInfo()
    prog = [
        # main
        (0x1000, "addi", "a0,a0,1"),
        (0x1004, "wfi", ""),
        (0x1008, "beq", "a0,a1,1010 <lbl>"),   # cond branch, target 0x1010
        (0x100c, "addi", "a1,a1,1"),
        (0x1010, "jalr", "ra,0(a2)"),           # indirect call
        (0x1014, "j", "1014"),
        # callee (reached via jalr)
        (0x2000, "addi", "a3,a3,1"),
        (0x2004, "ret", ""),
        # isr
        (0x3000, "addi", "t0,t0,1"),
        (0x3004, "jal", "ra,4000 <helper>"),
        (0x3008, "mret", ""),
        # helper
        (0x4000, "addi", "a2,a2,1"),
        (0x4004, "ret", ""),
        # isr2 (nested)
        (0x5000, "addi", "t1,t1,1"),
        (0x5004, "mret", ""),
    ]
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("main", 0x1000, 0x1018), Func("callee", 0x2000, 0x2008),
               Func("isr", 0x3000, 0x300c), Func("helper", 0x4000, 0x4008),
               Func("isr2", 0x5000, 0x5008)]
    b._starts = [f.start for f in b.funcs]
    return b


CL = get_classifier("riscv")


class TestEpcEntryExit(unittest.TestCase):
    """Interrupt right after an INDIRECT jump -- undetectable by the
    heuristic (landing could be anywhere), exact with epc."""

    # jalr at 0x1010 commits; before its target (0x2000) commits, an
    # interrupt fires: mepc <- 0x2000, handler runs, mret, then 0x2000.
    TRACE = [
        (0, 0x1008, 0),           # beq ...
        (1, 0x100c, 0),           # ... not taken (a0!=a1)
        (3, 0x1010, 0),           # jalr (indirect call)
        (4, 0x3000, 0x2000),      # ISR entry: mepc changed to 0x2000
        (5, 0x3004, 0x2000),
        (6, 0x4000, 0x2000),
        (7, 0x4004, 0x2000),
        (8, 0x3008, 0x2000),      # mret
        (9, 0x2000, 0x2000),      # resume: pc == saved epc
        (10, 0x2004, 0x2000),     # ret
        (11, 0x1014, 0x2000),
    ]

    def setUp(self):
        self.prof = run(iter(self.TRACE), B(), CL)

    def test_entry_detected(self):
        self.assertTrue(self.prof.epc_mode)
        self.assertEqual(self.prof.exceptions, 1)
        self.assertEqual(self.prof.isr_open, 0)

    def test_interrupted_call_resolved_at_resume(self):
        # the jalr's call arc must exist DESPITE the interrupt in between:
        # its resolution was saved at entry and replayed at pc==epc
        self.assertIn((0x1010, 0x2000), self.prof.calls)
        self.assertEqual(self.prof.calls[(0x1010, 0x2000)].count, 1)

    def test_callee_return_matches(self):
        # ret at 0x2004 -> 0x1014 pops the frame pushed at resume
        self.assertEqual(self.prof.unmatched_returns, 0)
        self.assertEqual(self.prof.drained_frames, 0)

    def test_handler_call_tracked(self):
        self.assertIn((0x3004, 0x4000), self.prof.calls)

    def test_no_flow_anomalies(self):
        # every discontinuity is explained by the ISR
        self.assertEqual(self.prof.flow_anomalies, 0)

    def test_isr_cycles_clamped(self):
        self.assertEqual(self.prof.self_cost[0x3000][E_CY], 1)


class TestEpcBranchDeferral(unittest.TestCase):
    """A cond branch interrupted mid-flight must be judged against the
    TRUE landing after mret, not the handler address."""

    TRACE = [
        (0, 0x100c, 0),
        (1, 0x1008, 0),           # beq commits; interrupt before landing
        (2, 0x3000, 0x1010),      # mepc = the branch TARGET (it was taken)
        (3, 0x3008, 0x1010),      # mret
        (4, 0x1010, 0x1010),      # resume at target -> branch WAS taken
        (5, 0x1014, 0x1010),
    ]

    def test_bcm_charged_from_true_landing(self):
        prof = run(iter(self.TRACE), B(), CL)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.self_cost[0x1008][E_BCM], 1)

    def test_bcm_not_charged_when_fallthrough(self):
        trace = [
            (0, 0x100c, 0),
            (1, 0x1008, 0),
            (2, 0x3000, 0x100c),   # mepc = fallthrough: NOT taken
            (3, 0x3008, 0x100c),
            (4, 0x100c, 0x100c),
            (5, 0x1010, 0x100c),
        ]
        prof = run(iter(trace), B(), CL)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.self_cost[0x1008][E_BCM], 0)


class TestEpcNested(unittest.TestCase):
    """Nested interrupt: inner mepc change while inside a handler."""

    TRACE = [
        (0, 0x1000, 0),
        (1, 0x100c, 0),
        (2, 0x3000, 0x1010),      # ISR1: mepc = 0x1010
        (3, 0x3004, 0x1010),
        (4, 0x4000, 0x1010),      # inside helper (frame open)
        (5, 0x5000, 0x4004),      # ISR2 (nested): mepc = 0x4004
        (6, 0x5004, 0x4004),      # mret
        (7, 0x4004, 0x4004),      # resume ISR1 at saved epc
        (8, 0x3008, 0x1010),      # sw restored mepc (isr epilogue); mret
        (9, 0x1010, 0x1010),      # resume main at ISR1's saved epc
        (10, 0x1014, 0x1010),
    ]

    def test_two_entries_two_exits(self):
        prof = run(iter(self.TRACE), B(), CL)
        self.assertEqual(prof.exceptions, 2)
        self.assertEqual(prof.isr_open, 0)
        # helper call frame survived the nested interrupt and closed
        self.assertIn((0x3004, 0x4000), prof.calls)
        self.assertEqual(prof.drained_frames, 0)


class TestEpcWfiWake(unittest.TestCase):
    """Back-to-back wakeups from the SAME wfi: mepc is rewritten with an
    identical value, so entry must come from the wfi-wake rule
    (is_wfi && after_wfi && different function)."""

    TRACE = [
        (0, 0x1000, 0x1008),      # stale mepc from an earlier trap
        (1, 0x1004, 0x1008),      # wfi
        (90, 0x3000, 0x1008),     # wake: mepc UNCHANGED (same value)
        (91, 0x3008, 0x1008),     # mret
        (92, 0x1008, 0x1008),     # resume
        (93, 0x100c, 0x1008),
    ]

    def test_wake_detected_without_epc_change(self):
        prof = run(iter(self.TRACE), B(), CL)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.isr_open, 0)
        # sleep gap clamped to 1 on the first handler insn
        self.assertEqual(prof.self_cost[0x3000][E_CY], 1)
        self.assertEqual(prof.self_cost[0x1008][E_IR], 1)


class TestEpcSpurious(unittest.TestCase):
    """An mepc change whose value lands in the SAME function as the
    current pc is spurious (simulator epc_error_check): no ISR entry."""

    TRACE = [
        (0, 0x1000, 0),
        (1, 0x100c, 0x1008),      # mepc changed but 0x1008 is in main too
        (2, 0x1010, 0x1008),
        (3, 0x2000, 0x1008),      # jalr target commits normally
        (4, 0x2004, 0x1008),
        (5, 0x1014, 0x1008),
    ]

    def test_suppressed(self):
        prof = run(iter(self.TRACE), B(), CL)
        self.assertEqual(prof.exceptions, 0)
        self.assertEqual(prof.spurious_epc, 1)
        # normal profiling continued: jalr call arc intact
        self.assertIn((0x1010, 0x2000), prof.calls)


class TestFlowAnomalyDiagnostic(unittest.TestCase):
    """In epc mode, a discontinuity with NO mepc change is counted as an
    anomaly (speculative PC pollution) instead of a fake ISR."""

    TRACE = [
        (0, 0x1000, 0),
        (1, 0x2000, 0),           # 0x1000 falls to 0x1004, not 0x2000
        (2, 0x2004, 0),
        (3, 0x1014, 0),           # ret -> 0x1014 (unmatched, healed or not)
    ]

    def test_counted_not_treated_as_isr(self):
        prof = run(iter(self.TRACE), B(), CL)
        self.assertEqual(prof.exceptions, 0)
        self.assertEqual(prof.flow_anomalies, 1)


class TestHeuristicStillWorks(unittest.TestCase):
    """2-tuple streams keep the old heuristic behavior untouched."""

    def test_plain_stream(self):
        trace = [(0, 0x1000), (1, 0x1004), (95, 0x3000), (96, 0x3004),
                 (97, 0x4000), (98, 0x4004), (99, 0x3008),
                 (100, 0x1008), (101, 0x100c)]
        prof = run(iter(trace), B(), CL)
        self.assertFalse(prof.epc_mode)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.self_cost[0x3000][E_CY], 1)


class TestVcdMultiExtraction(unittest.TestCase):
    """iter_commit_changes attaches the epc value in effect after ALL
    changes at the commit timestamp (same-cycle trap visibility)."""

    VCD = """$timescale 1ns $end
$scope module top $end
$var wire 32 ! pc [31:0] $end
$var wire 32 " mepc [31:0] $end
$upscope $end
$enddefinitions $end
#0
b1000 !
bx "
#10
b1010 !
#20
b11000000000000 !
b1010000000000 "
#30
b11000000000100 !
"""

    def _samples(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".vcd",
                                         delete=False) as f:
            f.write(text)
            path = f.name
        try:
            return list(iter_commit_changes(path, "pc", aux_names=("mepc",)))
        finally:
            os.unlink(path)

    def test_same_timestamp_epc_visible(self):
        out = self._samples(self.VCD)
        # (t, pc, epc): epc is None while x, then 0x1400 at the SAME
        # timestamp as the redirect to 0x3000
        self.assertEqual(out[0], (0, 0b1000, None))
        self.assertEqual(out[1], (10, 0b1010, None))
        self.assertEqual(out[2], (20, 0x3000, 0x1400))
        self.assertEqual(out[3], (30, 0x3004, 0x1400))

    def test_epc_dumped_before_pc_same_result(self):
        flipped = self.VCD.replace(
            "b11000000000000 !\nb1010000000000 \"",
            "b1010000000000 \"\nb11000000000000 !")
        self.assertEqual(self._samples(flipped)[2], (20, 0x3000, 0x1400))

    def test_ticks_carry_aux(self):
        out = self._samples(self.VCD)
        period, gen = changes_to_ticks(iter(out))
        ticks = list(gen)
        self.assertEqual(period, 10)
        self.assertEqual(ticks[2], (2, 0x3000, 0x1400))


class TestVcdClockedMulti(unittest.TestCase):
    VCD = """$timescale 1ns $end
$scope module top $end
$var wire 1 c clk $end
$var wire 32 ! pc [31:0] $end
$var wire 32 " mepc [31:0] $end
$upscope $end
$enddefinitions $end
#0
0c
b1000 !
bx "
#5
1c
#10
0c
b1010 !
#15
1c
#20
0c
b11000000000000 !
b1010000000000 "
#25
1c
"""

    def test_clocked_epc_sampling(self):
        from wavescope.vcd_reader import iter_samples_multi
        with tempfile.NamedTemporaryFile("w", suffix=".vcd",
                                         delete=False) as f:
            f.write(self.VCD)
            path = f.name
        try:
            out = list(iter_samples_multi(path, "clk", "pc",
                                          aux_names=("mepc",)))
        finally:
            os.unlink(path)
        self.assertEqual(out[0], (0, 0b1000, None))
        self.assertEqual(out[1], (1, 0b1010, None))
        self.assertEqual(out[2], (2, 0x3000, 0x1400))


if __name__ == "__main__":
    unittest.main()
