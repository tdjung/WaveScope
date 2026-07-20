"""Cortex-M (M4 / M35P) exception tracking via the IPSR level signal
(--isr-level): signal-driven entry/exit, preemption nesting, tail-chain
collapse, deferred branch resolution across the handler, and xPSR flag
noise masking.  No epc exists on these cores; hardware resumes exactly
at the interrupted instruction via EXC_RETURN, so the landing after a
level drop IS the resume point."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_BCM, E_CY, E_IR, run

CL = get_classifier("armv7m")


def binary():
    b = BinaryInfo()
    prog = [
        # main (thumb, 2-byte insns)
        (0x1000, 2, "movs", "r0, #0"),
        (0x1002, 2, "cmp", "r0, r1"),
        (0x1004, 2, "bne.n", "100a <main+0xa>"),
        (0x1006, 2, "adds", "r0, #1"),
        (0x1008, 2, "wfi", ""),
        (0x100a, 4, "bl", "2000 <worker>"),
        (0x100e, 2, "b.n", "100e"),
        # worker
        (0x2000, 2, "adds", "r2, #1"),
        (0x2002, 2, "bx", "lr"),
        # isr_a (exception 3)
        (0x3000, 2, "adds", "r3, #1"),
        (0x3002, 2, "bx", "lr"),          # EXC_RETURN in lr
        # isr_b (exception 7)
        (0x4000, 2, "adds", "r4, #1"),
        (0x4002, 2, "bx", "lr"),
    ]
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func("main", 0x1000, 0x1010), Func("worker", 0x2000, 0x2004),
               Func("isr_a", 0x3000, 0x3004), Func("isr_b", 0x4000, 0x4004)]
    b._starts = [f.start for f in b.funcs]
    return b


def lvl_run(trace, **kw):
    kw.setdefault("aux_mode", "level")
    return run(iter(trace), binary(), CL, **kw)


class TestLevelEntryExit(unittest.TestCase):
    """Interrupt between a conditional branch and its landing: the
    branch judgement must be deferred to the true post-return landing,
    with entry/exit driven purely by the IPSR value."""

    TRACE = [
        (0, 0x1000, 0),
        (1, 0x1002, 0),
        (2, 0x1004, 0),           # bne commits; interrupt fires
        (3, 0x3000, 3),           # IPSR 0 -> 3: isr_a
        (4, 0x3002, 3),           # bx lr (EXC_RETURN)
        (5, 0x100a, 0),           # IPSR -> 0; landing = branch TAKEN
        (6, 0x2000, 0),           # bl worker
        (7, 0x2002, 0),
        (8, 0x100e, 0),
    ]

    def setUp(self):
        self.prof = lvl_run(self.TRACE)

    def test_mode_and_counts(self):
        self.assertEqual(self.prof.isr_kind, "level")
        self.assertEqual(self.prof.exceptions, 1)
        self.assertEqual(self.prof.isr_open, 0)

    def test_deferred_branch_true_landing(self):
        # bne resolved against 0x100a (taken), not the handler address
        self.assertEqual(self.prof.self_cost[0x1004][E_BCM], 1)

    def test_clamp_and_flow(self):
        self.assertEqual(self.prof.self_cost[0x3000][E_CY], 1)
        self.assertEqual(self.prof.flow_anomalies, 0)
        self.assertIn((0x100a, 0x2000), self.prof.calls)

    def test_not_taken_variant(self):
        trace = [
            (0, 0x1002, 0),
            (1, 0x1004, 0),
            (2, 0x3000, 3),
            (3, 0x3002, 3),
            (4, 0x1006, 0),        # fall-through: NOT taken
            (5, 0x1008, 0),
        ]
        prof = lvl_run(trace)
        self.assertEqual(prof.self_cost[0x1004][E_BCM], 0)
        self.assertEqual(prof.exceptions, 1)


class TestLevelPreemption(unittest.TestCase):
    """0 -> 3 -> 7 -> 3 -> 0: exc 7 preempts exc 3; each drop pops one
    context and restores that context's interrupted Pending."""

    TRACE = [
        (0, 0x1000, 0),
        (1, 0x1002, 0),
        (2, 0x3000, 3),           # enter isr_a
        (3, 0x4000, 7),           # preempted by isr_b
        (4, 0x4002, 7),
        (5, 0x3002, 3),           # back in isr_a (its addi interrupted)
        (6, 0x1004, 0),           # back in main
        (7, 0x1006, 0),           # bne not taken this time
    ]

    def test_nested(self):
        prof = lvl_run(self.TRACE)
        self.assertEqual(prof.exceptions, 2)
        self.assertEqual(prof.isr_open, 0)
        self.assertEqual(prof.flow_anomalies, 0)
        # both handlers cost-clamped at entry
        self.assertEqual(prof.self_cost[0x3000][E_CY], 1)
        self.assertEqual(prof.self_cost[0x4000][E_CY], 1)


class TestLevelTailChain(unittest.TestCase):
    """0 -> 3 -> 7 -> 0: isr_a completes and isr_b tail-chains (IPSR
    goes 3->7 with no thread-mode gap); the direct 7->0 drop must pop
    BOTH contexts and restore the THREAD-mode interrupted Pending."""

    TRACE = [
        (0, 0x1000, 0),
        (1, 0x1002, 0),
        (2, 0x1004, 0),           # bne commits; interrupt
        (3, 0x3000, 3),
        (4, 0x3002, 3),           # bx lr -> tail-chain
        (5, 0x4000, 7),
        (6, 0x4002, 7),
        (7, 0x100a, 0),           # single drop to 0; branch was taken
        (8, 0x100e, 0),
    ]

    def test_collapse_restores_thread_pending(self):
        prof = lvl_run(self.TRACE)
        self.assertEqual(prof.exceptions, 2)
        self.assertEqual(prof.isr_open, 0)
        # thread-mode bne judged against the true landing after BOTH
        self.assertEqual(prof.self_cost[0x1004][E_BCM], 1)
        self.assertEqual(prof.flow_anomalies, 0)


class TestLevelWfiWake(unittest.TestCase):
    def test_same_exception_number_re_entry(self):
        # sleeping at wfi, same interrupt as before: IPSR still changes
        # 0 -> N, so no special wake rule is needed (unlike mepc)
        trace = [
            (0, 0x1006, 0),
            (1, 0x1008, 0),        # wfi
            (90, 0x3000, 3),       # wake
            (91, 0x3002, 3),
            (92, 0x100a, 0),
        ]
        prof = lvl_run(trace)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.self_cost[0x3000][E_CY], 1)   # sleep clamped


class TestLevelMask(unittest.TestCase):
    def test_xpsr_flag_noise_masked(self):
        # full xPSR dumped: N/Z/C/V bits (27..31) flap constantly; with
        # mask 0x1ff only the IPSR field drives entry/exit
        N, Z = 1 << 31, 1 << 30
        trace = [
            (0, 0x1000, 0),
            (1, 0x1002, Z),        # flags changed, IPSR still 0
            (2, 0x1004, N),
            (3, 0x3000, N | 3),    # real entry
            (4, 0x3002, Z | 3),    # flags flap inside handler
            (5, 0x100a, 0),
        ]
        prof = lvl_run(trace, level_mask=0x1FF)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.isr_open, 0)

    def test_without_mask_noise_would_trigger(self):
        prof = lvl_run([(0, 0x1000, 0), (1, 0x1002, 1 << 30),
                        (2, 0x1004, 0)])
        self.assertEqual(prof.exceptions, 1)   # documents why mask matters


class TestLevelBaseline(unittest.TestCase):
    def test_trace_starting_inside_handler(self):
        # dump begins with IPSR=3 (inside isr_a): baseline, no entry;
        # the later drop to 0 pops nothing and must not corrupt state
        trace = [
            (0, 0x3000, 3),
            (1, 0x3002, 3),
            (2, 0x1006, 0),
            (3, 0x1008, 0),
        ]
        prof = lvl_run(trace)
        self.assertEqual(prof.exceptions, 0)
        self.assertEqual(prof.isr_open, 0)


if __name__ == "__main__":
    unittest.main()
