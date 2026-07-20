"""simcore (literal simulator transcription) tests: reference semantics
(real_caller substitution, rule-based RETURN, IsrInfo replay, tail-chain
pops, wfi wake, spurious epc latch) plus cross-validation: on clean
traces sim and legacy must agree arc-for-arc."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_CY, E_IR, run
from wavescope.simcore import compare_profiles, run_sim

CL = get_classifier("riscv")


def milli_binary(jal_restore=True):
    b = BinaryInfo()
    prog = [
        (0x0500, 4, "jal", "ra,1000 <main>"),          # _start
        (0x0504, 4, "j", "504"),
        (0x1000, 4, "jal", "t0,5000 <__riscv_save_0>"),  # main
        (0x1004, 4, "jal", "ra,2000 <aa>"),
        (0x1008, 4, "addi", "a0,a0,2"),
        (0x100c, 4, "j", "6000 <__riscv_restore_0>"),
        (0x2000, 4, "jal", "t0,5000 <__riscv_save_0>"),  # aa
        (0x2004, 4, "addi", "s0,s0,1"),
        (0x2008, 4, "beq", "s0,s1,2010 <aa+0x10>"),
        (0x200c, 4, "addi", "s1,s1,1"),
        (0x2010, 4,
         "jal" if jal_restore else "j",
         "6000 <__riscv_restore_0>"),   # jal-ra form vs plain tail
        (0x5000, 2, "sw", "s0,4(sp)"),                   # save_0
        (0x5002, 2, "sw", "ra,0(sp)"),
        (0x5004, 2, "jr", "t0"),
        (0x6000, 2, "lw", "s0,4(sp)"),                   # restore_0
        (0x6002, 2, "lw", "ra,0(sp)"),
        (0x6004, 2, "addi", "sp,sp,16"),
        (0x6006, 2, "ret", ""),
        (0x7000, 4, "addi", "t2,t2,1"),                  # isr
        (0x7004, 4, "mret", ""),
    ]
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func("_start", 0x500, 0x508), Func("main", 0x1000, 0x1010),
               Func("aa", 0x2000, 0x2014),
               Func("__riscv_save_0", 0x5000, 0x5006),
               Func("__riscv_restore_0", 0x6000, 0x6008),
               Func("isr", 0x7000, 0x7008)]
    b._starts = [f.start for f in b.funcs]
    return b


SAVE = [0x5000, 0x5002, 0x5004]
REST = [0x6000, 0x6002, 0x6004, 0x6006]


def full_trace():
    tr = [0x0500]
    tr += [0x1000] + SAVE + [0x1004]            # main prologue, call aa
    tr += [0x2000] + SAVE                       # aa prologue
    tr += [0x2004, 0x2008, 0x200c, 0x2010]      # not-taken branch, jal rest
    tr += REST                                  # aa epilogue -> back in main
    tr += [0x1008, 0x100c] + REST               # main epilogue chain
    tr += [0x0504]
    return [(i, pc) for i, pc in enumerate(tr)]


class TestSimMillicode(unittest.TestCase):
    def setUp(self):
        self.prof = run_sim(iter(full_trace()), milli_binary(), CL)

    def test_save_arcs(self):
        # jal t0 -> CALL; jr t0 -> rule 2 (helper->non-helper) RETURN pop
        self.assertEqual(self.prof.calls[(0x1000, 0x5000)].count, 1)
        self.assertEqual(self.prof.calls[(0x1000, 0x5000)].inclusive[E_IR], 3)
        self.assertEqual(self.prof.calls[(0x2000, 0x5000)].inclusive[E_IR], 3)

    def test_jal_restore_arc(self):
        # `jal ra,restore_0`: CALL entry; restore's ret -> rule 1 RETURN
        # pops it (unconditional top pop) with exactly the body
        cs = self.prof.calls[(0x2010, 0x6000)]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 4)

    def test_tail_restore_chain_pop(self):
        # main's `j restore_0` = TAIL; restore's ret pops the tail entry
        # AND the anchor (_start->main call) via the tail-chain while
        cs = self.prof.calls[(0x100c, 0x6000)]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 4)
        self.assertIn((0x0500, 0x1000), self.prof.calls)

    def test_real_caller_state(self):
        # save helper contains no calls here, but the CALL INTO the save
        # helper must have recorded main/aa as real_caller and the arc
        # sits on the original caller (no substitution needed)
        self.assertEqual(self.prof.calls[(0x1004, 0x2000)].count, 1)

    def test_jal_restore_late_flush_is_reference_semantics(self):
        """REFERENCE QUIRK (faithfully transcribed): `jal ra,restore`
        pushes a NON-tail entry, and the RETURN through restore pops
        only that entry -- aa's own frame stays open and is flushed
        later by main's tail-chain, so arc(main->aa) legitimately
        includes main's post-return instructions.  This is exactly how
        the simulator behaves; the legacy engine (ret-addr matching)
        closes aa at the boundary instead.  A prime suspect for the
        remaining inclusive drift in the USER'S OWN numbers."""
        aa_pcs = (0x2000, 0x2004, 0x2008, 0x200c, 0x2010)
        aa_self = sum(self.prof.self_cost[pc][E_IR] for pc in aa_pcs)
        cs = self.prof.calls[(0x1004, 0x2000)]
        # aa(5) + save(3) + restore(4) + main post-return (2) + main's
        # epilogue restore chain (4) = 18: flushed at MAIN's return
        self.assertEqual(cs.inclusive[E_IR],
                         aa_self + 3 + 4 + 2 + 4)


class TestSimVsLegacyClean(unittest.TestCase):
    """On a clean, fully-tracked trace the two engines must agree
    arc-for-arc and event-for-event."""

    def test_full_agreement_on_tail_epilogues(self):
        # aa's epilogue as a plain `j restore` (the common form): both
        # engines close every frame at the same boundaries
        b = milli_binary(jal_restore=False)
        sim = run_sim(iter(full_trace()), b, CL)
        leg = run(iter(full_trace()), b, CL)
        cmp = compare_profiles(sim, leg, b)
        self.assertEqual(cmp["total"], {}, cmp)
        self.assertEqual(cmp["self"], [], cmp)
        self.assertEqual(cmp["arcs"], [], cmp)

    def test_jal_restore_divergence_is_visible(self):
        # with the jal-ra epilogue the engines MUST differ (reference
        # late-flush vs legacy boundary close) and the comparison tool
        # must surface exactly that arc
        b = milli_binary()
        sim = run_sim(iter(full_trace()), b, CL)
        leg = run(iter(full_trace()), b, CL)
        cmp = compare_profiles(sim, leg, b)
        names = [a[0] for a in cmp["arcs"]]
        self.assertIn("main->aa", names)


class TestSimIsr(unittest.TestCase):
    """update_epc entry (stack-of-stack swap), IsrInfo branch replay at
    resume, first_isr_cycle clamp."""

    def _trace(self):
        # interrupt fires right after the beq commits; mepc = taken
        # target; handler runs; mret; resume at the TRUE landing
        tr = [(0, 0x2000, 0), (1, 0x2004, 0),
              (2, 0x2008, 0),                    # beq commits
              (3, 0x7000, 0x2010),               # ISR: mepc -> 0x2010
              (9, 0x7004, 0x2010),               # mret (cycle gap inside)
              (10, 0x2010, 0x2010),              # resume = taken target
              (11, 0x6000, 0x2010)]
        return tr

    def test_entry_replay_and_clamp(self):
        prof = run_sim(iter(self._trace()), milli_binary(), CL)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.isr_open, 0)
        # sleep gap into the handler clamped to 1
        self.assertEqual(prof.self_cost[0x7000][E_CY], 1)
        # the interrupted beq is judged at resume against 0x2010: taken
        self.assertEqual(prof.cond_jumps.get((0x2008, 0x2010)), 1)

    def test_spurious_same_function_latch(self):
        tr = [(0, 0x2000, 0), (1, 0x2004, 0x2008),   # epc -> same func
              (2, 0x2008, 0x2008), (3, 0x200c, 0x2008)]
        prof = run_sim(iter(tr), milli_binary(), CL)
        self.assertEqual(prof.exceptions, 0)
        self.assertEqual(prof.spurious_epc, 1)

    def test_wfi_wake_same_epc(self):
        b = milli_binary()
        b.insns[0x2004] = Insn(0x2004, 4, "wfi", "")
        tr = [(0, 0x2000, 0x7000), (1, 0x2004, 0x7000),   # wfi
              (50, 0x7000, 0x7000),                        # wake, epc same
              (51, 0x7004, 0x7000), (52, 0x2008, 0x7000)]
        prof = run_sim(iter(tr), b, CL)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.self_cost[0x7000][E_CY], 1)


class TestSimEpcMidTraceDefinition(unittest.TestCase):
    def test_x_to_value_after_start_is_first_trap(self):
        # epc undefined at trace start, defined mid-trace: NOT a
        # baseline -- it is the first trap (adapter A2 scope)
        tr = [(0, 0x2000), (1, 0x2004),
              (2, 0x7000, 0x2008), (3, 0x7004, 0x2008),
              (4, 0x2008, 0x2008)]
        prof = run_sim(iter(tr), milli_binary(), CL)
        self.assertEqual(prof.exceptions, 1)

    def test_defined_at_first_commit_is_baseline(self):
        tr = [(0, 0x2000, 0x7000), (1, 0x2004, 0x7000),
              (2, 0x2008, 0x7000)]
        prof = run_sim(iter(tr), milli_binary(), CL)
        self.assertEqual(prof.exceptions, 0)


class TestSimRootLog(unittest.TestCase):
    def test_empty_stack_tail_recorded(self):
        tr = [(0, 0x1008), (1, 0x100c)] + \
             [(2 + i, pc) for i, pc in enumerate(REST)]
        prof = run_sim(iter(tr), milli_binary(), CL, trace_roots=True)
        kinds = [e[1] for e in prof.root_log["ev"]]
        self.assertIn("tail-noframe", kinds)

    def test_push_pop_events(self):
        prof = run_sim(iter(full_trace()), milli_binary(), CL,
                       trace_roots=True)
        kinds = prof.root_log["n"]
        self.assertGreater(kinds.get("push", 0), 0)
        self.assertGreater(kinds.get("pop", 0), 0)


class TestSimEmptyStackTail(unittest.TestCase):
    def test_count_without_frame(self):
        tr = [(0, 0x1008), (1, 0x100c)] + \
             [(2 + i, pc) for i, pc in enumerate(REST)]
        prof = run_sim(iter(tr), milli_binary(), CL)
        self.assertEqual(prof.calls[(0x100c, 0x6000)].count, 1)
        self.assertEqual(prof.calls[(0x100c, 0x6000)].inclusive[E_IR], 0)


if __name__ == "__main__":
    unittest.main()
