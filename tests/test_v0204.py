"""v0.20.4 discontinuity returns (disc-ret): a function that "ends"
without any committed return/jump must not leak its frame.

The user's report: A calls B; B's only committed instruction is
`auipc t1,0xf1000` (macro-fused auipc+jr pair -- only the first pc is
sampled -- or the paired jump ran through code outside the ELF), then
the very next commit is back in A at the call's return address.
Expected arc(A->B): Ir=1.  Observed before the fix: 139,084 (sim) /
1,116,524 (legacy), because the frame never closed and swallowed the
rest of the run.  The defense is ISA-agnostic; ARM (movw/movt + bx
veneers) is covered by the same code paths and tested here.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_IR, run
from wavescope.simcore import run_sim

CL = get_classifier("riscv")
CL_ARM = get_classifier("armv7m")


def _bin(prog, funcs):
    b = BinaryInfo()
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func(*f) for f in funcs]
    b._starts = [f.start for f in b.funcs]
    return b


def fused_binary():
    """A calls B; B = auipc + (never-sampled) jr pair, plus dead code."""
    return _bin(
        [(0x100, 4, "jal", "ra,300 <A>"), (0x104, 4, "j", "104"),
         (0x300, 4, "addi", "a0,a0,1"),                    # A
         (0x304, 4, "jal", "ra,400 <B>"),
         (0x308, 4, "addi", "a1,a1,1"),                    # ret site
         (0x30c, 4, "jal", "ra,700 <C>"),
         (0x310, 4, "ret", ""),
         (0x400, 4, "auipc", "t1,0xf1000"),                # B (fused pair:
         (0x404, 4, "jr", "-4(t1)"),                       #  jr never
         (0x408, 4, "addi", "s0,s0,1"),                    #  sampled)
         (0x700, 4, "addi", "a2,a2,1"),                    # C
         (0x704, 4, "ret", "")],
        [("_start", 0x100, 0x108), ("A", 0x300, 0x314),
         ("B", 0x400, 0x40c), ("C", 0x700, 0x708)])


def fused_trace():
    flow = [0x100, 0x300, 0x304,
            0x400,                        # B: auipc ONLY (Ir=1)
            0x308,                        # discontinuity -> A's ret site
            0x30c, 0x700, 0x704,          # A continues normally
            0x310, 0x104]
    return [(10 + 7 * i, pc) for i, pc in enumerate(flow)]


class TestFusedPairReturn(unittest.TestCase):
    def _check(self, prof, engine):
        cs = prof.calls[(0x304, 0x400)]
        self.assertEqual(cs.count, 1, engine)
        self.assertEqual(cs.inclusive[E_IR], 1,
                         f"{engine}: arc(A->B) must be exactly B's one "
                         f"committed instruction, not the rest of the run")
        # A's later call is attributed to A, not to the leaked B frame
        self.assertEqual(prof.calls[(0x30c, 0x700)].inclusive[E_IR], 2,
                         engine)
        self.assertEqual(prof.discontinuity_returns, 1, engine)

    def test_sim(self):
        prof = run_sim(iter(fused_trace()), fused_binary(), CL,
                       trace_roots=4)
        self._check(prof, "sim")
        self.assertIn("disc-ret", prof.root_log["n"])

    def test_legacy(self):
        prof = run(iter(fused_trace()), fused_binary(), CL, trace_roots=4)
        self._check(prof, "legacy")
        # the discontinuity must NOT be misread as an exception entry
        self.assertEqual(prof.exceptions, 0)

    def test_legacy_epc_mode(self):
        # with an epc signal present the same discontinuity used to be
        # a flow anomaly + leaked frame; now it's a disc-ret
        stream = [(t, pc, 0x111) for t, pc in fused_trace()]
        prof = run(iter(stream), fused_binary(), CL)
        self._check(prof, "legacy-epc")
        self.assertEqual(prof.flow_anomalies, 0)


class TestFarStubUnknownRegion(unittest.TestCase):
    """B's jr IS sampled but jumps outside the ELF; the far code runs
    (unknown pcs) and eventually returns to A's ret site with no
    classifiable return instruction."""

    def _trace(self):
        flow = [0x100, 0x300, 0x304,
                0x400, 0x404,             # B: auipc, jr (sampled)
                0xF1000400, 0xF1000404,   # far code outside the ELF
                0x308,                    # re-entry at A's ret site
                0x30c, 0x700, 0x704, 0x310, 0x104]
        return [(10 + 7 * i, pc) for i, pc in enumerate(flow)]

    def _check(self, prof, engine):
        cs = prof.calls[(0x304, 0x400)]
        self.assertEqual(cs.inclusive[E_IR], 2,
                         f"{engine}: arc(A->B) is B's two committed "
                         f"instructions (unknown pcs are not charged)")
        self.assertEqual(prof.unknown_pcs if hasattr(prof, "unknown_pcs")
                         else 0, prof.unknown_pcs, engine)
        self.assertEqual(prof.calls[(0x30c, 0x700)].inclusive[E_IR], 2,
                         engine)

    def test_legacy(self):
        prof = run(iter(self._trace()), fused_binary(), CL)
        self._check(prof, "legacy")
        self.assertEqual(prof.discontinuity_returns, 1)

    def test_sim(self):
        # sim's pending `jr` survives the unknown region and settles at
        # re-entry (rule 4), so A6 may not even need to fire -- either
        # way the frame must close at the boundary
        prof = run_sim(iter(self._trace()), fused_binary(), CL)
        self._check(prof, "sim")


class TestArmVeneer(unittest.TestCase):
    """Same defense on ARM (Cortex-M): bl into a veneer whose only
    sampled insn is the movw of a movw/movt+bx triple."""

    def _bin(self):
        return _bin(
            [(0x100, 4, "bl", "300 <A>"), (0x104, 2, "b", "104"),
             (0x300, 2, "adds", "r0,#1"),                  # A
             (0x302, 4, "bl", "400 <veneer>"),
             (0x306, 2, "adds", "r1,#1"),                  # ret site
             (0x308, 4, "bl", "700 <C>"),
             (0x30c, 2, "bx", "lr"),
             (0x400, 4, "movw", "ip,#0x1000"),             # veneer (movt
             (0x404, 4, "movt", "ip,#0xf100"),             #  + bx never
             (0x408, 2, "bx", "ip"),                       #  sampled)
             (0x700, 2, "adds", "r2,#1"),                  # C
             (0x702, 2, "bx", "lr")],
            [("_start", 0x100, 0x106), ("A", 0x300, 0x30e),
             ("veneer", 0x400, 0x40a), ("C", 0x700, 0x704)])

    def test_both_engines(self):
        flow = [0x100, 0x300, 0x302,
                0x400,                    # veneer: movw ONLY
                0x306,                    # discontinuity -> A's ret site
                0x308, 0x700, 0x702, 0x30c, 0x104]
        stream = [(10 + 7 * i, pc) for i, pc in enumerate(flow)]
        b = self._bin()
        for engine, fn in (("legacy",
                            lambda: run(iter(stream), b, CL_ARM)),
                           ("sim",
                            lambda: run_sim(iter(stream), b, CL_ARM))):
            prof = fn()
            self.assertEqual(prof.calls[(0x302, 0x400)].inclusive[E_IR],
                             1, engine)
            self.assertEqual(prof.calls[(0x308, 0x700)].inclusive[E_IR],
                             2, engine)
            self.assertEqual(prof.discontinuity_returns, 1, engine)


class TestNoFalseDiscRet(unittest.TestCase):
    """A discontinuity landing at a FUNCTION ENTRY (heuristic exception
    entry) must still be treated as an exception, not a return -- even
    if some frame's return address happens to sit at an entry."""

    def test_heuristic_isr_entry_preserved(self):
        b = _bin(
            [(0x100, 4, "jal", "ra,300 <A>"), (0x104, 4, "j", "104"),
             (0x300, 4, "addi", "a0,a0,1"),                # A
             (0x304, 4, "addi", "a1,a1,1"),
             (0x308, 4, "ret", ""),
             (0x900, 4, "addi", "t2,t2,1"),                # handler
             (0x904, 4, "mret", "")],
            [("_start", 0x100, 0x108), ("A", 0x300, 0x30c),
             ("ISR_h", 0x900, 0x908)])
        flow = [0x100, 0x300,
                0x900, 0x904,             # discontinuity -> handler entry
                0x304, 0x308, 0x104]
        stream = [(10 + 7 * i, pc) for i, pc in enumerate(flow)]
        prof = run(iter(stream), b, CL)
        self.assertEqual(prof.exceptions, 1)
        self.assertEqual(prof.discontinuity_returns, 0)


if __name__ == "__main__":
    unittest.main()
