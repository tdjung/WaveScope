"""v0.20.6 ADAPTER A8: an mepc change while the flow is sequential is a
SOFTWARE write, not a trap -- no phantom ISR entry.

The user's report (default engine): ISR_end_of_process_interrupt ends
with `j __riscv_restore_0`; the arc to restore shows a call but no
inclusive events, and the two callers (jal + `j` to another line in the
same function afterwards) lose the callee's inclusive too.  Mechanism:
the epilogue function rewrites mepc (nested-interrupt epilogue / task
switch) -> the engine saw the value change and declared a phantom
nested ISR entry, freezing the live stack; the very next tail into
restore then hit the reference's empty-stack tail-noframe path (count
only, no frame, no inclusive), and the frozen caller frames lost their
events as well.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profdata import E_IR
from wavescope.simcore import run_sim

CL = get_classifier("riscv")


def ieopi_binary():
    b = BinaryInfo()
    prog = [
        (0x300, 4, "addi", "a0,a0,1"),                     # main loop
        (0x304, 4, "addi", "a1,a1,1"),
        (0x308, 4, "addi", "a2,a2,1"),
        (0x30c, 4, "j", "300"),
        (0x800, 4, "jal", "ra,900 <ISR_end_process>"),     # vector stub
        (0x804, 4, "mret", ""),
        (0x900, 4, "addi", "t2,t2,1"),                     # ISR_end_process
        (0x904, 4, "jal", "ra,c00 <ISR_end_of_process_interrupt>"),
        (0x908, 4, "j", "910"),        # after the call: `j` to another
        (0x90c, 4, "addi", "t3,t3,1"),  # line in the SAME function
        (0x910, 4, "addi", "t4,t4,1"),
        (0x914, 4, "ret", ""),
        (0xa10, 2, "lw", "s0,8(sp)"),                      # restore_0
        (0xa12, 2, "lw", "t0,12(sp)"),
        (0xa14, 2, "jr", "t0"),
        (0xc00, 4, "addi", "a3,a3,1"),   # ISR_end_of_process_interrupt
        (0xc04, 4, "csrw", "mepc,a4"),   # software mepc write HERE
        (0xc08, 4, "j", "a10 <__riscv_restore_0>"),
    ]
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func("main", 0x300, 0x310),
               Func("ISR_stub", 0x800, 0x808),
               Func("ISR_end_process", 0x900, 0x918),
               Func("__riscv_restore_0", 0xa10, 0xa16),
               Func("ISR_end_of_process_interrupt", 0xc00, 0xc0c)]
    b._starts = [f.start for f in b.funcs]
    return b


def ieopi_stream():
    R, R2 = 0x308, 0x30c              # hw resume; software-written mepc
    flow = [(0x300, 0x111), (0x304, 0x111),
            (0x800, R), (0x900, R), (0x904, R),   # interrupt taken
            (0xc00, R),
            (0xc04, R2),              # csrw commits: epc value changes
            (0xc08, R2),
            (0xa10, R2), (0xa12, R2), (0xa14, R2),
            (0x908, R2),              # jr t0 lands on the caller's `j`
            (0x910, R2), (0x914, R2),
            (0x804, R2),              # stub mret
            (0x30c, R2),              # resume at the REWRITTEN mepc
            (0x300, R2), (0x304, R2)]
    return [(10 + 7 * i, pc, e) for i, (pc, e) in enumerate(flow)]


class TestSoftwareEpcRewrite(unittest.TestCase):
    def setUp(self):
        self.prof = run_sim(iter(ieopi_stream()), ieopi_binary(), CL,
                            trace_roots=4)

    def test_no_phantom_entry(self):
        kinds = self.prof.root_log["n"]
        self.assertEqual(kinds.get("isr-enter", 0), 1)
        self.assertEqual(kinds.get("isr-exit", 0), 1)
        self.assertGreaterEqual(kinds.get("epc-rewrite", 0), 1)
        self.assertNotIn("tail-noframe", kinds)
        self.assertEqual(self.prof.epc_rewrites, 1)

    def test_restore_arc_has_inclusive(self):
        cs = self.prof.calls[(0xc08, 0xa10)]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 3)

    def test_caller_arc_has_inclusive(self):
        # ISR_end_process -> ISR_end_of_process_interrupt: the callee's
        # body (3) plus its restore (3)
        cs = self.prof.calls[(0x904, 0xc00)]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 6)

    def test_stub_arc_and_retargeted_exit(self):
        # stub -> ISR_end_process holds the whole handler subtree
        cs = self.prof.calls[(0x800, 0x900)]
        self.assertEqual(cs.inclusive[E_IR], 11)
        # after the retargeted exit, main continues in the NORMAL
        # context: no arcs may leak past the resume
        for (cp, ce), c in self.prof.calls.items():
            if c.count:
                self.assertGreater(c.inclusive[E_IR], 0,
                                   f"arc {hex(cp)}->{hex(ce)}")

    def test_soft_write_outside_isr(self):
        # epc changes while normal sequential code runs: baseline
        # update only, no entry
        flow = [(0x300, 0x111), (0x304, 0x111), (0x308, 0x222),
                (0x30c, 0x222), (0x300, 0x222)]
        stream = [(10 + 7 * i, pc, e) for i, (pc, e) in enumerate(flow)]
        prof = run_sim(iter(stream), ieopi_binary(), CL, trace_roots=2)
        self.assertEqual(prof.root_log["n"].get("isr-enter", 0), 0)
        self.assertEqual(prof.epc_rewrites, 1)


if __name__ == "__main__":
    unittest.main()
