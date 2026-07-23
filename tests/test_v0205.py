"""v0.20.5 ISR-exit arrival gate: pc==resume is NOT an exit when the
handler's own architectural flow reaches that address.

The user's report: with an interrupt pending at `jal t0,__riscv_save_0`
(or inside the save helper), mepc lands INSIDE the SHARED millicode.
The handler's own prologue calls the same helper, so pc hits the saved
resume address mid-handler and both engines declared a false ISR exit:
handler frames were drained early (arcs kept their call counts but lost
their inclusive events -- '__riscv_restore inclusive missing', 'ISR_B
missing from ISR_A inclusive'), and the rest of the handler then ran on
the outer stack, cutting the root chain (legacy '_start/BSP/startup
inclusive too small').

The sweep below fires one interrupt before EVERY instruction of a
millicode-heavy main flow, with a handler that itself uses millicode
and an internal call, and asserts every ISR-internal arc carries its
exact body cost and the root chain survives to the drain.
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

SAVE = [0xa00, 0xa02, 0xa04]
REST = [0xa10, 0xa12, 0xa14]


def shared_milli_binary():
    b = BinaryInfo()
    prog = [
        (0x100, 4, "jal", "ra,300 <main>"), (0x104, 4, "j", "104"),
        (0x300, 4, "jal", "t0,a00 <__riscv_save_0>"),      # main
        (0x304, 4, "addi", "a0,a0,1"),
        (0x308, 4, "jal", "ra,400 <sub>"),
        (0x30c, 4, "j", "a10 <__riscv_restore_0>"),
        (0x400, 4, "jal", "t0,a00 <__riscv_save_0>"),      # sub
        (0x404, 4, "addi", "a1,a1,1"),
        (0x408, 4, "j", "a10 <__riscv_restore_0>"),
        (0x800, 4, "jal", "ra,900 <ISR_A>"),               # vector stub
        (0x804, 4, "mret", ""),
        (0x900, 4, "jal", "t0,a00 <__riscv_save_0>"),      # ISR_A
        (0x904, 4, "addi", "t2,t2,1"),
        (0x908, 4, "jal", "ra,b00 <ISR_B>"),
        (0x90c, 4, "j", "a10 <__riscv_restore_0>"),
        (0xa00, 2, "sw", "s0,8(sp)"), (0xa02, 2, "sw", "ra,12(sp)"),
        (0xa04, 2, "jr", "t0"),                            # save_0
        (0xa10, 2, "lw", "s0,8(sp)"), (0xa12, 2, "lw", "t0,12(sp)"),
        (0xa14, 2, "jr", "t0"),                            # restore_0
        (0xb00, 4, "jal", "t0,a00 <__riscv_save_0>"),      # ISR_B
        (0xb04, 4, "addi", "a3,a3,1"),
        (0xb08, 4, "j", "a10 <__riscv_restore_0>"),
    ]
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func("_start", 0x100, 0x108), Func("main", 0x300, 0x310),
               Func("sub", 0x400, 0x40c),
               Func("ISR_stub", 0x800, 0x808), Func("ISR_A", 0x900, 0x910),
               Func("__riscv_save_0", 0xa00, 0xa06),
               Func("__riscv_restore_0", 0xa10, 0xa16),
               Func("ISR_B", 0xb00, 0xb0c)]
    b._starts = [f.start for f in b.funcs]
    return b


BASE_FLOW = ([0x100, 0x300] + SAVE + [0x304, 0x308, 0x400] + SAVE
             + [0x404, 0x408] + REST + [0x30c] + REST + [0x104])
ISR_FLOW = ([0x800, 0x900] + SAVE + [0x904, 0x908, 0xb00] + SAVE
            + [0xb04, 0xb08] + REST + [0x90c] + REST + [0x804])

# exact ISR-internal arc bodies (Ir)
ISR_ARCS = {(0x800, 0x900): len(ISR_FLOW) - 2,   # stub -> ISR_A
            (0x900, 0xa00): 3, (0xb00, 0xa00): 3,
            (0x908, 0xb00): 9,                   # ISR_B incl its millicode
            (0x90c, 0xa10): 3, (0xb08, 0xa10): 3}


def interrupted_stream(k):
    """Interrupt fires just before BASE_FLOW[k]; mepc = that address."""
    resume = BASE_FLOW[k]
    flow = [(pc, 0x111) for pc in BASE_FLOW[:k]]
    flow += [(pc, resume) for pc in ISR_FLOW]
    flow += [(pc, resume) for pc in BASE_FLOW[k:]]
    return [(10 + 7 * i, pc, e) for i, (pc, e) in enumerate(flow)], resume


class TestSharedMillicodeFalseExit(unittest.TestCase):
    def _run_point(self, k, engine, fn):
        stream, resume = interrupted_stream(k)
        prof = fn(iter(stream), shared_milli_binary(), CL)
        for arc, want in ISR_ARCS.items():
            cs = prof.calls.get(arc)
            self.assertIsNotNone(
                cs, f"{engine} k={k} resume={hex(resume)}: arc "
                    f"{hex(arc[0])}->{hex(arc[1])} missing")
            self.assertEqual(
                cs.inclusive[E_IR], want,
                f"{engine} k={k} resume={hex(resume)}: arc "
                f"{hex(arc[0])}->{hex(arc[1])} inclusive")
            self.assertGreaterEqual(cs.count, 1)
        # root chain: (start->main) holds everything after it (except
        # the k=1 boundary case where the ISR legitimately runs before
        # main's frame exists)
        smain = prof.calls[(0x100, 0x300)]
        start_self = sum(prof.self_cost[pc][E_IR] for pc in (0x100, 0x104))
        want_root = prof.total[E_IR] - start_self \
            - (len(ISR_FLOW) if k == 1 else 0)
        self.assertEqual(smain.inclusive[E_IR], want_root,
                         f"{engine} k={k} resume={hex(resume)}: root cut")
        return prof

    def test_sweep_all_interrupt_points_both_engines(self):
        rejects = 0
        for k in range(1, len(BASE_FLOW) - 1):
            for engine, fn in (("sim", run_sim), ("legacy", run)):
                prof = self._run_point(k, engine, fn)
                rejects += getattr(prof, "exit_rejects", 0)
        # the millicode-resume points must actually exercise the gate
        self.assertGreater(rejects, 0)

    def test_no_count_without_inclusive(self):
        """The reported signature itself: no arc may have calls > 0 with
        inclusive == 0 anywhere in the sweep."""
        for k in range(1, len(BASE_FLOW) - 1):
            stream, resume = interrupted_stream(k)
            for engine, fn in (("sim", run_sim), ("legacy", run)):
                prof = fn(iter(stream), shared_milli_binary(), CL)
                for (cp, ce), cs in prof.calls.items():
                    if cs.count > 0:
                        self.assertGreater(
                            cs.inclusive[E_IR], 0,
                            f"{engine} k={k} resume={hex(resume)}: arc "
                            f"{hex(cp)}->{hex(ce)} has calls={cs.count} "
                            f"but zero inclusive")

    def test_real_exit_still_taken_after_reject(self):
        """After rejecting the handler's own visits to the resume
        address, the genuine exit (arriving via mret) must still fire:
        post-ISR code runs in the normal context."""
        stream, resume = interrupted_stream(2)     # resume = 0xa00
        prof = run_sim(iter(stream), shared_milli_binary(), CL,
                       trace_roots=4)
        self.assertGreaterEqual(prof.exit_rejects, 1)
        kinds = prof.root_log["n"]
        self.assertIn("exit-reject", kinds)
        self.assertIn("isr-exit", kinds)
        # sub is called AFTER the ISR: its arc must sit under main
        self.assertEqual(prof.calls[(0x308, 0x400)].inclusive[E_IR], 9)


if __name__ == "__main__":
    unittest.main()
