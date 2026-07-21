"""v0.20.3 landing guards: an unwind driven by a transfer landing at L
must never pop a frame whose callee still contains L.

Reproduces the user's --debug-roots depth collapse: with the
SYS_initialize frame lost (here: legitimately frameless because the
function was entered through a cross-function conditional branch --
v0.20.2 parity: Group::BRANCH makes no frame), the epilogue restore is
tail-pushed directly onto (BSP_reset->startup), and restore's `jr t0`
(landing INSIDE startup) used to chain-pop (BSP_reset->startup) and
(_start->BSP_reset), emptying the root chain and restarting the stack
at depth 1 -- the "_start inclusive is not the maximum" report.
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


def boot_binary():
    b = BinaryInfo()
    prog = [
        (0x100, 4, "jal", "ra,200 <SYS_BSP_reset>"),       # _start
        (0x104, 4, "j", "104"),
        (0x200, 4, "addi", "sp,sp,-16"),                   # SYS_BSP_reset
        (0x204, 4, "j", "300 <SYS_system_startup>"),       # TAIL
        (0x300, 4, "addi", "a0,a0,1"),                     # startup
        (0x304, 4, "beqz", "a0,400 <SYS_initialize>"),     # cross-func
        (0x308, 4, "addi", "a1,a1,1"),                     # cond branch
        (0x30c, 4, "jal", "ra,700 <First_fn>"),
        (0x310, 4, "j", "310"),
        (0x400, 4, "addi", "s0,s0,1"),                     # SYS_initialize
        (0x404, 4, "addi", "s1,s1,1"),                     # (frameless:
        (0x408, 4, "j", "600 <__riscv_restore_0>"),        #  branch entry)
        (0x500, 2, "sw", "s0,8(sp)"),                      # save_0
        (0x502, 2, "sw", "ra,12(sp)"),                     # (user disasm:
        (0x504, 2, "jr", "t0"),                            #  ends jr t0)
        (0x600, 2, "lw", "s0,8(sp)"),                      # restore_0
        (0x602, 2, "lw", "t0,12(sp)"),                     # (user disasm:
        (0x604, 2, "jr", "t0"),                            #  ends jr t0)
        (0x700, 4, "addi", "a2,a2,1"),                     # First_fn
        (0x704, 4, "ret", ""),
    ]
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func("_start", 0x100, 0x108),
               Func("SYS_BSP_reset", 0x200, 0x208),
               Func("SYS_system_startup", 0x300, 0x314),
               Func("SYS_initialize", 0x400, 0x40c),
               Func("__riscv_save_0", 0x500, 0x506),
               Func("__riscv_restore_0", 0x600, 0x606),
               Func("First_fn", 0x700, 0x708)]
    b._starts = [f.start for f in b.funcs]
    return b


def collapse_trace():
    flow = [0x100,                       # _start: jal BSP (CALL d1)
            0x200, 0x204,                # BSP: j startup (TAIL d2)
            0x300, 0x304,                # startup: beqz -> SYS_init
            0x400, 0x404, 0x408,         # SYS_init (NO frame), j restore
            0x600, 0x602, 0x604,         # restore (TAIL d3), jr t0
            0x308,                       # lands INSIDE startup
            0x30c, 0x700, 0x704,         # startup continues: First_fn
            0x310]
    return [(10 + 7 * i, pc) for i, pc in enumerate(flow)]


def arcs(prof, b):
    out = {}
    for (cp, callee), cs in prof.calls.items():
        cf, tf = b.func_at(cp), b.func_at(callee)
        out[(cf.name if cf else hex(cp),
             tf.name if tf else hex(callee))] = cs
    return out


class TestChainGuardCollapse(unittest.TestCase):
    """The user-reported signature: restore's jr t0 must stop at
    (BSP_reset -> startup) because the landing is inside startup."""

    def _check(self, prof, b, engine):
        a = arcs(prof, b)
        # _start's inclusive must dominate: everything after the jal
        # (the whole program minus _start's own insns) flows into it
        total_ir = prof.total[E_IR]
        start_self = sum(prof.self_cost[pc][E_IR] for pc in (0x100, 0x104))
        cs = a[("_start", "SYS_BSP_reset")]
        self.assertEqual(cs.inclusive[E_IR], total_ir - start_self,
                         f"{engine}: root chain was cut")
        # startup survived the restore return: First_fn's arc carries
        # its body, and startup's own arc still contains it
        self.assertEqual(a[("SYS_system_startup", "First_fn")]
                         .inclusive[E_IR], 2, engine)
        self.assertGreaterEqual(
            a[("SYS_BSP_reset", "SYS_system_startup")].inclusive[E_IR],
            2 + 3 + 2,          # startup insns after landing + First_fn
            f"{engine}: (BSP->startup) was popped by the chain")

    def test_legacy(self):
        b = boot_binary()
        prof = run(iter(collapse_trace()), b, CL, trace_roots=3)
        self._check(prof, b, "legacy")

    def test_sim(self):
        b = boot_binary()
        prof = run_sim(iter(collapse_trace()), b, CL, trace_roots=3)
        self._check(prof, b, "sim")
        self.assertGreaterEqual(prof.chain_guards, 1)
        kinds = prof.root_log["n"]
        self.assertIn("chain-guard", kinds)
        # depth never restarts at 1 for a startup-sourced call: the
        # First_fn push happens at depth 3 under startup
        pushes = [e for e in prof.root_log["ev"] if e[1] == "push"
                  and e[3] == 0x700]
        self.assertTrue(pushes and pushes[0][5] == 3,
                        prof.root_log["ev"])


class TestReturnGuard(unittest.TestCase):
    """A5a: rule-2 RETURN (helper -> non-helper) with the helper frame
    missing must not pop the enclosing function's frame -- the landing
    is inside that frame's callee."""

    def test_sim_missing_helper_frame(self):
        b = boot_binary()
        # SYS_initialize entered NORMALLY (via jal from startup) so its
        # frame exists, but save_0 is entered via a conditional branch
        # (no frame); save's jr t0 lands back inside SYS_initialize.
        b.insns[0x304] = Insn(addr=0x304, size=4, mnemonic="jal",
                              operands="ra,400 <SYS_initialize>")
        b.insns[0x400] = Insn(addr=0x400, size=4, mnemonic="beqz",
                              operands="a0,500 <__riscv_save_0>")
        flow = [0x100, 0x200, 0x204, 0x300, 0x304,
                0x400,                    # beqz -> save (NO frame)
                0x500, 0x502, 0x504,      # save, jr t0
                0x404, 0x408,             # back inside SYS_initialize
                0x600, 0x602, 0x604,      # epilogue restore, jr t0
                0x308, 0x30c, 0x700, 0x704, 0x310]
        stream = [(10 + 7 * i, pc) for i, pc in enumerate(flow)]
        prof = run_sim(iter(stream), b, CL, trace_roots=4)
        self.assertGreaterEqual(prof.return_guards, 1)
        a = arcs(prof, b)
        # (startup -> SYS_initialize) stayed open through the guarded
        # return and closed at the real epilogue: its inclusive holds
        # SYS_initialize's body + save + restore
        self.assertGreaterEqual(
            a[("SYS_system_startup", "SYS_initialize")].inclusive[E_IR],
            3 + 3 + 3)

    def test_sim_self_recursion_still_pops(self):
        b = BinaryInfo()
        prog = [(0x100, 4, "jal", "ra,200 <fib>"), (0x104, 4, "j", "104"),
                (0x200, 4, "addi", "a0,a0,-1"),            # fib
                (0x204, 4, "jal", "ra,200 <fib>"),
                (0x208, 4, "ret", "")]
        for a_, sz, m, o in prog:
            b.insns[a_] = Insn(addr=a_, size=sz, mnemonic=m, operands=o)
        b.funcs = [Func("_start", 0x100, 0x108), Func("fib", 0x200, 0x20c)]
        b._starts = [f.start for f in b.funcs]
        flow = [0x100, 0x200, 0x204,      # fib depth 1, recurse
                0x200, 0x208,             # fib depth 2, ret
                0x208,                    # depth 1 ret (lands in _start)
                0x104]
        stream = [(10 + 7 * i, pc) for i, pc in enumerate(flow)]
        prof = run_sim(iter(stream), b, CL)
        # the inner recursive return (landing inside fib) must POP:
        # callee == caller exemption keeps recursion working
        self.assertEqual(prof.return_guards, 0)
        self.assertEqual(prof.calls[(0x204, 0x200)].count, 1)
        self.assertEqual(prof.calls[(0x204, 0x200)].inclusive[E_IR], 2)


class TestLegacyGuards(unittest.TestCase):
    def test_helper_ret_pop_skipped_while_landing_in_helper(self):
        """restore chains (restore_8 -> restore_4 -> restore_0 via
        jr-style hops) must not close the head helper frame early."""
        b = BinaryInfo()
        prog = [(0x100, 4, "jal", "ra,200 <fn>"), (0x104, 4, "j", "104"),
                (0x200, 4, "addi", "a0,a0,1"),             # fn
                (0x204, 4, "j", "600 <__riscv_restore_8>"),
                (0x600, 2, "lw", "s7,0(sp)"),              # restore_8
                (0x602, 2, "jr", "a5"),                    # hop (indirect)
                (0x700, 2, "lw", "t0,12(sp)"),             # restore_0
                (0x702, 2, "jr", "t0")]
        for a_, sz, m, o in prog:
            b.insns[a_] = Insn(addr=a_, size=sz, mnemonic=m, operands=o)
        b.funcs = [Func("_start", 0x100, 0x108), Func("fn", 0x200, 0x208),
                   Func("__riscv_restore_8", 0x600, 0x604),
                   Func("__riscv_restore_0", 0x700, 0x704)]
        b._starts = [f.start for f in b.funcs]
        flow = [0x100, 0x200, 0x204,      # fn, tail into restore_8
                0x600, 0x602,             # hop lands in restore_0
                0x700, 0x702,             # jr t0 -> back in _start
                0x104]
        stream = [(10 + 7 * i, pc) for i, pc in enumerate(flow)]
        prof = run(iter(stream), b, CL)
        # the hop (jr a5 landing in restore_0) must NOT helper-ret-pop
        # the (fn -> restore_8) frame: it closes only at the real
        # return, so its inclusive spans the whole chain (4 insns)
        self.assertEqual(prof.calls[(0x204, 0x600)].inclusive[E_IR], 4)

    def test_isr_exit_floor(self):
        """A stale epc ctx (depth captured low, resume recurring later)
        must not unwind below the frame the resume pc is inside."""
        b = boot_binary()
        b.insns[0x304] = Insn(addr=0x304, size=4, mnemonic="jal",
                              operands="ra,400 <SYS_initialize>")
        b.insns[0x900] = Insn(addr=0x900, size=4, mnemonic="addi",
                              operands="t2,t2,1")
        b.insns[0x904] = Insn(addr=0x904, size=4, mnemonic="mret",
                              operands="")
        b.funcs.append(Func("ISR_h", 0x900, 0x908))
        b.funcs.sort(key=lambda f: f.start)
        b._starts = [f.start for f in b.funcs]
        E0, E1 = 0x111, 0x404             # resume INSIDE SYS_initialize
        flow = [(0x100, E0), (0x200, E0), (0x204, E0),
                (0x300, E0), (0x304, E0),          # depth 2 here
                (0x400, E1),                       # mepc "changes" ->
                                                   # spurious-ish entry
                                                   # ctx at depth 3? no:
                (0x404, E1), (0x408, E1),
                (0x600, E1), (0x602, E1), (0x604, E1),
                (0x308, E1), (0x30c, E1), (0x700, E1), (0x704, E1),
                (0x310, E1)]
        stream = [(10 + 7 * i, pc, e) for i, (pc, e) in enumerate(flow)]
        prof = run(iter(stream), b, CL)
        # regardless of how the bogus ctx resolves, the root chain
        # must survive to the drain
        a = arcs(prof, b)
        total_ir = prof.total[E_IR]
        start_self = sum(prof.self_cost[pc][E_IR] for pc in (0x100, 0x104))
        self.assertEqual(a[("_start", "SYS_BSP_reset")].inclusive[E_IR],
                         total_ir - start_self)


if __name__ == "__main__":
    unittest.main()
