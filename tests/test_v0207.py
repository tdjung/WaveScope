"""v0.20.7 regression tests.

1. Shared-callee false ISR exit (the user's confirmed analysis): a
   function called by BOTH the interrupted code and a handler can carry
   the resume address inside it; when the handler re-executes it, its
   millicode save's `jr t0` (INDIRECT) lands exactly on mepc and the
   v0.20.5 gate could not classify indirect arrivals -- false exit,
   early drain, count-without-inclusive.  Exclusive callees (called by
   one ISR only) never host a resume and were fine, matching the
   reported 2-of-4 ISR pattern.  The tightened A7 treats ANY pending
   branch settling at the commit as the handler's own flow; a real
   exit arrives after xret (which leaves no branch pending).
2. Compiler clone symbols ('[clone .constprop.0]', raw '_Z...suffix')
   normalize to the base name so the viewer aggregates them.
3. jcnd emission order: taken record first, not-taken after.
"""

import io
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn, _clean_symbol
from wavescope.profdata import E_BC, E_IR
from wavescope.simcore import run_sim

CL = get_classifier("riscv")

SAVE = [0xa00, 0xa02, 0xa04]
REST = [0xa10, 0xa12, 0xa14]
SUB = [0x400] + SAVE + [0x404, 0x408] + REST


def shared_callee_binary():
    b = BinaryInfo()
    prog = [
        (0x100, 4, "jal", "ra,300 <main>"), (0x104, 4, "j", "104"),
        (0x300, 4, "addi", "a0,a0,1"),                    # main
        (0x304, 4, "jal", "ra,400 <sub>"),
        (0x308, 4, "addi", "a1,a1,1"),
        (0x30c, 4, "j", "300"),
        (0x400, 4, "jal", "t0,a00 <__riscv_save_0>"),     # sub: SHARED
        (0x404, 4, "addi", "a2,a2,1"),
        (0x408, 4, "j", "a10 <__riscv_restore_0>"),
        (0x800, 4, "jal", "ra,900 <ISR_A>"), (0x804, 4, "mret", ""),
        (0x900, 4, "jal", "ra,400 <sub>"),                # ISR_A -> sub
        (0x904, 4, "jal", "ra,b00 <ISR_D>"),              # -> exclusive
        (0x908, 4, "ret", ""),
        (0xa00, 2, "sw", "s0,8(sp)"), (0xa02, 2, "sw", "ra,12(sp)"),
        (0xa04, 2, "jr", "t0"),
        (0xa10, 2, "lw", "s0,8(sp)"), (0xa12, 2, "lw", "t0,12(sp)"),
        (0xa14, 2, "jr", "t0"),
        (0xb00, 4, "addi", "a3,a3,1"), (0xb04, 4, "ret", ""),
    ]
    for a, sz, m, o in prog:
        b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
    b.funcs = [Func("_start", 0x100, 0x108), Func("main", 0x300, 0x310),
               Func("sub", 0x400, 0x40c),
               Func("ISR_stub", 0x800, 0x808), Func("ISR_A", 0x900, 0x90c),
               Func("__riscv_save_0", 0xa00, 0xa06),
               Func("__riscv_restore_0", 0xa10, 0xa16),
               Func("ISR_D", 0xb00, 0xb08)]
    b._starts = [f.start for f in b.funcs]
    return b


# main-context flow with an interrupt point before each instruction
MAIN_FLOW = [0x100, 0x300, 0x304] + SUB + [0x308, 0x30c, 0x300, 0x304] \
            + SUB + [0x308]
ISR_FLOW = [0x800, 0x900] + SUB + [0x904, 0xb00, 0xb04, 0x908, 0x804]


class TestSharedCalleeFalseExit(unittest.TestCase):
    def _run(self, k):
        resume = MAIN_FLOW[k]
        flow = [(pc, 0x111) for pc in MAIN_FLOW[:k]]
        flow += [(pc, resume) for pc in ISR_FLOW]
        flow += [(pc, resume) for pc in MAIN_FLOW[k:]]
        stream = [(10 + 7 * i, pc, e) for i, (pc, e) in enumerate(flow)]
        return run_sim(iter(stream), shared_callee_binary(), CL,
                       trace_roots=5), resume

    def test_user_reported_point(self):
        # interrupt at save's `jr t0` in main's sub: mepc = 0x404; the
        # handler's sub re-execution reaches 0x404 via its own save's
        # INDIRECT `jr t0`
        k = MAIN_FLOW.index(0xa04)
        prof, resume = self._run(k)
        self.assertEqual(resume, 0xa04)  # interrupted insn; mepc=0x404
        # ISR-internal arcs carry their exact bodies
        self.assertEqual(prof.calls[(0x900, 0x400)].inclusive[E_IR], 9)
        self.assertEqual(prof.calls[(0x904, 0xb00)].inclusive[E_IR], 2)
        self.assertNotIn("tail-noframe", prof.root_log["n"])
        self.assertGreaterEqual(prof.exit_rejects, 1)
        self.assertEqual(prof.root_log["n"].get("isr-exit", 0), 1)

    def test_sweep_all_points_no_zero_inclusive(self):
        for k in range(1, len(MAIN_FLOW) - 1):
            prof, resume = self._run(k)
            for (cp, ce), cs in prof.calls.items():
                if cs.count:
                    self.assertGreater(
                        cs.inclusive[E_IR], 0,
                        f"k={k} resume={hex(resume)}: arc "
                        f"{hex(cp)}->{hex(ce)} calls={cs.count} "
                        f"zero inclusive")
            # exclusive callee is always intact
            self.assertEqual(prof.calls[(0x904, 0xb00)].inclusive[E_IR],
                             2, f"k={k}")


class TestCloneSymbols(unittest.TestCase):
    def test_demangled_clone_annotation_stripped(self):
        self.assertEqual(_clean_symbol("foo(int) [clone .constprop.0]"),
                         "foo(int)")
        self.assertEqual(
            _clean_symbol("ns::bar(char*) const [clone .part.1]"),
            "ns::bar(char*) const")

    def test_raw_gcc_suffixes_stripped(self):
        self.assertEqual(_clean_symbol("_Z3fooi.constprop.0"), "_Z3fooi")
        self.assertEqual(_clean_symbol("helper.isra.0.constprop.2"),
                         "helper")
        self.assertEqual(_clean_symbol("tables.cold"), "tables")

    def test_plain_names_untouched(self):
        for n in ("main", "__riscv_restore_0", "ns::f(int)",
                  "operator()(int)", "v2.1_handler"):
            self.assertEqual(_clean_symbol(n), n)

    @unittest.skipIf(shutil.which("c++filt") is None, "c++filt missing")
    def test_batch_demangle(self):
        from wavescope.disasm import _batch_demangle
        got = _batch_demangle(["_Z3fooi", "main"])
        self.assertEqual(got.get("_Z3fooi"), "foo(int)")
        self.assertNotIn("main", got)


class TestJcndOrder(unittest.TestCase):
    def test_taken_before_not_taken(self):
        from wavescope.callgrind import write as write_callgrind
        from wavescope.profdata import Profile
        b = BinaryInfo()
        prog = [(0x100, 4, "beqz", "a0,10c"),      # cond: taken->0x10c
                (0x104, 4, "addi", "a0,a0,1"),     # fallthrough
                (0x108, 4, "j", "100"),
                (0x10c, 4, "ret", "")]
        for a, sz, m, o in prog:
            b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
        b.funcs = [Func("f", 0x100, 0x110)]
        b._starts = [0x100]
        prof = Profile(b)
        for pc in (0x100, 0x104, 0x108, 0x10c):
            prof.self_cost[pc][E_IR] += 1
        prof.self_cost[0x100][E_BC] += 10
        # not-taken (fallthrough 0x104) happened MORE often than taken:
        # count-descending order would print it first -- taken must
        # still come first
        prof.cond_jumps[(0x100, 0x104)] = 7      # not taken
        prof.cond_jumps[(0x100, 0x10c)] = 3      # taken
        out = io.StringIO()
        write_callgrind(prof, out, "test.elf")
        txt = out.getvalue()
        i_taken = txt.index("jcnd=3/10 0x10c")
        i_nt = txt.index("jcnd=7/10 0x104")
        self.assertLess(i_taken, i_nt,
                        "taken jcnd record must print before not-taken")


if __name__ == "__main__":
    unittest.main()
