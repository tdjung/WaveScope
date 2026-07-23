"""v0.20.8: mid-function fl= switching for inlined header code, and
--debug-func func-trace on the default engine."""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.callgrind import write as write_callgrind
from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profdata import E_IR, Profile
from wavescope.simcore import run_sim

CL = get_classifier("riscv")


class TestInlineFlSwitch(unittest.TestCase):
    def test_fl_reemitted_on_file_change(self):
        b = BinaryInfo()
        prog = [(0x100, 4, "addi", "a0,a0,1"),   # from main.c
                (0x104, 4, "addi", "a1,a1,1"),   # forceinlined header!
                (0x108, 4, "addi", "a2,a2,1"),   # header continues
                (0x10c, 4, "ret", "")]           # back to main.c
        for a, sz, m, o in prog:
            b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
        b.funcs = [Func("f", 0x100, 0x110)]
        b._starts = [0x100]
        b.lines = {0x100: ("main.c", 10),
                   0x104: ("util.h", 55),        # inlined header lines
                   0x108: ("util.h", 56),
                   0x10c: ("main.c", 12)}
        prof = Profile(b)
        for pc in prog:
            prof.self_cost[pc[0]][E_IR] += 1
        out = io.StringIO()
        write_callgrind(prof, out, "t.elf")
        txt = out.getvalue()
        # simulator convention: fl=<newfile> + fn=<same fn> on change,
        # in BOTH directions, so every cost line's line number resolves
        # in the right file
        i_main = txt.index("fl=main.c\nfn=f\n")
        i_hdr = txt.index("fl=util.h\nfn=f\n", i_main)
        i_back = txt.index("fl=main.c\nfn=f\n", i_hdr)
        self.assertLess(i_main, i_hdr)
        self.assertLess(i_hdr, i_back)
        # the header cost lines sit inside the util.h context
        self.assertLess(i_hdr, txt.index("0x104 55"))
        self.assertLess(txt.index("0x104 55"), i_back)
        self.assertLess(i_back, txt.index("0x10c 12"))

    def test_single_file_function_emits_fl_once(self):
        b = BinaryInfo()
        for i, a in enumerate((0x100, 0x104)):
            b.insns[a] = Insn(addr=a, size=4, mnemonic="addi",
                              operands="a0,a0,1")
        b.funcs = [Func("g", 0x100, 0x108)]
        b._starts = [0x100]
        b.lines = {0x100: ("g.c", 1), 0x104: ("g.c", 2)}
        prof = Profile(b)
        prof.self_cost[0x100][E_IR] += 1
        prof.self_cost[0x104][E_IR] += 1
        out = io.StringIO()
        write_callgrind(prof, out, "t.elf")
        self.assertEqual(out.getvalue().count("fl=g.c"), 1)


class TestFuncTrace(unittest.TestCase):
    def _bin(self):
        b = BinaryInfo()
        prog = [(0x100, 4, "jal", "ra,300 <main>"), (0x104, 4, "j", "104"),
                (0x300, 4, "jal", "ra,400 <tgt>"),        # main
                (0x304, 4, "jal", "ra,500 <other>"),
                (0x308, 4, "ret", ""),
                (0x400, 4, "addi", "a0,a0,1"),            # tgt (watched)
                (0x404, 4, "ret", ""),
                (0x500, 4, "addi", "a1,a1,1"),            # other
                (0x504, 4, "ret", "")]
        for a, sz, m, o in prog:
            b.insns[a] = Insn(addr=a, size=sz, mnemonic=m, operands=o)
        b.funcs = [Func("_start", 0x100, 0x108), Func("main", 0x300, 0x30c),
                   Func("tgt", 0x400, 0x408), Func("other", 0x500, 0x508)]
        b._starts = [f.start for f in b.funcs]
        return b

    def _stream(self):
        flow = [0x100, 0x300, 0x400, 0x404, 0x304, 0x500, 0x504,
                0x308, 0x104]
        return [(10 + 7 * i, pc) for i, pc in enumerate(flow)]

    def test_filtered_events_without_debug_roots(self):
        prof = run_sim(iter(self._stream()), self._bin(), CL,
                       debug_funcs={"tgt"})
        self.assertIsNone(prof.root_log)          # roots NOT enabled
        evs = prof.func_log["ev"]
        kinds = [(e[1], e[3]) for e in evs]
        self.assertIn(("push", 0x400), kinds)
        self.assertIn(("pop", 0x400), kinds)
        # untouched functions don't appear
        for e in evs:
            self.assertNotIn(e[3], (0x500,),
                             f"unwatched arc leaked into func-trace: {e}")
        # ticks are populated even without --debug-roots
        self.assertTrue(all(e[0] is not None for e in evs))

    def test_no_filter_no_log(self):
        prof = run_sim(iter(self._stream()), self._bin(), CL)
        self.assertIsNone(prof.func_log)


if __name__ == "__main__":
    unittest.main()
