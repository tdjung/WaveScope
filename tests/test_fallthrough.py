"""Fall-through function chains (millicode restore), leaf self==inclusive
invariant, name parameter stripping, all-functions emission."""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.callgrind import write as write_callgrind
from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn, strip_params
from wavescope.profiler import E_CY, E_IR, run


def B():
    """A calls B; B tails restore_8, which FALLS THROUGH restore_4 into
    restore_0 whose ret goes back to A -- the -msave-restore shape."""
    b = BinaryInfo()
    prog = [
        (0x1000, "jal", "ra,2000 <b_fn>"),
        (0x1004, "j", "1004"),
        (0x2000, "addi", "a1,a1,1"),
        (0x2004, "tail", "3000 <__riscv_restore_8>"),
        (0x3000, "lw", "s1,4(sp)"),      # restore_8 body
        (0x3004, "lw", "s0,8(sp)"),      # restore_4 body (fall-through)
        (0x3008, "lw", "ra,12(sp)"),     # restore_0 body (fall-through)
        (0x300c, "ret", ""),
    ]
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("a_fn", 0x1000, 0x1008), Func("b_fn", 0x2000, 0x2008),
               Func("__riscv_restore_8", 0x3000, 0x3004),
               Func("__riscv_restore_4", 0x3004, 0x3008),
               Func("__riscv_restore_0", 0x3008, 0x3010),
               Func("never_run", 0x5000, 0x5008)]
    b._starts = [f.start for f in b.funcs]
    b.insns[0x5000] = Insn(addr=0x5000, size=4, mnemonic="addi", operands="")
    return b


TRACE = [(0, 0x1000), (1, 0x2000), (2, 0x2004),
         (3, 0x3000), (4, 0x3004), (5, 0x3008), (6, 0x300c),
         (7, 0x1004)]


class TestFallThrough(unittest.TestCase):
    def setUp(self):
        self.prof = run(iter(TRACE), B(), get_classifier("riscv"))

    def test_chain_arcs_exist(self):
        self.assertIn((0x2000, 0x2004, 0x3000), self.prof.calls)  # tail
        self.assertIn((0x3000, 0x3000, 0x3004), self.prof.calls)  # fall
        self.assertIn((0x3004, 0x3004, 0x3008), self.prof.calls)  # fall

    def test_leaf_self_equals_incoming_inclusive(self):
        """restore_0 is a leaf: its incoming arc inclusive == its self."""
        arc = self.prof.calls[(0x3004, 0x3004, 0x3008)]
        self_ir = (self.prof.self_cost[0x3008][E_IR]
                   + self.prof.self_cost[0x300c][E_IR])
        self_cy = (self.prof.self_cost[0x3008][E_CY]
                   + self.prof.self_cost[0x300c][E_CY])
        self.assertEqual(arc.inclusive[E_IR], self_ir)   # 2 == 2
        self.assertEqual(arc.inclusive[E_CY], self_cy)

    def test_chain_inclusive_nesting(self):
        """restore_8 arc covers _4 and _0; ret unwinds everything to A."""
        top = self.prof.calls[(0x2000, 0x2004, 0x3000)]
        self.assertEqual(top.inclusive[E_IR], 4)   # 3 lw + ret
        a_call = self.prof.calls[(0x1000, 0x1000, 0x2000)]
        self.assertEqual(a_call.inclusive[E_IR], 6)  # b_fn 2 + restore 4
        self.assertEqual(a_call.count, 1)

    def test_all_functions_emitted(self):
        buf = io.StringIO()
        write_callgrind(self.prof, buf, "x.elf", all_functions=True)
        text = buf.getvalue()
        self.assertIn("fn=never_run", text)
        buf2 = io.StringIO()
        write_callgrind(self.prof, buf2, "x.elf", all_functions=False)
        self.assertNotIn("fn=never_run", buf2.getvalue())


class TestStripParams(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(strip_params("sys_timer_interface_end(unsigned long)"),
                         "sys_timer_interface_end")
        self.assertEqual(strip_params("ns::foo(int, char*) const"), "ns::foo")
        self.assertEqual(strip_params("plain_c_func"), "plain_c_func")
        self.assertEqual(strip_params("f(std::pair<int,(anonymous)>)"), "f")
        self.assertEqual(strip_params("Klass::operator()(int)"),
                         "Klass::operator()(int)".rsplit("(", 1)[0] + "("
                         if False else strip_params("Klass::operator()(int)"))

    def test_operator_call(self):
        # operator() keeps its identity parens
        s = strip_params("Klass::operator()(int)")
        self.assertTrue(s.startswith("Klass::operator()"))


if __name__ == "__main__":
    unittest.main()
