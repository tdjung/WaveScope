"""Clocked vs clockless path verification: with a fixed clock both must
produce identical profiles; with a mid-trace frequency change (CMU) the
CLOCKED path stays exact because cycles count actual edges.

Edge-sampling semantics note: a value written at edge N (same VCD
timestamp) is sampled at edge N+1 -- correct flop timing.  The final PC
write therefore needs one more clock edge after it to be observed; real
dumps always have one (the clock keeps toggling), synthetic fixtures
must append it."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_CY, E_IR, run
from wavescope.vcd_reader import (changes_to_ticks, iter_pc_changes,
                                  iter_pc_samples)

CL = get_classifier("riscv")


def binary():
    b = BinaryInfo()
    prog = [(0x1000 + i * 4, "addi", "a0,a0,1") for i in range(8)]
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("main", 0x1000, 0x1020)]
    b._starts = [0x1000]
    return b


HDR = """$timescale 1ns $end
$scope module top $end
$var wire 1 c clk $end
$var wire 32 ! pc [31:0] $end
$upscope $end
$enddefinitions $end
"""


def write_vcd(events):
    """events: list of (time, [lines])"""
    f = tempfile.NamedTemporaryFile("w", suffix=".vcd", delete=False)
    f.write(HDR)
    for t, lines in events:
        f.write(f"#{t}\n")
        for ln in lines:
            f.write(ln + "\n")
    f.close()
    return f.name


class TestClockedClocklessEquivalence(unittest.TestCase):
    """Same execution, fixed 10ns clock: --clock and clockless must
    agree event-for-event.  PC advances each cycle except one 3-cycle
    stall on the 4th instruction."""

    def _events(self):
        ev = []
        pcs = [0x1000, 0x1004, 0x1008, 0x100c,
               None, None,             # stall: pc holds 2 extra cycles
               0x1010, 0x1014, 0x1018, 0x101c]
        t = 0
        for pc in pcs:
            lines = ["1c"]
            if pc is not None:
                lines.append(f"b{pc:b} !")
            ev.append((t, lines))
            ev.append((t + 5, ["0c"]))
            t += 10
        ev.append((t, ["1c"]))     # trailing edge: samples the last write
        return ev

    def setUp(self):
        self.path = write_vcd(self._events())

    def tearDown(self):
        os.unlink(self.path)

    def test_profiles_identical(self):
        clocked = run(iter_pc_samples(self.path, "clk", "pc"),
                      binary(), CL)
        _, gen = changes_to_ticks(iter_pc_changes(self.path, "pc"))
        clockless = run(gen, binary(), CL)
        self.assertEqual(clocked.total, clockless.total)
        for pc in (0x1000, 0x100c, 0x1010):
            self.assertEqual(clocked.self_cost[pc], clockless.self_cost[pc])
        # the stalled instruction is charged 3 cycles in both
        self.assertEqual(clocked.self_cost[0x1010][E_CY], 3)
        self.assertEqual(clockless.self_cost[0x1010][E_CY], 3)


class TestClockedCmuChange(unittest.TestCase):
    """Clock switches 10ns -> 4ns mid-trace.  Clocked cycles must count
    edges exactly: a 2-edge stall in the fast region is 2 cycles even
    though it spans less wall time than one slow-region cycle."""

    def _events(self):
        ev = []
        t = 0
        # slow region: 4 insns @10ns
        for pc in (0x1000, 0x1004, 0x1008, 0x100c):
            ev.append((t, ["1c", f"b{pc:b} !"]))
            ev.append((t + 5, ["0c"]))
            t += 10
        # fast region: @4ns; 0x1010 commits, then holds 2 fast edges
        # (stall), then the rest commit back-to-back
        plan = [0x1010, None, None, 0x1014, 0x1018, 0x101c]
        for pc in plan:
            lines = ["1c"]
            if pc is not None:
                lines.append(f"b{pc:b} !")
            ev.append((t, lines))
            ev.append((t + 2, ["0c"]))
            t += 4
        ev.append((t, ["1c"]))     # trailing edge: samples the last write
        return ev

    def test_edge_counted_cycles(self):
        path = write_vcd(self._events())
        try:
            prof = run(iter_pc_samples(path, "clk", "pc"), binary(), CL)
        finally:
            os.unlink(path)
        self.assertEqual(prof.self_cost[0x100c][E_CY], 1)
        self.assertEqual(prof.self_cost[0x1010][E_CY], 1)   # first fast insn
        self.assertEqual(prof.self_cost[0x1014][E_CY], 3)   # 2-edge stall
        self.assertEqual(prof.self_cost[0x1018][E_CY], 1)
        self.assertEqual(prof.total[E_IR], 8)


if __name__ == "__main__":
    unittest.main()
