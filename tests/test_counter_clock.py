"""Multi-bit --clock support (C++ IP-simulator dumps): a 32/64-bit
cycle COUNTER uses its value as the tick (exact under jumps, frequency
changes, and wraparound); a 0/1 clock stored in a wide variable
edge-samples like a 1-bit clock.  Auto-detection distinguishes them."""

import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_CY, E_IR, run
from wavescope.vcd_reader import (iter_pc_samples, iter_pc_samples_counter,
                                  probe_signal_values)
from wavescope.waveform import open_pc_stream

CL = get_classifier("riscv")


def binary():
    b = BinaryInfo()
    for i in range(8):
        a = 0x1000 + i * 4
        b.insns[a] = Insn(addr=a, size=4, mnemonic="addi", operands="a0,a0,1")
    b.funcs = [Func("main", 0x1000, 0x1020)]
    b._starts = [0x1000]
    return b


def make_vcd(body, clk_width=64):
    f = tempfile.NamedTemporaryFile("w", suffix=".vcd", delete=False)
    f.write(f"""$timescale 1ns $end
$scope module top $end
$var wire {clk_width} c cyc [{clk_width - 1}:0] $end
$var wire 32 ! pc [31:0] $end
$var wire 32 " mepc [31:0] $end
$upscope $end
$enddefinitions $end
""")
    f.write(body)
    f.close()
    return f.name


def rows(entries):
    """entries: (time, counter or None, pc or None, epc or None)"""
    out = []
    for t, ctr, pc, epc in entries:
        out.append(f"#{t}")
        if ctr is not None:
            out.append(f"b{ctr:b} c")
        if pc is not None:
            out.append(f"b{pc:b} !")
        if epc is not None:
            out.append(f'b{epc:b} "')
    return "\n".join(out) + "\n"


class TestCounterClock(unittest.TestCase):
    def _samples(self, body, **kw):
        path = make_vcd(body)
        try:
            return list(iter_pc_samples_counter(path, "cyc", "pc", **kw))
        finally:
            os.unlink(path)

    def test_value_is_tick_with_stall(self):
        # counter increments every cycle; pc holds 2 cycles at 0x1008
        ents = [(0, 100, 0x1000, None), (10, 101, 0x1004, None),
                (20, 102, 0x1008, None), (30, 103, None, None),
                (40, 104, None, None), (50, 105, 0x100c, None)]
        out = self._samples(rows(ents))
        self.assertEqual(out, [(100, 0x1000), (101, 0x1004),
                               (102, 0x1008), (105, 0x100c)])
        prof = run(iter(out), binary(), CL)
        self.assertEqual(prof.self_cost[0x100c][E_CY], 3)   # stall charged

    def test_counter_jump_sleep_fast_forward(self):
        # model fast-forwards the counter by 500 during sleep: the gap
        # must be charged exactly (this is where LSB-toggle counting
        # or edge sampling would lose the sleep entirely)
        ents = [(0, 10, 0x1000, None), (10, 11, 0x1004, None),
                (20, 511, 0x1008, None), (30, 512, 0x100c, None)]
        out = self._samples(rows(ents))
        self.assertEqual([t for t, _ in out], [10, 11, 511, 512])
        prof = run(iter(out), binary(), CL)
        self.assertEqual(prof.self_cost[0x1008][E_CY], 500)

    def test_wraparound(self):
        top = (1 << 64) - 2
        ents = [(0, top, 0x1000, None), (10, top + 1, 0x1004, None),
                (20, 0, 0x1008, None), (30, 1, 0x100c, None)]
        out = self._samples(rows(ents))
        d = [out[i + 1][0] - out[i][0] for i in range(3)]
        self.assertEqual(d, [1, 1, 1])

    def test_same_timestamp_order_irrelevant(self):
        # counter dumped before or after the pc in the same timestamp:
        # end-of-timestamp finalization gives the same tick
        a = rows([(0, 7, 0x1000, None), (10, 8, 0x1004, None)])
        b = "#0\nb1000000000000 !\nb111 c\n#10\nb1000000000100 !\nb1000 c\n"
        self.assertEqual(self._samples(a), self._samples(b))

    def test_epc_rides_along(self):
        ents = [(0, 5, 0x1000, 0), (10, 6, 0x1004, None),
                (20, 7, 0x3000, 0x1008), (30, 8, 0x1008, None)]
        path = make_vcd(rows(ents))
        try:
            out = list(iter_pc_samples_counter(path, "cyc", "pc",
                                               aux_names=("mepc",)))
        finally:
            os.unlink(path)
        self.assertEqual(out[2], (7, 0x3000, 0x1008))
        self.assertEqual(out[3], (8, 0x1008, 0x1008))

    def test_undefined_counter_skipped(self):
        body = '#0\nbx c\nb1000000000000 !\n' \
            + rows([(10, 3, 0x1004, None), (20, 4, 0x1008, None)])
        out = self._samples(body)
        self.assertEqual(out, [(3, 0x1004), (4, 0x1008)])


class TestWideStoredBitClock(unittest.TestCase):
    """A 0/1 clock recorded in a 32-bit variable must behave exactly
    like a 1-bit clock under edge sampling."""

    def test_edge_equivalence(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".vcd", delete=False)
        f.write("""$timescale 1ns $end
$scope module top $end
$var wire 32 c clk [31:0] $end
$var wire 32 ! pc [31:0] $end
$upscope $end
$enddefinitions $end
""")
        pcs = [0x1000, 0x1004, 0x1008, 0x100c]
        t = 0
        for pc in pcs:
            f.write(f"#{t}\nb1 c\nb{pc:b} !\n#{t + 5}\nb0 c\n")
            t += 10
        f.write(f"#{t}\nb1 c\n")
        f.close()
        try:
            out = list(iter_pc_samples(f.name, "clk", "pc"))
        finally:
            os.unlink(f.name)
        self.assertEqual(out, [(0, 0x1000), (1, 0x1004),
                               (2, 0x1008), (3, 0x100c)])


class TestAutoDetection(unittest.TestCase):
    def test_probe_and_routing(self):
        ents = [(i * 10, 50 + i, 0x1000 + i * 4, None) for i in range(6)]
        path = make_vcd(rows(ents))
        err, real = io.StringIO(), sys.stderr
        sys.stderr = err
        try:
            self.assertGreater(max(probe_signal_values(path, "cyc")), 1)
            out = list(open_pc_stream(path, "cyc", "pc"))
        finally:
            sys.stderr = real
            os.unlink(path)
        self.assertIn("cycle counter", err.getvalue())
        self.assertEqual(out[0], (50, 0x1000))
        self.assertEqual(len(out), 6)


if __name__ == "__main__":
    unittest.main()
