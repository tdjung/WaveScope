"""Clockless mode: cycles derived from PC change times (GCD period)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_pipeline import TRACE, make_binary
from wavescope.classify import get_classifier
from wavescope.profiler import E_CY, E_IR, run
from wavescope.vcd_reader import (changes_to_ticks, iter_pc_changes,
                                  parse_period)

PERIOD = 10  # dump time units per cycle


def make_clockless_vcd(path: str, valid: bool = False) -> None:
    lines = [
        "$timescale 1ns $end",
        "$scope module sim $end",
        "$var reg 32 @ pc [31:0] $end",
    ]
    if valid:
        lines.append("$var wire 1 ! commit_valid $end")
    lines += ["$upscope $end", "$enddefinitions $end"]
    # TRACE contains a stall at tick 3 (pc unchanged) -> no line emitted,
    # producing a 2*PERIOD gap that the GCD must survive.
    if valid:
        lines += ["#0", "1!"]
    for tick, pc in TRACE:
        lines.append(f"#{tick * PERIOD}")
        lines.append(f"b{pc:b} @")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


class TestClockless(unittest.TestCase):
    def _samples(self, valid=False):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.vcd")
            make_clockless_vcd(p, valid=valid)
            changes = list(iter_pc_changes(
                p, "pc", valid_name="commit_valid" if valid else None))
        return changes

    def test_period_autodetect(self):
        period, gen = changes_to_ticks(iter(self._samples()))
        self.assertEqual(period, PERIOD)
        self.assertEqual(list(gen), TRACE)

    def test_explicit_period(self):
        period, gen = changes_to_ticks(iter(self._samples()), period=PERIOD)
        self.assertEqual(list(gen), TRACE)

    def test_profile_equivalence(self):
        """Clockless samples must produce the same profile as clocked."""
        _, gen = changes_to_ticks(iter(self._samples()))
        prof = run(gen, make_binary(), get_classifier("riscv"))
        self.assertEqual(prof.self_cost[0x2000][E_IR], 1)
        # arrival attribution: 0x2004 pays the 2-tick gap after the stall
        self.assertEqual(prof.self_cost[0x2004][E_CY], 2)
        self.assertEqual(prof.total[E_IR], 8)

    def test_valid_gating(self):
        changes = self._samples(valid=True)
        self.assertEqual(len(changes), len(TRACE))

    def test_parse_period_units(self):
        ts_1ns = 10**6  # fs
        self.assertEqual(parse_period("10ns", ts_1ns), 10)
        self.assertEqual(parse_period("10", ts_1ns), 10)
        self.assertEqual(parse_period("20000ps", ts_1ns), 20)


if __name__ == "__main__":
    unittest.main()


class TestLargeTimestamps(unittest.TestCase):
    def test_no_float_precision_drift(self):
        """fs-scale timestamps beyond float53 must still land on exact
        ticks (stall deltas of 2-3 preserved late in the run)."""
        from wavescope.vcd_reader import changes_to_ticks
        period = 1_000_000                     # 1ns in fs
        base = 9_007_199_254_740_992           # 2^53: float loses ints here
        times = [base, base + period, base + 3 * period, base + 4 * period]
        changes = [(t, 0x1000 + i * 4) for i, t in enumerate(times)]
        p, gen = changes_to_ticks(iter(changes), period=period)
        ticks = [t for t, _ in gen]
        self.assertEqual(ticks, [0, 1, 3, 4])   # 2-tick stall intact
