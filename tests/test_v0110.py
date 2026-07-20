"""Fixed clockless period with CMU/DVFS guidance (v0.12.0 revert of the
v0.11.0 adaptive re-lock) and behavioral epc validation (--check-epc)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.scan import check_epc_behavior
from wavescope.vcd_reader import changes_to_ticks


def ticks_of(chg, **kw):
    p, gen = changes_to_ticks(iter(chg), **kw)
    out = list(gen)
    d = [out[i + 1][0] - out[i][0] for i in range(len(out) - 1)]
    return p, [], out, d


class TestFixedPeriodWithGuidance(unittest.TestCase):
    """v0.12.0: the v0.11.0 adaptive re-lock is reverted -- the period
    is fixed for the whole trace, and mid-trace frequency changes
    (off-grid deltas) produce explicit guidance to dump the clock and
    use --clock instead."""

    def test_uniform_clock(self):
        chg = [(i * 7, i) for i in range(500)]
        p, rl, out, d = ticks_of(chg)
        self.assertEqual(p, 7)
        self.assertEqual(set(d), {1})

    def test_explicit_period_respected(self):
        chg = [(i * 10, i) for i in range(100)]
        p, rl, out, d = ticks_of(chg, period=5)
        self.assertEqual(p, 5)
        self.assertEqual(set(d), {2})

    def test_offgrid_warns_and_keeps_period(self):
        import io
        # frequency change AFTER the warmup window (the realistic case:
        # warmup is 2048 changes, real dumps are millions)
        chg = [(i * 10, i) for i in range(2500)] \
            + [(25002 + i * 2, 9000 + i) for i in range(50)]
        err = io.StringIO()
        real = sys.stderr
        sys.stderr = err
        try:
            p, gen = changes_to_ticks(iter(chg))
            out = list(gen)
        finally:
            sys.stderr = real
        self.assertEqual(p, 10)                       # period stays fixed
        self.assertEqual(len(out), 2550)
        msg = err.getvalue()
        self.assertIn("off the 10-unit clock grid", msg)
        self.assertIn("--clock", msg)
        self.assertIn("off-grid PC change(s) total", msg)

    def test_no_warning_on_clean_trace(self):
        import io
        err = io.StringIO()
        real = sys.stderr
        sys.stderr = err
        try:
            p, gen = changes_to_ticks(iter([(i * 4, i) for i in range(50)]))
            list(gen)
        finally:
            sys.stderr = real
        self.assertNotIn("WARNING", err.getvalue())


class TestCheckEpcBehavior(unittest.TestCase):
    """A true mepc changes to a .text resume address at a PC
    discontinuity and is later committed; a decoy CSR is not."""

    VCD = """$timescale 1ns $end
$scope module top $end
$var wire 32 ! pc [31:0] $end
$var wire 32 " mepc [31:0] $end
$var wire 32 # decoy [31:0] $end
$upscope $end
$enddefinitions $end
#0
b1000000000000 !
bx "
b1 #
#10
b1000000000100 !
b10 #
#20
b11000000000000 !
b1000000001000 "
#30
b11000000000100 !
b11 #
#40
b1000000001000 !
#50
b1000000001100 !
b100 #
"""

    def _run(self):
        with tempfile.NamedTemporaryFile("w", suffix=".vcd",
                                         delete=False) as f:
            f.write(self.VCD)
            path = f.name
        try:
            return {c.name: c for c in check_epc_behavior(
                path, "pc", ["mepc", "decoy"],
                text_ranges=[(0x1000, 0x4000)])}
        finally:
            os.unlink(path)

    def test_true_epc_signature(self):
        st = self._run()["mepc"]
        self.assertEqual(st.changes, 1)          # x->value baseline aside
        self.assertEqual(st.text_hits, 1)
        self.assertEqual(st.resumed, 1)          # pc later hits 0x1008
        self.assertEqual(st.disc_aligned, 1)     # change at the redirect
        self.assertEqual(st.expired, 0)

    def test_decoy_rejected(self):
        st = self._run()["decoy"]
        self.assertEqual(st.changes, 3)
        self.assertEqual(st.resumed, 0)
        self.assertEqual(st.text_hits, 0)


if __name__ == "__main__":
    unittest.main()
