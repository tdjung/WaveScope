"""v0.11.0: adaptive clockless period (CMU/DVFS mid-trace frequency
changes) and behavioral epc validation (scan --check-epc)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.scan import check_epc_behavior
from wavescope.vcd_reader import changes_to_ticks


def ticks_of(chg, **kw):
    relocks = []
    kw.setdefault("on_relock", lambda t, o, n: relocks.append((t, o, n)))
    p, gen = changes_to_ticks(iter(chg), **kw)
    out = list(gen)
    d = [out[i + 1][0] - out[i][0] for i in range(len(out) - 1)]
    return p, relocks, out, d


class TestAdaptivePeriod(unittest.TestCase):
    def test_faster_clock_relocks(self):
        # 300 commits @10ns, CMU switch (12ns straddle), 300 @2ns with a
        # 3-cycle stall afterwards -- the user's exact failure mode:
        # without adaptation everything after the switch collapses to 1
        chg = [(i * 10, i) for i in range(300)]
        t0 = chg[-1][0] + 12
        chg += [(t0 + i * 2, 1000 + i) for i in range(300)]
        chg += [(chg[-1][0] + 6 + i * 2, 2000 + i) for i in range(50)]
        p, rl, out, d = ticks_of(chg)
        self.assertEqual(p, 10)
        self.assertEqual([(o, n) for _, o, n in rl], [(10, 2)])
        self.assertEqual(set(d[:299]), {1})          # old region intact
        self.assertEqual(set(d[300:599]), {1})       # new region 1-cycle
        self.assertEqual(d[599], 3)                  # stall still visible

    def test_non_multiple_period(self):
        chg = [(i * 10, i) for i in range(200)] \
            + [(2003 + i * 3, 1000 + i) for i in range(200)]
        p, rl, out, d = ticks_of(chg)
        self.assertEqual([(o, n) for _, o, n in rl], [(10, 3)])
        self.assertEqual(set(d[201:]), {1})

    def test_change_inside_warmup(self):
        # switch after only 100 commits (< warmup): head-lock keeps the
        # first grid, relock handles the rest
        chg = [(i * 10, i) for i in range(100)] \
            + [(992 + i * 2, 1000 + i) for i in range(400)]
        p, rl, out, d = ticks_of(chg)
        self.assertEqual(p, 10)
        self.assertEqual(set(d[:99]), {1})
        self.assertEqual(set(d[101:]), {1})

    def test_double_change(self):
        chg = [(i * 10, i) for i in range(200)]
        chg += [(1992 + i * 2, 1000 + i) for i in range(200)]
        chg += [(chg[-1][0] + 5 + i * 5, 2000 + i) for i in range(200)]
        p, rl, out, d = ticks_of(chg)
        self.assertEqual([(o, n) for _, o, n in rl], [(10, 2), (2, 5)])
        self.assertEqual(set(d[:199]) | set(d[201:399]) | set(d[401:]), {1})

    def test_stall_locked_warmup_self_heals(self):
        # warmup sees only 2-cycle gaps -> locks 2x the true period;
        # the first 1-cycle gap is off-grid and triggers a downward relock
        chg = [(i * 20, i) for i in range(100)] \
            + [(1990 + i * 10, 1000 + i) for i in range(200)]
        p, rl, out, d = ticks_of(chg)
        self.assertEqual([(o, n) for _, o, n in rl], [(20, 10)])
        self.assertEqual(set(d[101:]), {1})

    def test_explicit_period_disables_adaptation(self):
        chg = [(i * 10, i) for i in range(100)] \
            + [(992 + i * 2, 1000 + i) for i in range(50)]
        p, rl, out, d = ticks_of(chg, period=10)
        self.assertEqual(rl, [])
        self.assertEqual(p, 10)

    def test_uniform_clock_untouched(self):
        chg = [(i * 7, i) for i in range(500)]
        p, rl, out, d = ticks_of(chg)
        self.assertEqual((p, rl), (7, []))
        self.assertEqual(set(d), {1})


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
