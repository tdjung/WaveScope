"""Scanner test: PC-like signal must outrank noise signals."""

import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.scan import scan

TEXT = [(0x8000_0000, 0x8000_4000)]


def make_vcd(path: str, cycles: int = 400) -> None:
    random.seed(7)
    lines = [
        "$timescale 1ns $end",
        "$scope module top $end",
        "$var wire 1 ! clk $end",
        "$var wire 1 % rst_n $end",
        "$scope module cpu $end",
        "$var wire 32 @ dbg_addr [31:0] $end",     # PC (unhelpful name)
        "$var wire 32 # counter [31:0] $end",      # monotonically counting
        "$var wire 32 $ data_bus [31:0] $end",     # random noise
        "$upscope $end",
        "$upscope $end",
        "$enddefinitions $end",
        "#0", "0!", "1%",
    ]
    t, pc, cnt = 0, 0x8000_0100, 0
    for _ in range(cycles):
        t += 5
        lines.append(f"#{t}")
        # PC: mostly +4, sometimes a branch inside text range
        pc = pc + 4 if random.random() > 0.15 else \
            0x8000_0000 + random.randrange(0, 0x4000, 4)
        cnt += 1
        lines += [f"b{pc:b} @", f"b{cnt:b} #",
                  f"b{random.getrandbits(32):b} $", "1!"]
        t += 5
        lines += [f"#{t}", "0!"]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


class TestScan(unittest.TestCase):
    def test_ranking(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.vcd")
            make_vcd(p)
            pcs, clks = scan(p, text_ranges=TEXT, isa_strides=(2, 4))

        self.assertTrue(pcs)
        self.assertTrue(pcs[0].name.endswith("dbg_addr"),
                        f"expected dbg_addr first, got {[c.name for c in pcs]}")
        # counter also lands in low text range? counter values are tiny,
        # outside 0x80000000 range -> must rank below dbg_addr
        names = [c.name for c in pcs]
        if any(n.endswith("counter") for n in names):
            self.assertLess(names.index("top.cpu.dbg_addr"),
                            [i for i, n in enumerate(names)
                             if n.endswith("counter")][0])
        self.assertTrue(any("% of values in ELF text" in r
                            for r in pcs[0].reasons))

        self.assertTrue(clks)
        self.assertTrue(clks[0].name.endswith("clk"),
                        f"expected clk first, got {[c.name for c in clks]}")

    def test_without_elf(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.vcd")
            make_vcd(p)
            pcs, _ = scan(p, text_ranges=None)
        # stride heuristic alone should still surface dbg_addr near the top
        top2 = [c.name for c in pcs[:2]]
        self.assertTrue(any(n.endswith("dbg_addr") for n in top2), top2)


if __name__ == "__main__":
    unittest.main()
