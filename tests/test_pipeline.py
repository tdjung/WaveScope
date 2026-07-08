"""End-to-end test with a synthetic VCD and a hand-built BinaryInfo.

Program modeled (RISC-V, 4-byte insns):

    0x1000 main:   addi          ; 1 cy
    0x1004         jal  ra, func ; call -> 0x2000
    0x1008         lw            ; after return
    0x100c         beq  -> taken back to 0x1004? no: taken to 0x1014
    0x1014         sw
    0x1018         j 0x1018      ; (not executed in trace)

    0x2000 func:   addi          ; 2 cycles (stall)
    0x2004         ret           ; -> 0x1008
"""

import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import (E_BC, E_BCM, E_CY, E_DR, E_DW, E_IR,
                                run)
from wavescope.callgrind import write as write_callgrind
from wavescope.vcd_reader import iter_pc_samples


def make_binary() -> BinaryInfo:
    b = BinaryInfo()
    prog = [
        (0x1000, "addi", "a0,a0,1"),
        (0x1004, "jal", "ra,2000 <func>"),
        (0x1008, "lw", "a1,0(sp)"),
        (0x100c, "beq", "a0,a1,1014"),
        (0x1010, "addi", "a0,a0,0"),
        (0x1014, "sw", "a1,0(sp)"),
        (0x1018, "j", "1018"),
        (0x2000, "addi", "a2,a2,1"),
        (0x2004, "ret", ""),
    ]
    for addr, m, ops in prog:
        b.insns[addr] = Insn(addr=addr, size=4, mnemonic=m, operands=ops)
    b.funcs = [Func("main", 0x1000, 0x101c), Func("func", 0x2000, 0x2008)]
    b._starts = [f.start for f in b.funcs]
    b.lines = {a: ("prog.c", (a & 0xFFF) // 4 + 1) for a, _, _ in prog}
    return b


# tick sequence: (tick, pc). func's addi stalls one extra tick.
TRACE = [
    (0, 0x1000),
    (1, 0x1004),
    (2, 0x2000),   # call taken
    # tick 3: stall on 0x2000 handled by same-pc suppression below
    (4, 0x2004),   # addi took 2 cycles
    (5, 0x1008),   # ret
    (6, 0x100c),
    (7, 0x1014),   # beq taken (skips 0x1010)
    (8, 0x1018),
]


def make_vcd(path: str) -> None:
    lines = [
        "$timescale 1ns $end",
        "$scope module top $end",
        "$var wire 1 ! clk $end",
        "$var wire 32 @ pc [31:0] $end",
        "$upscope $end",
        "$enddefinitions $end",
    ]
    t = 0
    pcs = dict(TRACE)
    stall = {3: 0x2000}
    for tick in range(9):
        pc = pcs.get(tick, stall.get(tick))
        lines.append(f"#{t}")
        lines.append("0!")
        t += 5
        lines.append(f"#{t}")
        if pc is not None:
            lines.append(f"b{pc:b} @")
        lines.append("1!")
        t += 5
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


class TestVcdReader(unittest.TestCase):
    def test_samples(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.vcd")
            make_vcd(p)
            samples = list(iter_pc_samples(p, "clk", "pc"))
        self.assertEqual(samples[0], (0, 0x1000))
        self.assertEqual(samples[2], (2, 0x2000))
        self.assertEqual(samples[3], (3, 0x2000))  # stall tick
        self.assertEqual(len(samples), 9)


class TestProfiler(unittest.TestCase):
    def setUp(self):
        self.binary = make_binary()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.vcd")
            make_vcd(p)
            samples = list(iter_pc_samples(p, "clk", "pc"))
        self.prof = run(samples, self.binary, get_classifier("riscv"))

    def test_instruction_counts(self):
        sc = self.prof.self_cost
        self.assertEqual(sc[0x1000][E_IR], 1)
        self.assertEqual(sc[0x2000][E_IR], 1)     # stall did not double count
        self.assertNotIn(0x1010, sc)              # skipped by taken branch

    def test_stall_cycles(self):
        # arrival attribution: the instruction AFTER the hold pays the gap
        self.assertEqual(self.prof.self_cost[0x2000][E_CY], 1)
        self.assertEqual(self.prof.self_cost[0x2004][E_CY], 2)

    def test_branch(self):
        sc = self.prof.self_cost[0x100c]
        self.assertEqual(sc[E_BC], 1)
        self.assertEqual(sc[E_BCM], 1)            # taken

    def test_call_tracked(self):
        key = (0x1004, 0x2000)
        self.assertIn(key, self.prof.calls)
        cs = self.prof.calls[key]
        self.assertEqual(cs.count, 1)
        self.assertEqual(cs.inclusive[E_IR], 2)   # addi + ret inside func
        self.assertEqual(cs.inclusive[E_CY], 3)   # 1 + stalled ret pays 2

    def test_mem_events(self):
        self.assertEqual(self.prof.self_cost[0x1008][E_DR], 1)
        self.assertEqual(self.prof.self_cost[0x1014][E_DW], 1)

    def test_callgrind_output(self):
        buf = io.StringIO()
        write_callgrind(self.prof, buf, "prog.elf")
        text = buf.getvalue()
        self.assertIn("events: Ir Cy", text)
        self.assertIn("fn=main", text)
        self.assertIn("fn=func", text)
        self.assertIn("cfn=func", text)
        self.assertIn("calls=1 0x2000", text)


if __name__ == "__main__":
    unittest.main()
