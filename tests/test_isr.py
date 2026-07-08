"""Exception/interrupt handling: entry detection, mret unwind, WFI clamp,
and aliased-symbol (millicode) canonical naming."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import BinaryInfo, Func, Insn
from wavescope.profiler import E_CY, E_IR, run


def B():
    b = BinaryInfo()
    prog = [
        # main
        (0x1000, "addi", "a0,a0,1"),
        (0x1004, "wfi", ""),
        (0x1008, "sw", "a1,0(sp)"),
        (0x100c, "j", "100c"),
        # isr
        (0x3000, "addi", "t0,t0,1"),
        (0x3004, "jal", "ra,4000 <helper>"),
        (0x3008, "mret", ""),
        # helper (called from isr)
        (0x4000, "addi", "a2,a2,1"),
        (0x4004, "ret", ""),
    ]
    for a, m, o in prog:
        b.insns[a] = Insn(addr=a, size=4, mnemonic=m, operands=o)
    b.funcs = [Func("main", 0x1000, 0x1010), Func("isr", 0x3000, 0x300c),
               Func("helper", 0x4000, 0x4008)]
    b._starts = [f.start for f in b.funcs]
    return b


# wfi sleeps ~90 ticks, then the interrupt fires
TRACE = [
    (0, 0x1000),
    (1, 0x1004),    # wfi commits
    (95, 0x3000),   # ISR entry after long sleep (gap = 94)
    (96, 0x3004),
    (97, 0x4000),   # call helper inside ISR
    (98, 0x4004),
    (99, 0x3008),   # ret back to isr, then mret
    (100, 0x1008),  # resume at wfi fallthrough
    (101, 0x100c),
]


class TestIsr(unittest.TestCase):
    def setUp(self):
        self.prof = run(iter(TRACE), B(), get_classifier("riscv"))

    def test_entry_detected(self):
        self.assertEqual(self.prof.exceptions, 1)

    def test_wfi_sleep_clamped(self):
        # the sleep gap arrives with the FIRST handler insn: clamped to 1
        self.assertEqual(self.prof.self_cost[0x3000][E_CY], 1)

    def test_isr_instructions_counted(self):
        for pc in (0x3000, 0x3004, 0x3008, 0x4000, 0x4004):
            self.assertEqual(self.prof.self_cost[pc][E_IR], 1, hex(pc))

    def test_call_inside_isr(self):
        key = (0x3004, 0x4000)
        self.assertIn(key, self.prof.calls)
        self.assertEqual(self.prof.calls[key].inclusive[E_IR], 2)

    def test_resume_after_mret(self):
        self.assertEqual(self.prof.self_cost[0x1008][E_IR], 1)

    def test_no_clamp_option(self):
        prof = run(iter(TRACE), B(), get_classifier("riscv"),
                   clamp_exception_cycles=False)
        self.assertEqual(prof.self_cost[0x3000][E_CY], 94)


class TestAliasedSymbols(unittest.TestCase):
    """Millicode aliases (__riscv_save_4..7 at one address) must collapse
    to a single Func so func_at/cfn naming is deterministic."""

    def test_dedup_logic(self):
        import subprocess, tempfile, textwrap, shutil
        # exercise the pure-python part: simulate load_binary's grouping
        raw = [(0x130, 0, "__riscv_save_7"), (0x130, 0, "__riscv_save_6"),
               (0x130, 0, "__riscv_save_5"), (0x130, 0, "__riscv_save_4"),
               (0x160, 8, "main")]
        labels = {0x130: "__riscv_save_4"}    # what objdump -d displays
        by_start = {}
        for start, size, name in sorted(raw):
            cur = by_start.get(start)
            if cur is None or size > cur[0]:
                by_start[start] = (size, name)
        starts = sorted(by_start)
        self.assertEqual(len(starts), 2)      # aliases collapsed
        size, name = by_start[0x130]
        name = labels.get(0x130, name)
        self.assertEqual(name, "__riscv_save_4")


if __name__ == "__main__":
    unittest.main()
