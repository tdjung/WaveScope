"""Real-toolchain regression tests (riscv64-unknown-elf-gcc, skipped if
absent): the objdump 'add'-as-hex size bug, real -msave-restore
millicode layout (aliases, overlapping sizes, fall-through chains),
empty-stack tail arcs, and helper arc suppression."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope.classify import get_classifier
from wavescope.disasm import _parse_disasm_fields, load_binary
from wavescope.profiler import E_IR, run

PREFIX = "riscv64-unknown-elf-"
HAVE_RV = shutil.which(PREFIX + "gcc") and shutil.which(PREFIX + "objdump")

SRC = """
#define NI __attribute__((noinline))
NI int leaf(int x) { return x * 3; }
NI int two(int a, int b) { int r = leaf(a); return r + leaf(b) + a * b; }
NI int many(int a, int b, int c, int d, int e, int f, int g, int h) {
    int r = leaf(a);
    r += leaf(b); r += leaf(c); r += leaf(d);
    r += leaf(e); r += leaf(f); r += leaf(g); r += leaf(h);
    return r + a*b + c*d + e*f + g*h;
}
NI int main(void) { return two(1, 2) + many(1,2,3,4,5,6,7,8); }
"""


class TestDisasmFieldParsing(unittest.TestCase):
    """Hex-looking mnemonics ('add' = 0xadd) must never be consumed as
    encoding bytes -- that inflated instruction sizes and corrupted
    every fallthrough computation (false exceptions/anomalies/Bcm)."""

    def test_compressed_add(self):
        r = _parse_disasm_fields("   10078:\t953e                \tadd\ta0,a0,a5")
        self.assertEqual(r, (0x10078, ["953e"], "add", "a0,a0,a5"))

    def test_wide_add(self):
        r = _parse_disasm_fields(
            "   1008e:\t02940433          \tmul\ts0,s0,s1")
        self.assertEqual(r[1:], (["02940433"], "mul", "s0,s0,s1"))

    def test_x86_byte_list_with_space_separated_operands(self):
        r = _parse_disasm_fields(
            "  401000:\t48 89 e5             \tmov    %rsp,%rbp")
        self.assertEqual(r, (0x401000, ["48", "89", "e5"], "mov",
                             "%rsp,%rbp"))

    def test_tabless_fallback_even_tokens_only(self):
        r = _parse_disasm_fields("   10078: 953e add a0,a0,a5")
        self.assertEqual(r[1:], (["953e"], "add", "a0,a0,a5"))

    def test_encoding_only_continuation(self):
        r = _parse_disasm_fields("   10078:\t953e")
        self.assertEqual(r[2], "")


@unittest.skipUnless(HAVE_RV, "riscv64-unknown-elf toolchain not available")
class TestRealMillicode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        src = os.path.join(cls.dir, "t.c")
        cls.elf = os.path.join(cls.dir, "t.elf")
        with open(src, "w") as f:
            f.write(SRC)
        subprocess.run([PREFIX + "gcc", "-march=rv32imac", "-mabi=ilp32",
                        "-O1", "-msave-restore", "-nostdlib",
                        "-Wl,-e,main", "-o", cls.elf, src, "-lgcc"],
                       check=True)
        cls.b = load_binary(cls.elf, PREFIX, with_lines=False)
        cls.by_name = {f.name: f for f in cls.b.funcs}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def _addr(self, name):
        return self.by_name[name].start

    def _insns(self, name):
        f = self.by_name[name]
        return sorted(a for a in self.b.insns if f.start <= a < f.end)

    def test_add_sizes_correct(self):
        adds = [i for i in self.b.insns.values() if i.mnemonic == "add"]
        self.assertTrue(adds)
        self.assertTrue(all(i.size in (2, 4) for i in adds))
        # every function's instruction sizes tile its range exactly
        f = self.by_name["two"]
        pcs = self._insns("two")
        for a, nxt in zip(pcs, pcs[1:]):
            self.assertEqual(a + self.b.insns[a].size, nxt,
                             f"size gap at 0x{a:x}")

    def test_millicode_funcs_present(self):
        for n in ("__riscv_save_0", "__riscv_restore_0",
                  "__riscv_restore_10"):
            self.assertIn(n, self.by_name)
        self.assertTrue(self.b.is_func_entry(
            self._addr("__riscv_restore_0")))

    def test_full_run_no_false_exceptions(self):
        """Simulate the complete main->two->many execution; correct
        sizes mean ZERO heuristic exceptions on a clean trace."""
        b = self.b
        save0 = self._insns("__riscv_save_0")
        rest0 = self._insns("__riscv_restore_0")
        leaf = self._insns("leaf")

        def body(name):
            return self._insns(name)

        two, many, main = body("two"), body("many"), body("main")
        tr = []
        tr += [main[0]] + save0                      # main prologue
        tr += main[1:3] + [main[3]]                  # li,li, jal two
        tr += [two[0]] + save0
        # two body: follow real flow -- jal leaf twice, then j restore_0
        i = 1
        while i < len(two):
            pc = two[i]
            tr.append(pc)
            if b.insns[pc].mnemonic in ("jal",) and "leaf" in b.insns[pc].operands:
                tr += leaf
            i += 1
        tr += rest0                                   # two's j restore_0 chain
        # back in main after two
        idx = main.index(next(a for a in main
                              if "many" in b.insns[a].operands))
        for pc in main[4:idx + 1]:
            tr.append(pc)
        # many: prologue save_10 -- follow the REAL flow (the chain
        # jumps into the MIDDLE of save_4, skipping its sp adjust,
        # and shares save_4's jr t0 tail)
        def walk_millicode(entry):
            path, pc = [], entry
            while True:
                path.append(pc)
                insn = b.insns[pc]
                if insn.mnemonic == "jr":
                    return path
                if insn.mnemonic in ("j", "c.j"):
                    pc = int(insn.operands.split()[0], 16)
                else:
                    pc += insn.size

        tr += [many[0]] + walk_millicode(self._addr("__riscv_save_10"))
        for pc in many[1:]:
            tr.append(pc)
            if b.insns[pc].mnemonic == "jal" and "leaf" in b.insns[pc].operands:
                tr += leaf
        # many's epilogue: j restore_10, full chain
        tr += self._insns("__riscv_restore_10") \
            + self._insns("__riscv_restore_4") + rest0
        # back in main; main epilogue j restore_0
        tr += main[idx + 1:]
        tr += rest0
        samples = [(i, pc) for i, pc in enumerate(tr)]
        prof = run(iter(samples), b, get_classifier("riscv"))

        # cross-validate the transcribed sim engine on the same real
        # execution: tail-form millicode epilogues -> full agreement
        from wavescope.simcore import compare_profiles, run_sim
        sim = run_sim(iter(samples), b, get_classifier("riscv"))
        cmp = compare_profiles(sim, prof, b)
        self.assertEqual(cmp["total"], {}, cmp)
        self.assertEqual(cmp["arcs"], [], cmp)

        self.assertEqual(prof.exceptions, 0)          # no false ISR entries
        r0, r10 = self._addr("__riscv_restore_0"), \
            self._addr("__riscv_restore_10")
        # direct tail arcs into restore_0: two's and main's epilogues
        r0_arcs = {cp: cs for (cp, cal), cs in prof.calls.items()
                   if cal == r0}
        self.assertEqual(len(r0_arcs), 2)
        self.assertEqual(sum(cs.count for cs in r0_arcs.values()), 2)
        # many's chain arc targets the chain HEAD and carries the whole
        # chain's inclusive
        r10_arcs = [cs for (cp, cal), cs in prof.calls.items()
                    if cal == r10]
        self.assertEqual(len(r10_arcs), 1)
        chain_ir = len(self._insns("__riscv_restore_10")) \
            + len(self._insns("__riscv_restore_4")) + len(rest0)
        self.assertEqual(r10_arcs[0].inclusive[E_IR], chain_ir)
        # no helper->helper arcs
        for (cp, cal) in prof.calls:
            cf = b.func_at(cp)
            if cf is not None and cf.name.startswith("__riscv_"):
                self.fail(f"helper-originated arc 0x{cp:x}")

    def test_empty_stack_tail_arc_counted(self):
        """A 'j __riscv_restore_0' with an empty call stack must still
        record the arc COUNT (simulator parity) -- the originally
        missing call."""
        b = self.b
        two = self._insns("two")
        j_pc = two[-1]
        self.assertEqual(b.insns[j_pc].mnemonic, "j")
        tr = two[-3:] + self._insns("__riscv_restore_0")
        prof = run(iter([(i, pc) for i, pc in enumerate(tr)]), b,
                   get_classifier("riscv"))
        r0 = self._addr("__riscv_restore_0")
        self.assertEqual(prof.calls[(j_pc, r0)].count, 1)


if __name__ == "__main__":
    unittest.main()
