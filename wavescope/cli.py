"""WaveScope CLI.

Usage:
    wavescope --vcd sim.vcd --elf firmware.elf \\
              --clock top.clk --pc top.core.commit_pc \\
              [--valid top.core.commit_valid] \\
              [--toolchain-prefix riscv64-unknown-elf-] \\
              -o callgrind.out.wavescope
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .callgrind import write as write_callgrind
from .classify import get_classifier
from .disasm import load_binary
from .profiler import EVENTS, run
from .vcd_reader import iter_pc_samples


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="wavescope",
        description="Waveform PC trace + debug symbols -> callgrind profile")
    p.add_argument("--vcd", required=True, help="input VCD waveform")
    p.add_argument("--elf", required=True, help="ELF with debug symbols")
    p.add_argument("--clock", required=True,
                   help="clock signal name (full path or unique suffix)")
    p.add_argument("--pc", required=True,
                   help="program counter signal name (prefer commit-stage PC)")
    p.add_argument("--valid", default=None,
                   help="optional commit-valid signal; PC sampled only when 1")
    p.add_argument("--edge", choices=["rising", "falling"], default="rising")
    p.add_argument("--isa", default="riscv")
    p.add_argument("--toolchain-prefix", default="",
                   help="binutils prefix, e.g. riscv64-unknown-elf-")
    p.add_argument("--no-lines", action="store_true",
                   help="skip addr2line source mapping (faster)")
    p.add_argument("-o", "--output", default="callgrind.out.wavescope")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    print(f"[wavescope] loading binary: {args.elf}", file=sys.stderr)
    binary = load_binary(args.elf, args.toolchain_prefix,
                         with_lines=not args.no_lines)
    print(f"[wavescope]   {len(binary.insns)} instructions, "
          f"{len(binary.funcs)} functions", file=sys.stderr)

    classifier = get_classifier(args.isa)

    print(f"[wavescope] reading waveform: {args.vcd}", file=sys.stderr)
    samples = iter_pc_samples(args.vcd, args.clock, args.pc,
                              sample_edge=args.edge, valid_name=args.valid)
    prof = run(samples, binary, classifier)

    if prof.unknown_pcs:
        print(f"[wavescope] warning: {prof.unknown_pcs} samples had PCs "
              f"outside the ELF text sections", file=sys.stderr)
    if not args.valid:
        print("[wavescope] note: no --valid signal given; repeated PCs are "
              "treated as stalls. For accurate results use a commit-stage "
              "PC qualified by a commit-valid signal.", file=sys.stderr)

    with open(args.output, "w") as f:
        write_callgrind(prof, f, args.elf,
                        cmd=" ".join(argv or sys.argv[1:]))

    totals = ", ".join(f"{n}={v}" for n, v in zip(EVENTS, prof.total))
    print(f"[wavescope] totals: {totals}", file=sys.stderr)
    print(f"[wavescope] wrote {args.output} "
          f"(open with kcachegrind/qcachegrind)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
