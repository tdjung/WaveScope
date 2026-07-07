"""WaveScope CLI.

Subcommands:
    scan     -- suggest PC / clock signal candidates in a waveform
    profile  -- generate a callgrind profile from waveform + ELF

Typical two-step workflow:

    wavescope scan --wave sim.vcd --elf fw.elf
    wavescope profile --wave sim.vcd --elf fw.elf \\
        --clock top.clk --pc top.core.wb_pc [--valid top.core.wb_valid] \\
        --isa armv7m --toolchain-prefix arm-none-eabi- \\
        -o callgrind.out.wavescope
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .callgrind import write as write_callgrind
from .classify import get_classifier, load_isa_spec
from .disasm import load_binary, text_ranges
from .profiler import EVENTS, run
from .scan import scan as scan_signals
from .waveform import WaveConfig, open_pc_stream, prepare_for_scan


def _add_wave_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--wave", "--vcd", dest="wave", required=True,
                   help="input waveform (.vcd or .fsdb)")
    p.add_argument("--verdi-home", default=None,
                   help="Verdi install dir for FSDB tools (default: $VERDI_HOME)")
    p.add_argument("--fsdb-scope", default=None,
                   help="restrict fsdb2vcd conversion to this scope "
                        "(e.g. top.soc.cpu0) -- much faster for big dumps")
    p.add_argument("--fsdbreport-args", default="",
                   help="extra fsdbreport args, ':' separated")
    p.add_argument("--fsdb2vcd-args", default="",
                   help="extra fsdb2vcd args, ':' separated")


def _wave_cfg(args) -> WaveConfig:
    return WaveConfig(
        verdi_home=args.verdi_home,
        fsdb_scope=args.fsdb_scope,
        fsdbreport_args=[a for a in args.fsdbreport_args.split(":") if a],
        fsdb2vcd_args=[a for a in args.fsdb2vcd_args.split(":") if a])


def cmd_scan(args) -> int:
    ranges = None
    if args.elf:
        ranges = text_ranges(args.elf, args.toolchain_prefix)
        print(f"[wavescope] ELF text ranges: "
              + ", ".join(f"0x{a:x}-0x{b:x}" for a, b in ranges),
              file=sys.stderr)
    else:
        print("[wavescope] no --elf given: scoring without address-range "
              "matching (much weaker). Passing the ELF is recommended.",
              file=sys.stderr)

    strides = (2, 4)
    if args.isa:
        strides = tuple(load_isa_spec(args.isa).get("insn_sizes", [2, 4]))

    vcd = prepare_for_scan(args.wave, _wave_cfg(args))
    pcs, clks = scan_signals(vcd, text_ranges=ranges, top_n=args.top,
                             max_changes=args.max_changes,
                             isa_strides=strides)

    if args.json:
        print(json.dumps({"pc_candidates": [c.to_dict() for c in pcs],
                          "clock_candidates": [c.to_dict() for c in clks]},
                         indent=2))
        return 0

    def show(title, cands):
        print(f"\n{title}")
        if not cands:
            print("  (none found)")
        for i, c in enumerate(cands, 1):
            print(f"  {i}. {c.name}  [score {c.score:.2f}]")
            for r in c.reasons:
                print(f"       - {r}")

    show("PC signal candidates:", pcs)
    show("Clock signal candidates:", clks)
    if pcs and clks:
        print(f"\nNext step:\n  wavescope profile --wave {args.wave} "
              f"--elf {args.elf or '<elf>'} \\\n"
              f"      --clock {clks[0].name} --pc {pcs[0].name} "
              f"[--valid <commit_valid>] -o callgrind.out.wavescope")
    return 0


def cmd_profile(args) -> int:
    print(f"[wavescope] loading binary: {args.elf}", file=sys.stderr)
    binary = load_binary(args.elf, args.toolchain_prefix,
                         with_lines=not args.no_lines)
    print(f"[wavescope]   {len(binary.insns)} instructions, "
          f"{len(binary.funcs)} functions", file=sys.stderr)

    classifier = get_classifier(args.isa, args.isa_ext)

    print(f"[wavescope] reading waveform: {args.wave}", file=sys.stderr)
    samples = open_pc_stream(args.wave, args.clock, args.pc,
                             valid=args.valid, sample_edge=args.edge,
                             cfg=_wave_cfg(args))
    prof = run(samples, binary, classifier)

    if prof.unknown_pcs:
        print(f"[wavescope] warning: {prof.unknown_pcs} samples had PCs "
              f"outside the ELF text sections", file=sys.stderr)
    if not args.valid:
        print("[wavescope] note: no --valid signal given; repeated PCs are "
              "treated as stalls. For accurate results use a commit-stage "
              "PC qualified by a commit-valid signal.", file=sys.stderr)

    with open(args.output, "w") as f:
        write_callgrind(prof, f, args.elf, cmd=" ".join(sys.argv[1:]))

    totals = ", ".join(f"{n}={v}" for n, v in zip(EVENTS, prof.total))
    print(f"[wavescope] totals: {totals}", file=sys.stderr)
    print(f"[wavescope] wrote {args.output} "
          f"(open with kcachegrind/qcachegrind)", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="wavescope",
        description="Waveform PC trace + debug symbols -> callgrind profile")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("scan", help="suggest PC/clock signal candidates")
    _add_wave_args(ps)
    ps.add_argument("--elf", default=None,
                    help="ELF binary (strongly recommended: enables "
                         "address-range matching)")
    ps.add_argument("--isa", default=None,
                    help="ISA hint for stride detection (riscv/armv7m/aarch64)")
    ps.add_argument("--toolchain-prefix", default="")
    ps.add_argument("--top", type=int, default=5)
    ps.add_argument("--max-changes", type=int, default=2_000_000,
                    help="value-change budget for sampling large waveforms")
    ps.add_argument("--json", action="store_true",
                    help="machine-readable output (for UI integration)")
    ps.set_defaults(func=cmd_scan)

    pp = sub.add_parser("profile", help="generate callgrind output")
    _add_wave_args(pp)
    pp.add_argument("--elf", required=True, help="ELF with debug symbols")
    pp.add_argument("--clock", required=True,
                    help="clock signal (full path or unique suffix)")
    pp.add_argument("--pc", required=True,
                    help="program counter signal (prefer commit-stage PC)")
    pp.add_argument("--valid", default=None,
                    help="optional commit-valid signal; PC sampled only when 1")
    pp.add_argument("--edge", choices=["rising", "falling"], default="rising")
    pp.add_argument("--isa", default="riscv",
                    help="riscv | armv7m (Cortex-M/Thumb-2) | aarch64")
    pp.add_argument("--isa-ext", action="append", default=[],
                    help="custom-instruction overlay JSON (repeatable)")
    pp.add_argument("--toolchain-prefix", default="",
                    help="binutils prefix, e.g. riscv64-unknown-elf-, "
                         "arm-none-eabi-, aarch64-linux-gnu-")
    pp.add_argument("--no-lines", action="store_true",
                    help="skip addr2line source mapping (faster)")
    pp.add_argument("-o", "--output", default="callgrind.out.wavescope")
    pp.set_defaults(func=cmd_profile)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
