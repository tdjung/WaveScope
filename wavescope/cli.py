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

import argparse
import json
import sys

from . import __version__
from .callgrind import write as write_callgrind
from .classify import get_classifier, load_isa_spec
from .disasm import load_binary, text_ranges
from .profiler import EVENTS, run
from .scan import explain as explain_signal, scan as scan_signals
from .waveform import WaveConfig, open_pc_stream, prepare_for_scan


def _add_wave_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--wave", "--vcd", dest="wave", required=True,
                   help="input waveform: .vcd, .fsdb, or .trn/.shm (Cadence)")
    p.add_argument("--verdi-home", default=None,
                   help="Verdi install dir for FSDB tools (default: $VERDI_HOME)")
    p.add_argument("--fsdb-scope", default=None,
                   help="restrict fsdb2vcd conversion to this scope "
                        "(e.g. top.soc.cpu0) -- much faster for big dumps")
    p.add_argument("--fsdbreport-args", default="",
                   help="extra fsdbreport args, ':' separated")
    p.add_argument("--fsdb2vcd-args", default="",
                   help="extra fsdb2vcd args, ':' separated")
    p.add_argument("--cadence-bin", default=None,
                   help="dir containing simvisdbutil for TRN/SHM input "
                        "(default: $XCELIUM_HOME/$CDS_ROOT tools/bin, PATH)")
    p.add_argument("--simvisdbutil-args", default="",
                   help="extra simvisdbutil args, ':' separated")


def _wave_cfg(args) -> WaveConfig:
    return WaveConfig(
        verdi_home=args.verdi_home,
        fsdb_scope=args.fsdb_scope,
        fsdbreport_args=[a for a in args.fsdbreport_args.split(":") if a],
        fsdb2vcd_args=[a for a in args.fsdb2vcd_args.split(":") if a],
        cadence_bin=args.cadence_bin,
        simvisdbutil_args=[a for a in args.simvisdbutil_args.split(":") if a])


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
    res = scan_signals(vcd, text_ranges=ranges, top_n=args.top,
                       max_changes=args.max_changes,
                       isa_strides=strides)
    pcs, clks = res.pc_candidates, res.clock_candidates

    p = res.parse
    print(f"[wavescope] parsed {p.n_signals} signals "
          f"({p.n_vector_tracked} vectors >=8b, {p.n_scalar_tracked} scalars); "
          f"value lines seen={p.value_lines_seen}, matched={p.value_lines_matched}"
          + (" [budget exhausted, increase --max-changes]"
             if p.budget_exhausted else ""),
          file=sys.stderr)
    if p.value_lines_matched == 0:
        print("[wavescope] WARNING: no value changes matched any tracked "
              "signal -- the VCD value-change section may use an "
              "unrecognized dialect. Run 'wavescope signals --wave ...' "
              "and share the output.", file=sys.stderr)

    if args.explain:
        print(explain_signal(res, args.explain, ranges, strides))
        return 0

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


def cmd_signals(args) -> int:
    from .vcd_reader import open_vcd_text, read_header
    vcd = prepare_for_scan(args.wave, _wave_cfg(args))
    with open_vcd_text(vcd) as f:
        signals, ts = read_header(f)
    shown = 0
    for s in signals:
        if args.grep and args.grep.lower() not in s.name.lower():
            continue
        print(f"{s.width:>5}  {s.name}   (id='{s.ident}')")
        shown += 1
    print(f"\n{shown} shown / {len(signals)} total signals; "
          f"timescale={ts} fs", file=sys.stderr)
    if shown == 0 and signals:
        print("no match -- try without --grep", file=sys.stderr)
    elif not signals:
        print("NO signals parsed from the header. The $var declarations "
              "use a form the parser doesn't understand -- please share "
              "the first ~40 lines of the file (head -40 file.vcd).",
              file=sys.stderr)
    return 0


def cmd_profile(args) -> int:
    print(f"[wavescope] loading binary: {args.elf}", file=sys.stderr)
    binary = load_binary(args.elf, args.toolchain_prefix,
                         with_lines=not args.no_lines,
                         demangle=not args.no_demangle)
    print(f"[wavescope]   {len(binary.insns)} instructions, "
          f"{len(binary.funcs)} functions", file=sys.stderr)

    classifier = get_classifier(args.isa, args.isa_ext)

    print(f"[wavescope] reading waveform: {args.wave}", file=sys.stderr)
    samples = open_pc_stream(args.wave, args.clock, args.pc,
                             valid=args.valid, sample_edge=args.edge,
                             clock_period=args.clock_period,
                             cfg=_wave_cfg(args))
    prof = run(samples, binary, classifier,
               clamp_exception_cycles=not args.no_isr_clamp)

    if prof.exceptions:
        print(f"[wavescope] detected {prof.exceptions} exception/interrupt "
              f"entries (boundary cycles "
              f"{'clamped to 1' if not args.no_isr_clamp else 'kept raw'})",
              file=sys.stderr)
    if prof.healed_returns or prof.unmatched_returns:
        print(f"[wavescope] returns: {prof.healed_returns} healed, "
              f"{prof.unmatched_returns} unmatched", file=sys.stderr)
    if prof.drained_frames:
        print(f"[wavescope] {prof.drained_frames} frames alive at end of "
              f"trace; top by accumulated Ir:", file=sys.stderr)
        for call_pc, callee, ir in prof.drained_top:
            cf = binary.func_at(callee)
            name = cf.name if cf else hex(callee)
            print(f"[wavescope]   call@0x{call_pc:x} -> {name}: "
                  f"Ir={ir}", file=sys.stderr)
        print("[wavescope]   (large values here = leaked frames whose "
              "inclusive costs absorbed the rest of the run)",
              file=sys.stderr)
    if prof.unknown_pcs:
        print(f"[wavescope] warning: {prof.unknown_pcs} samples had PCs "
              f"outside the ELF text sections", file=sys.stderr)
    if not args.valid:
        print("[wavescope] note: no --valid signal given; repeated PCs are "
              "treated as stalls. For accurate results use a commit-stage "
              "PC qualified by a commit-valid signal.", file=sys.stderr)

    executed = {f.start for pc in prof.self_cost
                for f in [binary.func_at(pc)] if f}
    print(f"[wavescope] functions: {len(binary.funcs)} in ELF, "
          f"{len(executed)} executed"
          + ("" if args.executed_only else " (emitting all)"),
          file=sys.stderr)

    with open(args.output, "w") as f:
        write_callgrind(prof, f, args.elf, cmd=" ".join(sys.argv[1:]),
                        all_functions=not args.executed_only)

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
    ps.add_argument("--explain", default=None, metavar="SIGNAL",
                    help="show the full scoring breakdown for one signal "
                         "(exact name, suffix, or substring)")
    ps.set_defaults(func=cmd_scan)

    pl = sub.add_parser("signals",
                        help="list every signal parsed from the waveform")
    _add_wave_args(pl)
    pl.add_argument("--grep", default=None,
                    help="only show signals whose name contains this")
    pl.set_defaults(func=cmd_signals)

    pp = sub.add_parser("profile", help="generate callgrind output")
    _add_wave_args(pp)
    pp.add_argument("--elf", required=True, help="ELF with debug symbols")
    pp.add_argument("--clock", default=None,
                    help="clock signal (full path or unique suffix). "
                         "OPTIONAL: without it, cycles are derived from "
                         "PC change times (period auto-detected via GCD)")
    pp.add_argument("--clock-period", default=None, metavar="P",
                    help="cycle length when no clock signal is dumped: "
                         "plain int = dump time units, or '10ns'/'20000ps' "
                         "(default: auto-detect)")
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
    pp.add_argument("--executed-only", action="store_true",
                    help="emit only executed functions (default emits every "
                         "ELF function, unexecuted ones at zero cost, for "
                         "coverage views and simulator parity)")
    pp.add_argument("--no-demangle", action="store_true",
                    help="keep mangled C++/Rust symbol names "
                         "(default: demangle via objdump -C)")
    pp.add_argument("--no-isr-clamp", action="store_true",
                    help="charge full raw cycles at exception/interrupt "
                         "boundaries (default clamps to 1, matching the "
                         "simulator convention across wfi sleeps)")
    pp.add_argument("--no-lines", action="store_true",
                    help="skip addr2line source mapping (faster)")
    pp.add_argument("-o", "--output", default="callgrind.out.wavescope")
    pp.set_defaults(func=cmd_profile)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
