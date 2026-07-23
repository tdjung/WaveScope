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
from .profiler import EVENTS, DebugTrace, run
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
    p.add_argument("--fsdbreport-bin", default=None,
                   help="exact fsdbreport executable/wrapper to run "
                        "(overrides discovery; for license-queue wrappers)")
    p.add_argument("--fsdb2vcd-bin", default=None,
                   help="exact fsdb2vcd executable/wrapper to run")
    p.add_argument("--simvisdbutil-bin", default=None,
                   help="exact simvisdbutil executable/wrapper to run")
    p.add_argument("--reconvert", action="store_true",
                   help="ignore cached FSDB/TRN->VCD conversions and "
                        "convert again (default reuses a conversion newer "
                        "than the source, saving license checkouts)")


def _wave_cfg(args) -> WaveConfig:
    return WaveConfig(
        verdi_home=args.verdi_home,
        fsdb_scope=args.fsdb_scope,
        fsdbreport_args=[a for a in args.fsdbreport_args.split(":") if a],
        fsdb2vcd_args=[a for a in args.fsdb2vcd_args.split(":") if a],
        cadence_bin=args.cadence_bin,
        simvisdbutil_args=[a for a in args.simvisdbutil_args.split(":") if a],
        fsdbreport_bin=args.fsdbreport_bin,
        fsdb2vcd_bin=args.fsdb2vcd_bin,
        simvisdbutil_bin=args.simvisdbutil_bin,
        reconvert=args.reconvert)


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

    # --- behavioral epc validation (--check-epc) -----------------------
    epc_checks = None
    if args.check_epc is not None:
        from .scan import check_epc_behavior
        cands = [c.name for c in res.epc_candidates]
        if isinstance(args.check_epc, str):
            cands += [n for n in args.check_epc.split(",") if n
                      and n not in cands]
        pc_sig = args.pc or (pcs[0].name if pcs else None)
        if not pc_sig:
            print("[wavescope] --check-epc: no PC candidate found and no "
                  "--pc given", file=sys.stderr)
            return 2
        if not cands:
            print("[wavescope] --check-epc: no epc candidates by name. "
                  "mepc may live in a CSR array -- pass explicit names: "
                  "--check-epc top.cpu.csr.csr_mem_833,... "
                  "(find them via 'wavescope signals --grep csr')",
                  file=sys.stderr)
            return 2
        print(f"[wavescope] behavioral epc check against pc={pc_sig} "
              f"(first {args.check_limit} commits)...", file=sys.stderr)
        epc_checks = check_epc_behavior(vcd, pc_sig, cands,
                                        text_ranges=ranges,
                                        limit=args.check_limit)

    if args.json:
        d = {"pc_candidates": [c.to_dict() for c in pcs],
             "clock_candidates": [c.to_dict() for c in clks],
             "epc_candidates": [c.to_dict() for c in res.epc_candidates]}
        if epc_checks is not None:
            d["epc_check"] = [c.to_dict() for c in epc_checks]
        print(json.dumps(d, indent=2))
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
    if res.epc_candidates:
        show("Exception-PC (mepc) candidates for --epc:", res.epc_candidates)
    if epc_checks is not None:
        print("\nBehavioral epc check (a real exception-PC register: value "
              "changes land in .text,\ncoincide with PC discontinuities, "
              "and are later committed as the resume PC):")
        print(f"  {'signal':<40s} {'changes':>7s} {'->text':>7s} "
              f"{'resumed':>8s} {'@disc':>6s}")
        ranked = sorted(epc_checks,
                        key=lambda c: (c.resumed, c.text_hits, -c.expired),
                        reverse=True)
        for c in ranked:
            if c.changes == 0:
                row = f"  {c.name:<40s} {'0 (constant -- not an epc)':>7s}"
            else:
                row = (f"  {c.name:<40s} {c.changes:>7d} "
                       f"{100 * c.text_hits // c.changes:>6d}% "
                       f"{c.resumed:>4d}/{c.changes:<3d} "
                       f"{100 * c.disc_aligned // c.changes:>5d}%")
            print(row)
        best = ranked[0]
        if best.changes and best.resumed:
            q = best.resumed / best.changes
            verdict = ("strong" if q > 0.9 and best.text_hits == best.changes
                       else "plausible" if q > 0.5 else "weak")
            print(f"  => {verdict} match: --epc {best.name}"
                  + ("" if q > 0.9 else
                     "  (unresumed changes: nested traps at trace end, "
                     "context switches, or not actually an epc)"))
        else:
            print("  => no candidate behaves like an exception PC over "
                  "this window; either no trap fired (try a longer "
                  "--check-limit) or mepc is not in the dump")
    if pcs and clks:
        epc_hint = f"--epc {res.epc_candidates[0].name} " \
            if res.epc_candidates else ""
        print(f"\nNext step:\n  wavescope profile --wave {args.wave} "
              f"--elf {args.elf or '<elf>'} \\\n"
              f"      --clock {clks[0].name} --pc {pcs[0].name} "
              f"{epc_hint}[--valid <commit_valid>] -o callgrind.out.wavescope")
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
          f"{len(binary.funcs)} functions"
          + (f" ({len(binary.data_syms)} in-text data objects excluded, "
             f"e.g. {next(iter(sorted(binary.data_syms.values())))})"
             if binary.data_syms else ""), file=sys.stderr)

    classifier = get_classifier(args.isa, args.isa_ext)

    if args.epc and args.isr_level:
        print("[wavescope] --epc and --isr-level are mutually exclusive "
              "(address-valued mepc/ELR vs level-valued IPSR)",
              file=sys.stderr)
        return 2
    isr_sig = args.epc or args.isr_level
    aux_mode = "level" if args.isr_level else "epc"
    level_mask = None
    if args.isr_level_mask:
        level_mask = int(args.isr_level_mask, 0)
    elif args.isr_level and "psr" in args.isr_level.lower() \
            and "ipsr" not in args.isr_level.lower():
        level_mask = 0x1FF   # full xPSR dumped: isolate the IPSR field
        print("[wavescope] --isr-level looks like a full xPSR: masking "
              "with 0x1ff to isolate IPSR (override with "
              "--isr-level-mask)", file=sys.stderr)

    print(f"[wavescope] reading waveform: {args.wave}", file=sys.stderr)

    def make_stream():
        return open_pc_stream(args.wave, args.clock, args.pc,
                              valid=args.valid, sample_edge=args.edge,
                              clock_period=args.clock_period,
                              cfg=_wave_cfg(args), epc=isr_sig,
                              clock_counter=args.clock_counter,
                              stream_cache=not args.no_stream_cache)

    import time as _time0
    _open_t0 = _time0.perf_counter()
    samples = make_stream()
    _open_dt = _time0.perf_counter() - _open_t0
    reader_timer = None
    if args.timing:
        import time as _time

        class _Timed:
            def __init__(self, it):
                self.it = iter(it)
                self.t = 0.0
                self.n = 0
                self.t0 = _time.perf_counter()

            def __iter__(self):
                return self

            def __next__(self):
                s = _time.perf_counter()
                try:
                    v = next(self.it)
                except StopIteration:
                    self.t += _time.perf_counter() - s
                    raise
                self.t += _time.perf_counter() - s
                self.n += 1
                if self.n % 2000000 == 0:
                    el = _time.perf_counter() - self.t0
                    print(f"[wavescope] ... {self.n} samples, "
                          f"{el:.0f}s elapsed ({self.n / el:.0f}/s)",
                          file=sys.stderr)
                return v

        samples = reader_timer = _Timed(samples)

    if args.engine == "sim":            # backward-compat alias
        args.engine = "default"
    if args.engine != "legacy":
        if args.isr_level:
            print("[wavescope] the default engine supports RISC-V epc semantics "
                  "only (--isr-level is a legacy-engine feature)",
                  file=sys.stderr)
            return 2
        if args.no_isr_clamp:
            print("[wavescope] note: --no-isr-clamp is ignored by the sim "
                  "engine (the reference has no such switch)",
                  file=sys.stderr)
        if args.debug_func and args.engine == "default":
            print("[wavescope] note: --debug-func traces the legacy "
                  "engine; use --engine both to run it alongside",
                  file=sys.stderr)
    debug = None
    dbg_out = None
    if args.debug_func:
        wanted = [w for arg in args.debug_func for w in arg.split(",") if w]
        watch = []
        for w in wanted:
            f = None
            if w.lower().startswith("0x"):
                f = binary.func_at(int(w, 16))
            if f is None:
                f = next((x for x in binary.funcs if x.name == w), None)
            if f is None:   # suffix match (mangled / prefixed names)
                sufs = [x for x in binary.funcs if x.name.endswith(w)]
                if len(sufs) == 1:
                    f = sufs[0]
                elif len(sufs) > 1:
                    print(f"[wavescope] --debug-func {w!r} is ambiguous: "
                          + ", ".join(x.name for x in sufs[:8]),
                          file=sys.stderr)
                    return 2
            if f is None:
                near = [x.name for x in binary.funcs if w.lower()
                        in x.name.lower()][:8]
                print(f"[wavescope] --debug-func {w!r}: no such function"
                      + (f"; close: {', '.join(near)}" if near else ""),
                      file=sys.stderr)
                return 2
            watch.append(f)
        dbg_out = open(args.debug_log, "w") if args.debug_log else sys.stderr
        debug = DebugTrace(binary, watch, dbg_out)
        print(f"[wavescope] debug trace: watching "
              + ", ".join(f"{f.name} [0x{f.start:x}-0x{f.end:x})"
                          for f in watch)
              + f" -> {args.debug_log or 'stderr'}", file=sys.stderr)

    legacy_prof = None
    import time as _t
    _t_engine0 = _t.perf_counter()
    if args.engine == "legacy":
        prof = run(samples, binary, classifier,
                   clamp_exception_cycles=not args.no_isr_clamp,
                   debug=debug, aux_mode=aux_mode, level_mask=level_mask,
                   trace_roots=args.debug_roots)
    else:
        from .simcore import compare_profiles, run_sim
        print("[wavescope] engine: default (transcription of "
              "docs/simulator_reference.md)", file=sys.stderr)
        prof = run_sim(samples, binary, classifier,
                       trace_roots=args.debug_roots)
        if getattr(prof, "sim_dropped_unknown", 0):
            print(f"[wavescope] sim: {prof.sim_dropped_unknown} event "
                  f"charges dropped at pcs outside infos_ (reference "
                  f"semantics: unknown pc -> no accounting)",
                  file=sys.stderr)
        if args.engine == "both":
            print("[wavescope] engine: legacy (comparison pass)",
                  file=sys.stderr)
            prof2 = run(make_stream(), binary, classifier,
                        clamp_exception_cycles=not args.no_isr_clamp,
                        debug=debug, aux_mode=aux_mode,
                        level_mask=level_mask,
                        trace_roots=args.debug_roots)
            legacy_prof = prof2
            cmp = compare_profiles(prof, prof2, binary)
            print("[wavescope] sim vs legacy (sim - legacy):",
                  file=sys.stderr)
            if cmp["total"]:
                for name, (a, b) in cmp["total"].items():
                    print(f"[wavescope]   total {name}: sim={a} "
                          f"legacy={b} (d={a - b:+d})", file=sys.stderr)
            else:
                print("[wavescope]   totals identical", file=sys.stderr)
            for name, dir_, dcy in cmp["self"]:
                print(f"[wavescope]   self {name}: Ir d={dir_:+d} "
                      f"Cy d={dcy:+d}", file=sys.stderr)
            for name, dn, dcy in cmp["arcs"]:
                print(f"[wavescope]   arc {name}: n d={dn:+d} "
                      f"inclCy d={dcy:+d}", file=sys.stderr)
            if not cmp["self"] and not cmp["arcs"] and not cmp["total"]:
                print("[wavescope]   engines fully agree on this trace",
                      file=sys.stderr)
    if dbg_out is not None and dbg_out is not sys.stderr:
        print(f"[wavescope] debug trace: {debug.events} events -> "
              f"{args.debug_log}", file=sys.stderr)
        dbg_out.close()

    _t_engine = _t.perf_counter() - _t_engine0
    if args.timing and reader_timer is not None:
        rt, n = reader_timer.t, reader_timer.n
        et = _t_engine - rt
        print(f"[wavescope] timing: {n} samples | open/convert "
              f"{_open_dt:.1f}s | waveform reading "
              f"{rt:.1f}s ({n / max(rt, 1e-9):.0f}/s) | profiling engine "
              f"{et:.1f}s | total {_open_dt + _t_engine:.1f}s"
              + (" (NOTE: --engine both runs a second full pass)"
                 if args.engine == "both" else ""), file=sys.stderr)

    def _print_roots(tag, plog):
        if not plog or not plog["n"]:
            if args.debug_roots:
                print(f"[wavescope] root-frame events ({tag}): none",
                      file=sys.stderr)
            return
        print(f"[wavescope] root-frame events ({tag}, depth<="
              f"{plog.get('depth', 3)}"
              + (f", {plog['omitted']} deeper/later events omitted"
                 if plog.get("omitted") else "") + "): "
              + ", ".join(f"{k}={v}" for k, v in sorted(plog["n"].items())),
              file=sys.stderr)
        def loc(a):
            if a is None:
                return "?"
            f = binary.func_at(a)
            return f"{f.name}(0x{a:x})" if f else hex(a)
        for tick, kind, cp, callee, info, depth, cy in plog["ev"]:
            cys = f" frameCy={cy}" if cy is not None else ""
            print(f"[wavescope]   t={tick} {kind:<12s} depth={depth} "
                  f"{loc(cp)} -> {loc(callee)} [{info}]{cys}",
                  file=sys.stderr)

    if args.debug_roots:
        _print_roots(args.engine if args.engine != "both" else "default",
                     getattr(prof, "root_log", None))
        if legacy_prof is not None:
            _print_roots("legacy", getattr(legacy_prof, "root_log", None))
        if getattr(prof, "max_exit_drain", 0) >= 3:
            print(f"[wavescope] sim: an ISR exit drained "
                  f"{prof.max_exit_drain} open frames at once -- likely "
                  f"a STALE ISR level firing at a recurring pc (missed "
                  f"exit earlier: mepc rewritten by software before "
                  f"mret?)", file=sys.stderr)

    if isr_sig and not prof.epc_mode:
        print(f"[wavescope] WARNING: {'--epc' if args.epc else '--isr-level'}"
              f" {isr_sig} never carried a defined value; fell back to "
              f"heuristic ISR detection. Check the signal with "
              f"'wavescope signals --grep <name>'.", file=sys.stderr)
    if prof.isr_kind == "level":
        print(f"[wavescope] level mode (IPSR): {prof.exceptions} exception "
              f"entries (incl. preemption/tail-chaining)"
              + (f", {prof.isr_open} still active at end of trace"
                 if prof.isr_open else ""), file=sys.stderr)
    elif prof.epc_mode:
        print(f"[wavescope] epc mode: {prof.exceptions} ISR entries "
              f"(mepc change / wfi wake), {prof.spurious_epc} spurious "
              f"same-function epc changes suppressed"
              + (f", {prof.isr_open} ISR contexts never returned to their "
                 f"epc (context switch inside a handler?)"
                 if prof.isr_open else ""), file=sys.stderr)
    if prof.epc_mode:
        if prof.flow_anomalies:
            print(f"[wavescope] WARNING: {prof.flow_anomalies} control-flow "
                  f"discontinuities NOT explained by an ISR -- if the PC "
                  f"signal is pre-commit (issue stage), these are likely "
                  f"speculative/flushed instructions polluting the profile",
                  file=sys.stderr)
    elif prof.exceptions:
        print(f"[wavescope] detected {prof.exceptions} exception/interrupt "
              f"entries via heuristic (pass --epc <mepc signal> for exact "
              f"detection incl. interrupts after indirect jumps; boundary "
              f"cycles "
              f"{'clamped to 1' if not args.no_isr_clamp else 'kept raw'})",
              file=sys.stderr)
    if prof.healed_returns or prof.unmatched_returns:
        print(f"[wavescope] returns: {prof.healed_returns} healed, "
              f"{prof.unmatched_returns} unmatched", file=sys.stderr)
    if getattr(prof, "guarded_unwinds", 0):
        det = ""
        if getattr(prof, "return_guards", None) is not None:
            det = (f" (sim A5: {prof.return_guards} skipped pops, "
                   f"{prof.chain_guards} stopped tail-chains)")
        print(f"[wavescope] {prof.guarded_unwinds} unwinds stopped by the "
              f"landing guard -- pops that would have closed a frame the "
              f"landing pc was still inside{det}; each is an 'unwind-guard'/"
              f"'return-guard'/'chain-guard' event under --debug-roots",
              file=sys.stderr)
    if getattr(prof, "discontinuity_returns", 0):
        print(f"[wavescope] {prof.discontinuity_returns} discontinuity "
              f"returns -- flow broke with no branch committed and landed "
              f"exactly on an open frame's return address (macro-fused "
              f"auipc+jr / veneer through untracked code / dropped jump "
              f"commit); frames were closed there instead of leaking "
              f"('disc-ret' events under --debug-roots)", file=sys.stderr)
    if getattr(prof, "exit_rejects", 0):
        print(f"[wavescope] {prof.exit_rejects} ISR-exit arrivals rejected "
              f"-- pc hit the saved resume address through the handler's "
              f"OWN flow (shared __riscv_save/restore millicode or shared "
              f"subroutines between handler and interrupted code); the "
              f"real exit is taken at the xret instead ('exit-reject' "
              f"events under --debug-roots)", file=sys.stderr)
    if getattr(prof, "epc_rewrites", 0):
        print(f"[wavescope] {prof.epc_rewrites} software mepc writes "
              f"consumed -- mepc changed while the flow was sequential "
              f"(nested-interrupt epilogue restoring the outer mepc, or "
              f"a task switch); no phantom ISR entry was declared and "
              f"the pending exit was retargeted to the new value "
              f"('epc-rewrite' events under --debug-roots)",
              file=sys.stderr)

    if args.debug_roots:
        # judgment aid: an inclusive that is too small on the root chain
        # means a root-depth frame was closed BEFORE the end-of-trace
        # drain; list every such pop with its reason
        for label, p_ in ((args.engine if args.engine != "both" else "default",
                           prof),
                          ("legacy", legacy_prof)):
            log = getattr(p_, "root_log", None) if p_ is not None else None
            if not log:
                continue
            cuts = [ev for ev in log["ev"]
                    if ev[1] == "pop" and ev[5] is not None and ev[5] <= 2
                    and "drain" not in str(ev[4])]
            if cuts:
                print(f"[wavescope] {label}: root-chain frames closed "
                      f"MID-RUN {len(cuts)} time(s) -- these cuts are why "
                      f"root inclusives come out small; the [reason] names "
                      f"the mechanism:", file=sys.stderr)
                for ev in cuts[:10]:
                    print(f"[wavescope]   t={ev[0]} depth={ev[5]} "
                          f"[{ev[4]}]", file=sys.stderr)

    if args.check_inclusive:
        from .profiler import inclusive_consistency
        rows, roots = inclusive_consistency(prof, binary)
        print("[wavescope] inclusive consistency "
              "(incoming arcs vs self+outgoing; nonzero delta = the "
              "function's frame was cut early or entered untracked):",
              file=sys.stderr)
        for r in rows:
            flag = " [recursive: expected]" if r["recursive"] else ""
            print(f"[wavescope]   {r['name']}: in Cy={r['in_cy']} vs "
                  f"self+out={r['expect_cy']} (d={r['d_cy']:+d}); "
                  f"Ir d={r['d_ir']:+d}; calls_in={r['calls_in']}{flag}",
                  file=sys.stderr)
        if not rows:
            print("[wavescope]   all tracked functions consistent",
                  file=sys.stderr)
        print("[wavescope]   roots (no incoming arcs): "
              + ", ".join(f"{n} (Ir={i}, Cy={c})" for n, i, c in roots),
              file=sys.stderr)
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
    if legacy_prof is not None:
        with open(args.output + ".legacy", "w") as f2:
            write_callgrind(legacy_prof, f2, args.elf,
                            cmd=" ".join(sys.argv[1:]),
                            all_functions=not args.executed_only)
        print(f"[wavescope] wrote {args.output}.legacy (legacy engine, "
              f"for diffing)", file=sys.stderr)

    totals = ", ".join(f"{n}={v}" for n, v in zip(EVENTS, prof.total))
    print(f"[wavescope] totals: {totals}", file=sys.stderr)
    print(f"[wavescope] wrote {args.output} "
          f"(open with kcachegrind/qcachegrind)", file=sys.stderr)
    return 0


def cmd_checkelf(args) -> int:
    from .disasm import check_disasm
    r = check_disasm(args.elf, args.toolchain_prefix,
                     demangle=not args.no_demangle)
    print(f"[checkelf] objdump raw insn lines: {r['n_raw']}, parsed: "
          f"{r['n_parsed']}, funcs: {r['n_funcs']}, in-text data syms "
          f"excluded: {r['n_data_syms']}")
    ok = True
    if r["n_parse_missing"]:
        ok = False
        print(f"[checkelf] {r['n_parse_missing']} lines FAILED TO PARSE "
              f"(dialect issue) -- raw lines:")
        for a, line in r["parse_missing"]:
            print(f"  {line}")
    if r["n_range_dropped"]:
        ok = False
        print(f"[checkelf] {r['n_range_dropped']} parsed insns fall in NO "
              f"function range (would be missing from the full-coverage "
              f"output):")
        for a, mnem, ctx in r["range_dropped"]:
            print(f"  {a:#x} {mnem}  ({ctx})")
    if r["n_gaps"]:
        ok = False
        print(f"[checkelf] {r['n_gaps']} size-tiling gaps (addr+size != "
              f"next addr; wrong instruction sizes):")
        for name, a, sz, nxt in r["gaps"]:
            print(f"  {name}: {a:#x}+{sz} != {nxt:#x}")
    if r["n_aliases"]:
        print(f"[checkelf] {r['n_aliases']} alias groups (multiple "
              f"symbols at one address; WaveScope's canonical name is "
              f"shown -- if the simulator's symbolizer picks another "
              f"alias, its calls appear 'missing' under that name):")
        for a, names, canon in r["aliases"]:
            print(f"  {a:#x}: {', '.join(names)} -> WaveScope uses "
                  f"{canon!r}")
    if r["n_end_mismatch"]:
        print(f"[checkelf] {r['n_end_mismatch']} functions whose recorded "
              f"end differs from last-insn end (symtab size vs "
              f"disassembly):")
        for name, s, e, last, sz in r["end_mismatch"]:
            print(f"  {name} [{s:#x},{e:#x}) last {last:#x}+{sz} -> "
                  f"{last + sz:#x}")
    if ok and not r["n_end_mismatch"]:
        print("[checkelf] clean: every objdump line parsed, every insn "
              "covered by exactly its function, sizes tile perfectly")
    return 0 if ok else 1


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
    ps.add_argument("--check-epc", nargs="?", const=True, default=None,
                    metavar="EXTRA_SIGNALS",
                    help="validate epc candidates BEHAVIORALLY against the "
                         "PC stream (value changes land in .text, coincide "
                         "with PC discontinuities, and later commit as the "
                         "resume PC). Optionally pass comma-separated extra "
                         "signal names to test, e.g. CSR-array elements "
                         "that name ranking cannot find")
    ps.add_argument("--pc", default=None,
                    help="PC signal for --check-epc (default: the top "
                         "scan candidate)")
    ps.add_argument("--check-limit", type=int, default=500000,
                    help="commits to examine in --check-epc (default 500k)")
    ps.set_defaults(func=cmd_scan)

    pe = sub.add_parser("checkelf",
                        help="diagnose disassembly parsing / function "
                             "ranges on this machine's objdump (finds "
                             "missing assembly lines and reports the "
                             "offending raw lines)")
    pe.add_argument("--elf", required=True)
    pe.add_argument("--toolchain-prefix", default="")
    pe.add_argument("--no-demangle", action="store_true")
    pe.set_defaults(func=cmd_checkelf)

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
    pp.add_argument("--epc", default=None,
                    help="optional exception PC CSR signal (mepc). Enables "
                         "exact ISR entry/exit detection: entry on mepc "
                         "value change, exit on committing the saved epc "
                         "address -- covers interrupts after indirect jumps "
                         "and defers interrupted-branch judgement to the "
                         "true landing, matching the reference simulator")
    pp.add_argument("--edge", choices=["rising", "falling"], default="rising")
    pp.add_argument("--isa", default="riscv",
                    help="riscv | armv7m (Cortex-M/Thumb-2) | aarch64")
    pp.add_argument("--isa-ext", action="append", default=[],
                    help="custom-instruction overlay JSON (repeatable)")
    pp.add_argument("--toolchain-prefix", default="",
                    help="binutils prefix, e.g. riscv64-unknown-elf-, "
                         "arm-none-eabi-, aarch64-linux-gnu-")
    pp.add_argument("--executed-only", action="store_true",
                    help="emit only executed PCs/functions (default emits "
                         "every instruction of every ELF function, "
                         "unexecuted ones at zero cost, for coverage: "
                         "zero-cost code = present but never executed, "
                         "absent code = compiled out; also used for "
                         "coverage views and simulator parity)")
    pp.add_argument("--no-demangle", action="store_true",
                    help="keep mangled C++/Rust symbol names "
                         "(default: demangle via objdump -C)")
    pp.add_argument("--no-stream-cache", action="store_true",
                    help="disable the extracted-sample cache (by default "
                         "the first pass writes (tick,pc,epc) samples to "
                         "a compact binary in the temp dir; reruns and "
                         "--engine both's second pass replay it in "
                         "seconds instead of re-parsing the waveform)")
    pp.add_argument("--timing", action="store_true",
                    help="report where time goes: waveform reading vs "
                         "profiling engine (adds ~100ns/sample overhead) "
                         "with a progress heartbeat every 2M samples")
    pp.add_argument("--debug-roots", nargs="?", const=3, default=0,
                    type=int, metavar="DEPTH",
                    help="log push/pop events of the bottom call-stack "
                         "frames (default depth<=3; pass a number for a "
                         "wider window, e.g. --debug-roots 6) with "
                         "ticks, reasons, ISR enter/exit events and "
                         "tail-chain pops -- diagnoses roots whose "
                         "inclusive comes out too small")
    pp.add_argument("--engine", choices=("default", "legacy", "both",
                                         "sim"),
                    default="default",
                    help="profiling engine: 'default' (transcription of "
                         "the simulator reference plus documented "
                         "adapters; formerly called 'sim', which is "
                         "kept as an alias), 'legacy' (the FROZEN "
                         "original engine -- kept for comparison, no "
                         "longer maintained), or 'both' (default "
                         "output + legacy output as <out>.legacy + "
                         "divergence summary)")
    pp.add_argument("--check-inclusive", action="store_true",
                    help="report functions whose incoming-arc inclusive "
                         "differs from self + outgoing-arc inclusive "
                         "(diagnoses inclusive drift; recursive functions "
                         "flagged, roots listed separately)")
    pp.add_argument("--clock-counter", action="store_true", default=None,
                    help="treat --clock as a multi-bit CYCLE COUNTER "
                         "(C++ IP-simulator dumps: the clock recorded as "
                         "a 32/64-bit incrementing integer) -- the "
                         "counter value becomes the cycle index. "
                         "Auto-detected for VCD (width > 1 bit and "
                         "values past 1); this flag forces it, e.g. for "
                         "FSDB input")
    pp.add_argument("--isr-level", metavar="SIGNAL",
                    help="Cortex-M (M4/M35P) exception tracking: the IPSR "
                         "signal (active exception number; 0 = thread "
                         "mode). Entry = change to a new nonzero level "
                         "(preemption/tail-chain nest), exit = return to "
                         "an outer level or 0. If only the full xPSR is "
                         "dumped, IPSR is isolated automatically (mask "
                         "0x1ff). Mutually exclusive with --epc")
    pp.add_argument("--isr-level-mask", metavar="HEX", default=None,
                    help="mask applied to the --isr-level value before "
                         "interpreting it as the exception number "
                         "(e.g. 0x1ff for a full xPSR dump)")
    pp.add_argument("--debug-func", action="append", metavar="NAME",
                    help="trace cycle accumulation and frame push/pop "
                         "(inclusive cost) events for this function -- "
                         "repeatable or comma-separated; accepts a name, "
                         "unique name suffix, or 0xADDR. See --debug-log")
    pp.add_argument("--debug-log", metavar="FILE",
                    help="write --debug-func event log to FILE instead of "
                         "stderr")
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
