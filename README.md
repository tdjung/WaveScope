# WaveScope

Turn an RTL **waveform PC trace** into a **callgrind profile** using only the
ELF debug symbols — no simulator-side instrumentation required.

```
VCD waveform ──┐
               ├──► WaveScope ──► callgrind.out ──► kcachegrind / qcachegrind
ELF (symbols) ─┘
```

## How it works

A simulator can call `update_profile()` with rich per-instruction info
(branch, taken, call, load/store, cycles). From a waveform we only get a
PC value per clock tick — but everything else is recoverable:

| Event | Reconstruction |
|---|---|
| `Ir` (instructions) | +1 per committed PC sample |
| `Cy` (cycles) | clock-tick delta between consecutive commits |
| `Bc` / `Bcm` (cond. branch / taken) | disassembly says it's a branch; taken if `next_pc != pc + insn_size` |
| `Bi` / `Bim` (jumps) | disassembly (`jal`, `jalr`, `j`, ...) |
| `Call` | link-writing jump (`jal ra`, `jalr ra`) landing on a function entry |
| `TailCall` | non-link jump landing on a *different* function's entry |
| `Dr` / `Dw` (loads / stores) | disassembly (`lw`, `sw`, ...) |

Call/return matching drives a shadow call stack, so the output includes
proper `calls=` / `cfn=` records with **inclusive costs** — the call tree
in kcachegrind works as expected.

## Supported ISAs

| ISA | `--isa` | Toolchain prefix example |
|---|---|---|
| RISC-V RV32/RV64 (incl. C ext) | `riscv` (default) | `riscv64-unknown-elf-` |
| ARM Cortex-M (Thumb/Thumb-2) | `armv7m` | `arm-none-eabi-` |
| ARM AArch64 | `aarch64` | `aarch64-linux-gnu-` |

ISA knowledge lives in **data files** (`wavescope/isa/*.json`), not code.
The classifier is a generic engine interpreting those tables, so adding
or tweaking an ISA means editing JSON.

### Custom instructions (RISC-V etc.)

Extend a base ISA with an overlay file, repeatable via `--isa-ext`:

```jsonc
// my_custom.json
{
  // case 1: your vendor objdump prints the mnemonic
  "classes": { "load": ["cust.vld"], "store": ["cust.vst"] },

  // case 2: objdump shows ".word 0x...." -- match by encoding
  "custom_encodings": [
    { "name": "cust_dma_ld", "mask": "0x7f", "match": "0x0b",
      "classes": ["load"], "size": 4 }
  ]
}
```

```sh
wavescope profile ... --isa riscv --isa-ext my_custom.json
```

## Waveform formats

| Format | Support |
|---|---|
| VCD | native (dependency-free parser; gzip/bz2/xz transparent) |
| FSDB | via Synopsys Verdi tools -- see below |
| TRN / SHM (Cadence) | via `simvisdbutil` (ships with Xcelium/SimVision) |

FSDB is a proprietary format with no open-source reader. WaveScope
auto-detects Verdi utilities (`--verdi-home`, `$VERDI_HOME`, or `$PATH`):

1. **`fsdbreport`** (preferred): dumps only the clk/pc/valid signals as
   text -- no VCD conversion, fast even for huge dumps.
2. **`fsdb2vcd`** fallback: converts to VCD first. Use `--fsdb-scope
   top.soc.cpu0` to convert only the core's scope -- dramatically faster.

Verdi tool flags vary slightly between releases; if the default
invocation fails, override with `--fsdbreport-args` / `--fsdb2vcd-args`
(":"-separated).

For Cadence TRN/SHM, pass the `.trn` file or the `.shm` directory as
`--wave`; WaveScope finds `simvisdbutil` via `--cadence-bin`,
`$XCELIUM_HOME` / `$CDS_ROOT`, or `$PATH`, converts to VCD (restrict
with `--fsdb-scope` -- the same flag drives `-scope ... -recursive`),
and proceeds. Override flags with `--simvisdbutil-args` if your
Xcelium release differs.

## Requirements

- Linux, Python ≥ 3.6, **zero dependencies** (stdlib only) -- runs
  directly from a clone without pip: `python3 -m wavescope.cli ...`
- binutils for your target (`objdump`, optional `addr2line`)
- for FSDB input: a Verdi installation

## Install

```sh
git clone https://github.com/tdjung/WaveScope.git
cd WaveScope
pip install -e .
```

## Usage: two-step workflow

**Step 1 -- find the PC/clock signals.** Real SoC waveforms have
thousands of signals; `scan` ranks candidates using the ELF:

```sh
$ wavescope scan --wave sim.vcd --elf firmware.elf

PC signal candidates:
  1. top.soc.cpu0.u_wb.wb_pc  [score 0.94]
       - 99% of values in ELF text sections
       - 78% sequential strides (+2/4)
       - name contains 'pc' (wb_pc)
  ...
Clock signal candidates:
  1. top.clk  [score 1.00]
```

Scoring combines: fraction of values inside the ELF's executable
sections (strongest), sequential-stride pattern, name hints, and signal
width. `--json` gives machine-readable output for UI integration.

**Step 2 -- profile with the chosen signals:**

```sh
wavescope profile \
    --wave sim.vcd \
    --elf firmware.elf \
    --clock top.clk \
    --pc top.soc.cpu0.u_wb.wb_pc \
    --valid top.soc.cpu0.u_wb.wb_valid \
    --isa armv7m --toolchain-prefix arm-none-eabi- \
    -o callgrind.out.wavescope

qcachegrind callgrind.out.wavescope   # or callgrind_annotate
```

Signal names accept a full hierarchical path or any unique suffix
(`wb_pc` works if only one signal ends with that name).

### No clock signal in the dump?

`--clock` is optional. Without it, WaveScope derives the cycle grid from
the PC signal's own change times: every event in an RTL dump sits on a
multiple of the clock period, so the GCD of the time deltas between PC
changes converges to the period within a handful of samples. Stalls
(gaps of N periods) then count as N cycles, exactly as in clocked mode.

This costs nothing extra -- only the PC value-change lines are examined,
so multi-million-cycle dumps stream at the same speed. If auto-detection
is not desired, pass `--clock-period 10ns` (or a plain integer in dump
time units).

### Interrupts: dump mepc and pass `--epc`

If the waveform also contains the exception PC CSR (RISC-V `mepc`,
found by `wavescope scan` under "Exception-PC candidates"), pass it:

```sh
wavescope profile --wave sim.vcd --elf fw.elf \
    --pc  cpu.core.issued.pc \
    --epc cpu.core.csr.mepc \
    -o callgrind.out.wavescope
```

ISR boundaries are then detected exactly instead of heuristically:

- **entry** = an mepc value change at a commit (plus a WFI-wake rule for
  back-to-back interrupts that rewrite mepc with the same value) --
  this also catches interrupts arriving right after *indirect* jumps,
  which no PC-only heuristic can see;
- **exit** = committing the saved epc address, so tail-chained handlers
  and non-`mret` returns unwind correctly, including nested interrupts;
- an interrupted branch/call is *judged after the handler returns*,
  against its true landing address -- its taken/not-taken counts and
  call arc are not polluted by the handler address;
- an mepc change landing in the same function as the current pc is
  treated as spurious and suppressed (CSR save/restore traffic);
- any remaining control-flow discontinuity *not* explained by an ISR is
  reported as a `flow anomaly` -- a useful smoke test for whether the
  chosen PC signal carries speculative (pre-commit) values.

Without `--epc`, the previous heuristic (architecturally unreachable
successor = entry, `mret`/return-to-resume = exit) remains in effect.

Compressed or binary files named `.vcd` are handled transparently:
gzip/bzip2/xz are decompressed on the fly, and FST/LXT2/VZT are
converted via the GTKWave-bundled fst2vcd/lxt2vcd/vzt2vcd if present
in PATH.

## Choosing the right PC signal

Accuracy depends heavily on **which** PC you tap:

1. **Best:** commit/retire-stage PC qualified by a commit-valid signal
   (`--valid`). Every sample is exactly one retired instruction.
2. **OK:** commit-stage PC without valid. Repeated PCs across ticks are
   treated as stalls (cycles accumulate, instruction counted once). A
   tight self-loop (`j .`) is indistinguishable from a stall in this mode.
3. **Risky:** fetch-stage PC. Speculative/flushed instructions pollute
   the profile; branch statistics become fetch-side, not architectural.

Cycle attribution follows the same convention as
`cur_cycle - last_committed_cycle`: stall cycles are charged to the
instruction that eventually commits.

## Current scope / roadmap

- [x] VCD input (dependency-free parser)
- [x] FSDB input via Verdi tools (fsdbreport / fsdb2vcd)
- [x] RISC-V, ARM Cortex-M (Thumb-2), AArch64 -- table-driven, JSON data files
- [x] Custom instruction overlays (mnemonic + encoding matching)
- [x] `scan`: PC/clock/mepc signal candidate discovery, plus
      `--check-epc`: behavioral validation of epc candidates against the
      PC stream (works for CSR-array elements name ranking cannot find)
- [x] Mid-trace clock-frequency change (CMU/DVFS) detection: clockless
      mode keeps a fixed period and cannot follow frequency changes --
      off-grid time deltas are detected and reported with explicit
      guidance to dump the core clock and use `--clock`, whose
      edge-counted cycles are exact under any frequency schedule
- [x] Multi-bit `--clock` (C++ IP-simulator dumps): a 32/64-bit cycle
      COUNTER is auto-detected and its value used directly as the cycle
      index -- exact under counter jumps (sleep fast-forward),
      frequency changes, and wraparound, at 1-bit edge-sampling speed;
      a 0/1 clock stored in a wide variable edge-samples normally.
      `--clock-counter` forces counter semantics (e.g. for FSDB)
- [x] Cortex-M (M4 / M35P) exception tracking via `--isr-level <IPSR>`:
      these cores have no epc; the IPSR level signal drives entry
      (new nonzero level; preemption and tail-chaining nest) and exit
      (drop to an outer level or 0), and hardware resumes exactly at the
      interrupted instruction, so interrupted-branch judgement works the
      same as in `--epc` mode. Full-xPSR dumps are masked to the IPSR
      field automatically
- [x] Callgrind output with call tree + inclusive costs (event order
      `Ir Dr Dw Bc Bi Bim Cy`, `fl=` emitted only on change -- both for
      line-diffing against an existing profiler's output)
- [x] `--engine sim|legacy|both`: a literal transcription of the
      reference simulator's algorithm (simcore) runs alongside the
      native engine; `both` writes both outputs and prints an
      arc-level divergence summary between them
- [x] `--check-inclusive`: per-function invariant report (incoming arc
      inclusive vs self + outgoing) that pinpoints functions whose
      frames were cut early or entered untracked
- [x] Conditional/unconditional jump records (`jcnd=`/`jump=`), both
      branch directions (taken + fall-through) so per-direction counts
      sum to the execution count -- branch coverage
- [x] Full-coverage emission: every instruction in the ELF's code
      region appears (zero cost if never executed), distinguishing
      unexecuted code from code compiled out of the binary
      (`--executed-only` disables)
- [x] `--debug-func NAME [--debug-log FILE]`: per-instruction cycle
      charging and frame push/pop event log (with pop reasons) for one
      or more functions, plus a self/inclusive summary -- for diffing
      against another profiler's numbers
- [ ] FST input (Verilator/GTKWave open format)
- [ ] Native FSDB reader binding (libnffr via ctypes)
- [ ] lcov coverage export (`--lcov`) for multi-run merged coverage
- [x] Interrupt/exception boundary handling: exact via `--epc <mepc signal>`
      (entry on mepc change, exit on committing the saved epc, WFI wake,
      nested ISRs, interrupted-branch judgement deferred to the true
      landing) with a PC-only heuristic fallback
- [ ] Multi-hart/core: one PC signal per hart, merged output

## Development

```sh
python3 -m unittest discover tests -v
```

## License

MIT
