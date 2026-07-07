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
| `DirJmp` / `IndJmp` | opcode: `jal`/`j` vs `jalr`/`jr`/`ret` |
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
| VCD | native (dependency-free parser) |
| FSDB | via Synopsys Verdi tools -- see below |

FSDB is a proprietary format with no open-source reader. WaveScope
auto-detects Verdi utilities (`--verdi-home`, `$VERDI_HOME`, or `$PATH`):

1. **`fsdbreport`** (preferred): dumps only the clk/pc/valid signals as
   text -- no VCD conversion, fast even for huge dumps.
2. **`fsdb2vcd`** fallback: converts to VCD first. Use `--fsdb-scope
   top.soc.cpu0` to convert only the core's scope -- dramatically faster.

Verdi tool flags vary slightly between releases; if the default
invocation fails, override with `--fsdbreport-args` / `--fsdb2vcd-args`
(":"-separated).

## Requirements

- Linux, Python ≥ 3.8 (no Python dependencies)
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
- [x] `scan`: PC/clock signal candidate discovery
- [x] Callgrind output with call tree + inclusive costs
- [ ] FST input (Verilator/GTKWave open format)
- [ ] Native FSDB reader binding (libnffr via ctypes)
- [ ] lcov coverage export (`--lcov`) for multi-run merged coverage
- [ ] Interrupt/exception (`epc`) boundary handling
- [ ] Multi-hart/core: one PC signal per hart, merged output

## Development

```sh
python3 -m unittest discover tests -v
```

## License

MIT
