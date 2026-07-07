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

## Requirements

- Linux, Python ≥ 3.8 (no Python dependencies)
- binutils for your target, e.g. `riscv64-unknown-elf-objdump` and
  `addr2line` (source-line mapping is optional)

## Install

```sh
git clone https://github.com/tdjung/WaveScope.git
cd WaveScope
pip install -e .
```

## Usage

```sh
wavescope \
    --vcd sim.vcd \
    --elf firmware.elf \
    --clock top.clk \
    --pc top.core.commit_pc \
    --valid top.core.commit_valid \
    --toolchain-prefix riscv64-unknown-elf- \
    -o callgrind.out.wavescope

qcachegrind callgrind.out.wavescope   # or callgrind_annotate
```

Signal names accept a full hierarchical path or any unique suffix
(`commit_pc` works if only one signal ends with that name).

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
- [x] RISC-V (RV32/RV64, incl. compressed) classification
- [x] Callgrind output with call tree + inclusive costs
- [ ] FSDB input (via `fsdb2vcd` for now)
- [ ] Other ISAs (classifier is pluggable — see `wavescope/classify.py`)
- [ ] Interrupt/exception (`epc`) boundary handling
- [ ] Multi-hart: one PC signal per hart, merged output

## Development

```sh
python3 -m unittest discover tests -v
```

## License

MIT
