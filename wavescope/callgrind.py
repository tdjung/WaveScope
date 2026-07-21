"""Callgrind format writer.

Produces files loadable by kcachegrind / qcachegrind / callgrind_annotate.
Format reference: https://valgrind.org/docs/manual/cl-format.html
"""

from collections import defaultdict
from typing import Dict, List, TextIO, Tuple

from .disasm import BinaryInfo
from .profiler import EVENTS, N_EVENTS, Profile


def write(prof: Profile, out: TextIO, binary_path: str, cmd: str = "",
          all_functions: bool = True) -> None:
    b: BinaryInfo = prof.binary

    out.write("# callgrind format\n")
    out.write("version: 1\n")
    out.write("creator: WaveScope\n")
    out.write("positions: instr line\n")
    out.write(f"events: {' '.join(EVENTS)}\n")
    if cmd:
        out.write(f"cmd: {cmd}\n")
    out.write(f"summary: {' '.join(str(v) for v in prof.total)}\n\n")

    # group self costs by function
    by_func: Dict[int, List[int]] = defaultdict(list)   # func_start -> [pc...]
    orphans: List[int] = []
    for pc in prof.self_cost:
        f = b.func_at(pc)
        if f:
            by_func[f.start].append(pc)
        else:
            orphans.append(pc)

    # jump associations (jcnd= conditional / jump= unconditional) keyed
    # by source pc; emitted directly before the source's cost line per
    # the callgrind spec ("an association applies to the following cost
    # line").  jcnd counts are followed/executed, executed = Bc.
    jumps_by_src: Dict[int, List[Tuple[str, int, int]]] = defaultdict(list)
    for (s, d), n in prof.cond_jumps.items():
        jumps_by_src[s].append(("jcnd", d, n))
    for (s, d), n in prof.uncond_jumps.items():
        jumps_by_src[s].append(("jump", d, n))

    # calls grouped by the function physically containing the call insn
    calls_by_func: Dict[int, List[Tuple[int, int]]] = defaultdict(list)
    for (call_pc, callee) in prof.calls:
        f = b.func_at(call_pc)
        calls_by_func[f.start if f else -1].append((call_pc, callee))

    def fname(start: int) -> str:
        if start < 0:
            return "<unknown>"
        f = b.func_at(start)
        return f.name if f else f"0x{start:x}"

    out.write(f"ob={binary_path}\n\n")

    emit_starts = set(list(by_func) + list(calls_by_func))
    if all_functions:
        emit_starts.update(f.start for f in b.funcs)

    last_fl = None
    for fstart in sorted(emit_starts):
        pcs = sorted(by_func.get(fstart, []))
        first_pc = pcs[0] if pcs else fstart
        fl, _ = b.line_at(first_pc)
        if fl != last_fl:
            out.write(f"fl={fl}\n")     # simulator format: fl only on change
            last_fl = fl
        out.write(f"fn={fname(fstart)}\n")

        # a call SITE can have several callees (indirect jalr targets,
        # per-target arcs); collapsing to one per pc dropped calls= lines
        call_pcs: Dict[int, List[int]] = defaultdict(list)
        for cp, callee in calls_by_func.get(fstart, []):
            call_pcs[cp].append(callee)

        # Coverage emission: every instruction of the function appears,
        # executed ones with real costs and the rest at zero, so
        # never-executed code inside the ELF is distinguishable from
        # code compiled out of the ELF entirely.  --executed-only
        # falls back to cost-bearing pcs alone.
        f = b.func_at(fstart)
        if all_functions and f is not None:
            emit_pcs = sorted(a for a in b.insns
                              if f.start <= a < f.end) or pcs
        else:
            emit_pcs = pcs

        if not emit_pcs and not call_pcs:
            # not represented in the disassembly (e.g. PLT-less import):
            # keep the function visible at zero cost
            _, line = b.line_at(fstart)
            out.write(f"0x{fstart:x} {line} "
                      f"{' '.join('0' for _ in range(N_EVENTS))}\n\n")
            continue

        zeros = [0] * N_EVENTS
        for pc in emit_pcs:
            _, line = b.line_at(pc)
            costs = prof.self_cost.get(pc, zeros)
            out.write(f"0x{pc:x} {line} "
                      f"{' '.join(str(v) for v in costs)}\n")
            # jump associations AFTER the source's cost line, each
            # followed by a position-only line (the cost line the
            # association attaches to, at the same source position):
            #   0xSRC LINE <costs>
            #   jcnd=30/100 0xT1 L1
            #   0xSRC LINE
            #   jcnd=70/100 0xT2 L2
            #   0xSRC LINE
            specs = jumps_by_src.get(pc)
            if specs:
                total = sum(n for kind, _, n in specs if kind == "jcnd")
                # simulator order (user-corrected): DESCENDING count
                # (jcnd=18/27 before jcnd=9/27), ties by ascending
                # target address (jcnd=1/2 0x00c before jcnd=1/2 0x010)
                for kind, dst, n in sorted(specs,
                                           key=lambda x: (-x[2], x[1])):
                    _, dline = b.line_at(dst)
                    if kind == "jcnd":
                        out.write(f"jcnd={n}/{total or n} 0x{dst:x} {dline}\n")
                    else:
                        out.write(f"jump={n} 0x{dst:x} {dline}\n")
                    out.write(f"0x{pc:x} {line}\n")
            if pc in call_pcs:
                for callee in sorted(call_pcs.pop(pc)):
                    _write_call(prof, out, b, pc, callee)

        # call sites with no recorded self-cost line (shouldn't normally happen)
        for pc, callees in sorted(call_pcs.items()):
            for callee in sorted(callees):
                _, line = b.line_at(pc)
                zeros = " ".join("0" for _ in range(N_EVENTS))
                out.write(f"0x{pc:x} {line} {zeros}\n")
                _write_call(prof, out, b, pc, callee)
        out.write("\n")

    if orphans:
        out.write("fl=??\nfn=<unknown>\n")
        for pc in sorted(orphans):
            costs = prof.self_cost[pc]
            out.write(f"0x{pc:x} 0 {' '.join(str(v) for v in costs)}\n")
        out.write("\n")


def _write_call(prof: Profile, out: TextIO, b: BinaryInfo,
                call_pc: int, callee: int) -> None:
    cs = prof.calls.get((call_pc, callee))
    if cs is None or cs.count == 0:
        return
    cf = b.func_at(callee)
    callee_pc = callee
    cfl, cline = b.line_at(callee_pc)
    out.write(f"cfl={cfl}\n")  # cfl= == cfi= (spec synonyms); cfl matches the sim output for diffing
    out.write(f"cfn={cf.name if cf else f'0x{callee:x}'}\n")
    out.write(f"calls={cs.count} 0x{callee:x} {cline}\n")
    _, line = b.line_at(call_pc)
    out.write(f"0x{call_pc:x} {line} "
              f"{' '.join(str(v) for v in cs.inclusive)}\n")
