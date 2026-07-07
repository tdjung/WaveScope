"""Core profiler: reconstructs update_profile() semantics from a PC stream.

Simulator pseudo code being mirrored (per committed instruction):

    update_epc(epc, pc)
    update(pc, TRACE_IR, 1)
    update(pc, TRACE_CY, cur_cycle - last_committed_cycle)
    if branch:        update(pc, TRACE_BC, 1)
    if taken:         update(pc, TRACE_BCM, 1)
    if jump:          update(pc, TRACE_BI, 1); update(pc, TRACE_BIM, 1)
    if function_call: update(pc, TRACE_CALL)
    if tail_call:     update(pc, TRACE_TAIL_CALL)
    if INDIRECT_JUMP: update(pc, TRACE_INDIRECT_JUMP)
    if DIRECT_JUMP:   update(pc, TRACE_DIRECT_JUMP)
    if LOAD:          update(pc, TRACE_DR, 1)
    if STORE:         update(pc, TRACE_DW, 1)

From a waveform we only have (tick, pc).  Everything else is derived:

    branch / jump / load / store / direct / indirect
        -> from disassembly of the ELF at `pc`
    taken
        -> next_pc != pc + insn_size
    cycles
        -> tick(next commit) - tick(this commit)
    function_call
        -> link-writing jump whose next_pc lands on a function entry
    tail_call
        -> non-link jump whose next_pc is a *different* function's entry
    return
        -> `ret`-class instruction, or next_pc matching a saved link addr

Call/return matching drives a shadow call stack so that callgrind
inclusive costs (calls= / cfn=) can be produced.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .classify import InsnClass
from .disasm import BinaryInfo, Insn

# Event names (callgrind "events:" order)
EVENTS = ["Ir", "Cy", "Bc", "Bcm", "Bi", "Bim",
          "Call", "TailCall", "IndJmp", "DirJmp", "Dr", "Dw"]
E_IR, E_CY, E_BC, E_BCM, E_BI, E_BIM, \
    E_CALL, E_TAIL, E_INDJ, E_DIRJ, E_DR, E_DW = range(len(EVENTS))
N_EVENTS = len(EVENTS)


@dataclass
class CallSite:
    """Aggregated call info for callgrind `calls=` lines."""
    count: int = 0
    inclusive: List[int] = field(default_factory=lambda: [0] * N_EVENTS)


@dataclass
class FrameCtx:
    func_start: int
    ret_addr: Optional[int]
    call_pc: Optional[int]          # pc of the call instruction
    callee_start: Optional[int]     # for parent's calls= bookkeeping
    acc: List[int] = field(default_factory=lambda: [0] * N_EVENTS)


class Profile:
    def __init__(self, binary: BinaryInfo):
        self.binary = binary
        # self-costs: pc -> event vector
        self.self_cost: Dict[int, List[int]] = defaultdict(lambda: [0] * N_EVENTS)
        # calls: (caller_func_start, call_pc, callee_func_start) -> CallSite
        self.calls: Dict[Tuple[int, int, int], CallSite] = defaultdict(CallSite)
        self.total: List[int] = [0] * N_EVENTS
        self.unknown_pcs = 0

    # -- accounting ----------------------------------------------------
    def _update(self, pc: int, ev: int, n: int, stack: List[FrameCtx]) -> None:
        self.self_cost[pc][ev] += n
        self.total[ev] += n
        for fr in stack:
            fr.acc[ev] += n


def run(pc_stream: Iterable[Tuple[int, int]], binary: BinaryInfo,
        classifier, max_stack: int = 512) -> Profile:
    """Consume (tick, pc) samples and build a Profile.

    The stream is treated as the committed-instruction sequence; each new
    sample is one retired instruction, and tick deltas are its cycles.
    Consecutive identical PCs at adjacent ticks are treated as stalls
    (cycles accumulate, no new instruction) unless the instruction is a
    self-branch, which cannot be distinguished without a valid signal --
    prefer supplying a commit-valid signal for such cores.
    """
    prof = Profile(binary)
    stack: List[FrameCtx] = []

    it: Iterator[Tuple[int, int]] = iter(pc_stream)
    try:
        prev_tick, prev_pc = next(it)
    except StopIteration:
        return prof

    def commit(pc: int, cycles: int, next_pc: Optional[int]) -> None:
        insn = binary.insns.get(pc)
        if insn is None:
            prof.unknown_pcs += 1
            return
        cls: InsnClass = classifier.classify(insn)

        prof._update(pc, E_IR, 1, stack)
        if cycles > 0:
            prof._update(pc, E_CY, cycles, stack)

        fallthrough = pc + insn.size
        taken = next_pc is not None and next_pc != fallthrough

        if cls.is_cond_branch:
            prof._update(pc, E_BC, 1, stack)
            if taken:
                prof._update(pc, E_BCM, 1, stack)

        if cls.is_jump:
            prof._update(pc, E_BI, 1, stack)
            prof._update(pc, E_BIM, 1, stack)
            if cls.is_indirect:
                prof._update(pc, E_INDJ, 1, stack)
            else:
                prof._update(pc, E_DIRJ, 1, stack)

        if cls.is_load:
            prof._update(pc, E_DR, 1, stack)
        if cls.is_store:
            prof._update(pc, E_DW, 1, stack)

        if next_pc is None:
            return

        cur_func = binary.func_at(pc)
        callee_entry = binary.is_func_entry(next_pc)
        diff_func = cur_func is None or not (cur_func.start <= next_pc < cur_func.end)

        # --- returns: pop frames whose saved link matches next_pc ------
        if cls.is_return or (cls.is_jump and cls.is_indirect and not cls.writes_link):
            for i in range(len(stack) - 1, -1, -1):
                if stack[i].ret_addr == next_pc:
                    _unwind_to(prof, stack, i)
                    return
            if cls.is_return:
                return  # unmatched ret (stack started mid-function)

        # --- calls ------------------------------------------------------
        if cls.is_jump and cls.writes_link and callee_entry:
            prof._update(pc, E_CALL, 1, stack)
            if len(stack) < max_stack:
                stack.append(FrameCtx(
                    func_start=next_pc,
                    ret_addr=fallthrough,
                    call_pc=pc,
                    callee_start=next_pc))
            return

        # --- tail calls --------------------------------------------------
        if cls.is_jump and not cls.writes_link and callee_entry and diff_func:
            prof._update(pc, E_TAIL, 1, stack)
            if stack:
                # reuse caller's frame: same return address, new callee
                top = stack[-1]
                _flush_call(prof, stack, len(stack) - 1)
                top.func_start = next_pc
                top.callee_start = next_pc
                top.call_pc = pc
                top.acc = [0] * N_EVENTS
            return

    while True:
        try:
            tick, pc = next(it)
        except StopIteration:
            commit(prev_pc, 1, None)
            break
        if pc == prev_pc:
            # stall: same instruction held across ticks -> defer commit
            # (cycle delta keeps growing via tick difference)
            continue
        commit(prev_pc, tick - prev_tick, pc)
        prev_tick, prev_pc = tick, pc

    # drain remaining frames (program ended inside calls)
    _unwind_to(prof, stack, 0)
    return prof


def _caller_start(prof: Profile, stack: List[FrameCtx], idx: int) -> int:
    if idx > 0:
        return stack[idx - 1].func_start
    fr = stack[idx]
    if fr.call_pc is not None:
        f = prof.binary.func_at(fr.call_pc)
        if f:
            return f.start
    return fr.func_start


def _flush_call(prof: Profile, stack: List[FrameCtx], idx: int) -> None:
    fr = stack[idx]
    if fr.call_pc is None or fr.callee_start is None:
        return
    key = (_caller_start(prof, stack, idx), fr.call_pc, fr.callee_start)
    cs = prof.calls[key]
    cs.count += 1
    for e in range(N_EVENTS):
        cs.inclusive[e] += fr.acc[e]


def _unwind_to(prof: Profile, stack: List[FrameCtx], depth: int) -> None:
    while len(stack) > depth:
        _flush_call(prof, stack, len(stack) - 1)
        popped = stack.pop()
        if stack:
            # inclusive costs already propagated during _update; nothing to add
            pass
        del popped
