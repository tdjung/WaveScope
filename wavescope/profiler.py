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
from .disasm import BinaryInfo, Insn, direct_target

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


_LOOP_SCAN_DEPTH = 64


def _close_loop_if_reentry(prof: "Profile", stack: List["FrameCtx"],
                           entry: int) -> bool:
    """Loop closure: a transfer back to an entry whose TAIL frame is
    already on the stack (a loop whose body crosses asm-label/function
    boundaries) must not push a new frame every iteration -- that stacks
    one frame per iteration, each accumulating all remaining iterations,
    blowing inclusive sums up quadratically. Instead, flush the tail
    frames opened since that entry (per-iteration arcs keep correct,
    bounded costs) and keep re-using the original frame."""
    lo = max(0, len(stack) - _LOOP_SCAN_DEPTH)
    for i in range(len(stack) - 1, lo - 1, -1):
        fr = stack[i]
        if not fr.is_tail:
            return False          # a real call intervenes: not a loop edge
        if fr.func_start == entry:
            _unwind_to(prof, stack, i + 1)
            return True
    return False


def _push_frame(prof: "Profile", stack: List["FrameCtx"],
                isr_ctxs: List["IsrCtx"], frame: "FrameCtx",
                max_stack: int) -> None:
    if len(stack) >= max_stack:
        _flush_call(prof, stack, 0)
        del stack[0]
        for c in isr_ctxs:
            c.depth = max(0, c.depth - 1)
    stack.append(frame)


@dataclass
class IsrCtx:
    depth: int                    # call-stack depth at exception entry
    resume: Optional[int]         # architectural resume PC (mepc), if known


XRET_MNEMONICS = {"mret", "sret", "uret", "eret"}


@dataclass
class FrameCtx:
    func_start: int
    ret_addr: Optional[int]
    call_pc: Optional[int]          # pc of the call instruction
    callee_start: Optional[int]     # for parent's calls= bookkeeping
    is_tail: bool = False
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
        self.exceptions = 0
        self.healed_returns = 0
        self.unmatched_returns = 0
        self.drained_frames = 0
        self.drained_top: List[Tuple[int, int, int]] = []  # (call_pc, callee, acc_ir)

    # -- accounting ----------------------------------------------------
    def _update(self, pc: int, ev: int, n: int, stack: List[FrameCtx]) -> None:
        self.self_cost[pc][ev] += n
        self.total[ev] += n
        for fr in stack:
            fr.acc[ev] += n


def run(pc_stream: Iterable[Tuple[int, int]], binary: BinaryInfo,
        classifier, max_stack: int = 4096,
        clamp_exception_cycles: bool = True) -> Profile:
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
    isr_ctxs: List[IsrCtx] = []

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

        fallthrough = pc + insn.size

        # Resolved target of a *direct* transfer lets us judge taken /
        # not-taken exactly (next_pc == target), instead of merely
        # next_pc != fallthrough.
        target = None
        if (cls.is_cond_branch or cls.is_jump) and not cls.is_indirect:
            target = direct_target(insn)

        taken = next_pc is not None and next_pc != fallthrough
        if target is not None and next_pc is not None:
            taken = next_pc == target

        # --- exception / interrupt entry ---------------------------------
        # Trap entry between two commits shows up as a successor that no
        # architectural path of this instruction can reach:
        #   plain insn      : next != fallthrough
        #   direct jump     : next != target
        #   direct cond br  : next not in {target, fallthrough}
        # (indirect transfers can reach anywhere -> undetectable here).
        # Remember the resume PC (mepc equivalent) where known and clamp
        # the boundary cycle delta: the gap may span a wfi sleep, which
        # the simulator convention counts as a single cycle.
        exception = False
        resume: Optional[int] = None
        if next_pc is not None:
            if not (cls.is_jump or cls.is_cond_branch or cls.is_return):
                if next_pc != fallthrough:
                    exception, resume = True, fallthrough
            elif target is not None:
                if cls.is_cond_branch:
                    if next_pc not in (target, fallthrough):
                        exception = True          # resume ambiguous
                elif cls.is_jump and not cls.writes_link:
                    if next_pc != target:
                        exception, resume = True, target
        if exception:
            isr_ctxs.append(IsrCtx(depth=len(stack), resume=resume))
            prof.exceptions += 1
            if clamp_exception_cycles:
                cycles = min(cycles, 1)
            taken = False

        prof._update(pc, E_IR, 1, stack)
        if cycles > 0:
            prof._update(pc, E_CY, cycles, stack)

        # --- exception / interrupt exit ----------------------------------
        if next_pc is not None and isr_ctxs and \
                (insn.mnemonic in XRET_MNEMONICS or
                 (cls.is_return and isr_ctxs[-1].resume is not None
                  and next_pc == isr_ctxs[-1].resume)):
            ctx = isr_ctxs.pop()
            _unwind_to(prof, stack, min(ctx.depth, len(stack)))
            if cls.is_jump:
                prof._update(pc, E_BI, 1, stack)
                prof._update(pc, E_BIM, 1, stack)
                prof._update(pc, E_INDJ, 1, stack)
            return

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
        # Tail frames inherit their parent's return address, so a match
        # must unwind through the whole consecutive tail chain plus the
        # normal frame that anchors it (callgrind semantics: the callers'
        # inclusive costs cover tail-called continuations).
        if cls.is_return or (cls.is_jump and cls.is_indirect and not cls.writes_link):
            for i in range(len(stack) - 1, -1, -1):
                if stack[i].ret_addr == next_pc:
                    j = i
                    while j > 0 and stack[j].is_tail:
                        j -= 1
                    _unwind_to(prof, stack, j)
                    return
            if cls.is_return:
                # Unmatched ret: exact link addresses can desync (frames
                # opened before profiling started, mid-function entry,
                # missed transfers). Heal like the simulator does: if we
                # are returning INTO the function that called some frame
                # on the stack, unwind to that frame -- otherwise stale
                # frames pile up forever and their inclusive costs
                # accumulate the rest of the program.
                nf = binary.func_at(next_pc)
                if nf is not None:
                    for i in range(len(stack) - 1, -1, -1):
                        cp = stack[i].call_pc
                        if cp is not None and binary.func_at(cp) is nf:
                            j = i
                            while j > 0 and stack[j].is_tail:
                                j -= 1
                            _unwind_to(prof, stack, j)
                            for c in isr_ctxs:
                                c.depth = min(c.depth, len(stack))
                            prof.healed_returns += 1
                            return
                prof.unmatched_returns += 1
                return

        # --- calls ------------------------------------------------------
        taken_transfer = cls.is_jump or (cls.is_cond_branch and taken)
        if taken_transfer and cls.writes_link and callee_entry:
            prof._update(pc, E_CALL, 1, stack)
            _push_frame(prof, stack, isr_ctxs, FrameCtx(
                func_start=next_pc,
                ret_addr=fallthrough,
                call_pc=pc,
                callee_start=next_pc), max_stack)
            return

        # --- tail calls --------------------------------------------------
        if taken_transfer and not cls.writes_link and callee_entry and diff_func:
            prof._update(pc, E_TAIL, 1, stack)
            if _close_loop_if_reentry(prof, stack, next_pc):
                return
            if stack:
                _push_frame(prof, stack, isr_ctxs, FrameCtx(
                    func_start=next_pc,
                    ret_addr=stack[-1].ret_addr,   # returns to original caller
                    call_pc=pc,
                    callee_start=next_pc,
                    is_tail=True), max_stack)
            return

        # --- fall-through into another function ---------------------------
        # No jump at all, but the next PC is a different function's entry
        # (millicode chains like __riscv_restore_8 -> _4 -> _0, cold/hot
        # split code, hand-written asm). Model it as an implicit tail
        # transfer so the entered function receives a proper incoming arc:
        # otherwise its self cost (every traversal) exceeds its incoming
        # inclusive (direct entries only), which breaks the self ==
        # inclusive invariant for leaves. No E_TAIL event is charged --
        # this is control-flow bookkeeping, not an executed jump.
        if next_pc == fallthrough and callee_entry and diff_func:
            if _close_loop_if_reentry(prof, stack, next_pc):
                return
            _push_frame(prof, stack, isr_ctxs, FrameCtx(
                func_start=next_pc,
                ret_addr=stack[-1].ret_addr if stack else None,
                call_pc=pc,
                callee_start=next_pc,
                is_tail=True), max_stack)
            return

    # Per-commit cycle floor, LOCAL only: coarse-time dumps (ISS
    # advancing time per block) put several PC changes on one timestamp,
    # yielding zero tick deltas; each committed instruction still costs
    # at least 1 cycle. Deliberately NOT conserved globally -- a carried
    # deficit would silently swallow real stall deltas for a long
    # stretch afterwards, destroying exactly the per-instruction stall
    # attribution profiling exists for. Trade-off: total Cy exceeds the
    # raw tick span by the size of the same-timestamp bursts.
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
        commit(prev_pc, max(1, tick - prev_tick), pc)
        prev_tick, prev_pc = tick, pc

    # drain remaining frames (program ended inside calls) -- large
    # accumulations here indicate leaked frames worth investigating
    prof.drained_frames = len(stack)
    prof.drained_top = sorted(
        ((fr.call_pc or 0, fr.callee_start or fr.func_start, fr.acc[E_IR])
         for fr in stack), key=lambda x: -x[2])[:5]
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
