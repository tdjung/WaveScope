"""Core profiler: reconstructs update_profile() semantics from a PC stream.

Cycle attribution (simulator convention): the gap between the previous
instruction's commit and THIS instruction's commit is charged to THIS
instruction -- "the one that waited pays".  Equivalent to the simulator's
`cur_cycle - last_committed_cycle_` charged at each commit.

Call arcs are keyed purely by (call_pc, callee_pc), matching the
simulator's `calls[caller_pc][callee_pc]` map: the enclosing caller
function is derived from call_pc at write time, never from transient
stack context (which fragmented arcs across contexts).

Events: Ir Cy Bc Bcm Bi Bim IndJmp DirJmp Dr Dw.  Calls and tail calls
are tracked structurally (frames / calls map), not as per-PC events.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .classify import InsnClass
from .disasm import BinaryInfo, Insn, direct_target

EVENTS = ["Ir", "Cy", "Bc", "Bcm", "Bi", "Bim",
          "IndJmp", "DirJmp", "Dr", "Dw"]
E_IR, E_CY, E_BC, E_BCM, E_BI, E_BIM, \
    E_INDJ, E_DIRJ, E_DR, E_DW = range(len(EVENTS))
N_EVENTS = len(EVENTS)

XRET_MNEMONICS = {"mret", "sret", "uret", "eret"}

_LOOP_SCAN_DEPTH = 64


@dataclass
class CallSite:
    """Aggregated call info for callgrind `calls=` lines."""
    count: int = 0
    inclusive: List[int] = field(default_factory=lambda: [0] * N_EVENTS)


@dataclass
class IsrCtx:
    depth: int                    # call-stack depth at exception entry
    resume: Optional[int]         # architectural resume PC (mepc), if known


@dataclass
class FrameCtx:
    func_start: int
    ret_addr: Optional[int]
    call_pc: Optional[int]          # pc of the call instruction
    callee_start: Optional[int]     # callee entry for calls= bookkeeping
    is_tail: bool = False
    acc: List[int] = field(default_factory=lambda: [0] * N_EVENTS)


class Profile:
    def __init__(self, binary: BinaryInfo):
        self.binary = binary
        self.self_cost: Dict[int, List[int]] = defaultdict(lambda: [0] * N_EVENTS)
        # (call_pc, callee_start) -> CallSite   [simulator-style pure-PC key]
        self.calls: Dict[Tuple[int, int], CallSite] = defaultdict(CallSite)
        self.total: List[int] = [0] * N_EVENTS
        self.unknown_pcs = 0
        self.exceptions = 0
        self.healed_returns = 0
        self.unmatched_returns = 0
        self.drained_frames = 0
        self.drained_top: List[Tuple[int, int, int]] = []  # (call_pc, callee, acc_ir)

    def _update(self, pc: int, ev: int, n: int, stack: List[FrameCtx]) -> None:
        self.self_cost[pc][ev] += n
        self.total[ev] += n
        for fr in stack:
            fr.acc[ev] += n


def _flush_call(prof: Profile, stack: List[FrameCtx], idx: int) -> None:
    fr = stack[idx]
    if fr.call_pc is None or fr.callee_start is None:
        return
    cs = prof.calls[(fr.call_pc, fr.callee_start)]
    cs.count += 1
    for e in range(N_EVENTS):
        cs.inclusive[e] += fr.acc[e]


def _unwind_to(prof: Profile, stack: List[FrameCtx], depth: int) -> None:
    while len(stack) > depth:
        _flush_call(prof, stack, len(stack) - 1)
        stack.pop()


def _close_loop_if_reentry(prof: Profile, stack: List[FrameCtx],
                           entry: int) -> bool:
    """Loop closure: a transfer back to an entry whose TAIL frame is
    already on the stack (loop body crossing asm-label boundaries) must
    not push one frame per iteration -- each would accumulate all
    remaining iterations, inflating inclusive sums quadratically.
    Flush the frames opened since that entry and reuse the original."""
    lo = max(0, len(stack) - _LOOP_SCAN_DEPTH)
    for i in range(len(stack) - 1, lo - 1, -1):
        fr = stack[i]
        if not fr.is_tail:
            return False          # a real call intervenes: not a loop edge
        if fr.func_start == entry:
            _unwind_to(prof, stack, i + 1)
            return True
    return False


def _push_frame(prof: Profile, stack: List[FrameCtx],
                isr_ctxs: List[IsrCtx], frame: FrameCtx,
                max_stack: int) -> None:
    if len(stack) >= max_stack:
        # saturating: flush-drop the OLDEST frame; silently refusing new
        # pushes would desynchronize call/return matching forever
        _flush_call(prof, stack, 0)
        del stack[0]
        for c in isr_ctxs:
            c.depth = max(0, c.depth - 1)
    stack.append(frame)


def run(pc_stream: Iterable[Tuple[int, int]], binary: BinaryInfo,
        classifier, max_stack: int = 4096,
        clamp_exception_cycles: bool = True) -> Profile:
    """Consume (tick, pc) samples and build a Profile.

    Each new PC value is one committed instruction.  Its cycle cost is
    the tick gap since the PREVIOUS commit (arrival attribution, matching
    the simulator), floored at 1.  Repeated identical PCs at consecutive
    ticks are value holds and produce no new commit; the widened gap is
    charged to the next instruction that commits.
    """
    prof = Profile(binary)
    stack: List[FrameCtx] = []
    isr_ctxs: List[IsrCtx] = []
    clamp_next = False           # set when an exception entry is detected:
                                 # the FIRST handler instruction's arrival
                                 # gap spans the sleep -> charge 1 cycle

    def commit(pc: int, cycles: int, next_pc: Optional[int]) -> None:
        nonlocal clamp_next
        insn = binary.insns.get(pc)
        if insn is None:
            prof.unknown_pcs += 1
            return
        cls: InsnClass = classifier.classify(insn)

        fallthrough = pc + insn.size

        # Resolved target of a *direct* transfer lets us judge taken /
        # not-taken exactly (next_pc == target).
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
                clamp_next = True    # the sleep gap arrives with the FIRST
                                     # handler instruction's commit
            taken = False

        prof._update(pc, E_IR, 1, stack)
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

        # --- returns: pop frames whose saved link matches next_pc ---------
        # Tail frames inherit their parent's return address, so a match
        # unwinds the whole consecutive tail chain plus the normal frame
        # anchoring it (callers' inclusive covers tail continuations).
        if cls.is_return or (cls.is_jump and cls.is_indirect and not cls.writes_link):
            for i in range(len(stack) - 1, -1, -1):
                if stack[i].ret_addr == next_pc:
                    j = i
                    while j > 0 and stack[j].is_tail:
                        j -= 1
                    _unwind_to(prof, stack, j)
                    return
            if cls.is_return:
                # Unmatched ret: heal like the simulator -- if we are
                # returning INTO the function that called some stacked
                # frame, unwind to it; otherwise stale frames accumulate
                # the rest of the program into their inclusive costs.
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

        # --- calls ---------------------------------------------------------
        taken_transfer = cls.is_jump or (cls.is_cond_branch and taken)
        if taken_transfer and cls.writes_link and callee_entry:
            _push_frame(prof, stack, isr_ctxs, FrameCtx(
                func_start=next_pc,
                ret_addr=fallthrough,
                call_pc=pc,
                callee_start=next_pc), max_stack)
            return

        # --- tail calls ------------------------------------------------------
        if taken_transfer and not cls.writes_link and callee_entry and diff_func:
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

        # --- fall-through into another function -------------------------------
        # No jump executed, but the next PC is a different function's
        # entry (millicode chains, cold/hot splits, asm). Model as an
        # implicit tail transfer so the entered function receives a
        # proper incoming arc; otherwise its self cost (every traversal)
        # exceeds its incoming inclusive (direct entries only), breaking
        # the leaf self == inclusive invariant. No jump event charged.
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

    it: Iterator[Tuple[int, int]] = iter(pc_stream)
    try:
        prev_tick, prev_pc = next(it)
    except StopIteration:
        return prof
    pend_cycles = 1                      # first instruction: 1 cycle

    while True:
        try:
            tick, pc = next(it)
        except StopIteration:
            commit(prev_pc, pend_cycles, None)
            break
        if pc == prev_pc:
            # value hold (stall under clocked sampling): no new commit;
            # the widened gap will be charged to the NEXT instruction
            continue
        commit(prev_pc, pend_cycles, pc)
        # arrival attribution: THIS instruction pays the gap since the
        # previous commit (floored at 1; local, never carried)
        pend_cycles = max(1, tick - prev_tick)
        if clamp_next:
            pend_cycles = 1
            clamp_next = False
        prev_tick, prev_pc = tick, pc

    # drain remaining frames (program ended inside calls) -- equivalent
    # to the simulator's remain_call_stack_process(): every frame still
    # open flushes its accumulated inclusive into its call arc, so
    # recursive chains close out. Large accumulations here indicate
    # leaked frames worth investigating (reported to stderr by the CLI).
    prof.drained_frames = len(stack)
    prof.drained_top = sorted(
        ((fr.call_pc or 0, fr.callee_start or fr.func_start, fr.acc[E_IR])
         for fr in stack), key=lambda x: -x[2])[:5]
    _unwind_to(prof, stack, 0)
    return prof
