"""Core profiler: reconstructs update_profile() semantics from a PC stream.

Pipeline (v0.8.0, restructured to mirror the simulator's update()):
each committed instruction is processed in simulator order --

    1. update_epc      : ISR entry via mepc value change (--epc mode)
    2. ISR exit        : pc == saved epc (--epc mode) / xret (heuristic)
    3. resolve pending : the PREVIOUS instruction's successor-dependent
                         work (taken judgement, Bcm, call/tail/return
                         stack ops) runs now that its landing pc is known
                         -- the simulator's check_branch_type +
                         handler_branch pair
    4. charge events   : Ir, Cy (arrival-attributed), Bc, Bi/Bim,
                         Dir/IndJmp, Dr, Dw
    5. record pending  : this instruction awaits its own successor

Deferring successor resolution through a `pending` record is what lets
an ISR entry SAVE the interrupted instruction's unresolved state (the
simulator's IsrInfo.{last_pc, branchType, taken}) and resolve it after
mret with the true landing pc -- without this, a branch interrupted
mid-flight is judged against the handler address and mis-attributed.

Cycle attribution (simulator convention): the gap between the previous
instruction's commit and THIS instruction's commit is charged to THIS
instruction -- "the one that waited pays".  Equivalent to the simulator's
`cur_cycle - last_committed_cycle_` charged at each commit.

Call arcs are keyed purely by (call_pc, callee_pc), matching the
simulator's `calls[caller_pc][callee_pc]` map.

Events: Ir Cy Bc Bcm Bi Bim IndJmp DirJmp Dr Dw.  Calls and tail calls
are tracked structurally (frames / calls map), not as per-PC events.

ISR detection modes:
  * epc mode (a third stream element carries the mepc CSR value):
    entry   = mepc value change at a commit (simulator update_epc),
              plus the WFI-wake rule (is_wfi && after_wfi && landing in
              a different function) for back-to-back wakeups where mepc
              is rewritten with an identical value;
    spurious= an mepc change landing in the SAME function as the current
              pc suppresses detection until the next ISR exit
              (simulator epc_error_check);
    exit    = committing the saved epc address (works even for
              interrupts right after indirect jumps, which the
              heuristic can never see).
  * heuristic mode (PC-only stream): an architecturally unreachable
    successor marks entry; xret / return-to-resume marks exit.
In epc mode the unreachable-successor test still runs, but only as a
diagnostic (`flow_anomalies`): discontinuities NOT explained by an ISR
usually mean the sampled PC is speculative (issue-stage pollution).
"""

from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

from .classify import InsnClass
from .disasm import BinaryInfo, direct_target

EVENTS = ["Ir", "Cy", "Bc", "Bcm", "Bi", "Bim",
          "IndJmp", "DirJmp", "Dr", "Dw"]
E_IR, E_CY, E_BC, E_BCM, E_BI, E_BIM, \
    E_INDJ, E_DIRJ, E_DR, E_DW = range(len(EVENTS))
N_EVENTS = len(EVENTS)

XRET_MNEMONICS = {"mret", "sret", "uret", "eret"}
WFI_MNEMONICS = {"wfi", "wfe"}

_LOOP_SCAN_DEPTH = 64


class CallSite(object):
    """Aggregated call info for callgrind `calls=` lines."""
    __slots__ = ("count", "inclusive")

    def __init__(self):
        self.count = 0
        self.inclusive = [0] * N_EVENTS


class Pending(object):
    """A committed instruction whose successor is not yet known."""
    __slots__ = ("pc", "insn", "cls", "target", "fallthrough", "exc")

    def __init__(self, pc, insn, cls, target, fallthrough):
        self.pc = pc
        self.insn = insn
        self.cls = cls
        self.target = target          # resolved direct-transfer target
        self.fallthrough = fallthrough
        self.exc = False              # heuristic: interrupted -> not taken


class IsrCtx(object):
    __slots__ = ("depth", "resume", "saved", "kind")

    def __init__(self, depth, resume, saved=None, kind="heur"):
        self.depth = depth        # call-stack depth at exception entry
        self.resume = resume      # architectural resume PC (mepc), if known
        self.saved = saved        # interrupted Pending (epc mode), like
                                  # the simulator's IsrInfo branch state
        self.kind = kind          # 'epc' | 'heur'


class FrameCtx(object):
    __slots__ = ("func_start", "ret_addr", "call_pc", "callee_start",
                 "is_tail", "acc")

    def __init__(self, func_start, ret_addr, call_pc, callee_start,
                 is_tail=False):
        self.func_start = func_start
        self.ret_addr = ret_addr
        self.call_pc = call_pc            # pc of the call instruction
        self.callee_start = callee_start  # callee entry for calls= bookkeeping
        self.is_tail = is_tail
        self.acc = [0] * N_EVENTS


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
        # --- epc-mode diagnostics ---
        self.epc_mode = False        # an epc value was actually seen
        self.spurious_epc = 0        # same-function mepc changes suppressed
        self.flow_anomalies = 0      # unexplained discontinuities (epc mode)
        self.isr_open = 0            # ISR contexts alive at end of trace

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


def _unreachable_successor(p: Pending, next_pc: int) -> Tuple[bool, Optional[int]]:
    """Trap entry between two commits shows up as a successor that no
    architectural path of the previous instruction can reach:
        plain insn      : next != fallthrough
        direct jump     : next != target
        direct cond br  : next not in {target, fallthrough}
    (indirect transfers can reach anywhere -> undetectable here).
    Returns (is_unreachable, resume_pc_or_None)."""
    cls = p.cls
    if not (cls.is_jump or cls.is_cond_branch or cls.is_return):
        if next_pc != p.fallthrough:
            return True, p.fallthrough
    elif p.target is not None:
        if cls.is_cond_branch:
            if next_pc not in (p.target, p.fallthrough):
                return True, None          # resume ambiguous
        elif cls.is_jump and not cls.writes_link:
            if next_pc != p.target:
                return True, p.target
    return False, None


def run(pc_stream: Iterable[Tuple], binary: BinaryInfo,
        classifier, max_stack: int = 4096,
        clamp_exception_cycles: bool = True) -> Profile:
    """Consume (tick, pc[, epc]) samples and build a Profile.

    Each new PC value is one committed instruction.  Its cycle cost is
    the tick gap since the PREVIOUS commit (arrival attribution, matching
    the simulator), floored at 1.  Repeated identical PCs at consecutive
    ticks are value holds and produce no new commit; the widened gap is
    charged to the next instruction that commits.

    Samples may carry a third element: the epc CSR (mepc) value at that
    commit, enabling exact ISR entry/exit detection (see module doc).
    """
    prof = Profile(binary)
    stack: List[FrameCtx] = []
    isr_ctxs: List[IsrCtx] = []

    pending: Optional[Pending] = None
    n_committed = 0

    # epc / wfi state (simulator update_epc + wfi handlers)
    epc_init = False
    prev_epc: Optional[int] = None
    epc_suppressed = False
    is_wfi = False
    after_wfi = False
    wfi_func = None

    def resolve(p: Pending, cur_pc: int) -> None:
        """Successor-dependent processing of the previous instruction,
        now that its landing pc is known (simulator check_branch_type +
        handler_branch)."""
        cls = p.cls

        taken = cur_pc != p.fallthrough
        if p.target is not None:
            taken = cur_pc == p.target
        if p.exc:
            taken = False        # interrupted: landing is the handler

        if cls.is_cond_branch and taken:
            prof._update(p.pc, E_BCM, 1, stack)

        if prof.epc_mode and not p.exc:
            # entry consumed its pending, exit resolves with the true
            # landing -- any unreachable successor left here is an
            # UNEXPLAINED discontinuity (likely speculative PC samples)
            anom, _ = _unreachable_successor(p, cur_pc)
            if anom:
                prof.flow_anomalies += 1

        cur_func = binary.func_at(p.pc)
        callee_entry = binary.is_func_entry(cur_pc)
        diff_func = cur_func is None or not (cur_func.start <= cur_pc < cur_func.end)

        # --- returns: pop frames whose saved link matches cur_pc -----------
        # Tail frames inherit their parent's return address, so a match
        # unwinds the whole consecutive tail chain plus the normal frame
        # anchoring it (callers' inclusive covers tail continuations).
        if cls.is_return or (cls.is_jump and cls.is_indirect and not cls.writes_link):
            for i in range(len(stack) - 1, -1, -1):
                if stack[i].ret_addr == cur_pc:
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
                nf = binary.func_at(cur_pc)
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

        # --- calls ----------------------------------------------------------
        taken_transfer = cls.is_jump or (cls.is_cond_branch and taken)
        if taken_transfer and cls.writes_link and callee_entry:
            _push_frame(prof, stack, isr_ctxs, FrameCtx(
                func_start=cur_pc,
                ret_addr=p.fallthrough,
                call_pc=p.pc,
                callee_start=cur_pc), max_stack)
            return

        # --- tail calls -------------------------------------------------------
        if taken_transfer and not cls.writes_link and callee_entry and diff_func:
            if _close_loop_if_reentry(prof, stack, cur_pc):
                return
            if stack:
                _push_frame(prof, stack, isr_ctxs, FrameCtx(
                    func_start=cur_pc,
                    ret_addr=stack[-1].ret_addr,   # returns to original caller
                    call_pc=p.pc,
                    callee_start=cur_pc,
                    is_tail=True), max_stack)
            return

        # --- fall-through into another function --------------------------------
        # No jump executed, but the next PC is a different function's
        # entry (millicode chains, cold/hot splits, asm). Model as an
        # implicit tail transfer so the entered function receives a
        # proper incoming arc; otherwise its self cost (every traversal)
        # exceeds its incoming inclusive (direct entries only), breaking
        # the leaf self == inclusive invariant. No jump event charged.
        if cur_pc == p.fallthrough and callee_entry and diff_func:
            if _close_loop_if_reentry(prof, stack, cur_pc):
                return
            _push_frame(prof, stack, isr_ctxs, FrameCtx(
                func_start=cur_pc,
                ret_addr=stack[-1].ret_addr if stack else None,
                call_pc=p.pc,
                callee_start=cur_pc,
                is_tail=True), max_stack)
            return

    def step(pc: int, cycles: int, epc: Optional[int]) -> None:
        nonlocal pending, n_committed, epc_init, prev_epc, epc_suppressed
        nonlocal is_wfi, after_wfi, wfi_func

        insn = binary.insns.get(pc)
        # An unknown landing pc (outside the ELF text) still resolves the
        # previous instruction and can mark an exception entry; only its
        # OWN events are skipped.
        cls: Optional[InsnClass] = None
        target = None
        fallthrough = pc
        if insn is not None:
            cls = classifier.classify(insn)
            fallthrough = pc + insn.size
            if (cls.is_cond_branch or cls.is_jump) and not cls.is_indirect:
                target = direct_target(insn)

        # --- 1. ISR entry via epc (simulator update_epc) ------------------
        entered = False
        if epc is not None:
            prof.epc_mode = True
            if not epc_init and n_committed == 0:
                # trace-start baseline: mepc may hold a stale value from
                # before the dump began; only CHANGES from here are traps
                prev_epc = epc
                epc_init = True
            else:
                changed = (not epc_init) or (epc != prev_epc)
                f_here = binary.func_at(pc)
                wfi_wake = (is_wfi and after_wfi and wfi_func is not None
                            and f_here is not wfi_func)
                if (changed or wfi_wake) and not epc_suppressed:
                    f_epc = binary.func_at(epc) if changed else None
                    if changed and f_epc is not None and f_here is not None \
                            and f_epc is f_here:
                        # same-function epc change: spurious (simulator
                        # epc_error_check) -- suppress until ISR exit
                        epc_suppressed = True
                        prof.spurious_epc += 1
                    else:
                        after_wfi = False
                        prev_epc = epc
                        epc_init = True
                        # save the interrupted instruction's unresolved
                        # branch state, exactly like IsrInfo, and resolve
                        # it after the handler returns
                        isr_ctxs.append(IsrCtx(depth=len(stack), resume=epc,
                                               saved=pending, kind="epc"))
                        pending = None
                        prof.exceptions += 1
                        if clamp_exception_cycles:
                            cycles = 1     # first_isr_cycle: sleep gap -> 1
                        entered = True

        # --- 2. ISR exit ----------------------------------------------------
        if not entered and isr_ctxs:
            ctx = isr_ctxs[-1]
            if ctx.kind == "epc":
                # simulator: committing the saved epc address restores the
                # pre-interrupt context (works after indirect jumps too)
                if pc == ctx.resume:
                    isr_ctxs.pop()
                    _unwind_to(prof, stack, min(ctx.depth, len(stack)))
                    pending = ctx.saved          # discard the xret pending;
                    epc_suppressed = False       # resolve the interrupted one
                    prev_epc = isr_ctxs[-1].resume if isr_ctxs else ctx.resume
            elif pending is not None:
                # heuristic: xret, or a return landing on the recorded
                # resume address
                if pending.insn.mnemonic in XRET_MNEMONICS or \
                        (pending.cls.is_return and ctx.resume is not None
                         and pc == ctx.resume):
                    isr_ctxs.pop()
                    _unwind_to(prof, stack, min(ctx.depth, len(stack)))
                    pending = None

        # --- 2b. heuristic ISR entry (PC-only mode) -------------------------
        if not prof.epc_mode and pending is not None:
            exc, resume = _unreachable_successor(pending, pc)
            if exc:
                isr_ctxs.append(IsrCtx(depth=len(stack), resume=resume,
                                       kind="heur"))
                prof.exceptions += 1
                if clamp_exception_cycles:
                    cycles = 1
                pending.exc = True   # interrupted transfer: judge not-taken

        # --- 3. resolve the previous instruction against this landing -------
        if pending is not None:
            resolve(pending, pc)

        if insn is None or cls is None:
            prof.unknown_pcs += 1
            pending = None
            return

        # --- 4. wfi tracking (simulator wfi_out/wfi_in order) ---------------
        f_here = binary.func_at(pc)
        if is_wfi and wfi_func is not None and f_here is wfi_func:
            is_wfi = False                       # back in the wfi function
        if not is_wfi and insn.mnemonic in WFI_MNEMONICS:
            is_wfi = True
            after_wfi = True
            wfi_func = f_here

        # --- 5. charge this instruction's own events -------------------------
        prof._update(pc, E_IR, 1, stack)
        prof._update(pc, E_CY, cycles, stack)
        if cls.is_cond_branch:
            prof._update(pc, E_BC, 1, stack)
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

        # --- 6. this instruction now awaits its own successor ----------------
        pending = Pending(pc, insn, cls, target, fallthrough)
        n_committed += 1

    prev_tick: Optional[int] = None
    prev_pc: Optional[int] = None
    for s in pc_stream:
        tick, pc = s[0], s[1]
        epc = s[2] if len(s) > 2 else None
        if prev_pc is not None and pc == prev_pc:
            # value hold (stall under clocked sampling): no new commit;
            # the widened gap will be charged to the NEXT instruction
            continue
        # arrival attribution: THIS instruction pays the gap since the
        # previous commit (floored at 1; local, never carried)
        cycles = 1 if prev_tick is None else max(1, tick - prev_tick)
        step(pc, cycles, epc)
        prev_tick, prev_pc = tick, pc

    # drain remaining frames (program ended inside calls) -- equivalent
    # to the simulator's remain_call_stack_process(): every frame still
    # open flushes its accumulated inclusive into its call arc, so
    # recursive chains close out. Large accumulations here indicate
    # leaked frames worth investigating (reported to stderr by the CLI).
    prof.isr_open = len(isr_ctxs)
    prof.drained_frames = len(stack)
    prof.drained_top = sorted(
        ((fr.call_pc or 0, fr.callee_start or fr.func_start, fr.acc[E_IR])
         for fr in stack), key=lambda x: -x[2])[:5]
    _unwind_to(prof, stack, 0)
    return prof
