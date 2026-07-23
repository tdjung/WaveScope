"""simcore: LITERAL transcription of docs/simulator_reference.md.

This engine mirrors the user's C++ simulator profiler line-for-line --
state names, control flow, quirks and all -- so that discrepancies
against the simulator's output can be resolved by CODE REVIEW against
the pseudocode instead of run-and-observe cycles.  Robustness features
of the legacy engine (healing, anomaly counters, ISR level mode) are
deliberately ABSENT here; anything not in the reference must not be
added without marking it as a feeder adapter.

Feeder adapters (the only places we deviate, because a waveform is not
an ISS -- each is marked ADAPTER in the code):
  A1. `taken` for a conditional branch: the ISS knows the architectural
      npc at commit; we derive it from the NEXT committed pc, so the
      feeder runs one commit behind the stream.  If the next commit is
      a trap redirect, the saved `last_branch_taken` can be judged
      against the handler address (the ISS would know the true npc);
      the landing itself is still replayed correctly at resume.
  A2. `prev_epc` baseline: the ISS starts with prev_epc == mepc == 0;
      a waveform can begin mid-run with a stale mepc, so prev_epc is
      initialized to the first defined epc value.
  A3. update_epc is skipped while the epc value is undefined (x); the
      ISS always has a register value.

Reproduced simulator quirks (kept for diff parity, marked QUIRK):
  Q1. update_epc's wfi-wake condition reads infos_[pc] with operator[]
      semantics: a missing pc inserts an empty entry (func "") that
      subsequently satisfies contains() -- acknowledged bug candidate.
"""

from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .disasm import BinaryInfo, direct_target
from .profdata import (E_BC, E_BI, E_BIM, E_CY, E_DR, E_DW, E_IR, EVENTS,
                       N_EVENTS, CallSite, Profile)

# BranchType (enum class BranchType)
BT_NONE = 0
BT_CALL = 1
BT_TAIL_CALL = 2
BT_RETURN = 3
BT_BRANCH = 4
BT_DIRECT_JUMP = 5
BT_INDIRECT_JUMP = 6

# FunctionType (enum class FunctionType)
FT_NORMAL = 0
FT_SAVE_HELPER = 1
FT_RESTORE_HELPER = 2

TRACE_IR = E_IR
TRACE_Cy_direct = -2          # pseudo id: routed to E_CY accumulation
TRACE_Bc = E_BC
TRACE_Bi = E_BI
TRACE_Bim = E_BIM
TRACE_Dr = E_DR
TRACE_Dw = E_DW


class SimInfo(object):
    """infos_ entry: {event[], debug_info(func/assembly), func_type}"""
    __slots__ = ("event", "func", "assembly", "func_type")

    def __init__(self, func="", assembly="", func_type=FT_NORMAL):
        self.event = [0] * N_EVENTS
        self.func = func
        self.assembly = assembly
        self.func_type = func_type


class CallStackEntry(object):
    __slots__ = ("caller_pc", "callee_pc", "caller_func", "callee_func",
                 "is_tail_call", "events_at_entry")

    def __init__(self):
        self.caller_pc = 0
        self.callee_pc = 0
        self.caller_func = ""
        self.callee_func = ""
        self.is_tail_call = False
        self.events_at_entry = [0] * N_EVENTS


class IsrInfo(object):
    __slots__ = ("epc", "last_pc", "branchType", "last_was_branch",
                 "last_branch_taken")


class BranchRec(object):
    __slots__ = ("total_executed", "taken_count", "taken_target",
                 "not_taken_target")

    def __init__(self):
        self.total_executed = 0
        self.taken_count = 0
        self.taken_target = None
        self.not_taken_target = None


def _func_type(name: str) -> int:
    if "__riscv_save" in name:
        return FT_SAVE_HELPER
    if "__riscv_restore" in name:
        return FT_RESTORE_HELPER
    return FT_NORMAL


def isSaveHelper(t: int) -> bool:
    return t == FT_SAVE_HELPER


def isCompilerHelper(t: int) -> bool:
    return t != FT_NORMAL


class SimProfiler(object):
    """Transcription of the simulator's profiler class."""

    def __init__(self, binary: BinaryInfo):
        self.binary = binary
        self.infos_: Dict[int, SimInfo] = {}
        for pc, insn in binary.insns.items():
            f = binary.func_at(pc)
            if f is None:
                continue                      # not part of any function
            asm = insn.mnemonic + ("\t" + insn.operands
                                   if insn.operands else "")
            self.infos_[pc] = SimInfo(f.name, asm, _func_type(f.name))

        self.accumulated_events = [0] * N_EVENTS
        self.calls: Dict[int, Dict[int, CallSite]] = defaultdict(
            lambda: defaultdict(CallSite))
        self.branches: Dict[int, BranchRec] = defaultdict(BranchRec)
        self.jumps: Dict[int, Dict[int, int]] = defaultdict(
            lambda: defaultdict(int))

        self.normal_stack: List[CallStackEntry] = []
        self.call_stack: List[CallStackEntry] = self.normal_stack
        self.isr_stack: List[IsrInfo] = []
        self.isr_call_stack_of_stack: List[List[CallStackEntry]] = []

        self.sizes_ = {pc: insn.size for pc, insn in binary.insns.items()}
        self.entry_set_ = {f.start for f in binary.funcs}
        self.prev_ft = None        # A6: expected sequential successor
        self.flow_lost = False     # A6: pcs ran outside the known text
        self._flowchk_base = None  # A6: once-per-commit dedup

        self.last_pc = 0
        self.branchType = BT_NONE
        self.last_was_branch = False
        self.last_branch_taken = False

        self.prev_epc = 0
        self.epc_error_check = False
        self.is_isr = False
        self.first_isr_cycle = False

        self.is_wfi = False
        self.after_wfi = False
        self.wfi_func = ""

        self.real_caller_pc = 0
        self.real_caller_func = ""

        self.cur_insn_ = 0
        self.last_func_name = ""
        self.enabled_ = True

        # diagnostics for the CLI (not part of the transcription)
        self.root_log = None
        self.cur_tick = None
        self.debug_funcs = None    # set of function names to func-trace
        self.func_log = None       # {"ev": [...], "omitted": n}
        self.n_isr_entries = 0
        self.n_isr_exits = 0
        self.max_exit_drain = 0
        self.n_spurious = 0
        self.n_return_guard = 0    # A5a: RETURN pops skipped (landing
                                   # still inside the top frame's callee)
        self.n_chain_guard = 0     # A5b: tail-chain pops stopped early
        self.n_disc_returns = 0    # A6: frames closed by a discontinuity
                                   # landing on an open frame's return
                                   # address with no branch committed
        self.n_exit_rejects = 0    # A7: pc==epc arrivals rejected as ISR
                                   # exits (handler's own flow reached the
                                   # resume address -- shared millicode)
        self.n_epc_rewrites = 0    # A8: software mepc writes consumed
                                   # without declaring a phantom entry
        self.n_tail_frames = 0     # A9: frames synthesized for tail
                                   # calls on an empty stack
        self.prev_was_xret = False # A7: previous committed insn was xret
        self._exit_gate_serial = -1    # A7: once-per-commit verdict cache
        self._exit_gate_block = False
        self._last_base = None         # commit serial: revisits of the
        self._commit_serial = 0        # same pc are distinct commits
        self.dropped_unknown_pc = 0

    def _root(self, kind, cp, callee, info, depth):
        # v0.20.8 func-trace: full event log filtered by FUNCTION,
        # independent of the depth-windowed root log -- --debug-roots
        # is unreadable on call-heavy traces, this answers "show me
        # everything that happens to THESE functions"
        fl = self.func_log
        if fl is not None:
            names = set()
            for a in (cp, callee):
                if a is not None:
                    i = self.infos_.get(a)
                    if i is not None and i.func:
                        names.add(i.func)
            if names & self.debug_funcs:
                if len(fl["ev"]) < 800:
                    fl["ev"].append((self.cur_tick, kind, cp, callee,
                                     info, depth))
                else:
                    fl["omitted"] += 1
        log = self.root_log
        if log is None:
            return
        if depth > log["depth"] and kind in ("push", "pop"):
            return                     # symmetric window for push AND pop
        log["n"][kind] = log["n"].get(kind, 0) + 1
        if len(log["ev"]) < 200:
            log["ev"].append((self.cur_tick, kind, cp, callee, info,
                              depth, None))
        else:
            log["omitted"] = log.get("omitted", 0) + 1

    # -- QUIRK Q1: infos_[pc] with std::map operator[] semantics -------
    def _infos_bracket(self, pc: int) -> SimInfo:
        info = self.infos_.get(pc)
        if info is None:
            info = SimInfo()                  # default-constructed entry
            self.infos_[pc] = info            # inserted into the map!
        return info

    # ------------------------------------------------------------------
    def update_epc(self, epc: int, pc: int, force: bool = False) -> None:
        # `force` is feeder ADAPTER A4 (same-mepc interrupt re-entry
        # detected from the waveform); the reference has no such
        # parameter -- its change detection is blind to a loop being
        # interrupted repeatedly at one pc (only the wfi case is
        # covered), and the user's simulator shares that gap.
        if force or (self.prev_epc != epc) or \
                (self.is_wfi and self.after_wfi and
                 (self.wfi_func != self._infos_bracket(pc).func)):

            if self.epc_error_check:
                return

            if (self.prev_epc != epc) and \
                    (epc in self.infos_ and pc in self.infos_) and \
                    (self.infos_[epc].func == self.infos_[pc].func):
                self.epc_error_check = True
                self.n_spurious += 1
                return

            # ADAPTER A8 (NOT in the reference): mepc changed, but the
            # flow ARRIVED at this commit through its own architectural
            # path (sequential, or a pending direct transfer's target)
            # -- no trap can have been taken here, so this is a
            # SOFTWARE write to mepc.  Real firmware does this all the
            # time: nested-capable handlers restore the outer mepc in
            # their epilogue (the ISR_end_of_process_interrupt shape),
            # and task switchers aim mepc at the next task before mret.
            # The reference declares a phantom nested ISR entry on the
            # bare value change, freezing the live call stack: the very
            # next `j __riscv_restore_0` then lands on an EMPTY stack
            # and takes the reference's tail-noframe path -- the arc
            # keeps its call count but never receives inclusive events,
            # and the frozen (caller -> handler-epilogue) frames lose
            # theirs too.  Instead: consume the new value as the
            # expected resume (retargeting the CURRENT context's exit,
            # since the eventual xret will go to the NEW mepc) and do
            # not enter.
            if (not force) and (self.prev_epc != epc) \
                    and self._arrival_explained(pc):
                self.n_epc_rewrites += 1
                self._root("epc-rewrite", pc, epc,
                           f"mepc -> 0x{epc:x} by software (flow at "
                           f"0x{pc:x} is sequential/explained -- no "
                           f"trap); "
                           + ("ISR exit retargeted (A8)" if self.is_isr
                              else "baseline updated, no entry (A8)"),
                           len(self.call_stack))
                self.prev_epc = epc
                if self.is_isr:
                    self.isr_stack[-1].epc = epc
                return

            self.after_wfi = False
            self.prev_epc = epc
            self.is_isr = True
            self.n_isr_entries += 1
            self._root("isr-enter", pc, epc,
                       "forced(A4 reenter)" if force else "epc-change",
                       len(self.call_stack))

            if self.isr_stack:
                self.isr_call_stack_of_stack.append(self.call_stack)
            self.call_stack = []

            isrInfo = IsrInfo()
            isrInfo.epc = epc
            isrInfo.last_pc = self.last_pc
            isrInfo.branchType = self.branchType
            isrInfo.last_was_branch = self.last_was_branch
            isrInfo.last_branch_taken = self.last_branch_taken
            self.isr_stack.append(isrInfo)

            self.last_was_branch = False
            self.first_isr_cycle = True
            self.prev_ft = None        # A6: handler entry is not a return
            self.flow_lost = False

    # ------------------------------------------------------------------
    def update(self, base: int, event: int, count: int) -> None:
        if not self.enabled_:
            return
        if base != self._last_base:
            self._last_base = base
            self._commit_serial += 1
        if base not in self.infos_:
            self.dropped_unknown_pc += 1
            self.flow_lost = True      # A6: veneer/far-stub territory
            return
        info = self.infos_[base]

        # ISR return: current pc equals the saved epc
        # ADAPTER A7 (NOT in the reference): the resume address can live
        # in code the handler ALSO executes -- above all the shared
        # __riscv_save/restore millicode (interrupt at `jal t0,save`
        # puts mepc at the helper entry, and the handler's own prologue
        # calls the same helper).  The reference exits on the bare
        # pc==epc equality, draining the handler's frames mid-handler:
        # arcs keep their call counts but lose their inclusive events,
        # and the rest of the handler then corrupts the outer stack.
        # A real exit arrives via xret (or as a discontinuity when the
        # xret commit was dropped); an arrival explained by the previous
        # instruction's own fallthrough/direct target is NOT an exit.
        if self.is_isr and self.isr_stack[-1].epc == base:
            # the verdict must be computed ONCE per commit: update() is
            # called for each event (IR, Cy, ...) of the same base, and
            # the first call's settle consumes last_was_branch and
            # advances prev_ft, which would flip the verdict on the
            # second call and let the false exit through after all
            if self._exit_gate_serial != self._commit_serial:
                self._exit_gate_serial = self._commit_serial
                # v0.20.7 tightening: ANY pending branch settling at
                # this commit -- indirect included -- means the arrival
                # is the handler's own flow.  This closes the v0.20.5
                # documented hole: a SHARED callee (executed by both the
                # interrupted code and the handler) can carry the resume
                # address inside it, and its millicode save's `jr t0`
                # (indirect) lands exactly there when the handler
                # re-executes it -- exit must not fire.  A real exit
                # arrives after an xret, which never leaves a branch
                # pending (prev_was_xret admits it), or through
                # untracked code (flow_lost admits it).
                self._exit_gate_block = (
                    not self.prev_was_xret
                    and not self.flow_lost
                    and ((self.prev_ft is not None
                          and base == self.prev_ft)
                         or self.last_was_branch))
                if self._exit_gate_block:
                    self.n_exit_rejects += 1
                    self._root("exit-reject", base, None,
                               f"pc==epc 0x{base:x} but the handler's "
                               f"own flow reaches it (shared code with "
                               f"the interrupted path) -- not an exit "
                               f"(A7)",
                               len(self.call_stack))
        if self.is_isr and self.isr_stack[-1].epc == base \
                and self._exit_gate_serial == self._commit_serial \
                and self._exit_gate_block:
            pass                       # A7: rejected -- stay in the ISR
        elif self.is_isr and self.isr_stack[-1].epc == base:
            top = self.isr_stack[-1]
            self.last_pc = top.last_pc
            self.branchType = top.branchType
            self.last_was_branch = top.last_was_branch
            self.last_branch_taken = top.last_branch_taken
            self.prev_epc = top.epc
            self.epc_error_check = False

            drained = len(self.call_stack)
            while self.call_stack:
                entry = self.call_stack[-1]
                call_info = self.calls[entry.caller_pc][entry.callee_pc]
                for i in range(N_EVENTS):
                    call_info.inclusive[i] += (
                        self.accumulated_events[i] -
                        entry.events_at_entry[i])
                self.call_stack.pop()
            self.isr_stack.pop()
            self.n_isr_exits += 1
            if drained > self.max_exit_drain:
                self.max_exit_drain = drained
            self._root("isr-exit", base, None,
                       f"resume epc=0x{top.epc:x}, drained {drained} "
                       f"open frames"
                       + (" <-- SUSPICIOUS (stale ISR level?)"
                          if drained >= 3 else ""),
                       drained)

            if not self.isr_stack:
                self.is_isr = False
                self.call_stack = self.normal_stack
            else:
                self.call_stack = self.isr_call_stack_of_stack.pop()
                self.prev_epc = self.isr_stack[-1].epc
            self.prev_ft = None        # A6: resume pc is not a return
            self.flow_lost = False

        # previous instruction was a branch: settle it with this landing
        settled = False
        if self.last_pc != 0 and self.last_was_branch:
            self.check_branch_type(base)
            self.handler_branch(base)
            self.last_was_branch = False
            settled = True

        # ADAPTER A6 (NOT in the reference): sequential flow broke with
        # NO branch committed -- macro-fused pairs (auipc+jr/jalr: only
        # the auipc's pc is sampled), veneers/far-stubs through
        # untracked code, or a dropped jump commit.  The reference
        # simply never closes the open frame, which then swallows the
        # rest of the run as bogus inclusive cost (the reported
        # 139k-instruction arc for a 1-instruction function).  If the
        # landing equals an open frame's return address, close down to
        # that frame; entries are excluded (missed call / interrupt).
        if self._flowchk_base != self._commit_serial:
            self._flowchk_base = self._commit_serial
            disc = self.flow_lost or (self.prev_ft is not None
                                      and base != self.prev_ft)
            if disc and not settled:
                self._disc_return(base)
            self.flow_lost = False
            self.prev_ft = base + self.sizes_.get(base, 4)
            self.prev_was_xret = info.assembly.startswith(
                ("mret", "sret", "uret", "eret"))

        if event == TRACE_Cy_direct:
            if self.first_isr_cycle:          # ISR first insn: clamp to 1
                count = 1
                self.first_isr_cycle = False
            info.event[E_CY] += count
            self.accumulated_events[E_CY] += count
            self.wfi_in_handler(info)
        elif event == TRACE_IR:
            self.wfi_out_handler(info, base)
            self.cur_insn_ = base
            info.event[event] += count
            self.accumulated_events[event] += count
        else:
            info.event[event] += count
            self.accumulated_events[event] += count

        self.last_func_name = info.func

    # ------------------------------------------------------------------
    def wfi_in_handler(self, info: SimInfo) -> None:
        if (not self.is_wfi) and info.assembly.startswith("wfi"):
            self.wfi_func = info.func
            self.is_wfi = True
            self.after_wfi = True

    def wfi_out_handler(self, info: SimInfo, cur_pc: int) -> None:
        if self.is_wfi and info.func == self.wfi_func:
            self.is_wfi = False

    # ------------------------------------------------------------------
    def update_branch(self, base: int, event: int,
                      taken: bool = False) -> None:
        self.last_pc = base
        self.branchType = event
        self.last_was_branch = True
        self.last_branch_taken = taken

    # ------------------------------------------------------------------
    def _arrival_explained(self, base: int) -> bool:
        """A7 helper: True when the previous instruction's own
        architectural flow reaches `base` -- sequential fallthrough, or
        a pending direct transfer whose static target is `base`.  Such
        arrivals cannot be interrupt returns."""
        if self.flow_lost:
            return False        # arrived through untracked code: cannot
                                # be explained by the handler's own flow
        if self.prev_ft is not None and base == self.prev_ft:
            return True
        if self.last_was_branch and self.last_pc:
            insn = self.binary.insns.get(self.last_pc)
            if insn is not None:
                t = direct_target(insn)
                if t is not None and t == base:
                    return True
        return False

    # ------------------------------------------------------------------
    def _disc_return(self, cur_pc: int) -> None:
        """ADAPTER A6 body: scan open frames for one whose return
        address (caller_pc + caller insn size) equals the landing; tail
        entries' caller_pc is the tail-jump pc so a chain naturally
        matches at its anchor and the tails above it are closed with
        it.  A5-style landing rule still applies to the frames being
        swept: never close one whose callee contains the landing."""
        if not self.call_stack or cur_pc in self.entry_set_:
            return
        stk = self.call_stack
        matched = None
        for i in range(len(stk) - 1, -1, -1):
            cp = stk[i].caller_pc
            if cp + self.sizes_.get(cp, 4) == cur_pc:
                matched = i
                break
        if matched is None:
            return
        to_info = self.infos_.get(cur_pc)
        to_func = to_info.func if to_info is not None else None
        self.n_disc_returns += 1
        self._root("disc-ret", stk[matched].caller_pc,
                   stk[matched].callee_pc,
                   f"flow discontinuity lands at this frame's return "
                   f"address 0x{cur_pc:x} with no branch committed "
                   f"(fused pair / hidden jump / untracked code) -- "
                   f"closing {len(stk) - matched} frame(s) (A6)",
                   matched + 1)
        while len(self.call_stack) > matched:
            e = self.call_stack[-1]
            if (len(self.call_stack) - 1 != matched
                    and to_func is not None
                    and e.callee_func == to_func
                    and e.callee_func != e.caller_func):
                self.n_chain_guard += 1
                self._root("chain-guard", e.caller_pc, e.callee_pc,
                           f"disc-ret sweep stopped: landing "
                           f"0x{cur_pc:x} is inside this frame's callee "
                           f"(A5/A6)", len(self.call_stack))
                break
            self._root("pop", e.caller_pc, e.callee_pc,
                       f"disc-ret landing 0x{cur_pc:x} (A6)",
                       len(self.call_stack))
            self.call_stack.pop()
            ci = self.calls[e.caller_pc][e.callee_pc]
            for k in range(N_EVENTS):
                ci.inclusive[k] += (self.accumulated_events[k]
                                    - e.events_at_entry[k])

    # ------------------------------------------------------------------
    def check_branch_type(self, cur_pc: int) -> None:
        if self.last_pc == 0:
            return
        from_info = self.infos_.get(self.last_pc)
        to_info = self.infos_.get(cur_pc)
        if from_info is None or to_info is None:
            return

        from_func, to_func = from_info.func, to_info.func
        from_type, to_type = from_info.func_type, to_info.func_type

        # 1) assembly starting with "ret" -> RETURN
        if from_info.assembly.startswith("ret"):
            self.branchType = BT_RETURN
        # 2) helper -> non-helper: RETURN (jr t0 etc.)
        if isCompilerHelper(from_type):
            if not isCompilerHelper(to_type):
                self.branchType = BT_RETURN
                return
        # 3) rd==x0 jump within the same function: switch, not tail call
        if self.branchType == BT_TAIL_CALL and from_func == to_func:
            self.branchType = BT_INDIRECT_JUMP
            return
        # 4) landing in the stack-top caller's function: RETURN (healing)
        if from_func != to_func and self.call_stack:
            stack_top = self.call_stack[-1]
            caller_info = self.infos_.get(stack_top.caller_pc)
            if caller_info is not None:
                if to_func == caller_info.func:
                    self.branchType = BT_RETURN
                    return

    # ------------------------------------------------------------------
    def handler_branch(self, cur_pc: int) -> None:
        if self.branchType == BT_NONE:
            return

        from_info = self.infos_.get(self.last_pc)
        to_info = self.infos_.get(cur_pc)
        from_func = from_info.func if from_info is not None else "unknown"
        to_func = to_info.func if to_info is not None else "unknown"
        from_type = from_info.func_type if from_info is not None \
            else FT_NORMAL
        to_type = to_info.func_type if to_info is not None else FT_NORMAL

        if self.branchType == BT_CALL:
            original_from_pc = self.last_pc
            original_from_func = from_func
            used_real_caller = False

            if isCompilerHelper(from_type):
                if isSaveHelper(from_type) and self.real_caller_func:
                    self.last_pc = self.real_caller_pc
                    from_func = self.real_caller_func
                    used_real_caller = True
                else:
                    return
            if isSaveHelper(to_type) and not used_real_caller:
                self.real_caller_pc = original_from_pc
                self.real_caller_func = original_from_func

            entry = CallStackEntry()
            entry.caller_pc = self.last_pc
            entry.callee_pc = cur_pc
            entry.caller_func = from_func
            entry.callee_func = to_func
            entry.is_tail_call = False
            entry.events_at_entry = list(self.accumulated_events)
            self.call_stack.append(entry)
            parent = (" | under " + self.call_stack[-2].callee_func
                      if len(self.call_stack) >= 2 else "")
            self._root("push", self.last_pc, cur_pc, "CALL" + parent,
                       len(self.call_stack))

            self.calls[self.last_pc][cur_pc].count += 1

            if used_real_caller:
                self.real_caller_pc = 0
                self.real_caller_func = ""

        elif self.branchType == BT_TAIL_CALL:
            if isCompilerHelper(from_type):
                return
            self.calls[self.last_pc][cur_pc].count += 1
            if not self.call_stack:
                # ADAPTER A9 (NOT in the reference): the reference
                # records COUNT ONLY for a tail call on an empty stack
                # -- so an ISR handler that dispatches its workers with
                # `j` (tail) on a fresh ISR-local stack loses every
                # callee's inclusive, permanently (the reported
                # ISR_A -> FUNC_A/FUNC_B tail-noframe signature after
                # an A4 forced re-entry).  Synthesize the frame instead:
                # inclusive accrues, the callee's return pops it via
                # rule 4 (landing in the caller's function), and the
                # ISR-exit drain flushes it otherwise.
                self.n_tail_frames += 1
                self._root("tail-frame", self.last_pc, cur_pc,
                           "empty stack: frame SYNTHESIZED (A9; the "
                           "reference records count-only here and the "
                           "callee's inclusive would be lost)", 1)
            else:
                parent = " | under " + self.call_stack[-1].callee_func
                self._root("push", self.last_pc, cur_pc, "TAIL" + parent,
                           len(self.call_stack) + 1)
            tail_entry = CallStackEntry()
            tail_entry.caller_pc = self.last_pc
            tail_entry.callee_pc = cur_pc
            tail_entry.caller_func = from_func
            tail_entry.callee_func = to_func
            tail_entry.is_tail_call = True
            tail_entry.events_at_entry = list(self.accumulated_events)
            self.call_stack.append(tail_entry)

        elif self.branchType == BT_RETURN:
            if self.call_stack:
                top = self.call_stack[-1]
                # ADAPTER A5a (NOT in the reference): a return can never
                # land INSIDE the function whose frame it closes -- the
                # only architectural way is self-recursion (callee ==
                # caller, exempted).  The reference pops top blindly, so
                # a MISSING intermediate frame (helper swallowed by a
                # missed ISR entry, untracked entry, ...) makes it pop
                # the ENCLOSING function's frame while that function is
                # still running: the t=145-style early pop that seeds
                # the whole depth collapse.  Skip and count instead.
                if (to_info is not None
                        and to_func == top.callee_func
                        and top.callee_func != top.caller_func
                        and from_func != to_func):
                    self.n_return_guard += 1
                    self._root("return-guard", top.caller_pc,
                               top.callee_pc,
                               f"RETURN landing 0x{cur_pc:x} is inside "
                               f"this frame's callee -- pop skipped "
                               f"(A5a, frame kept open)",
                               len(self.call_stack))
                    return
                self._root("pop", top.caller_pc, top.callee_pc,
                           f"RETURN landing 0x{cur_pc:x}",
                           len(self.call_stack))
                entry = self.call_stack.pop()
                call_info = self.calls[entry.caller_pc][entry.callee_pc]
                for i in range(N_EVENTS):
                    call_info.inclusive[i] += (
                        self.accumulated_events[i] -
                        entry.events_at_entry[i])
                # ADAPTER A5b (NOT in the reference): the tail-chain
                # while must never pop a frame whose CALLEE the landing
                # pc is still inside -- the flow is demonstrably
                # executing that frame's callee, so the "return through
                # the chain" reading is disproven at that frame.  With
                # an upstream frame already lost, the reference pops
                # straight through here: exactly how one lost
                # SYS_initialize frame let restore's `jr t0` (landing
                # INSIDE SYS_system_startup) pop (BSP_reset->startup)
                # and (_start->BSP_reset), emptying the root chain and
                # restarting the stack at depth 1.  Stale non-tail
                # frames are still late-flushed as in the reference
                # (the documented jal-ra-restore quirk is untouched).
                while entry.is_tail_call and self.call_stack:
                    nxt = self.call_stack[-1]
                    if to_info is not None and nxt.callee_func == to_func:
                        self.n_chain_guard += 1
                        self._root("chain-guard", nxt.caller_pc,
                                   nxt.callee_pc,
                                   f"tail-chain stopped: landing "
                                   f"0x{cur_pc:x} is inside this "
                                   f"frame's callee (A5b, frame kept "
                                   f"open)",
                                   len(self.call_stack))
                        break
                    self._root("pop", nxt.caller_pc, nxt.callee_pc,
                               "tail-chain pop (RETURN through tail)",
                               len(self.call_stack))
                    entry = self.call_stack.pop()
                    tail_call = self.calls[entry.caller_pc][entry.callee_pc]
                    for i in range(N_EVENTS):
                        tail_call.inclusive[i] += (
                            self.accumulated_events[i] -
                            entry.events_at_entry[i])

        elif self.branchType == BT_BRANCH:
            branch = self.branches[self.last_pc]
            branch.total_executed += 1
            if self.last_branch_taken:
                branch.taken_target = cur_pc
                branch.taken_count += 1
            else:
                branch.not_taken_target = cur_pc

        elif self.branchType in (BT_DIRECT_JUMP, BT_INDIRECT_JUMP):
            if isCompilerHelper(from_type):
                return
            self.jumps[self.last_pc][cur_pc] += 1

    # ------------------------------------------------------------------
    def remain_call_stack_process(self) -> None:
        # (isr_call_stack in the reference == frames of still-open ISR
        # contexts; here every stack in the of-stack pile plus the
        # active one drains identically)
        while self.isr_stack:
            while self.call_stack:
                entry = self.call_stack.pop()
                call_info = self.calls[entry.caller_pc][entry.callee_pc]
                for i in range(N_EVENTS):
                    call_info.inclusive[i] += (
                        self.accumulated_events[i] -
                        entry.events_at_entry[i])
            self.isr_stack.pop()
            if self.isr_call_stack_of_stack:
                self.call_stack = self.isr_call_stack_of_stack.pop()
            else:
                self.call_stack = self.normal_stack
        while self.normal_stack:
            entry = self.normal_stack.pop()
            call_info = self.calls[entry.caller_pc][entry.callee_pc]
            for i in range(N_EVENTS):
                call_info.inclusive[i] += (
                    self.accumulated_events[i] - entry.events_at_entry[i])


# ----------------------------------------------------------------------
# Feeder: waveform commit stream -> update_profile() calls
# ----------------------------------------------------------------------

def _update_profile(p: SimProfiler, binary: BinaryInfo, classifier,
                    pc: int, epc: Optional[int], cyc_delta: int,
                    next_pc: Optional[int],
                    static_cache: Dict[int, Tuple],
                    force_epc: bool = False) -> None:
    """One committed instruction, in the reference's exact call order."""
    if epc is not None:                       # ADAPTER A3
        p.update_epc(epc, pc, force=force_epc)
    p.update(pc, TRACE_IR, 1)
    p.update(pc, TRACE_Cy_direct, cyc_delta)

    st = static_cache.get(pc)
    if st is None:
        insn = binary.insns.get(pc)
        cls = classifier.classify(insn) if insn else None
        tgt = None
        if cls is not None and (cls.is_cond_branch or cls.is_jump) \
                and not cls.is_indirect:
            tgt = direct_target(insn)
        st = (insn, cls, tgt,
              pc + insn.size if insn is not None else pc)
        static_cache[pc] = st
    insn, cls = st[0], st[1]
    if insn is None:
        return

    if insn.mnemonic == "auipc":
        # v0.20.9 simulator parity: the reference counts every auipc
        # commit as Bi+1 and Bim+1.  Rationale: macro-fused auipc+jalr
        # pairs commit as ONE instruction at the auipc's pc, so the
        # hidden indirect-jump half's branch events are attributed to
        # the auipc.  (Semantic caveat, kept for diff parity: a
        # standalone address-forming auipc gets counted too.)
        p.update(pc, TRACE_Bi, 1)
        p.update(pc, TRACE_Bim, 1)
    if cls.is_cond_branch:                    # Group::BRANCH
        p.update(pc, TRACE_Bc, 1)
        # ADAPTER A1: taken from the next committed pc vs static npc
        taken = next_pc is not None and next_pc != pc + insn.size
        p.update_branch(pc, BT_BRANCH, taken)
    if cls.is_jump:                           # Group::JUMP
        p.update(pc, TRACE_Bi, 1)
        p.update(pc, TRACE_Bim, 1)
        if cls.writes_link:                   # Group::CALL (rd in {ra,t0})
            p.update_branch(pc, BT_CALL)
        elif True:                            # rd == x0 (all non-link jumps)
            p.update_branch(pc, BT_TAIL_CALL)
    if cls.is_load:
        p.update(pc, TRACE_Dr, 1)
    if cls.is_store:
        p.update(pc, TRACE_Dw, 1)


def run_sim(pc_stream, binary: BinaryInfo, classifier,
            trace_roots: int = 0, debug_funcs=None) -> Profile:
    """Run the transcribed engine over (tick, pc[, epc]) samples and
    return a legacy-shaped Profile for the shared callgrind writer.
    (--no-isr-clamp is not supported: the reference has no such switch.)
    """
    p = SimProfiler(binary)
    static_cache: Dict[int, Tuple] = {}
    if trace_roots:
        p.root_log = {"n": {}, "ev": [], "depth": int(trace_roots)}
    if debug_funcs:
        p.debug_funcs = set(debug_funcs)
        p.func_log = {"ev": [], "omitted": 0}

    prev: Optional[Tuple] = None              # (pc, epc, cyc_delta)
    last_fed = None                           # (cls, target, fallthrough)
    prev_tick: Optional[int] = None
    prev_pc: Optional[int] = None
    epc_seen = False
    n = 0

    for sample in pc_stream:
        tick, pc = sample[0], sample[1]
        epc = sample[2] if len(sample) > 2 else None
        if pc == prev_pc:
            continue                          # hold: same commit
        if epc is not None and not epc_seen:
            epc_seen = True
            if n == 0:
                # ADAPTER A2: defined at the very first commit ->
                # baseline (ISS starts with prev_epc == mepc); defined
                # LATER (x -> value) -> first trap, so keep prev_epc=0
                # and let update_epc fire
                p.prev_epc = epc
        delta = 1 if prev_tick is None else max(1, tick - prev_tick)
        cur = (pc, epc, delta)
        if prev is not None:
            p.cur_tick = prev_tick
            # ADAPTER A4: same-mepc re-entry -- the commit BEFORE the
            # one being fed supplies the interrupted context; if the
            # fed commit is an unexplained discontinuity whose source's
            # successor equals the (unchanged) mepc, it is an interrupt
            # entry the reference's change detection cannot see.
            force = False
            if prev[1] is not None and prev[1] == p.prev_epc \
                    and last_fed is not None:
                l_cls, l_tgt, l_ft = last_fed
                if l_cls is not None and not l_cls.is_indirect \
                        and not l_cls.is_return \
                        and prev[0] != l_ft \
                        and (l_tgt is None or prev[0] != l_tgt) \
                        and prev[0] != prev[1] \
                        and (prev[1] == l_ft or
                             (l_tgt is not None and prev[1] == l_tgt)):
                    force = True
            _update_profile(p, binary, classifier,
                            prev[0], prev[1], prev[2], pc,
                            static_cache, force_epc=force)   # A1: one behind
            st = static_cache.get(prev[0])
            last_fed = (st[1], st[2], st[3]) \
                if st is not None and st[0] is not None else None
        prev = cur
        prev_tick = tick
        prev_pc = pc
        n += 1
    if prev is not None:
        p.cur_tick = prev_tick
        _update_profile(p, binary, classifier,
                        prev[0], prev[1], prev[2], None, static_cache)
    p.remain_call_stack_process()

    return _to_profile(p, binary, epc_seen)


def _to_profile(p: SimProfiler, binary: BinaryInfo, epc_seen: bool) -> Profile:
    prof = Profile(binary)
    for pc, info in p.infos_.items():
        if any(info.event):
            prof.self_cost[pc] = list(info.event)
    prof.total = list(p.accumulated_events)
    for caller, m in p.calls.items():
        for callee, ci in m.items():
            cs = prof.calls[(caller, callee)]
            cs.count = ci.count
            cs.inclusive = list(ci.inclusive)
    # jcnd/jump lines from the sim's own branch/jump records
    for src, br in p.branches.items():
        if br.taken_count and br.taken_target is not None:
            prof.cond_jumps[(src, br.taken_target)] = br.taken_count
        nt = br.total_executed - br.taken_count
        if nt and br.not_taken_target is not None:
            prof.cond_jumps[(src, br.not_taken_target)] = nt
    for src, m in p.jumps.items():
        for dst, cnt in m.items():
            prof.uncond_jumps[(src, dst)] = cnt

    prof.epc_mode = epc_seen
    prof.isr_kind = "epc" if prof.epc_mode else None
    prof.exceptions = p.n_isr_entries
    prof.spurious_epc = p.n_spurious
    prof.isr_open = len(p.isr_stack)
    prof.sim_dropped_unknown = p.dropped_unknown_pc
    prof.root_log = p.root_log
    prof.isr_exits = p.n_isr_exits
    prof.max_exit_drain = p.max_exit_drain
    prof.guarded_unwinds = p.n_return_guard + p.n_chain_guard
    prof.return_guards = p.n_return_guard
    prof.chain_guards = p.n_chain_guard
    prof.discontinuity_returns = p.n_disc_returns
    prof.exit_rejects = p.n_exit_rejects
    prof.epc_rewrites = p.n_epc_rewrites
    prof.tail_frames = p.n_tail_frames
    prof.func_log = p.func_log
    return prof


# ----------------------------------------------------------------------
# Engine comparison (--engine both)
# ----------------------------------------------------------------------

def compare_profiles(sim: Profile, legacy: Profile, binary: BinaryInfo,
                     top: int = 12):
    """Structured diff between the two engines over the same stream."""
    out = {"total": {}, "self": [], "arcs": []}
    for i, name in enumerate(EVENTS):
        a, b = sim.total[i], legacy.total[i]
        if a != b:
            out["total"][name] = (a, b)

    fs_self: Dict[int, List[int]] = {}
    for src in (sim, legacy):
        pass
    def per_func(prof):
        d: Dict[int, List[int]] = {}
        for pc, ev in prof.self_cost.items():
            f = binary.func_at(pc)
            if f is None:
                continue
            acc = d.setdefault(f.start, [0] * N_EVENTS)
            for i in range(N_EVENTS):
                acc[i] += ev[i]
        return d
    a_self, b_self = per_func(sim), per_func(legacy)
    for fs in set(a_self) | set(b_self):
        a = a_self.get(fs, [0] * N_EVENTS)
        b = b_self.get(fs, [0] * N_EVENTS)
        if a != b:
            f = binary.func_at(fs)
            out["self"].append((f.name if f else hex(fs),
                                a[E_IR] - b[E_IR], a[E_CY] - b[E_CY]))
    out["self"].sort(key=lambda r: -abs(r[2]))
    out["self"] = out["self"][:top]

    keys = set(sim.calls) | set(legacy.calls)
    for k in keys:
        a = sim.calls.get(k)
        b = legacy.calls.get(k)
        an, acy = (a.count, a.inclusive[E_CY]) if a else (0, 0)
        bn, bcy = (b.count, b.inclusive[E_CY]) if b else (0, 0)
        if an != bn or acy != bcy:
            cf = binary.func_at(k[0])
            tf = binary.func_at(k[1])
            out["arcs"].append((f"{cf.name if cf else hex(k[0])}"
                                f"->{tf.name if tf else hex(k[1])}",
                                an - bn, acy - bcy))
    out["arcs"].sort(key=lambda r: (-abs(r[2]), -abs(r[1])))
    out["arcs"] = out["arcs"][:top]
    return out
