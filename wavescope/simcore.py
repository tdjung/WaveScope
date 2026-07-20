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

from .disasm import BinaryInfo
from .profiler import (E_BC, E_BI, E_BIM, E_CY, E_DR, E_DW, E_IR, EVENTS,
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
        self.n_isr_entries = 0
        self.n_spurious = 0
        self.dropped_unknown_pc = 0

    def _root(self, kind, cp, callee, info, depth):
        log = self.root_log
        if log is None:
            return
        log["n"][kind] = log["n"].get(kind, 0) + 1
        if len(log["ev"]) < 40:
            log["ev"].append((self.cur_tick, kind, cp, callee, info,
                              depth, None))

    # -- QUIRK Q1: infos_[pc] with std::map operator[] semantics -------
    def _infos_bracket(self, pc: int) -> SimInfo:
        info = self.infos_.get(pc)
        if info is None:
            info = SimInfo()                  # default-constructed entry
            self.infos_[pc] = info            # inserted into the map!
        return info

    # ------------------------------------------------------------------
    def update_epc(self, epc: int, pc: int) -> None:
        if (self.prev_epc != epc) or \
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

            self.after_wfi = False
            self.prev_epc = epc
            self.is_isr = True
            self.n_isr_entries += 1

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

    # ------------------------------------------------------------------
    def update(self, base: int, event: int, count: int) -> None:
        if not self.enabled_:
            return
        if base not in self.infos_:
            self.dropped_unknown_pc += 1
            return
        info = self.infos_[base]

        # ISR return: current pc equals the saved epc
        if self.is_isr and self.isr_stack[-1].epc == base:
            top = self.isr_stack[-1]
            self.last_pc = top.last_pc
            self.branchType = top.branchType
            self.last_was_branch = top.last_was_branch
            self.last_branch_taken = top.last_branch_taken
            self.prev_epc = top.epc
            self.epc_error_check = False

            while self.call_stack:
                entry = self.call_stack[-1]
                call_info = self.calls[entry.caller_pc][entry.callee_pc]
                for i in range(N_EVENTS):
                    call_info.inclusive[i] += (
                        self.accumulated_events[i] -
                        entry.events_at_entry[i])
                self.call_stack.pop()
            self.isr_stack.pop()

            if not self.isr_stack:
                self.is_isr = False
                self.call_stack = self.normal_stack
            else:
                self.call_stack = self.isr_call_stack_of_stack.pop()
                self.prev_epc = self.isr_stack[-1].epc

        # previous instruction was a branch: settle it with this landing
        if self.last_pc != 0 and self.last_was_branch:
            self.check_branch_type(base)
            self.handler_branch(base)
            self.last_was_branch = False

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
            self._root("push", self.last_pc, cur_pc, "CALL",
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
                self._root("tail-noframe", self.last_pc, cur_pc,
                           "empty stack: count only, NO inclusive "
                           "(reference semantics)", 0)
            if self.call_stack:
                self._root("push", self.last_pc, cur_pc, "TAIL",
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
                if len(self.call_stack) <= 3:
                    top = self.call_stack[-1]
                    self._root("pop", top.caller_pc, top.callee_pc,
                               f"RETURN landing 0x{cur_pc:x}",
                               len(self.call_stack))
                entry = self.call_stack.pop()
                call_info = self.calls[entry.caller_pc][entry.callee_pc]
                for i in range(N_EVENTS):
                    call_info.inclusive[i] += (
                        self.accumulated_events[i] -
                        entry.events_at_entry[i])
                while entry.is_tail_call and self.call_stack:
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
                    static_cache: Dict[int, Tuple]) -> None:
    """One committed instruction, in the reference's exact call order."""
    if epc is not None:                       # ADAPTER A3
        p.update_epc(epc, pc)
    p.update(pc, TRACE_IR, 1)
    p.update(pc, TRACE_Cy_direct, cyc_delta)

    st = static_cache.get(pc)
    if st is None:
        insn = binary.insns.get(pc)
        st = (insn, classifier.classify(insn) if insn else None)
        static_cache[pc] = st
    insn, cls = st
    if insn is None:
        return

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
            trace_roots: bool = False) -> Profile:
    """Run the transcribed engine over (tick, pc[, epc]) samples and
    return a legacy-shaped Profile for the shared callgrind writer.
    (--no-isr-clamp is not supported: the reference has no such switch.)
    """
    p = SimProfiler(binary)
    static_cache: Dict[int, Tuple] = {}
    if trace_roots:
        p.root_log = {"n": {}, "ev": []}

    prev: Optional[Tuple] = None              # (pc, epc, cyc_delta)
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
            if trace_roots:
                p.cur_tick = prev_tick
            _update_profile(p, binary, classifier,
                            prev[0], prev[1], prev[2], pc,
                            static_cache)                    # A1: one behind
        prev = cur
        prev_tick = tick
        prev_pc = pc
        n += 1
    if prev is not None:
        if trace_roots:
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
