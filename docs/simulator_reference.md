# Simulator Profiler Reference (사용자 제공 수도코드 정리본)

> 대화 중 사용자가 수기로 타이핑해 공유한 자체 simulator의 callgrind
> 생성 알고리즘. WaveScope가 이 의미론에 수렴하도록 개발 중이므로 비교
> 기준(reference)이 된다. 원문의 확인된 오타는 교정하고 주석으로 표시.
> (교정 근거: 사용자가 대화에서 직접 확인해준 항목)
>
> 확인된 오타 교정 목록:
> - `is_wfi = false` → `is_wfi == false` (대입→비교; 원본 코드는 정상)
> - `entry.is_tail_call & !empty` → `&&` (원본 정상)
> - `pec_error_check` ↔ `epc_error_check` 혼용 → 같은 변수, epc_error_check로 통일
> - `form_it`/`to_ti`/`issuued` 등 단순 타이포 정리
> - `last_stack.push(isrInfo)` → `isr_stack.push(isrInfo)` 로 추정 (update()에서
>   isr_stack.top()을 읽으므로)
>
> 실제 버그 후보로 사용자가 인정한 것:
> - update_epc 첫 조건의 `infos_[pc]` — contains 체크 없이 operator[] 접근
>   (pc 미존재 시 빈 엔트리 삽입/nullptr 역참조 위험)

## 전제

- 매 committed instruction마다 `update_profile()` 호출
- `infos_`: 전체 text의 pc → {event[], debug_info(func/assembly), func_type}
  - func_type: 이름이 `__riscv_save*`면 SAVE_HELPER, `__riscv_restore*`면
    RESTORE_HELPER, 그 외 NORMAL
- link register 정의: `static constexpr array<size_t,2> lr_ = {1, 5};` (x1=ra, x5=t0)
- CALL 분류: `c.jal`/`c.jalr` → true, `c.jr` → false,
  `jal`/`jalr` → `ranges::of(lr_).any([&](auto reg){ return insn.rd() == reg; })`
- TAIL_CALL 1차 분류: jump이면서 `dests().size() > 0 && dest(0) == 0` (rd == x0)
- Bcm: `issued.branch->taken != taken` — **prediction 비교 (misprediction)**.
  taken 자체는 `accessor.npc() != decode.npc(pc)`로 architectural 판정.

## update_profile()

```cpp
void update_profile() {
  auto pc = issued.pc;
  auto& decode = issued.decode.get();
  auto& profiler = get_profiler();

  const int PRIV_M = 3;
  profiler.update_epc(accessor.state().epc[PRIV_M], pc);   // mepc
  profiler.update(pc, TRACE_IR, 1);

  auto cur_cycle = clock.get_cycles();
  profiler.update(pc, TRACE_Cy_direct, cur_cycle - last_committed_cycle_);
  last_committed_cycle_ = cur_cycle;

  if (decode.belong_to(Group::BRANCH)) {
    profiler.update(pc, TRACE_Bc, 1);
    auto taken = accessor.npc() != decode.npc(pc);
    if (issued.branch->taken != taken) {           // 예측 vs 실제
      profiler.update(pc, TRACE_Bcm, 1);
    }
    profiler.update_branch(pc, BranchType::BRANCH, taken);
  }
  if (decode.belong_to(Group::JUMP)) {
    profiler.update(pc, TRACE_Bi, 1);
    profiler.update(pc, TRACE_Bim, 1);
    if (decode.belong_to(Group::CALL)) {
      profiler.update_branch(pc, BranchType::CALL);
    } else if (decode.dests().size() > 0 && decode.dest(0) == 0) {
      profiler.update_branch(pc, BranchType::TAIL_CALL);
    } else if (decode.belong_to(Group::INDIRECT_JUMP)) {
      profiler.update_branch(pc, BranchType::INDIRECT_JUMP);
    } else if (decode.belong_to(Group::DIRECT_JUMP)) {
      profiler.update_branch(pc, BranchType::DIRECT_JUMP);
    }
  }
  if (decode.belong_to(Group::LOAD))  profiler.update(pc, TRACE_Dr, 1);
  if (decode.belong_to(Group::STORE)) profiler.update(pc, TRACE_Dw, 1);
}
```

## update_epc() — 인터럽트/예외 진입 감지 (mepc CSR 변화)

```cpp
void update_epc(uint32_t epc, uint32_t pc) {
  if ((prev_epc != epc) ||
      (is_wfi && after_wfi && (wfi_func != infos_[pc].debug_info->func))) {
      // ^ 버그 후보: infos_.contains(pc) 체크 필요

    if (epc_error_check == true) return;

    // 같은 함수 내 epc 변화는 스퓨리어스로 간주
    if ((prev_epc != epc) && (infos_.contains(epc) && infos_.contains(pc)) &&
        (infos_[epc].debug_info->func == infos_[pc].debug_info->func)) {
      epc_error_check = true;
      return;
    }

    after_wfi = false;
    prev_epc = epc;
    is_isr = true;

    // 현재 call stack을 대피시키고 ISR용 새 stack 생성 (중첩 지원)
    if (!isr_stack.empty()) {
      isr_call_stack_of_stack.push(call_stack);
    }
    call_stack = new std::stack<CallStackEntry>();

    IsrInfo isrInfo;
    isrInfo.epc              = epc;
    isrInfo.last_pc          = last_pc;
    isrInfo.branchType       = branchType;
    isrInfo.last_was_branch  = last_was_branch;
    isrInfo.last_branch_taken = last_branch_taken;
    isr_stack.push(isrInfo);

    last_was_branch = false;
    first_isr_cycle = true;
  }
}
```

## update() — 이벤트 누적 + ISR 복귀 감지

```cpp
void update(uint32_t base, uint32_t event, uint32_t count) {
  if (!enabled_) return;
  if (!infos_.contains(base)) return;
  auto& info = infos_[base];

  // ISR 복귀: 현재 pc가 대피해둔 epc와 일치
  if (is_isr && (isr_stack.top().epc == base)) {
    last_pc           = isr_stack.top().last_pc;
    branchType        = isr_stack.top().branchType;
    last_was_branch   = isr_stack.top().last_was_branch;
    last_branch_taken = isr_stack.top().last_branch_taken;
    prev_epc          = isr_stack.top().epc;
    epc_error_check   = false;

    // ISR 내부에서 열렸던 call frame 전부 flush
    CallStackEntry entry;
    while (!call_stack->empty()) {
      entry = call_stack->top();
      auto& call_info = calls[entry.caller_pc][entry.callee_pc];
      for (size_t i = 0; i < TRACE_END; i++) {
        call_info.inclusive_events[i] +=
            (accumulated_events[i] - entry.events_at_entry[i]);
      }
      call_stack->pop();
    }
    isr_stack.pop();

    if (isr_stack.empty()) {
      is_isr = false;
      delete call_stack;
      call_stack = &normal_stack;
    } else {
      delete call_stack;
      call_stack = isr_call_stack_of_stack.top();
      isr_call_stack_of_stack.pop();
      prev_epc = isr_stack.top().epc;
    }
  }

  // 직전 instruction이 branch였다면 이번 pc(=착지점)로 유형 확정 + 처리
  if (last_pc != 0 && last_was_branch) {
    check_branch_type(base);
    handler_branch(base);
    last_was_branch = false;
  }

  if (event == TRACE_Cy) {                 // legacy 경로 (현재 미사용)
    if (prev_cycles_ != 0) {
      if (first_isr_cycle) {
        info.event[TRACE_Cy] += 1;
        accumulated_events[TRACE_Cy] += 1;
        first_isr_cycle = false;
      } else {
        info.event[event] += (count - prev_cycles_);
        accumulated_events[event] += (count - prev_cycles_);
      }
      prev_cycles_ = count;
    } else {
      prev_cycles_ = count;
    }
  } else if (event == TRACE_Cy_direct) {
    if (first_isr_cycle) {                 // ISR 첫 insn: sleep gap을 1로 clamp
      count = 1;
      first_isr_cycle = false;
    }
    info.event[TRACE_Cy] += count;
    accumulated_events[TRACE_Cy] += count;
    wfi_in_handler(info);
  } else if (event == TRACE_IR) {
    wfi_out_handler(info, base);
    cur_insn_ = base;
    info.event[event] += count;
    accumulated_events[event] += count;
  } else {
    info.event[event] += count;
    accumulated_events[event] += count;
  }

  last_func_name = info.debug_info->func;
}
```

## WFI 처리

```cpp
void wfi_in_handler(ProfileInfo& info) {
  if ((is_wfi == false) && (info.debug_info->assembly.find("wfi") == 0)) {
    wfi_func = info.debug_info->func;
    is_wfi = true;
    after_wfi = true;
  }
}

void wfi_out_handler(ProfileInfo& info, uint32_t cur_pc) {
  if ((is_wfi == true) && (info.debug_info->func == wfi_func)) {
    is_wfi = false;
  }
}
```

## update_branch() — branch 발생 기록 (다음 insn에서 착지점으로 확정)

```cpp
void update_branch(uint32_t base, BranchType event, bool taken = false) {
  last_pc = base;
  branchType = event;
  last_was_branch = true;
  last_branch_taken = taken;
}
```

## check_branch_type() — 착지점 기반 유형 재분류

```cpp
void check_branch_type(uint32_t cur_pc) {
  if (last_pc == 0) return;
  auto from_it = infos_.find(last_pc);
  auto to_it   = infos_.find(cur_pc);
  if (from_it == infos_.end() || to_it == infos_.end()) return;

  const std::string& from_func = from_it->second.debug_info->func;
  const std::string& to_func   = to_it->second.debug_info->func;
  const FunctionType from_type = from_it->second.func_type;
  const FunctionType to_type   = to_it->second.func_type;

  // 1) assembly가 "ret"로 시작하면 RETURN
  if (from_it->second.debug_info->assembly.find("ret") == 0) {
    branchType = BranchType::RETURN;
  }
  // 2) helper(save/restore)에서 non-helper로 나가면 RETURN (jr t0 등)
  if (isCompilerHelper(from_type)) {
    if (!isCompilerHelper(to_type)) {
      branchType = BranchType::RETURN;
      return;
    }
  }
  // 3) rd==x0 jump인데 같은 함수 안이면 tail call이 아니라 switch류
  //    (direct/indirect 혼재, 이 시점에 구분 곤란 → indirect로 고정)
  if ((branchType == BranchType::TAIL_CALL) && (from_func == to_func)) {
    branchType = BranchType::INDIRECT_JUMP;
    return;
  }
  // 4) stack top의 caller 함수로 착지하면 RETURN (healing)
  if ((from_func != to_func) && !call_stack->empty()) {
    const auto& stack_top = call_stack->top();
    auto caller_it = infos_.find(stack_top.caller_pc);
    if (caller_it != infos_.end()) {
      if (to_func == caller_it->second.debug_info->func) {
        branchType = BranchType::RETURN;
        return;
      }
    }
  }
}
```

## handler_branch() — 유형별 stack/arc 처리

```cpp
void handler_branch(uint32_t cur_pc) {
  if (branchType == BranchType::NONE) return;

  auto from_it = infos_.find(last_pc);
  auto to_it   = infos_.find(cur_pc);
  std::string from_func = (from_it != infos_.end())
      ? from_it->second.debug_info->func : "unknown";
  std::string to_func   = (to_it != infos_.end())
      ? to_it->second.debug_info->func : "unknown";
  FunctionType to_type   = (to_it != infos_.end())
      ? to_it->second.func_type : FunctionType::NORMAL;
  FunctionType from_type = (from_it != infos_.end())
      ? from_it->second.func_type : FunctionType::NORMAL;

  switch (branchType) {
  case BranchType::CALL: {
    uint64_t original_from_pc = last_pc;
    std::string original_from_func = from_func;
    bool used_real_caller = false;

    // helper 안에서 발생한 call: save helper라면 실제 caller로 치환
    if (isCompilerHelper(from_type)) {
      if (isSaveHelper(from_type) && !real_caller_func.empty()) {
        last_pc = real_caller_pc;
        from_func = real_caller_func;
        used_real_caller = true;
      } else {
        return;
      }
    }
    // save helper로의 call: 실제 caller(=이 함수)를 기억해둠
    if (isSaveHelper(to_type) && !used_real_caller) {
      real_caller_pc = original_from_pc;
      real_caller_func = original_from_func;
    }

    CallStackEntry entry;
    entry.caller_pc   = last_pc;
    entry.callee_pc   = cur_pc;
    entry.caller_func = from_func;
    entry.callee_func = to_func;
    entry.is_tail_call = false;
    std::copy(std::begin(accumulated_events), std::end(accumulated_events),
              std::begin(entry.events_at_entry));    // 스냅샷
    call_stack->push(entry);

    calls[last_pc][cur_pc].count++;

    if (used_real_caller) {
      real_caller_pc = 0;
      real_caller_func.clear();
    }
    break;
  }

  case BranchType::TAIL_CALL: {
    if (isCompilerHelper(from_type)) return;
    calls[last_pc][cur_pc].count++;
    if (!call_stack->empty()) {
      CallStackEntry tail_entry;
      tail_entry.caller_pc   = last_pc;
      tail_entry.callee_pc   = cur_pc;
      tail_entry.caller_func = from_func;
      tail_entry.callee_func = to_func;
      tail_entry.is_tail_call = true;
      std::copy(std::begin(accumulated_events), std::end(accumulated_events),
                std::begin(tail_entry.events_at_entry));
      call_stack->push(tail_entry);
    }
    break;
  }

  case BranchType::RETURN: {
    if (!call_stack->empty()) {
      auto entry = call_stack->top();
      call_stack->pop();
      auto& call_info = calls[entry.caller_pc][entry.callee_pc];
      for (size_t i = 0; i < TRACE_END; ++i) {
        call_info.inclusive_events[i] +=
            (accumulated_events[i] - entry.events_at_entry[i]);
      }
      // tail chain 연쇄 pop: tail frame이었으면 그 아래도 함께 닫는다
      while (entry.is_tail_call && !call_stack->empty()) {
        entry = call_stack->top();
        call_stack->pop();
        auto& tail_call = calls[entry.caller_pc][entry.callee_pc];
        for (size_t i = 0; i < TRACE_END; i++) {
          tail_call.inclusive_events[i] +=
              (accumulated_events[i] - entry.events_at_entry[i]);
        }
      }
    }
    break;
  }

  case BranchType::BRANCH: {
    auto& branch = branches[last_pc];
    branch.total_executed++;
    if (last_branch_taken) {
      branch.taken_target = cur_pc;
      branch.taken_count++;
    } else {
      branch.not_taken_target = cur_pc;
    }
    break;
  }

  case BranchType::DIRECT_JUMP:
  case BranchType::INDIRECT_JUMP: {
    if (isCompilerHelper(from_type)) return;
    jumps[last_pc][cur_pc]++;
    break;
  }

  default:
    break;
  }
}
```

## Helper 판별

```cpp
inline bool isSaveHelper(FunctionType t) const { return t == FunctionType::SAVE_HELPER; }
inline bool isRestoreHelper(FunctionType t) const { return t == FunctionType::RESTORE_HELPER; }
inline bool isCompilerHelper(FunctionType t) const { return t != FunctionType::NORMAL; }
// infos_ 구성 시: 함수명이 __riscv_save*면 SAVE_HELPER,
// __riscv_restore*면 RESTORE_HELPER, 그 외 NORMAL
```

## remain_call_stack_process() — 종료 시 stack drain

```cpp
void remain_call_stack_process() {
  while (!isr_call_stack.empty()) {
    auto& entry = isr_call_stack.top();
    auto& call_info = calls[entry.caller_pc][entry.callee_pc];
    for (size_t i = 0; i < TRACE_END; i++) {
      call_info.inclusive_events[i] +=
          (accumulated_events[i] - entry.events_at_entry[i]);
    }
    isr_call_stack.pop();
  }
  while (!normal_stack.empty()) {
    auto& entry = normal_stack.top();
    auto& call_info = calls[entry.caller_pc][entry.callee_pc];
    for (size_t i = 0; i < TRACE_END; i++) {
      call_info.inclusive_events[i] +=
          (accumulated_events[i] - entry.events_at_entry[i]);
    }
    normal_stack.pop();
  }
}
```

## WaveScope 대응 관계 요약

| Simulator | WaveScope (`wavescope/profiler.py`) |
|---|---|
| `accumulated_events[]` 전역 누적 | `Profile._update()` — stack 위 모든 frame의 `acc`에 가산 (스냅샷 차분과 동치) |
| push 시 `events_at_entry` 스냅샷 | frame 생성 시 `FrameCtx.acc = [0]*N` |
| RETURN pop: `accumulated − snapshot` 가산 | `_flush_call()` — `cs.inclusive += fr.acc` |
| RETURN의 tail 연쇄 while pop | `commit()` return 블록의 tail-chain walk + `_unwind_to()` |
| `calls[caller_pc][callee_pc]` | `Profile.calls[(call_pc, callee)]` (v0.6.0에서 일치시킴) |
| `Cy_direct = cur − last_committed` (현재 insn 귀속) | `pend_cycles = max(1, t_i − t_{i−1})` (v0.6.0에서 일치시킴) |
| `first_isr_cycle` → 1 clamp | ISR 진입 감지된 첫 handler insn의 `cycles = 1` |
| mepc CSR 변화로 ISR 감지 | **v0.8.0 `--epc`: 동일 (mepc signal parsing)**. PC-only일 땐 휴리스틱(도달 불가능한 successor, indirect 직후 감지 불가) fallback |
| update_epc의 같은 함수 epc 변화 → epc_error_check | `epc_suppressed` — 동일 (exit에서 해제) |
| is_wfi/after_wfi/wfi_func + wfi_in/out_handler | 동일 이식 (`step()`의 wfi tracking, mnemonic wfi/wfe) |
| IsrInfo에 last_pc/branchType/taken 대피, 복귀 후 재해석 | `IsrCtx.saved`에 `Pending`(미해결 직전 insn) 저장 → `pc == resume` commit에서 복원, 진짜 착지점으로 resolve — 동일 |
| `is_isr && isr_stack.top().epc == base` 복귀 | `pc == isr_ctxs[-1].resume` commit — 동일 |
| 중첩 exit 시 `prev_epc = isr_stack.top().epc` | 동일 (handler epilogue의 mepc 복원 가정 공유) |
| ISR stack-of-stack 대피 | 단일 stack + `IsrCtx(depth)` 마커 (exit 시 depth까지 unwind = handler 내 frame flush와 동치) |
| check_branch_type 4) caller 착지 → RETURN | unmatched ret healing (`resolve()` return 블록) |
| check_branch_type + handler_branch (착지점 확정 후 처리) | **v0.8.0: `Pending` + `resolve()` — 구조 자체를 일치시킴** |
| RETURN 시 무조건 top pop | ret_addr 정확 매칭 우선 + healing 보조 — **정책 차이, 미해결 이슈 6.1** |
| save helper real_caller 치환 | 미구현 — ret_addr 매칭으로 자연 해소된다고 보고 있으나 검증 필요 |
| remain_call_stack_process() | `run()` 말미 `_unwind_to(prof, stack, 0)` + 잔존 frame 진단 출력 |
| (해당 없음 — 시뮬레이터는 항상 정확) | epc 모드 한정 `flow_anomalies`: ISR로 설명 안 되는 불연속 = speculative PC 오염 진단 |
