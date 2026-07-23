# WaveScope — Project Notes (대화 인수인계용)

> 새 대화 시작 시: 이 파일과 README.md를 먼저 읽고 이어서 작업.
> 마지막 업데이트: 2026-07-23, v0.20.11

## 1. 프로젝트 개요

RTL/simulator waveform(VCD/FSDB)에서 PC signal을 추출하고 ELF debug
symbol과 결합해 **callgrind format 프로파일**을 생성하는 Linux CLI 툴.
사용자는 기존에 자체 simulator에 내장된 update_profile() 기반 callgrind
생성기를 보유 — WaveScope의 출력을 그 결과와 비교하며 수렴시키는 중.

- 레포: github.com/tdjung/WaveScope (Python ≥3.6, 의존성 완전 제로 —
  오프라인 환경에서 clone만으로 `python3 -m wavescope.cli` 직접 실행
  가능. 구형 pip 9용 setup.py 병행 유지 — v0.6.3)
- 참조 구현: 사용자의 simulator profiler (C++, 대화에서 수도코드로 공유받음)
- UI: 별도 레포 MoveMyCode/profiler_web_prj (Electron+Next.js callgrind
  뷰어)와 연동 예정. WaveScope는 CLI 생성기로 유지하기로 결정.
- 대상: RISC-V (현재 검증 중, e24 계열 core), ARM Cortex-M/AArch64 (준비됨)
- 사용자 환경: 대규모 FW를 돌리는 simulator가 VCD를 dump (clock signal
  없음, gzip 아닌 미지의 바이너리 → 자동 변환기 경로로 처리됨).
  FW는 -msave-restore millicode, C++ 심볼, WFI+인터럽트 사용.

## 2. 아키텍처

```
wavescope/
├── isa/                # ISA 지식은 전부 JSON 데이터 (코드와 분리)
│   ├── riscv.json      # link regs = {ra,x1,x5,t0} — 시뮬레이터 lr_={1,5}와 일치 확인됨
│   ├── armv7m.json     # Thumb-2: cond suffix, pc-write 규칙
│   └── aarch64.json
├── classify.py         # JSON 테이블 해석 엔진. --isa-ext overlay로
│                       #   custom instruction (mnemonic + encoding mask/match)
├── disasm.py           # objdump -d -C / -t / addr2line 파싱
│                       #   - 함수 universe = objdump -d 라벨 ∪ F-symbol
│                       #   - 같은 주소 alias(save_4..7) 병합, objdump 라벨을 canonical name으로
│                       #   - strip_params(): demangle된 이름에서 인자 제거
│                       #   - direct_target(): direct branch/jump의 목적지 파싱
├── vcd_reader.py       # 의존성 없는 VCD 파서
│                       #   - open_vcd_text(): gzip/bz2/xz 투명 해제, FST/LXT2/VZT는
│                       #     fst2vcd/lxt2vcd/vzt2vcd 자동 변환
│                       #   - 방언 대응: 탭 구분, real 값, pc[31:0] 붙은 이름
│                       #   - clockless: iter_pc_changes + changes_to_ticks
│                       #     (period = delta GCD, tick = 정수 round-half-up)
│                       #   - multi-signal (v0.8.0): iter_commit_changes /
│                       #     iter_samples_multi — PC commit마다 aux signal
│                       #     (mepc 등) 현재값 부착. clockless는 timestamp 끝
│                       #     기준으로 aux 확정 (같은 cycle의 trap CSR write가
│                       #     첫 handler insn sample에 보이도록 — 시뮬레이터가
│                       #     commit 시점에 CSR 읽는 것과 동일). changes_to_ticks는
│                       #     (t, v, *aux) 튜플 투과
├── fsdb.py             # Verdi fsdbreport(신호별 추출 우선) / fsdb2vcd(--fsdb-scope)
├── trn.py              # Cadence TRN/SHM → simvisdbutil로 VCD 변환 (v0.7.0, 실환경 미검증)
├── waveform.py         # 입력 디스패치 (vcd/fsdb, clocked/clockless)
├── scan.py             # PC/clock signal 후보 랭킹 (ELF text range 매칭 0.55
│                       #   + stride + 이름 + 폭). --json, --explain, signals 서브커맨드
│                       #   + epc 후보 랭킹 (v0.8.0: 이름에 epc 토큰 필수,
│                       #     MIN_CHANGES 게이트 없음 — trap은 드물어서)
├── profiler.py         # ★ 핵심. 아래 3절 참조
├── callgrind.py        # writer. calls 키 = (call_pc, callee) 순수 PC.
│                       #   기본으로 ELF 전 함수 emit (미실행은 zero-cost, coverage용)
└── cli.py              # 서브커맨드: scan / signals / profile
```

CLI 예시:
```sh
wavescope profile --wave all.vcd --elf fw.elf \
  --pc blk_cpu.riscve24.core.issued.pc \
  --epc blk_cpu.riscve24.core.csr.mepc \
  --isa riscv --toolchain-prefix riscv64-unknown-elf- -o callgrind.out
# clock signal 불필요 (clockless 모드), --clock-period로 override 가능
# --epc는 선택 (없으면 휴리스틱 ISR 감지). 사용자에게 mepc dump 추가 요청 필요.
```

## 3. profiler.py 핵심 의미론 (시뮬레이터와 맞춘 것들)

- **이벤트 (8개, v0.10.0)**: Ir Cy Bc Bcm Bi Bim Dr Dw.
  Call/TailCall 컬럼은 v0.6.0에, IndJmp/DirJmp 컬럼은 v0.10.0에 사용자
  요청으로 제거. call은 frame/calls map, 점프 흐름은 cond_jumps/
  uncond_jumps (src,dst) arc로 구조적으로 유지.
- **Cycle attribution (v0.6.0)**: `cycles(pc_i) = max(1, t_i − t_{i−1})` —
  **도착한 instruction이 gap을 문다** (시뮬레이터의 cur−last_committed와 동일).
  이전엔 직전 instruction에 청구해서 stall이 한 칸 밀렸었음.
  floor는 지역적(local)이며 이월(carry) 없음 — v0.5.0의 보존형 carry는
  burst 구간의 빚이 실제 stall을 먹어버려서 폐기(v0.5.1).
- **taken 판정**: direct 전이는 objdump operand에서 target 파싱 →
  `next_pc == target`. Bcm = taken count (※ 시뮬레이터 Bcm은 misprediction
  기반이라 정의가 다름 — 미해결 항목 6.2 참조).
- **calls 키**: `(call_pc, callee_pc)` — 시뮬레이터의
  calls[caller_pc][callee_pc]와 동일. 소속 함수는 write 시 func_at(call_pc).
- **tail call**: frame을 추가 push (부모 ret_addr 상속, is_tail=True).
  return 매칭 시 tail chain + anchor normal frame까지 연쇄 unwind →
  caller inclusive가 tail 연속 실행을 포함 (callgrind 의미론, 시뮬레이터와 동일).
- **fall-through 함수 전환**: jump 없이 다른 함수 entry로 넘어가면
  (millicode restore_8→_4→_0 체인 등) 암묵적 tail frame push. 이벤트는
  안 올림. leaf의 self==incoming inclusive 불변식 복구용.
- **loop closure**: backward edge가 asm 라벨(=함수 entry)로 재진입 시
  같은 entry의 tail frame이 이미 stack에 있으면 (위가 전부 tail일 때)
  그 위만 flush하고 재사용 — iteration마다 frame이 쌓여 inclusive가
  O(N²)로 폭발하던 것 방지 (_close_loop_if_reentry).
- **return 처리**: ① ret_addr 정확 매칭 (tail chain walk 포함) →
  ② healing: next_pc의 함수 == 어떤 frame의 caller 함수면 거기까지 unwind
  (시뮬레이터의 check_branch_type "to_func == caller func → RETURN" 대응) →
  ③ 그래도 없으면 unmatched 카운트만 하고 무시.
  ※ 시뮬레이터는 RETURN에서 무조건 top pop — 이 차이가 남은 불일치의
  후보임 (미해결 6.1).
- **profiler 구조 (v0.8.0 재편)**: 시뮬레이터 update()와 동일한
  per-instruction 파이프라인 — ① update_epc(진입) ② ISR exit ③ **pending
  resolution** (직전 insn의 successor 의존 처리: taken/Bcm 판정,
  call/tail/return stack ops = check_branch_type+handler_branch 대응)
  ④ 이벤트 청구 ⑤ pending 기록. pending 구조 덕에 ISR 진입 시 인터럽트된
  insn의 미해결 상태를 IsrInfo처럼 저장했다가 **복귀 후 진짜 착지점으로
  해석** — 인터럽트된 branch의 Bcm/call arc가 handler 주소로 오염되지 않음
  (epc 없이는 구조적으로 불가능했던 부분).
- **exception/ISR — epc 모드 (v0.8.0, --epc)**: 시뮬레이터 update_epc 이식.
  진입 = commit 시점 mepc 값 변화, + WFI-wake 규칙 (is_wfi && after_wfi &&
  착지 함수 ≠ wfi_func — 같은 wfi에서 연속 wake 시 mepc가 동일값으로
  재기록되는 케이스). 같은 함수 내 epc 변화는 스퓨리어스 억제
  (epc_error_check 대응, exit에서 해제). 복귀 = 저장한 epc 주소 commit
  (indirect jump 직후 인터럽트도 정확 — 휴리스틱의 원리적 한계 해소).
  중첩 지원 (exit 시 prev_epc = 남은 top의 epc — 시뮬레이터와 동일하게
  handler epilogue의 sw mepc 복원을 가정). handler에는 caller arc를 만들지
  않음 (시뮬레이터 parity — 휴리스틱 모드의 암묵적 tail push와 다름).
  진단: spurious_epc, isr_open (epc로 복귀 안 한 ctx = context switch 의심),
  **flow_anomalies** = ISR로 설명 안 되는 불연속 → issued.pc의 speculative
  오염 검증용 (사용자 waveform이 commit-valid 없는 issue stage라 중요).
- **exception/ISR — 휴리스틱 (PC-only, 기존 유지)**:
  "architectural하게 도달 불가능한 successor" (plain insn: next≠fallthrough;
  direct jump: next≠target; cond br: next∉{target,fallthrough}).
  resume PC 기억, mret/sret/uret(또는 resume 복귀)에서 handler 내 frame
  unwind. sleep gap은 첫 handler insn 도착 시 1로 clamp (first_isr_cycle
  대응, --no-isr-clamp로 해제). indirect jump 직후 인터럽트는 원리적으로
  감지 불가. epc 모드에서도 clamp 동일 적용.
- **stack 안전장치**: max_stack=4096, 포화 시 가장 오래된 frame flush-drop.
  종료 시 _unwind_to(0) = 시뮬레이터 remain_call_stack_process() 동등.
- **진단 출력** (stderr): healed/unmatched return 수, 종료 시 잔존 frame
  수 + 상위 누적자(잔존 Ir 크면 leak), exception 감지 수, 함수 수(ELF/실행).

## 4. 사용자 simulator 알고리즘 요점 (공유받은 수도코드)

> **전체 코드 정리본: `docs/simulator_reference.md`** — update_profile /
> update_epc / update / wfi handlers / update_branch / check_branch_type /
> handler_branch / remain_call_stack_process 전문과 오타 교정,
> WaveScope 대응표 포함. 새 대화에서 재타이핑 불필요.

- 매 instruction: update_epc(mepc, pc) → Ir → Cy_direct(cur−last) →
  branch/jump/load/store 이벤트 → update_branch로 (last_pc, branchType,
  taken) 기록 → 다음 instruction에서 check_branch_type + handler_branch.
- CALL 정의: c.jal/c.jalr true, c.jr false, jal/jalr은 rd ∈ lr_={x1,x5}.
- TAIL_CALL: rd==x0 jump → check_branch_type에서 재분류
  (같은 함수면 INDIRECT_JUMP, helper→non-helper면 RETURN,
  stack top caller 함수로 가면 RETURN).
- __riscv_save/restore는 FunctionType SAVE/RESTORE_HELPER로 태깅,
  helper발 call은 real_caller 치환 로직 있음.
- ISR: mepc CSR 변화 감지로 진입, call_stack을 stack-of-stack으로 대피,
  epc 주소로 복귀 시 unwind+복원. WFI 특수처리 (first_isr_cycle=1 clamp).
- inclusive: push 시 events_at_entry 스냅샷, pop 시
  accumulated − snapshot을 arc에 가산. (WaveScope의 FrameCtx.acc와 동치)
- 종료: remain_call_stack_process()로 전 stack drain.
- 사용자 코드의 확인된 오타(원본은 정상): is_wfi=false는 ==, & 는 &&.
  실버그 후보로 인정받은 것: update_epc의 infos_[pc] contains 미체크.

## 5. 해결된 이슈 (버전 순)

| 버전 | 내용 |
|---|---|
| v0.1 | 기본 파이프라인 (VCD→callgrind), shadow call stack |
| v0.2 | ISA JSON 분리(riscv/armv7m/aarch64), custom insn overlay, FSDB, scan |
| v0.2.1 | scan 진단(signals/--explain), ISS 방언(탭/real/붙은범위) |
| v0.2.2 | gzip/bz2/xz 투명 해제, FST/LXT2/VZT 자동 변환 |
| v0.3.0 | clockless 모드 (PC change GCD로 period 자동감지) |
| v0.3.1 | millicode alias 이름(cfn=save_7→save_4 버그), exception/ISR 1차 |
| v0.4.0 | tail frame push 모델(inclusive 의미론 수정), target 기반 taken, demangle |
| v0.4.1 | strip_params(인자 제거), fall-through arc, 전 함수 emit |
| v0.5.0 | asm 라벨 함수 universe(.S 함수 누락/침식 해결), return healing, 포화 drop |
| v0.5.1 | carry 폐기(지역 floor — stall 보존), loop closure, 진단 카운터 |
| v0.6.0 | ★ cycle 도착 귀속, calls 순수 PC 키, Call/TailCall 이벤트 제거 |
| v0.6.1 | 정수 tick 변환 (float 정밀도) |
| v0.6.3–0.7.1 | 의존성 제로 / TRN 지원 / 라이선스 큐 대응 |
| v0.8.0 | ★ --epc: mepc parsing 기반 정확한 ISR 진입/복귀 (update_epc 이식), profiler를 pending-resolution 파이프라인으로 재편 (인터럽트된 branch를 복귀 후 진짜 착지점으로 판정), WFI wake / 스퓨리어스 억제 / 중첩, multi-signal 추출 인프라 (VCD+fsdbreport), scan epc 후보, flow_anomalies 진단, fsdb2vcd clockless 경로 버그 수정 |
| v0.9.0 | ★ millicode 수정: jr/c.jr/tail 등을 no_link_mnemonics로 분류 (jr t0 오분류 → __riscv_save inclusive 폭증 = 이슈 6.1 유력 원인 → 사용자 확인: "많이 좋아졌"으나 잔여 차이 있음). in-text 데이터 심볼 제외 (이슈 6.3 → 사용자 확인: 함수 개수 일치 = 해결). --debug-func/--debug-log. callgrind jcnd=/jump= |
| v0.11.0 | ① clockless 적응형 period (→ v0.12.0에서 원복) ② scan --check-epc: epc 후보 행동 검증 (유지) |
| v0.15.0 | 사용자 2차 디테일 리포트 대응: ① `jal ra,__riscv_restore_0`(link 있는 restore 진입!) 케이스 — caller frame이 미추적일 때 restore frame의 ret_addr(jal+4)가 영영 commit 안 돼 6 insn/14 Cy가 arc에 못 들어가고 drain까지 표류 → **helper 내 return류의 무조건 top-pop** (시뮬레이터 규칙 2 이식, ret과 jr t0 양쪽) ② _close_loop_if_reentry에서 helper 제외 (stale restore frame 1개가 대량 unwind을 유발해 caller들 inclusive를 조기 절단하는 것 방지 — "arc 497 vs callee 총합 1094" 증상의 유력 기전) ③ writer: 같은 call site 복수 callee(간접 jalr)가 dict 키 충돌로 calls= 라인 유실되던 버그 수정 ④ 출력 포맷 = 시뮬레이터 diff용: 이벤트 `Ir Dr Dw Bc Bi Bim Cy` (Bcm 제거 — taken은 jcnd arc에 유지), fl=은 변경 시에만 출력 ⑤ --check-inclusive: 함수별 "incoming arc 합 == self+outgoing 합" 불변식 검사 리포트 (조기 pop/미추적 진입 진단, 재귀 함수 표시, root 목록 — _start가 root 최상위인지 즉시 확인 가능) ⑥ end-of-trace drain이 _start inclusive에 전액 반영됨을 테스트로 고정 (이슈였다면 stale frame 절단이 원인이었을 것) |
| v0.14.0 | ★★ inclusive 디테일 불일치 2대 원인 수정 (실물 riscv toolchain으로 검증): ① disasm 파서가 hex처럼 보이는 mnemonic("add"=0xadd!)을 인코딩 바이트로 삼켜 size 오염 (add가 size 3이 됨) → fallthrough 전부 어긋나 가짜 heuristic 예외·flow_anomaly·Bcm 오판·resume 불일치 유발. 탭 필드 구조 파싱으로 교체 (x86 byte-list/탭 없는 방언 fallback 포함) ② 빈 call stack에서 tail jump(`j __riscv_restore_0`)의 arc가 통째로 누락 — 시뮬레이터는 count를 push 시점에 무조건 기록 (`calls[..].count++` 후 frame만 조건부). count 기록을 push 시점으로 이동(parity), 빈 스택이면 count만 기록. ③ isCompilerHelper 이식: helper(__riscv_save/restore*)발 tail/fall-through arc 억제 — restore chain 내부(helper→helper) arc를 만들지 않아 시뮬레이터와 arc 구조 일치 (chain inclusive는 head arc에 귀속) ④ 회귀 테스트: gcc-riscv64-unknown-elf로 실제 -msave-restore ELF 빌드 (millicode 별칭·크기 겹침·`j save_4+0x4` 중간 진입 등 실물 레이아웃, toolchain 없으면 skip) |
| v0.13.0 | multi-bit --clock 지원 (C++ IP simulator dump): ① 32/64-bit **cycle counter** clock — LSB 토글 방식 대신 **counter 값 자체를 tick으로** 사용 (사용자 아이디어의 상위호환: LSB rising edge는 2 cycle당 1회라 반토막 함정, LSB 토글 카운트는 sleep fast-forward의 counter 점프를 놓침; 값 방식은 점프/주파수 변화/wraparound까지 정확). commit 시에만 lazy int-parse + hold 샘플 미생성이라 1-bit edge 대비 속도 동급 (1M cycle 벤치: byte당 동일). VCD는 자동 감지 (width>1 + 값이 1 초과), --clock-counter로 강제 (FSDB 경로 필수). wraparound는 header width로 보정 ② wide 변수에 저장된 0/1 clock — 마지막 bit을 레벨로 edge 샘플링 (1-bit과 동일 동작) |
| v0.12.0 | ① 적응형 원복: 고정 period + off-grid 감지 시 --clock 가이드 경고 (정책: CMU dump는 clock 필수) ② clocked/clockless 검증 테스트 (동등성 + clocked CMU 정확성) ③ ★ Cortex-M4/M35P 지원: --isr-level (IPSR 레벨 신호) — 진입=새 비0 레벨(선점/tail-chain 중첩), 복귀=외곽 레벨/0으로 하강(중간 ctx 일괄 pop, 최외곽 saved pending 복원 = HW EXC_RETURN이 정확히 원위치 복귀하므로 착지=resume, 주소 매칭 불필요), xPSR dump 시 0x1ff 자동 마스크, wfi wake는 IPSR이 항상 변하므로 별도 규칙 불필요 |
| v0.10.0 | 사용자 포맷 요구 반영: ① coverage 방출 — ELF code 영역 전체 insn을 zero-cost라도 표기 (미실행 code vs 컴파일 제외 code 구분용; --executed-only로 비활성) ② jump 라인 순서 = cost 라인 → jcnd/jump → position-only 라인(0xPC LINE) 반복 ③ cond branch 양방향 기록 (taken + fall-through, jcnd=30/100·70/100 합=실행수, 분모=방향 합) ④ IndJmp/DirJmp 이벤트 제거 (8개) |

테스트: 97개 통과 (tests/). 실 ELF 통합 테스트 포함 (호스트 gcc).

## 6. 미해결 / 검증 대기 이슈 ★ 다음 대화의 시작점

1. **inclusive 값 이상 (최우선)** — v0.14.0에서 2건 추가 수정 (add size
   오염 → 가짜 예외/오판 광범위 / 빈 스택 tail arc count 누락 = 사용자
   보고 restore_0 call 누락). **사용자 상태: self Ir/Cy는 전반적으로
   일치 확인, inclusive만 잔여 불일치 → v0.14.0 재실행 결과 대기.**
   재검증 시 확인 포인트: restore_0 incoming call 수, heuristic/anomaly
   수치 급감 여부, jcnd 변화. v0.15.0 이후 워크플로: ① 시뮬레이터
   출력과 라인 diff (포맷 동일화됨) ② --check-inclusive로 불일치 함수
   자동 추출 ③ 해당 함수 --debug-func 로그로 pop 사유 추적. 사용자
   케이스 "AA arc 497 vs 총합 1094"는 AA frame이 중간에 잘렸다는 뜻 —
   check-inclusive가 AA를 직접 지목해줌. ★ v0.9.0에서 유력 원인 수정:
   `jr t0`(millicode __riscv_save 복귀)가 operand 규약 탓에
   writes_link=True로 오분류 → return 매칭(273행 조건의 `not
   writes_link`)이 안 걸려 save frame이 안 닫히고 caller 본문 전체가
   save arc inclusive로 유입. 사용자 증상(호출수 ○, self Ir ○,
   inclusive만 폭증)과 정확히 일치. isa/riscv.json에
   no_link_mnemonics(jr, c.jr, ret, tail, j 등) 추가로 수정.
   **실 waveform 재검증 대기** — riscv_save 180138 기대치와 비교할 것.
   → 사용자 확인: "많이 좋아졌"으나 **아직 다른 부분 있음**. 다음 단계:
   --debug-func <어긋나는 함수> --debug-log dbg.log 로그를 받아 pop
   사유(ret-match/heal/drain)와 arc 누적 시점을 시뮬레이터와 대조.
   남은 구조적 차이 후보:
   - return pop 정책: 시뮬레이터=무조건 top pop vs WaveScope=매칭+healing.
     setjmp/context switch/RTOS task 전환이 있으면 여기서 갈림.
2. **Bcm 정의 차이 (설계 결정 필요)** — WaveScope=architectural taken,
   시뮬레이터=misprediction. waveform에 mispredict/flush signal을 추가
   dump하면 맞출 수 있음 (--mispredict-signal 옵션 후보).
3. ~~함수 개수 검증~~ → **해결 확인 (v0.9.0 데이터 심볼 제외 후 사용자가
   "원래대로 맞아졌"다고 확인).**
4. **ceiling/max call 누락** — 키 수정(v0.6.0)으로 해결 예상이나 재확인
   대기. 남으면 인라이닝 여부를 objdump로 확인 (jal 부재 = 인라인).
5. **cycle 재검증** — ★ 1차 원인 규명 (사용자 발견): **CMU가 중간에
   clock 주기를 변경** (후반부 빨라짐). 기존 구현은 warmup 2048개
   delta의 GCD로 period를 한 번만 잠갔기 때문에, 이후 빨라진 clock의
   1-cycle 간격(< period)이 0~1 tick으로 뭉개지고 max(1,·) floor에 걸려
   latency가 있어도 전부 1 cycle로 나옴 = "예상보다 작게" 증상.
   → v0.11.0 적응형 period로 수정: period의 배수가 아닌 delta는 고정
   clock에서 불가능(stall은 항상 정수 cycle)하므로 새 grid의 확실한
   증거로 보고 relock (window GCD + support 검증, straddle delta 제외
   fallback, 다중 변화 지원, warmup 내 변화도 head-lock으로 처리).
   **원리적 한계**: 느려지는 방향이 기존 period의 정배수면 stall과 구분
   불가 — CMU가 양방향 조절하면 clock dump + --clock이 정답 (아래 6.5b).
   기존 dump 재실행으로 Cy 재검증 필요; relock 시점/period가 stderr에
   찍히니 CMU 설정과 대조할 것. sw 4개 = Cy 2858/1715/... 패턴도 재확인.
5b. **★ v0.11.0 적응형 period는 v0.12.0에서 원복** — 사용자 실 dump에서
   실패: "결과가 엄청 오래 걸리고 모든 event가 0". 원인은 합성 테스트로
   재현 못 함 (실 파형에서만; off-grid 이벤트 빈발로 relock이 연쇄
   오발동해 스트림을 잘못 소모했을 가능성 의심). **확정 정책**: clock
   변화 없는 dump = 기존 고정 period 방식 그대로 (검증됨). clock 변화
   있는 dump = clockless로는 지원하지 않음 — off-grid delta 감지 시
   (비용: 샘플당 mod 1회) "clock을 dump하고 --clock을 쓰라"는 명시
   경고를 첫 발생 + 종료 시 출력. 양 경로 검증 완료: 고정 clock에서
   clocked/clockless 프로파일 event 단위 동일(tests/test_clock_paths),
   CMU 상황에서 clocked는 edge count라 정확함을 테스트로 고정.
   **edge 샘플링 의미론 주의**: edge N에서 같은 timestamp에 써진 값은
   edge N+1에서 샘플됨 (flop 타이밍상 올바름) — 합성 VCD는 마지막 pc
   write 뒤 trailing edge 필요, 실 dump는 자연 충족.
5c. **C++ 모델 counter clock (v0.13.0)** — 사용자 환경이 RTL이 아닌 C++
   IP simulator로 이동, clock을 32/64-bit 정수로 기록. counter 값 =
   cycle index로 직접 사용 (iter_pc_samples_counter: clockless commit
   추출과 동형, counter는 timestamp 끝 확정 + commit당 1회 파싱).
   CMU 주파수 변화 문제도 이 경로에선 원천 소멸 (값이 곧 cycle).
   --epc/--isr-level과 조합 가능 (aux 동반).
6. ~~indirect jump 직후 인터럽트 감지 불가~~ → **v0.8.0에서 --epc로 해결**
   (mepc dump 필요 — 사용자에게 waveform에 mepc 추가 dump 요청해야 함).
   실 waveform 검증 대기. epc 모드의 flow_anomalies 수치가 크면
   issued.pc의 speculative 오염 신호 → commit-valid signal 추가 dump 논의.
7. **epc 모드 미검증 가정들** (실환경 확인 필요):
   - handler epilogue가 mepc를 복원한다는 가정 (중첩 시 prev_epc 처리,
     시뮬레이터와 동일한 가정). 복원 안 하는 FW면 mret 후 스퓨리어스 진입
     1회 발생 가능 (진입 즉시 pc==epc로 exit되어 실害는 적을 것으로 예상).
   - clocked 샘플링에서 같은 edge에 clk 라인보다 늦게 dump된 mepc 변화는
     다음 commit에서 감지 (1 commit 지연 — 값은 동일하므로 복귀 매칭은 무관).
   - handler에 caller arc 없음 (시뮬레이터 parity) — UI에서 handler
     inclusive가 고아처럼 보이는 게 싫다면 --isr-arc 옵션 추가 검토.

## 6b. 디버깅 도구 (v0.9.0, 사용자와 수치 대조용)

```sh
wavescope profile ... --debug-func riscv_save --debug-log dbg.log
# 함수명 / 유일 suffix / 0x주소, 콤마·반복 가능
```
로그 이벤트: `commit`(insn별 Cy+n과 함수 self 누적 — 이슈 6.5용),
`push`/`pop`(frame 여닫힘, pop엔 사유: ret-match/heal/drain/loop-reentry/
isr-exit/stack-saturated — 이슈 6.1용), `isr enter/exit`(clamp 표시),
`unmatched-ret`, `flow-anomaly`. 끝에 함수별 self 합계 + incoming arc
전수(개수·inclusive)와 incl/self 비율 summary. 사용자에게 시뮬레이터
로그와 같은 함수 구간을 나란히 받아 대조하는 워크플로 제안할 것.

## 6r. v0.20.11 — 부팅 cycle 클램프 + ISA-일반 idle + ★ ARM 리스크 감사 (사용자 확인 대기)

### 사용자 지시 (2026-07-23)

1. clock-on→첫 fetch 사이 cycle을 첫 명령이 흡수 → **첫 명령 Cy=1로**
   (fetch 신호 추가 없이). 이후 clock 온오프는 wfi 처리로 충분.
2. 시뮬레이터의 wfi 감지는 "wfi" 리터럴(RISC-V 종속) — WaveScope는?
3. RISC-V 결과로만 검증 중 — ARM에서 오차 날 부분 사전 검토 요청.

### v0.20.11 수정

1. **부팅 경계 클램프**: run_sim 피더에서 n==1(두 번째 distinct 커밋)의
   delta를 1로 — 홀드가 prev_tick을 전진시키지 않아 부팅 홀드 전체가
   두 번째 커밋에 실리던 것을 차단. 부팅 갭은 **미계상**(총 Cy에서
   제외), 이후 갭(wfi 수면)은 기존대로 계상. 테스트로 양쪽 고정.
2. **idle의 ISA-일반화**: ISA json에 idle_mnemonics 추가(riscv: wfi /
   armv7m: wfi,wfe / aarch64: wfi,wfe,wfit,wfet), classifier가 노출,
   SimInfo.is_idle로 프리컴퓨트(.n/.w 접미 정규화 포함). 레퍼런스의
   "wfi" 리터럴 비교를 대체 — **시뮬레이터에도 동일 일반화 권장**.
3. **Thumb 비트 마스크**(cli): ARM 계열 ISA에서 pc 신호의 LSB=1
   (interworking 비트)을 마스크 — 안 하면 전 명령 unknown_pcs.

### ARM 리스크 감사 (사전 검토 결과, 중요도순)

A. **ISR 기전 전체가 mepc 중심** — Cortex-M은 mepc CSR이 없고 예외
   복귀가 EXC_RETURN 매직값(0xFFFFFFF1 등)으로의 bx lr/pop pc.
   epc 신호 없는 ARM 트레이스에선 default 엔진의 ISR entry/exit 감지가
   **전무** → 핸들러 frame이 현재 스택에 적층, A6 disc-ret이 부분
   치유. → ARM용 휴리스틱 필요(EXC_RETURN 범위 착지 감지 + NVIC 신호
   활용). **사용자에게 ARM 파형의 가용 신호 목록 질의 필요.**
B. **xret 부재**: XRET={mret,sret,uret,eret} — aarch64 eret ✓,
   Cortex-M 해당 없음 → prev_was_xret 항상 False. (A 해결과 연동:
   EXC_RETURN 착지를 xret-등가로 처리하는 게 자연스러움. 단, 매직값이
   커밋 pc 스트림에 실제로 찍히는지 파형 확인 필요 — unknown pc라
   flow_lost 경유로 우연히 동작할 수도.)
C. **helper 분류 riscv 전용**: __riscv_save/restore만 인식. ARM은
   millicode가 없지만 **veneer(`__*_veneer`, long-branch 트램폴린)**와
   `__gnu_thumb1_case_*`(switch 헬퍼), `__aeabi_*` 런타임이 유사 역할
   → 현재는 일반 함수 취급이라 far-call마다 여분 frame. veneer 패턴을
   helper로 등록 검토.
D. **IT 블록 조건부 실행**: 코어에 따라 skip된 조건부 명령도 커밋으로
   찍힐 수 있음 → 조건부 bx lr의 not-taken이 return으로 오독될 위험.
   단 A5a 가드(착지가 callee 내부면 pop 금지)가 이 케이스를 정확히
   막아줌을 확인 — 실파형으로 재검증만 필요.
E. 조건 접미(bne, bxne 등) 분류: json cond_suffixes 존재 — 실파형
   검증 항목.
F. pc_write 복귀(pop {pc}/ldm/mov pc,lr) ✓, blx 간접 ✓, .word 리터럴
   풀 ✓ — json 커버 확인됨. disc-ret/landing guard 등 엔진 레벨
   가드는 전부 ISA-무관 ✓ (armv7m veneer 테스트 기존 존재).
G. 사이클: Thumb 2/4바이트 크기는 insn.size 경유로 일반 ✓.

- tests/test_v0211.py 4종(부팅 클램프/후속 갭 계상/riscv·arm idle).
  전체 209 green.

### 사용자 회신 요청

1. 부팅 클램프 동작 확인 (첫 명령 Cy=1, 총 Cy에서 부팅 갭 제외).
2. ARM 파형에 어떤 신호가 있는지 (epc 등가물? EXC_RETURN이 pc
   스트림에 찍히는지? NVIC active 신호?) — 감사 항목 A/B의 설계 입력.
3. 시뮬레이터 wfi 감지도 idle 리스트 방식으로 일반화 권장 (wfe 등).

## 6q. v0.20.10 — 상태: ISR inclusive 사가 종결 ✅ / auipc Bi/Bim 철회

### 사용자 확인 (2026-07-23, v0.20.9 결과)

- ✅ **ISR inclusive 문제 해결 확인** — 4개 패턴(공유 millicode 가짜
  exit A7 / 소프트웨어 mepc 재기록 A8 / 공유 callee 간접 도달 A7강화 /
  빈스택 tail-dispatch A9)으로 종결. 사가 시작점이던 "_start inclusive
  최대 아님"(6i)부터의 계보 마무리.
- auipc Bi/Bim: **사용자 착오였음** (시뮬레이터는 auipc를 분기
  이벤트로 집계하지 않음, 다른 것과 혼동). → v0.20.10에서 규칙 철회,
  테스트를 "auipc는 분기 이벤트 0"으로 반전 고정.

### 잔여/유의

- A9는 여전히 의도적 레퍼런스 이탈 (시뮬레이터는 count-only) — 해당
  arc의 inclusive 발산은 tail_frames 카운트로 추적 가능, 시뮬레이터
  이식 권장 상태 유지.
- t=145 [사유] 미수신이나 A4~A9로 종결 추정. legacy 동결 유지.
- clone 정책(구분 vs --merge-clones) 사용자 결정 대기 중 (6o 질문 1).

## 6p. v0.20.9 — ★★ 다음 세션 우선: ISR tail-dispatch 해결(A9) + auipc Bi/Bim (사용자 재실행 대기)

### 사용자 회신 (2026-07-23, v0.20.8 func-trace 결과) — 네 번째 패턴 확정

func-trace가 병소를 정확히 지목:
```
t=2290918 isr-enter d=6 ISR_A@0x1424 -> FUNC_WFI@0xe3e4 [forced(A4 reenter)]
t=2290967 tail-noframe d=0 ISR_A@0x1492 -> FUNC_A@0x0cfc [empty stack: count only]
t=2291023 tail-noframe d=0 ISR_A@0x1516 -> FUNC_B@0x1394 [empty stack: count only]
```
해석: FUNC_WFI의 wfi 루프에서 동일 mepc 재인터럽트 → A4 강제 재진입
(정상) → **핸들러가 벡터 직접 진입이라 자기 frame이 없고**, 워커들을
`j`(tail)로 디스패치 → **빈 스택 위 tail = 레퍼런스가 count만 기록**
(tail-noframe) → FUNC_A/B inclusive 영구 유실. 즉 버그가 아니라
**레퍼런스 자체의 의미론적 한계**이며, `j`-디스패치 ISR에서는 항상
발생. (FUNC_A@0x0cfc가 ISR_A@0x14xx보다 낮은 주소 + 복귀 흐름 존재 —
컴파일러 분할부(.part/.cold)일 가능성도 있으나 기전은 동일.)

### v0.20.9 수정

1. **ADAPTER A9**: 빈 스택 위 tail call에서 frame을 **합성**(count는
   기존대로 + frame 추가, "tail-frame" 이벤트). callee의 복귀는 rule 4
   (caller 함수 내 착지)로 정상 pop, 미복귀 시 isr-exit drain이 flush.
   tail-noframe 이벤트/경로는 소멸. 카운터 prof.tail_frames + CLI
   stderr 라인. 레퍼런스 명시 이탈 — test_simcore의 count-only 고정
   테스트 2건을 A9 의미론으로 갱신(주석 명기).
2. **auipc → Bi+Bim** (_update_profile): 시뮬레이터 패리티로 auipc
   커밋마다 Bi+1, Bim+1 (사용자: "auipc일 때 Bi, Bcm 1씩"). 근거:
   fused auipc+jalr 쌍이 auipc pc로 1커밋되므로 숨은 간접점프 몫의
   분기 이벤트 귀속. 의미상 단독 auipc(주소 형성용)도 집계되는 과계수
   여지 있음 — **사용자에게 확인 요청**: 시뮬레이터가 무조건인지
   fusion 조건부인지 (조건부면 A6 불연속 신호로 게이트 가능).
3. tests/test_v0209.py 5종: 사용자 형상 그대로(벡터 직접 진입 frameless
   핸들러 + wfi 동일 mepc 2회째 A4 강제 + `j` 디스패치 + jr a5 복귀)
   — 두 패스 모두 arc inclusive 정확, tail-noframe 0, func-trace pop
   가시화, auipc Bi/Bim. 전체 205 green.

### 사용자 회신 요청

1. v0.20.9 재실행: FUNC_A/FUNC_B inclusive 정상 포함 + stderr "N frames
   synthesized ... (A9)" 수치 + func-trace에서 tail-noframe 소멸/
   tail-frame 등장 확인.
2. auipc Bi/Bim: 시뮬레이터 규칙이 **모든 auipc 무조건**인지, fused
   쌍일 때만인지 — 무조건이면 현행 유지(패리티), 조건부면 알려달라
   (게이트 추가).
3. 이로써 ISR inclusive 4개 패턴(공유 millicode·소프트 mepc·공유
   callee 간접·빈스택 tail-dispatch) 전부 처리 — 남은 누락 있으면
   동일하게 --debug-func func-trace 회신.

### 유의

- A9로 시뮬레이터와 의도적 발산: 시뮬레이터는 여전히 count-only이므로
  해당 arc들의 inclusive가 우리 쪽에만 존재 — tail_frames 카운트가 그
  지점 목록. 시뮬레이터에 같은 수정 이식 권장.
- t=145 [사유]는 여전히 미수신이나 A4~A9로 원인군 사실상 소진 추정.

## 6o. v0.20.8 — ★★ 다음 세션 우선: clone 정책 확정 필요 + inline fl + func-trace (사용자 재실행 대기)

### 사용자 질문/피드백 (2026-07-23, v0.20.7 결과)

1. `[clone .constprop.0]`이 뭔지 — 주소 영역이 다르고 어떨 땐 clone이,
   어떨 땐 원본이 실행됨을 확인. **정체를 알아야 제거 여부 결정**.
2. forceinline 헤더 코드: 같은 fn인데 fl(파일)이 다른 경우 시뮬레이터는
   fl/fn을 추가 기재하는데 WaveScope는 누락 → "pc code_line event"의
   code_line이 엉뚱한 곳으로 튐.
3. ISR inclusive 이슈 잔존 — 호출이 너무 많아 --debug-roots로는 못 봄.
   특정 함수만 추적하는 수단 필요.

### 답변/수정 (v0.20.8)

1. **constprop 정체**: GCC IPA-CP(상수 전파) 클론 — 일부 호출부가 상수
   인자를 넘길 때 그 상수를 박아넣고 죽은 분기를 제거한 **별도 특수화
   본체**(별도 주소). 상수 호출부는 클론을, 나머지는 원본을 호출 →
   "어떨 땐 이거, 어떨 땐 저거"가 정상. **정책 변경**: v0.20.7의
   기본-병합을 철회하고 기본 = **구분 유지 + 가독화**(raw
   `_Z...constprop.0`도 base를 demangle해 `foo(int) [clone
   .constprop.0]` 형태로 통일). 합산 뷰를 원하면 `--merge-clones`.
   → **사용자 결정 대기**: 구분(기본) vs 병합(--merge-clones) 중 뭘
   상시 쓸지 회신 요청.
2. **inline fl 전환**: writer가 함수 내부에서 cost line의 소스 파일이
   바뀌면 시뮬레이터 관례대로 `fl=<새파일>` + `fn=<같은 함수>`를 재기재
   (양방향 전환 모두). last_fl 연동으로 다음 함수 헤더도 정합.
3. **func-trace**: `--debug-func NAME[,NAME]`이 이제 default 엔진에서
   동작 — 지목 함수(정확명/0x주소/suffix 매칭, legacy와 동일한 해석기)
   가 caller 혹은 callee로 등장하는 **모든 스택 이벤트**(push/pop/
   guard/exit-reject/epc-rewrite/tail-noframe/isr-*)를 depth 제한 없이
   최대 800개 기록, stderr에 "[wavescope] func-trace" 섹션으로 출력.
   --debug-roots 없이도 동작(cur_tick 상시 유지로 변경). ISR inclusive
   추적용: `--debug-func 문제함수,__riscv_restore_0`.

- tests: test_v0208.py(fl 전환 양방향/단일파일 1회, func-trace 필터링/
  틱/비활성) + test_v0207 clone 테스트를 신정책으로 갱신. 전체 200
  green. `--merge-clones` 플래그, load_binary(merge_clones=) 스레딩.

### 사용자 회신 요청

1. clone: 구분(기본, 특수화별 비용 분리) vs 병합(--merge-clones, 함수
   단위 합산) — 어느 쪽을 상시 정책으로 할지. (시뮬레이터가 어떻게
   표기하는지도 알려주면 diff 정합 기준으로 맞춤.)
2. code_line 튀는 증상이 fl 전환으로 해소됐는지 (헤더 파일명이 fl로
   찍히는지).
3. **잔여 ISR inclusive**: `--debug-func <문제 ISR의 callee>,
   __riscv_restore_0`로 재실행해 func-trace 섹션 전체를 회신 —
   tail-noframe/isr-exit/exit-reject 중 무엇이 찍히는지가 다음 병소
   판정 데이터. (지금까지: 가짜 exit 3종(공유 millicode·소프트 mepc
   재기록·공유 callee 간접 도달)을 잡았고 네 번째 패턴이 남아있는 것.)

### 유의

- func-trace는 스택 이벤트만 기록(비용 라인 아님). 800개 초과분은
  생략 카운트로 표시 — 필요 시 한도 상향 요청.
- clone 구분 모드에서 엔진 내부 이름 비교(A5a 등)는 clone과 원본을
  다른 함수로 취급 — 의미상 올바름(실제 다른 코드).

## 6n. v0.20.7 — ★★★ 다음 세션 최우선: 공유-callee 가짜 exit (A7 간접-도달 구멍 봉합) + clone 심볼 + jcnd 순서 (사용자 재실행 대기)

### 사용자 피드백 (2026-07-23, v0.20.6 결과) 및 분석 검증

- 사용자 분석: ISR 4개 중 2개만 inclusive 누락. **배타 callee(ISR_D:
  한 ISR에서만 호출)는 정상, 공유 callee(ISR_B: 다른 ISR/일반 함수도
  호출)는 누락** → 합성 재현으로 **분석 정확함을 확인**.
- 기전: 공유 callee는 피인터럽트 코드에서도 실행되므로 mepc가 그 함수
  **내부**(특히 `jal t0,save` 직후 = save의 jr t0 복귀점)를 가리킬 수
  있음. 핸들러가 같은 함수를 재실행하면 save의 `jr t0`(**간접**)가
  mepc에 정확히 착지 → v0.20.5 A7 게이트는 간접 도달을 판정 불가
  (6l에 문서화했던 바로 그 구멍) → 가짜 exit → ISR 스택 조기 drain
  → (ISR_A→ISR_B) inclusive 소실 + 이후 tail-noframe 연쇄. 배타
  callee는 resume을 품을 일이 없어 무사 — 2/4 패턴과 정합.

### v0.20.7 수정 3건

1. **A7 강화** (simcore): exit 차단 조건을 "순차 도달 OR **임의의
   pending branch(간접 포함)가 이 커밋에서 settle**"로 확장. 진짜
   exit은 xret 직후(branch pending 없음, prev_was_xret로 허용)거나
   unknown 경유(flow_lost 허용)만. 알려진 트레이드오프: mret 커밋이
   샘플링에서 유실되고 직전이 branch면 exit을 놓칠 수 있으나(드레인은
   여전히 flush함), 가짜 exit의 체계적 inclusive 0화보다 훨씬 경미.
   A8 게이트는 기존(순차+direct target) 유지 — 간접 착지에서의 epc
   변화는 진짜 트랩일 수 있음.
2. **clone 심볼 정규화** (disasm): `[clone .constprop.N]` 주석 제거 +
   raw `.constprop/.part/.isra/.cold/...` 접미 제거 후 잔여 `_Z...`는
   c++filt 일괄 demangle (없으면 우아한 강등). 결과: 원본과 클론이
   같은 이름 → callgrind 뷰어가 집계 → 중복/미해석 항목 소멸.
3. **jcnd 순서**: count 내림차순 → **taken 레코드 우선, not-taken
   후행** (그룹 내 count 내림차순, 주소 오름차순). 시뮬레이터 출력
   순서와 재정합.

- tests/test_v0207.py 7종: 사용자 지목 지점(mepc=sub+4, 간접 착지) +
  전 지점 스윕("count>0&&incl==0 금지" + 배타 callee 불변) + clone
  정리 + c++filt + jcnd taken-우선. 전체 196 green.

### 사용자 회신 요청

1. v0.20.7 재실행: ① 문제였던 2개 ISR의 공유 callee inclusive 정상화
   여부 ② stderr exit-reject 수치 (공유 callee가 자주 인터럽트되면
   유의미하게 나옴) ③ clone 중복 소멸 + jcnd 순서 확인.
2. 남은 누락 시: 함수명 + --debug-roots의 해당 구간 (tail-noframe /
   isr-exit 이벤트 유무).

### 유의/미결

- (계속) legacy 동결. t=145 [사유] 미수신 — A7/A8 강화로 원인군 대부분
  커버 추정.
- clone 집계는 이름 통합 방식: 클론과 원본의 코드 주소는 별개로 남고
  뷰어에서 합산 표시. 엔진 내부 이름 비교(A5a 재귀 예외 등)에 이론상
  영향 가능하나 실무 무시 수준 (클론이 원본을 호출하는 희귀 케이스).

## 6m. v0.20.6 — ★★★ 다음 세션 최우선: 소프트웨어 mepc 재기록 = 유령 ISR entry (사용자 재실행 대기)

### 사용자 지시/피드백 (2026-07-23, v0.20.5 결과)

- 정책: **default 엔진 = 구 sim** (기본값 변경 + 명칭 default로).
  legacy는 동결 — 수정 금지, 폐기 대신 미사용 코드로 보존.
- ❌ default: ISR 내부 inclusive 누락 잔존. 구체 형상:
  ISR_end_of_process_interrupt(IEOPI)가 `j __riscv_restore_0`로 끝남 →
  (IEOPI→restore) arc는 **call count만 있고 inclusive 없음**. IEOPI를
  jal로 부르는 두 함수(ISR_end_2_process/ISR_end_process — 호출 뒤
  같은 함수 내 다른 라인으로 `j`)의 (caller→IEOPI) inclusive도 누락.

### 근본 원인 (형상 재현으로 확정)

**소프트웨어 mepc 쓰기 = 유령 중첩 ISR entry.** IEOPI류(중첩 에필로그/
태스크 스위치)는 mret 직전 mepc를 csrw로 재기록함. 레퍼런스(와 전사본)는
epc **값 변화만으로** entry를 선언 → 흐름이 순차인데도 유령 중첩 entry
발생 → 라이브 ISR 스택([caller→IEOPI])이 stack-of-stack에 동결 + 새 빈
스택 → 바로 다음 `j restore`가 **빈 스택 tail push = 레퍼런스
tail-noframe 경로(count만 기록, frame 없음)** → restore arc inclusive
영구 0 (사용자 증상 그대로), 동결된 caller frame들의 inclusive도 유실/
왜곡. "count>0 & inclusive==0" 시그니처는 레퍼런스에서 tail-noframe
단일 경로라는 사실이 결정적 단서였음.

### v0.20.6 = ADAPTER A8 + 엔진 정책 반영

- **A8** (simcore, 레퍼런스 이탈 주석 명기): update_epc에서 epc 변화
  감지 시, 해당 커밋 도달이 **아키텍처적으로 설명되면**(순차 fallthrough
  또는 pending direct target — A7의 _arrival_explained 재사용, update_epc
  가 update()보다 먼저라 직전 커밋 플래그 유효) trap이 아니라 소프트웨어
  쓰기로 판정: entry 선언 안 함, prev_epc 갱신, **is_isr이면
  isr_stack[-1].epc를 새 값으로 재타깃**(실제 mret은 새 mepc로 가므로
  exit 감지 정합). 카운터 prof.epc_rewrites + "epc-rewrite" root 이벤트
  + CLI stderr 라인. flow_lost(unknown 경유)나 force(A4)는 게이트 미적용.
  알려진 가정: mepc 신호가 커밋 정밀도로 정렬(트랩 entry 커밋에서 변화)
  — 사용자 파형/시뮬레이터 하네스와 동일 전제.
- **엔진 정책**: --engine choices = default|legacy|both (+숨은 별칭
  sim→default 정규화), 기본값 default. legacy는 FROZEN 명기(help/README).
  이번 세션부터 legacy 코드는 수정하지 않음 (v0.20.6의 A8도 simcore만).
- **파일 분리**: 엔진 파일은 원래 분리돼 있었음(profiler.py=legacy,
  simcore.py=default). 공유 데이터 모델(EVENTS/E_*/N_EVENTS, CallSite,
  Profile)을 **wavescope/profdata.py로 추출** → default 엔진이 legacy
  모듈을 import하지 않음. profiler.py는 하위호환 재수출 유지.
- tests/test_v0206.py 5종: 사용자 IEOPI 형상 그대로(csrw 시점 epc 변화,
  jal 후 `j`, 재타깃 exit) — 유령 entry 0, tail-noframe 0, restore/caller
  arc 정확치, "count>0&&incl==0 금지", 비-ISR 소프트 쓰기. 전체 189 green.

### 사용자 회신 요청

1. v0.20.6 재실행 (이제 옵션 없이 default): ① IEOPI/restore/호출자 arc
   inclusive 정상 포함 여부 ② stderr "N software mepc writes consumed"
   수치 (IEOPI가 인터럽트마다 돌면 인터럽트 횟수와 비슷해야 정상).
2. --debug-roots에서 "epc-rewrite" 이벤트가 IEOPI의 csrw 지점에 찍히는지.
3. 남은 누락이 있으면: 해당 함수명 + 그 지점 root 이벤트 (tail-noframe이
   또 보이면 다른 빈-스택 경로가 남은 것 → 그 직전 이벤트가 범인).
4. 시뮬레이터 대조 시: 시뮬레이터도 같은 유령 entry를 가질 것이므로
   epc-rewrite 지점마다 의도적 발산 예상 — 시뮬레이터 수정 포인트 목록.

### 유의/미결

- legacy 동결: 앞으로 legacy 관련 사용자 보고는 기록만 하고 수정 안 함.
- (계속 미결) 과거 t=145 [사유] — 6l까지의 수정들(A7+A8)이 원인군을
  대부분 커버했을 가능성이 높지만 사용자 확인 문자열은 여전히 미수신.

## 6l. v0.20.5 — ★★★ 다음 세션 최우선: 공유 millicode 가짜 ISR exit (사가의 유력 근본 병소, 사용자 재실행 대기)

### 사용자 피드백 (2026-07-23, v0.20.4 실행 결과)

- ✅ auipc return 해결 확인 (sim 기준).
- ❌ sim: ISR 발생 시 __riscv_restore_x가 **진입/호출 카운트는 보이는데
  inclusive 이벤트가 빠짐**. ISR_A→ISR_B 내부 호출의 ISR_B 비용도
  ISR_A inclusive에서 누락.
- ❌ legacy: _start/SYS_BSP_reset/SYS_system_startup **inclusive가 너무
  작음** (중간에 누적이 끊김). 사용자: legacy는 sim 로직과 달라 유지비
  부담 → 몇 번 더 고쳐보고 안 되면 폐기 예정 (코드는 보존).

### 근본 원인 (합성 스윕으로 확정: 인터럽트를 모든 명령 지점에 주입)

**공유 millicode 가짜 ISR exit.** 인터럽트가 `jal t0,__riscv_save_0`
(또는 save/restore 내부)에서 걸리면 mepc = **공유 helper 내부 주소**.
핸들러 자신의 프롤로그도 같은 helper를 호출 → 핸들러 실행 중 pc가
저장된 resume 주소와 일치 → 양 엔진 모두 `pc==epc`만 보고 **가짜
exit** 선언:
- sim: ISR-로컬 스택 조기 drain → 핸들러 arc들이 count만 남고
  inclusive 유실 (사용자 증상 그대로). 이후 핸들러 잔여 실행이
  복원된 normal 스택 위에서 진행되며 main frame들을 오염.
- legacy: isr-exit(epc) unwind가 핸들러 frame 절단 + 이후 핸들러의
  restore return들이 root 인접 frame을 잠식 → **root inclusive
  과소** (사용자 1번). 과거 t=145 조기 pop([사유]가 isr-exit(epc)일
  가능성 높음)의 유력 정체이기도 함.
- 공유 millicode뿐 아니라 핸들러와 피인터럽트 코드가 **공유하는 모든
  서브루틴**에서 동일 발생 (jal ra,F 중 인터럽트 → resume=F entry →
  핸들러도 F 호출).

### v0.20.5 수정 = ISR-exit 도달 게이트 (양 엔진)

원칙: **resume 주소 도달이 직전 명령의 아키텍처적 flow(순차 fallthrough
또는 direct transfer의 target)로 설명되면 exit이 아니다.** 진짜 exit은
xret 직후 도달이거나 (xret 커밋 누락 시) 설명 불가능한 불연속 도달.
- legacy: epc-mode exit(`pc==ctx.resume`)에 게이트. pending이 xret이면
  통과, fallthrough/target 일치면 reject (`prof.exit_rejects` +
  "exit-reject" root 이벤트). heur/level exit은 기존 조건이 이미
  xret/level 기반이라 무변경.
- sim: **ADAPTER A7** — prev_was_xret + _arrival_explained(순차 or
  pending direct target) 게이트. 함정 2개를 밟고 고침: ① update()가
  base당 IR/Cy 2회 호출되어 첫 호출의 settle이 판정 재료(last_was_branch,
  prev_ft)를 소비 → 판정을 **커밋 단위로 1회 캐시**해야 함 ② 캐시 키를
  pc로 하면 같은 pc 재방문(공유 helper!) 시 이전 판정이 재사용돼 진짜
  exit까지 차단 → **커밋 일련번호(_commit_serial)** 도입. _flowchk도
  동일 결함이 있어 serial로 전환 (unknown 구간 사이 동일 pc 재방문 시
  A6 체크 누락되던 잠재 버그 동시 수리).
- unknown 구간 경유 도달은 "설명 불가" 취급(exit 허용, flow_lost).
- CLI: exit_rejects stderr 라인 + **root-chain 중도 절단 자동 감지**
  (--debug-roots 시 depth≤2 pop 중 drain이 아닌 것을 [사유]와 함께
  나열 — 사용자 1번 질문 "어떻게 판단해야 할까"의 직접 답).
- tests/test_v0205.py: 인터럽트 지점 전수 스윕(19지점×2엔진) — ISR
  arc 정확치 + root 보존 + "count>0 && inclusive==0 금지"(사용자 증상
  자체를 invariant로) + reject 후 진짜 exit 동작. 전체 184 green.

### 사용자 회신 요청

1. v0.20.5 재실행 (sim/legacy 모두): ① ISR 내부 함수들(restore 포함)의
   inclusive가 정상 포함됐는지 ② legacy의 _start/BSP/startup inclusive가
   최대치로 복구됐는지 ③ stderr "N ISR-exit arrivals rejected" 수치.
2. --debug-roots 시 새로 나오는 "root-chain frames closed MID-RUN" 목록
   — 남아있다면 그 [사유]가 다음 타깃.
3. legacy 폐기 판단은 이 결과 보고 나서: 이번 병소는 양 엔진 공통이었고
   legacy 특유 증상(1번)도 같은 뿌리였을 가능성이 높음.

### 유의

- 게이트가 막지 못하는 잔여 케이스: 핸들러가 resume 주소에 **간접
  점프(jr/jalr)로** 도달하는 경우 — 간접은 어디든 갈 수 있어 "설명됨"
  판정 불가라 exit을 허용함(기존 동작 보존). millicode의 jr t0가 정확히
  resume에 착지하는 병리적 상황은 t0 값 특성상 사실상 불가능.
- sim의 A5/A6/A7은 레퍼런스 이탈(주석 명기). 사용자 시뮬레이터가 같은
  가짜 exit을 갖고 있다면 그 지점에서 의도적으로 수치가 갈라짐 —
  exit-reject 이벤트가 시뮬레이터 쪽 수정 지점 리스트가 됨.

## 6k. v0.20.4 — ★★ 다음 세션 최우선: disc-ret (auipc-return frame 유출 수리, 사용자 재실행 대기)

### 사용자 피드백 (2026-07-22, v0.20.3 실행 결과)

- ✅ _start가 root 최상위 복귀, t=154 붕괴 소멸 (landing guard 유효 확인).
- ✅ t=47/145/147/158의 SYS_initi* 생략 표기 = 전부 같은 함수 (SYS_initialize).
- ❌ 신규(공통) 이슈: **auipc return** — A가 B 호출, B는 if로 대부분
  미실행이라 `auipc t1,0xf1000` 단 1개 커밋(Ir=1, Cy=3) 후 곧바로 A의
  복귀지점으로 커밋이 점프. arc(A→B) inclusive가 sim 139,084 /
  legacy 1,116,524로 폭주. **RISC-V macro-fusion (auipc+jr/jalr 쌍이
  1커밋으로 합쳐져 뒤 점프 pc가 파형에 안 찍힘)** 또는 far-stub이
  ELF 밖 코드로 나갔다 돌아오는 경우 → 분류 가능한 return이 안 보여
  (A→B) frame이 영영 안 닫히고 이후 실행 전부를 흡수하던 것.
- ❌ legacy 전용 이슈(보류): inclusive top 항목들 — self는 정상인데
  inclusive만 큼 = frame 유출의 전형적 시그니처. disc-ret로 같이
  풀릴 가능성 높음 (leaked frame이 흡수한 비용). v0.20.4 결과로 판정.

### v0.20.4 수정 = discontinuity return (disc-ret, 양 엔진·ISA 무관)

branch 커밋 없이 순차 흐름이 깨졌고(disc) 착지가 **열린 frame의 복귀
주소와 정확히 일치**하면 return으로 간주하고 그 frame까지 닫음
(tail 상속/anchor 매칭, v0.20.3 landing floor 그대로 적용). 함수
ENTRY 착지는 제외 — entry로의 불연속은 missed call 또는 인터럽트라
기존 휴리스틱/epc 예외 감지가 그대로 담당 (회귀 테스트로 고정).

- legacy: ① heur 모드 2b에서 가짜 ISR entry 선언 전에 disc-ret 시도
  (auipc-return이 유령 IsrCtx를 만들던 것도 함께 제거, exceptions
  오염 방지) ② epc 모드 resolve() anomaly 경로에서 disc-ret 시도
  (매칭 시 flow_anomalies 미집계) ③ unknown pc 구간(lost_flow) 재진입
  시 disc-ret (far-stub → ELF 밖 → 복귀). 카운터
  prof.discontinuity_returns + "disc-ret" root 이벤트.
- sim: **ADAPTER A6** — prev_ft(직전 known 커밋의 fallthrough) 추적,
  settle 안 된 불연속에서 caller_pc+size == 착지인 frame 스캔 후 그
  위를 sweep해 닫음 (A5 callee-포함 가드 유지). ISR entry/exit 시
  prev_ft 리셋(resume/handler 진입은 return 아님). unknown pc는
  flow_lost 마킹. sim의 jr-경유 far-stub은 pending이 unknown 구간을
  살아남아 rule4로 자가 치유되는 경우도 있음(레퍼런스 동작 보존).
- ARM: 전부 엔진 레벨이라 armv7m/aarch64 동일 적용 (movw/movt+bx
  veneer 시나리오 armv7m 테스트 추가 — 사용자 명시 요청).
- tests/test_v0204.py 7종: fused-pair(양엔진+epc모드), far-stub
  unknown 구간, ARM veneer, heur-ISR entry 비회귀. 6000-insn 후속
  실행 합성에서 arc(A→B) Ir=1 확인. 전체 181 테스트 green.
- 부수: A6가 test_v0203 재귀 테스트의 비아키텍처적 합성 trace 결함을
  검출 → trace를 실제 분기 포함 형태로 교정 (A6 민감도 방증).

### 사용자 회신 요청

1. v0.20.4 재실행: 문제의 arc(A→B) inclusive가 Ir≈1/Cy≈3으로
   내려왔는지 + stderr "N discontinuity returns" 수치.
2. --debug-roots에서 해당 지점의 "disc-ret" 이벤트 라인 (fused pair가
   상시 패턴이면 실행당 수백 회일 수 있음 — 카운트만이라도).
3. **8번 legacy-전용 inclusive top 이슈**가 함께 해소됐는지. 남아있으면
   해당 함수의 --check-inclusive 델타와 --debug-roots 인근 로그 요청
   (leaked frame 흡수가 아니라면 별도 원인 — heal/ret-match 오매칭 등
   후보 조사 필요).
4. (미결 유지) t=145 조기 pop의 [사유] 문자열 — 6j 질문 3번 그대로.
   landing guard가 피해를 막고는 있지만 병소 원인은 아직 미확정.

### 한계/유의

- disc-ret은 복귀주소 정확 일치 시에만 발동 (보수적). fused **call**
  (auipc+jalr ra가 함수 entry로 점프)은 아직 미처리 — entry 착지는
  ISR과 구분 불가라 의도적으로 제외. 사용자 데이터에서 필요 신호가
  보이면(호출 arc 누락 보고) 다음 버전에서 entry-착지 + call-후보
  휴리스틱 검토.
- 같은 pc 연속 커밋은 hold로 dedup되므로(클록 샘플링), 인접 동일 pc
  재실행(0-거리 재귀 등)은 원천적으로 1커밋으로 보임 — 엔진 한계.

## 6j. v0.20.3 — ★★ 다음 세션 최우선: landing guard (depth 붕괴의 후폭풍 차단, 사용자 재실행 대기)

### 사용자 신규 단서 (2026-07-21 메시지)

- __riscv_restore_0 / __riscv_restore_4 **둘 다 마지막이 `jr t0`** (restore_0의
  직전 insn "sw ra,12(sp)"?, restore_4는 "sub sp,sp,t1" — 전자는 사실 libgcc
  save 계열 몸체와 동일한 형태. 사용자 오타이거나 벤더 커스텀 millicode).
  둘의 마지막 insn이 동일한데 한쪽만 스택이 관통됨 → **분류 차이가 아니라
  스택 상태 의존적 cascade**라는 결정적 증거 (엔진에서 두 helper는 완전히
  동일하게 처리됨을 코드로 확인).
- t=154에서 pop d3(restore)→d2(BSP→startup)→d1(_start→BSP) 3연쇄 후
  t=158 push depth=1 재시작 = 6i 재구성과 정합.

### 원인 구조 (이번 세션에서 합성으로 재현·확정)

깨끗한 trace에선 모든 컨벤션(j / jal ra / jal t0 에필로그, 2단 tail,
missed-ISR 다수 조합)에서 양 엔진 모두 균형 → t=145의 조기 pop(병소)은
비정상 이벤트이고, 관찰된 붕괴는 그 **기계적 후폭풍**이 맞음. 후폭풍의
정확한 기전을 재현함: 함수 frame이 하나 없어진 상태(예: v0.20.2 parity로
**교차 함수 cond branch 진입 = frame 없음** — beqz→SYS_init 류!)에서
에필로그 restore가 (BSP→startup) 위에 직접 tail-push되고, `jr t0`의
착지가 **startup 내부**인데도 레퍼런스 tail-chain while이 (BSP→startup),
(_start→BSP)를 관통 pop → 스택 공동화 → depth=1 재시작. 착지 pc가
스택과 모순됨을 엔진이 알면서도 무시하던 것이 본질.

### v0.20.3 수정 = landing guard (양 엔진)

원칙 2개: ① return은 자신이 닫는 frame의 callee **내부에 착지할 수 없다**
(자기재귀 caller==callee만 예외) ② 어떤 unwind도 **착지 pc를 아직 포함하고
있는 callee의 frame을 pop할 수 없다** (landing floor).

- legacy: ret-match의 tail walk-down에 floor (매칭 frame 자체는 ret_addr
  증거이므로 예외 — 재귀 안전), heal에 floor, isr-exit(epc/heur/level)
  unwind에 floor (stale ctx가 낮은 depth로 하부를 날리는 6h(A) 방어),
  helper-ret-pop은 착지가 다른 helper면 skip (restore 체인 중간 오폐쇄
  방지). 카운터 prof.guarded_unwinds + --debug-roots "unwind-guard" 이벤트
  (어떤 frame이 보호됐고 원래 몇 depth까지 내려갈 뻔했는지 명시).
- sim: **ADAPTER A5** (레퍼런스 이탈, 주석 명기) — A5a: BT_RETURN top pop을
  착지가 top.callee 내부면 skip ("return-guard" 이벤트, helper frame 소실
  시 감싸는 함수 frame이 날아가던 t=145 후보 (d) 차단). A5b: tail-chain
  while에서 다음 frame의 callee가 착지를 포함하면 중단 ("chain-guard").
  주의: 레퍼런스의 stale non-tail late-flush quirk(6c의 jal-ra-restore
  의미론)은 **그대로 보존** — claimed-caller 검사까지 넣었다가 parity
  테스트(test_jal_restore_late_flush)가 깨져서 callee-포함 검사만 남김.
  counters: prof.return_guards/chain_guards (stderr 라인 + both diff에서
  사용자 시뮬레이터와의 발산 가시화용).
- 재현 고정: tests/test_v0203.py 6종 — 사용자 로그의 붕괴 시나리오
  (frameless 진입 + tail restore + jr t0)에서 양 엔진 모두 _start
  inclusive == total−self(_start), First push가 depth 3 "under startup",
  sim chain-guard 발화; A5a helper-frame-소실; 자기재귀 pop 정상; legacy
  restore 체인 hop; stale isr-exit floor. 전체 174 테스트 통과.

### 사용자 회신 요청 (이 순서로)

1. v0.20.3 재실행: **_start가 root 최상위 + inclusive 최대**가 되는지
   (붕괴가 t=145 원인과 무관하게 이제 격리됨), --check-inclusive 델타 변화.
2. stderr의 "N unwinds stopped by the landing guard" 수치 + --debug-roots의
   unwind-guard/return-guard/chain-guard 이벤트 라인 (t=154 지점이
   chain-guard로 바뀌었는지 = 기전 확정).
3. **t=145 pop 라인의 [ ... ] 사유 문자열** — 지난 회신에서 생략됨. 이게
   병소의 최종 판정 데이터 (ret-match .. -> 0x착지 / helper-ret-pop /
   isr-exit / RETURN landing 0x..).
4. t=47/147/158의 "SYS_initi...", "SYS_initial...", "SYS_initializ..."가
   같은 함수인지 (6i 질문 유지).
5. isr-enter/isr-exit/orphan-xrets/tail-noframe/guard 카운트 전체.

### 유의 (사용자에게 설명할 것)

- A5는 레퍼런스 이탈이므로, 사용자 시뮬레이터가 레퍼런스처럼 스택을
  관통한다면 그 지점에서 sim/시뮬레이터 수치가 **의도적으로** 달라짐 —
  guard 이벤트가 그 지점을 정확히 지목하므로 오히려 시뮬레이터 쪽 버그
  후보 리스트가 됨 (사용자 코드에 같은 가드를 이식 제안 가능).
- t=145의 근본 원인은 아직 미확정 (사유 문자열 대기). guard는 원인과
  무관하게 피해를 국소화하는 방어층. 원인이 확정되면 그 지점 자체를
  추가 수정.

## 6i. v0.20.2 — ★ 다음 세션 최우선 (depth 붕괴 본선, 사용자 새 채팅 예고)

### 사용자 로그 정밀 재구성 (v0.20.1 로그)
t=145 pop d3 (startup→SYS_init) ← ★★ 병소. SYS_init이 아직 실행 중인데
  frame이 먼저 pop됨. 이후는 전부 기계적 후폭풍:
t=147 push d3 (SYS_init→restore_0): pop 후 스택2 + push = depth 3 정합
  (사용자가 "depth 그대로"라 오해한 부분 — pop 라벨 = pop되는 frame의
  depth라서 숫자는 전부 정상. 표기 문제 아님을 사용자에게 설명함)
t=154 pop d3(restore) → d2(BSP→startup) → d1(_start→BSP): restore가
  TAIL로 push됐고 e3(SYS_init CALL anchor)가 이미 없어서 tail-chain
  while이 e2(tail), e1(anchor)까지 관통 — 레퍼런스 의미론대로의 동작.
  e3만 살아있었으면 [restore + e3]에서 멈추고 startup 정상 복귀였음.
t=158 push d1 (startup→SYS_init...): 빈 스택 위 재시작. legacy도 동일
  위치 동일 증상.

### 다음 회신으로 판정 가능한 것 (사용자에게 요청함)
1. t=145/t=154 pop 라인의 [ ... ] 사유 문자열 — 이미 로그에 있음:
   ret-match mnem@pc -> 0xLANDING / helper-ret-pop / tail-chain pop /
   RETURN landing 0x.. / isr-exit drained N. v0.20.2에서 사유에 착지
   주소, push에 "| under 부모함수"까지 추가되어 한 줄로 판정됨.
2. t=47 "SYS_initi...", t=147 "SYS_initial...", t=158 "SYS_initializ..."
   가 같은 함수인지 (사용자 말줄임 — 다른 함수일 가능성!)
3. isr-enter/isr-exit/orphan-xrets/tail-noframe 카운트 + SUSPICIOUS
   drain 경고 여부.

### t=145 조기 pop 용의자 (사유 문자열로 확정될 것)
(a) ret-match 오매칭: 어떤 ret의 착지가 우연히 e3.ret_addr과 일치
(b) helper-ret-pop: jal-restore가 SYS_init 내부 서브콜리에서 표류
(c) isr-exit: stale ISR ctx의 resume pc 재등장 → depth까지 unwind
(d) sim이면 RETURN landing 0x.. 사유로 rule1/2/4 중 무엇인지 나옴

### v0.20.2 확정 수정
- ★ legacy가 교차-함수 cond branch(beqz→opt_memcpy_tail)를 TAIL로
  push하던 것 제거 — 시뮬레이터는 Group::BRANCH(통계만, arc/frame
  없음). 사용자가 보고한 sim/legacy 로그 차이의 원인. parity 테스트
  고정. (sim은 교차 함수 jcnd도 기록, legacy는 intra만 — 잔여 발산
  항목으로 인지)
- push에 "| under 부모" 주석, ret-match/helper-ret-pop 사유에 착지
  주소 추가.
- 테스트 GIGO에서 발견한 구조적 사실: sim feeder는 ISS 전제로
  branchType을 신뢰하고 착지를 검증하지 않음 → 놓친 ISR 진입 시
  jal→handler 가짜 arc 생성 가능 (legacy는 direct target 검증으로
  보호, indirect는 미보호). "SYS_system_startup→ISR_x push"의 sim측
  기전 후보.

## 6h. v0.20.1 — --debug-roots 계측 자체의 버그 수정 (사용자 로그 분석)
사용자가 본 "이상"의 상당수가 계측 문제였음:
- legacy pop 라벨이 0-기반 idx (push는 1-기반) → "t=28 push depth=3 /
  t=35 pop depth=2"가 같은 frame. → 1-기반 통일.
- depth≤3 창 밖 이벤트 무기록 → "t=49 이후 save_0 call 소실"은 로그
  창 문제 (엔진은 정상 pop; t=145 pop = SYS_init의 정상 복귀).
  → --debug-roots [N] 으로 창 조절 (기본 3).
- sim은 push 무필터·pop만 ≤3 필터 (비대칭) → save_0 pop이 안 보였음.
  → 대칭화.
- sim tail-chain while의 연쇄 pop 미로깅 → "pop 없이 depth 2 감소"
  착시. → 각 pop을 "tail-chain pop"으로 기록.
- 이벤트 상한 40 → 바쁜 구간에서 후반 pop 통째 생략 → 상한 200 +
  생략 카운트 표기.
남은 진짜 버그 후보 (다음 회신으로 판별):
(A) sim depth 붕괴 (t=158 push depth=1, t=340 tail-noframe depth=0):
    유력 기전 = **stale ISR level** — exit 조건이 pc==저장된 epc 정확
    일치인데, 소프트웨어가 mret 전 mepc를 바꾸면(스케줄러류) exit을
    영영 놓치고 is_isr 고착 → 이후 그 pc가 재등장하는 순간 reference의
    exit 분기가 **현재 call_stack 전량 drain**. 계측 추가: isr-exit에
    "drained N open frames" + N≥3이면 SUSPICIOUS 표기 + 종료 시 경고,
    prof.isr_exits/max_exit_drain. 레퍼런스/사용자 시뮬레이터 공통 위험.
(B) tail-chain 완전 unwind: startup 체인이 전부 tail이면 restore ret
    1회에 앵커까지 전부 pop = 레퍼런스 의미론상 정상일 수 있음 —
    이제 "tail-chain pop" 연쇄로 로그에서 구분됨.
legacy "ISR이 root": handler가 root인 것 자체는 설계상 정상 (caller
arc 없음, 사용자도 동의했던 사항) — 문제는 handler가 일반 call로
push되는 잔존 케이스 → isr-enter(handler-entry) 카운트와 대조 요청.

## 6g. v0.20.0 — 사용자 5개 항목 (사용량 초과로 중단 후 재개분)
1. jcnd **내림차순** 정정 (v0.17의 오름차순은 오해였음): 18/27 → 9/27,
   동수면 타겟 주소 오름차순. 테스트로 고정.
2. unimp = nop과 동일 (ret 뒤 symtab size 밖 정렬/경계 패딩, 0x0000).
   제외가 맞음 — 시뮬레이터도 nop과 함께 제외 권고. checkelf
   range_dropped가 나열해줌. 코드 변경 없음.
3+4. ISR 잔여 누락 대응 (사용자 제공 정보: **중첩 ISR은 ISS에서 epc
   미갱신** + wfi 복합 시 epc만으로 애매 — 후자는 이미 전사됨):
   (a) xret(mret/sret/uret)을 riscv.json indirect_jump에서 제거 —
       system 명령이지 JUMP group이 아님 (양 엔진 공통: Bi/Bim 미부과,
       sim feeder update_branch 미발행 → rule4 오판 소멸). **ISS
       decode도 xret이 JUMP group 밖인지 사용자 확인 필요.**
   (b) legacy orphan-xret 가드: epc 모드에서 resolve까지 도달한 xret =
       진입을 놓친 증거 (감지된 exit은 resume commit에서 pending을
       폐기하므로 resolve에 안 옴) → ret-match 스캔 금지 (바닥 frame
       훼손 차단), prof.orphan_xrets 카운트 + root 이벤트.
   (c) legacy known-handler-entry 휴리스틱: A4는 간접(jalr) 소스를
       의도적으로 제외 (mepc=알 수 없는 target) — 사용자 로그의 잔여
       "SYS_system_startup -> ISR_x push"의 유력 기전. 감지된 진입에서
       handler entry pc를 학습, 이후 그 주소로의 비검증 착지(직접
       target/fallthrough 불일치, pc≠epc)는 mepc 무변화여도 진입
       (resume=현재 mepc). sim은 순수성 유지 (A4까지만) — both 비교로
       발산 가시화.
5. restore call 누락 신규 가설 = **별칭**: restore_0~3이 동일 주소,
   canonical 1개만 출력됨. checkelf에 alias 그룹 리포트 추가 (실물
   millicode에서 6그룹 검출 확인). 사용자 확인 요청: checkelf 실행 +
   출력에서 `grep "cfn=__riscv_restore"` — 빠진 call이 같은 주소의
   다른 restore_N 이름으로 있는지. helper tail-return의 이름 기반
   처리(contains + ret/jr t0)는 양 엔진 구현·테스트 완료 상태.

## 6f. v0.19.0 — ISR 재진입 맹점 (사용자 --debug-roots가 잡아낸 것)
사용자 로그: "t=745 push depth=3 SYS_system_startup -> ISR_InvokeClock"
= ISR 진입이 감지되지 않고 일반 call로 push됨 + 이후 pop 꼬임.
진단: **같은 pc가 반복 인터럽트되면 mepc 값이 안 변해** 변화 감지가
2회차부터 실명 (레퍼런스도 동일한 맹점 — wfi 케이스만 별도 커버.
사용자 시뮬레이터도 같은 갭을 가질 가능성 높음 → 사용자에게 제기).
놓친 진입 후 handler의 ret들이 일반 스택 바닥 frame을 pop
(sim은 RETURN 무조건 pop이라 특히) → SYS_BSP_reset arc 조기 마감 =
"root inclusive 과소"의 유력 본체.
수정 = **ADAPTER A4** (양 엔진): 파형의 더 강한 신호 사용 — 하드웨어는
mepc에 "실행 직전이던 pc"를 쓰므로, 설명 불가능한 불연속에서
mepc == 직전 insn의 후속 주소(fallthrough 또는 direct target)면 값이
안 변해도 재진입. 조건: epc 무변화 && pending 비간접·비리턴 &&
착지가 후속들과 불일치 && mepc ∈ {fallthrough, target} && 착지 != mepc.
sim은 update_epc(force=) 인자로 주입 (전사 이탈, ADAPTER 표기).
--debug-roots에 isr-enter(사유: mepc-change/wfi-wake/mepc-reenter)와
isr-exit 이벤트 추가 — 다음 회신에서 t=745 지점이 isr-enter로 바뀌는지
확인. 예상: exceptions 카운트 급증 + root inclusive 회복.

또한 fall-through parity 확정 (사용자 확인): fall-through 함수 경계
crossing은 **arc/frame 미생성** (시뮬레이터 동일) — 비용은 열린 상위
frame들에 흡수, 해당 함수는 self만 가진 root로 표시 (양쪽 합의된
아티팩트). legacy의 비-helper fall-through push 제거.
nop 이슈는 사용자측 종결 (시뮬레이터를 우리에 맞춤).

## 6e-2. v0.18.1 — 후속 (사용자: v0.18.0에도 reading 553.7s 불변)
원인: v0.18.0 최적화는 iter_commit_changes(clockless)에만 적용됐고
사용자는 counter clock(--clock) 경로 = iter_pc_samples_counter를 탐.
→ counter 경로 전면 fast-reject 재작성 (노이즈 32신호/cycle 벤치
74 MB/s), iter_samples_multi/iter_pc_samples/iter_pc_changes에는
루프 상단 prefilter(untracked b/scalar 라인을 endswith 튜플 1회로
기각) 삽입. 예상: 사용자 첫 pass ~120~150s, 캐시 hit 재실행은
reading·convert 모두 소멸. 사용자 실측 timing: open/convert 104s
(fst2vcd — 첫 실행 고정비), reading 553.7s(→개선 대상), engine 9.8s.

사용자 확인 사항 (1번): 사라지던 assembly = ret 뒤 align 패딩 "nop".
**우리 동작이 원래 맞음** — 함수 end를 symtab size로 잡아 패딩이
자연 제외됨 (checkelf의 range_dropped 항목이 정확히 이 nop들).
사용자가 자기 시뮬레이터를 우리 쪽에 맞춰 nop 제외하기로 결정 →
이 diff 항목은 "설명된 차이"로 종결. --debug-roots 결과는 다음 회신.

## 6e. v0.18.0 — reader 병목 (사용자 실측: reading 550.4s vs engine 9.6s)
사용자 파이프라인 = FST → fst2vcd 전체 변환 → 전 신호가 담긴 거대 VCD를
파싱 (추적 신호는 2~3개, 나머지 95%+ 라인은 skip). 대응 3종:
1. **skip 경로 재작성** (iter_commit_changes): 미추적 라인이 strip+
   split+int 파싱을 타던 것을 → 무할당 endswith(튜플) 1회로 기각
   (인라인 루프). 노이즈 dump 벤치 19→127 MB/s (**6.5배**).
   사용자 550s → 85~120s 예상. CR/LF·탭·선행공백 방언은 fallback 유지.
2. **추출 스트림 캐시** (waveform.py _stream_cache_*): 첫 pass에서
   (tick,pc,epc)를 바이너리(.wsc, tempdir/wavescope-cache/, 키=파일
   size+mtime+신호명+모드)로 tee 기록, 이후 실행·--engine both 2차
   pass는 재파싱 없이 replay (읽기 7.6M samples/s — 80M도 ~10초).
   --no-stream-cache로 비활성. 출력 동일성 검증 완료 (cmd: 라인 제외
   byte-identical). 원자적 rename, 미완주 시 tmp 폐기.
3. --timing에 open/convert 시간 분리 표시 (fst2vcd 변환이 여기 잡힘 —
   변환 캐시가 안 먹는지 다음 회신에서 확인 가능).
근본 조언 (사용자에게 전달): C++ 시뮬레이터가 FST를 만들 때 **pc/epc/
clock만 dump**하도록 제한하면 변환·파싱 모두 수십 배 절감 — 소스에서
줄이는 게 최선.

## 6d. v0.17.0 — 사용자 3차 리포트 대응 (sim/legacy 공통 inclusive 불일치)
1. 속도: --timing (reader vs engine 분리 측정 + 2M 샘플마다 heartbeat).
   실측 결과 병목은 reader가 아니라 **엔진** (3M 샘플: read 4~6s vs
   engine 18~19s) → pc별 정적 사실(classify/direct_target/func_at/
   entry) memoization으로 legacy 18.1→7.3s, sim 19.0→10.9s.
   sim이 아직 느린 건 commit당 update() 함수호출 4~7회 오버헤드 —
   추가 최적화 여지 있음. --engine both는 2-pass임을 사용자에게 상기.
2. 함수 마지막 assembly line 소실: 이 컨테이너의 gcc-13 objdump로는
   재현 불가 (-d/-dl 모두 118/118 완전 타일링) → 사용자 objdump 방언
   의존. **wavescope checkelf --elf fw.elf** 신설: 그쪽 머신에서
   파싱 실패 원문 라인 / 함수 범위에서 떨어진 insn / size 타일링 갭 /
   end 불일치를 원문과 함께 출력 → 회신 받으면 방언 특정 가능.
   재현 안 되면 사용자 dump 알고리즘 수신 예정.
3. jcnd 출력 오름차순 (9/27 → 18/27) 완료.
4. _start→SYS_BSP_reset inclusive 과소: --debug-roots 신설 (양 엔진,
   depth≤3 frame push/pop을 tick·사유와 함께 최대 40건 + 종류별 계수;
   빈 스택 tail은 "tail-noframe"으로 명시). ★ 핵심 가설: 그 진입이
   j/tail이고 trace 시작 시 스택이 비면 **레퍼런스 자체가**
   `if (!call_stack->empty())` 가드로 frame 없이 count만 기록 →
   inclusive 0. 시뮬레이터도 같아야 하는데 사용자 쪽이 크게 나온다면
   실제 코드가 레퍼런스와 다르거나(가드 없음?) 진입이 jal(CALL)임.
   회신 요청: --debug-roots 출력 + _start의 해당 호출 assembly 1줄.

## 6c. sim 엔진 (v0.16.0에서 전사 완료 — wavescope/simcore.py)

레퍼런스를 문자 그대로 전사한 SimProfiler (상태명·제어흐름·quirk까지
동일: update/update_epc/update_branch/check_branch_type/handler_branch/
wfi 핸들러/remain_call_stack_process). 사용법:
  wavescope profile ... --engine sim        # sim 출력
  wavescope profile ... --engine both       # sim 출력 + <out>.legacy +
                                            # 엔진 간 발산 요약(stderr)
Feeder 어댑터 3개만 존재 (코드에 ADAPTER 표시): A1 taken은 다음 commit
착지로 1-commit 지연 판정(트랩 개입 시 taken bool만 오염 가능 — 착지
자체는 resume 재해석으로 정확), A2 prev_epc는 첫 commit의 정의값으로
baseline(중간 정의는 첫 trap), A3 epc 미정의 시 update_epc 생략.
재현된 quirk: Q1 update_epc의 infos_[pc] operator[] 삽입 버그.
sim 미지원: --isr-level(ARM), --no-isr-clamp, healing/anomaly 진단,
--debug-func (legacy 전용, both로 병행 가능).

★★ 전사가 즉시 드러낸 레퍼런스 의미론 (사용자와 논의 필요):
`jal ra,__riscv_restore_0` 에필로그는 non-tail CALL entry를 만들고,
restore의 ret에서 RETURN은 그 entry "하나만" pop (tail-chain while은
is_tail에서만 연쇄) → 호출한 함수 자신의 frame은 늦게(상위의 tail
chain에서) 닫혀 arc inclusive에 caller의 복귀 후 명령들이 섞임.
시뮬레이터도 동일하게 동작할 것 — 사용자 자기 수치(1104)에도 restore
call이 빠져 보인다는 보고와 정합 가능성. tests/test_simcore.py의
test_jal_restore_late_flush가 이 의미론을 고정, legacy와의 발산은
test_jal_restore_divergence로 가시화. 검증: tail형 에필로그 클린
trace에선 두 엔진 arc/이벤트 완전 일치 (합성+실물 ELF 모두).

### 정보 회신 기록 (2026-07-18 사용자 답변)
1. Group 멤버십 = 현행 classifier 유지 (jal t0 = CALL 확정)
2. update_branch 전문 수신 (전사 반영)
3/4. check_branch_type/handler_branch/remain 생략부 없음 확정
5. FunctionType: 이름에 __riscv_save "포함"→SAVE_HELPER,
   __riscv_restore 포함→RESTORE_HELPER (contains, prefix 아님)
6. update_epc/wfi 수정본 없음  7/8. 심볼라이제이션·writer 현행 유지
9. ARM은 시뮬레이터에 없음 (추후 추가) — riscv 우선
- golden pack: 폐쇄망이라 불가 → push→사용자 실행→회신 루프 유지

## (구) 준비 체크리스트

방침 확정: 의미론 계층을 simulator_reference와 라인 대조 가능한 문자
전사본(simcore)으로 새로 작성, reader 계층 공유, --engine sim|legacy
기간 한정 투트랙, golden diff 후 sim 승격. 제약: 사용자 테스트 환경은
폐쇄망 (git pull만 가능, push 불가) → 모든 자료는 채팅 텍스트로 수신,
검증은 "우리가 push → 사용자 실행 → 결과 회신" 루프.

사용자에게 요청한 정보 목록 (회신 오는 대로 여기에 체크):
[ ] 1. Group 멤버십 정의 (decode.belong_to): BRANCH/JUMP/CALL/
       INDIRECT_JUMP/DIRECT_JUMP/LOAD/STORE 각각의 명령 목록. 특히
       ret·jr의 JUMP 여부(=Bi/Bim 부과), jal t0의 CALL 여부, c.* 압축,
       amo(Dr/Dw?), fence/csr, mret 분류
[ ] 2. update_branch() 전문
[ ] 3. check_branch_type()/handler_branch()의 레퍼런스 생략부:
       real_caller 치환 전체, save helper 특수 처리 전체
[ ] 4. remain_call_stack_process() 전문
[ ] 5. isCompilerHelper()/FunctionType 판정 정확한 코드
[ ] 6. update_epc()/wfi 핸들러 최신본 (레퍼런스 이후 수정분)
[ ] 7. 심볼라이제이션: pc→(func,file,line) 생성 방법, 별칭(restore_0~3
       동일 주소) 이름 선택, static 중복명, size 0 심볼 범위, demangle
[ ] 8. writer 상세: 함수 출력 순서, 미실행 함수 표기, positions 설정,
       subposition 절대/상대, summary: 형식, cfl/cfn/calls 순서,
       jump/jcnd 라인 사용 여부·형식, 이벤트 이름 문자열
[ ] 9. 알려진 시뮬레이터 버그 목록 + 재현/수정 정책
[ ] 10. Bcm: sim 내부 상태로도 불필요한지 최종 확인
[ ] 11. ARM(M4/M35P)도 같은 시뮬레이터로 프로파일하는지
[ ] 12. 초소형 golden (폐쇄망 대응): 우리가 레포에 작은 test FW를
        올리면 사용자가 시뮬레이터로 돌려 (a) callgrind 출력 전문
        (b) 가능하면 update_profile 진입부 fprintf 패치로 commit 트레이스
        (pc,cycle,epc CSV) 앞부분 수천 줄을 채팅으로 회신
        → 이것이 확보되면 offline 수렴 가능 (인터랙션 최소화)

## 7. 로드맵 (미착수)

- **ISA별 exception 신호** (타깃 확정: 사용자 = RISC-V e24 +
  **Cortex-M4, Cortex-M35P**):
  - Cortex-M4/M35P: ★ v0.12.0에서 --isr-level로 구현 완료 (위 표 참조;
    M4=ARMv7E-M, M35P=ARMv8-M Mainline — IPSR 의미론 동일, Secure/
    Non-secure 뱅킹은 IPSR에 영향 없음). 미구현 잔여: IPSR 신호도 dump에
    없을 때의 vector table(__Vectors) 기반 진입 휴리스틱 (--vector-table
    로드맵), scan에 ipsr/psr 이름 랭킹.
  - AArch64: ELR_EL1/EL2/EL3가 mepc 등가 (resume 주소) — 현행 --epc
    그대로 동작할 것. scan epc 랭킹에 elr 토큰 추가만 하면 됨.
  - epc 검토 표준 절차 (사용자 안내용): ① scan 이름 랭킹 → ② scan
    --check-epc 행동 검증 (CSR array면 'wavescope signals --grep csr'로
    원소 나열 후 --check-epc name1,name2 직접 지정) → ③ profile 실행 후
    진단 수치 확인 (isr_open≈0, spurious 소수, flow_anomalies 감소) →
    ④ 신호 부재 시 휴리스틱 fallback (+ 위 vector-table 로드맵).
- --mispredict-signal: Bcm을 시뮬레이터 정의(misprediction)로 맞추기 —
  v0.8.0의 multi-signal(aux) 인프라로 signal 추출은 이미 가능,
  branch commit과 mispredict pulse의 파이프라인 시차 정렬이 과제 (이슈 6.2)
- lcov coverage export (--lcov) → 다중 시나리오 병합 coverage
  (같은 binary=주소 병합, 다른 binary=소스라인 병합; MoveMyCode에
  N개 파일 로드 시 coverage 전용 모드 — 대화에서 방향 합의됨)
- MoveMyCode 연동: Electron이 wavescope CLI spawn (scan --json →
  후보 UI → profile 실행). WaveScope 쪽 준비물은 --json/진행률 출력.
- tarmac/Spike/QEMU 로그 입력 reader (waveform.py에 추가하는 형태)
- FST native 지원, libnffr ctypes 바인딩
- multi-hart (hart별 PC signal → 병합 출력)
- Cortex-M EXC_RETURN(0xFFFFFFFx) 매직 값 기반 exception 복귀 감지

## 8. 참고 사항

- ESWD/tarmac 대비 포지셔닝 논의 완료: WaveScope의 니치 = 사후(post-hoc)
  분석, RISC-V/custom core, 라이선스 free CI, 오픈 포맷. Indago ESWD는
  tarmac trace 기반(ARM+Cadence 종속)으로 확인.
- FSDB 도구 플래그는 Verdi 버전별 상이 → --fsdbreport-args/--fsdb2vcd-args
  override 제공. 실환경 미검증.
- TRN/SHM(Cadence)은 simvisdbutil 변환 경로 (--cadence-bin/$XCELIUM_HOME/
  $CDS_ROOT/PATH 탐색, --simvisdbutil-args override). 역시 실환경 미검증.
- **라이선스 큐 환경 대응 (v0.7.1)**: EDA 도구(fsdbreport/fsdb2vcd/
  simvisdbutil)는 자식 프로세스로 실행되며 환경변수(LM_LICENSE_FILE 등)
  상속 → 라이선스 요청/큐 대기는 도구 자신이 수행, timeout 없음.
  사이트 wrapper 스크립트 지정용 --fsdbreport-bin/--fsdb2vcd-bin/
  --simvisdbutil-bin (탐색보다 우선). FSDB/TRN→VCD 변환 캐시
  (원본보다 최신이면 재사용, scope별 분리, --reconvert로 강제) —
  반복 분석 시 라이선스 재체크아웃 방지.
- 벤더/도구 구분: FSDB=Synopsys(Verdi의 fsdbreport/fsdb2vcd),
  TRN/SHM=Cadence(Xcelium/SimVision의 simvisdbutil, VCD 변환 전용).
  라이선스 필요 도구는 이 3개뿐, VCD 경로는 완전 무의존.
  fsdbreport는 signal당 1회 실행(체크아웃 2-3회)이라 큐가 긴 사이트는
  fsdb2vcd 1회 변환+캐시가 유리할 수 있음.
- 사용자 waveform의 PC signal: blk_cpu.riscve24.core.issued.pc (issue
  stage — commit-valid signal 없음. speculative 오염 가능성 인지하고 진행 중).
- GitHub 토큰: 대화마다 새로 받아야 함 (fine-grained, WaveScope repo에
  Contents: Read and write. 작업 후 revoke 권장).
