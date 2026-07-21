# WaveScope — Project Notes (대화 인수인계용)

> 새 대화 시작 시: 이 파일과 README.md를 먼저 읽고 이어서 작업.
> 마지막 업데이트: 2026-07-19, v0.20.0

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
