# WaveScope — Project Notes (대화 인수인계용)

> 새 대화 시작 시: 이 파일과 README.md를 먼저 읽고 이어서 작업.
> 마지막 업데이트: 2026-07-16, v0.11.0

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
| v0.11.0 | ① clockless 적응형 period: CMU/DVFS 중간 주파수 변화 감지·재잠금 (off-grid delta 트리거, 이슈 6.5 = cycle 과소 측정의 1차 원인 수정), 명시 --clock-period 시 off-grid 1회 경고 ② scan --check-epc: epc 후보 행동 검증 (변화값의 .text 적중 / PC 불연속 동시성 / 이후 resume commit — 이름 무관, CSR array 원소도 이름 직접 지정 가능) + verdict |
| v0.10.0 | 사용자 포맷 요구 반영: ① coverage 방출 — ELF code 영역 전체 insn을 zero-cost라도 표기 (미실행 code vs 컴파일 제외 code 구분용; --executed-only로 비활성) ② jump 라인 순서 = cost 라인 → jcnd/jump → position-only 라인(0xPC LINE) 반복 ③ cond branch 양방향 기록 (taken + fall-through, jcnd=30/100·70/100 합=실행수, 분모=방향 합) ④ IndJmp/DirJmp 이벤트 제거 (8개) |

테스트: 97개 통과 (tests/). 실 ELF 통합 테스트 포함 (호스트 gcc).

## 6. 미해결 / 검증 대기 이슈 ★ 다음 대화의 시작점

1. **inclusive 값 이상 (최우선)** — ★ v0.9.0에서 유력 원인 수정:
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
5b. **clock dump 권고 판단** — 사용자 질문("clock을 전달해야?")에 대한
   결론: 이번 케이스(빨라짐)는 clockless 적응형으로 충분. 단 (a) CMU가
   느려지는 방향(정배수)도 쓰거나 (b) 전환이 잦아 relock window(64
   commit) 내 오귀속이 신경 쓰이면 core clock 1-bit dump + --clock이
   유일하게 정확 (cycle = edge count, 주파수 변화에 무관). mcycle CSR
   dump는 multi-bit가 매 cycle 토글이라 clock보다 비쌈 — 비추.
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

## 7. 로드맵 (미착수)

- **ISA별 exception 신호 일반화 (설계 완료, 미구현)**:
  - AArch64: ELR_EL1/EL2/EL3가 mepc 등가 (resume 주소) — 현행 --epc
    그대로 동작할 것. scan epc 랭킹에 elr 토큰 추가만 하면 됨.
  - ARM Cortex-M: epc 없음. IPSR(xPSR[8:0], 현재 exception number)이
    최적 신호 — **레벨 의미론**이라 새 모드 필요 (--isr-level-signal:
    진입 = 0→비0 또는 값 변화(선점/중첩), 복귀 = 이전 값 복원).
    resume 주소는 신호에 없으므로 saved pending의 fallthrough/target
    추정 + 복귀 착지 매칭(HW가 EXC_RETURN으로 정확히 복귀). IPSR도
    없으면: ELF vector table(__Vectors/주소 0)에서 handler entry 집합
    추출 → "call 없이 handler entry 착지" 진입 휴리스틱 강화
    (--vector-table 옵션 후보). PC 스트림의 0xFFFFFFFx(EXC_RETURN)
    출현도 exit marker로 활용 가능.
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
