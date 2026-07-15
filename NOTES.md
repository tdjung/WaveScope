# WaveScope — Project Notes (대화 인수인계용)

> 새 대화 시작 시: 이 파일과 README.md를 먼저 읽고 이어서 작업.
> 마지막 업데이트: 2026-07-09, v0.6.1 (commit ec0fded)

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
├── fsdb.py             # Verdi fsdbreport(신호별 추출 우선) / fsdb2vcd(--fsdb-scope)
├── trn.py              # Cadence TRN/SHM → simvisdbutil로 VCD 변환 (v0.7.0, 실환경 미검증)
├── waveform.py         # 입력 디스패치 (vcd/fsdb, clocked/clockless)
├── scan.py             # PC/clock signal 후보 랭킹 (ELF text range 매칭 0.55
│                       #   + stride + 이름 + 폭). --json, --explain, signals 서브커맨드
├── profiler.py         # ★ 핵심. 아래 3절 참조
├── callgrind.py        # writer. calls 키 = (call_pc, callee) 순수 PC.
│                       #   기본으로 ELF 전 함수 emit (미실행은 zero-cost, coverage용)
└── cli.py              # 서브커맨드: scan / signals / profile
```

CLI 예시:
```sh
wavescope profile --wave all.vcd --elf fw.elf \
  --pc blk_cpu.riscve24.core.issued.pc \
  --isa riscv --toolchain-prefix riscv64-unknown-elf- -o callgrind.out
# clock signal 불필요 (clockless 모드), --clock-period로 override 가능
```

## 3. profiler.py 핵심 의미론 (시뮬레이터와 맞춘 것들)

- **이벤트 (10개)**: Ir Cy Bc Bcm Bi Bim IndJmp DirJmp Dr Dw.
  Call/TailCall 이벤트 컬럼은 사용자 요청으로 제거 (v0.6.0). call 추적은
  frame/calls map으로 구조적으로 유지.
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
- **exception/ISR**: mepc signal이 없으므로 휴리스틱 감지 —
  "architectural하게 도달 불가능한 successor" (plain insn: next≠fallthrough;
  direct jump: next≠target; cond br: next∉{target,fallthrough}).
  resume PC 기억, mret/sret/uret(또는 resume 복귀)에서 handler 내 frame
  unwind. sleep gap은 첫 handler insn 도착 시 1로 clamp (first_isr_cycle
  대응, --no-isr-clamp로 해제). indirect jump 직후 인터럽트는 원리적으로
  감지 불가.
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

테스트: 62개 통과 (tests/). 실 ELF 통합 테스트 포함 (호스트 gcc).

## 6. 미해결 / 검증 대기 이슈 ★ 다음 대화의 시작점

1. **inclusive 값 이상 (최우선)** — v0.6.0/0.6.1 재테스트 결과 대기 중.
   사용자도 자기 알고리즘 코드를 병행 검토 중. 남은 구조적 차이 후보:
   - return pop 정책: 시뮬레이터=무조건 top pop vs WaveScope=매칭+healing.
     setjmp/context switch/RTOS task 전환이 있으면 여기서 갈림.
   - 판별법: stderr 진단의 unmatched 수와 "frames alive at end" 상위
     함수명을 받아서 추적하기로 함.
   - 사용자가 "구조 변경을 아직 많이 해야 할 것 같다"고 언급 —
     profiler.py 구조 리팩토링 논의 예상.
2. **Bcm 정의 차이 (설계 결정 필요)** — WaveScope=architectural taken,
   시뮬레이터=misprediction. waveform에 mispredict/flush signal을 추가
   dump하면 맞출 수 있음 (--mispredict-signal 옵션 후보).
3. **함수 개수 검증** — v0.5.0 이후 "functions: N in ELF" 수치가
   시뮬레이터의 2000+와 맞는지 확인 대기.
4. **ceiling/max call 누락** — 키 수정(v0.6.0)으로 해결 예상이나 재확인
   대기. 남으면 인라이닝 여부를 objdump로 확인 (jal 부재 = 인라인).
5. **cycle 재검증** — sw 4개 = Ir 1337, Cy 2858/1715/1721/1719 패턴
   재현 여부 (v0.6.0 도착 귀속의 직접 검증 케이스).
6. **indirect jump 직후 인터럽트** 감지 불가 — mepc/trap signal dump
   옵션(--trap-signal) 검토.

## 7. 로드맵 (미착수)

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
- 사용자 waveform의 PC signal: blk_cpu.riscve24.core.issued.pc (issue
  stage — commit-valid signal 없음. speculative 오염 가능성 인지하고 진행 중).
- GitHub 토큰: 대화마다 새로 받아야 함 (fine-grained, WaveScope repo에
  Contents: Read and write. 작업 후 revoke 권장).
