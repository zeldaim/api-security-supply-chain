# ML BOLA 탐지 — 최종 보고 v1.0 (2026-11-18, 기능 동결)

> **여기서 끝낸다.** 새 특징 · 새 모델은 더 넣지 않는다. 아래 숫자는 결과가 나쁜 것도 그대로 둔다.
> 다음 단계는 질문이 다른 새 작업(방어 연습 레포)으로 따로 한다.

## 무엇을 하는 모델인가

| 항목 | 내용 |
|---|---|
| 목적 | 명세 **안의** API 로 남의 객체를 훑는 BOLA 를 잡는다. 명세 **밖** 호출은 Shadow API 룰(Wazuh)이 맡는다 |
| 입력 | 웹 접근 로그(combined) → IP × 5분 창 → 특징 13개 (`automate/portable-workflow/features.py`, v2.1 은 `automate/portable-workflow-v2.1/features.py`) |
| 특징 예 | `seq_id_run`(연속 ID 길이) · `id_span_log`(서로 다른 객체 수) · `err_ratio` · `offspec_ratio` · `gap_mean_log` — **IP 는 특징이 아님** |
| 모델 | IsolationForest, 대상 앱의 **정상 트래픽만**으로 학습 (오류 많은 창 · 룰이 잡는 창은 학습에서 뺌) |
| 판정 | 점수 < high 기준 → high, < medium 기준 → medium |
| 배포 조건 | 평가 게이트: 조용한 정상 창 ≥ 50, high 오탐 ≤ 2%, 합성 변종 V1(순차) · V5(아주 느림) 탐지 |
| 이식 | 코드는 그대로, 앱마다 `config.env`(명세 경로 · 로그 · `BOLA_TARGETS`)만 바꾼다 |

## 앱별 결과 (전부)

| 앱 | 개발에 썼나 | Shadow 룰 (실제 Wazuh) | ML 게이트 | 실제 BOLA | 정상 오탐 (학습 안 쓴 정상) |
|---|---|---|---|---|---|
| **팀 웹** (PHP 쇼핑몰) | ✅ 원본 | 서명 룰 · 명세 대조 룰 운영 | — (운영 모델) | 5분 창 high 61/116 (53%), medium+ 92/116 | 0/44 · **ML 만 잡은 공격 창 0/5** |
| **crAPI** (3차, 모델 B) | v2 를 이걸 보고 고침 | 72/72 → v2.1 75/75 | ✅ 통과 (76창 high 0) | 주문 · 보고서(쿼리 ID) · 차량(UUID) BOLA 13창 high 12 · medium 1 | 재생 정상 120창 high 3 (모델 A 는 **115/120**) |
| **VAmPI** | v2.1 을 이걸 보고 고침 | v2 실패(48/49) → v2.1 52/52 · 탐색 14/15 · 정상 0/362 | 돌리지 않음 (정상 12창뿐) | 특징만 확인: 서로 다른 객체 17개 vs 정상 최대 2개 | — |
| **DVRA** (2차) | ❌ **처음 보는 앱** | 116/118 (실패 2 = 시험 케이스 버스트) · 탐색 15/15 · 정상 2/355 (`/docs`) | ❌ **근소 실패** (49창 < 50 · 오탐 4.1%) | **high** · 변종 V1·V2·V3·V5 40/40 | **다른 세션 정상 180창 high 0** |

자세한 숫자: 팀 웹 (작업 레포 비공개 — 팀 원본 로그 사용) · crAPI [`verify/crapi/03_run3_vehicle_bola_replay.md`](../verify/crapi/03_run3_vehicle_bola_replay.md) · VAmPI [`verify/vampi/`](../verify/vampi/v2_run_2026-11-18/README.md) · [`automate/portable-workflow-v2.1/`](../automate/portable-workflow-v2.1/README.md) · DVRA 룰 [`verify/dvra/rules_2026-11-18/`](../verify/dvra/rules_2026-11-18/README.md) · DVRA ML [`verify/dvra/ml_run2_2026-11-18/`](../verify/dvra/ml_run2_2026-11-18/README.md)

## 말할 수 있는 것

1. **설정만 바꿔 처음 보는 앱(DVRA)에 적용했고, 실제 BOLA 를 high 로 잡았다.** 숫자 ID · 쿼리 ID(crAPI 보고서) · UUID(crAPI 차량) BOLA 를 모두 잡았다.
2. **회피 변종에 강하다:** 순서 섞기 · 여러 API 분산 · 60~110초 간격 느린 열거를 DVRA 에서 40/40 high.
3. **학습과 다른 세션의 정상**(DVRA 1차 앞부분 180창)에서 high 오탐 0.

## 말할 수 없는 것 (한계)

1. **팀 웹에서 ML 이 룰보다 더 잡는다는 근거는 없다.** 룰이 못 잡은 공격 창 5개 중 ML 이 잡은 것 0.
2. **정상 트래픽 대부분이 기계가 만든 것이다.** 규칙 정상으로만 학습한 모델은 사람 속도의 정상(공개 데이터 재생)을 **거의 전부 오탐**했다(crAPI 모델 A 115/120). 재생 정상을 학습에 넣어야 줄었다(3/120). DVRA 에는 재생 정상이 없다.
3. **1 IP = 1 사람, 공격 IP 는 공격만 한다.** 공격자가 정상 행동에 섞으면 high 비율이 떨어진다(DVRA V4 31/40, V7 결합 4/40 — medium+ 로는 37~40/40).
4. **IP 를 여러 개로 나누면 못 본다**(V6: 창당 요청 5건 미만 → 판단 불가).
5. **DVRA 게이트는 통과하지 못했다.** 기준을 낮추지 않았다.
6. 공격은 앱마다 같은 생성기로 1~2회다. 통계적으로 강한 주장은 못 한다.

## 실행하다 생긴 문제와 교훈 (기록)

| 문제 | 원인 | 이후 |
|---|---|---|
| DVRA 1차 무효 | 토큰 30분 만료, 생성기가 다시 로그인하지 않음 | 재로그인 래퍼 · 시작 전 만료 시험 · 만료 직후 상태 코드 점검 |
| v2.1 학습 단계 `ModuleNotFoundError: _shim` | `runpy` 가 v2 폴더를 경로에 넣지 않음 | 실행 시 `PYTHONPATH` (기존 파일 무수정) |
| 커밋한 `.gz` 손상 | `.gitattributes` 의 `e2e_story/** text eol=lf` | 폴더별 `*.gz binary` |
| Docker Desktop 읽기 전용 오류 | WSL 디스크 상태 | 재부팅 |

## 다음 (이 모델 밖에서)

- 방어 연습 레포: 앱 + 정상 · 공격 로그 + 정답지 + Wazuh/Sigma 룰 + 이 모델의 기준점 — 남이 `docker compose up` 으로 같은 실험을 해 볼 수 있게.
- 사람 속도 정상(재생)을 DVRA 에도 넣는 것은 그 레포에서 한다.
