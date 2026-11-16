# v2_portable — 다른 앱에도 쓸 수 있게 고친 탐지 워크플로 (2026-11-16)

> crAPI 검증([`../crapi_generality_2026-11-15/`](../crapi_generality_2026-11-15/README.md))에서 "설정만 바꿔서는 다른 앱에서 안 돈다"가 확인됐다.
> 이 폴더는 그때 막힌 곳만 고친 새 파일들이다. **기존 파일은 한 줄도 고치지 않았다** (`e2e_story/ml/`, `e2e_story/eval/`, `e2e_story/bootstrap.sh`, `team_src/` 그대로).

## 결과 요약 (같은 crAPI 데이터, 수정 전 → 후)

| 항목 | 수정 전 (원본) | 수정 후 (v2) |
|---|---|---|
| 룰 생성 단계 | 자체 시험 61/64 로 중단 | 통과 72/72 |
| 생성된 Shadow API 룰 (실제 Wazuh 4.14.6 `wazuh-logtest`) | crAPI 요청에 한 번도 안 걸림 | 케이스 72/72 일치 · 명세 밖 탐색 14줄 중 10줄 경보(L1) · 정상 400줄 경보 0 · 명세 안 BOLA 147줄 경보 0 |
| `api_ratio` (API 비율) | 전부 0 | 정상 중앙값 0.88 |
| `offspec_ratio` (명세 밖 비율) | 명세 밖 탐색 창도 0 | 명세 밖 탐색 창 0.71 |
| 보고서 BOLA (`?report_id=N`)의 연속 ID | 0 (못 봄) | 12 · 13 |
| 실제 공격 창 판정 | high 8 · medium 1 | high 8 · medium 1 (같음) |
| 평가 게이트 | 실패 (정상 창 36 < 50) | 실패 (같은 이유 — 데이터 양) |
| 워크플로 전체 | 2단계에서 멈춤 | 1~6단계 실행, 6단계에서 데이터 양으로 중단 |

- 판정 개수는 같지만 **걸린 이유가 달라졌다.** 보고서 BOLA 는 수정 전에는 오류 응답 때문에 걸렸고, 수정 후에는 열거 자체가 보인다. 응답을 전부 200 으로 바꾼 가정 실험(합성)에서도 high 2/2 였다.
- 게이트가 여전히 실패하는 것은 코드가 아니라 수집량 문제다(정상 85분치).

## 무엇을 고쳤나

| 파일 | 원본의 가정 | v2 |
|---|---|---|
| `features.py` | API 경로는 `/api` 로 시작 | 명세에서 범위를 뽑는다 (`/identity/api` 등). `E2E_API_SCOPE` 로 직접 지정 가능 |
| | 명세는 YAML | JSON 명세도 읽는다 |
| | 객체 ID 는 경로의 숫자 | 경로의 숫자·UUID + 쿼리의 ID 파라미터(`id`, `*_id`, `*Id`) |
| `variants.py` | 공격 변종의 대상 경로가 `/api/v2/orders/{id}` 등으로 고정 | 대상 명세와 `BOLA_TARGETS` 설정에서 가져온다. 회피 기법(V1~V7)은 원본 그대로 |
| `gen_shadow_rules_v2.py` | 검사 범위 `^/+api` 고정 | 명세에서 뽑는다 |
| | 앱 JSON 로그(`app.log`) 전용 | `--log-format accesslog` 면 웹 접근 로그용 룰(Wazuh `web-accesslog` 디코더: `url`·`protocol`·`id`·`srcip`) |
| | 자체 시험 케이스에 팀 웹 경로 | 케이스를 전부 대상 명세에서 만든다 |
| `bootstrap.sh` | 평가 결과를 `e2e_story/eval/` 에 덮어씀 | 산출물은 `STATE_DIR` 에만 쓴다 |
| `train.py` · `evaluate.py` · `detect.py` | — | 원본을 그대로 실행하는 얇은 래퍼. v2 특징을 쓰게 하고, 출력 위치를 반드시 지정하게 한다 |

`train.py` 는 모델 메타에 `feature_version: 2` 를 적고, `evaluate.py`·`detect.py` 는 그 표시가 없는 모델을 거부한다. v1 모델에 v2 특징을 넣으면 같은 이름의 값이 다른 뜻이 되기 때문이다.

## 팀 웹에서는 값이 그대로인가 (회귀 확인)

```bash
cd /d/shadow_api_monitoring
python e2e_story/v2_portable/compare_v1_v2.py team_src/web/src/public/docs/openapi.yaml e2e_story/ml/experiments/synth.log e2e_story/eval/sessions/*.jsonl
```
예상 출력: `합계: 값 … 중 0개 다름`.

| 로그 | 창 | 다른 값 |
|---|---|---|
| 레포 안 샘플·평가 세션 11개 | 389 | **0** / 5,057 |
| 팀 웹 실제 접근 로그 (108만 줄, 레포 밖) | 363 | **254** / 4,719 |

실제 로그에서 값이 달라진 이유는 두 가지이고, 둘 다 원본이 못 보던 것이다.

- **쿼리로 ID 를 넘기는 요청:** `/product.php?id=N` 2,298건, `/order.php?id=N` 126건. 원본은 쿼리를 버려서 주문 페이지 열거를 보지 못했다.
- **`/api` 로 시작하지만 API 가 아닌 경로:** `/apis`, `/api.php`, `/api-docs` 등 195건(스캐너). 원본은 이것도 API 로 셌다.

따라서 **팀 웹에서도 v2 특징을 쓰려면 모델을 다시 학습해야 한다.** 기존 운영 모델(`e2e_story/ml/model`)은 원본 특징과 함께 그대로 쓴다.

## 새 설정 키

| 키 | 뜻 | 기본값 |
|---|---|---|
| `STATE_DIR` | 산출물 폴더 | `e2e_story/.bootstrap_v2` |
| `LOG_FORMAT` | `accesslog`(웹 접근 로그) 또는 `applog`(앱 JSON 로그) | `accesslog` |
| `BOLA_TARGETS` | 주인만 봐야 하는 자원의 조회 경로(쉼표 구분). 첫 번째가 게이트의 주 공격 대상 | 비우면 명세의 ID 경로 전부 |
| `API_SCOPE` | 검사 범위 정규식 | 비우면 명세에서 뽑음 |
| `GATE_MIN_QUIET` | 게이트가 요구하는 검증용 정상 창 수 | 50 |
| `CONFIG_ENV` | 읽을 설정 파일 | `e2e_story/config.env` |

`BOLA_TARGETS` 는 사람이 정해야 한다. 어떤 자원이 "주인만 봐야 하는 것"인지는 명세에 없다(게시글은 공개, 주문은 비공개).

## 따라 하기 — crAPI

준비(crAPI 기동, 실행 환경 이미지 `e2e-runner`, 로그·명세)는 [`../crapi_generality_2026-11-15/README.md`](../crapi_generality_2026-11-15/README.md) §1·§6 과 같다.

**1. 워크플로 실행**
```bash
cd /d/shadow_api_monitoring/e2e_story/v2_portable
bash crapi_run_2026-11-16/run.sh all
```
예상 출력: `규칙 생성·자체시험 통과 (72/72 …)`, `학습 243`, 마지막에 `[GATE] ❌ 실패 — … 조용한 정상 창 36개 < 50`. 전체는 `crapi_run_2026-11-16/bootstrap_v2_output.txt`.

**2. 생성된 룰을 실제 Wazuh 로 확인** (Wazuh 이미지 `wazuh/wazuh-manager:4.14.6` 필요, 약 2분)
```bash
W=crapi_run_2026-11-16/logtest_inputs
bash logtest_accesslog.sh crapi_run_2026-11-16/state/0915-shadow_api_rules.xml crapi_run_2026-11-16/state/rules_meta.json crapi_run_2026-11-16/state/testcases.jsonl $W/lt_shadow_probe.log $W/lt_bola_attacks.log $W/lt_normal_400.log
```
예상 출력: `72/72 일치 (실제 wazuh-logtest)`, `lt_shadow_probe.log … L1 10 · 경보 없음 4`, 나머지 두 로그는 `경보 없음`. 기록은 `crapi_run_2026-11-16/wazuh_logtest_output.txt`.
(`logtest_inputs/` 의 세 파일은 2차 실행 로그에서 잘라 둔 것이다: 명세 밖 탐색 14줄, 나머지 공격 147줄, 정상 앞 400줄.)

**3. 실제 공격 창 채점**
```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "D:/shadow_api_monitoring:/repo" e2e-runner bash /repo/e2e_story/v2_portable/crapi_run_2026-11-16/score.sh
```
예상 출력: 공격 9창 중 `high` 8 · `medium` 1, 검증용 정상 54창 중 경보 0. 기록은 `crapi_run_2026-11-16/score_attacks_v2.txt`.

## 이 결과로 말할 수 있는 것 / 없는 것

**말할 수 있음**
- 수정 후 워크플로는 설정만 바꿔 crAPI 에서 끝까지 돈다(게이트는 데이터 양으로 실패).
- 생성된 접근 로그용 Shadow API 룰은 실제 Wazuh 에서 의도대로 판정한다: 명세 밖만 경보, 명세 안 BOLA 와 정상은 경보 없음.
- 쿼리 파라미터로 번호를 넘기는 열거가 특징에 잡힌다.

**말할 수 없음**
- "어떤 앱에서도 된다". 확인한 앱은 팀 웹과 crAPI 둘뿐이다.
- UUID 열거 탐지. 코드는 넣었지만 차량 BOLA 를 실행하지 못해 실제 공격으로 확인하지 못했다.
- 게이트 변종 수치(V4 40/40 등)를 crAPI 탐지 성능으로 읽는 것. 정상이 스크립트 생성기라 분포가 좁아서, 주문 열거가 조금만 섞여도 걸린다. 팀 웹에서는 같은 변종이 18% 였다.
- 오탐률. 정상은 스크립트이고 자기 주문만 연다.
- 접근 로그용 룰의 빈도 룰(F1·F2)은 logtest 로 확인하지 않았다(단건 판정만 확인).
- 팀 웹에서 v2 로 다시 학습한 모델의 성능. 회귀 비교만 했다.

## 다음

1. PC 절전을 끄고 crAPI 정상 120분을 다시 모아 게이트를 통과시키는지 본다.
2. 정상 사용자가 차량을 등록하게 해서 UUID 열거(차량 위치 BOLA)를 실제로 돌린다.
3. 공개 데이터(OTTO, Stack Overflow 세션)로 정상을 재생해 같은 공격을 다시 채점한다.
4. 팀 웹 실제 로그로 v2 모델을 학습해 원본 모델과 같은 평가(`e2e_story/ml/experiments/teamweb_labeled_2026-11-11`)로 비교한다.
