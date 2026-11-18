# v2.1_portable — 세 번째 앱(VAmPI)에서 막힌 곳만 고친 판 (2026-11-18)

> v2 는 crAPI 를 보고 고친 판이라, 처음 보는 VAmPI 에서는 설정만으로 실패했다([`../../verify/vampi/v2_run_2026-11-18/`](../../verify/vampi/v2_run_2026-11-18/README.md)).
> 이 폴더는 v2 파일을 **한 줄도 고치지 않고**, v2 모듈을 불러와 함수 몇 개만 바꿔 끼운다.

## 고친 것

| | v2 | v2.1 | 파일 |
|---|---|---|---|
| 검사 범위 | `api` 조각이 없으면 명세의 첫 조각들만(`/users`, `/books`) → `/admin` · `/debug` 를 못 봄 | 명세 어디에도 `api` 조각이 없으면 **루트(`/`)와 정적 파일을 뺀 전부** | `features.py`, `gen_shadow_rules_v2_1.py` |
| 명세 대조 | 경로 파라미터는 무엇이든 맞음 → `/orders/export` 가 `{order_id}` 에 흡수 | 명세에 형식이 있으면 그 형식만 (`integer` → 숫자, `uuid` → UUID). 형식이 없으면 v2 와 같음 | 둘 다 |
| 객체 ID | 경로의 숫자 · UUID 만 | `BOLA_TARGETS` 틀의 자리(`{book_title}`)에 들어온 값은 형식과 무관하게 객체로 셈 → `id_span_log`(서로 다른 객체 수)에 잡힘. 특징 이름 · 순서는 그대로 | `features.py` |
| 시험 케이스 | "명세 경로 + 없는 메서드"에 루트 `/` 를 골라 기대값이 틀림 | 검사 범위 안의 경로를 고름. 새 첫 조각 · 명세 문서 탐색 · 형식 밖 값 케이스 추가 | `gen_shadow_rules_v2_1.py` |
| 학습 · 평가 · 변종 | — | `run_v2.py` 가 v2.1 특징을 올려 둔 채 v2 스크립트를 그대로 실행 | `run_v2.py` |
| 워크플로 | — | v2 `bootstrap.sh` 를 복사해 모듈 경로만 바꿈 | `bootstrap.sh` |

## 결과 (실제 Wazuh 4.14.6 `wazuh-logtest`)

| | VAmPI v2 | **VAmPI v2.1** | crAPI v2 | **crAPI v2.1** |
|---|---|---|---|---|
| 설정만으로 룰 단계 | ❌ 48/49 중단 | ✅ **52/52** | ✅ 72/72 | ✅ **75/75** |
| 명세 밖 탐색 재현율 | 9/15 (60%) | **14/15 (93%)** | 10/12 (83%) | **11/12 (92%)** |
| 정상 경보 | 0/362 | 0/362 | 0/400 | 0/400 |
| 명세 안 BOLA (Shadow 룰 경보) | 0/33 | 0/33 | 0/147 | 0/147 |
| BOLA 출발지 서로 다른 객체 수 (`id_span_log`) | 0 (정상과 같음) | **2.89 = 17개** (정상 최대 1.10 = 2개) | — | — |

기록: [`vampi_run_2026-11-18/wazuh_logtest_output.txt`](vampi_run_2026-11-18/wazuh_logtest_output.txt) · [`crapi_check_2026-11-18/wazuh_logtest_output.txt`](crapi_check_2026-11-18/wazuh_logtest_output.txt)

**회귀** (`compare_v2_v2_1.py` — `api` 접두어가 있는 명세 · `BOLA_TARGETS` 없음에서는 v2 와 같아야 함)

| 로그 | 다른 값 |
|---|---|
| crAPI 정상 (108창) | **0** / 1,620 |
| 팀 웹 샘플 `synth.log` | **0** / 30 |
| VAmPI (의도한 변경) | 18 / 210 — `id_span_log` 14 · 범위 3 · `top_tpl_share` 2 |

## 남은 한계

- `/users/v1/_internal` (VAmPI) · `posts/all` (crAPI): 명세 파라미터가 **형식 없는 문자열**이면 명세만으로는 못 가른다.
- 범위가 "정적 파일을 뺀 전부"라서 서버가 그리는 페이지가 많은 앱에서는 확장자 없는 페이지 요청(`/login`, `/cart` 등)도 검사 대상이 된다 — `api` 조각이 없는 명세에서만 이렇게 동작한다. 그런 앱은 `API_SCOPE` 로 직접 지정.
- BOLA 는 특징 값까지만 확인했다. VAmPI 정상이 12창뿐이라 학습 · 평가 게이트는 돌리지 않았다.
- **v1 기준 1 은 아직 통과가 아니다.** v2.1 은 VAmPI 를 보고 고쳤으므로 VAmPI 는 더 이상 처음 보는 앱이 아니다. 개발에 쓰지 않은 네 번째 앱으로 다시 재야 한다.

## 따라 하기

```bash
cd /d/api-security-supply-chain
# VAmPI 와 nginx 앞단 · 트래픽은 verify/vampi/v2_run_2026-11-18/README.md "다시 돌리기" 와 같다
bash verify/vampi/v2_1_run_2026-11-18/run.sh spec && bash verify/vampi/v2_1_run_2026-11-18/run.sh rules
#  예상: 규칙 생성·자체시험 통과 (52/52 …)
S=verify/vampi/v2_1_run_2026-11-18/state L=verify/vampi/v2_run_2026-11-18/logtest_inputs
bash automate/portable-workflow/logtest_accesslog.sh $S/0915-shadow_api_rules.xml $S/rules_meta.json $S/testcases.jsonl $L/lt_probe.log $L/lt_bola.log $L/lt_normal.log
#  예상: 52/52 일치 · lt_probe L1 14 · 경보 없음 1 · 나머지 경보 없음
```
