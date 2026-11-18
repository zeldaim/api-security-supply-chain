# 명세 밖 호출 우선순위 → Wazuh 경보 레벨 (offspec_rules)

[`offspec_triage.py`](offspec_triage.md) 가 명세 밖 (메서드, 경로) 마다 매긴 우선순위(정보 · 낮음 · 중간 · 높음)를 Wazuh 경보 레벨에 반영한다.
기존 Shadow API 룰(`automate/rules/gen_shadow_rules.py`, `automate/portable-workflow/gen_shadow_rules_v2.py`)은 고치지 않고, 그 단계 룰 아래에 엔드포인트별 하위 룰을 붙인다.

## 동작

```
명세 밖 호출 ─ 기존 단계 룰 (응답 코드) ─┬─ 판정 CSV 에 있는 엔드포인트 → 하위 룰: 우선순위로 레벨 재지정
                                          └─ 없는 엔드포인트           → 기존 레벨 그대로
```

| 우선순위 | L1 정찰 (404·405) | L2 발견 (401·403) | L3 악용 (2xx) | L3-E 서버 오류 (5xx) |
|---|---|---|---|---|
| 기존 | 5 | 8 | 12 | 10 |
| 정보 | 3 | 3 | 3 | 3 |
| 낮음 (기존 −3, 최소 3) | 3 | 5 | 9 | 7 |
| 중간 (기존 그대로) | 5 | 8 | 12 | 10 |
| 높음 (기존 +2, 최대 15) | 7 | 10 | 14 | 12 |

- 하위 룰이 이벤트를 가져가면 기존 빈도 룰 F1 · F2(`if_matched_sid` = 단계 룰 ID)가 그 이벤트를 세지 못한다. 그래서 같은 문턱(F1 20회/30초 · F2 10회/60초)의 **보완 빈도 룰**을 `if_matched_group` 으로 같이 만든다.
- 룰 그룹에 `offspec_high` · `offspec_low` 같은 우선순위를 남겨 대시보드에서 우선순위로 거를 수 있다.
- 로그 형식은 기존 룰의 `meta.json` 에서 읽는다(app.log JSON → `field`, 접근 로그 → `protocol`/`url`/`srcip`).

## 실행

```bash
# 1) 기존 Shadow API 룰과 meta.json (이미 있으면 생략)
python automate/rules/gen_shadow_rules.py build --spec openapi.yaml --out 0915-shadow_api_rules.xml --meta rules_meta.json --cases base_cases.jsonl
# 2) 판정 CSV
python standardize/policy/offspec_triage.py --spec openapi.yaml --baseline baseline_v2.csv --log app.log --out-dir triage/
# 3) 우선순위 룰
python standardize/policy/offspec_rules.py --triage triage/offspec_triage.csv --meta rules_meta.json \
       --out 0916-offspec_priority.xml --cases offspec_cases.jsonl --map offspec_map.csv
# 4) 검증
python standardize/policy/offspec_rules.py check --rules 0916-offspec_priority.xml --meta rules_meta.json --cases offspec_cases.jsonl
bash   standardize/policy/logtest_offspec.sh 0915-shadow_api_rules.xml 0916-offspec_priority.xml offspec_cases.jsonl
python standardize/policy/offspec_rules.py replay --rules 0916-offspec_priority.xml --meta rules_meta.json app.log
```

배포: 두 XML 을 `/var/ossec/etc/rules/` 에 넣고 `systemctl restart wazuh-manager`. 0916 이 0915 의 단계 룰 ID 를 참조하므로 함께 넣는다.

## 검증 (2026-11-18, 팀 웹 데이터)

입력: 팀 웹 명세(작업 16개) · 기준선 v2 · app.log 36만 줄 → 판정 15개(높음 2 · 낮음 13) → 룰 62개(100600~100661).
결과 파일: [`results/offspec_rules_2026-11-18/`](results/offspec_rules_2026-11-18/)

| 검증 | 결과 |
|---|---|
| XML 해석 재현 (`check`) | 86/86 일치 |
| 실제 Wazuh 4.14.6 `wazuh-logtest` (Docker) | 룰 로드 오류 없음 · **87/87 일치** (빈도 보완 F2: 같은 IP 2xx 10회째 레벨 14 포함) |
| 실제 로그 재판정 (`replay`, 단건 · 빈도 룰 제외) | 아래 표 |

| 레벨 | 기존 | 우선순위 반영 |
|---|---|---|
| 14 | 0 | 15,177 |
| 12 | 15,177 | 0 |
| 10 | 62 | 101 |
| 8 | 251 | 196 |
| 7 | 0 | 52 |
| 6 | 6,019 | 6,019 |
| 5 | 277,254 | 277,218 |

- 명세 밖 성공 응답(2xx) 15,177건은 모두 '높음' 엔드포인트(`GET /api/v1/users/{id}` BOLA · `GET /api/v1/diagnostics/ping` RCE)였다 → 12 → 14.
- '낮음'(존재 불명) 엔드포인트 이벤트 16건이 내려갔다 (5xx 10→7 11건, 401·403 8→5 5건).
- 레벨 5인 27만 건은 스캐너의 없는 경로 404 다. 판정에서 자산이 아니라고 뺀 경로라 하위 룰이 없고 기존 레벨이 유지된다.

시험 중 발견: 케이스를 모두 같은 IP 로 넣으면 `wazuh-logtest` 세션 안에서 빈도가 누적돼 보완 빈도 룰이 20번째 L1 · 10번째 L3 부터 끼어든다(첫 실행 65/77). 단건 케이스는 IP 를 다르게 두고, 빈도는 따로 시험하도록 바꿨다.

## 한계

- 실제 데이터에서 레벨이 바뀐 건 '높음'(올림)과 '낮음'(내림)뿐이다. '정보' · '중간'은 팀 데이터에 해당 엔드포인트가 없어 시험 케이스로만 확인했다.
- 판정은 실행 시점의 스냅숏이다. 새 명세 밖 엔드포인트는 다시 판정 → 다시 생성하기 전까지 기존 레벨로 경보된다.
- 같은 출발지의 빈도는 판정된 엔드포인트와 안 된 엔드포인트가 따로 세진다(기존 F1 · F2 와 보완 F1 · F2 가 나뉨). 섞여 들어오면 문턱에 늦게 닿을 수 있다.
- 3xx · 400 · 422 등 '기타' 응답(기존 레벨 6)은 단계 룰이 아니라 명세 밖 판정 룰에서 끝나서 우선순위를 반영하지 않는다.
- 접근 로그 형식(crAPI)은 생성만 지원하고 logtest 로 확인하지 않았다 — crAPI run3 은 명세 밖 판정 대상이 0개였다.
