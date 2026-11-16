# 웹 공격 룰 v2 — 오탐 수정 + 실제 Wazuh 검증 (2026-11-09)

v1(`../rules/0910-shadow_api_threats.xml`)은 **그대로 둔다**(삭제·덮어쓰기 금지 규칙). v2 는 이 폴더에 새 파일로.

## 무엇을 고쳤나

| v1 룰 | 문제 | v2 |
|---|---|---|
| 100904 BOLA 열거 (L12) | `/users/1\|/users/2` 요청 **1건**으로 판정. 변환기가 YARA `2 of them` 을 "앞 2개 OR"로 근사하고 `fullword` 를 버려서 생긴 패턴. "열거"(여러 ID 반복)를 전혀 보지 않음 | 제거 → `0911-bola_enumeration.xml` **빈도 룰**: 같은 IP · 120초 · 서로 다른 객체 URL 10개. **응답 코드로 결과 분리** — 2xx 성공 = L12(자동 차단), 401/403 거부 = L8(알림만) |
| 100905 JWT 조작 (L12) | `eyJhbGciOiJIUzI1NiJ9` = **표준 HS256 헤더**. 정상 토큰과 구분 불가 | HS256 패턴 제거, `alg:none` 만 유지 (100914) |
| 나머지 (SQLi·경로 순회·명령 주입·XSS) | 변경 없음 | ID 만 100910~ 로 이동(v1 과 동시 로드 시 충돌 방지) |

원본: `../../yara/rules/http_attacks_v2.yar` → `python tools/yara_to_wazuh.py --yar api-bom/yara/rules/http_attacks_v2.yar --out api-bom/wazuh/rules_v2/0910-shadow_api_threats_v2.xml --base-id 100910`

## 실제 Wazuh 검증 — `bash api-bom/wazuh/rules_v2/logtest_docker.sh v1|v2`

Docker `wazuh/wazuh-manager:4.14.6` 의 `wazuh-logtest`. 룰 로드 오류 없음. 시나리오는 `test_rules_v2.py` 의 CASES.

| 시나리오 | v1 (실제 Wazuh) | v2 (실제 Wazuh) |
|---|---|---|
| 정상: 자기 프로필 1회 조회 (200) | 0 | 0 |
| 정상: 자기 주문 5건 빠르게 (200) | 0 | 0 |
| 정상: 같은 주문 새로고침 15회 | 0 | 0 |
| 정상: HS256 토큰이 URL 에 실린 요청 | **L12 (100905) → 자동 차단** | 0 |
| 공격: 빠른 BOLA 성공 20개 (200) | **0 — 미탐** | **L12 (100923) ×2** |
| 공격: 빠른 BOLA 거부 20개 (403) | L12 (100904) ×13 → 자동 차단 | L8 (100924) ×2 → 알림 |
| 공격: alg:none JWT | L12 | L12 (100914) |
| 공격: 명령 주입 | L14 | L14 (100913) |

**v1 BOLA 는 거꾸로 동작했다**: 막힌 시도(403)는 차단하고, 실제로 데이터가 나간 성공 열거(200)는 놓쳤다.
원인 — Wazuh 기본 룰 31108(단순 GET 2xx, level 0)이 깨끗한 200 요청을 먼저 가져가는데 v1 상위 SID 에 31108 이 없다. 403 은 31100 아래에서 v1 에 닿았고 `/users/1`·`/users/2` 부분일치(1, 2, 10~19, 20)로 13건 울렸다.

## 검증하다 찾은 것

- **Wazuh 는 level 0 룰에 걸린 이벤트를 `if_matched_sid` 빈도 집계에 쌓지 않는다.** 처음 v2 는 100921/100922 를 level 0 으로 둬서 20건에도 100923 이 안 울렸다(파이썬 재현은 통과). level 2 로 올려 해결 — log_alert_level(기본 3) 미만이라 alerts 에 안 남는다.
- **파이썬 재현(`tools/rule_fp_check.py`)은 Wazuh 기본 룰 트리를 모델링하지 않는다** → v1 을 과대 집계한다(예: 200 단일 조회에 v1 L12 로 나오지만 실제는 0). 기준은 logtest. 재현기는 큰 로그를 빠르게 훑는 1차 용도.

## 한계 (그대로 적는다)

- **정상 트래픽 오탐률은 아직 못 쟀다.** 팀 웹 실제 로그(168만 줄)는 그 PC·VM 에만 있다. 레포 안 정상 데이터(`e2e_story/eval/sessions/B_normal.jsonl` 40세션, 합성)에서는 v1·v2 모두 경보 0 — 데이터가 작고 합성이라 근거로 약하다. → 실제 로그로 `python tools/rule_fp_check.py --log <access.log>` 1차, 그다음 logtest.
- **임계값 10개/120초는 근거 없는 출발값이다.** 정상 사용자의 "서로 다른 객체 조회" 분포를 실제 로그로 보고 정해야 한다.
- **느린 열거는 못 잡는다.** eval 세션(16~20초 간격)은 v2 BOLA 에 0건 — 설계상 ML(`e2e_story/wazuh/0920-ml_anomaly.xml`) 몫. IP 분산(V6)은 둘 다 못 잡는다.
- **명령 주입 100913 의 `;id` · `;ls` 는 단어 경계가 없다** (`;identity` 도 일치). 실제 로그에서 오탐이 나오는지 보고 고친다 — 데이터 없이 미리 바꾸지 않았다.
- 시나리오 기대값은 내가 정했다 → 독립 검증 아님.

## 배포 (아직 안 함)

`response/lab/deploy.sh` 는 여전히 v1 을 복사한다. v2 로 바꾸려면 실제 로그 오탐 확인 후:
```
sudo cp 0910-shadow_api_threats_v2.xml 0911-bola_enumeration.xml /var/ossec/etc/rules/
sudo rm /var/ossec/etc/rules/0910-shadow_api_threats.xml   # v1 과 동시 로드 금지 (같은 공격에 이중 경보)
sudo systemctl restart wazuh-manager
```
`deploy_wazuh_rules.sh`(이 폴더)는 변환기가 자동 생성한 것으로 0910_v2 만 다룬다 — 0911 은 위처럼 함께 복사.
