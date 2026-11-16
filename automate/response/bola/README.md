# BOLA 대응 — 계정 정지 + 출발지 IP 차단 (2026-11-10)

## 왜
- BOLA 소유권 룰(`api-bom/wazuh/rules_v2/0912-bola_ownership.xml`, 100930/100931)은 "남의 객체 조회 성공"을 잡지만,
  앱 로그의 출발지가 `data.client_ip`(srcip 아님)라서 v1 rulebook 의 차단 규칙(`data.srcip`)에 걸리지 않고 **알림만** 됐다.
- 또 IP 차단만으로는 BOLA 를 못 막는다. **로그인한 정상 계정**의 공격이라 IP 를 바꾸면 같은 토큰으로 계속한다.
  → 경보에 있는 `user_id` 로 **계정을 정지**한다.
- 팀 구조(Shuffle + block-api)는 BOLA 를 BOLA 로 잡지 않는다: WAF 반복 경로는 BOLA 요청을 의심으로 찍지 않고,
  즉시 탐지(101011)는 "명세 외 API"라서 걸린 것이라 v2 BOLA 는 못 잡는다.

## 흐름
```
app.log ─▶ Wazuh 100930(남의 객체 1건, L10) ─▶ 알림
                 └▶ 100931(5분 3개 이상, L12) ─▶ EDA rulebook v2 ─▶ bola_response.yml
                                                    ├─ ① suspend_account.yml : user_id → 정지 목록(TSV, 60분 뒤 자동 해제)
                                                    └─ ② block_ip.yml        : client_ip → nftables 차단(허용목록이면 건너뜀)
웹 앱 인증 직후 AccountGuard 가 정지 목록 확인 ─▶ 정지 계정이면 403 "정지된 계정입니다" (v1·v2 모두)
```
기본은 `response_mode: notify` — 정지·차단 모두 기록만 한다(dry-run). 실제 적용은 `block`.

## 파일 (전부 새 파일, v1 은 그대로 둠)
| 파일 | 하는 일 |
|---|---|
| `rulebooks/wazuh_alerts_v2.yml` | v1 + 맨 위에 100931 규칙 (user_id 기준 5분 throttle) |
| `playbooks/bola_response.yml` | ① 계정 정지 → ② client_ip 차단 |
| `playbooks/suspend_account.yml` | 판단(형식·보호 계정·모드) → 정지 목록 기록 → 공통 기록·알림 |
| `playbooks/vars/bola.yml` | 정지 시간, 정지 목록 경로(`SUSPENDED_USERS_FILE`), 보호 계정 |
| `inventory/hosts_v2.yml` | hosts.yml + `webapp` 그룹 |
| `tests/alerts/high_bola_enum*.json` | 100931 샘플 (공인 시험 IP / 실습망 IP) |
| `bola/app_patch/AccountGuard.php` | 정지 목록 읽기 (파일 없거나 읽기 실패 = 정지 없음, fail-open) |
| `bola/app_patch/account_guard.patch` | 팀 앱 2곳(v2 AuthMiddleware, v1 index.php)에 정지 확인 추가 |

## 앱 패치 적용 (팀 원본이 아니라 **개인 실습 웹**에)
```bash
cd <웹 소스 루트>                 # web/src 가 보이는 곳
git apply response/bola/app_patch/account_guard.patch
cp response/bola/app_patch/AccountGuard.php web/src/src/Core/
# 정지 목록 위치: 기본 web/src/logs/suspended_users.tsv, 바꾸려면 웹 서버 환경변수 SUSPENDED_USERS_FILE
```
`team_src/` 스냅샷은 수정하지 않았다 (사본에 `git apply --check` 통과 확인).

## 검증 (2026-11-10, 이 PC Docker)
| 시험 | 결과 |
|---|---|
| PHP 7.4 `php -l` (AccountGuard, 패치된 AuthMiddleware·v1 index) | 문법 오류 0 |
| AccountGuard 단위 6건 (정지 중 / 해제시각 지남 / 목록에 없음 / 형식 틀린 줄 / 파일 없음 / 환경변수 경로) | 6/6 |
| v2 AuthMiddleware 통합 (SQLite, 실제 JWT): 정지 7 → 403, 정상 8 → 통과, 만료 9 → 통과 | 3/3 |
| 플레이북 notify: 정지 dry-run + IP dry-run, IP = client_ip(203.0.113.77) | 확인 |
| 플레이북 block: TSV 에 `7<TAB>해제시각<TAB>사유` 기록, 두 번 실행해도 한 줄 | 확인 |
| 실습망 IP(192.168.0.27): 계정(1)만 정지, IP 는 허용목록이라 skip-allowlist | 확인 |
| 보호 계정(7): skip-protected-user | 확인 |
| rulebook v2 웹훅: BOLA 2회 → 대응 1회(throttle), SQLi → IP 차단 규칙, XSS → 알림 | 확인 |

## 한계 (확인 안 된 것 포함)
- **사후 대응이다.** 100931 은 남의 정보 3건이 이미 나간 뒤에 난다. 피해를 줄일 뿐 막지 못한다.
  근본 해결은 앱의 소유권 검사(v1 `users/{id}`) 또는 v1 제거 — 이 폴더의 범위 밖.
- 실제 Wazuh 에서 100931(frequency 룰) 경보에 `data.user_id`·`data.client_ip` 가 그대로 실리는지는 이 PC 에서 확인 못 함 (soc-lab VM 없음). `wazuh-logtest` 로 확인 필요.
- v1 `index.php` 는 MySQL 연결이 먼저라 HTTP 로 끝까지 돌려 보지 못했다 (문법 검사만). 같은 코드를 v2 에서 통합 시험.
- 정지 목록은 파일 한 개 — 웹 서버가 여러 대면 공유 저장소(DB 테이블 등)가 필요.
- fail-open: 정지 목록 파일이 사라지면 정지가 풀린다 (로그인 전체 장애보다 낫다는 선택).
