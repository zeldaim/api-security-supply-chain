# DVRA — 개발에 쓰지 않은 네 번째 앱에 v2.1 을 설정만 바꿔 적용 (2026-11-18)

대상: [Damn Vulnerable RESTaurant API](https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game) (FastAPI, `d32d099`), 앞단 nginx 로 표준 접근 로그.
코드는 그대로, `config.dvra.v2_1.env` 만 새로 썼다.

## 결과 (실제 Wazuh 4.14.6 `wazuh-logtest`, `wazuh_logtest_output_after_reboot.txt`)

| | 결과 |
|---|---|
| 설정만으로 룰 단계 | ✅ 명세 작업 21개 · 예외 0 · 파이썬 자체시험 **118/118** |
| 실제 Wazuh 케이스 대조 | **116/118** — 아래 "실패 2건" |
| 명세 밖 탐색 재현율 (`lt_probe`) | **15/15** (L1 11 · L2 1 · L3 2 · OTHER 1), 숨은 API 3개(`/debug`, `/delivery/orders`, `/admin/reset-chef-password`) 모두 경보 |
| 정상 경보 (`lt_normal`) | **2/355** — `GET /docs`, `GET /openapi.json` (L3) |
| 명세 안 BOLA (Shadow 룰 경보, `lt_bola`) | 0/63 — Shadow 룰의 대상이 아님(BOLA 는 ML 쪽) |

### 실패 2건 — 룰이 아니라 시험 방식

케이스 118개를 같은 출발지(`192.168.80.50`)로 연달아 넣어서 버스트 룰이 먼저 걸렸다.

- 88번째 케이스(`GET /reset-password/zz-undocumented-1` 404, 기대 L1): 이 출발지의 **20번째 L1** → F1 (룰 100520, `frequency="20" timeframe="30"`)
- 91번째 케이스(같은 경로 200, 기대 L3): **10번째 L3** → F2 (룰 100521, `frequency="10"`)

파이썬 자체시험은 버스트를 흉내 내지 않아 118/118 이 나왔다. crAPI(75개)·VAmPI(52개)는 앱 경로가 적어 임계값에 닿지 않았다. 고친다면 케이스마다 출발지를 바꾸거나 F1·F2 기대값을 케이스에 넣어야 한다(이번에는 기록만).

### 정상 경보 2건

`/docs`, `/openapi.json` 은 FastAPI 가 자동으로 여는 문서 경로라 명세에 없다. 트래픽 생성기가 "개발자 1명이 /docs 를 연다"로 일부러 넣은 것이다. 명세 밖 호출 성공이라 L3 는 룰대로 나온 결과이고, 운영 문서 노출로 보면 맞게 잡은 것이다. 정상 트래픽 기준으로는 오탐 2/355(0.6%).

## 진행 기록

- 처음 실행(`wazuh_logtest_output.txt`)은 Docker Desktop 오류(`chown …/resolv.conf: read-only file system`)로 logtest 이벤트가 0개였다. PC 재부팅 후 Docker 를 다시 띄워 같은 입력으로 재실행했다.
- 학습·평가(ML) 단계는 돌리지 않았다(`DRY=1`, 룰 단계까지만).

## 다시 돌리기

```bash
cd /d/lab_apps && git clone https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game.git
cd Damn-Vulnerable-RESTaurant-API-Game && docker compose -p dvra up -d      # web:8091, 네트워크 dvra_default
R=D:/api-security-supply-chain/verify/dvra/rules_2026-11-18
MSYS_NO_PATHCONV=1 docker run -d --name dvra-proxy --net dvra_default -p 127.0.0.1:8089:80 \
  -v "$R/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$R/work/logs:/logs" nginx:1.27-alpine
cd /d/api-security-supply-chain/verify/dvra/rules_2026-11-18
python dvra_traffic.py normal --users 12 --rounds 8 && python dvra_traffic.py probe && python dvra_traffic.py bola
bash run.sh                                     # 예상: 118/118 통과 (파이썬 재현)
cd /d/api-security-supply-chain && S=verify/dvra/rules_2026-11-18
bash automate/portable-workflow/logtest_accesslog.sh $S/state/0915-shadow_api_rules.xml $S/state/rules_meta.json $S/state/testcases.jsonl \
  $S/logtest_inputs/lt_normal.log $S/logtest_inputs/lt_bola.log $S/logtest_inputs/lt_probe.log $S/logtest_inputs/lt_probe_all.log
#  예상: 116/118 일치 · lt_normal L3 2 · lt_bola 경보 없음 63 · lt_probe L1 11 · L2 1 · L3 2 · OTHER 1
```
