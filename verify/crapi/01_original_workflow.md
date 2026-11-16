# crAPI 일반성 검증 — 결과와 따라 하기 (2026-11-15)

> **질문:** 팀 웹에 맞춰 만든 탐지 워크플로(`e2e_story/bootstrap.sh`)가 **`config.env` 값만 바꿔서** 다른 앱(crAPI)에서도 도는가.
>
> **결론 (탐지 코드는 한 줄도 안 고침):**
> - **Shadow API 룰 쪽은 설정만으로 안 된다.** 룰 생성 단계에서 워크플로가 멈추고, 만들어진 룰도 crAPI 요청에는 걸리지 않는다(§3-2).
> - **ML 쪽은 숫자 ID 가 경로에 있는 BOLA 에 한해 그대로 통한다.** crAPI 정상으로 학습한 모델이 실제 주문 BOLA(빠름·느림·순서 섞음) 6창을 전부 high 로 판정했다(§7).
> - **죽은 특징 3개**(`api_ratio`·`offspec_ratio`·`static_ratio`)와 **못 보는 ID 형태 2개**(쿼리 파라미터, UUID)가 확인됐다(§7-3).
> - **평가 게이트는 실패**했다. 검증용 정상 창이 36개로 기준 50개에 못 미쳤다(PC 절전으로 수집이 85분에서 끊김).
>
> 판정: **"설정만으로 이식된다"는 틀렸고, "ML 특징의 핵심(열거 탐지)은 앱이 바뀌어도 동작한다"는 맞다.**

## 0. 이 폴더의 파일

| 파일 | 용도 |
|---|---|
| `config.crapi.env` | crAPI 용으로 바꾼 설정값 (`e2e_story/config.env` 대신 환경변수로 넘김) |
| `run_bootstrap.sh` | 위 설정으로 `bootstrap.sh` 를 Docker 안에서 실행 |
| `Dockerfile.runner` | 실행 환경 (scikit-learn 1.5.2, PyYAML). 이 PC 는 호스트 Python 으로 scikit-learn 이 안 돈다 |
| `crapi_traffic.py` | 정상 사용자·공격 6종 트래픽 생성기 (표준 라이브러리만) |
| `run_normal.sh` · `run_attacks.sh` | 생성기를 컨테이너 여러 개로 띄움 (컨테이너마다 출발지 IP 가 다름) |
| `score_attacks.py` | 학습된 모델로 실제 공격 창을 채점 |
| `labels_normal.jsonl` · `labels_attack.jsonl` | 2차 실행의 정상 18명·공격 6종 IP·시작·종료·요청 수·응답 코드 (정답 라벨) |
| `results_partial/` | 1차 실행(12분에서 중단) 산출물 |
| `results_run2/` | 2차 실행 산출물 — 접근 로그, 특징, 모델 메타, 게이트 결과, 공격 채점 |
| `work/` | 원본 로그·명세 (git 제외) |

## 1. 준비 — 따라 하기

명령은 Git Bash 에서 한 줄씩. 저장소 루트는 `D:\shadow_api_monitoring`.

**1-1. Docker Desktop 을 켠다.** 확인:
```bash
docker version --format '{{.Server.Version}}'
```
예상 출력: `29.9.2` 같은 버전 번호. 오류가 나면 Docker Desktop 이 꺼진 것.

**1-2. crAPI 를 올린다.** 이 PC 에는 `D:\shadow_api_lab\crapi` 에 compose 파일과 이미지가 이미 있다.
```bash
cd /d/shadow_api_lab/crapi
docker compose up -d crapi-web mailhog
```
예상 출력: `Container crapi-identity Healthy` … `Container crapi-web Started`.

**1-3. crapi-web 이 바로 죽으면 (챗봇 호스트 이름 문제).**
crapi-web 의 nginx 는 `crapi-chatbot` 이라는 호스트를 찾지 못하면 시작하지 않는다. 챗봇은 메모리를 많이 써서 띄우지 않고, 같은 이름의 빈 컨테이너를 둔다.
```bash
docker run -d --name crapi-chatbot-stub --network crapi_default --network-alias crapi-chatbot busybox:1.36 sh -c 'mkdir -p /w && echo stub > /w/index.html && httpd -f -p 5002 -h /w'
docker compose up -d --no-deps crapi-web
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8888/health
```
예상 출력: 마지막 줄 `200`.

**1-4. 접근 로그 위치.** crapi-web 은 접근 로그를 파일이 아니라 표준출력으로 낸다. 그래서 `docker logs crapi-web` 이 곧 접근 로그다(Apache combined 형식).

**1-5. 실행 환경 이미지를 만든다.**
```bash
cd /d/shadow_api_monitoring/e2e_story/crapi_generality_2026-11-15
docker build -q -t e2e-runner -f Dockerfile.runner .
```
예상 출력: `sha256:…` 한 줄.

**1-6. crAPI 명세를 `work/` 에 둔다.**
```bash
mkdir -p work
cp /d/shadow_api_lab/crapi/crapi-openapi-spec.json work/
```

## 2. 바꾼 설정 (`config.crapi.env`)

| 키 | 팀 웹 값 | crAPI 값 | 이유 |
|---|---|---|---|
| `LAB_SSH` | `yhc@192.168.100.50` | (빈 값) | 이 PC 에는 원격 VM 이 없다. 비우면 로컬 로그 파일을 쓴다 |
| `SPEC_PATH` | 팀 웹 `openapi.yaml` | `work/crapi-openapi-spec.json` | 대상 명세 |
| `WEB_LOG` | 팀 웹 Apache 로그 | `work/normal.log` | 대상 접근 로그 |
| `TRAIN_WINDOW` | `15` | `5` | 수집 시간이 짧아 창을 줄임 |
| `DRY` | (없음) | `1` | 배포 단계 생략 (배포할 원격 호스트가 없음) |

## 3. 1차 실행에서 확인한 것 (룰 생성 단계)

### 3-1. 단계별 (코드 수정 없이, 12분치) — 2차 결과는 §7

| 단계 | 결과 | 내용 |
|---|---|---|
| 1. 명세 | **통과** | JSON 명세를 그대로 읽음 (3,411줄) |
| 2. 룰 생성 | **중단** | 룰 파일은 만들어지지만 자체 시험 61/64 → 워크플로가 여기서 멈춤 |
| 3. 수집 | 통과 | 로컬 로그를 앞 85% 학습 · 뒤 15% 검증으로 나눔 |
| 4. 특징 | 통과 (값은 §3-3) | 출발지 × 5분 창으로 변환됨 |
| 5. 학습 | 미완 | 4분치로는 창 42개 → "50개 이상 필요"로 중단. 12분치는 120개라 학습은 가능 |
| 6. 게이트 | 미실행 | 검증용 조용한 정상 창 50개가 필요한데 12분치로는 18개 |

재현:
```bash
bash run_bootstrap.sh spec
bash run_bootstrap.sh rules
```
예상 출력(rules): `[중단] 규칙 자체시험 실패`. 상세는 `results_partial/stage2_rules_build.log`.

### 3-2. 룰 생성 단계에서 확인된 것 — 코드에 박힌 팀 웹 가정 2개

1. **자체 시험 케이스에 팀 웹 경로가 들어 있다.** 실패한 3건은 `/api/v2/products?category=…`, `/api/v2/products/`, `/api/v2/orders/me?…` 로, crAPI 명세에는 없는 경로다(`gen_shadow_rules.py` 373~375행). 명세가 바뀌면 이 시험은 항상 실패한다.
2. **기반 룰이 `/api` 로 시작하는 경로만 본다.** 생성된 룰 100500 의 조건이 `^/+api(?:/|\?|$)` 이다(`API_SCOPE_REGEX`, 51행). crAPI 경로는 `/identity/api/…`, `/workshop/api/…`, `/community/api/…` 라서 **이 룰은 crAPI 요청에 한 번도 걸리지 않는다.** 하위 룰(명세 밖 판정)도 전부 따라서 안 울린다.
   - 같은 룰이 `app.log`(JSON, `path`·`method` 필드)를 전제로 한다. crAPI 에는 그런 앱 로그가 없고 nginx 접근 로그뿐이다.

생성된 룰 자체는 `results_partial/stage2_generated_rules.xml` 에 있다. 메서드별 허용 경로 목록(작업 44개)은 crAPI 명세대로 맞게 만들어졌다.

### 3-3. 특징 추출 코드에서 미리 예상한 것 (`e2e_story/ml/features.py`) — 실행 결과는 §7-3

| 코드 | 팀 웹 가정 | crAPI 에서 예상되는 결과 |
|---|---|---|
| `p.startswith("/api")` | API 경로는 `/api` 로 시작 | `api_ratio` 가 항상 0, `offspec_ratio`(명세 밖 비율)도 항상 0 |
| `NUM = /\d+` | 객체 ID 는 경로의 숫자 | 차량 ID 는 UUID 라 열거 특징(`seq_id_run`, `id_span_log`)에 안 잡힘 |
| `url.split("?")[0]` | ID 는 경로에 있음 | 정비 보고서는 `?report_id=N` 이라 ID 가 버려짐 |
| `eval/variants.py` | 공격 변종 경로가 `/api/v2/orders/{id}` 등 | 게이트가 팀 웹 모양의 공격으로 crAPI 모델을 시험하게 됨 |

주문 조회(`/workshop/api/shop/orders/{id}`)는 숫자 ID 가 경로에 있어 열거 특징이 그대로 동작할 것으로 예상한다.

## 4. 수집한 데이터

- **2차 정상:** 사용자 18명, 08:19~09:44 UTC, 10,119 요청 → `results_run2/normal_access.log.gz`
- **2차 공격:** 6종, 13:00~13:11 UTC, 161 요청 → `results_run2/attack_access.log.gz`, 라벨 `labels_attack.jsonl`
- **1차 정상:** 사용자 40명(출발지 40곳), 2026-11-15 07:17~07:28 UTC, 2,567 요청, 응답 200 이 2,565건.
  - `results_partial/normal_12min_access.log.gz` (원본 접근 로그, 랩 내부 IP·가짜 계정뿐)
  - `results_partial/normal_12min_features_w5.csv` (5분 창 120개, IP 제외)

## 5. 실행 이력

| 실행 | 계획 | 실제 | 사유 |
|---|---|---|---|
| 1차 (07:17 UTC) | 정상 40명 × 50분 + 공격 | 정상 12분에서 중단, 공격 못 함 | PC 남은 메모리 1.0GB — 대기 작업이 메모리 부족으로 종료 |
| 2차 (08:20 UTC) | 정상 18명 × 120분 + 공격 | 정상 85분(08:19~09:44), 공격은 13:00 에 실행 | 09:44~12:50 요청 기록 없음(PC 절전으로 추정). 깨어난 뒤 예약된 공격이 실행됨 |

2차 실행의 주의점: 정상 사용자 컨테이너가 끝난 뒤 공격 컨테이너가 떠서 **같은 IP 를 다시 받았다.** 그래서 정상/공격은 IP 가 아니라 **시각**으로 나눴다(12시 이전 = 정상, 13시 이후 공격 IP = 공격).

## 6. 2차 실행 — 따라 하기

```bash
cd /d/shadow_api_monitoring/e2e_story/crapi_generality_2026-11-15
bash run_normal.sh 18 120 101
```
예상 출력: `정상 사용자 118 시작` … `총 18 명 · 120분`. **PC 절전을 끄고** 돌린다(제어판 → 전원 옵션).

정상이 끝나기 10분 전에:
```bash
bash run_attacks.sh
```
예상 출력: `공격 시작: bola_orders_fast …` 6줄, 약 9분 뒤 `labels_attack.jsonl: 6 줄`.

로그를 꺼내 정상·공격으로 나눈다(`work/normal.log`, `work/attack.log`). crapi-web 접근 로그는 `docker logs` 로 나온다.
```bash
bash run_normal.sh collect
docker logs --since 6h crapi-web 2>/dev/null | grep -E '^172\.[0-9.]+ - - \[' > work/run2_all.log
```
그다음 단계별 실행:
```bash
bash run_bootstrap.sh collect
bash run_bootstrap.sh features
bash run_bootstrap.sh train
bash run_bootstrap.sh gate
```
예상 출력(이번 실행): `학습 243` 창, 게이트는 `❌ 실패 — 조용한 정상 창 36개 < 50`. 전체 출력은 `results_run2/bootstrap_stages.txt`.

실제 공격 창 채점(모델은 `e2e_story/.bootstrap/model` 에 생긴다):
```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "D:/shadow_api_monitoring:/repo" -w /repo/e2e_story/crapi_generality_2026-11-15 e2e-runner python score_attacks.py ../.bootstrap/model work/attack_features_ip.csv labels_attack.jsonl ../.bootstrap/holdout_features.csv
```
`work/attack_features_ip.csv` 는 `python ../ml/features.py extract work/attack.log --window 5 --out work/attack_features_ip.csv` 로 만든다(환경변수 `E2E_SPEC=work/crapi-openapi-spec.json`).

## 7. 2차 실행 결과

### 7-1. 단계별

| 단계 | 결과 |
|---|---|
| 1. 명세 | 통과 |
| 2. 룰 생성 | 중단 (자체 시험 61/64, §3-2) |
| 3. 수집 | 통과 — 정상 10,119줄 → 학습 8,601 · 검증 1,518 |
| 4. 특징 | 통과 — 학습 243창 · 검증 54창 (5분, 출발지 18곳) |
| 5. 학습 | 통과 — IsolationForest, high < -0.0158 · medium < 0.0072 |
| 6. 게이트 | **실패** — 학습 시간과 겹치는 18창을 빼면 조용한 정상 36창 < 50 |

### 7-2. 실제 crAPI 공격 채점 (`results_run2/score_attacks.txt`)

| 공격 | 대상 | 응답 | 5분 창 | 판정 | 걸린 이유 |
|---|---|---|---|---|---|
| 주문 BOLA 빠름 | `/workshop/api/shop/orders/{n}` 60개 | 200 × 62 | 2 | **high 2/2** | 연속 ID 44·16개 (정상 최대 2) |
| 주문 BOLA 느림 (14~26초) | 같은 경로 25개 | 200 × 27 | 2 | **high 2/2** | 연속 ID 9·13개 |
| 주문 BOLA 느림 + 순서 섞음 | 같은 경로 25개 | 200 × 27 | 2 | **high 2/2** | 서로 다른 ID 개수(`id_span_log` 2.4~2.6, 정상 최대 1.39) |
| 보고서 BOLA 느림 | `/workshop/api/mechanic/mechanic_report?report_id=N` | 200 × 7 · 400 × 20 | 2 | high 2/2 | **열거가 아니라 오류 비율**(0.5·1.0) — 정상은 오류가 0 |
| 명세 밖 경로 탐색 | 명세에 없는 경로 12개 | 404 × 11 | 1 | medium 1/1 | 오류 비율 0.86. `offspec_ratio` 는 0 으로 나옴 |
| 차량 위치 BOLA | `/identity/api/v2/vehicle/{uuid}/location` | — | 0 | **미실행** | 게시글에서 차량 ID 를 하나도 못 얻음 |

- 검증용 정상: 54창 중 high 0 · medium 0 (겹침 제외 36창도 0).
- 주문 BOLA 는 **실제로 남의 주문이 200 으로 반환되는** 공격이고, 명세 안 경로라 Shadow API 룰 대상이 아니다. 120초에 10개 빈도 룰 기준으로 보면 느린 두 종은 간격이 14~26초라 놓친다(120초에 5~8개).

### 7-3. 확인된 한계 — 코드가 팀 웹에 맞춰진 곳

| 위치 | 증거 (이번 실행) | 영향 |
|---|---|---|
| `features.py` 의 `startswith("/api")` | `api_ratio` 가 정상·공격 전부 0.0 | 특징 하나가 죽음 |
| 같은 조건을 쓰는 `offspec_ratio` | 명세 밖 경로만 12번 부른 창도 0.0 | "룰이 이미 잡는 창" 구분이 안 됨 → 학습·평가의 거르기가 동작 안 함 |
| `static_ratio`, `n_ua` | 전부 0.0 / 1 | 생성기가 정적 파일을 안 부르고 UA 가 하나라 값이 없음(데이터 쪽 한계) |
| ID 를 경로 숫자로만 봄 | 보고서 BOLA 의 `seq_id_run`·`id_span_log` 가 0 | 쿼리 파라미터 ID 열거는 못 봄. 이번엔 400 오류 때문에 걸렸을 뿐 |
| UUID | 미실행 | 미확인. 코드상 숫자만 세므로 못 볼 것으로 예상 |
| `eval/variants.py` 의 공격 경로 | 게이트 변종 V3 40/40 · V4 39/40 (팀 웹에서는 62% · 18%) | 팀 웹 모양(`/api/v2/…`) 요청이 crAPI 모델에는 처음 보는 값이라 쉽게 걸림 — **이 수치는 crAPI 탐지 성능이 아님** |
| `gen_shadow_rules.py` | §3-2 | Shadow API 룰이 crAPI 에서 안 울림 |

### 7-4. 이 결과로 말할 수 있는 것 / 없는 것

**말할 수 있음**
- 워크플로의 수집·특징·학습 단계는 설정만 바꿔 crAPI 에서 돈다.
- 숫자 ID 가 경로에 있는 BOLA 는 앱이 바뀌어도, 느리게 해도, 순서를 섞어도 탐지된다.
- Shadow API 룰 생성과 명세 밖 특징은 `/api` 접두어 가정 때문에 crAPI 에서 동작하지 않는다.

**말할 수 없음**
- "오탐 0". 정상은 스크립트 생성기이고 **정상 사용자는 자기 주문만 연다.** 정상의 `seq_id_run` 최대가 2, 오류 비율이 전부 0 이라 공격이 지나치게 쉽게 갈린다. 임계값 룰(5분에 서로 다른 주문 ID 5개 이상 — 정상 최대 3개, 공격 최소 9개)로도 같은 결과가 나온다.
- "보고서 BOLA 를 탐지한다". 걸린 이유가 오류 응답이다. 존재하는 보고서 번호만 조회하면(전부 200) 안 걸릴 수 있다.
- "게이트 통과". 데이터 양 부족으로 실패했다.
- 공격은 종류당 1회, 창 2개씩이다.

## 8. 다음

1. PC 절전을 끄고 정상 120분을 다시 수집해 게이트의 정상 창 기준(50개)을 채운다.
2. 차량 BOLA 를 실행하려면 정상 사용자가 차량을 등록해야 한다(메일로 온 VIN·PIN 으로 `add_vehicle`). 생성기에 추가한다.
3. 보고서 BOLA 를 "존재하는 번호만"으로 다시 돌려 오류 없이도 걸리는지 본다.
4. 공개 데이터(OTTO, Stack Overflow 세션)로 정상을 재생해 같은 공격을 다시 채점한다 — 정상이 남의 주문을 열지 않는다는 한계는 그대로 남는다.
5. ~~코드 수정(새 파일로)~~ → **완료 (2026-11-16): [`../v2_portable/`](../v2_portable/README.md)** — API 범위를 명세에서, 쿼리 파라미터·UUID ID 인식, 게이트 변종 경로를 명세에서, 접근 로그용 Shadow API 룰. 같은 데이터로 다시 돌린 결과 포함.
