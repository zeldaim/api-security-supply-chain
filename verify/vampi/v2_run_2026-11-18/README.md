# 세 번째 앱 — VAmPI 에 설정만으로 적용 (2026-11-18)

v1 기준 1 "처음 보는 앱에 **코드 수정 없이 설정만으로** 적용"을 확인한다. VAmPI(OWASP API Top 10 실습용 Flask 앱)는 개발에 쓰지 않은 앱이고, crAPI 와 구조가 다르다.

| | crAPI | VAmPI |
|---|---|---|
| 경로 접두어 | `/identity/api`, `/workshop/api` … | **없음** (`/users/v1`, `/books/v1`, `/me`, `/`) |
| BOLA 대상 ID | 숫자 · UUID | **문자열** (`/books/v1/{book_title}`, `/users/v1/{username}`) |

## 한 것

- 바꾼 것: [`config.vampi.v2.env`](config.vampi.v2.env) 하나 (명세 · 로그 경로 · `BOLA_TARGETS`). `run.sh` 는 crAPI 것과 설정 파일 이름만 다르다.
- 인프라: VAmPI 앞에 nginx([`nginx.conf`](nginx.conf))를 두어 표준 접근 로그를 남겼다. 앱 코드는 그대로.
- 시험 트래픽([`vampi_traffic.py`](vampi_traffic.py), 시험 장치): 정상 사용자 12명 · 명세 밖 탐색 15건(정답지 `work/probe_paths.txt`) · BOLA(남의 책 15권 · 사용자 15명 조회). 출발지는 `X-Client-IP` 헤더로 나눴다. 접근 로그 410줄.

## 결과

| v1 기준 | 결과 | |
|---|---|---|
| 1. 설정만으로 적용 | ❌ **실패** — 규칙 자체 시험 48/49 에서 파이프라인 중단 | 아래 실패 1 |
| 2. 생성된 룰 자체 시험 100% | ❌ 48/49 (실제 wazuh-logtest 도 48/49) | 실패 1 — 룰이 아니라 시험 케이스 생성 쪽 |
| 3. 명세 밖 탐색 재현율 ≥ 80% | ❌ **9/15 (60%)** | 실패 2 · 3 |
| 4. 정상 오탐 0 | ✅ 정상 362줄 경보 0 | |
| 5. ID 열거 탐지 | ❌ **문자열 ID 를 객체로 세지 못함** | 실패 4 |

실제 Wazuh 기록: [`wazuh_logtest_output.txt`](wazuh_logtest_output.txt) — BOLA 33줄은 명세 안 호출이라 Shadow 룰 경보 0 (정상, BOLA 는 다른 층의 몫).

### 실패 1 — 루트 경로 `/` 가 있으면 시험 케이스가 틀린 기대값을 만든다

명세에 `GET /` 가 있다. 시험 케이스 생성기가 "명세 경로 + 그 경로에 없는 메서드" 케이스로 `DELETE /` 를 만들고 L1 을 기대했는데, `/` 는 검사 범위 밖이라 룰은 맞게 경보를 내지 않았다. **룰은 맞고 시험이 틀렸는데, 그 시험 때문에 파이프라인이 멈춘다.**

### 실패 2 — 검사 범위를 명세 첫 조각에서 뽑아 새 첫 조각을 못 본다 (5건)

`/api` 가 없으면 범위를 명세 경로의 첫 조각으로 정한다 → `^(?:/books|/createdb|/me|/users)`. 그래서 `/admin`, `/api/v1/users`, `/debug`, `/swagger.json`, `/actuator/health` 는 **검사 대상이 아니다.** 탐색 공격이 가장 먼저 두드리는 경로들이라 구조적 약점이다.

### 실패 3 — 문자열 파라미터 템플릿이 명세 밖 경로를 흡수 (1건)

`/users/v1/_internal` → `/users/v1/{username}` 에 맞아 명세 안으로 판정. crAPI 의 `orders/export` 와 같은 문제. 파라미터에 형식(정수 · UUID)이 없으면 명세만으로는 못 가른다.

### 실패 4 — 객체 ID 를 숫자 · UUID 로만 센다

`features.py` 는 경로의 숫자 · UUID 조각만 객체 ID 로 본다. `BOLA_TARGETS` 를 설정해도 템플릿 치환이 숫자 · UUID 기준이라 효과가 없다. BOLA 출발지(10.77.0.1)의 ID 특징:

| 특징 | BOLA 출발지 | 정상 최대 (12창) |
|---|---|---|
| `seq_id_run` · `seq_ratio` · `id_span_log` (ID 열거) | 0 · 0 · 0 | 0 · 0 · 0 |
| `uniq_path_ratio` | **1.0** | 0.26 |
| `top_tpl_share` | **0.03** | 0.29 |

ID 특징으로는 정상과 같다. 경로 다양성 특징에서는 튀지만, 그건 책 제목마다 다른 경로로 세서 생긴 것("탐색처럼 보임")이지 ID 열거로 잡은 게 아니다. ML 게이트는 정상 데이터가 12창뿐이라 돌리지 않았다(crAPI 는 정상 150분).

## 결론

**v1 기준 1 은 VAmPI 에서 실패했다.** 설정만으로는 파이프라인이 멈추고, 고쳐서 돌려도 탐색 재현율 60% · 문자열 ID BOLA 미탐이다. crAPI 에 맞춰 고친 v2_portable 이 "crAPI 와 비슷한 앱"에만 일반화돼 있었다는 뜻이다.

고칠 것 (코드 수정 — 고친 뒤에는 **또 다른 처음 보는 앱**으로 기준 1 을 다시 재야 한다):

1. 시험 케이스: 검사 범위 안의 명세 경로만 고른다.
2. 검사 범위: 명세에 공통 접두어가 없으면 "정적 파일 · 알려진 페이지를 뺀 전부"를 범위로 — 새 첫 조각도 검사.
3. 객체 ID: `BOLA_TARGETS` 템플릿의 자리(`{book_title}`)에 들어온 값을 형식과 무관하게 객체로 센다.
4. 템플릿 흡수: 명세 파라미터에 형식이 있으면(integer · uuid) 그 형식만 맞춘다 — crAPI `orders/export` 도 함께 해결. 형식이 없으면 한계로 남긴다.

## 다시 돌리기

```bash
docker run -d --name vampi -e vulnerable=1 erev0s/vampi:latest
docker network create vampi-net && docker network connect vampi-net vampi
MSYS_NO_PATHCONV=1 docker run -d --name vampi-proxy --net vampi-net -p 127.0.0.1:8088:80 \
  -v "D:/api-security-supply-chain/verify/vampi/v2_run_2026-11-18/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "D:/api-security-supply-chain/verify/vampi/v2_run_2026-11-18/work/logs:/logs" nginx:1.27-alpine
curl -s -H 'X-Client-IP: 10.1.0.1' localhost:8088/createdb
cd /d/api-security-supply-chain/verify/vampi/v2_run_2026-11-18
python vampi_traffic.py normal && python vampi_traffic.py probe && python vampi_traffic.py bola
bash run.sh spec && bash run.sh rules          # 예상: [중단] 규칙 자체시험 실패 (48/49)
```
