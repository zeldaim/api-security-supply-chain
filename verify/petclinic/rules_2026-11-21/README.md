# spring-petclinic — 다섯 번째 처음 보는 앱 · 첫 Spring 앱 · 명세 없음 (2026-11-21)

대상: [spring-projects/spring-petclinic](https://github.com/spring-projects/spring-petclinic) `500158f` (Spring Boot 4.1.0, Thymeleaf 서버 렌더링, 로그인 없음), 앞단 nginx 로 표준 접근 로그.
지금까지의 앱(쇼핑몰 · crAPI · VAmPI · DVRA)과 달리 **OpenAPI 명세가 아예 없다.** 그래서 순서가 하나 늘었다.

```
소스 코드 ──source_to_baseline.py (Spring 추출기, 이번에 추가)──▶ 기준선 CSV ──사람 검토──▶ CycloneDX API-BOM ──▶ OpenAPI 허용 목록
                                                                                                         │
접근 로그 ◀── 트래픽 생성기                                  v2.1 워크플로(코드 그대로, 설정 파일만) ◀───┘ ──▶ Wazuh 룰 ──▶ 실제 wazuh-logtest
```

## 결과

### 1. 명세 만들기 — 추출기를 실제 앱과 대조

| | 추출기 | 실제 (실행 중인 앱) | |
|---|---|---|---|
| 컨트롤러 경로 | 17 (화면·폼 16 · JSON API 1) | `/actuator/mappings` 의 앱 컨트롤러 17 | **17/17 일치**, 누락 0 · 잘못 넣음 0 |
| 설정으로 열린 actuator | 13 (+ `GET /actuator`, 쓰기 2) | `GET /actuator` 목록 13 | **13/13**. 처음 예측의 `heapdump` 는 실제로 안 열려 목록에서 뺐다 |

- 코드에 경로가 없는 actuator 13개는 `application.properties:21` (`management.endpoints.web.exposure.include=*`) 에서 찾았다. 컨트롤러만 보는 추출로는 놓치는 공격 표면이다 (`/actuator/env` · `configprops` · `mappings` · `beans` · `threaddump` 등).
- `GET /vets` 는 `@ResponseBody` JSON API 인데 화면 어디에도 링크가 없다 → `review`(Shadow 후보)로 분류됐다.
- 사람 검토는 한 건만 했다: `GET /actuator/health` = 모니터링 헬스 체크 → `active`. **검증용이라 Claude 가 대신 결정했다** (`work/baseline.csv` note 에 표시). 나머지 actuator 와 `/vets` 는 `review` 그대로.
- BOM: CycloneDX 1.6 strict 스키마 통과 (`work/petclinic.api-bom.cdx.json`). 허용 목록 17 operation (`work/petclinic-openapi.json`).
- 기준선 재생성(`--prev`) 때 사람 결정(health 승인)은 이어받고, 사라진 `heapdump` 는 `[삭제]` 로 알렸다.

### 2. 룰 — 설정만으로 (실제 Wazuh 4.14.6 `wazuh-logtest`, `wazuh_logtest_output.txt`)

| | 결과 |
|---|---|
| 설정만으로 룰 단계 | ❌ **56/57** — 아래 "실패 1건". 그래서 워크플로가 자체시험에서 멈췄다 (룰 XML 은 만들어져서 탐지 측정은 계속했다) |
| 실제 Wazuh 케이스 대조 | 56/57 (같은 1건) |
| 명세 밖 탐색 재현율 (`lt_probe`) | **15/15** (L1 8 · L3 6 · OTHER 1). 숨은 실제 경로 6개(`/vets` JSON · actuator 5개) 모두 **L3** |
| 정상 경보 (`lt_normal`) | **0/542** (헬스 체크 11회 · 메뉴의 `/oups` 오류 화면 포함) |
| 명세 안 열거 (Shadow 룰 경보, `lt_bola`) | 0/61 — Shadow 룰의 대상이 아님 (열거는 ML 쪽, 이번엔 안 돌림) |

### 실패 1건 — `.html` 로 끝나는 Spring 처리기

`GET //vets.html` (슬래시 겹침 우회 케이스, 기대 L1) 이 경보 없음. v2.1 기본 검사 범위는 `.html` 을 정적 파일로 보고 빼는데, petclinic 의 `/vets.html` 은 정적 파일이 아니라 컨트롤러다.
설정값 `API_SCOPE` 로 html 을 범위에 넣어 봤더니 이번엔 시험 케이스 생성기가 "직접 준 범위는 좁다"고 가정하고 만든 범위 밖 케이스 2건(`/index.html`, `/zz-not-api/1`)이 틀렸다 (52/54, `work/rules_build_with_api_scope.log`).
→ 둘 다 워크플로(시험 케이스 생성기)를 고쳐야 하는 문제다. 고치면 petclinic 도 "본 앱"이 되므로 이번에는 고치지 않고 기록만 한다. 최종 설정은 `API_SCOPE` 없는 최소 설정.

### 처음 실행에서 고친 것 — 추출기(명세 생성) 쪽

첫 룰 단계는 **48/55** 였다. `/owners/zz-undocumented-1` 6건이 경보 없음 — 명세의 `/owners/{id}` 에 형식이 없어 아무 문자열이나 `{id}` 로 받아들였다.
Spring 소스에는 `@PathVariable("ownerId") int ownerId` 로 숫자라는 정보가 있는데 추출기가 버리고 있었다 → 경로 변수 형식을 BOM(`sesac:api:path-param-types`) → OpenAPI `parameters` 로 넘기게 고쳤다.
워크플로 코드가 아니라 **입력 명세를 소스에 맞게 정확히 만든 것**이다. 그 결과 `/owners/abc` (400) 탐색도 OTHER 로 잡혔다 (형식 없는 명세였다면 명세 안).

## 정직한 한계

- v1 기준 1(설정만으로 적용)은 **이 앱에서도 통과가 아니다** — 56/57.
- 탐색 15줄 · 정상 542줄은 이 저장소의 트래픽 생성기(`petclinic_traffic.py`)가 만든 것이다. 실제 운영 트래픽이 아니다.
- actuator 목록은 Boot 4.1.0 실측이다. 다른 Boot 버전 · 의존성(prometheus 등)에서는 달라질 수 있다 → 실행 중인 앱의 `GET /actuator` 로 대조할 것.
- 열거(BOLA) ML 단계는 돌리지 않았다 (`DRY=1`).

## 다시 돌리기

```bash
cd /d/lab_apps && git clone https://github.com/spring-projects/spring-petclinic.git && git -C spring-petclinic checkout 500158f
# 빌드 (Maven 컨테이너)
MSYS_NO_PATHCONV=1 docker run --rm -v "D:/lab_apps/spring-petclinic:/src:ro" -v petclinic-build:/out -v m2cache:/root/.m2 maven:3.9-eclipse-temurin-21 \
  bash -c 'cp -r /src /tmp/b && cd /tmp/b && mvn -q -B package -DskipTests -Dcheckstyle.skip=true -Dspring-javaformat.skip=true && cp target/*.jar /out/app.jar'
# 명세: 추출 → (사람 검토: work/baseline.csv) → BOM → 검증 → 허용 목록
cd /d/api-security-supply-chain/verify/petclinic/rules_2026-11-21; T=../../../standardize/api-bom/source_to_baseline.py
python $T extract /d/lab_apps/spring-petclinic --prev work/baseline.csv > work/baseline.new.csv && mv work/baseline.new.csv work/baseline.csv
API_BOM_SRC_VERSION=500158f SOURCE_DATE_EPOCH=1763683200 python $T cyclonedx work/baseline.csv /d/lab_apps/spring-petclinic \
  --app spring-petclinic --app-group spring-projects --app-desc "Spring PetClinic (Spring Boot 4.1, Thymeleaf, 500158f)" \
  --base-url http://127.0.0.1:8099 --owner petclinic-team > work/petclinic.api-bom.cdx.json
python $T validate work/petclinic.api-bom.cdx.json && python $T openapi work/petclinic.api-bom.cdx.json --include-pages > work/petclinic-openapi.json
# 앱 + nginx 앞단
MSYS_NO_PATHCONV=1 docker network create petclinic_lab
MSYS_NO_PATHCONV=1 docker run -d --name petclinic-app --network petclinic_lab --network-alias app -v petclinic-build:/app:ro eclipse-temurin:21-jre java -jar /app/app.jar
MSYS_NO_PATHCONV=1 docker run -d --name petclinic-proxy --network petclinic_lab -p 127.0.0.1:8099:80 \
  -v "$(pwd -W)/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$(pwd -W)/work/logs:/logs" nginx:1.27-alpine
python petclinic_traffic.py normal --users 12 --rounds 8 --pause 0.1 && python petclinic_traffic.py probe && python petclinic_traffic.py bola
python petclinic_traffic.py normal --users 12 --rounds 3 --pause 0.1
#  주의: Windows 폴더에 nginx 가 이어 쓰면 NUL 바이트가 끼는 일이 있었다 → 로그에서 \0 을 지우고 쓴다(줄 손상 없음 확인)
# 룰 + 실제 Wazuh
cd /d/api-security-supply-chain && bash verify/petclinic/rules_2026-11-21/run.sh spec && bash verify/petclinic/rules_2026-11-21/run.sh rules   # 예상: 56/57 에서 중단
S=verify/petclinic/rules_2026-11-21
bash automate/portable-workflow/logtest_accesslog.sh $S/state/0915-shadow_api_rules.xml $S/state/rules_meta.json $S/state/testcases.jsonl \
  $S/logtest_inputs/lt_normal.log $S/logtest_inputs/lt_bola.log $S/logtest_inputs/lt_probe.log $S/logtest_inputs/lt_probe_all.log
#  예상: 56/57 일치 · lt_normal 경보 없음 542 · lt_bola 경보 없음 61 · lt_probe L1 8 · L3 6 · OTHER 1
```
