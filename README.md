# API 보안 · 소프트웨어 공급망 — 표준화와 자동화

> **명세가 없는 서비스에서 "무엇이 정상 API 이고 무엇으로 만들어졌나"를 표준 형식으로 만들고, 그 기준으로 탐지 룰 생성부터 대응까지 자동으로 돌린다.**
> 행위 기반 ML 은 룰로 못 쓰는 공격(느린 BOLA 열거)을 보완하는 층으로 붙이고, 모든 수치는 다른 앱(OWASP crAPI)에서 다시 검증했다.

이현정 · 보안 엔지니어 과정(SeSAC) 최종 팀 프로젝트의 담당 파트(**API 명세화 · 탐지 룰 파이프라인**)에서 출발해 개인적으로 확장한 저장소입니다.

| 영상 | |
|---|---|
| [![내 시연](media/poster_mine.jpg)](media/demo_mine_live_2x.mp4) | **개인 확장 — 실제 화면 녹화 (78초, 2배속)** crAPI 에 실제 BOLA 공격 → 접근 로그 → 행위 특징·모델 채점 → 명세에서 자동 생성한 룰을 실제 Wazuh 로 확인 |
| [![팀 시연](media/poster_team.jpg)](media/demo_team_edited_6x.mp4) | **팀 프로젝트 시연 (편집본, 108초, 6배속)** 공격자 화면(구버전 API 의 BOLA) → 관제 화면(명세 밖 호출 경보, 차단) |

---

## 1. 표준화 — 기준을 표준 형식으로

| 무엇을 | 표준 | 코드 |
|---|---|---|
| 정상 API 목록(기준) | **CycloneDX 1.6 API-BOM** → OpenAPI 허용 목록 | [`standardize/api-bom/source_to_baseline.py`](standardize/api-bom/source_to_baseline.py) |
| 자산 인벤토리 (소스·방화벽 설정·로그·스캔 4출처) | CycloneDX 서비스 BOM | [`standardize/inventory/`](standardize/inventory/) |
| 소프트웨어 구성 | **SBOM** (Syft, CycloneDX) → Dependency-Track | [`standardize/sbom/`](standardize/sbom/) |
| 취약점 영향 판단 | **VEX** (도달하지 않는 CVE = not_affected 후보) | [`standardize/sbom/make_vex.py`](standardize/sbom/make_vex.py) |
| 판정 기준 | OWASP · CIS · NIST 기반 기준표 | [`standardize/policy/`](standardize/policy/) |

- **사람이 승인한 것만 기준이 된다.** 발견한 API 를 자동으로 기준에 넣으면 공격 대상 경로까지 "정상"이 되어 경보가 꺼진다. 도구는 후보만 내고 사람은 승인만 한다([`approval_server.py`](standardize/inventory/approval_server.py)).
- **결과** (팀 웹): 소스만 보면 Shadow 0 → 4출처를 합치면 **Shadow 4 · 외부 노출 4**. 부품 취약점 2,355건 중 API 에서 실제로 닿는 CVE 는 **23%**([`standardize/reach/`](standardize/reach/), 정적 분석).
- **관계 그래프:** 엔드포인트 → 서비스 → 이미지 → 부품 → 취약점 → 커널 계층 ([`standardize/graph/`](standardize/graph/)).

![관계 그래프](media/api_asset_graph.png)

## 2. 자동화 — 기준에서 룰, 룰에서 대응까지

```
소스·설정·로그·스캔 ─▶ API-BOM / SBOM ─▶ (사람 승인) ─▶ OpenAPI 허용 목록 ─▶ Wazuh 룰 자동 생성·시험
                                                                              │
                     공격 ─▶ 접근 로그 ─▶ Wazuh ─▶ Event-Driven Ansible ─▶ 차단 · 계정 정지 · 자동 해제
                                         ▲
                     행위 특징 ─▶ ML 점수 ─┘
```

| 자동화 | 내용 | 코드 |
|---|---|---|
| 매일 수집 | GitHub Actions — SBOM 생성, API-BOM, 룰 생성·시험 | [`automate/github-actions/`](automate/github-actions/) (원본 저장소 경로 기준) |
| 룰 자동 생성 | 명세 → 메서드별 허용 경로 → "명세 밖 호출" 룰 + 응답 코드별 단계 | [`automate/rules/gen_shadow_rules.py`](automate/rules/gen_shadow_rules.py) |
| 대응을 코드로 | Wazuh → EDA → Ansible 플레이북. 허용 목록 한 곳, 60분 자동 해제, BOLA 는 **계정 정지** | [`automate/response/`](automate/response/) |
| 이식 가능한 워크플로 | 명세 → 룰 → 수집 → 특징 → 학습 → **평가 게이트** → 배포. 설정 파일만 바꿔 다른 앱에 | [`automate/portable-workflow/`](automate/portable-workflow/) |

- **룰을 실제 Wazuh 로 검증:** 배포돼 있던 BOLA 룰이 거꾸로 동작(막힌 시도는 차단, 성공한 열거는 미탐)하는 것을 `wazuh-logtest` 로 찾아 고쳤다 ([`automate/rules/wazuh_rules_v2/`](automate/rules/wazuh_rules_v2/README.md)).
- **"돈다 ≠ 잘 된다":** 학습한 모델은 공격 변종·정상 오탐 기준을 통과해야만 배포한다.

![탐지 → 대응 대시보드](media/e2e_dashboard.png)

## 3. 보안 ML — 룰이 못 쓰는 행위를 보완

| 비교 (실제 랩 로그) | 빠른 BOLA | 느린 BOLA (출발지 7곳) | 정상 오탐 |
|---|---|---|---|
| 빈도 룰 (120초에 객체 10개) | 일부 | **전부 미탐** | 0 |
| 임계값 룰 (5분에 객체 5개) | 전부 | 205/210 | 0/356 |
| ML (LOF) | 34/35 | **210/210** | 52/356 (14.6%) |

- 결론을 한쪽으로 몰지 않았다. 느린 BOLA 는 빈도 룰이 놓치고 ML 이 잡지만, BOLA 만 보면 임계값 룰이 오탐 0 으로 같은 일을 한다. ML 의 몫은 룰을 미리 쓰지 않은 종류다 ([`ml/docs/37_…`](ml/docs/), 재현 `bash ml/docs/37_결과/run.sh`).
- 모델 카드: [`ml/docs/MODEL_CARD.md`](ml/docs/MODEL_CARD.md) — 처음 보는 정상 사용자 오탐 10~15% (PoC, 운영 전).

## 4. 검증 — 다른 앱(OWASP crAPI)에서 다시

| 항목 | 고치기 전 | 고친 뒤 |
|---|---|---|
| 룰 생성 | 자체 시험 61/64 로 중단 | 72/72 |
| 생성된 룰 (실제 Wazuh) | crAPI 요청에 한 번도 안 걸림 | 명세 밖 14줄 중 10줄 경보 · 정상 400줄 0 |
| 주소 뒤 `?id=N` · UUID 열거 | 못 봄 | 탐지 (남의 차량 위치 20대) |
| 평가 게이트 | 실패 | 통과 |

| 학습에 쓴 정상 트래픽 | 실제 공격 17구간 | 사람 속도 정상 오탐 |
|---|---|---|
| 스크립트만 | high 17 | **115/120** |
| 스크립트 + 공개 데이터 재생 (OTTO · Stack Overflow) | high 15 · medium 1 | 3/120 |

상세: [`verify/crapi/`](verify/crapi/) · [`automate/portable-workflow/README.md`](automate/portable-workflow/README.md)

## 5. 스스로 정정한 것

| 처음 주장 | 정정 | 어떻게 찾았나 |
|---|---|---|
| ML 오탐 0/65 | 10~15% | 정상을 시각순이 아니라 출발지 단위로 나눔 |
| 합성 데이터에서 "느린 BOLA 는 LOF 만 잡는다" | 철회 | 피처 하나로 전부 갈리는 지름길 발견 |
| 설정만 바꾸면 다른 앱에서도 된다 | 틀림 | crAPI 에 직접 돌림 |
| 팀 웹 로그에서 ML 이 룰보다 더 잡는다 | 근거 없음 | 룰을 통과한 공격 구간 중 ML 탐지 0 |

## 한계

- 정상 트래픽은 스크립트와 공개 데이터 재생이다. 실제 서비스의 오탐률은 모른다.
- 행위 단위가 출발지 IP 라 여러 IP 로 나눈 공격은 탐지 0%. 계정·토큰 단위가 다음 단계다.
- 도달성 분석은 정적 분석이다. 실행 중 실제로 로드된 라이브러리·커널 기능을 잇는 것이 다음 목표다.
- 확인한 앱은 팀 웹과 crAPI 둘뿐이다.

## 구성

| 폴더 | 내용 |
|---|---|
| `standardize/` | API-BOM · 인벤토리 · SBOM · VEX · 판정 기준 · 관계 그래프 · 도달성 |
| `automate/` | CI · 룰 생성 · Wazuh 룰 v2 · 대응(Ansible/EDA) · 이식 가능한 워크플로 |
| `ml/` | 행위 특징 · 학습 · 탐지 · 평가(변종 · 게이트) · 랩 실험 코드 · 모델 카드 · 랩 로그 |
| `verify/crapi/` | crAPI 검증 기록 · 트래픽 생성기 |
| `media/` | 시연 영상 2개 · 대시보드 그림 · 녹화 스크립트 |

코드는 원본 저장소에서 골라 옮긴 것이라 일부 스크립트의 경로(`api-bom/…`, `e2e_story/…`, `team_one/…`)는 원본 구조 기준이다. 팀 프로젝트의 웹 애플리케이션 소스는 포함하지 않았다.
