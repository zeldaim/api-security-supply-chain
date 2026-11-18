# API 보안 · 소프트웨어 공급망 — 표준화와 자동화

> **명세가 없는 서비스에서 "무엇이 정상 API 이고 무엇으로 만들어졌나"를 표준 형식으로 만들고, 그 기준으로 탐지 룰 생성부터 대응까지 자동으로 돌린다.**
> 행위 기반 ML 은 룰로 못 쓰는 공격(느린 BOLA 열거)을 보완하는 층으로 붙이고, 모든 수치는 다른 앱(OWASP crAPI)에서 다시 검증했다.

보안 엔지니어 팀 프로젝트의 담당 파트(**API 명세화 · 탐지 룰 파이프라인**)에서 출발해 개인적으로 확장한 저장소입니다.

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
| 명세 밖 호출 분류 | 명세에 없다고 악성으로 단정하지 않고 승인 상태 · 소유자 · 사용 맥락으로 우선순위 | [`offspec_triage.md`](standardize/policy/offspec_triage.md) |
| 우선순위 → 경보 레벨 | 명세 밖 호출 우선순위를 Wazuh 레벨로 (기존 룰 수정 없이 하위 룰), 실제 logtest 87/87 | [`offspec_rules.md`](standardize/policy/offspec_rules.md) |

- **사람이 승인한 것만 기준이 된다.** 발견한 API 를 자동으로 기준에 넣으면 공격 대상 경로까지 "정상"이 되어 경보가 꺼진다. 도구는 후보만 내고 사람은 승인만 한다([`approval_server.py`](standardize/inventory/approval_server.py)).
- **결과** (팀 웹): 소스만 보면 Shadow 0 → 4출처를 합치면 **Shadow 4 · 외부 노출 4**. 부품 취약점 2,355건 중 API 에서 실제로 닿는 CVE 는 **23%**([`standardize/reach/`](standardize/reach/), 정적 분석).
- **관계 그래프:** 엔드포인트 → 서비스 → 이미지 → 부품 → 취약점 → 커널 계층 ([`standardize/graph/`](standardize/graph/)).

![관계 그래프](media/api_asset_graph.png)

### 승인 대시보드 — 사람은 "승인"만 한다

| 자산 승인 (기준선 v2) | 예외 승인 (v3 일반 기준) |
|---|---|
| ![자산 승인](media/approval_8090.png) | ![예외 승인](media/approval_8091.png) |

- **자산 승인:** 인벤토리에 있는데 기준선에 없는 것(추가 후보)과 판단 보류(review)를 버튼 하나로 고른다 — 추가(active) · 폐기 예정 · 보류 · 추가 안 함. 기준은 "우리가 의도해서 운영하는가"이고, 고른 결과는 누가·언제·무엇을·왜와 함께 기록돼 인벤토리와 탐지 룰이 다시 만들어진다 ([`approval_server.py`](standardize/inventory/approval_server.py)).
- **예외 승인:** 일반 기준(G1~G9 · S1~S4) 위반은 기본적으로 **고칠 대상**이다. 고치지 않고 둘 것만 사유와 **만료일 필수**로 예외 승인한다 ([`exception_server.py`](standardize/policy/exception_server.py)).
- 위 화면은 저장소에 남은 실제 판정 데이터로 서버를 띄워 캡처한 것이다(대기 후보 2 · 보류 15 / 위반 높음 37 · 중간 21).

### 근거 대시보드 — "왜 위험한가"를 근거 종류별로

| 근거 표시 관계 그래프 | 엔드포인트 위험 순위 (근거 칸) |
|---|---|
| ![근거 그래프](media/evidence_graph.png) | ![위험 순위](media/evidence_risk_table.png) |

- 엔드포인트 하나에 **동적**(로그 관측 · 블랙박스 스캔 · nuclei) · **실증**(VEX) · **정적**(코드 호출 경로로 닿는 부품) 근거를 나란히 놓는다. 그래프에서는 선 모양이 근거 종류이고 체크박스로 켜고 끈다 ([`evidence_dashboard.py`](standardize/reach/evidence_dashboard.py), [`build_relations.py`](standardize/graph/build_relations.py)).
- 시작은 "API-BOM 과 SBOM 이 그래프에 나열만 돼 있고 실제로는 이어져 있지 않다"는 문제 제기였다. 코드 호출을 따라 잇고 나서야 **고유 CVE 403개 중 309개(77%)가 어떤 엔드포인트에서도 닿지 않는다**는 결과가 나왔다. 결과를 믿기 전에 분석기 버그 5개(엉뚱한 핸들러, 인증 조건 무시, 미해석 호출 200여 건 등)를 먼저 고쳤다.
- 순위 1위: `GET /api/v1/users/{id}` — Shadow + 개인정보 + 실증된 BOLA + 닿는 Critical 부품.
- 한계: 이 앱에서는 닿는 CVE 94개가 전부 런타임 공통 부품(apache2 · glibc)이라 **엔드포인트 사이 순위를 가르지는 못한다.** 가치는 소음 제거와 영향 범위(셸에 닿는 건 `ping` 하나, JWT 라이브러리는 인증 경로만)다. 분석은 정적이고 PHP 라우팅에 맞춰져 있다.

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

### 실제 실행 화면 (2026-11-09, 팀 환경)

> 이 환경(팀 웹 · Wazuh · Dependency-Track)은 교육과정 종료로 더 이상 없다. 아래 화면이 그 실행의 기록이다. 화면 속 주소는 모두 실습망 사설 IP 이다.

**탐지 → 대응 → 승인 → 룰 재생성, 3막 시연 한 번의 기록**

| 화면 | 내용 |
|---|---|
| ![3막 요약](media/e2e_3act_summary.png) | **E2E 보안 시연 — 공격 → 탐지(ML) → 대응(Ansible) → 승인 → 룰 재생성.** 1막은 느린 BOLA 를 ML 이 잡아 차단하고, 2막은 경로 순회 공격(CWE-22)을 룰이 잡아 차단하고, 3막은 운영 중 새로 생긴 API 를 사람이 승인해 룰을 다시 만든다. 중간의 점수 그래프는 공격 구간에서 이상 점수가 임계값을 넘는 모습 |
| ![3막 허용 목록 변화](media/e2e_3act_allowlist_change.png) | **3막 — 승인 판정과 허용 목록 변화.** 새로 보인 `/api/v1/files`, `/api/v1/products` 는 reject(운영 의도 없음), `/api/v2/health` 는 add:active(운영팀 헬스체크). 허용 목록이 비어 있던 상태에서 승인된 경로만 들어간 뒤의 룰 변화도 함께 보인다 |
| ![진행 기록](media/e2e_3act_timeline.png) | **시각별 진행 기록.** 11:46 시작 → 1막 느린 BOLA 탐지, EDA 차단 → 2막 경로 순회 공격 차단 → 3막 승인 후 룰 재생성·배포 → 재확인 |

> 이 3막은 이후 회차(11-11)에서 허용 목록이 이전 회차에서 넘어와 다르게 나왔다(추정, 확인 중). 위 화면은 11-09 회차 기준이다.

**매일 자동으로 나오는 보안 보고서**

수집이 끝나면 사람이 쓰지 않고 보고서가 만들어진다. 직전 보고 대비 신규 · 해소, 가장 위험한 API 와 점수 근거, 사람이 결정할 것까지 들어 있다.

- 샘플: [`2026-11-09 보안 일일 보고서 (자동)`](automate/daily-report/sample/2026-11-09_0843_보안일일보고서.md) — 기준 위반 높음 37 · 중간 22, 부품 취약점 2,355건, 1위 `GET /api/v1/users/{id}`
- 생성기와 설명: [`automate/daily-report/`](automate/daily-report/README.md)
- **서버가 꺼진 날(출근하지 않는 날)의 자동화:** GitHub Actions 가 서버 없이 같은 보고서를 만들고, 서버가 꺼진 채 스캔해 인벤토리가 오염되는 일을 막는다 — [`오프라인 모드`](automate/daily-report/README.md#실습-서버가-꺼진-날--오프라인-자동화)

**관제 화면과 부품 취약점**

| Wazuh 경보 (Threat Hunting) | Wazuh MITRE ATT&CK 매핑 |
|---|---|
| ![Wazuh 경보](media/wazuh_alerts_threat_hunting.png) | ![MITRE 매핑](media/wazuh_mitre_mapping.png) |
| 같은 시간대 레벨 12~14 경보 7건: ML 이상 행위(느린 BOLA), 명세 밖 호출(Shadow API), SQL UNION, 경로 순회 공격 | 같은 경보가 정찰 · 초기 접근 · 탐색(T1595, T1083, T1190 등)으로 분류된 화면 |

| 엔드포인트 ↔ 부품 도달성 | Dependency-Track 포트폴리오 |
|---|---|
| ![도달성](media/reach_dashboard.png) | ![DT](media/dt_portfolio_dashboard.png) |
| 고유 CVE 403개 중 94개만 엔드포인트에서 닿고 309개는 닿지 않음(not_affected 후보) | 매일 수집한 SBOM(CycloneDX 1.6)이 버전별로 쌓이는 모습 |

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

### 개발에 쓰지 않은 앱에서 — VAmPI 실패 → v2.1 → 네 번째 앱 DVRA (2026-11-18)

| 앱 | Shadow 룰 (실제 Wazuh) | ML (BOLA) |
|---|---|---|
| VAmPI, v2 설정만 | ❌ 자체 시험 48/49 중단 · 탐색 재현율 9/15 | — |
| VAmPI, v2.1 (VAmPI 를 보고 고침) | 52/52 · 탐색 14/15 · 정상 0/362 | 특징만 확인 |
| **DVRA, v2.1 설정만 (처음 보는 앱)** | **116/118 · 탐색 15/15 · 정상 2/355** | **실제 BOLA high** · 회피 변종 4종 40/40 · 다른 세션 정상 180창 오탐 0 · 평가 게이트는 **근소 실패**(49창 < 50 · 4.1%) |

![DVRA 대시보드 — 탐색은 룰이, BOLA 는 ML 이](verify/dashboard_dvra_2026-11-18/screenshots/02_attack_window.png)

요청 수로 줄 세우면 BOLA 공격자는 공격 10분 동안에도 13위지만, **서로 다른 경로 수**로 보면 63 vs 2위 29 로 1위다 — 탐지 특징을 요청량이 아니라 객체 접근 다양성으로 잡은 이유.

![직접 만든 패널](verify/dashboard_dvra_2026-11-18/screenshots/03_my_panels.png)

팀 시연 대시보드(대응 · SOAR 중심)와 나란히: [`04_team_vs_mine.png`](verify/dashboard_dvra_2026-11-18/screenshots/04_team_vs_mine.png)

상세: [`verify/dvra/`](verify/dvra/README.md) · [`verify/vampi/`](verify/vampi/README.md) · [`automate/portable-workflow-v2.1/`](automate/portable-workflow-v2.1/README.md) · 대시보드(코드화) [`verify/dashboard_dvra_2026-11-18/`](verify/dashboard_dvra_2026-11-18/README.md) · **ML 최종 정리 [`ml/FINAL_v1.0.md`](ml/FINAL_v1.0.md)**

> **v1 제품 정의서:** [PRODUCT_V1.md](PRODUCT_V1.md) — 누가 쓰나 · v1 범위 · 성공 기준 7개와 현재 상태

## 5. 다음 목표 — 소프트웨어에서 커널까지

![소프트웨어 → 커널 ABI → 하드웨어 체인](media/kernel_chain.png)

- SBOM 패키지 200개를 앱 → 시스템 → 커널 ABI → 하드웨어 인터페이스 계층으로 나눠 이은 화면 ([`kernel_hw_chain.py`](standardize/graph/kernel_hw_chain.py)).
- **아직 결과가 아니라 방향이다.** 계층은 패키지 이름 규칙으로 나눴고(200개 중 111개는 미분류), 하드웨어 노드는 가정해서 그렸고, 선은 패키지 의존 관계다.
- 다음 단계는 이 선을 **실행 중 관측**으로 바꾸는 것: 요청을 처리한 프로세스가 실제로 로드한 라이브러리(strace · eBPF)와 실제로 부른 커널 기능을 이어, 근거 대시보드의 "정적" 칸 옆에 "런타임" 칸을 만든다.

## 6. 스스로 정정한 것

| 처음 주장 | 정정 | 어떻게 찾았나 |
|---|---|---|
| ML 오탐 0/65 | 10~15% | 정상을 시각순이 아니라 출발지 단위로 나눔 |
| 합성 데이터에서 "느린 BOLA 는 LOF 만 잡는다" | 철회 | 피처 하나로 전부 갈리는 지름길 발견 |
| 설정만 바꾸면 다른 앱에서도 된다 | 틀림 | crAPI 에 직접 돌림 |
| (v2 는) 처음 보는 앱에서도 된다 | VAmPI 에서 실패 → v2.1 로 고친 뒤 네 번째 앱 DVRA 에서 룰은 통과, ML 게이트는 근소 실패 | VAmPI · DVRA 에 설정만으로 적용 |
| 팀 웹 로그에서 ML 이 룰보다 더 잡는다 | 근거 없음 | 룰을 통과한 공격 구간 중 ML 탐지 0 |

## 한계

- 정상 트래픽은 스크립트와 공개 데이터 재생이다. 실제 서비스의 오탐률은 모른다.
- 행위 단위가 출발지 IP 라 여러 IP 로 나눈 공격은 탐지 0%. 계정·토큰 단위가 다음 단계다.
- 도달성 분석은 정적 분석이다. 실행 중 실제로 로드된 라이브러리·커널 기능을 잇는 것이 다음 목표다.
- 확인한 앱은 팀 웹 · crAPI · VAmPI · DVRA 넷이다. 공격은 앱마다 같은 생성기로 1~2회라 통계적으로 강한 주장은 못 한다.

## 구성

| 폴더 | 내용 |
|---|---|
| `standardize/` | API-BOM · 인벤토리 · SBOM · VEX · 판정 기준 · 관계 그래프 · 도달성 |
| `automate/` | CI · 룰 생성 · Wazuh 룰 v2 · 대응(Ansible/EDA) · 이식 가능한 워크플로 |
| `ml/` | 행위 특징 · 학습 · 탐지 · 평가(변종 · 게이트) · 랩 실험 코드 · 모델 카드 · 랩 로그 |
| `verify/crapi/` | crAPI 검증 기록 · 트래픽 생성기 |
| `verify/vampi/` · `verify/dvra/` | 처음 보는 앱 검증 (VAmPI 실패 · DVRA 룰 · ML 1차 무효 · 2차) |
| `verify/dashboard_dvra_2026-11-18/` | 룰(실제 Wazuh) + ML 대시보드 — Grafana 코드화 |
| `verify/elk_teamlog_2026-11-18/` | ELK 인덱스 기반 Shadow 분류 — 팀 로그 108만 줄, 9% 분류 실패 원인 수정 |
| `ml/FINAL_v1.0.md` | ML 최종 보고 v1.0 (기능 동결) |
| `media/` | 시연 영상 2개 · 대시보드 그림 · 녹화 스크립트 |

코드는 원본 저장소에서 골라 옮긴 것이라 일부 스크립트의 경로(`api-bom/…`, `e2e_story/…`, `team_one/…`)는 원본 구조 기준이다. 팀 프로젝트의 웹 애플리케이션 소스는 포함하지 않았다.

## 라이선스

이 레포에서 **제가 작성한 코드와 문서**는 [Apache License 2.0](LICENSE) 을 따릅니다.

다음은 제외합니다 (각 원저작자의 권리를 따름):
- `media/demo_team_edited_6x.mp4`, `media/poster_team.jpg` — 팀 프로젝트 시연 영상과 그 편집본
- 외부 도구·데이터(OWASP crAPI, Dependency-Track, Syft 등)는 각자의 라이선스를 따릅니다
