# DVRA — 개발에 쓰지 않은 네 번째 앱 (2026-11-18)

[Damn Vulnerable RESTaurant API](https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game) 에 v2.1 워크플로([`automate/portable-workflow-v2.1/`](../../automate/portable-workflow-v2.1/README.md))를 **설정만 바꿔** 적용했다. 최종 정리: [`ml/FINAL_v1.0.md`](../../ml/FINAL_v1.0.md)

| 폴더 | 내용 | 결과 |
|---|---|---|
| [`rules_2026-11-18/`](rules_2026-11-18/README.md) | Shadow API 룰 (실제 Wazuh 4.14.6) | 116/118 · 탐색 15/15 · 정상 2/355 |
| [`ml_run1_2026-11-18/`](ml_run1_2026-11-18/README.md) | ML 1차 — **무효** (토큰 30분 만료) | 실패 기록 |
| [`ml_run2_2026-11-18/`](ml_run2_2026-11-18/README.md) | ML 2차 (재로그인) | 실제 BOLA high · 다른 세션 정상 180창 오탐 0 · 게이트 근소 실패 |

`score_attacks.py` 는 실제 공격 창 채점기(crAPI 검증 때 만든 것과 같다). 실행 환경 이미지는 [`automate/portable-workflow-v2.1/Dockerfile.runner`](../../automate/portable-workflow-v2.1/Dockerfile.runner) 로 `docker build -t e2e-runner .`
