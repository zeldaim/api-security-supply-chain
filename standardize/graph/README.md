# graph — API-BOM ↔ SBOM ↔ 취약점 관계 그래프 · 위험 점수 · VEX · 대시보드

설명·결과·검증: [../docs/06_관계그래프_대시보드.md](../docs/06_관계그래프_대시보드.md)

```bash
python api-bom/graph/build_relations.py                      # 기본 입력 → graph/sample/
python api-bom/graph/build_relations.py --grype-json g.json  # grype 전체 결과로 부품 색칠
DT_APIKEY=... python api-bom/graph/build_relations.py --dtrack-url http://<VM_IP>:8081   # DT 연동 → graph/sample_dt/
```

| 파일 | 역할 |
|---|---|
| `build_relations.py` | 파일을 읽어 관계·점수·VEX·대시보드 생성 (표준 라이브러리만) |
| `relations_rules.json` | 엔드포인트 → 부품 연결 규칙 + 실증 취약점 (코드 근거 필수) |
| `inputs/grype_summary_2026-10-30.md` | 팀 grype 요약 사본 (team_one `ab6c390:docs/sbom/results/2026-10-30/summary.md`, sha256 `53fc70b4…be17`) |
| `sample/dashboard.html` | 대시보드 (단일 HTML) |
| `sample/relations.json` | 노드·관계 (다른 도구로 재사용) |
| `sample/risk.csv` | 엔드포인트별 위험 점수 + 근거 |
| `sample/vex.cdx.json` | CycloneDX 1.6 VEX (BOM-Link 로 API-BOM 엔드포인트 지정) → DT 업로드용 |
| `sample_dt/*` | 같은 산출물을 **Dependency-Track** 부품 취약점으로 만든 것 (2026-11-03, DT+OSV 556건). 기존 `sample/` 과 나란히 비교 — [../docs/08](../docs/08_DT_구축_기록과_의미.md) |
