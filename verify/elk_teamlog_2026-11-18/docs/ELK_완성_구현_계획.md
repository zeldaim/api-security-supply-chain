# ELK 기반 완성 시스템 구현 계획

**작성**: YHC · **날짜**: 2026-11-05  
**전제**: ELK + DT가 같은 VM에 이미 실행 중 / Filebeat + Metricbeat 설정 완료

---

## 목표 아키텍처

```
팀 웹서버 (192.168.0.141:8000)
    ↓ Filebeat (nginx/apache 접근 로그)
    ↓ Metricbeat (시스템 메트릭)
    ↓ SSH 역방향 터널
─────────────────────────────────────
개인 VM (ELK + DT)
    ├── Elasticsearch
    │       ├── filebeat-* (실시간 접근 로그)
    │       ├── shadow-api-assets-* (nuclei 스캔 결과)
    │       └── shadow-api-findings-* (Shadow API 발견)
    ├── Kibana
    │       ├── SIEM Detection Rules (API-BOM 기반 자동 생성)
    │       └── Shadow API 대시보드
    └── DT (Dependency-Track)
            └── SBOM 취약점 추적
─────────────────────────────────────
GitHub Actions (api-bom.yml)
    → API-BOM 생성
    → Kibana SIEM 룰 JSON 생성 (신규)
    → git push → VM cron이 pull → Kibana API 자동 적재
```

---

## 구현 단계

### Step 1. Kibana SIEM 룰 변환기 추가 (파이프라인)

**파일**: `api-bom/gen_kibana_rules.py`

API-BOM의 shadow 엔드포인트 목록 → Kibana Detection Rule JSON 생성

```python
# 생성할 룰 형식 (Kibana EQL rule)
{
  "name": "Shadow API Access: GET /api/v1/users/{id}",
  "type": "eql",
  "language": "eql",
  "query": "any where url.path like \"/api/v1/users/*\" and not url.path in (\"/api/v2/users/*\")",
  "severity": "high",
  "risk_score": 73,
  "tags": ["shadow-api", "bola", "owasp-api1"]
}
```

**Actions 연동**: `run_pipeline.sh`에 `gen_kibana_rules.py` 단계 추가
**출력**: `out/kibana_shadow_rules.ndjson`

---

### Step 2. nuclei 결과 → Elasticsearch 적재

**파일**: `api-bom/nuclei/push_to_es.sh`

nuclei의 `-jsonl` 출력을 ES `shadow-api-assets-*` 인덱스에 적재:

```bash
#!/usr/bin/env bash
# nuclei JSONL → Elasticsearch bulk 적재
ES_HOST=${1:-http://localhost:9200}
JSONL=${2:-api-bom/nuclei/out/observed.jsonl}
INDEX="shadow-api-assets-$(date +%Y.%m.%d)"

while IFS= read -r line; do
  curl -s -X POST "$ES_HOST/$INDEX/_doc" \
       -H "Content-Type: application/json" \
       -d "$line" > /dev/null
done < "$JSONL"
echo "→ $INDEX 에 적재 완료"
```

**scan_assets.sh 뒤에 호출**:
```bash
bash api-bom/nuclei/push_to_es.sh http://localhost:9200 api-bom/nuclei/out/observed.jsonl
```

---

### Step 3. VM cron — 룰 자동 배포

```bash
# crontab -e (VM에서)
# Actions가 05:30 KST에 push → 06:30 KST에 VM이 pull + Kibana 적재
30 21 * * *  cd /path/to/shadow_api_monitoring && git pull && bash api-bom/deploy/kibana_deploy.sh
```

**파일**: `api-bom/deploy/kibana_deploy.sh`

```bash
#!/usr/bin/env bash
KIBANA=${1:-http://localhost:5601}
RULES="out/kibana_shadow_rules.ndjson"
[ -f "$RULES" ] || { echo "룰 파일 없음"; exit 0; }

curl -s -X POST "$KIBANA/api/detection_engine/rules/_import" \
     -H "kbn-xsrf: true" \
     -F "file=@$RULES" \
  | python3 -m json.tool
echo "→ Kibana SIEM 룰 적재 완료"
```

---

### Step 4. Kibana 인덱스 패턴 설정

VM에서 Kibana 접속 후:

| 인덱스 패턴 | 용도 |
|---|---|
| `filebeat-*` | 팀 웹서버 접근 로그 |
| `shadow-api-assets-*` | nuclei 자산 스캔 결과 |
| `metricbeat-*` | 시스템 메트릭 |

---

### Step 5. Kibana Shadow API 대시보드

생성할 시각화:

| 패널 | 데이터 소스 | 내용 |
|---|---|---|
| Shadow API 호출 추이 | filebeat-* | 시간대별 shadow 엔드포인트 접근 |
| 자산 상태 현황 | shadow-api-assets-* | live / absent / shadow 비율 |
| Top 위험 엔드포인트 | filebeat-* | 호출 빈도 × 위험도 |
| SIEM 경보 현황 | .siem-signals-* | Kibana Detection 경보 |

---

## VM 접속 후 순서

```bash
# 1. 최신 코드
git pull origin main

# 2. DT 확인
sudo docker ps | grep dtrack

# 3. ELK 확인
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool

# 4. Kibana SIEM 활성화 (처음 한 번)
curl -X POST "http://localhost:5601/api/detection_engine/index" \
     -H "kbn-xsrf: true"

# 5. 인덱스 패턴 확인
curl -s "http://localhost:9200/_cat/indices?v"

# 6. nuclei 스캔 + ES 적재
bash api-bom/nuclei/scan_assets.sh http://192.168.0.141:8000 api-bom/nuclei/out
bash api-bom/nuclei/push_to_es.sh

# 7. SBOM DT 업로드
# DT UI: http://localhost:8080 → 프로젝트 → Upload BOM
# 파일: sbom/results/최신날짜/sbom-image.cdx.json, api-bom.cdx.json

# 8. 오늘 보안 보고서 작성
# reports/2026-11-05_보안일일보고서.md
```

---

## 참고

| 자료 | 경로 |
|---|---|
| API-BOM 파이프라인 | `api-bom/run_pipeline.sh` |
| nuclei 자산 스캔 | `api-bom/nuclei/scan_assets.sh` |
| 기존 Wazuh 룰 (참고용) | `api-bom/deploy/backups/` |
| SBOM 결과 | `sbom/results/YYYY-MM-DD/` |
| VEX | `api-bom/graph/sample/vex.cdx.json` |
