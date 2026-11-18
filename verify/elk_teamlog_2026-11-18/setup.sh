#!/usr/bin/env bash
# 로컬 ES(보안 끔)에 인벤토리 · enrich · 파이프라인 v1(가이드 원본)/v2(팀 로그 대응) · 인덱스 템플릿을 만든다.
#   bash setup.sh [ES 주소]   (기본 http://localhost:9200)
set -euo pipefail
cd "$(dirname "$0")"
E="${1:-http://localhost:9200}"; J='Content-Type: application/json'
curl -s -XDELETE "$E/api-inventory" >/dev/null     # 다시 실행해도 인벤토리가 겹치지 않게
curl -sf -XPUT "$E/api-inventory" -H "$J" -d '{"mappings":{"properties":{"endpoint_key":{"type":"keyword"},"service":{"type":"keyword"},"owner":{"type":"keyword"},"status":{"type":"keyword"}}}}' >/dev/null
curl -sf -XPOST "$E/api-inventory/_bulk?refresh=true" -H 'Content-Type: application/x-ndjson' --data-binary @inventory.ndjson >/dev/null
curl -sf -XPUT "$E/_enrich/policy/api-inventory-policy" -H "$J" -d '{"match":{"indices":"api-inventory","match_field":"endpoint_key","enrich_fields":["service","owner","status"]}}' >/dev/null || echo "(enrich 정책 이미 있음)"
curl -sf -XPOST "$E/_enrich/policy/api-inventory-policy/_execute" >/dev/null
curl -sf -XPUT "$E/_ingest/pipeline/api-access-v1" -H "$J" --data-binary @pipeline_v1_guide.json >/dev/null
curl -sf -XPUT "$E/_ingest/pipeline/api-access-v2" -H "$J" --data-binary @pipeline_v2_teamlog.json >/dev/null
curl -sf -XPUT "$E/_index_template/shop-access" -H "$J" -d '{"index_patterns":["shop-access-*"],"template":{"settings":{"number_of_replicas":0,"refresh_interval":"30s"},"mappings":{"properties":{"api":{"properties":{"classification":{"type":"keyword"},"endpoint_key":{"type":"keyword"},"endpoint":{"type":"keyword"}}},"source":{"properties":{"ip":{"type":"ip"}}},"error":{"properties":{"message":{"type":"keyword"}}}}}}}' >/dev/null
echo "준비 완료: api-inventory $(grep -c endpoint_key inventory.ndjson)개 · 파이프라인 api-access-v1 · api-access-v2"
# 인벤토리는 다음으로 만들었다 (팀 명세):
#   MSYS_NO_PATHCONV=1 python ../tools/openapi_to_inventory.py ../api-bom/inputs/team_one_ab6c390/web/src/public/docs/openapi.yaml shop-api 웹팀 > inventory.ndjson
