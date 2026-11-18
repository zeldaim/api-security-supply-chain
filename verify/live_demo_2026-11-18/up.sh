#!/usr/bin/env bash
# 실시간 시연 환경 올리기: DVRA · nginx(차단 목록) · Wazuh manager(실시간 룰) · 파이프라인(ML · 자동 차단) · Grafana(3001)
#   bash up.sh        (es-local 이 elk-local 네트워크에 떠 있어야 한다 — dashboard_2026-11-18/README 참고)
set -euo pipefail
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"; W="$(cygpath -m "$HERE")"; REPO="$(cygpath -m "$HERE/../..")"
RULES="$REPO/verify/dvra/ml_run2_2026-11-18/state/0915-shadow_api_rules.xml"
RUN="run_$(date +%Y%m%d_%H%M)"; mkdir -p "$HERE/$RUN"; echo "$RUN" > "$HERE/.current_run"
docker rm -f live-nginx live-wazuh live-pipeline grafana-live >/dev/null 2>&1 || true
docker start dvra-db-1 dvra-web-1 >/dev/null
: > "$HERE/logs/access.log"; : > "$HERE/blocked/ips.map"
docker volume rm wz-live-alerts >/dev/null 2>&1 || true; docker volume create wz-live-alerts >/dev/null

docker run -d --name live-nginx --net dvra_default -p 127.0.0.1:8089:80 \
  -v "$W/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$W/logs:/logs" -v "$W/blocked:/etc/nginx/blocked:ro" nginx:1.27-alpine \
  sh -c 'nginx; old=""; while sleep 2; do new=$(md5sum /etc/nginx/blocked/ips.map); if [ "$new" != "$old" ]; then old=$new; nginx -s reload; fi; done' >/dev/null

docker run -d --name live-wazuh -v "$W/logs:/logs:ro" -v wz-live-alerts:/var/ossec/logs/alerts wazuh/wazuh-manager:4.14.6 >/dev/null
until docker exec live-wazuh test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done
docker cp "$RULES" live-wazuh:/var/ossec/etc/rules/0915-shadow_api_rules.xml
docker cp "$W/wazuh_localfile.xml" live-wazuh:/tmp/lf.xml
# 취약점 탐지(vd) 는 끈다 — 켜 두면 CVE 데이터를 내려받아 /var/ossec/queue/vd 가 몇 GB 씩 커진다(2026-11-18 16GB 로 C 드라이브가 가득 차 Docker 가 멈췄다)
docker exec live-wazuh bash -c "sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s#<enabled>yes</enabled>#<enabled>no</enabled>#' /var/ossec/etc/ossec.conf; rm -rf /var/ossec/queue/vd/*"
docker exec live-wazuh bash -c 'cat /tmp/lf.xml >> /var/ossec/etc/ossec.conf; chown wazuh:wazuh /var/ossec/etc/rules/*.xml; /var/ossec/bin/wazuh-control restart >/dev/null 2>&1'
until docker exec live-wazuh test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done

docker run -d --name live-pipeline --restart unless-stopped --net elk-local -w /repo -e PYTHONIOENCODING=utf-8 \
  -e E2E_SPEC=verify/dvra/ml_run2_2026-11-18/state/spec.yaml -e "E2E_BOLA_TARGETS=/orders/{order_id},/orders/status/{order_id}" \
  -v "$REPO:/repo" -v "$W/logs:/logs:ro" -v wz-live-alerts:/alerts:ro -v "$W/blocked:/blocked" e2e-runner \
  python -u verify/live_demo_2026-11-18/pipeline.py --log /logs/access.log --alerts /alerts/alerts.json \
  --model verify/dvra/ml_run2_2026-11-18/state/model --blocked /blocked/ips.map \
  --out "verify/live_demo_2026-11-18/$RUN" >/dev/null

( cd "$HERE" && python build_live_dashboard.py >/dev/null )
docker run -d --name grafana-live --network elk-local -p 127.0.0.1:3001:3000 \
  -e GF_AUTH_ANONYMOUS_ENABLED=true -e GF_AUTH_ANONYMOUS_ORG_ROLE=Admin -e GF_AUTH_DISABLE_LOGIN_FORM=true \
  -v "$W/grafana/provisioning:/etc/grafana/provisioning:ro" -v "$W/grafana/dashboards:/var/lib/grafana/dashboards:ro" grafana/grafana:11.6.0 >/dev/null
for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code}' -H 'X-Client-IP: 10.1.0.1' localhost:8089/healthcheck | grep -q 200 && break; sleep 2; done
echo "준비 완료 — 실행 폴더 $RUN · 대시보드 http://localhost:3001/d/live-demo · 로그 docker logs -f live-pipeline"
