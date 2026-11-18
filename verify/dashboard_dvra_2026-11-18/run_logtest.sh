#!/usr/bin/env bash
# 접근 로그 전체를 실제 Wazuh(wazuh-logtest)에 통과시켜 줄마다 울린 룰을 남긴다 → to_alerts.py 가 경보 문서로 바꾼다.
#   bash run_logtest.sh <rules.xml> <access.log> <출력 파일>
set -euo pipefail
export MSYS_NO_PATHCONV=1
RULES="$(cygpath -m "$1" 2>/dev/null || echo "$1")"; LOG="$(cygpath -m "$2" 2>/dev/null || echo "$2")"; OUT="$3"; IMG="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.6}"; C=wz-logtest-dash
trap 'docker rm -f "$C" >/dev/null 2>&1 || true' EXIT
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" "$IMG" >/dev/null
until docker exec "$C" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done
docker cp "$RULES" "$C:/var/ossec/etc/rules/0915-shadow_api_rules.xml"
docker exec "$C" bash -c 'chown wazuh:wazuh /var/ossec/etc/rules/*.xml; /var/ossec/bin/wazuh-control restart >/dev/null 2>&1'
until docker exec "$C" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done
sleep 3
docker cp "$LOG" "$C:/tmp/in.log" >/dev/null
docker exec "$C" bash -c "/var/ossec/bin/wazuh-logtest < /tmp/in.log 2>&1" > "$OUT"
echo "입력 $(wc -l < "$LOG")줄 → 이벤트 $(grep -c 'Phase 1: Completed pre-decoding' "$OUT")개"
