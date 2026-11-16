#!/usr/bin/env bash
# rules_v2 를 실제 Wazuh(4.14.6, Docker)의 wazuh-logtest 로 검증한다. VM 없이 로컬에서.
#   bash api-bom/wazuh/rules_v2/logtest_docker.sh [v1|v2]   (기본 v2)
# 시나리오는 test_rules_v2.py 의 CASES 와 같다. 시나리오마다 wazuh-logtest 를 새로 띄워 빈도 상태가 섞이지 않게 한다.
set -euo pipefail
export MSYS_NO_PATHCONV=1
VER="${1:-v2}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMG="wazuh/wazuh-manager:4.14.6"; C="wz-logtest-$VER"
WORK="$(mktemp -d)"
trap 'docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" "$IMG" >/dev/null
until docker exec "$C" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done

if [ "$VER" = v1 ]; then FILES=(api-bom/wazuh/rules/0910-shadow_api_threats.xml)
else FILES=(api-bom/wazuh/rules_v2/0910-shadow_api_threats_v2.xml api-bom/wazuh/rules_v2/0911-bola_enumeration.xml); fi
for f in "${FILES[@]}"; do (cd "$ROOT" && docker cp "$f" "$C:/var/ossec/etc/rules/"); done
docker exec "$C" bash -c 'chown wazuh:wazuh /var/ossec/etc/rules/*.xml; /var/ossec/bin/wazuh-control restart >/dev/null 2>&1'
until docker exec "$C" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done
sleep 3
docker exec "$C" grep -iE "ERROR|CRITICAL" /var/ossec/logs/ossec.log | grep -i rule && { echo "룰 로드 오류"; exit 1; } || true

(cd "$ROOT" && python - "$(cygpath -m "$WORK" 2>/dev/null || echo "$WORK")" <<'PY'
import sys; sys.path.insert(0, 'api-bom/wazuh/rules_v2'); import test_rules_v2 as T
w = sys.argv[1]
for i, (name, sess, *_) in enumerate(T.CASES):
    open(f"{w}/case{i}.log", "w", newline="\n").write("\n".join(T.line(e["ip"], 0, e["url"], e["status"]) for e in sess) + "\n")
    open(f"{w}/case{i}.name", "w", encoding="utf-8").write(name)
PY
)
echo "## wazuh-logtest $VER ($IMG)"
echo "| 시나리오 | 울린 룰(레벨) × 횟수 | 최고 레벨 |"; echo "|---|---|---|"
for nf in "$WORK"/case*.name; do
  i="$(basename "$nf" .name)"
  (cd "$WORK" && docker cp "$i.log" "$C:/tmp/$i.log" >/dev/null)
  out="$(docker exec "$C" bash -c "/var/ossec/bin/wazuh-logtest < /tmp/$i.log 2>&1")"
  hits="$(echo "$out" | awk '/Phase 3/{p=1;next} p&&/^\s+id:/{id=$2} p&&/^\s+level:/{print id"(L"$2")"; p=0}' | tr -d "'" | { grep -E '^1009' || true; } | sort | uniq -c | awk '{print $2"×"$1}' | paste -sd' ' -)"
  max="$(echo "$hits" | grep -oE 'L[0-9]+' | tr -d L | sort -n | tail -1 || true)"
  echo "| $(cat "$nf") | ${hits:--} | ${max:-0} |"
done
