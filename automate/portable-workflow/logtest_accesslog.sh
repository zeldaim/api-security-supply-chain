#!/usr/bin/env bash
# 생성한 접근 로그용 Shadow API 룰을 실제 Wazuh(Docker, wazuh-logtest)로 검증한다. VM 없이 로컬에서.
#   bash logtest_accesslog.sh <rules.xml> <meta.json> <cases.jsonl> [실제 접근 로그 …]
# ① 케이스(cases.jsonl)를 접근 로그 줄로 바꿔 넣고 기대값과 대조  ② 뒤에 준 실제 로그는 단계별 건수만 센다
set -euo pipefail
export MSYS_NO_PATHCONV=1 PYTHONIOENCODING=utf-8
RULES="$1"; META="$2"; CASES="$3"; shift 3
HERE="$(cd "$(dirname "$0")" && pwd)"; HERE="$(cygpath -m "$HERE" 2>/dev/null || echo "$HERE")"   # Git Bash: python 에 D:/… 형식으로 넘긴다
IMG="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.6}"; C="wz-logtest-shadow-v2"
WORK="$(mktemp -d)"; WORK="$(cygpath -m "$WORK" 2>/dev/null || echo "$WORK")"; trap 'docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" "$IMG" >/dev/null
until docker exec "$C" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done
docker cp "$RULES" "$C:/var/ossec/etc/rules/0915-shadow_api_rules.xml"
docker exec "$C" bash -c 'chown wazuh:wazuh /var/ossec/etc/rules/*.xml; /var/ossec/bin/wazuh-control restart >/dev/null 2>&1'
until docker exec "$C" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done
sleep 3
if docker exec "$C" grep -iE "ERROR|CRITICAL" /var/ossec/logs/ossec.log | grep -iE "rule|xml"; then echo "룰 로드 오류"; exit 1; fi
echo "## 룰 로드 오류 없음 ($IMG)"
run(){ docker cp "$1" "$C:/tmp/in.log" >/dev/null; docker exec "$C" bash -c "/var/ossec/bin/wazuh-logtest < /tmp/in.log 2>&1" > "$2"; }
python "$HERE/gen_shadow_rules_v2.py" lines --cases "$CASES" > "$WORK/cases.log"
run "$WORK/cases.log" "$WORK/cases.out"
echo "## 케이스 대조"; python "$HERE/logtest_parse.py" "$WORK/cases.out" "$META" cases "$CASES" || true
for f in "$@"; do
  run "$f" "$WORK/real.out"
  echo "## 실제 로그: $(basename "$f")"; python "$HERE/logtest_parse.py" "$WORK/real.out" "$META" count
done
