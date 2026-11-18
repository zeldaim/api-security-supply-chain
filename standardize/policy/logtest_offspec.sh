#!/usr/bin/env bash
# 기존 Shadow API 룰 + 우선순위 룰을 실제 Wazuh(Docker wazuh-logtest)에 올려 케이스별 최종 룰 ID·레벨을 대조한다.
#   bash logtest_offspec.sh <기존 룰.xml> <우선순위 룰.xml> <cases.jsonl> [결과 저장 경로]
# 케이스의 log 를 JSON 한 줄(app.log 형식)로 넣는다. 기대 레벨은 offspec_rules.py 의 표로 계산한다.
set -euo pipefail
export MSYS_NO_PATHCONV=1 PYTHONIOENCODING=utf-8
BASE="$1"; PRIO="$2"; CASES="$3"; OUT="${4:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"; HERE="$(cygpath -m "$HERE" 2>/dev/null || echo "$HERE")"
IMG="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.6}"; C="wz-logtest-offspec"
WORK="$(mktemp -d)"; WORK="$(cygpath -m "$WORK" 2>/dev/null || echo "$WORK")"
trap 'docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" "$IMG" >/dev/null
until docker exec "$C" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done
docker cp "$BASE" "$C:/var/ossec/etc/rules/0915-shadow_api_rules.xml"
docker cp "$PRIO" "$C:/var/ossec/etc/rules/0916-offspec_priority.xml"
docker exec "$C" bash -c 'chown wazuh:wazuh /var/ossec/etc/rules/*.xml; /var/ossec/bin/wazuh-control restart >/dev/null 2>&1'
until docker exec "$C" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do sleep 2; done
sleep 3
if docker exec "$C" grep -iE "ERROR|CRITICAL" /var/ossec/logs/ossec.log | grep -iE "rule|xml"; then echo "룰 로드 오류"; exit 1; fi
echo "## 룰 로드 오류 없음 ($IMG)"
python -c "import json,sys
for l in open(sys.argv[1],encoding='utf-8'):
    if l.strip(): print(json.dumps(json.loads(l)['log'],ensure_ascii=False))" "$CASES" > "$WORK/in.log"
docker cp "$WORK/in.log" "$C:/tmp/in.log" >/dev/null
docker exec "$C" bash -c "/var/ossec/bin/wazuh-logtest < /tmp/in.log 2>&1" > "$WORK/out.txt"
[ -n "$OUT" ] && cp "$WORK/out.txt" "$OUT"
python - "$WORK/out.txt" "$CASES" "$HERE" <<'EOF'
import json, re, sys
sys.path.insert(0, sys.argv[3])
from offspec_rules import expected_level
blocks = re.split(r"\*\*Phase 1: Completed pre-decoding", open(sys.argv[1], encoding="utf-8", errors="replace").read())[1:]
cases = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
ok = 0
for c, b in zip(cases, blocks):
    rid = re.search(r"id: '(\d+)'", b); lv = re.search(r"level: '(\d+)'", b)
    got = int(lv.group(1)) if lv else 0
    want = expected_level(c)
    if got == want:
        ok += 1
    else:
        print(f"FAIL 기대 {want} 결과 {got} (룰 {rid.group(1) if rid else '-'})  {c['log']['method']} {c['log']['path']} {c['log']['status']}  ({c['note']})")
print(f"{ok}/{len(cases)} 일치 (실제 wazuh-logtest)" + ("" if len(blocks) == len(cases) else f"  ※ 출력 {len(blocks)}건 / 케이스 {len(cases)}건"))
sys.exit(0 if ok == len(cases) == len(blocks) else 1)
EOF
