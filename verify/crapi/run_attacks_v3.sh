#!/usr/bin/env bash
# 공격 7종을 컨테이너 7개로 동시에 돌린다 (공격마다 출발지 IP 가 다르다). 정상 사용자가 아직 도는 동안 실행한다(IP 겹침 방지).
#   bash run_attacks_v3.sh        # 약 9분
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; WIN_HERE="$(cd "$HERE" && pwd -W 2>/dev/null || echo "$HERE")"
export MSYS_NO_PATHCONV=1
NAMES=""
run(){ docker rm -f "c3a-$1" >/dev/null 2>&1; NAMES="$NAMES c3a-$1"
  docker run -d --name "c3a-$1" --network crapi_default -v "$WIN_HERE:/t:ro" python:3.12-slim python /t/crapi_traffic_v3.py attack "$2" "$3" "$4" >/dev/null && echo "공격 시작: $2 (간격 $3~$4초)"; }
run orders-fast     bola_orders_fast           0.2 0.5
run orders-slow     bola_orders_slow           14 26
run orders-shuffled bola_orders_slow_shuffled  14 26
run report-slow     bola_report_slow           14 26
run vehicle-slow    bola_vehicle_slow          14 26
run vehicle-fast    bola_vehicle_fast          0.2 0.5
run shadow-probe    shadow_probe               5 10
echo "끝날 때까지 대기 (약 9분)…"
# shellcheck disable=SC2086
docker wait $NAMES >/dev/null
for c in $NAMES; do docker logs "$c" 2>&1 | sed -n 's/^LABEL //p'; done > "$HERE/labels_attack.jsonl"
echo "labels_attack.jsonl: $(wc -l < "$HERE/labels_attack.jsonl") 줄"; cat "$HERE/labels_attack.jsonl"
