#!/usr/bin/env bash
# 정상 사용자를 컨테이너로 띄운다: 규칙 기반 G명 + 공개 데이터 재생 R명 (컨테이너마다 IP 가 다르다).
#   bash run_normal_v3.sh [G=16] [R=20] [분=150]
#   bash run_normal_v3.sh collect        # 끝난 뒤 LABEL 줄을 labels_normal.jsonl 로 모은다
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; WIN_HERE="$(cd "$HERE" && pwd -W 2>/dev/null || echo "$HERE")"
export MSYS_NO_PATHCONV=1
if [ "${1:-}" = collect ]; then
  for c in $(docker ps -a --filter name=c3g- --filter name=c3r- --format '{{.Names}}'); do docker logs "$c" 2>&1 | sed -n 's/^LABEL //p'; done > "$HERE/labels_normal.jsonl"
  echo "labels_normal.jsonl: $(wc -l < "$HERE/labels_normal.jsonl") 줄"; exit 0
fi
G=${1:-16}; R=${2:-20}; MIN=${3:-150}
run(){ docker rm -f "$1" >/dev/null 2>&1; docker run -d --name "$1" --network crapi_default -v "$WIN_HERE:/t:ro" python:3.12-slim python /t/crapi_traffic_v3.py "${@:2}" >/dev/null; }
for i in $(seq 1 "$G"); do run "c3g-$i" normal $((200 + i)) "$MIN"; done; echo "규칙 기반 정상 $G 명 시작"
for i in $(seq 1 "$R"); do run "c3r-$i" replay $((200 + i)) "$MIN" /t/replay_sessions.jsonl.gz; done; echo "재생 정상 $R 명 시작"
echo "총 $((G + R)) 명 · ${MIN}분"
