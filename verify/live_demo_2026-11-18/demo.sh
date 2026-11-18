#!/usr/bin/env bash
# 시연 진행 (up.sh 뒤): 정상 20명 15분 + 4분째 탐색 + 6분째 BOLA, 대시보드 녹화
#   bash demo.sh
HERE="$(cd "$(dirname "$0")" && pwd)"; RUN="$HERE/$(cat "$HERE/.current_run")"; cd "$HERE"
NP="${PW_NODE_PATH:-}"
log(){ echo "$(date +%H:%M:%S) $*" | tee -a "$RUN/demo_console.log"; }
log "정상 사용자 20명 시작"; python dvra_traffic_relogin.py --users 20 --rounds 45 --pause 1.0 > "$RUN/normal_traffic.txt" 2>&1 &
NORMAL=$!
NODE_PATH="$NP" node record_live.js "$RUN/video" 900 > "$RUN/record.txt" 2>&1 &
REC=$!
sleep 240; log "탐색 공격 시작 (10.66.0.2)"; python -u attack.py probe 2>&1 | tee -a "$RUN/attack_probe.txt" | tail -2
sleep 100; log "BOLA 공격 시작 (10.77.0.2)"; python -u attack.py bola --n 150 2>&1 | tee -a "$RUN/attack_bola.txt" | grep -E "차단됨|끝"
wait $NORMAL; log "정상 트래픽 끝"; wait $REC; log "녹화 끝"
