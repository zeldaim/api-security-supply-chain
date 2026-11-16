#!/usr/bin/env bash
# 녹화되는 터미널 안에서 실제로 실행되는 시연. record_live.sh 가 가상 화면의 xterm 에서 이 스크립트를 돌리고 화면을 캡처한다.
# 출력은 전부 그 자리에서 실행된 명령의 실제 출력이다.
cd /repo/e2e_story
D=demo_video_2026-11-16; R3=crapi_run3_2026-11-16; V=v2_portable; L=$D/live; mkdir -p $L; rm -f $L/*
B=$'\e[1;36m'; G=$'\e[1;32m'; Y=$'\e[1;33m'; N=$'\e[0m'
say(){ printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
run(){ printf '%s$ %s%s\n' "$Y" "$*" "$N"; }
say "crAPI 에서 BOLA · Shadow API 탐지 — 실제 실행 화면 ($(date -u '+%F %T UTC'))"
run "docker ps  (대상: OWASP crAPI, 로컬 Docker)"
docker ps --format '  {{.Names}}\t{{.Status}}' | grep -E "crapi-(web|identity|community|workshop)|mailhog"
sleep 3
say "[1] 공격 3종을 서로 다른 컨테이너(= 서로 다른 출발지 IP)에서 동시에 시작"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
atk(){ run "attack $2  (간격 $3~$4초)"; docker rm -f "live-$1" >/dev/null 2>&1
  docker run -d --name "live-$1" --network crapi_default -e ATTACK_N="${5:-}" -v "$WIN_REPO/e2e_story/$R3:/t:ro" python:3.12-slim python /t/crapi_traffic_v3.py attack "$2" "$3" "$4" >/dev/null; }
atk orders  bola_orders_fast  0.2 0.5 12      # 남의 주문 12건 열거
atk vehicle bola_vehicle_fast 0.2 0.5         # 남의 차량 위치 (UUID)
atk shadow  shadow_probe      0.5 1.0         # 명세에 없는 경로 12개
say "[2] crAPI 접근 로그 (실시간) — 공격 요청이 200 / 404 로 돌아오는 모습"
run "docker logs -f crapi-web | grep orders/ vehicle/ 404"
( docker logs -f --since "$T0" crapi-web 2>/dev/null | grep --line-buffered -E '^172\.' | grep --line-buffered -E 'shop/orders/[0-9]|vehicle/.*/location|" 404 ' | cut -c1-118 ) &
TAIL=$!
docker wait live-orders live-vehicle live-shadow >/dev/null; sleep 1; pkill -P $TAIL >/dev/null 2>&1; kill $TAIL >/dev/null 2>&1
say "[3] 공격이 남긴 결과 (실제로 반환된 응답 코드)"
for n in orders vehicle shadow; do docker logs "live-$n" 2>&1 | sed -n 's/^LABEL //p' | tee -a $L/labels.jsonl | python3 -c "
import json,sys
for l in sys.stdin:
    d=json.loads(l); print('  %-18s IP %-12s 요청 %-3s 응답 %s  %s' % (d['kind'], d['ip'], d['requests'], d['codes'], ('남의 자원 200 반환: %s건' % d['returned_200']) if 'returned_200' in d else ''))"; docker rm -f "live-$n" >/dev/null; done
sleep 4
say "[4] 접근 로그 → 행위 특징(v2) → 모델 채점  (정상 트래픽만 학습한 IsolationForest)"
docker logs --since "$T0" crapi-web 2>/dev/null | grep -E '^172\.[0-9.]+ - - \[' > $L/access.log
python3 - $L <<'PY'
import json, re, sys
from datetime import datetime
c = sys.argv[1]; L = [json.loads(l) for l in open(c + "/labels.jsonl", encoding="utf-8")]
TS = re.compile(r"\[([^\]]+)\]"); out = {"attack": [], "shadow": []}
for l in open(c + "/access.log", encoding="utf-8", errors="replace"):
    ip = l.split(" ", 1)[0]; t = datetime.strptime(TS.search(l).group(1), "%d/%b/%Y:%H:%M:%S %z").timestamp()
    lab = next((x for x in L if x["ip"] == ip and x["start"] - 2 <= t <= x["end"] + 2), None)
    if lab:
        out["attack"].append(l)
        if lab["kind"] == "shadow_probe": out["shadow"].append(l)
for k, v in out.items(): open(f"{c}/{k}.log", "w", newline=chr(10), encoding="utf-8").writelines(v)
PY
run "features.py extract attack.log --window 5  →  score_attacks.py (모델 B)"
docker run --rm -v "$WIN_REPO:/repo" -w /repo -e PYTHONIOENCODING=utf-8 -e E2E_SPEC=e2e_story/$R3/state/A/spec.yaml e2e-runner sh -c \
 "python e2e_story/$V/features.py extract e2e_story/$L/attack.log --window 5 --out e2e_story/$L/attack_features.csv 2>&1 | cut -c1-110; \
  python e2e_story/crapi_generality_2026-11-15/score_attacks.py e2e_story/$R3/state/B/model e2e_story/$L/attack_features.csv e2e_story/$L/labels.jsonl e2e_story/$R3/state/B/holdout_features.csv | cut -c1-118"
sleep 6
say "[5] 명세에서 자동 생성한 Shadow API 룰을 실제 Wazuh(wazuh-logtest)로 확인"
run "logtest_accesslog.sh <생성한 룰> <메타> <케이스> shadow.log    (Wazuh 컨테이너 기동에 1~2분)"
S=$V/crapi_run_2026-11-16/state
bash $V/logtest_accesslog.sh $S/0915-shadow_api_rules.xml $S/rules_meta.json $S/testcases.jsonl $L/shadow.log 2>&1 | cut -c1-118
say "끝 — 명세 밖 호출만 경보(L1), 명세 안 BOLA 는 행위 모델이 탐지"
printf '%s  한계: 정상 트래픽은 스크립트·공개 데이터 재생 · 공격은 종류당 1회%s\n' "$G" "$N"
sleep 8
