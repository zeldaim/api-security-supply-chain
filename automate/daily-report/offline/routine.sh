#!/usr/bin/env bash
# [직접 실행 루틴] SBOM 수집 → VM daily(DT 업로드·판정·대시보드) → 보고서 — 이 PC 의 Git Bash 에서 한 줄로
#
#   bash tools/routine.sh check    # 상태만 본다 (아무것도 바꾸지 않음)
#   bash tools/routine.sh sbom     # ① GitHub Actions 로 SBOM 수집 (오늘 것 있으면 건너뜀, FORCE=1 이면 다시)
#   bash tools/routine.sh daily    # ② VM 에서 daily.sh (실습 서버 꺼져 있으면 자동 오프라인: 수집·스캔만 건너뜀)
#   bash tools/routine.sh report   # ③ 최신 자동 보고서 보기
#   bash tools/routine.sh all      # check → sbom → daily → report 순서로 전부
#   bash tools/routine.sh dash     # 대시보드 전부 열기 — 터널(8090·8091)을 뒤에서 열고 브라우저로 DT·승인·그래프
#   bash tools/routine.sh dash-stop  # 터널 닫기
#   ※ 전부 이 PC 의 Git Bash(프롬프트에 MINGW64)에서. VM 안(yhc@yhc)에서 치면 안 된다
#
# 환경변수: VM=yhc@192.168.100.137 (VM IP 가 바뀌면)  FORCE=1 (오늘 SBOM 있어도 Actions 다시)
#           OFFLINE=auto|0|1 (기본 auto: WEB 포트 닫혀 있으면 오프라인)  DASHBOARD=1 (새 SBOM 없어도 그래프 다시)
# 문서: docs/루틴_직접실행.md   (2026-11-07 작성 — 서버가 다 꺼진 날에도 Actions 는 돌아 SBOM 은 쌓인다)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
VM=${VM:-yhc@192.168.100.137}
GH_REPO=${GH_REPO:-zeldaim/shadow_api_monitoring}
WF=api-bom.yml
# Git Bash 에는 zoneinfo 가 없어 TZ=Asia/Seoul 이 UTC 로 동작 → POSIX 형식 KST-9 (2026-11-07 리뷰)
TODAY_KST=$(TZ=KST-9 date +%F)
SSH="ssh -o BatchMode=yes -o ConnectTimeout=6"

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m[!!]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m[XX]\033[0m %s\n' "$*"; }

pull() { git pull -q --rebase --autostash && ok "git pull ($(git log -1 --format='%h %s' | cut -c1-70))" || warn "git pull 실패 — 로컬 상태로 계속"; }

latest_sbom() { ls -d sbom/results/20??-??-??_run* 2>/dev/null | sort | tail -1; }

# 최신 SBOM 이 오늘(KST) 만들어졌나 — 폴더 날짜는 UTC 라 meta.txt 의 generated_at 을 KST 로 바꿔 본다
sbom_today() {
  local d; d=$(latest_sbom); [ -n "$d" ] || return 1
  local g; g=$(sed -n 's/^generated_at: //p' "$d/meta.txt")
  [ "$(TZ=KST-9 date -d "$g" +%F 2>/dev/null)" = "$TODAY_KST" ]
}

vm_up() { $SSH "$VM" true 2>/dev/null; }

cmd_check() {
  say "0. 레포 최신화"; pull

  say "1. SBOM (GitHub Actions — 서버 없어도 돈다)"
  gh run list -R "$GH_REPO" -w "$WF" -L 3 2>/dev/null | sed 's/^/  /' || warn "gh 실패 (gh auth login)"
  local d; d=$(latest_sbom)
  if sbom_today; then ok "오늘 SBOM 있음: $d"; else warn "오늘(KST $TODAY_KST) SBOM 없음 — 최신: ${d:-없음} → routine.sh sbom"; fi
  [ -n "$d" ] && sed 's/^/     /' "$d/meta.txt"

  say "2. VM ($VM) — DT·승인 대시보드"
  if vm_up; then
    ok "VM 접속됨"
    $SSH "$VM" 'docker ps --format "{{.Names}} {{.Status}}"; export XDG_RUNTIME_DIR=/run/user/$(id -u); echo "approval(8090)/exception(8091): $(systemctl --user is-active inventory-approval policy-exception | tr "\n" " ")"' | sed 's/^/     /'
    say "3. 실습 서버 (WEB 192.168.0.141:2222) — VM 에서 확인"
    if $SSH "$VM" 'timeout 4 bash -c "</dev/tcp/192.168.0.141/2222"' 2>/dev/null; then ok "WEB 켜짐 → daily 는 수집·스캔까지 전부"
    else warn "WEB 꺼짐 → daily 는 오프라인(수집·스캔 건너뜀, 직전 결과로 판정·보고서)"; fi
  else
    bad "VM 접속 안 됨 — VMware 에서 VM 켜기 / IP 바뀌었으면 VM=yhc@<새IP> bash tools/routine.sh check"
  fi

  say "4. 오늘 기록"
  local c; c=$(git log --oneline --since="$TODAY_KST 00:00" | grep -E 'chore\(sbom\)|daily:' )
  [ -n "$c" ] && echo "$c" | sed 's/^/     /' || warn "오늘 chore(sbom)/daily 커밋 없음"
  if git log --since="$TODAY_KST 00:00" --format=%s | grep -q '^daily:'; then ok "오늘 daily 완료"; else warn "오늘 daily 안 돔 (VM 이 10:30 에 꺼져 있었으면 건너뜀) → routine.sh daily"; fi
  local r; r=$(ls reports/auto/*_보안일일보고서.md 2>/dev/null | sort | tail -1)
  echo "     최신 보고서: ${r:-없음}"
}

cmd_sbom() {
  say "① SBOM 수집 (GitHub Actions $WF)"; pull
  if sbom_today && [ "${FORCE:-0}" != 1 ]; then
    ok "오늘 SBOM 이미 있음: $(latest_sbom) — 건너뜀 (다시 하려면 FORCE=1)"; return 0
  fi
  gh workflow run "$WF" -R "$GH_REPO" --ref main || { bad "실행 요청 실패 (gh auth status 확인)"; return 1; }
  ok "실행 요청함 — 실행 번호 기다리는 중"
  local id="" i
  for i in 1 2 3 4 5 6; do
    sleep 5
    id=$(gh run list -R "$GH_REPO" -w "$WF" -e workflow_dispatch -L 1 --json databaseId,status -q '.[0] | select(.status!="completed") | .databaseId')
    [ -n "$id" ] && break
  done
  [ -n "$id" ] || { bad "실행을 못 찾음 — gh run list -R $GH_REPO -w $WF -L 3 로 직접 확인"; return 1; }
  echo "  실행 $id — 약 3~5분. 진행 화면: https://github.com/$GH_REPO/actions/runs/$id"
  if gh run watch "$id" -R "$GH_REPO" --exit-status --interval 15 >/dev/null; then ok "Actions 성공"
  else bad "Actions 실패 — gh run view $id -R $GH_REPO --log-failed"; return 1; fi
  pull
  ok "결과: $(latest_sbom)"; sed 's/^/     /' "$(latest_sbom)/meta.txt"
}

cmd_daily() {
  say "② VM daily (로그 수집·스캔 → DT 업로드 → SBOM 판정 → 그래프 → 보고서 → 커밋·push)"
  vm_up || { bad "VM 접속 안 됨 ($VM)"; return 1; }
  # DT 가 꺼져 있으면 켠다 — docker compose stop 으로 끈 컨테이너는 unless-stopped 라도 재부팅 후 안 뜬다
  if ! $SSH "$VM" 'docker ps --format "{{.Names}}" | grep -q dtrack-apiserver'; then
    warn "DT 꺼져 있음 → 켜는 중"
    $SSH "$VM" 'cd ~/apilab-git && DTRACK_BIND=0.0.0.0 DTRACK_HOST=$(hostname -I | cut -d" " -f1) docker compose -f tools/docker-compose.dtrack.yml up -d' 2>&1 | tail -3 | sed 's/^/     /'
  fi
  # DT apiserver 가 healthy 일 때까지 (VM 막 켠 직후엔 수 분). "(unhealthy)" 는 제외
  local i
  for i in $(seq 1 20); do
    if $SSH "$VM" 'docker ps --format "{{.Names}} {{.Status}}" | grep -q "apiserver.*(healthy)"'; then ok "DT apiserver healthy"; break; fi
    [ "$i" = 20 ] && { bad "DT 가 5분 넘게 healthy 아님 — ssh $VM docker ps"; return 1; }
    echo "  DT 기동 대기 중... ($i/20, 15초 간격)"; sleep 15
  done
  echo "  실행 중 (오프라인이면 약 1~3분, 스캔 포함이면 더) — VM 로그 ~/inventory_daily.log"
  # 먼저 git pull: daily.sh 자신이 이번에 바뀌었으면(오프라인 모드 등) 새 버전으로 돌게
  # daily.sh 는 exec > >(tee ...) 라 끝나도 tee 가 늦게 닫힌다 → 2초 기다린 뒤 이번 실행분만 출력, 종료 코드는 그대로 돌려준다
  local rc
  $SSH "$VM" "cd ~/apilab-git && git pull -q --rebase --autostash; n=\$(wc -l < ~/inventory_daily.log 2>/dev/null || echo 0);     OFFLINE=${OFFLINE:-auto} DASHBOARD=${DASHBOARD:-0} DAILY_PUSH=1 bash api-bom/inventory/daily.sh >> ~/inventory_daily.log 2>&1; rc=\$?; sleep 2;     tail -n +\$((n+1)) ~/inventory_daily.log | grep -E '^\[|^====='; exit \$rc" | sed 's/^/  /'
  rc=${PIPESTATUS[0]}
  [ "$rc" = 0 ] || bad "daily.sh 종료 코드 $rc — VM ~/inventory_daily.log 확인"
  pull
  return "$rc"
}

cmd_report() {
  say "③ 보고서"; pull
  local r; r=$(ls reports/auto/*_보안일일보고서.md 2>/dev/null | sort | tail -1)
  [ -n "$r" ] || { bad "자동 보고서 없음"; return 1; }
  ok "$r"
  sed -n '/^## 요약/,/^---/p' "$r" | sed 's/^/  /'
  sed -n '/^## 모니터링 인프라 현황/,/^---/p' "$r" | sed 's/^/  /'
  echo
  echo "  전체 보기: start \"$r\"     (또는 GitHub: https://github.com/$GH_REPO/blob/main/$r)"
}

DASH_SOCK=${DASH_SOCK:-$HOME/.ssh/shadow-dash.sock}
tunnel_up() { ssh -S "$DASH_SOCK" -O check "$VM" 2>/dev/null; }

cmd_dash() {
  say "대시보드 열기 (이 PC → VM 터널 + 브라우저)"
  case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) ;; *) bad "이 PC 의 Git Bash 에서 실행하세요 (지금: $(hostname) — VM 안이면 exit 로 나오기)"; return 1 ;; esac
  vm_up || { bad "VM 접속 안 됨 ($VM) — VMware 에서 VM 켜기"; return 1; }
  if tunnel_up; then ok "터널 이미 열려 있음"
  else
    rm -f "$DASH_SOCK"   # 재부팅 등으로 남은 소켓 파일 — 있으면 -M 이 마스터 없이 열려 dash-stop 이 못 닫는다
    # -f 뒤에서 실행 · -M/-S 소켓으로 나중에 dash-stop 으로 닫음 · 포트가 이미 쓰이면 실패로 알려 줌
    if ssh -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -f -N -M -S "$DASH_SOCK"          -L 8090:127.0.0.1:8090 -L 8091:127.0.0.1:8091 "$VM"; then ok "터널 열림 (8090·8091)"
    else bad "터널 실패 — 다른 창에 터널이 이미 있으면 그 창 Ctrl+C 후 다시"; return 1; fi
  fi
  local c
  for p in 8090 8091; do
    c=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://localhost:$p")
    [ "$c" = 200 ] && ok "localhost:$p 응답 200" || warn "localhost:$p 응답 $c — VM 에서 서버 확인: systemctl --user status inventory-approval policy-exception"
  done
  c=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://${VM#*@}:8082")
  [ "$c" = 200 ] && ok "DT ${VM#*@}:8082 응답 200" || warn "DT 응답 $c — 루틴_직접실행 §1-1 DT 켜기"
  local reach; reach=$(ls -d api-bom/reach/results/*/ 2>/dev/null | sort | tail -1)
  start "http://${VM#*@}:8082"
  start http://localhost:8090
  start http://localhost:8091
  local f files=(api-bom/graph/sample_dt/dashboard.html api-bom/graph/sample_dt_reach/dashboard.html)
  [ -n "$reach" ] && files+=("${reach}reach_dashboard.html" "${reach}evidence_dashboard.html")
  # 2026-11-09 추가: 11-08 에 만든 SW→커널→HW 체인 · YARA+ML 공격체인 (dash 목록에 빠져 있었음)
  files+=(api-bom/graph/sample/hw_kernel_chain.html api-bom/graph/sample/hw_kernel_chain_full.html
          api-bom/graph/sample/attack_chain_dashboard.html)
  local n=3
  for f in "${files[@]}"; do
    [ -f "$f" ] && { start "" "$(cygpath -w "$PWD/$f")"; n=$((n+1)); }   # Windows 경로로 넘김 (슬래시 경로를 cmd start 가 잘못 읽지 않게)
  done
  ok "브라우저 탭 ${n}개 열기 요청함 (DT · 8090 · 8091 · 관계 그래프 2 · 도달성 · 근거 표 · 커널 체인 2 · 공격체인)"
  echo "  다 보면: bash tools/routine.sh dash-stop"
}

cmd_dash_stop() {
  if tunnel_up; then ssh -S "$DASH_SOCK" -O exit "$VM" 2>/dev/null; ok "터널 닫음"; else ok "열린 터널 없음"; fi
}

case "${1:-}" in
  check)  cmd_check ;;
  sbom)   cmd_sbom ;;
  daily)  cmd_daily ;;
  report) cmd_report ;;
  all)    cmd_check; cmd_sbom && cmd_daily && cmd_report ;;
  dash)   cmd_dash ;;
  dash-stop) cmd_dash_stop ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
