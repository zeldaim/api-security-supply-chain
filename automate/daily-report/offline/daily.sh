#!/usr/bin/env bash
# [매일 자동] 인벤토리 갱신 — 실습망 VM 에서 cron 으로 실행 (문서 11 §13-3)
#
#   bash api-bom/inventory/daily.sh
#   cron: 30 1 * * * (UTC) = 10:30 KST — 실습 서버 가동 10~17시 안, Actions(05:30 KST, GitHub 러너라 서버 불필요)가 SBOM 커밋한 뒤
#   예전: 30 6 * * * cd ~/apilab-git && bash api-bom/inventory/daily.sh >> ~/inventory_daily.log 2>&1
#
# 순서: git pull → ① WEB 로그 수집 → ② 로그 관측 → ③ 블랙박스 스캔 → ④ 합치기 → ⑤ 새 후보 계산 → ⑥ DT 업로드(API-BOM·SBOM) → ⑦ 대시보드(DT 연동) → ⑧ 자동 보고서 → git 커밋(·push)
# 사람이 고르는 단계는 여기 없다 → 승인 대시보드(approval_server.py)에서 한다.
#
# 환경변수 (기본값):
#   WEB_SSH=ubuntu@192.168.0.141  WEB_PORT=2222  WEB_LOGDIR=sesac_shop_web_php/logs
#   TARGET=http://192.168.0.141:8000  WAN_IP=192.168.0.141
#   DAILY_PUSH=1 이면 push (GitHub 인증 필요)   DAILY_COMMIT=0 이면 커밋 안 함(시험용)   KEEP_DAYS=3 원본 로그 보관 일수
#   OFFLINE=1 이면 ① 로그 수집·③ 스캔을 건너뛴다 (실습 서버가 꺼진 날 — 2026-11-07 추가)
#     서버가 꺼진 채 스캔하면 모든 서비스가 "filtered" 로 기록돼 인벤토리가 오염된다 (2026-11-06 기록). 직전 스캔 결과를 그대로 쓴다.
#     OFFLINE=auto 면 WEB SSH 포트·스캔 대상(TARGET) 중 하나라도 닫혀 있으면 자동으로 오프라인 (tools/routine.sh 가 이 값으로 부른다)
set -uo pipefail
cd "$(dirname "$0")/../.."
WEB_SSH=${WEB_SSH:-ubuntu@192.168.0.141}
WEB_PORT=${WEB_PORT:-2222}
WEB_LOGDIR=${WEB_LOGDIR:-sesac_shop_web_php/logs}
TARGET=${TARGET:-http://192.168.0.141:8000}
WAN_IP=${WAN_IP:-192.168.0.141}
KEEP_DAYS=${KEEP_DAYS:-3}
PY=${PY:-python3}
INV=api-bom/inventory
RAWROOT=api-bom/inputs/logs_raw
TODAY=$(date +%F)
export PYTHONUTF8=1
# 실행 기록 (2026-11-05): 이 실행의 출력 전체를 레포 api-bom/inventory/runs/ 에 실행마다 한 파일로 남기고 커밋한다
#   (VM 의 ~/inventory_daily.log 는 그대로 이어 쓰고, 레포에는 실행별로 쌓인다)
RUNDIR=api-bom/inventory/runs; mkdir -p "$RUNDIR"
#   실행 중 로그는 레포 밖(~/daily_runs)에 쓴다 — push 전 pull --autostash 가 레포 안 로그 파일을 교체해
#   tee 가 지운 파일에 계속 써서 마지막 줄([push]·끝)이 빠졌다 (2026-11-05 15:30 실행). 레포에는 복사본을 커밋.
#   이전 실행들의 완전한 로그는 다음 실행 시작 때 다시 복사돼 같이 커밋된다.
LIVE=${DAILY_LIVE_DIR:-$HOME/daily_runs}; mkdir -p "$LIVE"
RUNNAME="$(date +%F_%H%M%S)_$(hostname).txt"
RUNLOG="$RUNDIR/$RUNNAME"
for f in "$LIVE"/*.txt; do [ -f "$f" ] && cp "$f" "$RUNDIR/"; done
exec > >(tee "$LIVE/$RUNNAME") 2>&1
echo "===== $(date '+%F %T') 인벤토리 갱신 시작"

OFFLINE=${OFFLINE:-0}
if [ "$OFFLINE" = auto ]; then
  WEB_HOST=${WEB_SSH#*@}
  # SSH(로그 수집)와 스캔 대상(TARGET) 둘 다 열려 있어야 온라인 — 하나라도 닫히면 스캔 오염 방지로 오프라인 (2026-11-07 리뷰)
  T_HOSTPORT=${TARGET#*://}; T_HOSTPORT=${T_HOSTPORT%%/*}; T_HOST=${T_HOSTPORT%%:*}; T_PORT=${T_HOSTPORT##*:}
  [ "$T_PORT" = "$T_HOSTPORT" ] && T_PORT=80
  if timeout 5 bash -c "</dev/tcp/$WEB_HOST/$WEB_PORT" 2>/dev/null && timeout 5 bash -c "</dev/tcp/$T_HOST/$T_PORT" 2>/dev/null; then OFFLINE=0; else OFFLINE=1; fi
fi
[ "$OFFLINE" = 1 ] && echo "[오프라인] 실습 서버(WEB ${WEB_SSH#*@}:$WEB_PORT · 스캔 대상 $TARGET) 꺼짐 → ① 로그 수집·③ 스캔 건너뜀, 직전 결과로 ④~⑧ 진행"

[ "${DAILY_COMMIT:-1}" = 1 ] && { git pull -q --rebase --autostash || echo "[경고] git pull 실패 — 로컬 상태로 계속"; }

# ① WEB 로그 수집 (SSH 키 필요. 실패하면 가장 최근 원본으로 진행)
if [ "$OFFLINE" = 1 ]; then
  echo "[1] 로그 수집 건너뜀 (오프라인) — 기존 원본 사용"
elif mkdir -p "$RAWROOT/$TODAY" && ssh -o BatchMode=yes -o ConnectTimeout=8 -p "$WEB_PORT" "$WEB_SSH" \
     "cd $WEB_LOGDIR && tar czf - apache/shop_access.log waf/access.log app.log" | tar xzf - -C "$RAWROOT/$TODAY"; then
  echo "[1] 로그 수집 완료: $RAWROOT/$TODAY ($(du -sh "$RAWROOT/$TODAY" | cut -f1))"
else
  rmdir "$RAWROOT/$TODAY" 2>/dev/null || true
  echo "[1] 로그 수집 실패 (WEB SSH 키 확인) — 기존 원본 사용"
fi
LOGDIR=$(ls -d "$RAWROOT"/20??-??-?? 2>/dev/null | sort | tail -1)
# 오래된 원본 정리 (git 에는 안 올라감, 디스크만 차지)
ls -d "$RAWROOT"/20??-??-?? 2>/dev/null | sort | head -n -"$KEEP_DAYS" | xargs -r rm -rf

# ② 로그 관측
if [ -n "$LOGDIR" ]; then
  $PY $INV/observe_logs.py "$LOGDIR" api-bom/baseline/baseline.csv $INV > /dev/null && echo "[2] 로그 관측 완료 ($LOGDIR)"
else
  echo "[2] 원본 로그 없음 — 이전 endpoints_observed.csv 유지"
fi

# ③ 블랙박스 스캔 (GET 약 350건, 초당 10건)
if [ "$OFFLINE" = 1 ]; then
  echo "[3] 스캔 건너뜀 (오프라인) — 직전 scan_*.csv 유지"
else
  $PY $INV/discover_blackbox.py "$TARGET" "$WAN_IP" $INV > /dev/null && echo "[3] 스캔 완료"
fi

# ④ 합치기 → ⑤ 새 후보 (사람 선택은 보존) → 검증
$PY $INV/merge_inventory.py > /dev/null && echo "[4] 합치기 완료"
$PY $INV/make_baseline_v2.py
if $PY -c "import cyclonedx" 2>/dev/null; then
  $PY api-bom/tools/source_to_baseline.py validate $INV/inventory.cdx.json || exit 1
else
  echo "[검증 건너뜀] cyclonedx-python-lib 없음"
fi

# ⑥ Dependency-Track 자동 업로드 (tools/dt_upload.sh, 키는 레포 밖 ~/.dt_env: DT_URL·DT_APIKEY)
#    API-BOM(inventory.cdx.json)          → sesac-shop-api@오늘        : 내용이 바뀐 날만
#    SBOM(sbom/results/<최신>/, Actions 커밋) → sesac-shop-image@그 날짜 : 새 SBOM 일 때만, --upstream 사본
#    (2026-11-05: GitHub 토큰으로 팀 CI artifact 받던 방식 → 레포에 쌓인 SBOM 을 읽는 방식으로 변경. 토큰 불필요)
SBOM_NEW=0
bash tools/dt_upload.sh api 2>&1 | sed 's/^/[6] /'
R=$(bash tools/dt_upload.sh sbom 2>&1); echo "$R" | sed 's/^/[6] /'
grep -q "업로드 완료" <<<"$R" && SBOM_NEW=1

# ⑥-a 자산 일반 기준 판정 v3 (문서 12, G1~G9) — 2026-11-10 추가: 전에는 8091 서버만 호출해서 판정이 11-03 에 멈춰 있었다
$PY api-bom/policy/judge.py 2>&1 | sed 's/^/[6a] /'

# ⑥-b SBOM 변화 판정 (문서 13): 최신 DT 스냅샷 + SBOM 을 일반 기준 S1~S4 로 → 위반만 예외 승인 대시보드(8091)에
$PY api-bom/policy/sbom_review.py 2>&1 | sed 's/^/[6b] /'

# ⑦ 자산 관계 대시보드(DT 연동) 재생성 → api-bom/graph/sample_dt/ (DT 최신 이미지 버전 기준)
#    새 SBOM 이 올라간 날, 또는 DASHBOARD=1 일 때. DT 가 매일 재평가한 결과도 이때 반영된다.
DASH_FILES=""
if [ -f "${DT_ENV:-$HOME/.dt_env}" ] && { [ $SBOM_NEW = 1 ] || [ "${DASHBOARD:-0}" = 1 ]; }; then
  REACH_JSON=$(ls -d api-bom/reach/results/*/ 2>/dev/null | sort | tail -1)reach.json
  if ( set -a; . "${DT_ENV:-$HOME/.dt_env}"; set +a
       $PY api-bom/graph/build_relations.py --dtrack-url "$DT_URL" --dtrack-version latest
       # 도달성 결과가 있으면 reach 반영 그래프(sample_dt_reach)도 갱신 — 점수를 자산/도달/실증 으로 분리, comp_cve 는 도달 부품만
       [ -f "$REACH_JSON" ] && $PY api-bom/graph/build_relations.py --dtrack-url "$DT_URL" --dtrack-version latest --reach "$REACH_JSON" ) > /tmp/daily_dash.log 2>&1; then
    echo "[7] 대시보드 재생성 완료 (api-bom/graph/sample_dt/$([ -f "$REACH_JSON" ] && echo ' + sample_dt_reach/ 도달성 반영'), $(grep -o 'sesac-shop-image@[0-9-]*' api-bom/graph/sample_dt/relations.json | head -1))"
    DASH_FILES="api-bom/graph/sample_dt"
    [ -f "$REACH_JSON" ] && DASH_FILES="$DASH_FILES api-bom/graph/sample_dt_reach"
  else
    echo "[7] 대시보드 재생성 실패: $(tail -1 /tmp/daily_dash.log)"
  fi
else
  echo "[7] 대시보드 건너뜀 (새 SBOM 없음 — 강제로 하려면 DASHBOARD=1)"
fi

cp "$LIVE/$RUNNAME" "$RUNLOG"   # 지금까지의 로그를 레포로 (보고서·커밋용)
# ⑧ 자동 보안 일일 보고서 (reports/auto_v2/<날짜>_<시각>_보안일일보고서.md, 실행마다 새 파일로 쌓음) — 양식: reports/보고서_양식_가이드.md
# 2026-11-10: v1(tools/daily_report.py) → v2 — 입력 미갱신 경고 · 위험 순 정렬 · 런타임 경보 섹션. v1 은 남겨 둠(reports/auto/ 기록)
#   WAZUH_ALERTS 에 alerts.json 경로를 주면 런타임 섹션이 채워진다 (없으면 '데이터 없음'으로 명시)
$PY tools/daily_report_v2.py "$LIVE/$RUNNAME" ${WAZUH_ALERTS:+--alerts "$WAZUH_ALERTS"} 2>&1 | sed 's/^/[8] /'

# 바뀐 것만 보고 (어제와 비교)
echo "[변화] $(git diff --stat -- $INV/inventory.md $INV/candidates.csv | tail -1)"
git diff -U0 -- $INV/inventory.md | grep '^[+-]|' | head -20

# VM 상태 기록 (키·비밀번호 없음): cron · DT 업로드 기록 · DT/Docker 상태 · 디스크 — VM 에만 있던 것을 레포에 남긴다
{
  echo "# VM 상태 $(date '+%F %T %Z') $(hostname)"
  echo "## crontab"; crontab -l 2>/dev/null | grep -v '^#'
  echo "## ~/.dt_uploaded (DT 에 올린 파일 해시)"; cat "${DT_STATE:-$HOME/.dt_uploaded}" 2>/dev/null
  echo "## ~/.dt_env (키 이름만)"; sed 's/=.*/=…/' "${DT_ENV:-$HOME/.dt_env}" 2>/dev/null
  echo "## docker"; docker ps --format '{{.Names}} {{.Image}} {{.Status}}' 2>/dev/null
  echo "## disk"; df -h / 2>/dev/null | tail -1
  echo "## memory"; free -m 2>/dev/null | sed -n 2p
} > "$RUNDIR/vm_state.txt"

cp "$LIVE/$RUNNAME" "$RUNLOG"
if [ "${DAILY_COMMIT:-1}" != 1 ]; then
  echo "[커밋] 건너뜀 (DAILY_COMMIT=0)"
else
git add -- $INV/endpoints_observed.csv $INV/observe_summary.md $INV/scan_endpoints.csv $INV/scan_ports.csv \
           $INV/scan_summary.md $INV/inventory.cdx.json $INV/inventory.md $INV/candidates.csv $INV/baseline_v2.csv $DASH_FILES            api-bom/dt_history "$RUNDIR"            api-bom/policy/sbom_judgement.csv api-bom/policy/sbom_report.md reports/auto reports/auto_v2            api-bom/policy/judgement.csv api-bom/policy/report.md api-bom/policy/inventory_v3.cdx.json
if git diff --cached --quiet; then
  echo "[커밋] 바뀐 것 없음"
else
  git commit -q -m "daily: 인벤토리 갱신 $TODAY ($(hostname))" && echo "[커밋] 완료"
  # 실행 중에 다른 곳(이 PC 문서·Actions·승인 서버)이 먼저 push 했을 수 있다 → 받아서 위에 얹고 push (2026-11-05 push 거절)
  if [ "${DAILY_PUSH:-0}" = 1 ]; then
    git pull -q --rebase --autostash && git push -q && echo "[push] 완료" || echo "[push] 실패 — pull 충돌 또는 인증 확인"
  fi
fi
fi
PENDING=$($PY -c "import sys;sys.path.insert(0,'$INV');import decisions as D;print(len(D.pending_candidates()))")
echo "===== 끝. 선택 대기 후보 ${PENDING}개 → 승인 대시보드에서 고르기"
