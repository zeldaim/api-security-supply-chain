#!/usr/bin/env bash
# bootstrap v2 — 이식 가능한 탐지 워크플로. 원본 e2e_story/bootstrap.sh 는 그대로 두고 새로 만든 파일이다.
#
#   bash e2e_story/v2_portable/bootstrap.sh all          # 명세→규칙→수집→특징→학습→[평가 게이트]→배포
#   bash e2e_story/v2_portable/bootstrap.sh <stage>      # spec|rules|collect|features|train|gate|deploy
#   DRY=1 bash e2e_story/v2_portable/bootstrap.sh all    # 배포 생략
#
# 원본과 다른 점 (근거: e2e_story/crapi_generality_2026-11-15/README.md §3-2 · §7-3)
#   - 특징·학습·평가·변종은 v2_portable/ 의 것을 쓴다 (API 범위를 명세에서 뽑음, 쿼리·UUID ID 인식, 공격 변종 경로를 명세에서 만듦)
#   - 규칙은 gen_shadow_rules_v2.py 로 만든다 (범위를 명세에서, 로그 형식 선택, 시험 케이스를 명세에서)
#   - 산출물은 STATE_DIR 에만 쓴다 (원본은 평가 결과를 e2e_story/eval/ 에 덮어썼다)
#   - 새 설정 키: STATE_DIR · LOG_FORMAT(accesslog|applog) · BOLA_TARGETS · API_SCOPE · GATE_MIN_QUIET
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE/../.."
CONF="${CONFIG_ENV:-$HERE/../config.env}"       # 기본은 원본 config.env. 환경변수가 파일 값을 이긴다
set -a
while IFS= read -r _line; do
  case "$_line" in ''|\#*) continue;; esac
  _k=${_line%%=*}
  [ -n "${!_k+x}" ] && continue
  eval "$_line"
done < "$CONF"
set +a
STATE="${STATE_DIR:-e2e_story/.bootstrap_v2}"; mkdir -p "$STATE"
V=e2e_story/v2_portable
PY=${PYTHON:-python}; export PYTHONIOENCODING=utf-8
export E2E_SPEC="$STATE/spec.yaml" E2E_API_SCOPE="${API_SCOPE:-}" E2E_BOLA_TARGETS="${BOLA_TARGETS:-}"
say(){ printf '\n== %s\n' "$*"; }
die(){ printf '[중단] %s\n' "$*"; exit 1; }

stage_spec(){
  say "1. 명세 확보"
  if [ -n "${SPEC_URL:-}" ]; then curl -fsS "$SPEC_URL" -o "$STATE/spec.yaml" || die "SPEC_URL 받기 실패"
  else cp "$SPEC_PATH" "$STATE/spec.yaml" || die "SPEC_PATH 없음: $SPEC_PATH"; fi
  $PY $V/features.py scope || die "명세를 읽지 못함"
}
stage_rules(){
  say "2. Wazuh 규칙 생성 (명세 밖 = Shadow, 로그 형식 ${LOG_FORMAT:-accesslog})"
  $PY $V/gen_shadow_rules_v2.py build --spec "$STATE/spec.yaml" --log-format "${LOG_FORMAT:-accesslog}" ${API_SCOPE:+--scope "$API_SCOPE"} \
     --out "$STATE/0915-shadow_api_rules.xml" --meta "$STATE/rules_meta.json" --cases "$STATE/testcases.jsonl" \
     --base-id "${BASE_ID:-100500}" > "$STATE/rules_build.log" 2>&1 || die "규칙 생성 실패 ($STATE/rules_build.log)"
  $PY $V/gen_shadow_rules_v2.py test --meta "$STATE/rules_meta.json" --cases "$STATE/testcases.jsonl" >> "$STATE/rules_build.log" 2>&1 \
     && echo "  규칙 생성·자체시험 통과 ($(tail -1 "$STATE/rules_build.log"))" || die "규칙 자체시험 실패 ($STATE/rules_build.log)"
  echo "  실제 Wazuh 확인: bash $V/logtest_accesslog.sh $STATE/0915-shadow_api_rules.xml $STATE/rules_meta.json $STATE/testcases.jsonl"
}
stage_collect(){
  say "3. 대상 트래픽 수집 (정상 기준선 학습용)"
  if [ -n "${LAB_SSH:-}" ] && ssh -o ConnectTimeout=6 "$LAB_SSH" "test -f $WEB_LOG" 2>/dev/null; then
    scp -q "$LAB_SSH:$WEB_LOG" "$STATE/raw.log" && echo "  수집: $LAB_SSH:$WEB_LOG → raw.log"
  elif [ -f "$WEB_LOG" ]; then cp "$WEB_LOG" "$STATE/raw.log"; echo "  로컬 로그 사용: $WEB_LOG"
  else die "트래픽 로그 없음 (WEB_LOG=$WEB_LOG)"; fi
  local n; n=$(wc -l < "$STATE/raw.log"); local cut=$(( n * 85 / 100 ))
  head -n "$cut" "$STATE/raw.log" > "$STATE/train.log"
  tail -n +"$((cut+1))" "$STATE/raw.log" > "$STATE/holdout.log"
  echo "  전체 $n 줄 → 학습 $cut · 검증 $((n-cut))"
}
stage_features(){
  say "4. 특징 추출 v2 (IP×${TRAIN_WINDOW:-15}분, IP 저장 안 함)"
  $PY $V/features.py extract "$STATE/train.log" --window "${TRAIN_WINDOW:-15}" --no-ip --out "$STATE/train_features.csv" || die "학습 특징 실패"
  $PY $V/features.py extract "$STATE/holdout.log" --window "${TRAIN_WINDOW:-15}" --no-ip --out "$STATE/holdout_features.csv" || die "검증 특징 실패"
}
stage_train(){
  say "5. 모델 학습 (IsolationForest — 대상 환경 트래픽으로)"
  $PY $V/train.py "$STATE/train_features.csv" --out "$STATE/model" --source "bootstrap v2 $(date +%F) from $WEB_LOG" || die "학습 실패"
}
stage_gate(){
  say "6. ★ 평가 게이트 — 통과해야만 배포"
  [ -d "$STATE/model" ] || die "학습된 모델 없음 — train 먼저"
  $PY $V/variants.py --out-dir "$STATE/sessions" --n 40 || die "변종 생성 실패"
  $PY $V/evaluate.py --model "$STATE/model" --sessions "$STATE/sessions" --holdout "$STATE/holdout_features.csv" --out "$STATE" \
     --gate --max-fp-high "${GATE_MAX_FP_HIGH:-0.02}" --must-detect "${GATE_MUST_DETECT:-V1_sequential,V5_very_slow}" \
     --min-quiet "${GATE_MIN_QUIET:-50}" \
     || die "평가 게이트 실패 → 배포 안 함. 지표: $STATE/results.json"
}
stage_deploy(){
  say "7. 배포 (게이트 통과분만 — 모델 + 규칙)"
  [ "${DRY:-0}" = 1 ] && { echo "  DRY=1 → 배포 생략"; return; }
  [ -n "${LAB_SSH:-}" ] || die "LAB_SSH 없음 — 배포할 호스트가 없다 (DRY=1 로 생략 가능)"
  [ -d "$STATE/model" ] || die "모델 없음"
  ssh "$LAB_SSH" "mkdir -p $REMOTE_E/app/ml/model_v2 $REMOTE_E/app/ml_v2" \
     && scp -q "$STATE/model/." "$LAB_SSH:$REMOTE_E/app/ml/model_v2/" && scp -q $V/*.py "$LAB_SSH:$REMOTE_E/app/ml_v2/" \
     && echo "  모델·v2 스크립트 전송 → $REMOTE_E/app/ml/model_v2 · $REMOTE_E/app/ml_v2  (ml-detector 가 v2_portable/detect.py --model …/model_v2 를 쓰도록 서비스 파일을 바꿔야 한다 — 자동으로 바꾸지 않는다)"
  ssh "$LAB_SSH" "mkdir -p $REMOTE_E/.bootstrap_v2" \
     && scp -q "$STATE/0915-shadow_api_rules.xml" "$LAB_SSH:$REMOTE_E/.bootstrap_v2/0915-shadow_api_rules.xml" \
     && ssh "$LAB_SSH" "cd $REMOTE_E/app/ansible && ~/eda/bin/ansible-playbook deploy_rules_docker.yml \
        -e rule_src=$REMOTE_E/.bootstrap_v2/0915-shadow_api_rules.xml -e rule_name=0915-shadow_api_rules.xml" </dev/null 2>&1 | tail -3 \
     && echo "  규칙 배포(ansible) 완료" || echo "  규칙 배포 실패 — 대상 ansible 경로 확인"
}

case "${1:-all}" in
  spec) stage_spec;; rules) stage_rules;; collect) stage_collect;;
  features) stage_features;; train) stage_train;; gate) stage_gate;; deploy) stage_deploy;;
  all) stage_spec; stage_rules; stage_collect; stage_features; stage_train; stage_gate; stage_deploy
       say "완료 — 산출물: $STATE";;
  *) die "단계: spec|rules|collect|features|train|gate|deploy|all";;
esac
