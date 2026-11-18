#!/usr/bin/env bash
# DVRA ML 단계: 로그를 IP 로 정상/공격 분리 → bootstrap v2.1 (명세→규칙→수집→특징→학습→게이트) → 실제 공격 채점
#   bash run_ml.sh            (Git Bash 에서. 학습은 Docker 이미지 e2e-runner 안에서 돈다)
# PYTHONPATH: v2_1 의 run_v2.py 가 v2 의 train.py 를 runpy 로 부르면 v2_portable/_shim.py 를 못 찾는다(ModuleNotFoundError) — 기존 파일은 그대로 두고 경로만 넣는다.
# IP 는 나누기·채점(정답지)에만 쓴다. 모델 특징에는 IP 가 없다(features.py --no-ip).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
grep -E '^10\.10\.' work/logs/access.log > work/normal.log          # 정상 사용자 30명
grep -E '^10\.(66|77)\.' work/logs/access.log > work/attack.log     # 탐색 10.66.0.1 · BOLA 10.77.0.1
printf '%s\n' '{"ip": "10.66.0.1", "kind": "probe(명세 밖 탐색)"}' '{"ip": "10.77.0.1", "kind": "BOLA(남의 주문 열거)"}' > work/labels_attack.jsonl
echo "정상 $(wc -l < work/normal.log)줄 · 공격 $(wc -l < work/attack.log)줄"
ENVS="-e CONFIG_ENV=verify/dvra/ml_run1_2026-11-18/config.dvra_ml.env"; while IFS= read -r l; do case "$l" in ''|\#*) continue;; esac; ENVS="$ENVS -e $l"; done < config.dvra_ml.env
R=verify/dvra/ml_run1_2026-11-18; C=verify/dvra; V21=automate/portable-workflow-v2.1
export MSYS_NO_PATHCONV=1
# shellcheck disable=SC2086
docker run --rm -v "D:/api-security-supply-chain:/repo" -w /repo $ENVS -e PYTHONIOENCODING=utf-8 -e PYTHONPATH=/repo/$V21/../portable-workflow e2e-runner bash -c "
  bash $V21/bootstrap.sh all
  echo; echo '== 8. 실제 공격 채점 (IP 는 채점용으로만 남김)'
  E2E_SPEC=$R/state/spec.yaml E2E_BOLA_TARGETS='/orders/{order_id},/orders/status/{order_id}' python $V21/features.py extract $R/work/attack.log --window 5 --out $R/state/attack_features.csv
  [ -f $R/state/model/model.joblib ] && python $C/score_attacks.py $R/state/model $R/state/attack_features.csv $R/work/labels_attack.jsonl $R/state/holdout_features.csv
"
