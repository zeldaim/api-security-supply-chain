#!/usr/bin/env bash
# 컨테이너(e2e-runner) 안에서 실행: 로그 분리 → 모델 A(규칙 정상) · B(규칙+재생) · C(재생만) 학습·게이트 → 실제 공격 채점 → 교차 오탐
#   MSYS_NO_PATHCONV=1 docker run --rm -v "D:/shadow_api_monitoring:/repo" e2e-runner bash /repo/e2e_story/crapi_run3_2026-11-16/run_analysis.sh
cd /repo/e2e_story/crapi_run3_2026-11-16 && python split_logs.py
cd /repo; R=e2e_story/crapi_run3_2026-11-16; V=e2e_story/v2_portable; C=e2e_story/crapi_generality_2026-11-15
export PYTHONIOENCODING=utf-8 LAB_SSH= SPEC_URL= SPEC_PATH=$C/work/crapi-openapi-spec.json TRAIN_WINDOW=5 DRY=1 LOG_FORMAT=accesslog
export BOLA_TARGETS="/workshop/api/shop/orders/{id},/identity/api/v2/user/videos/{id}"
for m in A:gen B:gen_replay C:replay; do
  name=${m%%:*}; src=${m##*:}
  echo; echo "################################ 모델 $name (학습 로그: $src.log)"
  STATE_DIR=$R/state/$name WEB_LOG=$R/work/$src.log bash $V/bootstrap.sh all 2>&1 | grep -vE "^  (n_req|uniq_|top_|seq_|id_span|gap_|err_|api_|static_|n_ua|offspec)" 
done
export E2E_SPEC=$R/state/A/spec.yaml
for k in attack gen replay; do python $V/features.py extract $R/work/$k.log --window 5 --out $R/state/${k}_features.csv; done
for name in A B C; do
  [ -f $R/state/$name/model/model.joblib ] || { echo; echo "######## 모델 $name: 학습 안 됨 — 채점 생략"; continue; }
  echo; echo "################################ 모델 $name — 실제 공격 채점 (뒤의 '검증용 정상'은 이 모델의 뒤 15% 정상)"
  python $C/score_attacks.py $R/state/$name/model $R/state/attack_features.csv $R/labels_attack.jsonl $R/state/$name/holdout_features.csv
  echo "--- 교차 오탐: 모델 $name 으로 규칙 정상 전체 / 재생 정상 전체 (자기 학습분 포함 — 학습에 안 쓴 쪽 줄을 볼 것)"
  for k in gen replay; do python $C/score_attacks.py $R/state/$name/model $R/state/attack_features.csv $R/labels_attack.jsonl $R/state/${k}_features.csv | tail -1 | sed "s/^/  [$k] /"; done
done
