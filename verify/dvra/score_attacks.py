#!/usr/bin/env python3
"""bootstrap 이 crAPI 정상으로 학습한 모델(.bootstrap/model)로 '실제 crAPI 공격 창'과 검증용 정상 창을 채점한다.
   python score_attacks.py <model_dir> <attack_features_ip.csv> <labels_attack.jsonl> <holdout_features.csv>
"""
import csv, json, os, sys
import joblib, numpy as np
mdir, atk, lab, hold = sys.argv[1:5]
meta = json.load(open(os.path.join(mdir, "model_meta.json"), encoding="utf-8"))
m = joblib.load(os.path.join(mdir, "model.joblib")); F = meta["features"]; hi, md = meta["threshold_high"], meta["threshold_medium"]
kind = {json.loads(l)["ip"]: json.loads(l)["kind"] for l in open(lab, encoding="utf-8")}
lvl = lambda s: "high" if s < hi else "medium" if s < md else "-"
print(f"모델: 학습 창 {meta['n_windows']} · high<{hi} · medium<{md}\n")
print(f"{'공격':28}{'창시작':>12}{'요청':>5}{'seq_id_run':>11}{'id_span':>8}{'err':>6}{'offspec':>8}{'점수':>9}  판정")
rows = list(csv.DictReader(open(atk, encoding="utf-8")))
for r in rows:
    s = float(m.decision_function(np.array([[float(r[k]) for k in F]]))[0])
    print(f"{kind.get(r['ip'], '?'):28}{r['window_start']:>12}{r['n_req']:>5}{r['seq_id_run']:>11}{float(r['id_span_log']):>8.2f}{float(r['err_ratio']):>6.2f}{float(r['offspec_ratio']):>8.2f}{s:>9.4f}  {lvl(s)}")
h = list(csv.DictReader(open(hold, encoding="utf-8")))
S = m.decision_function(np.array([[float(r[k]) for k in F] for r in h]))
print(f"\n검증용 정상 창 {len(h)}개: high {int((S < hi).sum())} · medium+ {int((S < md).sum())}  (학습 시간과 겹치는 창 포함, 줄 단위 85/15 분할)")
