#!/usr/bin/env python3
"""학습된 모델(v2.1 특징)로 접근 로그의 IP × 5분 창을 모두 채점 → CSV (e2e-runner 컨테이너 안에서).

  E2E_SPEC=<spec.yaml> E2E_BOLA_TARGETS=... python score_windows.py <access.log> <model_dir> <out.csv>
"""
import csv
import json
import os
import subprocess
import sys

import joblib
import numpy as np

log, mdir, out = sys.argv[1:4]
feat = os.path.join(os.path.dirname(out), "_features_ip.csv")
v21 = os.path.join(os.path.dirname(__file__), "..", "v2_1_portable", "features.py")              # 작업 레포
if not os.path.exists(v21):                                                                    # 공개 레포
    v21 = os.path.join(os.path.dirname(__file__), "..", "..", "automate", "portable-workflow-v2.1", "features.py")
subprocess.run([sys.executable, v21, "extract", log, "--window", "5", "--out", feat], check=True)
meta = json.load(open(os.path.join(mdir, "model_meta.json"), encoding="utf-8"))
m = joblib.load(os.path.join(mdir, "model.joblib"))
F, hi, md = meta["features"], meta["threshold_high"], meta["threshold_medium"]
rows = list(csv.DictReader(open(feat, encoding="utf-8")))
S = m.decision_function(np.array([[float(r[k]) for k in F] for r in rows]))
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["ip", "window_start", "score", "level", "n_req", "seq_id_run", "id_span_log", "err_ratio", "offspec_ratio"])
    for r, s in zip(rows, S):
        lvl = "high" if s < hi else "medium" if s < md else "-"
        w.writerow([r["ip"], r["window_start"], round(float(s), 5), lvl, r["n_req"], r["seq_id_run"],
                    r["id_span_log"], r["err_ratio"], r["offspec_ratio"]])
os.remove(feat)
print(f"창 {len(rows)}개 채점 → {out} (high {int((S < hi).sum())} · medium+ {int((S < md).sum())})")
