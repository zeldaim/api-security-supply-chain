#!/usr/bin/env python3
"""v2 특징으로 학습 — 원본 e2e_story/ml/train.py 를 그대로 실행하고, 모델 메타에 feature_version=2 를 적는다.

  python3 train.py <features.csv> --out <model_dir> [원본과 같은 옵션]
"""
import json, os, sys
from _shim import FEATURE_VERSION, arg, require, run_original, use_v2_features

require("--out")
use_v2_features()
run_original("ml/train.py")                     # 실패하면 여기서 SystemExit 으로 끝난다
p = os.path.join(arg("--out"), "model_meta.json")
meta = json.load(open(p, encoding="utf-8"))
meta["feature_version"] = FEATURE_VERSION
meta["feature_module"] = "e2e_story/v2_portable/features.py"
json.dump(meta, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(f"[train v2] feature_version={FEATURE_VERSION} 기록 → {p}")
