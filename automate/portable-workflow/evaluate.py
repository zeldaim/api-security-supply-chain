#!/usr/bin/env python3
"""v2 특징으로 평가·게이트 — 원본 e2e_story/eval/evaluate.py 를 그대로 실행한다.

  python3 evaluate.py --model <model_dir> --sessions <dir> --out <dir> [--holdout …] [--gate …]
"""
from _shim import arg, check_model, require, run_original, use_v2_features

require("--model", "--sessions", "--out")
check_model(arg("--model"))
use_v2_features()
run_original("eval/evaluate.py")
