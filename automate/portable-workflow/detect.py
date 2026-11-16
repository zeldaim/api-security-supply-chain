#!/usr/bin/env python3
"""v2 특징으로 실시간 탐지 — 원본 e2e_story/ml/detect.py 를 그대로 실행한다. 모델은 --model 로 직접 지정한다.

  python3 detect.py --model <model_dir> --log <access.log> --alerts <ml_alerts.json> [원본과 같은 옵션]
"""
from _shim import arg, check_model, require, run_original, use_v2_features

require("--model")
check_model(arg("--model"))
use_v2_features()
run_original("ml/detect.py")
