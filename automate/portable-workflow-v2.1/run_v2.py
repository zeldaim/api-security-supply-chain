#!/usr/bin/env python3
"""v2 스크립트(train · evaluate · variants · detect)를 v2.1 특징으로 실행한다 — v2 파일은 그대로.
  python run_v2.py <v2 스크립트 이름> [그 스크립트의 인자…]      예: python run_v2.py variants.py --out-dir …
v2.1 features 를 먼저 `features` 이름으로 올려 두면, v2 스크립트의 `import features` 가 바꿔 끼운 모듈을 받는다."""
import os, runpy, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import features  # noqa: E402,F401 — v2.1 (sys.modules['features'] 를 v2 모듈 + 바꿔 끼운 함수로 채운다)
features.load_spec()
script = os.path.join(HERE, "..", "portable-workflow", sys.argv[1])
sys.argv = [script] + sys.argv[2:]
runpy.run_path(script, run_name="__main__")
