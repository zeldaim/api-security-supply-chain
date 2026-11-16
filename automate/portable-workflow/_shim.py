"""원본 스크립트(e2e_story/ml, e2e_story/eval)를 고치지 않고 v2 특징으로 돌리기 위한 공통 부분.

원본들은 `from features import …` 로 특징 모듈을 가져온다. 이 폴더의 features.py(v2)를 먼저 `features` 라는 이름으로
올려 두면, 원본이 자기 폴더를 sys.path 앞에 넣더라도 이미 올라온 v2 를 쓰게 된다.
"""
import json
import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FEATURE_VERSION = 2


def use_v2_features():
    sys.path.insert(0, HERE)
    import features  # noqa: F401  (v2)
    assert os.path.dirname(os.path.abspath(features.__file__)) == HERE, "v2 features 가 아닌 모듈이 올라옴"


def arg(name):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv and sys.argv.index(name) + 1 < len(sys.argv) else None


def require(*names):
    """원본의 기본 출력 위치는 원본 폴더다(기존 모델·결과를 덮어쓴다). v2 에서는 반드시 직접 지정하게 한다."""
    missing = [n for n in names if arg(n) is None]
    if missing:
        sys.exit(f"[v2] {' '.join(missing)} 를 지정해야 합니다 — 지정하지 않으면 원본 폴더의 기존 파일을 덮어씁니다")


def check_model(model_dir):
    meta = json.load(open(os.path.join(model_dir, "model_meta.json"), encoding="utf-8"))
    if meta.get("feature_version") != FEATURE_VERSION:
        sys.exit(f"[v2] 이 모델은 v2 특징으로 학습한 것이 아닙니다({model_dir}). v1 모델에 v2 특징을 넣으면 값의 뜻이 달라집니다 → v2_portable/train.py 로 다시 학습")


def run_original(rel):
    runpy.run_path(os.path.join(HERE, "..", rel), run_name="__main__")
