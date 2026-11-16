#!/usr/bin/env python3
"""회귀 확인 — 같은 로그에서 원본 특징(e2e_story/ml/features.py)과 v2 특징이 같은 값을 내는지 본다.

  python compare_v1_v2.py <명세> <access.log> [<access.log> …]      # *.jsonl 이면 eval 세션 파일(각 줄의 "lines")로 읽는다

팀 웹(/api 접두어 · 숫자 경로 ID) 로그에서는 차이 0 이어야 한다. 차이가 나면 어느 특징이 얼마나 다른지 보여 준다.
"""
import importlib.util, json, os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
os.environ["E2E_SPEC"] = sys.argv[1]
v1 = load("features_v1", os.path.join(HERE, "..", "ml", "features.py"))
v2 = load("features_v2", os.path.join(HERE, "features.py"))
total = diff = 0
for src in sys.argv[2:]:
    path = src
    if src.endswith(".jsonl"):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
        for l in open(src, encoding="utf-8"):
            tmp.write("\n".join(json.loads(l)["lines"]) + "\n")
        tmp.close(); path = tmp.name
    a = {(ip, s): ft for ip, s, ft in v1.windows(v1.parse(path), 15)}
    b = {(ip, s): ft for ip, s, ft in v2.windows(v2.parse(path), 15)}
    d, changed = 0, {}
    for k in a:
        for f in v1.FEATURES:
            if abs(a[k][f] - b[k][f]) > 1e-9:
                d += 1; changed[f] = changed.get(f, 0) + 1
    total += len(a) * len(v1.FEATURES); diff += d
    print(f"{os.path.basename(src):28} 창 {len(a):5} (v2 {len(b):5})  다른 값 {d:5}  {changed if changed else ''}")
    if src.endswith(".jsonl"): os.unlink(path)
print(f"합계: 값 {total}개 중 {diff}개 다름")
sys.exit(1 if diff else 0)
