#!/usr/bin/env python3
"""v2 와 v2.1 특징이 같은 로그에서 같은 값을 내는지 (회귀 확인). v2.1 은 다른 프로세스로 돌려 모듈이 섞이지 않게 한다.
  python compare_v2_v2_1.py <명세> <access.log> [--targets T1,T2]
"""
import csv, io, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
spec, log = sys.argv[1], sys.argv[2]
targets = sys.argv[sys.argv.index("--targets") + 1] if "--targets" in sys.argv else ""
env = dict(os.environ, E2E_SPEC=spec, E2E_BOLA_TARGETS=targets, E2E_API_SCOPE="")
def run(script):
    out = subprocess.run([sys.executable, script, "extract", log, "--window", "15", "--min-req", "5"],
                         env=env, capture_output=True, text=True, check=True).stdout
    return list(csv.reader(io.StringIO(out)))
a = run(os.path.join(HERE, "..", "portable-workflow", "features.py"))
b = run(os.path.join(HERE, "features.py"))
head, diff, total = a[0], 0, 0
cols = {}
for ra, rb in zip(a[1:], b[1:]):
    for h, x, y in zip(head, ra, rb):
        total += 1
        if x != y:
            diff += 1; cols[h] = cols.get(h, 0) + 1
print(f"{os.path.basename(log)}: 창 {len(a)-1}/{len(b)-1} · 값 {total} 중 {diff}개 다름 {cols if cols else ''}")
