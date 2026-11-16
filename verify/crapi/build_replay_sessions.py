#!/usr/bin/env python3
"""공개 데이터 2종 → 재생용 세션 파일 (요청 간격과 행동 종류만 남긴다. 상품 번호·글 내용은 버린다).

  python build_replay_sessions.py <otto sample_sessions.jsonl.gz> <stackoverflow train parquet> <out.jsonl.gz> [--n 1500] [--seed 7]

출력 한 줄 = {"src":"otto"|"so","id":…,"events":[[앞 이벤트와의 간격(초), 종류], …]}   (첫 이벤트 간격은 0)
  OTTO 종류: clicks · carts · orders          Stack Overflow 종류: POST_QUESTION · POST_ANSWER · COMMENT · EDIT_* · VOTE_*
이벤트 5개 이상인 세션만, 출처별로 무작위 n 개. pyarrow 필요(parquet).
"""
import argparse, gzip, json, random, statistics
from datetime import datetime
import pyarrow.parquet as pq

ap = argparse.ArgumentParser(); ap.add_argument("otto"); ap.add_argument("so"); ap.add_argument("out")
ap.add_argument("--n", type=int, default=1500); ap.add_argument("--seed", type=int, default=7); a = ap.parse_args()
rng = random.Random(a.seed)

otto = []
for line in gzip.open(a.otto, "rt", encoding="utf-8"):
    s = json.loads(line); ev = sorted(s["events"], key=lambda e: e["ts"])
    if len(ev) >= 5:
        otto.append({"src": "otto", "id": s["session"],
                     "events": [[round((e["ts"] - (ev[i - 1]["ts"] if i else e["ts"])) / 1000, 1), e["type"]] for i, e in enumerate(ev)]})
t = pq.read_table(a.so, columns=["session_id", "event_timestamp", "action_type"]).to_pylist()
by = {}
for r in t:
    by.setdefault(r["session_id"], []).append((datetime.fromisoformat(r["event_timestamp"].replace("Z", "+00:00")).timestamp(), r["action_type"]))
so = []
for sid, ev in by.items():
    ev.sort()
    if len(ev) >= 5:
        so.append({"src": "so", "id": sid, "events": [[round(e[0] - (ev[i - 1][0] if i else e[0]), 1), e[1]] for i, e in enumerate(ev)]})

def stats(name, ss):
    gaps = [g for s in ss for g, _ in s["events"][1:]]; n = [len(s["events"]) for s in ss]; q = statistics.quantiles(gaps, n=100)
    kinds = {}
    for s in ss:
        for _, k in s["events"]: kinds[k] = kinds.get(k, 0) + 1
    print(f"{name}: 세션 {len(ss)} · 세션당 이벤트 중앙 {statistics.median(n)} · 간격(초) p25 {q[24]:.0f} p50 {q[49]:.0f} p75 {q[74]:.0f} p90 {q[89]:.0f} · 300초 초과 {sum(g > 300 for g in gaps) / len(gaps):.0%}")
    print("   종류:", dict(sorted(kinds.items(), key=lambda kv: -kv[1])))
stats("OTTO(전체 후보)", otto); stats("StackOverflow(전체 후보)", so)
pick = rng.sample(otto, min(a.n, len(otto))) + rng.sample(so, min(a.n, len(so)))
with gzip.open(a.out, "wt", encoding="utf-8") as f:
    for s in pick: f.write(json.dumps(s, separators=(",", ":")) + "\n")
print(f"→ {a.out}: {len(pick)} 세션")
