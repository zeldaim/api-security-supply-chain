#!/usr/bin/env python3
"""수집한 접근 로그를 정답 라벨(IP + 시각)로 나눈다 → work/gen.log · work/replay.log · work/gen_replay.log · work/attack.log
   python split_logs.py        (이 폴더에서. work/run3_all.log · labels_normal.jsonl · labels_attack.jsonl 필요)
"""
import json, re, collections
from datetime import datetime
L = [json.loads(l) for f in ("labels_normal.jsonl", "labels_attack.jsonl") for l in open(f, encoding="utf-8")]
by_ip = collections.defaultdict(list)
for x in L: by_ip[x["ip"]].append(x)
TS = re.compile(r"\[([^\]]+)\]")
out = {k: open(f"work/{k}.log", "w", newline="\n", encoding="utf-8") for k in ("gen", "replay", "gen_replay", "attack")}
c = collections.Counter()
for line in open("work/run3_all.log", encoding="utf-8", errors="replace"):
    ip = line.split(" ", 1)[0]; t = datetime.strptime(TS.search(line).group(1), "%d/%b/%Y:%H:%M:%S %z").timestamp()
    lab = next((x for x in by_ip.get(ip, []) if x["start"] - 40 <= t <= x["end"] + 5), None)
    if not lab: c["라벨 없음(서버 내부 호출 등)"] += 1; continue
    k = {"normal_generator": "gen", "normal_replay": "replay"}.get(lab["kind"], "attack")
    out[k].write(line); c[k] += 1
    if k != "attack": out["gen_replay"].write(line)
print(dict(c))
