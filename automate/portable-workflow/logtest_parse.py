#!/usr/bin/env python3
"""wazuh-logtest 출력 → 입력 줄마다 울린 룰. logtest_accesslog.sh 가 쓴다.
   python logtest_parse.py <logtest 출력> <meta.json> cases <cases.jsonl>     # 케이스 기대값과 대조
   python logtest_parse.py <logtest 출력> <meta.json> count                   # 단계별 건수만
"""
import collections, json, re, sys
out, meta_p, mode = sys.argv[1:4]
meta = json.load(open(meta_p, encoding="utf-8"))
ids = meta["rule_ids"]
stage = {str(ids[k]): k for k in ("L1", "L2", "L3", "L3E", "F1", "F2")}
undoc = {str(v) for k, v in ids.items() if k.startswith("undoc_") or k == "other_method"}
events = []
for block in re.split(r"\*\*Phase 1: Completed pre-decoding\.", open(out, encoding="utf-8", errors="replace").read())[1:]:
    m = re.search(r"\*\*Phase 3: Completed filtering \(rules\)\.\s+id: '(\d+)'\s+level: '(\d+)'", block)
    rid, lvl = (m.group(1), int(m.group(2))) if m else (None, 0)
    got = stage.get(rid) or ("OTHER" if rid in undoc else None)
    events.append((rid, lvl, got))
if mode == "count":
    c = collections.Counter((g or "경보 없음") for _, _, g in events)
    print(f"입력 {len(events)}줄 → " + " · ".join(f"{k} {v}" for k, v in sorted(c.items())))
    sys.exit(0)
cases = [json.loads(l) for l in open(sys.argv[4], encoding="utf-8")]
if len(cases) != len(events):
    sys.exit(f"케이스 {len(cases)}개인데 logtest 이벤트 {len(events)}개 — 출력 형식 확인 필요")
fails = 0
for c, (rid, lvl, got) in zip(cases, events):
    if got != c["expect"]:
        fails += 1
        print(f"FAIL 기대={c['expect']}  실제={got} (룰 {rid}, L{lvl})  {c['log']['method']} {c['log']['path']} -> {c['log']['status']}  ({c['note']})")
print(f"{len(cases) - fails}/{len(cases)} 일치 (실제 wazuh-logtest)")
sys.exit(1 if fails else 0)
