#!/usr/bin/env python3
"""접근 로그 + 실제 wazuh-logtest 판정 + ML 창 점수 → Elasticsearch (대시보드용). 표준 라이브러리만.

  python to_es.py --log data/access_dvra_run2.log --logtest data/logtest_out.txt \
                  --ml data/ml_windows.csv [--es http://localhost:9200]

인덱스 3개 (다시 실행하면 지우고 새로 만든다)
  dvra-access        모든 요청 (Wazuh archives 역할)            시각 필드 timestamp
  wazuh-alerts-dvra  Shadow API 룰이 울린 요청만 (Wazuh alerts 모양: rule.* · data.*)
  dvra-ml            IP × 5분 창의 ML 점수·판정

경보 시각은 logtest 처리 시각이 아니라 **로그에 찍힌 요청 시각**이다.
빈도 룰(F1·F2)은 logtest 가 줄을 연달아 받는 순서로 판정했다(실제 manager 는 받은 시각 기준).
정답(label)은 출발지 IP 로 붙인다 — 시험 장치가 정상 10.10.* · 탐색 10.66.0.1 · BOLA 10.77.0.1 로 보냈다. 모델 입력에는 쓰지 않는다.
"""
import argparse
import csv
import json
import re
import urllib.request
from datetime import datetime, timezone

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"')
PHASE3 = re.compile(r"\*\*Phase 3: Completed filtering \(rules\)\.\s+id: '(\d+)'\s+level: '(\d+)'\s+description: '([^']*)'\s+groups: '\[([^\]]*)\]'")


def label(ip):
    return "normal" if ip.startswith("10.10.") else "probe" if ip == "10.66.0.1" else "bola" if ip == "10.77.0.1" else "other"


def es(method, url, body=None, ctype="application/json"):
    req = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if method == "DELETE" and e.code == 404:
            return {}
        raise


def bulk(base, index, docs):
    errs = 0
    for i in range(0, len(docs), 5000):
        lines = []
        for d in docs[i:i + 5000]:
            lines.append('{"index":{}}')
            lines.append(json.dumps(d, ensure_ascii=False))
        res = es("POST", f"{base}/{index}/_bulk?refresh=true", ("\n".join(lines) + "\n").encode(), "application/x-ndjson")
        errs += sum(1 for it in res["items"] if it["index"].get("error"))
    print(f"{index}: {len(docs):,}건 · 오류 {errs}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True)
    p.add_argument("--logtest", required=True)
    p.add_argument("--ml", required=True)
    p.add_argument("--es", default="http://localhost:9200")
    a = p.parse_args()

    blocks = re.split(r"\*\*Phase 1: Completed pre-decoding\.", open(a.logtest, encoding="utf-8", errors="replace").read())[1:]
    lines = [l.rstrip("\n") for l in open(a.log, encoding="utf-8") if l.strip()]
    if len(blocks) != len(lines):
        raise SystemExit(f"로그 {len(lines)}줄 ≠ logtest 이벤트 {len(blocks)}개")

    access, alerts = [], []
    for line, block in zip(lines, blocks):
        m = LINE.match(line)
        if not m:
            continue
        ip, ts, method, url, status, size, ua = m.groups()
        t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
        path = url.split("?")[0]
        d = {"timestamp": t, "client_ip": ip, "method": method, "path": path, "status": int(status),
             "bytes": 0 if size == "-" else int(size), "user_agent": ua, "label": label(ip)}
        r = PHASE3.search(block)
        g = re.findall(r"'([^']+)'", r.group(4)) if r else []
        if r and "shadow_api" in g and int(r.group(2)) > 0:          # 레벨 0(명세 범위 표시)은 Wazuh 에서도 경보가 아니다
            d.update({"rule_id": r.group(1), "rule_level": int(r.group(2)), "rule_group": [x for x in g if x != "shadow_api"]})
            alerts.append({"timestamp": t,
                           "rule": {"id": r.group(1), "level": int(r.group(2)), "description": r.group(3), "groups": g},
                           "data": {"client_ip": ip, "method": method, "path": path, "url": url, "status": status,
                                    "user_agent": ua},
                           "label": label(ip)})
        access.append(d)

    ml = []
    for row in csv.DictReader(open(a.ml, encoding="utf-8")):
        ml.append({"timestamp": datetime.fromtimestamp(int(row["window_start"]), timezone.utc).isoformat(),
                   "client_ip": row["ip"], "score": float(row["score"]), "level": row["level"],
                   "n_req": int(row["n_req"]), "seq_id_run": float(row["seq_id_run"]),
                   "id_span_log": float(row["id_span_log"]), "err_ratio": float(row["err_ratio"]),
                   "offspec_ratio": float(row["offspec_ratio"]), "label": label(row["ip"])})

    maps = {
        "dvra-access": {"timestamp": {"type": "date"}, "client_ip": {"type": "keyword"}, "method": {"type": "keyword"},
                        "path": {"type": "keyword"}, "status": {"type": "integer"}, "label": {"type": "keyword"},
                        "rule_id": {"type": "keyword"}, "rule_level": {"type": "integer"}, "rule_group": {"type": "keyword"},
                        "user_agent": {"type": "keyword"}},
        "wazuh-alerts-dvra": {"timestamp": {"type": "date"},
                              "rule": {"properties": {"id": {"type": "keyword"}, "level": {"type": "integer"},
                                                      "description": {"type": "keyword"}, "groups": {"type": "keyword"}}},
                              "data": {"properties": {"client_ip": {"type": "keyword"}, "method": {"type": "keyword"},
                                                      "path": {"type": "keyword"}, "url": {"type": "keyword"},
                                                      "status": {"type": "keyword"}, "user_agent": {"type": "keyword"}}},
                              "label": {"type": "keyword"}},
        "dvra-ml": {"timestamp": {"type": "date"}, "client_ip": {"type": "keyword"}, "level": {"type": "keyword"},
                    "label": {"type": "keyword"}, "score": {"type": "float"}},
    }
    for idx, docs in (("dvra-access", access), ("wazuh-alerts-dvra", alerts), ("dvra-ml", ml)):
        es("DELETE", f"{a.es}/{idx}")
        es("PUT", f"{a.es}/{idx}", json.dumps({"settings": {"number_of_replicas": 0},
                                               "mappings": {"properties": maps[idx]}}).encode())
        bulk(a.es, idx, docs)


if __name__ == "__main__":
    main()
