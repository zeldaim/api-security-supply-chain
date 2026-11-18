#!/usr/bin/env python3
"""접근 로그 → Elasticsearch _bulk (Filebeat 대신, 줄을 message 필드로 넣고 ingest pipeline 을 태운다).

  python load.py <access.log> <index> <pipeline> [--es http://localhost:9200] [--batch 5000]
표준 라이브러리만 쓴다. 보안을 끈 로컬 ES 전용.
"""
import argparse
import json
import sys
import time
import urllib.request


def post(url, body):
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/x-ndjson"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("log")
    p.add_argument("index")
    p.add_argument("pipeline")
    p.add_argument("--es", default="http://localhost:9200")
    p.add_argument("--batch", type=int, default=5000)
    a = p.parse_args()
    url = f"{a.es}/{a.index}/_bulk?pipeline={a.pipeline}"
    sent = errs = 0
    buf = []
    t0 = time.time()

    def flush():
        nonlocal errs
        if buf:
            res = post(url, ("\n".join(buf) + "\n").encode("utf-8"))
            errs += sum(1 for it in res["items"] if it["create"].get("error"))
            buf.clear()

    with open(a.log, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            buf.append('{"create":{}}')
            buf.append(json.dumps({"message": line}, ensure_ascii=False))
            sent += 1
            if sent % a.batch == 0:
                flush()
                print(f"\r{sent:,}줄", end="", file=sys.stderr)
    flush()
    print(f"\n{a.index}: {sent:,}줄 전송 · bulk 오류 {errs} · {time.time() - t0:.0f}초")


if __name__ == "__main__":
    main()
