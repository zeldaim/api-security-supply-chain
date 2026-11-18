#!/usr/bin/env python3
"""실시간 시연 파이프라인 (e2e-runner 컨테이너 안에서) — 5초마다
  ① nginx 접근 로그 새 줄 → ES live-access
  ② Wazuh manager 경보(alerts.json) 새 줄 → ES live-alerts  (Shadow API 룰만)
  ③ v1.0 ML 모델로 IP × 5분 창 채점 → ES live-ml
  ④ 차단 정책에 걸리면 blocked/ips.map 에 추가 (nginx 가 다시 읽어 403) → ES live-response, events.jsonl

차단 정책 (README 와 같게 유지)
  ML high (그 창 요청 15건 이상)           → 자동 차단 (명세 안 BOLA — 룰이 못 잡는다)
  Shadow 룰 L3(숨은 API 호출 성공) · F1 · F2 → 자동 차단
  Shadow 룰 L1 · L2 · 기타                  → 기록만
  허용 목록(--allow, 기본 헬스체크 10.1.0.1)  → 걸려도 차단하지 않고 기록만
정답 라벨(normal · probe · bola)은 시험 장치의 출발지 IP 로 붙인다 — 화면 표시용, 판정에는 안 쓴다.

  python pipeline.py --log /logs/access.log --alerts /alerts/alerts.json --model <dir> --blocked /blocked/ips.map \
                     --out <run 폴더> [--es http://es-local:9200] [--every 5]
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
_V21, _V2 = os.path.join(HERE, "..", "v2_1_portable"), os.path.join(HERE, "..", "v2_portable")          # 작업 레포
if not os.path.isdir(_V21):                                                                           # 공개 레포
    _V21 = os.path.join(HERE, "..", "..", "automate", "portable-workflow-v2.1")
    _V2 = os.path.join(HERE, "..", "..", "automate", "portable-workflow")
sys.path.insert(0, _V21)
sys.path.insert(1, _V2)
import features as F  # noqa: E402  (v2.1 — v2 모듈에 바꿔 끼운 함수)

import joblib  # noqa: E402
import numpy as np  # noqa: E402

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"')
BLOCK_RULE_GROUPS = {"shadow_api_exploit", "shadow_api_recon_burst", "shadow_api_mass_exfil"}


def label(ip):
    return "normal" if ip.startswith("10.10.") else "probe" if ip.startswith("10.66.") else "bola" if ip.startswith("10.77.") else "other"


def es(method, url, body=None, ctype="application/json", tries=6):
    """ES 가 잠깐 느려도 죽지 않게 재시도 (시작 직후 타임아웃으로 멈춘 적 있음)."""
    for k in range(tries):
        req = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (400, 404) and method in ("PUT", "DELETE"):
                return {}
            raise
        except (TimeoutError, urllib.error.URLError, ConnectionError) as e:
            print(f"[ES 재시도 {k + 1}/{tries}] {e}", flush=True)
            time.sleep(5)
    raise RuntimeError(f"ES 응답 없음: {method} {url}")


def bulk(base, index, docs, ids=None):
    if not docs:
        return
    lines = []
    for i, d in enumerate(docs):
        lines.append(json.dumps({"index": {"_id": ids[i]}} if ids else {"index": {}}))
        lines.append(json.dumps(d, ensure_ascii=False))
    es("POST", f"{base}/{index}/_bulk", ("\n".join(lines) + "\n").encode(), "application/x-ndjson")


class Tail:
    """파일 새 줄만 읽는다 (회전 · 잘림이면 처음부터)."""

    def __init__(self, path):
        self.path, self.pos = path, 0

    def lines(self):
        if not os.path.exists(self.path):
            return []
        if os.path.getsize(self.path) < self.pos:
            self.pos = 0
        with open(self.path, encoding="utf-8", errors="replace") as f:
            f.seek(self.pos)
            data = f.read()
            self.pos = f.tell()
        return [l for l in data.split("\n") if l.strip()]


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True)
    p.add_argument("--alerts", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--blocked", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--es", default="http://es-local:9200")
    p.add_argument("--every", type=float, default=5)
    p.add_argument("--window", type=int, default=5)
    p.add_argument("--allow", default="10.1.0.1",
                   help="차단하지 않을 IP (쉼표) — 헬스체크 · 모니터링. 2026-11-18 첫 실행에서 up.sh 헬스체크(10.1.0.1)가 ML high 로 차단됨")
    p.add_argument("--block-min-req", type=int, default=15,
                   help="ML 로 차단하려면 그 창 요청이 이만큼 쌓여야 한다 — 접속 직후 몇 초에 몰린 짧은 창 오탐 방지(대응 정책, 모델은 그대로)")
    a = p.parse_args()

    F.load_spec()
    meta = json.load(open(os.path.join(a.model, "model_meta.json"), encoding="utf-8"))
    model = joblib.load(os.path.join(a.model, "model.joblib"))
    FEAT, HI, MD = meta["features"], meta["threshold_high"], meta["threshold_medium"]
    os.makedirs(a.out, exist_ok=True)
    events = open(os.path.join(a.out, "events.jsonl"), "a", encoding="utf-8")

    maps = {
        "live-access": {"timestamp": {"type": "date"}, "client_ip": {"type": "keyword"}, "method": {"type": "keyword"},
                        "path": {"type": "keyword"}, "status": {"type": "integer"}, "label": {"type": "keyword"},
                        "blocked": {"type": "boolean"}},
        "live-alerts": {"timestamp": {"type": "date"},
                        "rule": {"properties": {"id": {"type": "keyword"}, "level": {"type": "integer"},
                                                "description": {"type": "keyword"}, "groups": {"type": "keyword"}}},
                        "data": {"properties": {"client_ip": {"type": "keyword"}, "method": {"type": "keyword"},
                                                "path": {"type": "keyword"}, "status": {"type": "keyword"}}},
                        "label": {"type": "keyword"}},
        "live-ml": {"timestamp": {"type": "date"}, "client_ip": {"type": "keyword"}, "level": {"type": "keyword"},
                    "label": {"type": "keyword"}, "score": {"type": "float"}},
        "live-response": {"timestamp": {"type": "date"}, "client_ip": {"type": "keyword"}, "source": {"type": "keyword"},
                          "reason": {"type": "keyword"}, "label": {"type": "keyword"}},
    }
    for idx, m in maps.items():
        es("DELETE", f"{a.es}/{idx}")
        es("PUT", f"{a.es}/{idx}", json.dumps({"settings": {"number_of_replicas": 0, "refresh_interval": "2s"},
                                               "mappings": {"properties": m}}).encode())

    blocked = {}
    if os.path.exists(a.blocked):
        for l in open(a.blocked, encoding="utf-8"):
            if l.strip():
                blocked[l.split()[0]] = "(시작 전부터)"

    allow = {x.strip() for x in a.allow.split(",") if x.strip()}

    def block(ip, source, reason, detail):
        if ip in blocked:
            return
        if ip in allow:                              # 허용 목록 — 차단하지 않고 기록만 (한 번)
            blocked[ip] = "(허용 목록 — 차단 안 함)"
            events.write(json.dumps({"type": "allowlisted", "timestamp": iso(time.time()), "client_ip": ip, "source": source,
                                     "reason": reason, "detail": detail}, ensure_ascii=False) + "\n")
            events.flush()
            print(f"[허용 목록] {ip} ← {source}: {reason} — 차단하지 않음", flush=True)
            return
        blocked[ip] = reason
        with open(a.blocked, "a", encoding="utf-8") as f:
            f.write(f"{ip} 1;\n")
        now = time.time()
        ev = {"timestamp": iso(now), "client_ip": ip, "source": source, "reason": reason, "detail": detail,
              "label": label(ip)}
        bulk(a.es, "live-response", [ev])
        events.write(json.dumps({"type": "block", **ev}, ensure_ascii=False) + "\n")
        events.flush()
        print(f"[차단] {ip} ← {source}: {reason} ({detail})", flush=True)

    acc, alr = Tail(a.log), Tail(a.alerts)
    ml_seen = {}                   # (ip, bucket) → level (처음 high/medium 된 시각 기록용)
    print(f"[시작] 모델 학습 창 {meta['n_windows']} · high<{HI} · medium<{MD} · 정책: ML high / 룰 L3·F1·F2 → 차단", flush=True)
    state = {"rows": []}

    def step():
        rows = state["rows"]
        # ① 접근 로그
        docs = []
        for line in acc.lines():
            m = LINE.match(line)
            if not m:
                continue
            ip, ts, meth, url, st, _, ua = m.groups()
            try:
                t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp()
            except ValueError:
                continue
            path, _, q = url.partition("?")
            rows.append((ip, t, meth, path, int(st), ua, q))
            docs.append({"timestamp": iso(t), "client_ip": ip, "method": meth, "path": path, "status": int(st),
                         "label": label(ip), "blocked": ip in blocked and int(st) == 403})
        bulk(a.es, "live-access", docs)

        # ② Wazuh 경보
        adocs = []
        for line in alr.lines():
            try:
                al = json.loads(line)
            except ValueError:
                continue
            g = al.get("rule", {}).get("groups", [])
            if "shadow_api" not in g:
                continue
            d = al.get("data", {})
            ip = d.get("srcip", "")
            ts = al.get("timestamp", "")
            try:
                t = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
            except ValueError:
                t = time.time()
            doc = {"timestamp": iso(t), "rule": {k: al["rule"].get(k) for k in ("id", "level", "description", "groups")},
                   "data": {"client_ip": ip, "method": d.get("protocol", ""), "path": (d.get("url", "") or "").split("?")[0],
                            "status": d.get("id", "")},
                   "label": label(ip)}
            adocs.append(doc)
            events.write(json.dumps({"type": "alert", **doc}, ensure_ascii=False) + "\n")
            hit = BLOCK_RULE_GROUPS & set(g)
            if ip and hit:
                block(ip, "Shadow 룰", f"{sorted(hit)[0]} (레벨 {al['rule'].get('level')})", doc["data"]["path"])
        bulk(a.es, "live-alerts", adocs)
        events.flush()

        # ③ ML — 최근 두 창만 채점 (지난 창은 끝난 값으로 고정됨)
        if rows:
            now = time.time()
            recent = [r for r in rows if r[1] >= now - 2 * a.window * 60]
            mdocs, ids = [], []
            for ip, start, ft in F.windows(recent, a.window, 5):
                x = np.array([[ft[k] for k in FEAT]])
                s = float(model.decision_function(x)[0])
                lvl = "high" if s < HI else "medium" if s < MD else "-"
                key = f"{ip}-{int(start)}"
                mdocs.append({"timestamp": iso(start), "client_ip": ip, "score": round(s, 5), "level": lvl,
                              "n_req": ft["n_req"], "seq_id_run": ft["seq_id_run"], "id_span_log": round(ft["id_span_log"], 3),
                              "label": label(ip)})
                ids.append(key)
                if lvl != "-" and ml_seen.get(key) != lvl:
                    ml_seen[key] = lvl
                    events.write(json.dumps({"type": "ml", "timestamp": iso(now), "client_ip": ip, "level": lvl,
                                             "score": round(s, 5), "n_req": ft["n_req"], "seq_id_run": ft["seq_id_run"],
                                             "label": label(ip)}, ensure_ascii=False) + "\n")
                if lvl == "high" and ft["n_req"] >= a.block_min_req:
                    block(ip, "ML", "BOLA 의심 (high)", f"점수 {s:.3f} · 요청 {ft['n_req']} · 연속 ID {ft['seq_id_run']}")
            bulk(a.es, "live-ml", mdocs, ids)
            rows = [r for r in rows if r[1] >= now - 3 * a.window * 60]
        state["rows"] = rows

    while True:
        try:
            step()
        except Exception as e:                      # 한 번 실패해도 시연이 멈추지 않게
            print(f"[오류 — 다음 주기에 계속] {type(e).__name__}: {e}", flush=True)
        time.sleep(a.every)


if __name__ == "__main__":
    main()
