#!/usr/bin/env python3
"""접근 로그(Apache/nginx combined) → 출발지 IP × 시간 창 별 행위 특징 — v2 (앱에 덜 묶인 판).

원본 `e2e_story/ml/features.py` 를 고치지 않고 새로 만든 파일이다. 특징 이름·순서(FEATURES)는 원본과 같다.
crAPI 검증(e2e_story/crapi_generality_2026-11-15, §7-3)에서 확인된 팀 웹 가정 세 가지를 뺐다.

  1) API 범위   원본: 경로가 "/api" 로 시작      → v2: 명세에서 범위를 뽑는다 (/identity/api, /workshop/api …). E2E_API_SCOPE 로 직접 지정 가능
  2) 명세 형식  원본: YAML 을 들여쓰기로 읽음     → v2: JSON 명세도 읽는다
  3) 객체 ID    원본: 경로의 숫자만               → v2: 경로의 숫자·UUID + 쿼리의 ID 파라미터(id, *_id, *Id)

  python3 features.py extract <access.log> [--window 15] [--out features.csv] [--no-ip]

팀 웹처럼 /api 접두어 · 숫자 경로 ID 만 쓰는 로그에서는 원본과 같은 값이 나와야 한다 (회귀 확인: compare_v1_v2.py).
"""
import argparse
import csv
import json
import math
import os
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+) "[^"]*" "([^"]*)"')
STATIC = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$", re.I)
_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
NUM = re.compile(r"/\d+(?=/|$)")                      # 원본과 같은 규칙: 숫자만으로 된 경로 조각
UUID_SEG = re.compile(r"/" + _UUID + r"(?=/|$)")
ID_SEG = re.compile(r"/(\d+|" + _UUID + r")(?=/|$)")   # 숫자 또는 UUID 조각
ID_PARAM = re.compile(r"^(?:id|[A-Za-z0-9_-]*[_-]id|[A-Za-z0-9]*[a-z0-9]Id)$")   # id, report_id, order-id, vehicleId
ID_VALUE = re.compile(r"^(?:\d+|" + _UUID + r")$")

# 특징 이름 — 원본과 같은 이름·순서 (모델 입력 순서)
FEATURES = [
    "n_req", "uniq_path_ratio", "top_tpl_share", "seq_id_run", "seq_ratio", "id_span_log",
    "gap_mean_log", "gap_cv", "err_ratio", "api_ratio", "static_ratio", "n_ua", "offspec_ratio",
]

_HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_CANDIDATES = [os.environ.get("E2E_SPEC", ""), os.path.join(_HERE, "openapi.yaml"),
                   os.path.join(_HERE, "..", "ml", "openapi.yaml"),
                   os.path.join(_HERE, "..", "..", "team_src", "web", "src", "public", "docs", "openapi.yaml")]
SPEC = []            # [(METHOD, 정규식)]
SPEC_PATHS = []      # 명세의 경로 틀 원문 (variants.py 가 쓴다)
SCOPE = None         # API 범위 정규식


def read_spec_paths(path):
    """명세 → [(경로 틀, [메서드…])]. JSON 이면 json 으로, 아니면 원본처럼 YAML 들여쓰기로 읽는다(의존성 없음)."""
    text = open(path, encoding="utf-8").read()
    if text.lstrip().startswith("{"):
        doc = json.loads(text)
        return [(p, [m.upper() for m in item if m.lower() in ("get", "post", "put", "patch", "delete", "head", "options")])
                for p, item in (doc.get("paths") or {}).items() if isinstance(item, dict)]
    out, cur, inside = [], None, False
    for line in text.splitlines():
        if re.match(r"^paths:\s*$", line):
            inside = True
            continue
        if inside and re.match(r"^\S", line):
            break
        m = re.match(r"^  (/\S*):\s*$", line)
        if inside and m:
            cur = [m.group(1), []]
            out.append(cur)
            continue
        m = re.match(r"^    (get|post|put|patch|delete|head|options):", line)
        if inside and cur and m:
            cur[1].append(m.group(1).upper())
    return [(p, ms) for p, ms in out]


def derive_scope(paths):
    """명세 경로들에서 API 범위를 뽑는다: 'api' 조각이 있으면 거기까지, 없으면 첫 조각.
       /api/v2/products → /api · /identity/api/v2/user → /identity/api · /v1/items → /v1"""
    prefixes = set()
    for p in paths:
        segs = [s for s in p.split("/") if s]
        if not segs:
            continue
        idx = next((i for i, s in enumerate(segs) if s.lower() == "api"), 0)
        prefixes.add("/" + "/".join(segs[:idx + 1]))
    if not prefixes:
        return re.compile(r"^/api(?:/|$)")
    return re.compile(r"^(?:" + "|".join(sorted(re.escape(x) for x in prefixes)) + r")(?:/|$)")


def load_spec(path=None):
    global SCOPE
    path = path or next((p for p in SPEC_CANDIDATES if p and os.path.exists(p)), None)
    if not path:
        raise SystemExit("명세(openapi) 를 찾을 수 없음 (E2E_SPEC 로 지정)")
    items = read_spec_paths(path)
    SPEC[:] = [(m, re.compile("^" + re.sub(r"\\{[^}]+\\}", "[^/]+", re.escape(p)) + "/*$")) for p, ms in items for m in ms]
    SPEC_PATHS[:] = items
    env = os.environ.get("E2E_API_SCOPE", "")
    SCOPE = re.compile(env) if env else derive_scope([p for p, _ in items])
    return path


def in_scope(path):
    if SCOPE is None:
        load_spec()
    return bool(SCOPE.match(path))


def offspec(method, path):
    if not SPEC:
        load_spec()
    return not any(meth == method and rx.match(path) for meth, rx in SPEC)


def parse(path):
    """→ (ip, epoch, method, path, status, ua, query) 를 시간 순으로. 앞 6칸은 원본과 같다(query 만 추가)."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LINE.match(line)
            if not m:
                continue
            ip, ts, meth, url, st, _, ua = m.groups()
            try:
                t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S.%f %z" if "." in ts else "%d/%b/%Y:%H:%M:%S %z").timestamp()
            except ValueError:
                continue
            p, _, q = url.partition("?")
            out.append((ip, t, meth, p, int(st), ua, q))
    out.sort(key=lambda r: r[1])
    return out


def template(p):
    """경로 틀: 숫자·UUID 조각을 자리표시로. (숫자만 있으면 원본 template() 과 같은 문자열)"""
    return NUM.sub("/{n}", UUID_SEG.sub("/{u}", p))


def id_params(query):
    """쿼리에서 ID 로 보이는 파라미터만 → [(이름, 값)]"""
    out = []
    for kv in query.split("&") if query else []:
        k, _, v = kv.partition("=")
        if ID_PARAM.match(k) and ID_VALUE.match(v):
            out.append((k, v))
    return out


def object_refs(path, query):
    """요청 하나가 가리키는 객체 → [(틀, ID)]. 경로의 마지막 ID 조각 + 쿼리의 ID 파라미터."""
    refs = []
    segs = ID_SEG.findall(path)
    if segs:
        refs.append((template(path), segs[-1]))
    for k, v in id_params(query):
        refs.append((template(path) + "?" + k, v))
    return refs


def seq_run(ids):
    """호출 순서 그대로 +1 연속(가장 긴 것)과, 정렬 후 연속 중 큰 쪽 — 원본과 같다."""
    def run(seq):
        best = cur = 1 if seq else 0
        for a, b in zip(seq, seq[1:]):
            cur = cur + 1 if b == a + 1 else 1
            best = max(best, cur)
        return best
    return max(run(ids), run(sorted(set(ids))))


def featurize(reqs):
    """한 IP 의 한 창 요청 목록 → 특징 dict"""
    n = len(reqs)
    paths = [r[3] for r in reqs]
    queries = [r[6] if len(r) > 6 else "" for r in reqs]
    # 서로 다른 '자원' = 경로 + ID 파라미터 값 (쿼리로 ID 를 넘기는 열거도 서로 다른 자원으로 센다)
    resources = {(p, tuple(id_params(q))) for p, q in zip(paths, queries)}
    tpls = defaultdict(int)
    for p in paths:
        tpls[template(p)] += 1
    groups = defaultdict(list)
    for p, q in zip(paths, queries):
        for tpl, oid in object_refs(p, q):
            groups[tpl].append(oid)
    best_run, best_span = 0, 0
    for tpl, ids in groups.items():
        nums = [int(i) for i in ids if i.isdigit()]
        if nums:
            best_run = max(best_run, seq_run(nums))
        best_span = max(best_span, len(set(ids)))
    api = [r for r in reqs if in_scope(r[3])]
    ts = [r[1] for r in reqs]
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    gm = statistics.fmean(gaps) if gaps else 0.0
    cv = (statistics.pstdev(gaps) / gm) if len(gaps) > 1 and gm > 0 else 0.0
    return {
        "n_req": n,
        "uniq_path_ratio": len(resources) / n,
        "top_tpl_share": max(tpls.values()) / n,
        "seq_id_run": best_run,
        "seq_ratio": best_run / n,
        "id_span_log": math.log1p(best_span),
        "gap_mean_log": math.log1p(gm),
        "gap_cv": min(cv, 10.0),
        "err_ratio": sum(1 for r in reqs if r[4] >= 400) / n,
        "api_ratio": len(api) / n,
        "static_ratio": sum(1 for p in paths if STATIC.search(p)) / n,
        "n_ua": len({r[5] for r in reqs}),
        "offspec_ratio": (sum(1 for r in api if offspec(r[2], r[3])) / len(api)) if api else 0.0,
    }


def windows(rows, window_min=15, min_req=5):
    """고정 창(window_min 분)으로 잘라 IP 별 특징. 요청이 min_req 미만인 창은 판단 불가로 뺀다."""
    w = window_min * 60
    buckets = defaultdict(list)
    for r in rows:
        buckets[(r[0], int(r[1] // w))].append(r)
    for (ip, b), reqs in sorted(buckets.items(), key=lambda kv: kv[0][1]):
        if len(reqs) >= min_req:
            yield ip, b * w, featurize(reqs)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    e = sp.add_parser("extract")
    e.add_argument("log")
    e.add_argument("--window", type=int, default=15)
    e.add_argument("--min-req", type=int, default=5)
    e.add_argument("--out", default="-")
    e.add_argument("--no-ip", action="store_true", help="IP 를 빼고 저장")
    sc = sp.add_parser("scope", help="명세에서 뽑은 API 범위와 작업 수를 출력")
    a = ap.parse_args()
    if a.cmd == "scope":
        p = load_spec()
        print(f"명세: {p}\nAPI 범위: {SCOPE.pattern}\n작업 수: {len(SPEC)}")
        return
    rows = parse(a.log)
    f = sys.stdout if a.out == "-" else open(a.out, "w", newline="", encoding="utf-8")
    w = csv.writer(f, lineterminator="\n")
    w.writerow(([] if a.no_ip else ["ip"]) + ["window_start"] + FEATURES)
    n = 0
    for ip, start, ft in windows(rows, a.window, a.min_req):
        w.writerow(([] if a.no_ip else [ip]) + [int(start)] + [round(ft[k], 4) for k in FEATURES])
        n += 1
    print(f"[features v2] 줄 {len(rows)} → 창 {n}개 ({a.window}분, 요청 {a.min_req}건 이상) · API 범위 {SCOPE.pattern if SCOPE else '(미사용)'}", file=sys.stderr)


if __name__ == "__main__":
    main()
