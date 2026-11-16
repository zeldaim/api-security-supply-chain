#!/usr/bin/env python3
"""[출처 3 — 로그] WAF·Apache·app.log 에서 실제로 호출된 엔드포인트를 집계한다 (문서 11 §10).

    python api-bom/inventory/observe_logs.py <로그폴더> <baseline.csv> <출력폴더>
    예: python api-bom/inventory/observe_logs.py api-bom/inputs/logs_raw/2026-11-03 \
            api-bom/baseline/baseline.csv api-bom/inventory

로그폴더 안: waf/access.log, apache/shop_access.log, app.log (없는 건 건너뜀)
출력:
  endpoints_observed.csv  — 엔드포인트별 관측 (노이즈 제외 + 기준선 전체)
  observe_summary.md      — 기간·줄 수·원본 SHA256·판정 집계 (IP 는 남기지 않음)
"""
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from source_to_baseline import normalize  # Q4 정규화 규칙을 v1 과 공유

COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\w+) (\S+)[^"]*" (\d{3}) ')
ASSET = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$", re.I)
DEAD_DAYS = 7  # Q5: 실습망 7일 미관측 = dead 후보

# "처리 코드가 있다"는 증거로 인정하는 응답 (soft-404 보정, 문서 11 §10-4)
#   2xx·3xx·422(입력 검증 = 라우트가 잡음)는 증거. 400·403·404·405(메서드 불일치)·500(없는 경로에서도 남)은 아님.
#   401 은 구역별: v1 은 라우팅 전에 인증 검사(public/api/v1/index.php 68행 < 77행) → 없는 경로도 401 → 증거 아님
#   3xx 는 증거 아님: 이 앱은 / 와 index.php 가 어떤 메서드·경로든 302 로 돌려보냄(catch-all).
#     단 확장자 없는 경로의 301 = Apache 폴더 리다이렉트(끝에 / 붙이기) → '폴더 존재'로 따로 분류
#   OPTIONS·비표준 메서드(PROPFIND, TRACK, 임의 문자열)는 Apache 가 경로와 무관하게 응답 → 증거 아님
WEAK_401_PREFIXES = ("/api/v1/",)
REAL_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
PATH_INFO = re.compile(r"^(/[^/]+\.php)/.+")  # /login.php/<아무거나> → PHP 가 /login.php 로 처리


def handled_code(code, path, method):
    if method not in REAL_METHODS:
        return False
    if code[0] == "2" or code == "422":
        return True
    if code == "401":
        return not path.startswith(WEAK_401_PREFIXES)
    return False


def is_dir_redirect(code, path):
    return code == "301" and "." not in path.rsplit("/", 1)[-1]


def template_matcher(declared):
    """Q4: 코드에 선언된 템플릿 우선. '/api/v1/users/{id}' 는 '/api/v1/users/abc' 도 잡는다."""
    pats = []
    for key in declared:
        method, tpl = key.split(" ", 1)
        if "{" in tpl:
            rx = re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(tpl)) + "$")
            pats.append((method, rx, key))

    def match(method, path):
        for m, rx, key in pats:
            if m == method and rx.match(path):
                return key
        return None
    return match

SOURCES = [("waf", "waf/access.log", "combined"),
           ("apache", "apache/shop_access.log", "combined"),
           ("app", "app.log", "json")]


def parse_time(s):
    # 26/Oct/2026:08:16:02 +0000  /  03/Nov/2026:14:20:38.075 +0900  /  2026-10-26T19:46:39+09:00
    if "T" in s[:11]:
        return datetime.fromisoformat(s)
    fmt = "%d/%b/%Y:%H:%M:%S.%f %z" if "." in s.split()[0] else "%d/%b/%Y:%H:%M:%S %z"
    return datetime.strptime(s, fmt)


def kind_of(path):
    if path.startswith("/api/"):
        return "api"
    if path == "/" or path.endswith(".php"):
        return "page"
    if ASSET.search(path) or path.startswith("/assets/"):
        return "asset"
    return "file"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main(logdir, baseline_path, outdir):
    with open(baseline_path, encoding="utf-8-sig", newline="") as f:
        declared = {r["endpoint_key"]: r["decision"] for r in csv.DictReader(f)}
    match_tpl = template_matcher(declared)
    tpl_cache = {}

    ep = defaultdict(lambda: {"n": Counter(), "codes": Counter(), "first": None, "last": None, "clients": set()})
    meta = []
    for src, rel, fmt in SOURCES:
        p = os.path.join(logdir, rel)
        if not os.path.exists(p):
            continue
        lines = bad = 0
        t0 = t1 = None
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                lines += 1
                try:
                    if fmt == "json":
                        j = json.loads(line)
                        ip, ts, method, raw, code = j["client_ip"], j["timestamp"], j["method"], j["path"], str(j["status"])
                    else:
                        m = COMBINED.match(line)
                        if not m:
                            bad += 1
                            continue
                        ip, ts, method, raw, code = m.groups()
                    t = parse_time(ts).astimezone(timezone.utc)
                except (ValueError, KeyError):
                    bad += 1
                    continue
                path = raw.split("?", 1)[0]
                if not path.startswith("/"):
                    bad += 1  # 'GET %2F%2Fetc%2Fpasswd' 같은 비정상 요청줄
                    continue
                method = method.upper()
                if method == "HEAD":
                    method = "GET"  # HEAD 는 GET 과 같은 처리 경로
                pi = PATH_INFO.match(path)
                if pi:
                    path = pi.group(1)
                key = f"{method} {normalize(path) or '/'}"
                if key not in declared:
                    ck = (method, path)
                    if ck not in tpl_cache:
                        tpl_cache[ck] = match_tpl(method, path.rstrip("/") or "/")
                    key = tpl_cache[ck] or key
                e = ep[key]
                e["n"][src] += 1
                # 상태코드는 앱에 가까운 출처 우선 (apache·app). WAF 는 WAF 가 막은 것만 의미 있음
                e["codes"][(src, code)] += 1
                e["first"] = t if e["first"] is None or t < e["first"] else e["first"]
                e["last"] = t if e["last"] is None or t > e["last"] else e["last"]
                e["clients"].add(ip)
                t0 = t if t0 is None or t < t0 else t0
                t1 = t if t1 is None or t > t1 else t1
        meta.append({"src": src, "file": rel, "lines": lines, "skipped": bad, "sha256": sha256(p),
                     "from": t0, "to": t1})

    period_end = max(m["to"] for m in meta)

    def codes_str(e):
        c = Counter()
        for (src, code), n in e["codes"].items():
            if src != "waf" or code == "403":  # WAF 응답코드는 차단(403)만 따로 셈
                c[("waf403" if src == "waf" else code)] += n
        return c

    def verdict(key, e):
        d = declared.get(key)
        k = kind_of(key.split(" ", 1)[1])
        c = codes_str(e)
        method, path = key.split(" ", 1)
        handled = any(code != "waf403" and handled_code(code, path + "/", method) for code in c)
        if d == "active":
            return "active"
        if d == "deprecated":
            return "zombie"
        if d == "review":
            return "shadow(코드에 있음, 호출됨)"
        if k == "asset":
            return "asset"
        if not handled:
            if method in REAL_METHODS and any(is_dir_redirect(code, path) for code in c):
                return "폴더 존재(301)"
            return "noise"
        return {"api": "shadow 후보(선언 밖 API)", "file": "exposure 후보(선언 밖 파일)",
                "page": "shadow 후보(선언 밖 페이지)"}[k]

    rows = []
    for key, e in ep.items():
        v = verdict(key, e)
        rows.append((key, e, v))
    for key, d in declared.items():  # 기준선인데 로그에 없음
        if key not in ep:
            rows.append((key, None, f"미관측({d}) — dead 후보" if d == "active" else f"미관측({d})"))

    order = ["zombie", "shadow(코드에 있음, 호출됨)", "shadow 후보(선언 밖 API)", "shadow 후보(선언 밖 페이지)", "폴더 존재(301)",
             "exposure 후보(선언 밖 파일)", "active"]
    rank = lambda v: order.index(v) if v in order else len(order)
    os.makedirs(outdir, exist_ok=True)
    out_csv = os.path.join(outdir, "endpoints_observed.csv")
    noise = Counter()
    kept = 0
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["endpoint_key", "kind", "declared", "verdict", "seen_in", "waf_n", "apache_n", "app_n",
                    "status_codes", "first_seen_utc", "last_seen_utc", "days_since_last", "distinct_clients"])
        for key, e, v in sorted(rows, key=lambda r: (rank(r[2]), -(sum(r[1]["n"].values()) if r[1] else 0), r[0])):
            if v in ("noise", "asset"):
                noise[v] += 1
                continue
            kept += 1
            if e is None:
                w.writerow([key, kind_of(key.split(" ", 1)[1]), declared.get(key, ""), v, "", 0, 0, 0, "", "", "", "", 0])
                continue
            c = codes_str(e)
            days = (period_end - e["last"]).days
            if declared.get(key) == "active" and days >= DEAD_DAYS:
                v += f" (마지막 관측 {days}일 전 — dead 후보)"
            w.writerow([key, kind_of(key.split(" ", 1)[1]), declared.get(key, ""), v,
                        "+".join(s for s in ("waf", "apache", "app") if e["n"][s]),
                        e["n"]["waf"], e["n"]["apache"], e["n"]["app"],
                        " ".join(f"{k}:{n}" for k, n in sorted(c.items())),
                        e["first"].strftime("%Y-%m-%dT%H:%M:%SZ"), e["last"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        days, len(e["clients"])])

    verdicts = Counter(v.split(" (")[0] if v.startswith("active") else v for _, _, v in rows)
    md = [f"# 출처 3 — 로그 관측 요약", "",
          f"- 생성: `python api-bom/inventory/observe_logs.py {logdir} {baseline_path} {outdir}`",
          f"- 기준선: `{baseline_path}` ({len(declared)}개)", "", "## 입력 (원본은 git 제외, 해시로 재현 확인)", "",
          "| 출처 | 파일 | 줄 수 | 건너뜀 | 기간(UTC) | SHA256 |", "|---|---|---|---|---|---|"]
    for m in meta:
        md.append(f"| {m['src']} | `{m['file']}` | {m['lines']:,} | {m['skipped']:,} | "
                  f"{m['from']:%Y-%m-%d %H:%M} ~ {m['to']:%Y-%m-%d %H:%M} | `{m['sha256']}` |")
    md += ["", "## 판정 집계 (엔드포인트 수)", "", "| 판정 | 수 |", "|---|---|"]
    for v, n in sorted(verdicts.items(), key=lambda x: (rank(x[0]), x[0])):
        md.append(f"| {v} | {n:,} |")
    md += ["", f"- `endpoints_observed.csv` 에는 noise·asset 을 뺀 {kept}개를 기록 (noise = 처리 증거 없는 경로: 3xx·400·403·404·405·500, v1 의 401, OPTIONS·비표준 메서드. asset = css·js·이미지)",
           "- HEAD 는 GET 으로, `/x.php/아무거나`(PATH_INFO) 는 `/x.php` 로 합산",
           "- 선언 템플릿 우선 매칭(Q4): `/api/v1/users/abc` 같은 값 변형은 `GET /api/v1/users/{id}` 로 합산",
           f"- dead 후보 기준: 기간 끝({period_end:%Y-%m-%d})에서 {DEAD_DAYS}일 이상 미관측 (Q5)",
           "- `distinct_clients` 는 서로 다른 출발지 IP 수 (IP 자체는 기록하지 않음)"]
    with open(os.path.join(outdir, "observe_summary.md"), "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
