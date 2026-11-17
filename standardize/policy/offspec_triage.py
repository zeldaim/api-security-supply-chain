#!/usr/bin/env python3
"""명세 밖 호출 분류 — "명세에 없음"을 판정이 아니라 조사 시작점으로 쓴다.

OpenAPI 에 없는 (메서드, 경로) 호출을 모아서, 명세 밖이라는 사실 하나로 위험하다고 정하지 않고
아래 세 가지를 함께 보고 상태와 우선순위를 정한다. "악성"인지는 판정하지 않는다.

  1) 승인 상태   기준선 CSV 의 decision (active / review / deprecated / remove / 없음=미등록)
  2) 소유권     기준선 CSV 의 owner (비어 있으면 '소유자 없음')
  3) 사용 맥락   로그에서: 실제로 응답하는 경로인가, 누가(정상 이용 이력이 있는 출발지 / 탐색 흔적이 많은 출발지 /
                내부·외부) 얼마나 꾸준히 부르나, 프런트가 부르나, 명세에 있는 경로의 다른 메서드인가

  python offspec_triage.py --spec openapi.json --log access.log[.gz] [--log ...] \
        [--baseline baseline.csv] [--internal 10.0.0.0/8 ...] [--scope REGEX] --out-dir OUT

  출력  OUT/offspec_triage.csv     명세 밖 (메서드, 경로) 마다 상태·우선순위·근거·조치
        OUT/offspec_callers.csv    출발지별 정상 이용 이력과 탐색 흔적
        OUT/offspec_report.md      사람용 요약
        OUT/offspec_allowlist.yaml '명세 누락(승인·소유자 있음)' 만 — gen_shadow_rules --allowlist 형식

기준선 CSV 는 baseline_v2.csv 와 같은 열 이름을 쓴다(endpoint_key, decision, owner). frontend(y/n) 열이 있으면 쓴다.
판정표는 같은 폴더 offspec_triage.md 에 있다. 표준 라이브러리만 쓴다(명세가 YAML 이면 PyYAML 필요).
"""
import argparse
import csv
import gzip
import ipaddress
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
PARAM_RE = re.compile(r"\{[^/{}]+\}")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SENSITIVE = ("admin", "debug", "diagnostic", "internal", "management", "manage", "export", "dump", "backup",
             "actuator", "swagger", "openapi", "phpinfo", "config", "/all")
GRADE = ["정보", "낮음", "중간", "높음"]
ACCESS_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) ')


# ── 입력 ──────────────────────────────────────────────────────────────────
def load_spec(path):
    txt = open(path, encoding="utf-8").read()
    if path.endswith((".yaml", ".yml")):
        import yaml
        spec = yaml.safe_load(txt)
    else:
        spec = json.loads(txt)
    base = ""
    for s in spec.get("servers") or []:
        m = re.match(r"^(?:https?://[^/]+)?(/[^?#]*)", s.get("url", ""))
        if m and m.group(1) != "/":
            base = m.group(1).rstrip("/")
            break
    ops = defaultdict(set)  # template → methods
    for p, item in (spec.get("paths") or {}).items():
        for m in item:
            if m.upper() in METHODS:
                ops[norm_params(base + p)].add(m.upper())
    return ops


def norm_params(t):
    return PARAM_RE.sub("{id}", t.rstrip("/") or "/")


def template_regex(t):
    parts = PARAM_RE.split(t)
    return re.compile("^" + "[^/]+".join(re.escape(x) for x in parts) + "/?$")


def load_baseline(path):
    out = {}
    if not path:
        return out
    for r in csv.DictReader(open(path, encoding="utf-8-sig")):
        if r.get("layer", "endpoint") not in ("endpoint", "") or " " not in r.get("endpoint_key", ""):
            continue
        m, p = r["endpoint_key"].split(" ", 1)
        out[(m.upper(), norm_params(p))] = {
            "decision": (r.get("decision") or "").strip() or "미등록",
            "owner": (r.get("owner") or "").strip(),
            "frontend": (r.get("frontend") or "").strip().lower() == "y"}
    return out


def iter_log(path):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                ts = j.get("ts") or j.get("time") or j.get("timestamp") or ""
                yield (j.get("ip") or j.get("client_ip") or j.get("src_ip") or "-", str(ts),
                       str(j.get("method", "")).upper(), str(j.get("path", "")), int(j.get("status") or 0),
                       str(j.get("user_id") or ""))
                continue
            m = ACCESS_RE.match(line)
            if m:
                yield m.group(1), m.group(2), m.group(3).upper(), m.group(4), int(m.group(5)), ""


def hour_bucket(ts):
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts[:25] if "T" in ts else ts, fmt).strftime("%Y-%m-%d %H")
        except ValueError:
            continue
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H")
    except (ValueError, OSError, OverflowError):
        return ts[:13]


# ── 경로 → 템플릿 ─────────────────────────────────────────────────────────
class Templater:
    def __init__(self, spec_ops, baseline):
        known = set(spec_ops) | {p for _, p in baseline}
        # 고정 조각이 많은 템플릿부터 맞춘다 (/orders/all 이 /orders/{id} 에 먹히지 않게)
        self.known = sorted(known, key=lambda t: (-len(PARAM_RE.sub("", t)), t))
        self.rx = {t: template_regex(t) for t in self.known}

    def __call__(self, path):
        path = path.split("?", 1)[0].split("#", 1)[0]
        path = re.sub(r"/{2,}", "/", path).rstrip("/") or "/"
        for t in self.known:
            if self.rx[t].match(path):
                return t
        segs = []
        for s in path.split("/"):
            if s.isdigit() or UUID_RE.match(s) or (len(s) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", s)):
                segs.append("{id}")
            else:
                segs.append(s)
        return "/".join(segs) or "/"


def derive_scope(templates):
    pre = set()
    for t in templates:
        segs = [s for s in t.split("/") if s]
        if segs:
            i = next((k for k, s in enumerate(segs) if s.lower() == "api"), 0)
            pre.add("/" + "/".join(segs[:i + 1]))
    return re.compile(r"^(?:" + "|".join(re.escape(p) for p in sorted(pre)) + r")(?:/|$)") if pre else re.compile(".")


def existence(statuses):
    """경로가 실제로 있는지 응답 코드로 본다.
      있음   2xx·3xx 가 한 번이라도 있음
      없음   2xx·3xx 없고 404·405 가 있음 — 섞인 401·403·400·5xx 는 라우팅 전 단계(인증 미들웨어·WAF·페이로드 오류) 응답으로 본다
      불명   2xx·3xx 도 404·405 도 없고 401·403·400·422·5xx 만 있음 — 인증 뒤에 있을 수 있어 확인이 필요하다
    팀 웹 실측(2026-10-26~11-03 app.log): 스캐너가 부른 /api/v1/* 없는 경로가 404 와 함께 401·500 을 섞어 받았다.
    """
    if any(200 <= s < 400 for s in statuses):
        return "있음"
    if any(s in (404, 405, 501) for s in statuses):
        return "없음"
    return "불명"


# ── 판정 ──────────────────────────────────────────────────────────────────
def classify(key, a, base, ctx, args):
    method, tmpl = key
    st = a["status"]
    ok2 = sum(v for s, v in st.items() if 200 <= s < 300)
    ips = a["ips"]
    probe_ips = {ip for ip in ips if ctx["prober"].get(ip)}
    est_ips = {ip for ip in ips if ctx["established"].get(ip) and ip not in probe_ips}
    risk, mit, facts = [], [], []

    facts.append(f"호출 {a['calls']}회 · 출발지 {len(ips)}곳 · 시간대 {len(a['hours'])}개 · 상태 "
                 + ", ".join(f"{s}×{n}" for s, n in sorted(st.items())))
    if a["method_variant"]:
        facts.append(f"명세에 있는 경로의 다른 메서드 (명세: {', '.join(sorted(a['method_variant']))})")

    ex = existence(st)
    if ex == "없음":
        cls, grade = "없는 경로 호출", 0
        note = "응답이 404·405 뿐 — 자산이 아님. 자산 판정 대신 호출한 출발지를 본다"
        if probe_ips:
            note += f" (탐색 흔적 출발지 {len(probe_ips)}곳: {', '.join(sorted(probe_ips)[:3])})"
        return cls, grade, [], [], facts, note

    dec = base.get("decision", "미등록") if base else "미등록"
    owner = base.get("owner", "") if base else ""
    if ex == "불명" and dec == "미등록":
        return ("존재 불명 (401·403·4xx·5xx 만)", 1, [], [], facts,
                "인증된 요청으로 다시 호출해 실제로 있는지 확인 → 있으면 소유 팀 찾기")

    # 위험 요인 (미등록은 소유자가 없는 게 정의라 기본 우선순위에 이미 들어 있다 — 두 번 세지 않는다)
    if not owner and dec in ("review", "deprecated"):
        risk.append("소유자 없음")
    if any(s in tmpl.lower() for s in SENSITIVE):
        risk.append("관리·내부·대량 조회 성격의 경로 이름")
    if a["method_variant"] and method in WRITE_METHODS:
        risk.append(f"읽기 경로에 쓰기 메서드({method})가 응답")
    if ok2 and probe_ips and not est_ips:
        risk.append("성공 응답이 탐색 흔적 출발지에서만 나옴")
    if args.internal:
        ext = [ip for ip in ips if not ctx["internal"](ip)]
        if ext and ok2:
            risk.append(f"외부 출발지 {len(ext)}곳에서 성공 응답")
        elif not ext:
            mit.append("내부 출발지에서만 호출")
    # 완화 요인
    if base and base.get("frontend"):
        mit.append("프런트엔드가 부름")
    if len(est_ips) >= args.min_clients and len(a["hours"]) >= args.min_hours:
        mit.append(f"정상 이용 이력이 있는 출발지 {len(est_ips)}곳이 {len(a['hours'])}개 시간대에 걸쳐 부름")

    if dec == "active":
        cls = "명세 누락 (승인·소유자 있음)" if owner else "승인됐으나 소유자 없음"
        grade = 0 if owner else 1
        note = (f"명세에 추가 요청 → {owner}" if owner else "소유자 지정 후 명세 추가")
        if owner and risk:  # 승인은 사람이 한 것 — 우선순위는 올리지 않고 재확인만 요청
            note += f" · 재확인 권장: {', '.join(risk)}"
        return cls, grade, risk, mit, facts, note
    if dec == "remove":
        cls, b = "제거 결정인데 응답", 3
        note = "제거 결정이 적용되지 않음 — 배포 확인"
    elif dec == "deprecated":
        cls, b = "폐기 예정인데 사용 중 (Zombie)", 2
        note = "누가 아직 부르는지 확인 후 이관·차단 일정" + (f" → {owner}" if owner else "")
    elif dec == "review":
        cls, b = "검토 중", 1 if owner else 2
        note = f"판정 요청 → {owner}" if owner else "소유자 찾기 → 판정"
    else:
        cls, b = "미등록 (Shadow 후보)", 2
        note = "소유 팀 찾기 → 승인(active)·폐기·제거 중 판정"
    # 기본 + 위험 요인 있으면 1 − 완화 요인 있으면 1. 단, 읽기 경로에 쓰기 메서드가 응답하는 것은 정상 이용으로 덜어 주지 않는다.
    lower = 1 if mit and not any("쓰기 메서드" in r for r in risk) else 0
    grade = max(0, min(3, b + (1 if risk else 0) - lower))
    if dec == "remove":
        grade = 3
    elif dec in ("review", "deprecated", "미등록"):
        grade = max(grade, 1)  # 판정이 끝나지 않았거나 폐기 대상 — '정보'로 내리지 않는다
    return cls, grade, risk, mit, facts, note


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--spec", required=True)
    ap.add_argument("--log", action="append", required=True)
    ap.add_argument("--baseline", default="")
    ap.add_argument("--internal", action="append", default=[], help="내부로 볼 CIDR (여러 번)")
    ap.add_argument("--scope", default="", help="검사 범위 정규식. 없으면 명세 경로 접두어에서 뽑는다")
    ap.add_argument("--probe-paths", type=int, default=5, help="404 를 받은 서로 다른 명세 밖 경로가 이 수 이상이면 '탐색 흔적' 출발지")
    ap.add_argument("--min-ok", type=int, default=3, help="명세 경로 2xx 가 이 수 이상이면 '정상 이용 이력' 출발지")
    ap.add_argument("--min-clients", type=int, default=3)
    ap.add_argument("--min-hours", type=int, default=2)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    spec_ops = load_spec(args.spec)
    baseline = load_baseline(args.baseline)
    tpl = Templater(spec_ops, baseline)
    scope = re.compile(args.scope) if args.scope else derive_scope(spec_ops)
    nets = [ipaddress.ip_network(c, strict=False) for c in args.internal]

    def is_internal(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets)

    agg = defaultdict(lambda: {"calls": 0, "status": Counter(), "ips": Counter(), "hours": set(),
                               "method_variant": set(), "samples": Counter()})
    caller = defaultdict(lambda: {"calls": 0, "spec_ok": 0, "offspec": 0, "offspec_404_paths": set()})
    total = in_scope = 0
    for path in args.log:
        for ip, ts, method, raw, status, _uid in iter_log(path):
            total += 1
            clean = raw.split("?", 1)[0]
            if not scope.match(re.sub(r"/{2,}", "/", clean)):
                continue
            in_scope += 1
            t = tpl(raw)
            c = caller[ip]
            c["calls"] += 1
            if method in spec_ops.get(t, ()):
                if 200 <= status < 300:
                    c["spec_ok"] += 1
                continue
            c["offspec"] += 1
            if status == 404:
                c["offspec_404_paths"].add(clean)
            a = agg[(method, t)]
            a["calls"] += 1
            a["status"][status] += 1
            a["ips"][ip] += 1
            a["hours"].add(hour_bucket(ts))
            a["samples"][clean] += 1
            if t in spec_ops:
                a["method_variant"] = spec_ops[t]

    ctx = {"prober": {ip: len(c["offspec_404_paths"]) >= args.probe_paths for ip, c in caller.items()},
           "established": {ip: c["spec_ok"] >= args.min_ok for ip, c in caller.items()},
           "internal": is_internal}

    # 기준선에만 있고 이번 로그에 안 나온 명세 밖 항목도 남긴다 (사용 맥락 '관측 없음')
    rows = []
    for key, a in agg.items():
        cls, grade, risk, mit, facts, note = classify(key, a, baseline.get(key), ctx, args)
        b = baseline.get(key) or {}
        rows.append({"grade": GRADE[grade], "class": cls, "endpoint_key": f"{key[0]} {key[1]}",
                     "decision": b.get("decision", "미등록"), "owner": b.get("owner", ""),
                     "calls": a["calls"], "sources": len(a["ips"]), "hours": len(a["hours"]),
                     "risk": "; ".join(risk), "mitigation": "; ".join(mit), "facts": " / ".join(facts),
                     "action": note, "sample_path": a["samples"].most_common(1)[0][0], "_g": grade})
    for key, b in baseline.items():
        if key not in agg and key[0] not in spec_ops.get(key[1], ()) and scope.match(key[1]):
            rows.append({"grade": "정보", "class": "기준선에만 있음 (이번 로그에 호출 없음)", "endpoint_key": f"{key[0]} {key[1]}",
                         "decision": b["decision"], "owner": b["owner"], "calls": 0, "sources": 0, "hours": 0,
                         "risk": "", "mitigation": "", "facts": "관측 없음",
                         "action": "deprecated·remove 면 제거 확인, active 면 명세 추가" if b["decision"] != "미등록" else "",
                         "sample_path": "", "_g": -1})
    rows.sort(key=lambda r: (-r["_g"], r["class"], -r["calls"], r["endpoint_key"]))

    os.makedirs(args.out_dir, exist_ok=True)
    # 없는 경로 호출(404·405)은 자산이 아니라 따로 둔다 — 스캐너가 있으면 수만 개가 된다
    notfound = [r for r in rows if r["class"] == "없는 경로 호출"]
    rows = [r for r in rows if r["class"] != "없는 경로 호출"]
    fields = ["grade", "class", "endpoint_key", "decision", "owner", "calls", "sources", "hours",
              "risk", "mitigation", "facts", "action", "sample_path"]
    for name, rs in (("offspec_triage.csv", rows), ("offspec_notfound.csv", notfound)):
        with open(os.path.join(args.out_dir, name), "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
            w.writeheader()
            w.writerows(rs)

    crow = [{"source": ip, "calls": c["calls"], "spec_2xx": c["spec_ok"], "offspec_calls": c["offspec"],
             "offspec_404_paths": len(c["offspec_404_paths"]),
             "role": ("탐색 흔적" if ctx["prober"][ip] else "") + ("+" if ctx["prober"][ip] and ctx["established"][ip] else "")
             + ("정상 이용 이력" if ctx["established"][ip] else ""),
             "internal": "y" if nets and is_internal(ip) else ("n" if nets else "")}
            for ip, c in caller.items() if c["offspec"]]
    crow.sort(key=lambda r: (-r["offspec_404_paths"], -r["offspec_calls"]))
    with open(os.path.join(args.out_dir, "offspec_callers.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(crow[0]) if crow else ["source"], lineterminator="\n")
        w.writeheader()
        w.writerows(crow)

    allow = [r for r in rows if r["class"].startswith("명세 누락")]
    with open(os.path.join(args.out_dir, "offspec_allowlist.yaml"), "w", encoding="utf-8", newline="") as f:
        f.write("# offspec_triage.py 가 만든 예외 목록 — '명세 누락(승인·소유자 있음)' 만. 명세에 반영되면 여기서 빠진다.\nallow:\n")
        if not allow:
            f.write("  []\n")
        for r in allow:
            m, p = r["endpoint_key"].split(" ", 1)
            f.write(f"  - method: {m}\n    path: \"{p}\"\n    reason: \"기준선 active, 소유자 {r['owner']} — 명세 누락\"\n")

    cnt = Counter(r["class"] for r in rows)
    gcnt = Counter(r["grade"] for r in rows if r["_g"] >= 0)
    rep = ["# 명세 밖 호출 분류 보고서", "",
           f"- 로그 {total}줄 중 검사 범위 {in_scope}줄 · 명세 operation {sum(len(v) for v in spec_ops.values())}개 · "
           f"기준선 {len(baseline)}행 · 내부 대역 {', '.join(args.internal) or '지정 안 함(외부·내부 요인 미사용)'}",
           f"- 명세 밖 (메서드, 경로) 중 실제로 있거나 있을 수 있는 것 {sum(1 for r in rows if r['_g'] >= 0)}개 — 우선순위 "
           + (", ".join(f"{g} {gcnt[g]}" for g in reversed(GRADE) if gcnt[g]) or "없음"),
           "- 분류: " + (", ".join(f"{k} {v}" for k, v in cnt.most_common()) or "없음"),
           f"- 없는 경로 호출(404·405 만) {len(notfound)}개 · {sum(r['calls'] for r in notfound)}회 — 자산이 아니므로 표에서 뺐다 (offspec_notfound.csv)",
           "- '명세에 없음'만으로 위험하다고 정하지 않는다. 우선순위는 승인 상태 · 소유자 · 사용 맥락으로 정한다 (판정표: offspec_triage.md).", "",
           "## 명세 밖 (메서드, 경로)", "",
           "| 우선순위 | 분류 | 엔드포인트 | 승인 | 소유자 | 호출·출발지·시간대 | 위험 요인 | 완화 요인 | 조치 |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        rep.append(f"| {r['grade']} | {r['class']} | `{r['endpoint_key']}` | {r['decision']} | {r['owner'] or '-'} | "
                   f"{r['calls']}·{r['sources']}·{r['hours']} | {r['risk'] or '-'} | {r['mitigation'] or '-'} | {r['action']} |")
    probers = [c for c in crow if "탐색" in c["role"]]
    rep += ["", "## 탐색 흔적 출발지", "",
            f"서로 다른 명세 밖 경로 {args.probe_paths}개 이상에서 404 를 받은 출발지. 자산 판정과 별개로 '호출자' 관점의 단서다.", ""]
    if probers:
        rep += ["| 출발지 | 전체 호출 | 명세 경로 2xx | 명세 밖 호출 | 404 받은 서로 다른 경로 |", "|---|---|---|---|---|"]
        rep += [f"| {c['source']} | {c['calls']} | {c['spec_2xx']} | {c['offspec_calls']} | {c['offspec_404_paths']} |" for c in probers]
    else:
        rep.append("없음")
    with open(os.path.join(args.out_dir, "offspec_report.md"), "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(rep) + "\n")
    print("\n".join(rep[2:6]))


if __name__ == "__main__":
    main()
