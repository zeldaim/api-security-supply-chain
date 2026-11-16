#!/usr/bin/env python3
"""[v3 판정] 자산마다 일반 기준(G1~G9)을 자동으로 대입한다 — 의도 판정은 쓰지 않는다 (문서 12 §1).

    python api-bom/policy/judge.py
    → api-bom/policy/judgement.csv    자산 × 기준 판정
      api-bom/policy/report.md        사람용 요약
      api-bom/policy/inventory_v3.cdx.json  v2 인벤토리 + 판정·nuclei 결과 (CycloneDX 1.6)

입력 (사실만): 인벤토리 v2 수집 결과(inventory.cdx.json·services.csv), 팀 명세(openapi.yaml),
pfSense 설정 스냅샷, 실증 취약점(VEX), nuclei 커뮤니티 템플릿 결과(policy/nuclei/findings.jsonl),
사람이 승인한 예외(policy/exceptions.csv). baseline_v2.csv(의도)는 읽지 않는다.
"""
import copy
import csv
import json
import os
import re
import sys
import urllib.parse
from datetime import date, datetime, timezone

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
INV = os.path.join(ROOT, "inventory")
sys.path.insert(0, os.path.join(ROOT, "tools"))
from source_to_baseline import normalize  # noqa: E402  (v1·v2 와 같은 경로 정규화)

SPEC = os.path.join(ROOT, "inputs", "team_one_ab6c390", "web", "src", "public", "docs", "openapi.yaml")
FW = os.path.join(ROOT, "inputs", "config_2026-11-03_pfsense", "SNAPSHOT.md")
VEX = os.path.join(ROOT, "graph", "sample_dt", "vex.cdx.json")
NUCLEI = os.path.join(HERE, "nuclei", "findings.jsonl")
EXC = os.path.join(HERE, "exceptions.csv")
SEV_RANK = {"high": 3, "medium": 2, "low": 1}
SEV_KO = {"high": "높음", "medium": "중간", "low": "낮음"}


def props(x):
    return {p["name"]: p["value"] for p in x.get("properties", [])}


def load_spec():
    s = yaml.safe_load(open(SPEC, encoding="utf-8"))
    ops = set()
    for path, item in s["paths"].items():
        for m in item:
            if m.lower() in ("get", "post", "put", "patch", "delete"):
                ops.add(f"{m.upper()} {normalize(path)}")
    versions = [int(v) for v in re.findall(r"/api/v(\d+)/", " ".join(s["paths"]))]
    return ops, max(versions) if versions else None


def load_any_any_rules():
    """pfSense 스냅샷 규칙 표의 '허용' 규칙 중 포트가 전체(*)인 것. 출발지·목적지까지 * 면 any→any.
    (Anti-Lockout 처럼 포트가 정해진 규칙은 제외)"""
    out, tab = [], "?"
    for line in open(FW, encoding="utf-8"):
        m = re.match(r"#+ .*Rules\s*(?:→|->)\s*(\w+)", line)
        if m:
            tab = m.group(1)
        if not line.startswith("|") or "허용" not in line:
            continue
        cells = [re.sub(r"[*`\\\s]", "", c) for c in line.strip().strip("|").split("|")]
        raw = [c.strip() for c in line.strip().strip("|").split("|")]
        # 열: # | 동작 | 프로토콜 | 출발지 | 목적지 | 포트 | 설명 | 상태
        if len(cells) >= 6 and cells[5] == "":
            kind = "any→any" if cells[3] == "" and cells[4] == "" else f"{re.sub(r'[*`]', '', raw[3]).strip() or '*'} → {re.sub(r'[*`]', '', raw[4]).strip() or '*'} 포트 전체"
            out.append(f"{tab} #{raw[0]} {kind} '{re.sub(r'[*]', '', raw[6]).strip()}' ({re.sub(r'[*]', '', raw[7]).strip() if len(raw) > 7 else ''})")
    return out


def load_vex():
    out = {}
    v = json.load(open(VEX, encoding="utf-8"))
    for x in v.get("vulnerabilities", []):
        st = x.get("analysis", {}).get("state", "")
        if st not in ("exploitable", "in_triage"):
            continue
        for a in x.get("affects", []):
            ref = urllib.parse.unquote(a.get("ref", "").split("#", 1)[-1])
            if ref.startswith("op:"):
                out.setdefault(ref[3:], []).append(f"{x['id']} {st}: {(x.get('description') or '')[:40]}")
    return out


def load_nuclei():
    rows = []
    if os.path.exists(NUCLEI):
        for line in open(NUCLEI, encoding="utf-8"):
            try:
                j = json.loads(line)
            except ValueError:
                continue
            u = urllib.parse.urlparse(j.get("matched-at") or j.get("url") or "")
            port = u.port or (443 if u.scheme == "https" else 80)
            info = j.get("info", {})
            rows.append({"hostport": f"{u.hostname}:{port}", "scheme": u.scheme, "path": u.path or "/",
                         "id": j.get("template-id", ""), "name": info.get("name", ""),
                         "severity": info.get("severity", "info"), "tags": info.get("tags", []) or [],
                         "matched": j.get("matched-at", "")})
    return rows


def nuclei_status(n):
    run = os.path.join(HERE, "nuclei", "RUN.txt")
    txt = open(run, encoding="utf-8").read() if os.path.exists(run) else ""
    if not txt:
        return "nuclei 스캔 안 함"
    if "미완료" in txt:
        return f"**nuclei 스캔 미완료 — 결과 {n}건은 '없음'이 아님** (nuclei/RUN.txt)"
    return f"nuclei 결과 {n}건"


def load_exceptions():
    out = {}
    if os.path.exists(EXC):
        today = date.today().isoformat()
        for r in csv.DictReader(open(EXC, encoding="utf-8-sig")):
            if r.get("expires", "") >= today:
                out[(r["asset"], r["criterion"])] = r
    return out


def main():
    crit = yaml.safe_load(open(os.path.join(HERE, "criteria.yaml"), encoding="utf-8"))
    C = crit["criteria"]
    spec_ops, latest = load_spec()
    any_any = load_any_any_rules()
    vex = load_vex()
    nuc = load_nuclei()
    exc = load_exceptions()
    svc_cfg = {r["service_id"]: r for r in csv.DictReader(open(os.path.join(INV, "services.csv"), encoding="utf-8-sig"))}
    bom = json.load(open(os.path.join(INV, "inventory.cdx.json"), encoding="utf-8"))
    bom = copy.deepcopy(bom)

    results = []  # (layer, asset, group, seen_in, [(G, sev, evidence)], node)

    def nuclei_for(hostport, path=None):
        out = []
        for n in nuc:
            if n["hostport"] != hostport:
                continue
            if path is None or normalize(n["path"]) == path or (path != "/" and n["path"].rstrip("/") == path):
                out.append(n)
        return out

    # ── 엔드포인트 (svc:web-http 아래) ──
    web = next(s for s in bom["services"] if s["name"] == "web-http")
    used_nuclei = set()
    for grp in web.get("services", []):
        for op in grp.get("services", []):
            p = props(op)
            key = p["sesac:api:endpoint_key"]
            method, path = key.split(" ", 1)
            kind = p.get("sesac:api:kind", "api")
            seen = p.get("sesac:inv:seen_in", "")
            observed = "log" in seen or "scan" in seen
            v = []
            if kind == "api" and observed and key not in spec_ops:
                v.append(("G1", f"명세(openapi.yaml {len(spec_ops)}개)에 없음, 관측 {seen}"))
            m = re.match(r"/api/v(\d+)/", path + "/")
            if kind == "api" and observed and m and latest and int(m.group(1)) < latest:
                v.append(("G2", f"v{m.group(1)} < 최신 v{latest}"))
            if observed and any(sp in path.lower() for sp in crit["sensitive_paths"]):
                v.append(("G3", f"민감 경로 패턴, 관측 {seen}"))
            elif observed and any(path.lower().startswith(hp) for hp in crit["health_paths"]):
                v.append(("G3:low", f"헬스체크 경로 외부 응답, 관측 {seen}"))
            classes = [d.get("classification", "") for d in op.get("data", [])]
            # G4 는 API 에만: 화면(.php) 의 데이터 분류는 '폼이 받는 것'이지 돌려주는 게 아님 (login.php 오탐 방지)
            if kind == "api" and observed and method == "GET" and "PII" in classes and op.get("authenticated") is False:
                v.append(("G4", "PII + 인증 없음"))
            for e in vex.get(key, []):
                v.append(("G7", e))
            for n in nuclei_for("192.168.0.141:8000", path if method == "GET" else "__none__"):
                used_nuclei.add(n["matched"])
                if any(t in crit["nuclei_exposure_tags"] for t in n["tags"]) and not any(g.startswith("G3") for g, _ in v):
                    v.append(("G3", f"nuclei {n['id']} ({n['severity']})"))
                if SEV_RANK.get(n["severity"], 0) >= 2:
                    v.append(("G7", f"nuclei {n['id']} ({n['severity']})"))
            nuc_ids = [n["id"] for n in nuclei_for("192.168.0.141:8000", path if method == "GET" else "__none__")]
            results.append(("endpoint", key, grp["name"], seen + ("+nuclei" if nuc_ids else ""), v, op, nuc_ids))

    # nuclei 가 쇼핑몰에서 찾았는데 인벤토리에 없는 경로 → 새 자산
    web_extra = {}
    for n in nuc:
        if n["hostport"] == "192.168.0.141:8000" and n["matched"] not in used_nuclei:
            key = f"GET {normalize(n['path']) or '/'}"
            web_extra.setdefault(key, []).append(n)
    for key, ns in web_extra.items():
        path = key.split(" ", 1)[1]
        v = []
        if path.startswith("/api/") and key not in spec_ops:
            v.append(("G1", "nuclei 로 발견, 명세에 없음"))
        if any(sp in path.lower() for sp in crit["sensitive_paths"]) or any(
                t in crit["nuclei_exposure_tags"] for n in ns for t in n["tags"]):
            v.append(("G3", "nuclei " + ", ".join(sorted({n["id"] for n in ns}))))
        if any(SEV_RANK.get(n["severity"], 0) >= 2 for n in ns):
            v.append(("G7", "nuclei medium+ " + ", ".join(sorted({n["id"] for n in ns if SEV_RANK.get(n["severity"], 0) >= 2}))))
        node = {"bom-ref": f"op:{key}", "name": key, "description": "nuclei 커뮤니티 템플릿으로만 발견",
                "endpoints": ["http://192.168.0.141:8000" + path], "x-trust-boundary": True, "trustZone": "dmz",
                "properties": [{"name": "sesac:api:endpoint_key", "value": key},
                               {"name": "sesac:inv:seen_in", "value": "nuclei"}]}
        grp = next((g for g in web["services"] if g["name"] == "shop-nuclei-found"), None)
        if grp is None:
            grp = {"bom-ref": "svc:shop-nuclei-found", "name": "shop-nuclei-found",
                   "description": "v3 nuclei 로만 발견된 경로", "services": []}
            web["services"].append(grp)
        grp["services"].append(node)
        results.append(("endpoint", key, "shop-nuclei-found", "nuclei", v, node, [n["id"] for n in ns]))

    # ── 서비스 ──
    for svc in bom["services"]:
        p = props(svc)
        sid = svc["name"]
        cfg = svc_cfg.get(sid, {})
        seen = p.get("sesac:inv:seen_in", "")
        hostport = svc["endpoints"][0].split("://", 1)[-1].split("/")[0]
        if ":" not in hostport:
            hostport += ":80"
        v = []
        wan = p.get("sesac:svc:exposure", "").startswith("wan")
        restr = p.get("sesac:svc:source_restriction", "")
        admin = any(h in sid for h in crit["admin_service_hints"])
        if wan and admin and restr in ("any", "", "192.168.0.0/24"):
            v.append(("G5", f"관리 서비스, WAN 노출, 출발지 제한 '{restr or '없음'}'"))
        if seen == "scan":
            v.append(("G8", "설정 목록에 없고 스캔에서만 열림"))
        if "udp" in cfg.get("proto", ""):
            v.append(("G9", f"프로토콜 {cfg['proto']}"))
        ns = nuclei_for(hostport) if sid != "web-http" else []
        for n in ns:
            if SEV_RANK.get(n["severity"], 0) >= 2:
                v.append(("G7", f"nuclei {n['id']} ({n['severity']})"))
            elif "panel" in n["tags"] and wan and not any(g == "G5" for g, _ in v):
                v.append(("G5", f"nuclei {n['id']}: 관리 화면 외부 노출"))
        results.append(("service", sid, svc.get("trustZone", ""), seen + ("+nuclei" if ns else ""), v, svc,
                        sorted({n["id"] for n in ns})))

    # ── 플랫폼: 방화벽 정책 ──
    fw_node = {"bom-ref": "svc:fw-policy", "name": "fw-policy", "description": "pfSense 필터 규칙 집합 (구역 간 정책)",
               "endpoints": ["https://192.168.0.141"], "trustZone": "wan", "x-trust-boundary": True, "properties": []}
    results.append(("platform", "fw-policy", "pfSense", "config",
                    [("G6", r) for r in any_any], fw_node, []))
    bom["services"].append(fw_node)
    bom["dependencies"][0]["dependsOn"].append("svc:fw-policy")

    # ── 판정 정리 ──
    rows = []
    for layer, asset, group, seen, v, node, nids in results:
        items = []
        for g, ev in v:
            base = g.split(":")[0]
            sev = "low" if g.endswith(":low") else C[base]["severity"]
            ex = exc.get((asset, base))
            items.append((base, sev, ev, ex))
        open_items = [i for i in items if not i[3]]
        top = max((SEV_RANK[i[1]] for i in open_items), default=0)
        result = "통과" if not items else ("예외 승인" if not open_items else f"위반({SEV_KO[[k for k, r in SEV_RANK.items() if r == top][0]]})")
        rows.append({"layer": layer, "asset": asset, "group": group, "seen_in": seen, "result": result,
                     "violations": ";".join(sorted({i[0] for i in open_items})),
                     "excepted": ";".join(sorted({i[0] for i in items if i[3]})),
                     "evidence": " | ".join(f"{i[0]}: {i[2]}" for i in items),
                     "nuclei": ";".join(nids)})
        node.setdefault("properties", [])
        node["properties"] = [x for x in node["properties"] if not x["name"].startswith("sesac:policy:")] + [
            {"name": "sesac:policy:result", "value": result},
            *([{"name": "sesac:policy:violations", "value": rows[-1]["violations"]}] if rows[-1]["violations"] else []),
            *([{"name": "sesac:policy:excepted", "value": rows[-1]["excepted"]}] if rows[-1]["excepted"] else []),
            *([{"name": "sesac:policy:evidence", "value": rows[-1]["evidence"][:1000]}] if rows[-1]["evidence"] else []),
            *([{"name": "sesac:nuclei:templates", "value": rows[-1]["nuclei"]}] if rows[-1]["nuclei"] else []),
        ]

    order = {"위반(높음)": 0, "위반(중간)": 1, "위반(낮음)": 2, "예외 승인": 3, "통과": 4}
    rows.sort(key=lambda r: (order[r["result"]], r["layer"], r["asset"]))
    with open(os.path.join(HERE, "judgement.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    # v3 BOM
    md = bom["metadata"]
    md["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    md["tools"]["components"].append({"type": "application", "name": "judge.py", "version": "3.0",
                                      "group": "sesac-nobreak-team-one"})
    cnt = {}
    for r in rows:
        cnt[r["result"]] = cnt.get(r["result"], 0) + 1
    md["properties"] = [x for x in md["properties"] if not x["name"].startswith("sesac:inv:count")] + [
        {"name": "sesac:inv:version", "value": "v3"},
        {"name": "sesac:policy:criteria", "value": "docs/12_일반승인기준_v3.md (G1~G9, 의도 판정 미사용)"},
        *({"name": f"sesac:policy:count:{k}", "value": str(v)} for k, v in sorted(cnt.items()))]
    md["properties"] = [x for x in md["properties"] if x["name"] != "sesac:inv:version" or x["value"] == "v3"]
    import hashlib, uuid
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "sesac-inventory-v3:" + hashlib.sha256(
        json.dumps(rows, ensure_ascii=False, sort_keys=True).encode()).hexdigest()))
    with open(os.path.join(HERE, "inventory_v3.cdx.json"), "w", encoding="utf-8", newline="") as f:
        json.dump(bom, f, ensure_ascii=False, indent=2)

    # 보고서
    rep = ["# v3 판정 보고서 — 일반 승인 기준(G1~G9)만으로", "",
           f"- 생성: `python api-bom/policy/judge.py` · 기준: [문서 12](../docs/12_일반승인기준_v3.md) · 의도 판정(baseline_v2) 미사용",
           f"- 명세: openapi.yaml {len(spec_ops)}개 operation (최신 v{latest}) · " + nuclei_status(len(nuc)) + f" · 예외 {len(exc)}건",
           f"- 자산 {len(rows)}개: " + ", ".join(f"{k} {v}" for k, v in sorted(cnt.items(), key=lambda x: order[x[0]])), "",
           "## 기준별 위반 수", "", "| 기준 | 심각도 | 근거 | 위반 자산 |", "|---|---|---|---|"]
    for g, c in C.items():
        n = [r["asset"] for r in rows if g in r["violations"].split(";")]
        rep.append(f"| **{g}** {c['name']} | {SEV_KO[c['severity']]} | {c['ref']} | {len(n)} — {', '.join(n[:6])}{' …' if len(n) > 6 else ''} |")
    rep += ["", "## 자산별 판정 (위반 먼저)", "", "| 결과 | 층 | 자산 | 위반 기준 | 근거 |", "|---|---|---|---|---|"]
    for r in rows:
        ev = r["evidence"].replace("|", "/")
        rep.append(f"| {r['result']} | {r['layer']} | `{r['asset']}` | {r['violations'] or '-'} | {ev[:220]} |")
    with open(os.path.join(HERE, "report.md"), "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(rep) + "\n")
    print("\n".join(rep[:5]))


if __name__ == "__main__":
    main()
