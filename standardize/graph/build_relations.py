"""API-BOM + SBOM + 취약점 → 관계 그래프 · 위험 점수 · VEX · 대시보드 (Dependency-Track 없이).

재료 (전부 이 레포에 있는 파일 — 사람이 그리는 게 아니라 파일을 읽어 그린다)
  ① API-BOM (nuclei 관측 반영)   nuclei/sample/assets_2026-11-02/baseline.asset-observed.cdx.json
  ② 이미지 SBOM                    BOM-Link(metadata.component.externalReferences[type=bom]) 로 찾음
  ③ 부품 취약점                    --grype-json (전체) · --grype-summary (팀 summary.md 상위 10)
                                   · --dtrack-url (Dependency-Track API, 부품 전부 · 판단 반영)
  ④ 연결 규칙 + 실증 취약점       graph/relations_rules.json (코드 근거 있는 것만)

관계
  app ─(provides)→ service ─(has)→ endpoint
  app ─(runs on, BOM-Link)→ image ─(runtime)→ apache2·libphp ─(SBOM dependencies)→ 하위 부품
  endpoint ─(uses, 규칙)→ php-jwt · dash        endpoint ─(VEX)→ 실증 취약점

위험 점수 = docs/05 §2-1 가중치 (+++=3, ++=2, ++++=4). 우선순위 정렬용, 자동 차단용 아님.

사용:
  python api-bom/graph/build_relations.py                 # 기본 입력 → api-bom/graph/sample/
  python api-bom/graph/build_relations.py --grype-json g.json -o api-bom/out/graph
  DT_APIKEY=... python api-bom/graph/build_relations.py --dtrack-url http://<VM_IP>:8081   # → graph/sample_dt/
출력: relations.json · risk.csv · vex.cdx.json · dashboard.html
"""
import argparse
import collections
import csv
import glob
import json
import os
import re
import datetime
import urllib.parse
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))          # api-bom/graph
APIBOM_DIR = os.path.dirname(HERE)                          # api-bom
REPO = os.path.dirname(APIBOM_DIR)

DEF_APIBOM = os.path.join(APIBOM_DIR, "nuclei", "sample", "assets_2026-11-02", "baseline.asset-observed.cdx.json")
DEF_SUMMARY = os.path.join(HERE, "inputs", "grype_summary_2026-10-30.md")
DEF_RULES = os.path.join(HERE, "relations_rules.json")
VIS_JS = "https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"

WEIGHTS = {  # docs/05_baseline_고도화_설계.md §2-1 · (가중치, 설명, 범주)
    # 범주: asset=항상 계산되는 자산·노출 속성 · reach=실제 도달하는 부품 취약점 · proven=실증(모의해킹 VEX)
    "sensitive": (3, "PII/결제 취급", "asset"),
    "noauth": (2, "인증 없음", "asset"),
    "dmz": (2, "DMZ 노출", "asset"),
    "zombie": (3, "deprecated∩live = zombie", "asset"),
    "shadow": (3, "선언 밖(명세 없음) = shadow", "asset"),
    "exploitable": (4, "실증 취약점(VEX exploitable)", "proven"),
    "triage": (2, "코드상 취약점(VEX in_triage)", "proven"),
    "comp_cve": (2, "도달하는 부품에 Critical CVE", "reach"),
}
CATEGORIES = ("asset", "reach", "proven")
SENSITIVE = {"PII", "customer-transaction", "payment"}
SEV_COLOR = {"critical": "#c62828", "high": "#ef6c00", "none": "#90a4ae", "unknown": "#cfd8dc"}


def props(o):
    return {p["name"]: p["value"] for p in o.get("properties", []) or []}


# ---------- 입력 ----------
def load_apibom(path):
    d = json.load(open(path, encoding="utf-8"))
    app = d["metadata"]["component"]
    services, endpoints = [], []
    for s in d.get("services", []) or []:
        services.append({"ref": s["bom-ref"], "name": s["name"], "zone": s.get("trustZone", "")})
        for o in s.get("services", []) or []:
            p = props(o)
            endpoints.append({
                "ref": o["bom-ref"], "key": o["name"], "service": s["bom-ref"],
                "kind": p.get("sesac:api:kind", "api"),
                "auth": bool(o.get("authenticated")),
                "classes": [x.get("classification") for x in o.get("data", []) or []],
                "zone": o.get("trustZone", s.get("trustZone", "")),
                "decision": p.get("sesac:baseline:decision", ""),
                "observed_as": p.get("sesac:baseline:observed-as", ""),
                "asset": p.get("sesac:asset:observed", ""),
                "asset_status": p.get("sesac:asset:status", ""),
                "source": p.get("sesac:source:location", ""),
            })
    link = next((r["url"] for r in app.get("externalReferences", []) or [] if r.get("type") == "bom"), None)
    return d, app, services, endpoints, link


def resolve_bomlink(link, search_root):
    """urn:cdx:<serial>/<ver>#<ref> → 그 serialNumber 를 가진 로컬 CycloneDX 파일."""
    m = re.match(r"urn:cdx:([0-9a-f-]+)/(\d+)(?:#(.+))?$", link or "")
    if not m:
        raise SystemExit(f"BOM-Link 형식 아님: {link}")
    serial, ver, ref = "urn:uuid:" + m.group(1), int(m.group(2)), urllib.parse.unquote(m.group(3) or "")
    for f in glob.glob(os.path.join(search_root, "**", "*.cdx.json"), recursive=True):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if d.get("serialNumber") == serial and int(d.get("version", 1)) == ver:
            return f, d, ref
    raise SystemExit(f"BOM-Link 대상 SBOM 을 찾지 못함: {link}")


def vulns_from_summary(path):
    """팀 grype summary.md '원본 패키지 상위 10' 표 → {부품이름: {critical, high}} (상위 10 밖은 모름)."""
    out, meta = {}, {}
    for line in open(path, encoding="utf-8"):
        m = re.match(r"\|\s*취약점 DB 기준 시각\s*\|\s*([^|]+)\|", line)
        if m:
            meta["db"] = m.group(1).strip()
        m = re.match(r"\|\s*(Critical)\s*\|", line)
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 6 and cells[0].isdigit() and "total" not in meta:
            meta.update(zip(["critical", "high", "medium", "low", "negligible", "total"], map(int, cells)))
        if len(cells) == 6 and re.match(r"^\d+$", cells[3] or "") and re.match(r"^\d+$", cells[4] or "") \
                and cells[2] in ("deb", "binary", "composer", "generic"):
            for comp in [c.strip() for c in cells[5].split(",")]:
                out[comp] = {"critical": int(cells[3]), "high": int(cells[4]), "src": cells[0]}
        m = re.search(r"실제 악용 확인\(KEV\):\s*\*\*(\d+)", line)
        if m:
            meta["kev"] = int(m.group(1))
    meta["mode"] = "summary-top10"
    return out, meta


def vulns_from_grype(path):
    d = json.load(open(path, encoding="utf-8"))
    out = collections.defaultdict(lambda: {"critical": 0, "high": 0, "src": ""})
    meta = collections.Counter()
    for m in d.get("matches", []) or []:
        sev = ((m.get("vulnerability") or {}).get("severity") or "").lower()
        name = (m.get("artifact") or {}).get("name", "")
        meta[sev] += 1
        if sev in ("critical", "high"):
            out[name][sev] += 1
    meta = dict(meta)
    meta.update({"mode": "grype-json", "total": sum(v for k, v in meta.items() if isinstance(v, int)),
                 "db": str(((d.get("descriptor") or {}).get("db") or {}).get("built", ""))})
    return dict(out), meta


def _dt_get(base, key, path):
    req = urllib.request.Request(base.rstrip("/") + path, headers={"X-Api-Key": key, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def vulns_from_dtrack(base, key, project, version):
    """Dependency-Track 프로젝트의 finding → {부품이름: {critical, high}}.
    사람이 DT 에서 '해당 없음'(NOT_AFFECTED·FALSE_POSITIVE) 으로 판단했거나 숨긴(suppressed) 것은 뺀다."""
    if version == "latest":   # DT 에서 isLatest 로 표시된 버전 (자동 업로드가 매번 isLatest=true 로 올림)
        cands = [p for p in _dt_get(base, key, "/api/v1/project?" + urllib.parse.urlencode({"name": project, "pageSize": 100}))
                 if p.get("name") == project and p.get("active", True)]
        if not cands:
            raise SystemExit(f"DT 에 {project} 프로젝트 없음")
        proj = next((p for p in cands if p.get("isLatest")), None) or max(cands, key=lambda p: p.get("lastBomImport") or 0)
        version = proj.get("version", "")
    else:
        q = urllib.parse.urlencode({"name": project, "version": version})
        proj = _dt_get(base, key, f"/api/v1/project/lookup?{q}")
    findings = _dt_get(base, key, f"/api/v1/finding/project/{proj['uuid']}?suppressed=false")
    out = collections.defaultdict(lambda: {"critical": 0, "high": 0, "src": ""})
    meta, skipped, sources = collections.Counter(), 0, collections.Counter()
    for f in findings:
        state = ((f.get("analysis") or {}).get("state") or "").upper()
        if (f.get("analysis") or {}).get("isSuppressed") or state in ("NOT_AFFECTED", "FALSE_POSITIVE"):
            skipped += 1
            continue
        sev = ((f.get("vulnerability") or {}).get("severity") or "").lower()
        name = (f.get("component") or {}).get("name", "")
        meta[sev] += 1
        sources[(f.get("vulnerability") or {}).get("source", "?")] += 1
        if sev in ("critical", "high"):
            out[name][sev] += 1
    meta = dict(meta)
    meta.update({"mode": "dtrack", "total": sum(meta.values()), "skipped_by_analysis": skipped,
                 "sources": dict(sources), "project": f"{project}@{version}", "dt_url": base,
                 "db": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC (조회)")})
    return dict(out), meta


def vulns_from_snapshot(folder):
    """git 에 쌓인 DT 스냅샷(api-bom/dt_history/<프로젝트>/<버전>_<시각>/ 의 findings.csv·metrics.json) — DT 서버 없이 같은 결과"""
    m = json.load(open(os.path.join(folder, "metrics.json"), encoding="utf-8"))
    out = collections.defaultdict(lambda: {"critical": 0, "high": 0, "src": ""})
    meta, skipped, sources = collections.Counter(), 0, collections.Counter()
    for f in csv.DictReader(open(os.path.join(folder, "findings.csv"), encoding="utf-8")):
        if (f.get("analysis") or "").upper() in ("NOT_AFFECTED", "FALSE_POSITIVE") or str(f.get("suppressed")).lower() == "true":
            skipped += 1
            continue
        sev = (f.get("severity") or "").lower()
        meta[sev] += 1
        sources[f.get("source", "?")] += 1
        if sev in ("critical", "high"):
            out[f["component"]][sev] += 1
    meta = dict(meta)
    meta.update({"mode": "dtrack", "total": sum(meta.values()), "skipped_by_analysis": skipped, "sources": dict(sources),
                 "project": f"{m['project']}@{m['version']}", "dt_url": f"스냅샷 {os.path.relpath(folder, REPO)}",
                 "db": m.get("captured_at", "")[:16].replace("T", " ") + " UTC (스냅샷)"})
    return dict(out), meta


# ---------- 조립 ----------
def load_reach(path):
    """도달성 정적 분석 결과(api-bom/reach/results/*/reach.json, 문서 14) → {정규화 엔드포인트: {부품: [근거]}}"""
    if not path:
        return {}
    d = json.load(open(path, encoding="utf-8"))
    return {re.sub(r"\{\w+\}", "{id}", e["endpoint_key"]): e["components"] for e in d["endpoints"]}


def build(apibom_path, rules_path, grype_json=None, grype_summary=None, dtrack=None, reach_path=None):
    apibom, app, services, endpoints, link = load_apibom(apibom_path)
    sbom_path, sbom, image_ref = resolve_bomlink(link, APIBOM_DIR)
    rules = json.load(open(rules_path, encoding="utf-8"))
    if isinstance(dtrack, str):          # --dtrack-snapshot 폴더
        vulns, vmeta = vulns_from_snapshot(dtrack)
    elif dtrack:
        vulns, vmeta = vulns_from_dtrack(*dtrack)
    else:
        vulns, vmeta = (vulns_from_grype(grype_json) if grype_json else vulns_from_summary(grype_summary))

    comps = {c["bom-ref"]: c for c in sbom.get("components", []) if c.get("type") != "file" and c.get("bom-ref")}
    by_name = {}
    for c in comps.values():
        by_name.setdefault(c["name"], c)
    children = collections.defaultdict(set)
    for dep in sbom.get("dependencies", []) or []:
        for t in dep.get("dependsOn", []) or []:
            if dep["ref"] in comps and t in comps:
                children[dep["ref"]].add(t)

    def sev_of(name):
        v = vulns.get(name)
        if v is None:  # DT 는 부품 전부를 평가하므로 finding 없음 = 취약점 없음
            return "none" if vmeta["mode"] == "dtrack" else "unknown"
        return "critical" if v["critical"] else ("high" if v["high"] else "none")

    def vuln_paths(root_ref, max_depth=3):
        """루트 부품에서 SBOM dependencies 를 따라가며 '취약 부품까지의 경로'만 남긴다 (털뭉치 방지)."""
        keep, edges = set(), set()

        def walk(ref, path, depth):
            if sev_of(comps[ref]["name"]) in ("critical", "high") and len(path) > 1:
                keep.update(path)
                edges.update(zip(path, path[1:]))
            if depth >= max_depth:
                return
            for ch in sorted(children.get(ref, ())):
                if ch not in path:
                    walk(ch, path + [ch], depth + 1)
        walk(root_ref, [root_ref], 0)
        return keep, edges

    nodes, edges = {}, set()

    def add(nid, **kw):
        nodes.setdefault(nid, {"id": nid, **kw})

    add(app["bom-ref"], label=app["name"], group="app", level=0,
        title=f"{app['name']} {app.get('version','')}\n{app.get('description','')}")
    img_meta = sbom["metadata"]["component"]
    img_id = "image:" + image_ref
    add(img_id, label=f"{img_meta.get('name','image')} (SBOM)", group="image", level=1,
        title=f"이미지 SBOM — BOM-Link\n{link}\n{os.path.relpath(sbom_path, REPO)}\n부품 {len(comps)}")
    edges.add((app["bom-ref"], img_id, "runs on (BOM-Link)"))

    for s in services:
        add(s["ref"], label=s["name"], group="service", level=1, title=f"{s['name']} · trustZone={s['zone']}")
        edges.add((app["bom-ref"], s["ref"], "provides"))

    def comp_node(c, level):
        cid = "pkg:" + c["bom-ref"]
        v = vulns.get(c["name"])
        sv = sev_of(c["name"])
        tip = f"{c['name']} {c.get('version','')}\n{c.get('purl','')}"
        tip += (f"\nCritical {v['critical']} · High {v['high']} (원본 {v['src']})" if v else
                "\n취약점 데이터 없음 (상위10 밖 또는 미검사)" if vmeta["mode"] == "summary-top10" else "\nCritical/High 0")
        add(cid, label=c["name"], group="pkg", level=level, sev=sv, title=tip,
            crit=(v or {}).get("critical", 0), high=(v or {}).get("high", 0))
        return cid

    # 런타임 부품 + 그 아래 '취약 부품까지의 경로'
    runtime_ids = []
    for name in rules["runtime"]["components"]:
        c = by_name.get(name)
        if not c:
            continue
        rid = comp_node(c, 3)
        runtime_ids.append(rid)
        edges.add((img_id, rid, "runtime: " + rules["runtime"]["evidence"]))
        keep, pedges = vuln_paths(c["bom-ref"])
        for ref in sorted(keep):
            comp_node(comps[ref], 4)
        for a, b in sorted(pedges):
            edges.add(("pkg:" + a, "pkg:" + b, "SBOM dependsOn"))

    known = {k["endpoint_key"]: k for k in rules.get("known_vulns", [])}
    # 도달성(문서 14, --reach 줄 때만): 런타임 공통은 이미지 쪽에 이미 있음. API 전부가 닿는 부품은 서비스 노드에 한 번만
    # (선 겹침 방지), 엔드포인트마다 다른 부품만 엔드포인트에 잇는다. 선 제목 앞머리 = 근거 종류
    reach = load_reach(reach_path)
    # 엔드포인트별 '도달하는 Critical CVE 수' (reach.json 레코드의 critical 목록) — 점수 설명·표시용
    reach_crit_count = {}
    if reach_path:
        _rd = json.load(open(reach_path, encoding="utf-8"))
        reach_crit_count = {re.sub(r"\{\w+\}", "{id}", e["endpoint_key"]): len(e.get("critical") or [])
                            for e in _rd["endpoints"]}
    runtime_names = set(rules["runtime"]["components"]) | {"apache2-bin", "libapr1", "libaprutil1", "libc6", "libpcre3"}
    nk = lambda k: re.sub(r"\{\w+\}", "{id}", k)
    api_keys = [nk(e["key"]) for e in endpoints if e["kind"] == "api" and nk(e["key"]) in reach]
    common = (set.intersection(*[set(reach[k]) for k in api_keys]) - runtime_names) if api_keys else set()
    if reach:
        for svc in services:
            if any(e["service"] == svc["ref"] and e["kind"] == "api" and nk(e["key"]) in reach for e in endpoints):
                for name in sorted(common):
                    c = by_name.get(name)
                    if c:
                        ev = sorted(reach[api_keys[0]][name])[0] if reach[api_keys[0]][name] else ""
                        edges.add((svc["ref"], comp_node(c, 3), f"[정적·공통] 이 서비스의 모든 API 가 지남 — {ev}"))
    rows = []
    for e in endpoints:
        is_api = e["kind"] == "api"
        linked = list(rules["runtime"]["components"])
        evid = []
        link_ev = collections.OrderedDict()   # 도달성 모드: 부품 → {"규칙": 근거, "정적": 근거}
        for r in rules["rules"]:
            w = r["when"]
            if all((e["key"] == v) if k == "endpoint_key" else (e.get("auth") == v if k == "authenticated"
                   else e.get(k) == v) for k, v in w.items()):
                for name in r["components"]:
                    if reach:   # 도달성 모드: 규칙 근거는 모아 두었다가 아래에서 정적 근거와 함께 선 하나로
                        link_ev.setdefault(name, {})["규칙"] = r["evidence"]
                        evid.append(r["evidence"])
                        continue
                    c = by_name.get(name)
                    if c:
                        cid = comp_node(c, 3)
                        edges.add((e["ref"], cid, "uses: " + r["evidence"]))
                        if name not in linked:
                            linked.append(name)
                        evid.append(r["evidence"])
        for name, ev in (reach.get(nk(e["key"])) or {}).items():
            if name in runtime_names:
                continue
            if name in common:
                if name not in linked:
                    linked.append(name)
                continue
            link_ev.setdefault(name, {})["정적"] = sorted(ev)[0] if ev else ""
        for name, ev in link_ev.items():
            c = by_name.get(name)
            if not c:
                continue
            kinds = "+".join(k for k in ("정적", "규칙") if k in ev)
            edges.add((e["ref"], comp_node(c, 3), f"[{kinds}] " + " | ".join(f"{k}: {v}" for k, v in ev.items())))
            if name not in linked:
                linked.append(name)

        # 위험 점수 — 자산 / 도달 / 실증 으로 나눠 집계 (하나의 숫자로 뭉치지 않게)
        why, score = [], 0
        sub = {c: 0 for c in CATEGORIES}

        def hit(sig):
            nonlocal score
            w, desc, cat = WEIGHTS[sig]
            score += w
            sub[cat] += w
            why.append(f"{desc} +{w}")
        # 화면(page)은 껍데기 HTML 이고 데이터는 app.js 가 /api/v2/* 로 가져온다 (페이지에 $_ 데이터 접근 없음)
        # → 데이터·인증 가중치는 실제로 데이터를 내주는 api 에만 준다
        if is_api and SENSITIVE & set(e["classes"]):
            hit("sensitive")
        if is_api and not e["auth"]:
            hit("noauth")
        if e["zone"] == "dmz":
            hit("dmz")
        if e["decision"] == "deprecated" and e["asset"] == "live":
            hit("zombie")
        if e["observed_as"] == "shadow" or e["decision"] == "review":
            hit("shadow")
        kv = known.get(e["key"])
        if kv:
            hit("exploitable" if kv["state"] == "exploitable" else "triage")
        # 연결 부품 중 Critical CVE 가진 것. reach 가 있으면 '실제 도달하는 부품'으로만 한정 (미도달 CVE 는 점수에서 뺌)
        crit_comps = [n for n in linked if (vulns.get(n) or {}).get("critical")]
        reached_names = set((reach.get(nk(e["key"])) or {}).keys()) | common if reach else None
        reach_crit = [n for n in crit_comps if n in reached_names] if reach else crit_comps
        reach_info = ""
        if reach:
            n_reach_crit = reach_crit_count.get(nk(e["key"]))
            reach_info = (f"도달 Critical CVE {n_reach_crit}개" if n_reach_crit is not None
                          else f"도달 Critical 부품 {len(reach_crit)}/{len(crit_comps)}")
        if reach_crit:
            hit("comp_cve")
        elif reach and crit_comps:
            why.append(f"부품 Critical 있으나 모두 미도달 — 제외 (총 {len(crit_comps)})")
        if reach and reach_info and reach_crit:
            why[-1] = why[-1] + f" [{reach_info}]"

        cls = "shadow" if (e["observed_as"] == "shadow" or e["decision"] == "review") else \
              ("zombie" if e["decision"] == "deprecated" else "documented")
        add(e["ref"], label=e["key"], group="endpoint", level=2, cls=cls, score=score,
            kind=e["kind"], asset=e["asset"],
            title=(f"{e['key']}\n분류 {cls} · 관측 {e['asset'] or '-'} {e['asset_status']}\n"
                   f"인증 {'필요' if e['auth'] else '없음'} · 데이터 {','.join(e['classes'])}\n"
                   f"코드 {e['source'] or '-'}\n위험 {score}: " + " / ".join(why)))
        edges.add((e["service"], e["ref"], "has"))
        if kv:
            vid = "vuln:" + kv["id"]
            add(vid, label=f"{kv['title'].split('—')[0].strip()} ({kv['state']})", group="vuln", level=3,
                state=kv["state"], title=f"{kv['id']} · CWE-{kv['cwe']} · {kv['severity']}\n{kv['title']}\n{kv['detail']}")
            edges.add((e["ref"], vid, ("[실증] " if reach else "") + "VEX " + kv["state"]))
        rows.append({
            "endpoint_key": e["key"], "kind": e["kind"], "class": cls, "risk": score,
            "asset": sub["asset"], "reach": sub["reach"], "proven": sub["proven"], "reach_info": reach_info,
            "why": " / ".join(why),
            "observed": e["asset"] or "-", "status": e["asset_status"] or "-",
            "auth": "필요" if e["auth"] else "없음", "data": ",".join(e["classes"]),
            "components": ",".join(linked), "critical_components": ",".join(crit_comps),
            "vex": f"{kv['id']} {kv['state']}" if kv else "", "source": e["source"],
        })

    rows.sort(key=lambda r: (-r["risk"], r["endpoint_key"]))
    stats = {
        "endpoints": len(endpoints), "api": sum(e["kind"] == "api" for e in endpoints),
        "live": sum(e["asset"] == "live" for e in endpoints),
        "shadow": sum(r["class"] == "shadow" for r in rows), "zombie": sum(r["class"] == "zombie" for r in rows),
        "exploitable": sum(k["state"] == "exploitable" for k in known.values()),
        "triage": sum(k["state"] == "in_triage" for k in known.values()),
        "sbom_components": len(comps), "vuln_meta": vmeta,
    }
    inputs = {"api_bom": os.path.relpath(apibom_path, REPO), "api_bom_serial": apibom.get("serialNumber"),
              "sbom": os.path.relpath(sbom_path, REPO), "bom_link": link,
              "vulns": (f"Dependency-Track {vmeta['dt_url']} 프로젝트 {vmeta['project']}" if dtrack
                        else os.path.relpath(grype_json or grype_summary, REPO)),
              "rules": os.path.relpath(rules_path, REPO),
              **({"reach": os.path.relpath(reach_path, REPO)} if reach_path else {})}
    return {"nodes": list(nodes.values()), "edges": sorted(edges), "rows": rows, "stats": stats,
            "inputs": inputs, "known": list(known.values()), "apibom": apibom}


# ---------- 출력 ----------
def vex_doc(g):
    """CycloneDX 1.6 VEX — affects.ref 는 API-BOM 엔드포인트를 BOM-Link 로 가리킨다."""
    ab = g["apibom"]
    serial = ab["serialNumber"].replace("urn:uuid:", "")
    vulns = []
    for k in g["known"]:
        ref = "op:" + k["endpoint_key"]
        vulns.append({
            "bom-ref": k["id"], "id": k["id"],
            "source": {"name": "sesac pentest (nuclei)"},
            "ratings": [{"severity": k["severity"], "method": "other"}],
            "cwes": [k["cwe"]], "description": k["title"], "detail": k["detail"],
            "analysis": {"state": k["state"], "detail": k["evidence"]},
            "affects": [{"ref": f"urn:cdx:{serial}/{ab.get('version', 1)}#{urllib.parse.quote(ref, safe='')}"}],
        })
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json", "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "sesac-vex:" + serial)), "version": 1,
        "metadata": {"timestamp": ab["metadata"].get("timestamp"),
                     "tools": {"components": [{"type": "application", "name": "build_relations.py", "version": "1.0"}]}},
        "vulnerabilities": vulns,
    }


def layout(g, col_w=330, row_h=34):
    """결정적 좌표: 열 = level, 행 = 의미 있는 순서 (서비스별 엔드포인트는 위험순). 클릭해도 안 움직인다."""
    rank = {r["endpoint_key"]: i for i, r in enumerate(g["rows"])}
    svc_order = {n["id"]: i for i, n in enumerate(x for x in g["nodes"] if x["group"] == "service")}
    parent = {b: a for a, b, _ in g["edges"]}

    def key(n):
        grp = n["group"]
        if grp == "endpoint":
            return (svc_order.get(parent.get(n["id"]), 9), rank.get(n["label"], 99))
        if grp == "service":
            return (1, svc_order[n["id"]])
        if grp == "image":
            return (0, 0)
        if grp == "vuln":
            return (2, n["id"])
        if grp == "pkg":
            return (1, -n.get("crit", 0), n["label"])
        return (0, n["id"])
    cols = collections.defaultdict(list)
    for n in g["nodes"]:
        cols[n["level"]].append(n)
    tallest = max(len(v) for v in cols.values())
    pos = {}
    for lvl, ns in cols.items():
        ns.sort(key=key)
        step = max(row_h, min(70, tallest * row_h / max(len(ns), 1)))  # 노드 적은 열은 넓게
        top = (tallest * row_h - (len(ns) - 1) * step) / 2
        for i, n in enumerate(ns):
            pos[n["id"]] = (lvl * col_w, top + i * step)
    return pos, tallest * row_h


def render_html(g):
    pos, height = layout(g)
    vis_nodes = []
    for n in g["nodes"]:
        grp = n["group"]
        node = {"id": n["id"], "label": n["label"], "title": n["title"],
                "x": pos[n["id"]][0], "y": pos[n["id"]][1], "fixed": True}
        if grp == "app":
            node.update(shape="box", color="#1a237e", font={"color": "#fff"})
        elif grp == "image":
            node.update(shape="box", color="#37474f", font={"color": "#fff"})
        elif grp == "service":
            node.update(shape="box", color="#3949ab", font={"color": "#fff"})
        elif grp == "endpoint":
            col = {"shadow": "#d32f2f", "zombie": "#f57c00"}.get(n["cls"], "#43a047" if n["kind"] == "api" else "#a5d6a7")
            node.update(shape="box", label=f"{n['score']:>2} · {n['label']}", color=col,
                        font={"color": "#fff" if n["kind"] == "api" else "#1b3a1d", "size": 11, "face": "monospace"},
                        borderWidth=3 if n["asset"] == "live" else 1)
        elif grp == "pkg":
            node.update(shape="diamond", size=9 + min(n.get("crit", 0) + n.get("high", 0) * 0.2, 14),
                        color=SEV_COLOR[n["sev"]])
        elif grp == "vuln":
            node.update(shape="star", size=22, color="#b71c1c" if n["state"] == "exploitable" else "#ff8f00")
        vis_nodes.append(node)
    def ekind(t):
        m = re.match(r"\[([^\]]+)\]", t)
        return m.group(1) if m else "구조"
    EST = {"정적": {"dashes": [6, 4], "color": {"color": "#2a78d6"}, "width": 1.4},
           "정적·공통": {"dashes": [2, 4], "color": {"color": "#2a78d6"}, "width": 1.2},
           "규칙": {"dashes": [1, 4], "color": {"color": "#77756f"}, "width": 1.2},
           "정적+규칙": {"color": {"color": "#2a78d6"}, "width": 2.4},
           "실증": {"color": {"color": "#c0392b"}, "width": 2.4}}
    with_reach = "reach" in g["inputs"]
    vis_edges = [({"from": a, "to": b, "title": t, "arrows": "to", "kind": ekind(t), **EST.get(ekind(t), {})} if with_reach
                  else {"from": a, "to": b, "title": t, "arrows": "to"}) for a, b, t in g["edges"]]   # 도달성 없으면 기존과 같은 출력
    reach_legend = ("""<div class="lg" style="margin-top:6px"><b>선 = 근거 종류</b> (체크 해제 = 숨김):
<label><input type="checkbox" class="ek" value="정적+규칙" checked> <span style="color:#2a78d6">━ 정적+규칙</span></label>
<label><input type="checkbox" class="ek" value="정적" checked> <span style="color:#2a78d6">╌ 정적 도달 (문서 14)</span></label>
<label><input type="checkbox" class="ek" value="정적·공통" checked> <span style="color:#2a78d6">┈ 정적·공통 (서비스의 모든 API)</span></label>
<label><input type="checkbox" class="ek" value="규칙" checked> <span style="color:#77756f">┈ 규칙만</span></label>
<label><input type="checkbox" class="ek" value="실증" checked> <span style="color:#c0392b">━ 실증 (모의해킹 VEX)</span></label>
<label><input type="checkbox" class="ek" value="구조" checked> ─ 구조 (앱·서비스·SBOM)</label>
· 동적 관측(로그·스캔)은 엔드포인트 테두리(live)·표 '관측' 칸 · 근거를 한 표로: <code>api-bom/reach/results/&lt;날짜&gt;/evidence_dashboard.html</code></div>"""
                    if with_reach else "")
    reach_js = ("""document.querySelectorAll("input.ek").forEach(cb=>cb.onchange=()=>{const off=new Set([...document.querySelectorAll("input.ek")].filter(x=>!x.checked).map(x=>x.value));
 E.update(E.get().map(e=>({id:e.id,hidden:off.has(e.kind)})));});
""" if with_reach else "")

    s, vm = g["stats"], g["stats"]["vuln_meta"]
    kpi = [("엔드포인트", f"{s['endpoints']}", f"API {s['api']} · 화면 {s['endpoints'] - s['api']}"),
           ("관측 live (nuclei)", f"{s['live']}", "선언 API 생존 확인"),
           ("Shadow", f"{s['shadow']}", "명세 없음 · 코드에만"),
           ("실증 취약점", f"{s['exploitable']}", f"+ 확인 대기 {s['triage']}"),
           ("부품 Critical", f"{vm.get('critical', '-')}", f"High {vm.get('high', '-')} · KEV {vm.get('kev', '-')}"),
           ("SBOM 부품", f"{s['sbom_components']}", f"취약 DB {vm.get('db', '-')[:10]}")]
    kpi_html = "".join(f'<div class="k"><div class="kl">{a}</div><div class="kv">{b}</div><div class="ks">{c}</div></div>'
                       for a, b, c in kpi)
    sp = lambda v, c: f'<span style="color:{c}">{v}</span>' if v else '<span style="color:var(--sub)">0</span>'
    trs = "".join(
        f'<tr class="{r["class"]}" data-id="op:{r["endpoint_key"]}"><td><b>{r["risk"]}</b></td>'
        f'<td class="sub3">{sp(r.get("asset", 0), "#8e8e8e")} / {sp(r.get("reach", 0), "#ef6c00")} / {sp(r.get("proven", 0), "#c62828")}</td>'
        f'<td><code>{r["endpoint_key"]}</code></td>'
        f'<td>{r["class"]}</td><td>{r["observed"]} {r["status"]}</td><td>{r["auth"]}</td><td>{r["data"]}</td>'
        f'<td>{r["components"]}</td><td>{r["vex"]}</td><td class="why">{r["why"]}</td></tr>'
        for r in g["rows"])
    inp = "".join(f"<li><b>{k}</b> <code>{v}</code></li>" for k, v in g["inputs"].items())
    note = {"summary-top10": "부품 취약점은 팀 grype summary.md 의 '원본 패키지 상위 10'만 반영 (나머지 부품은 회색=데이터 없음). "
                             "전체 반영: --grype-json",
            "grype-json": "부품 취약점: grype JSON 전체",
            "dtrack": f"부품 취약점: Dependency-Track 프로젝트 {vm.get('project')} 의 finding 전부 (출처별 {vm.get('sources')}). "
                      f"DT 에서 '해당 없음'·숨김 판단된 {vm.get('skipped_by_analysis', 0)}건 제외. "
                      "취약점이 없는 부품은 회색(none)."}[vm["mode"]]
    src_line = ("파일만 읽어 생성 (Dependency-Track 미사용)." if vm["mode"] != "dtrack"
                else "부품 취약점은 <b>Dependency-Track API</b> 에서 조회 (DT 가 매일 재평가).")
    title = "API 자산 관계 대시보드" + (" (DT 연동)" if vm["mode"] == "dtrack" else "")
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><script src="{VIS_JS}"></script>
<style>
:root{{--bg:#f6f7fb;--card:#fff;--ink:#1c2333;--sub:#5f6b7a;--line:#e3e6ee}}
@media (prefers-color-scheme:dark){{:root{{--bg:#12151c;--card:#1b2029;--ink:#e8ebf1;--sub:#9aa4b2;--line:#2a313d}}}}
body{{margin:0;font-family:system-ui,'Malgun Gothic',sans-serif;background:var(--bg);color:var(--ink)}}
main{{max-width:1400px;margin:0 auto;padding:16px}} h1{{font-size:20px;margin:4px 0 2px}} .sub{{color:var(--sub);font-size:13px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:14px 0}}
.k{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}}
.kl{{font-size:12px;color:var(--sub)}} .kv{{font-size:26px;font-weight:700}} .ks{{font-size:12px;color:var(--sub)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;margin:12px 0}}
#g{{height:900px}} .lg span{{margin-right:12px;font-size:12px}}
table{{border-collapse:collapse;width:100%;font-size:12.5px}} th,td{{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}}
tr.shadow td:first-child{{color:#d32f2f}} tr{{cursor:pointer}} tr:hover{{background:rgba(120,130,160,.08)}} .why{{color:var(--sub)}}
.wrap{{overflow-x:auto}} td:nth-child(1),td:nth-child(4),td:nth-child(5){{white-space:nowrap}} button{{font-size:12px;margin-right:6px}}
</style></head><body><main>
<h1>{title} — sesac-shop</h1>
<div class="sub">API-BOM(소스 기준선 + nuclei 관측) ─BOM-Link→ 이미지 SBOM ─→ 부품 취약점 · VEX. {src_line}</div>
<div class="kpis">{kpi_html}</div>
<div class="card"><div class="lg">
<span>■ 앱/서비스/이미지</span><span style="color:#d32f2f">● Shadow</span><span style="color:#43a047">● 문서화 API</span>
<span style="color:#a5d6a7">● 화면</span><span style="color:#c62828">◆ Critical 부품</span><span style="color:#ef6c00">◆ High</span>
<span style="color:#cfd8dc">◆ 데이터 없음</span><span style="color:#b71c1c">★ 실증 취약점</span><span style="color:#ff8f00">★ 확인 대기</span>
· 엔드포인트 상자 앞 숫자 = 위험 점수 · 굵은 테두리 = nuclei live · <b>노드/표 행 클릭 = 연결 경로만 강조</b></div>
{reach_legend}<div><button id="all">전체 보기</button><button id="fit">화면 맞춤</button></div>
<div id="g"></div></div>
<div class="card"><h3 style="margin:4px 0">엔드포인트 위험 순위 (docs/05 §2-1 가중치)</h3><div class="wrap"><table>
<tr><th>위험</th><th title="자산/도달/실증">자산·도달·실증</th><th>엔드포인트</th><th>분류</th><th>관측</th><th>인증</th><th>데이터</th><th>연결 부품</th><th>VEX</th><th>근거</th></tr>{trs}</table></div></div>
<div class="card sub"><b>입력</b><ul>{inp}</ul>{note}</div>
</main><script>
const N=new vis.DataSet({json.dumps(vis_nodes, ensure_ascii=False)}), E=new vis.DataSet({json.dumps(vis_edges, ensure_ascii=False)});
const net=new vis.Network(document.getElementById("g"),{{nodes:N,edges:E}},{{
 physics:false, edges:{{color:{{color:"#9aa4b2",opacity:.55}},smooth:{{type:"cubicBezier",forceDirection:"horizontal"}},width:.7}},
 nodes:{{font:{{size:12,color:getComputedStyle(document.body).color}}}}, interaction:{{hover:true,tooltipDelay:80,zoomView:false,navigationButtons:true}}}});
const out={{}},inn={{}};E.forEach(e=>{{(out[e.from]=out[e.from]||[]).push(e.to);(inn[e.to]=inn[e.to]||[]).push(e.from)}});
function reach(id,adj){{const s=new Set([id]),q=[id];while(q.length){{for(const n of adj[q.pop()]||[])if(!s.has(n)){{s.add(n);q.push(n)}}}}return s}}
const IMG={json.dumps(next(n["id"] for n in g["nodes"] if n["group"] == "image"))};
function focus(id){{const k=new Set([...reach(id,out),...reach(id,inn)]);
 // 엔드포인트는 공통 런타임(이미지 → apache2·libphp → 하위 부품) 위에서 돈다 → 그 경로도 같이 보여줌
 if((N.get(id)||{{}}).shape==="box"&&k.has(IMG)===false&&[...k].some(x=>x.startsWith("svc:")))reach(IMG,out).forEach(x=>k.add(x));
 N.update(N.get().map(n=>({{id:n.id,opacity:k.has(n.id)?1:.12}})));
 E.update(E.get().map(e=>({{id:e.id,hidden:!(k.has(e.from)&&k.has(e.to))}})));}}
function all(){{N.update(N.get().map(n=>({{id:n.id,opacity:1}})));E.update(E.get().map(e=>({{id:e.id,hidden:false}})));}}
net.on("click",p=>p.nodes.length?focus(p.nodes[0]):all());
document.querySelectorAll("tr[data-id]").forEach(tr=>tr.onclick=()=>{{focus(tr.dataset.id);net.selectNodes([tr.dataset.id]);
 net.focus(tr.dataset.id,{{scale:1,animation:true}});document.getElementById("g").scrollIntoView({{behavior:"smooth"}})}});
{reach_js}document.getElementById("all").onclick=all;document.getElementById("fit").onclick=()=>net.fit();
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-bom", default=DEF_APIBOM)
    ap.add_argument("--rules", default=DEF_RULES)
    ap.add_argument("--grype-json", help="grype -o json (있으면 summary 대신 전체 사용)")
    ap.add_argument("--grype-summary", default=DEF_SUMMARY)
    ap.add_argument("--dtrack-url", help="Dependency-Track API 주소 (예 http://192.168.100.137:8081). 키는 환경변수 DT_APIKEY")
    ap.add_argument("--dtrack-project", default="sesac-shop-image")
    ap.add_argument("--dtrack-version", default="2026-10-30", help="'latest' = DT 의 isLatest 버전 (daily ⑦)")
    ap.add_argument("-o", "--out", help="출력 폴더 (기본: graph/sample, DT 모드는 graph/sample_dt, --reach 면 graph/sample_dt_reach)")
    ap.add_argument("--dtrack-snapshot", help="DT 서버 대신 dt_history 스냅샷 폴더 (findings.csv·metrics.json) 또는 'latest'")
    ap.add_argument("--reach", help="도달성 결과 reach.json (문서 14) 또는 'latest'. 주면 근거 종류별 선 + 새 폴더(기존 출력은 그대로)")
    a = ap.parse_args()

    dtrack = None
    if a.dtrack_url:
        key = os.environ.get("DT_APIKEY") or ap.error("--dtrack-url 에는 환경변수 DT_APIKEY 가 필요")
        dtrack = (a.dtrack_url, key, a.dtrack_project, a.dtrack_version)
    if a.dtrack_snapshot:
        if a.dtrack_snapshot == "latest":
            c = [d for d in sorted(glob.glob(os.path.join(APIBOM_DIR, "dt_history", "sesac-shop-image", "*")), key=lambda d: (json.load(open(os.path.join(d, "metrics.json"), encoding="utf-8")).get("lastBomImport") or 0) if os.path.exists(os.path.join(d, "metrics.json")) else 0)
                 if os.path.exists(os.path.join(d, "findings.csv")) and json.load(open(os.path.join(d, "metrics.json"), encoding="utf-8")).get("active") is not False]
            a.dtrack_snapshot = c[-1]
        dtrack = a.dtrack_snapshot
    if a.reach == "latest":
        cands = sorted(glob.glob(os.path.join(APIBOM_DIR, "reach", "results", "*", "reach.json")))
        a.reach = cands[-1] if cands else None
    a.out = a.out or os.path.join(HERE, ("sample_dt_reach" if a.reach else "sample_dt") if dtrack else ("sample_reach" if a.reach else "sample"))
    g = build(a.api_bom, a.rules, a.grype_json, None if a.grype_json else a.grype_summary, dtrack, a.reach)
    os.makedirs(a.out, exist_ok=True)
    w = lambda name, text: open(os.path.join(a.out, name), "w", encoding="utf-8", newline="\n").write(text)
    w("relations.json", json.dumps({k: g[k] for k in ("inputs", "stats", "nodes", "edges")},
                                   ensure_ascii=False, indent=1) + "\n")
    w("vex.cdx.json", json.dumps(vex_doc(g), ensure_ascii=False, indent=2) + "\n")
    with open(os.path.join(a.out, "risk.csv"), "w", encoding="utf-8-sig", newline="") as f:
        cw = csv.DictWriter(f, fieldnames=list(g["rows"][0]), lineterminator="\n")
        cw.writeheader()
        cw.writerows(g["rows"])
    w("dashboard.html", render_html(g))
    s = g["stats"]
    print(f"[graph] 노드 {len(g['nodes'])} · 관계 {len(g['edges'])} · 엔드포인트 {s['endpoints']} "
          f"(live {s['live']}, shadow {s['shadow']}) · 실증 {s['exploitable']} · 대기 {s['triage']} "
          f"· 취약데이터 {s['vuln_meta']['mode']} -> {a.out}", flush=True)
    for r in g["rows"][:5]:
        print(f"  {r['risk']:>2}  {r['endpoint_key']:<32} {r['why']}")


if __name__ == "__main__":
    main()
