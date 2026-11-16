#!/usr/bin/env python3
"""[합치기] 출처 1~4 를 하나의 자산 인벤토리(CycloneDX 1.6)로 묶는다 (문서 11 §2·§12).

    python api-bom/inventory/merge_inventory.py
    → api-bom/inventory/inventory.cdx.json  (최종 산출물, 검증: source_to_baseline.py validate)
      api-bom/inventory/inventory.md        (사람용 보기)

입력 (모두 레포 안):
  출처 1 선언  : api-bom/baseline/baseline.cdx.json (v1, 태그 inventory-v1-code-baseline — 읽기만)
  출처 2 설정  : api-bom/inventory/services.csv (pfSense·compose)
  출처 3 로그  : api-bom/inventory/endpoints_observed.csv
  출처 4 스캔  : api-bom/inventory/scan_endpoints.csv, scan_ports.csv
  (출처 5 확인 = 선언 목록 생존 probe(nuclei) 는 출처 4 와 같은 '관측'으로 보고 v1 BOM 속성으로 남아 있음)
  (출처 6 사람 = decision·owner — 이 도구는 바꾸지 않음. PR 로만, Q6)

구조 (Q1: 서비스 → 엔드포인트 2층):
  services[]  = 호스트:포트 (services.csv)
    └ svc:web-http 아래 그룹(shop-api-v1/v2, shop-web-pages, shop-web-files, shop-waf) → 엔드포인트
"""
import copy
import csv
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPEC = "1.6"
BASE_URL = "http://192.168.0.141:8000"


def read_csv(name):
    with open(os.path.join(HERE, name), encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def props(d):
    return [{"name": k, "value": str(v)} for k, v in d.items() if v not in ("", None)]


def set_props(svc, d):
    keep = [p for p in svc.get("properties", []) if p["name"] not in d]
    svc["properties"] = keep + props(d)


def verdict(declared, observed, kind):
    """문서 11 §2 판정표."""
    if declared == "active":
        return "active" if observed else "dead 후보"
    if declared == "deprecated":
        return "zombie" if observed else "retired"
    if declared in ("review", "exclude"):
        return "shadow" if observed else "review(미관측)"
    if declared == "remove":
        return "제거 대상(아직 있음)" if observed else "제거 확인"
    if observed:
        return "exposure" if kind == "file" else "shadow"
    return "unknown"


def main():
    with open(os.path.join(ROOT, "baseline", "baseline.cdx.json"), encoding="utf-8") as f:
        v1 = json.load(f)
    services_cfg = read_csv("services.csv")
    log = {r["endpoint_key"]: r for r in read_csv("endpoints_observed.csv")}
    scan = {}
    for r in read_csv("scan_endpoints.csv"):  # '/docs/' 와 '/docs' 는 같은 자산 — 발견된 쪽 우선
        k = r["path"].rstrip("/") or "/"
        if k not in scan or r["verdict"].startswith("발견"):
            scan[k] = r
    ports = {r["port"]: r["state"] for r in read_csv("scan_ports.csv")}
    # 출처 6 사람: 판정은 기준선 v2(baseline_v2.csv, approve.py 로 사람이 고름)에서 읽는다. 코드 선언 ≠ 승인
    b2 = {(r["layer"], r["endpoint_key"]): r for r in read_csv("baseline_v2.csv")} if os.path.exists(os.path.join(HERE, "baseline_v2.csv")) else {}
    cand = {(r["layer"], r["key"]): r for r in read_csv("candidates.csv")} if os.path.exists(os.path.join(HERE, "candidates.csv")) else {}

    def human(layer, key):
        """(decision, owner, 표시용 decision)"""
        r = b2.get((layer, key))
        if r:
            return r["decision"], r["owner"], r["decision"]
        c = cand.get((layer, key))
        if c and c["choice"] == "reject":
            return None, "", "추가 안 함(기준선 밖)"
        return None, "", "미등록(선택 대기)"

    # ── 엔드포인트 층: v1 의 그룹·엔드포인트를 복사해 관측 속성을 덧붙인다 ──
    groups = {g["name"]: copy.deepcopy(g) for g in v1["services"]}
    declared_keys = set()
    for g in groups.values():
        for op in g.get("services", []):
            p = {x["name"]: x["value"] for x in op.get("properties", [])}
            declared_keys.add(p["sesac:api:endpoint_key"])

    def observe(op, key, kind, in_code):
        declared, owner, shown = human("endpoint", key)
        method, path = key.split(" ", 1)
        lg = log.get(key)
        sc = scan.get(path) if method == "GET" else None
        sc_hit = sc and sc["verdict"].startswith("발견")
        seen = ["code"] if in_code else []
        if lg and lg.get("seen_in"):
            seen.append("log")
        if sc_hit:
            seen.append("scan")
        v = verdict(declared, bool((lg and lg.get("seen_in")) or sc_hit), kind)
        set_props(op, {
            "sesac:inv:seen_in": "+".join(seen),
            "sesac:inv:verdict": v,
            "sesac:inv:decision": shown,
            "sesac:inv:owner": owner,
            # 같은 요청이 WAF·Apache·app 에 각각 남으므로 더하지 않는다: 앱까지 간 요청 = Apache, 바깥 전체 = WAF
            "sesac:log:requests": lg["apache_n"] if lg and lg.get("seen_in") else "",
            "sesac:log:waf_requests": lg["waf_n"] if lg and lg.get("seen_in") else "",
            "sesac:log:status_codes": lg["status_codes"] if lg else "",
            "sesac:log:first_seen": lg["first_seen_utc"] if lg else "",
            "sesac:log:last_seen": lg["last_seen_utc"] if lg else "",
            "sesac:log:distinct_clients": lg["distinct_clients"] if lg and lg.get("seen_in") else "",
            "sesac:scan:status": sc["status"] if sc else "",
        })
        return v

    for g in groups.values():
        for op in g.get("services", []):
            p = {x["name"]: x["value"] for x in op.get("properties", [])}
            observe(op, p["sesac:api:endpoint_key"], p.get("sesac:api:kind", "api"), True)

    # 선언 밖에서 로그·스캔으로 발견된 것 → 새 엔드포인트 (decision=review: 사람이 판단, Q6)
    def new_op(key, kind, desc, source_note, data=None, auth=None):
        method, path = key.split(" ", 1)
        op = {"bom-ref": f"op:{key}", "name": key, "description": desc,
              "endpoints": [BASE_URL + path], "x-trust-boundary": True, "trustZone": "dmz"}
        if auth is not None:
            op["authenticated"] = auth
        if data:
            op["data"] = [{"flow": "bi-directional", "classification": data}]
        op["properties"] = props({"sesac:api:endpoint_key": key, "sesac:api:method": method, "sesac:api:path": path,
                                  "sesac:api:kind": kind, "sesac:inv:discovered_by": source_note})
        observe(op, key, kind, False)
        return op

    new_groups = {
        "shop-web-files": {"bom-ref": "svc:shop-web-files", "group": "sesac-shop", "name": "shop-web-files",
                           "description": "public/ 아래 정적 파일 (DocumentRoot 노출 범위, 문서 11 C1)",
                           "endpoints": [BASE_URL + "/docs"], "x-trust-boundary": True, "trustZone": "dmz",
                           "services": []},
        "shop-waf": {"bom-ref": "svc:shop-waf", "group": "sesac-shop", "name": "shop-waf",
                     "description": "WAF(ModSecurity CRS 컨테이너)가 직접 응답하는 경로 — 앱 로그에 안 남음",
                     "endpoints": [BASE_URL + "/healthz"], "x-trust-boundary": True, "trustZone": "dmz",
                     "services": []},
    }
    added = []
    for key, r in log.items():
        if key in declared_keys or r["verdict"].startswith("폴더"):
            continue
        kind = r["kind"]
        if kind == "page":
            op = new_op(key, kind, "폼 전송 — 코드 추출기가 GET 만 뽑아 누락 (문서 11 L3)", "log",
                        data="PII" if "login" in key or "signup" in key else None, auth=False)
            groups["shop-web-pages"]["services"].append(op)
        elif kind == "file":
            op = new_op(key, kind, "공개 폴더의 파일 (문서 11 C1·L4)", "config+log")
            new_groups["shop-web-files"]["services"].append(op)
        else:
            op = new_op(key, kind, "선언 밖 API (로그 관측)", "log")
            groups.setdefault("shop-api-unknown", {"bom-ref": "svc:shop-api-unknown", "name": "shop-api-unknown",
                                                   "services": []})["services"].append(op)
        added.append(key)
    for path, r in scan.items():
        key = f"GET {path}"
        if not r["verdict"].startswith("발견") or key in declared_keys or key in added:
            continue
        if path == "/healthz":
            op = new_op(key, "file", "WAF 헬스체크 (블랙박스로만 발견, 문서 11 B1)", "scan", auth=False)
            new_groups["shop-waf"]["services"].append(op)
        else:
            op = new_op(key, "file", "블랙박스 발견", "scan")
            new_groups["shop-web-files"]["services"].append(op)
        added.append(key)
    groups.update({k: v for k, v in new_groups.items() if v["services"]})

    # ── 서비스 층 (services.csv + 스캔 포트) ──
    top = []
    for r in services_cfg:
        port_state = ports.get(r["exposed_as"].rsplit(":", 1)[-1]) if r["exposure"] == "wan" else None
        seen = [r.get("seen_in") or "config"] + (["scan"] if port_state == "open" else [])  # 설정 캡처 밖 출처(예: topology) 는 seen_in 그대로
        proto = {"22": "ssh", "443": "https", "80": "http", "3306": "mysql", "3000": "http", "8080": "http", "3001": "http"}.get(r["port"], "tcp")
        svc = {"bom-ref": f"svc:{r['service_id']}", "name": r["service_id"], "description": r["description"],
               "endpoints": [f"{proto}://{r['exposed_as'] or r['host'] + ':' + r['port']}".replace(" (라우팅 시)", "")],
               "x-trust-boundary": r["exposure"].startswith("wan"), "trustZone": r["zone"].lower()}
        mismatch = "설정상 열림인데 스캔 응답 없음" if r["exposure"] == "wan" and port_state and port_state != "open" else ""
        svc["properties"] = props({
            "sesac:svc:host": r["host"], "sesac:svc:port": r["port"], "sesac:svc:proto": r["proto"],
            "sesac:svc:exposure": r["exposure"], "sesac:svc:source_restriction": r["source_restriction"],
            "sesac:inv:seen_in": "+".join(seen), "sesac:inv:decision": human("service", r["service_id"])[2],
            "sesac:inv:owner": human("service", r["service_id"])[1],
            "sesac:scan:port_state": port_state or "", "sesac:inv:mismatch": mismatch,
            "sesac:inv:evidence": r["evidence"], "sesac:inv:note": r["note"]})
        if r["service_id"] == "web-http":
            svc["services"] = list(groups.values())
        top.append(svc)
    known_ports = {r["exposed_as"].rsplit(":", 1)[-1] for r in services_cfg if r["exposure"] == "wan"}
    for port, state in sorted(ports.items(), key=lambda x: int(x[0])):
        if state == "open" and port not in known_ports:
            top.append({"bom-ref": f"svc:wan-{port}", "name": f"wan-{port}",
                        "description": "스캔으로만 발견된 열린 포트 (설정 목록에 없음)"
                                       + (" — 응답 Server: nginx, 301 → https (pfSense 관리 화면 HTTP 로 추정)" if port == "80" else ""),
                        "endpoints": [f"tcp://192.168.0.141:{port}"], "x-trust-boundary": True, "trustZone": "wan",
                        "properties": props({"sesac:svc:port": port, "sesac:svc:exposure": "wan",
                                             "sesac:inv:seen_in": "scan", "sesac:inv:decision": human("service", f"wan-{port}")[2],
                                             "sesac:scan:port_state": state})})

    # ── 문서 ──
    def walk(svcs):
        for s in svcs:
            yield s
            yield from walk(s.get("services", []))
    allsvc = list(walk(top))
    vc = {}
    for s in allsvc:
        p = {x["name"]: x["value"] for x in s.get("properties", [])}
        if "sesac:api:endpoint_key" in p:
            vc[p["sesac:inv:verdict"]] = vc.get(p["sesac:inv:verdict"], 0) + 1
    inputs = ["baseline/baseline.cdx.json", "inventory/services.csv", "inventory/endpoints_observed.csv",
              "inventory/scan_endpoints.csv", "inventory/scan_ports.csv", "inventory/baseline_v2.csv"]
    digest = hashlib.sha256(b"".join(open(os.path.join(ROOT, p), "rb").read() for p in inputs)).hexdigest()
    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": SPEC,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "sesac-inventory:" + digest)),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lifecycles": [{"phase": "operations"}],
            "tools": {"components": [{"type": "application", "name": "merge_inventory.py", "version": "2.0",
                                      "group": "sesac-nobreak-team-one"}]},
            "component": {"type": "platform", "bom-ref": "platform:sesac-lab", "name": "sesac-lab",
                          "description": "팀 실습망 (pfSense WAN 192.168.0.141 / LAN / DMZ / SIEM)"},
            "properties": props({"sesac:inv:version": "v2", "sesac:inv:method": "docs/11_자산인벤토리_방법론.md",
                                 "sesac:inv:inputs-sha256": digest,
                                 "sesac:inv:baseline": "inventory/baseline_v2.csv (사람 판정, approve.py)",
                                 "sesac:inv:v1-baseline": v1["serialNumber"],
                                 **{f"sesac:inv:count:{k}": v for k, v in sorted(vc.items())}}),
        },
        "services": top,
        "dependencies": [{"ref": "platform:sesac-lab", "dependsOn": [s["bom-ref"] for s in top]},
                         {"ref": "svc:web-http", "dependsOn": ["svc:db-mysql"]}],
    }
    with open(os.path.join(HERE, "inventory.cdx.json"), "w", encoding="utf-8", newline="") as f:
        json.dump(bom, f, ensure_ascii=False, indent=2)

    # ── 사람용 보기 ──
    md = ["# v2 자산 인벤토리 (CycloneDX 1.6: `inventory.cdx.json`)", "",
          f"- 생성: `python api-bom/inventory/merge_inventory.py` · 입력 해시 `{digest[:16]}…`",
          f"- 서비스 {len(top)}개 · 엔드포인트 {sum(vc.values())}개 · 판정 " + ", ".join(f"{k} {v}" for k, v in sorted(vc.items())),
          "", "## 서비스 층", "", "| 서비스 | 구역 | 노출 | 출발지 제한 | 출처 | 스캔 | 사람 판정 | 비고 |", "|---|---|---|---|---|---|---|---|"]
    for s in top:
        p = {x["name"]: x["value"] for x in s.get("properties", [])}
        md.append(f"| {s['name']} `{s['endpoints'][0]}` | {s['trustZone']} | {p.get('sesac:svc:exposure', '')} | "
                  f"{p.get('sesac:svc:source_restriction', '')} | {p.get('sesac:inv:seen_in', '')} | "
                  f"{p.get('sesac:scan:port_state', '')} | {p.get('sesac:inv:decision', '')} | "
                  f"{p.get('sesac:inv:mismatch', '') or p.get('sesac:inv:note', '') or s.get('description', '')} |")
    md += ["", "## 엔드포인트 층 (svc:web-http 아래)", "",
           "| 판정 | 엔드포인트 | 그룹 | 출처 | 앱 도달 요청(Apache) | 마지막 관측 | 스캔 | 사람 판정 | owner |", "|---|---|---|---|---|---|---|---|---|"]
    order = ["zombie", "제거 대상(아직 있음)", "shadow", "exposure", "dead 후보", "review(미관측)", "active"]
    ops = []
    for g in groups.values():
        for op in g.get("services", []):
            p = {x["name"]: x["value"] for x in op.get("properties", [])}
            ops.append((p, g["name"]))
    for p, g in sorted(ops, key=lambda x: (order.index(x[0]["sesac:inv:verdict"]) if x[0]["sesac:inv:verdict"] in order else 9,
                                          -int(x[0].get("sesac:log:requests") or 0))):
        md.append(f"| {p['sesac:inv:verdict']} | `{p['sesac:api:endpoint_key']}` | {g} | {p['sesac:inv:seen_in']} | "
                  f"{p.get('sesac:log:requests', '')} | {p.get('sesac:log:last_seen', '')[:10]} | "
                  f"{p.get('sesac:scan:status', '')} | {p['sesac:inv:decision']} | {p.get('sesac:inv:owner', '')} |")
    with open(os.path.join(HERE, "inventory.md"), "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md[:4]))


if __name__ == "__main__":
    main()
