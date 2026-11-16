#!/usr/bin/env python3
"""인벤토리에서 '기준선에 없는 새 자산'만 뽑아 추가 후보(candidates.csv)를 만든다.
무엇을 기준선에 넣을지는 사람이 approve.py 로 고른다 (문서 11 §13).

    python api-bom/inventory/make_baseline_v2.py
    → api-bom/inventory/candidates.csv   (추가 후보 + 사람의 선택 기록)
      api-bom/inventory/baseline_v2.csv  (처음 한 번: v1 baseline.csv 28개로 시작)

- 이미 고른 후보의 선택(choice·chosen_*)은 덮어쓰지 않는다. 새 후보만 추가.
"""
import csv
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CAND = os.path.join(HERE, "candidates.csv")
BASE2 = os.path.join(HERE, "baseline_v2.csv")
CAND_FIELDS = ["layer", "key", "group", "found_by", "verdict", "evidence", "suggested",
               "choice", "chosen_by", "chosen_at", "reason"]
BASE2_FIELDS = ["layer", "endpoint_key", "kind", "group", "decision", "owner", "source", "added_by", "added_at", "note"]


def p(svc):
    return {x["name"]: x["value"] for x in svc.get("properties", [])}


def main():
    # 1) baseline_v2 시작점 = v1 (없을 때만)
    if not os.path.exists(BASE2):
        with open(os.path.join(ROOT, "baseline", "baseline.csv"), encoding="utf-8-sig", newline="") as f:
            v1 = list(csv.DictReader(f))
        with open(BASE2, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=BASE2_FIELDS, lineterminator="\n")
            w.writeheader()
            for r in v1:
                w.writerow({"layer": "endpoint", "endpoint_key": r["endpoint_key"], "kind": r["kind"], "group": "",
                            "decision": r["decision"], "owner": r["owner"], "source": "v1 (코드 추출)",
                            "added_by": "", "added_at": "", "note": r["note"]})
    with open(BASE2, encoding="utf-8-sig", newline="") as f:
        in_base = {(r["layer"], r["endpoint_key"]) for r in csv.DictReader(f)}

    # 2) 인벤토리 중 기준선에 없는 것 = 후보
    with open(os.path.join(HERE, "inventory.cdx.json"), encoding="utf-8") as f:
        bom = json.load(f)
    rows = []
    for svc in bom["services"]:
        q = p(svc)
        wan = q.get("sesac:svc:exposure", "").startswith("wan")
        if ("service", svc["name"]) not in in_base:
            note = q.get("sesac:inv:mismatch") or q.get("sesac:inv:note") or svc.get("description", "")
            rows.append({"layer": "service", "key": svc["name"], "group": svc["trustZone"],
                         "found_by": q.get("sesac:inv:seen_in", ""),
                         "verdict": "WAN 노출" if wan else "내부",
                         "evidence": f"{svc['endpoints'][0]} · 출발지 제한 {q.get('sesac:svc:source_restriction', '-')} · {note}",
                         "suggested": "필요하면 추가(출발지 제한 권장), 필요 없으면 추가 안 함 + 포워딩·규칙 삭제"
                         if wan else "추가 — 내부 전용 서비스"})
        for grp in svc.get("services", []):
            for op in grp.get("services", []):
                q = p(op)
                key = q["sesac:api:endpoint_key"]
                if ("endpoint", key) in in_base:
                    continue
                ev = []
                if q.get("sesac:log:requests"):
                    ev.append(f"앱 도달 {q['sesac:log:requests']}건(마지막 {q.get('sesac:log:last_seen', '')[:10]}, 출발지 {q.get('sesac:log:distinct_clients', '')}곳)")
                if q.get("sesac:scan:status"):
                    ev.append(f"스캔 응답 {q['sesac:scan:status']}")
                ev.append(op.get("description", ""))
                rows.append({"layer": "endpoint", "key": key, "group": grp["name"],
                             "found_by": q["sesac:inv:seen_in"], "verdict": q["sesac:inv:verdict"],
                             "evidence": " · ".join(e for e in ev if e),
                             "suggested": {"shadow": "쓸 거면 추가(active), 없앨 거면 추가 안 함(코드에서 제거)",
                                           "exposure": "의도된 공개면 추가, 아니면 추가 안 함(파일·경로 차단)"}
                             .get(q["sesac:inv:verdict"], "검토")})

    old = {}
    if os.path.exists(CAND):
        with open(CAND, encoding="utf-8-sig", newline="") as f:
            old = {(r["layer"], r["key"]): r for r in csv.DictReader(f)}
    for r in rows:
        o = old.pop((r["layer"], r["key"]), None)
        for k in ("choice", "chosen_by", "chosen_at", "reason"):
            r[k] = o[k] if o else ""
    rows += list(old.values())  # 이미 고른 것(기준선에 들어간 것 포함)은 기록으로 남긴다
    with open(CAND, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CAND_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"candidates.csv: 후보 {len(rows)}개 (선택 대기 {sum(1 for r in rows if not r['choice'])})")


if __name__ == "__main__":
    main()
