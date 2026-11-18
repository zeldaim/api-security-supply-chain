#!/usr/bin/env python3
"""명세 밖 호출 우선순위(offspec_triage) → Wazuh 경보 레벨.

기존 Shadow API 룰(gen_shadow_rules.py / gen_shadow_rules_v2.py)은 명세 밖 호출을 응답 코드만 보고
L1 정찰(404·405)=5 · L2 발견(401·403)=8 · L3 악용(2xx)=12 · L3-E 서버 오류(5xx)=10 으로 경보한다.
이 스크립트는 그 룰을 고치지 않고, 단계 룰 아래에 엔드포인트별 하위 룰을 붙여 레벨만 다시 정한다.

  python offspec_rules.py --triage offspec_triage.csv --meta rules_meta.json --out 0916-offspec_priority.xml \
                          [--base-id 100600] [--cases cases.jsonl]
  python offspec_rules.py check --rules 0916-offspec_priority.xml --meta rules_meta.json --cases cases.jsonl

  --meta  기존 룰을 만들 때 나온 meta.json (rule_ids · status_option 또는 log_format 을 읽는다)

레벨 = 단계 레벨 + 우선순위 보정 (LEVELS 표). '중간'은 기존 레벨 그대로라 기존 동작과 같다.
하위 룰이 이벤트를 가져가면 기존 빈도 룰(if_matched_sid 단계 ID)이 그 이벤트를 못 센다 → 보완 빈도 룰을 같이 만든다.
표준 라이브러리만 쓴다.
"""
import argparse
import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

# 단계 키 → (기존 레벨, 응답 코드 정규식, 기존 그룹)  — gen_shadow_rules.py STAGES 와 같은 값
STAGES = {
    "L1": (5, r"^40[45]$", "shadow_api_recon"),
    "L2": (8, r"^40[13]$", "shadow_api_discovery"),
    "L3": (12, r"^2\d\d$", "shadow_api_exploit"),
    "L3E": (10, r"^5\d\d$", "shadow_api_error"),
}
# 우선순위 → 단계별 레벨. 정보는 기록만(3), 낮음 −3(최소 3), 중간 = 기존, 높음 +2(최대 15)
GRADES = {"정보": "info", "낮음": "low", "중간": "medium", "높음": "high"}


def level_for(grade, stage):
    base = STAGES[stage][0]
    return {"정보": 3, "낮음": max(3, base - 3), "중간": base, "높음": min(15, base + 2)}[grade]


# 빈도 보완: 기존 F1(L1 20회/30초) · F2(L3 10회/60초) 와 같은 문턱을 하위 룰 그룹에 건다
BURSTS = [("F1", "L1", 10, "offspec_recon_triaged", "shadow_api_recon_burst", "F1 자동화 정찰", "T1595.003"),
          ("F2", "L3", 14, "offspec_exploit_triaged", "shadow_api_mass_exfil", "F2 대량 유출", "T1119")]
PARAM_RE = re.compile(r"\{[^/{}]+\}")


def x(s):
    return escape(s, {'"': "&quot;"})


def path_regex(template):
    """/api/v1/users/{id} → ^/api/v1/users/[^/?]+/*(?:\\?.*)?$  (팀 생성기 template_to_regex 와 같은 규칙)"""
    parts = PARAM_RE.split(template)
    out = "[^/?]+".join(re.escape(p) for p in parts)
    return "^" + out.rstrip("/") + r"/*(?:\?.*)?$"


def load_meta(path):
    meta = json.load(open(path, encoding="utf-8"))
    ids = meta["rule_ids"]
    fmt = meta.get("log_format", "applog")
    return {"stage_ids": {k: ids[k] for k in STAGES}, "burst_ids": {k: ids.get(k) for k in ("F1", "F2")},
            "fmt": fmt, "status_option": meta.get("status_option", "static")}


def load_triage(path):
    rows = []
    for r in csv.DictReader(open(path, encoding="utf-8")):
        grade = r["grade"].strip()
        if grade not in GRADES:
            continue
        method, _, template = r["endpoint_key"].partition(" ")
        rows.append({"grade": grade, "method": method.upper(), "template": template, "class": r["class"],
                     "decision": r.get("decision", ""), "owner": r.get("owner", "")})
    order = {"높음": 0, "중간": 1, "낮음": 2, "정보": 3}
    rows.sort(key=lambda r: (order[r["grade"]], r["method"], r["template"]))
    return rows


def build(rows, m, base_id, source):
    fmt = m["fmt"]
    f_method, f_path, f_ip = ("protocol", "url", "srcip") if fmt == "accesslog" else ("method", "path", "client_ip")

    def cond(name, rx):
        if fmt == "accesslog":
            return f'    <{name} type="pcre2">{x(rx)}</{name}>'
        return f'    <field name="{name}" type="pcre2">{x(rx)}</field>'

    n_rules = len(rows) * len(STAGES) + len(BURSTS)
    if n_rules > 400:
        sys.exit(f"하위 룰이 {n_rules}개라 너무 많습니다. 판정 CSV 를 먼저 줄이세요(낮음 제외 등).")
    L = ["<!--",
         "  명세 밖 호출 우선순위 → 경보 레벨 (자동 생성: standardize/policy/offspec_rules.py)",
         f"  판정 원본: {source}",
         f"  로그 형식: {fmt} · 붙는 단계 룰: " + ", ".join(f"{k}={v}" for k, v in m["stage_ids"].items()),
         "  레벨: 정보=3 · 낮음=기존-3(최소 3) · 중간=기존 · 높음=기존+2(최대 15)",
         "  판정 CSV 에 없는 명세 밖 호출은 기존 단계 룰 레벨 그대로 남는다.",
         "-->", '<group name="shadow_api,offspec_priority,">', ""]
    rid = base_id
    rule_map = []
    for r in rows:
        L.append(f"  <!-- {r['grade']} · {r['method']} {r['template']} · {r['class']} · 승인 {r['decision'] or '-'} · 소유자 {r['owner'] or '없음'} -->")
        for stage, (base_lv, _st, group) in STAGES.items():
            lv = level_for(r["grade"], stage)
            extra = {"L1": "offspec_recon_triaged,", "L3": "offspec_exploit_triaged,"}.get(stage, "")
            L += [f'  <rule id="{rid}" level="{lv}">', f'    <if_sid>{m["stage_ids"][stage]}</if_sid>',
                  cond(f_method, f"^{r['method']}$"), cond(f_path, path_regex(r["template"])),
                  f"    <description>[Shadow API {stage} · 우선순위 {r['grade']}] $({f_ip}) $({f_method}) $({f_path})</description>",
                  f"    <group>{group},offspec_{GRADES[r['grade']]},{extra}</group>", "  </rule>"]
            rule_map.append({"id": rid, "stage": stage, "grade": r["grade"], "method": r["method"],
                             "template": r["template"], "level": lv})
            rid += 1
        L.append("")
    L.append("  <!-- 빈도 보완: 위 하위 룰로 넘어간 이벤트는 기존 F1·F2(if_matched_sid)가 세지 못한다 -->")
    same = "    <same_srcip />" if fmt == "accesslog" else "    <same_field>client_ip</same_field>"
    for key, stage, lv, grp, group, label, mitre in BURSTS:
        n, t = (20, 30) if key == "F1" else (10, 60)
        L += [f'  <rule id="{rid}" level="{lv}" frequency="{n}" timeframe="{t}" ignore="60">',
              f"    <if_matched_group>{grp}</if_matched_group>", same,
              f"    <description>[Shadow API {label} · 우선순위 반영 경로] $({f_ip}) {t}초 안에 {n}회 이상</description>",
              f"    <mitre><id>{mitre}</id></mitre>", f"    <group>{group},offspec_priority_burst,</group>", "  </rule>"]
        rule_map.append({"id": rid, "stage": key, "grade": "", "method": "", "template": "", "level": lv})
        rid += 1
    L += ["", "</group>"]
    return "\n".join(L) + "\n", rule_map


def make_cases(rows):
    """판정 CSV 의 엔드포인트마다 단계별 1건 + 판정 CSV 에 없는 명세 밖 경로(기존 레벨 유지) 대조군 + 빈도 보완 룰.

    단건 케이스는 출발지 IP 를 모두 다르게 둔다 — 같은 IP 로 넣으면 logtest 세션 안에서 빈도 룰이 누적돼 끼어든다.
    """
    seq = iter(range(1, 60000))

    def ev(method, path, status, expect_stage, expect_grade, note, ip=None, expect_level=None):
        n = next(seq)
        c = {"note": note, "expect_stage": expect_stage, "expect_grade": expect_grade,
             "log": {"timestamp": "2026-11-18T10:00:00+09:00", "client_ip": ip or f"10.80.{n // 250}.{n % 250 + 1}",
                     "method": method, "path": path, "status": status, "response_bytes": 0, "user_agent": "offspec-rules-case"}}
        if expect_level is not None:
            c["expect_level"] = expect_level
        return c
    cases = []
    for r in rows:
        p = PARAM_RE.sub("7", r["template"])
        for stage, status in (("L1", 404), ("L2", 401), ("L3", 200), ("L3E", 500)):
            cases.append(ev(r["method"], p, status, stage, r["grade"], f"{r['grade']} {r['method']} {r['template']} → {status}"))
        cases.append(ev(r["method"], p + "?x=1", 200, "L3", r["grade"], f"{r['grade']} 쿼리스트링 붙음"))
    pre = "/" + "/".join(rows[0]["template"].strip("/").split("/")[:1]) if rows else "/api"
    for status, stage in ((404, "L1"), (200, "L3")):
        cases.append(ev("GET", pre + "/zz-not-in-triage", status, stage, "", f"판정 CSV 밖 → 기존 레벨 ({status})"))
    if rows:                                                     # 빈도 보완 F2: 같은 IP 가 2xx 10회 → 10번째에 레벨 14
        r = rows[0]
        p = PARAM_RE.sub("7", r["template"])
        for i in range(1, 11):
            cases.append(ev(r["method"], p, 200, "L3", r["grade"], f"빈도 F2 보완 {i}/10", ip="10.99.0.1",
                            expect_level=14 if i == 10 else None))
    return cases


def expected_level(case):
    if "expect_level" in case:
        return case["expect_level"]
    st = case["expect_stage"]
    return STAGES[st][0] if not case["expect_grade"] else level_for(case["expect_grade"], st)


def check(rules_xml, m, cases):
    """XML 자체를 읽어서 판정 — 생성 로직과 따로 XML 문자열을 해석한다 (단계 룰은 응답 코드로 정해진다고 가정)."""
    root = ET.fromstring(rules_xml.split("-->", 1)[1])
    kids = {}
    for rule in root.iter("rule"):
        sid = rule.findtext("if_sid")
        if not sid:
            continue
        conds = {}
        for el in rule:
            if el.tag == "field":
                conds[el.get("name")] = re.compile(el.text)
            elif el.tag in ("protocol", "url"):
                conds[{"protocol": "method", "url": "path"}[el.tag]] = re.compile(el.text)
        conds = {{"method": "method", "path": "path"}.get(k, k): v for k, v in conds.items()}
        kids.setdefault(int(sid), []).append((int(rule.get("id")), int(rule.get("level")), conds))
    fails = 0
    cases = [c for c in cases if "expect_level" not in c]       # 빈도 케이스는 상태가 필요해 logtest 로만 본다
    for c in cases:
        log = c["log"]
        stage = next(k for k, (_l, st, _g) in STAGES.items() if re.search(st, str(log["status"])))
        got = STAGES[stage][0]
        for _rid, lv, conds in kids.get(m["stage_ids"][stage], []):
            if conds["method"].search(log["method"]) and conds["path"].search(log["path"]):
                got = lv
                break
        want = expected_level(c)
        if got != want:
            fails += 1
            print(f"FAIL 기대 {want} 결과 {got}  {log['method']} {log['path']} {log['status']}  ({c['note']})")
    print(f"{len(cases) - fails}/{len(cases)} 일치 (XML 해석 재현)")
    return fails


def replay(rules_xml, meta_path, gen_path, logs):
    """실제 로그를 기존 룰 로직(팀 생성기 Classifier) + 이 룰로 다시 판정해 레벨 분포를 비교한다. 빈도 룰은 빼고 단건만."""
    import importlib.util
    from collections import Counter
    spec = importlib.util.spec_from_file_location("gen_v1", gen_path)
    G = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(G)
    meta = json.load(open(meta_path, encoding="utf-8"))
    meta["bursts"] = {k: tuple(v) for k, v in meta["bursts"].items()}
    clf = G.Classifier(meta)
    m = load_meta(meta_path)
    root = ET.fromstring(rules_xml.split("-->", 1)[1])
    kids = {}
    for rule in root.iter("rule"):
        sid = rule.findtext("if_sid")
        if sid:
            c = {el.get("name"): re.compile(el.text) for el in rule if el.tag == "field"}
            grp = next(g for g in ("high", "medium", "low", "info") if f"offspec_{g}" in rule.findtext("group"))
            kids.setdefault(int(sid), []).append((int(rule.get("level")), c, grp))
    before, after, moved = Counter(), Counter(), Counter()
    for path in logs:
        for line in open(path, encoding="utf-8", errors="replace"):
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            stage, lv = clf.classify(ev)
            if stage is None:
                continue
            before[lv] += 1
            new = lv
            for klv, c, grp in kids.get(m["stage_ids"].get(stage, -1), []):
                if c["method"].search(str(ev.get("method", ""))) and c["path"].search(str(ev.get("path", ""))):
                    new = klv
                    moved[(stage, grp, lv, klv)] += 1
                    break
            after[new] += 1
    print("레벨 | 기존 | 우선순위 반영")
    for lv in sorted(set(before) | set(after), reverse=True):
        print(f"{lv:>4} | {before[lv]:>7} | {after[lv]:>7}")
    print(f"합계 | {sum(before.values()):>7} | {sum(after.values()):>7}")
    print("\n바뀐 이벤트 (단계 · 우선순위 · 기존→새 레벨 · 건수)")
    for (st, g, a, b), n in sorted(moved.items(), key=lambda kv: -kv[1]):
        print(f"  {st:<4} {g:<6} {a:>2}→{b:<2} {n}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "replay":
        p = argparse.ArgumentParser()
        p.add_argument("cmd")
        p.add_argument("--rules", required=True)
        p.add_argument("--meta", required=True)
        p.add_argument("--gen", default="automate/rules/gen_shadow_rules.py", help="기존 룰 생성기 (Classifier 를 빌려 쓴다)")
        p.add_argument("logs", nargs="+", help="app.log (JSON 줄)")
        a = p.parse_args()
        return replay(open(a.rules, encoding="utf-8").read(), a.meta, a.gen, a.logs)
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        p = argparse.ArgumentParser()
        p.add_argument("cmd")
        p.add_argument("--rules", required=True)
        p.add_argument("--meta", required=True)
        p.add_argument("--cases", required=True)
        a = p.parse_args()
        cases = [json.loads(l) for l in open(a.cases, encoding="utf-8") if l.strip()]
        sys.exit(1 if check(open(a.rules, encoding="utf-8").read(), load_meta(a.meta), cases) else 0)
    p = argparse.ArgumentParser(description="offspec_triage.csv → Wazuh 우선순위 레벨 룰")
    p.add_argument("--triage", required=True)
    p.add_argument("--meta", required=True, help="기존 Shadow API 룰의 meta.json")
    p.add_argument("--out", required=True)
    p.add_argument("--base-id", type=int, default=100600)
    p.add_argument("--cases", default="", help="시험 케이스 JSONL 출력 (check · logtest 입력)")
    p.add_argument("--map", default="", help="룰 ID 표 CSV 출력")
    a = p.parse_args()
    m = load_meta(a.meta)
    rows = load_triage(a.triage)
    xml, rule_map = build(rows, m, a.base_id, a.triage.replace("\\", "/").split("/")[-1])
    open(a.out, "w", encoding="utf-8", newline="\n").write(xml)
    cnt = {g: sum(1 for r in rows if r["grade"] == g) for g in GRADES}
    print(f"판정 {len(rows)}개 (" + " · ".join(f"{g} {n}" for g, n in cnt.items() if n) + f") → 룰 {len(rule_map)}개 "
          f"(ID {a.base_id}~{a.base_id + len(rule_map) - 1}) → {a.out}")
    if a.cases:
        with open(a.cases, "w", encoding="utf-8", newline="\n") as f:
            for c in make_cases(rows):
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
        print(f"  시험 케이스 → {a.cases}")
    if a.map:
        with open(a.map, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["id", "stage", "grade", "method", "template", "level"], lineterminator="\n")
            w.writeheader()
            w.writerows(rule_map)


if __name__ == "__main__":
    main()
