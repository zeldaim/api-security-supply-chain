#!/usr/bin/env python3
"""OpenAPI 명세 → Wazuh Shadow API 룰 v2.1 — v2(`../v2_portable/gen_shadow_rules_v2.py`)를 고치지 않고 바꿔 끼운다.

세 번째 앱(VAmPI, vampi_run_2026-11-18)에서 막힌 세 곳:
  1) 검사 범위   'api' 조각이 없는 명세 → v2 는 첫 조각들만, v2.1 은 "루트(/)와 정적 파일을 뺀 전부"
  2) 파라미터    명세에 형식이 있으면 그 형식만 허용 (integer → \\d+, uuid → UUID) — /orders/export 같은 흡수를 막는다
  3) 시험 케이스 "명세 경로 + 없는 메서드" 케이스를 검사 범위 안의 경로로 고른다 (루트 / 를 고르면 기대값이 틀렸다)

'api' 조각이 있고 파라미터 형식이 없는 명세에서는 v2 와 같은 룰이 나온다. 사용법은 v2 와 같다:
  python gen_shadow_rules_v2_1.py build --spec <명세> --out rules.xml --meta meta.json --cases cases.jsonl [--log-format accesslog]
  python gen_shadow_rules_v2_1.py test  --meta meta.json --cases cases.jsonl
"""
import copy
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(HERE, "..", "portable-workflow")
_s = importlib.util.spec_from_file_location("gen_v2", os.path.join(V2, "gen_shadow_rules_v2.py"))
R = importlib.util.module_from_spec(_s)
_s.loader.exec_module(R)
G = R.G                                                   # 팀 생성기 (v2 가 이미 불러 둔 것)

STATIC_EXT = r"css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|html?|txt"
ALL_BUT_STATIC = r"^/(?!(?:\?|$))(?![^?]*\.(?:" + STATIC_EXT + r")(?:\?|$))"
UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
SAMPLE = {r"\d+": "7", UUID: "0f0e0d0c-0b0a-4908-8706-050403020100"}
FORMATS = {}                                              # 경로 틀(접두어 포함) → {파라미터: 정규식}
STATE = {"scope_arg": ""}
_v2_derive_scope, _v2_make_cases, _v2_cmd_build = R.derive_scope, R.make_cases, R.cmd_build
_g_template_to_regex = G.template_to_regex


def has_api_segment(templates):
    return any(s.lower() == "api" for t in templates for s in t.split("/"))


def derive_scope(templates):
    return _v2_derive_scope(templates) if has_api_segment(templates) else ALL_BUT_STATIC


def template_to_regex(template):
    fm = FORMATS.get(template)
    if not fm:
        return _g_template_to_regex(template)
    out, pos = [], 0
    for m in G.PARAM_RE.finditer(template):
        out.append(re.escape(template[pos:m.start()]))
        out.append(fm.get(m.group(0)[1:-1], r"[^/?]+"))
        pos = m.end()
    out.append(re.escape(template[pos:]))
    return "".join(out)


def sample_path(template, value="7"):
    fm = FORMATS.get(template, {})
    return G.PARAM_RE.sub(lambda m: SAMPLE.get(fm.get(m.group(0)[1:-1]), value), template)


def load_formats(spec):
    prefix = G.base_path(spec)
    for p, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        params = list(item.get("parameters") or [])
        for op in item.values():
            if isinstance(op, dict):
                params += op.get("parameters") or []
        fm = {}
        for pr in params:
            if isinstance(pr, dict) and pr.get("in") == "path":
                sc = pr.get("schema") or pr
                if sc.get("type") == "integer":
                    fm[pr["name"]] = r"\d+"
                elif sc.get("format") == "uuid":
                    fm[pr["name"]] = UUID
        if fm:
            FORMATS[prefix + p] = fm


def make_cases(ops, prefixes):
    templates = [o["template"] for lst in ops.values() for o in lst if o["source"] == "openapi"]
    scope_re = STATE["scope_arg"] or derive_scope(templates)
    rx = re.compile(scope_re)
    ordered = {m: sorted(lst, key=lambda o: not rx.search(G.sample_path(o["template"]))) for m, lst in ops.items()}
    cases = _v2_make_cases(ordered, prefixes)
    if scope_re == ALL_BUT_STATIC:
        for c in cases:
            if c["note"] == "범위 밖 404":                 # v2 는 /zz-not-api 를 범위 밖으로 봤다 — v2.1 에서는 범위 안
                c["note"], c["expect"] = "범위 안 새 첫 조각 (api 접두어 없는 명세는 전부 검사)", "L1"
        base = copy.deepcopy(cases[0])
        for path, st, note, exp in (("/admin", 404, "새 첫 조각 탐색 /admin", "L1"),
                                    ("/swagger.json", 404, "명세 문서 탐색 (.json 은 정적으로 보지 않음)", "L1"),
                                    ("/static/app.js", 200, "범위 밖 (정적 확장자)", None)):
            c = copy.deepcopy(base)
            c["log"].update({"method": "GET", "path": path, "status": st})
            c["note"], c["expect"] = note, exp
            cases.append(c)
    for m, lst in ops.items():                            # 형식이 있는 파라미터: 형식에 안 맞는 값은 명세 밖
        for o in lst:
            fm = FORMATS.get(o["template"])
            if fm and o["source"] == "openapi":
                c = copy.deepcopy(cases[0])
                c["log"].update({"method": m, "path": G.PARAM_RE.sub("export", o["template"]), "status": 404})
                c["note"], c["expect"] = f"형식 있는 파라미터에 형식 밖 값 ({o['template']})", "L1"
                cases.append(c)
                break
    return cases


def cmd_build(a):
    import yaml
    STATE["scope_arg"] = a.scope
    load_formats(yaml.safe_load(G.read_source(a.spec)))
    return _v2_cmd_build(a)


def cmd_test(a):
    import json
    meta = json.load(open(a.meta, encoding="utf-8"))
    FORMATS.update(meta.get("param_formats", {}))
    return R.cmd_test(a)


_v2_build_meta_writer = None
R.derive_scope, R.make_cases, R.cmd_build = derive_scope, make_cases, cmd_build
G.template_to_regex, G.sample_path = template_to_regex, sample_path


def _patch_meta_writer():
    """meta.json 에 파라미터 형식을 남긴다 — test 단계(다른 프로세스)가 같은 정규식으로 재현하도록."""
    import json
    from pathlib import Path
    orig = Path.write_text

    def write_text(self, data, *args, **kw):
        if self.suffix == ".json" and '"rule_ids"' in data:
            d = json.loads(data)
            d["param_formats"] = FORMATS
            d["generator"] = "gen_shadow_rules_v2_1.py"
            data = json.dumps(d, ensure_ascii=False, indent=2) + "\n"
        return orig(self, data, *args, **kw)
    Path.write_text = write_text


if __name__ == "__main__":
    _patch_meta_writer()
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("cmd")
        p.add_argument("--meta", required=True)
        p.add_argument("--cases", required=True)
        cmd_test(p.parse_args())
    else:
        R.main()
