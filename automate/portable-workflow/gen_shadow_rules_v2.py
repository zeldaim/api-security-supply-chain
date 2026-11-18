#!/usr/bin/env python3
"""OpenAPI 명세 → Wazuh Shadow API 룰 (v2: 다른 앱에도 쓸 수 있게).

팀 생성기 `team_src/detection/shadow_api/gen_shadow_rules.py` 는 고치지 않는다. 명세 읽기·허용 경로 정규식·단계(L1~L3E)·빈도 정의는
그 모듈의 함수를 그대로 가져다 쓰고, crAPI 검증에서 막힌 세 가지만 바꾼다 (crapi_generality_2026-11-15 README §3-2).

  1) 검사 범위   원본: `^/+api` 고정           → v2: 명세에서 뽑는다 (/identity/api, /workshop/api …) 또는 --scope
  2) 로그 형식   원본: 앱 JSON 로그(app.log) 전용 → v2: --log-format accesslog 면 웹 접근 로그(Wazuh web-accesslog 디코더)용 룰
  3) 자체 시험   원본: 팀 웹 경로가 박힌 케이스  → v2: 케이스를 전부 대상 명세에서 만든다

  python3 gen_shadow_rules_v2.py build --spec <명세> --out rules.xml --meta meta.json --cases cases.jsonl \
                                 [--log-format accesslog|applog] [--scope REGEX] [--allowlist FILE] [--base-id 100500]
  python3 gen_shadow_rules_v2.py test  --meta meta.json --cases cases.jsonl      # 파이썬 재현으로 기대값 확인 (구현 검증)
  python3 gen_shadow_rules_v2.py lines --cases cases.jsonl                       # 케이스를 접근 로그 줄로 (wazuh-logtest 입력)

주의: test 통과는 "룰이 생성기 의도대로 판정한다"는 뜻이지 탐지 정확도가 아니다. 실제 Wazuh 판정은 logtest_accesslog.sh 로 본다.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_GEN_V1 = HERE / ".." / ".." / "team_src" / "detection" / "shadow_api" / "gen_shadow_rules.py"   # 작업 레포 위치
if not _GEN_V1.exists():                                   # 공개 레포에는 같은 파일이 automate/rules/ 에 있다
    _GEN_V1 = HERE / ".." / "rules" / "gen_shadow_rules.py"
_spec = importlib.util.spec_from_file_location("gen_v1", _GEN_V1)
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)        # 팀 생성기 (PyYAML 필요)

# Wazuh 기본 웹 룰: 31100 접근 로그 · 31101 4xx · 31108 2xx/3xx 단순 요청 · 31120~31123 5xx.
# 자식 룰이 이벤트를 먼저 가져가므로, 어느 쪽으로 내려가든 닿도록 모두 상위로 둔다 (rules_v2 README 의 31108 사례와 같은 이유).
WEB_PARENTS = "31100, 31101, 31108, 31120, 31121, 31122, 31123"


def derive_scope(templates):
    """명세 경로 → 검사 범위 정규식. 'api' 조각이 있으면 거기까지, 없으면 첫 조각. 슬래시 겹침(//api)도 잡는다."""
    prefixes = set()
    for t in templates:
        segs = [s for s in t.split("/") if s]
        if not segs:
            continue
        idx = next((i for i, s in enumerate(segs) if s.lower() == "api"), 0)
        prefixes.add("/+" + "/+".join(re.escape(s) for s in segs[:idx + 1]))
    if not prefixes:
        return G.API_SCOPE_REGEX
    return r"^(?:" + "|".join(sorted(prefixes)) + r")(?:/|\?|$)"


def scope_prefixes(templates):
    out = set()
    for t in templates:
        segs = [s for s in t.split("/") if s]
        if segs:
            idx = next((i for i, s in enumerate(segs) if s.lower() == "api"), 0)
            out.add("/" + "/".join(segs[:idx + 1]))
    return sorted(out)


def x(text):
    return G.x(text)


def build_xml_accesslog(ops, ids, bursts, meta):
    methods = list(ops.keys())
    L = ["<!--",
         "  Shadow API 탐지 룰 — 웹 접근 로그용 (자동 생성: gen_shadow_rules_v2.py build 로 다시 만드세요)",
         f"  생성 시각 : {meta['generated_at']}", f"  명세 원본 : {meta['spec_source']}", f"  명세 SHA256: {meta['spec_sha256']}",
         f"  명세 작업 수: {meta['operation_count']} (예외 목록 {meta['allowlist_count']}건 포함)", f"  검사 범위 : {meta['scope']}",
         "  필드: url(경로+쿼리) · protocol(메서드) · id(응답 코드) · srcip — Wazuh web-accesslog 디코더"]
    for m in methods:
        for o in ops[m]:
            L.append(f"    {m:<7} {o['template']}" + ("  [예외] " + o["reason"] if o["source"] == "allowlist" else ""))
    L += ["-->", '<group name="shadow_api,">', "",
          "  <!-- 기반: 접근 로그의 API 범위 요청. 명세 안 요청은 여기서 끝난다 (레벨 0 = 경보 없음) -->",
          f'  <rule id="{ids["base"]}" level="0">', f"    <if_sid>{WEB_PARENTS}</if_sid>",
          f'    <url type="pcre2">{x(meta["scope"])}</url>', "    <description>API 요청 (명세 범위)</description>", "  </rule>", "",
          "  <!-- 명세 밖 판정: 명세에 아예 없는 메서드 -->",
          f'  <rule id="{ids["other_method"]}" level="{G.OTHER_LEVEL}">', f'    <if_sid>{ids["base"]}</if_sid>',
          f'    <protocol type="pcre2" negate="yes">{x(G.methods_regex(methods))}</protocol>',
          "    <description>[Shadow API] 명세 밖 호출: $(srcip) $(protocol) $(url)</description>",
          "    <group>shadow_api_undocumented,</group>", "  </rule>"]
    for m in methods:
        L += ["", f"  <!-- 명세 밖 판정: {m} 인데 명세의 {m} 경로({len(ops[m])}개) 어디에도 맞지 않음 -->",
              f'  <rule id="{ids["undoc_" + m]}" level="{G.OTHER_LEVEL}">', f'    <if_sid>{ids["base"]}</if_sid>',
              f'    <protocol type="pcre2">^{m}$</protocol>',
              f'    <url type="pcre2" negate="yes">{x(G.method_allow_regex(ops[m]))}</url>',
              "    <description>[Shadow API] 명세 밖 호출: $(srcip) $(protocol) $(url)</description>",
              "    <group>shadow_api_undocumented,</group>", "  </rule>"]
    L += ["", "  <!-- 단계: 명세 밖 호출을 응답 코드로 분류 -->"]
    for key, _off, level, status_re, group, label in G.STAGES:
        L += [f'  <rule id="{ids[key]}" level="{level}">', "    <if_group>shadow_api_undocumented</if_group>",
              f'    <id type="pcre2">{x(status_re)}</id>',
              f"    <description>[Shadow API {label}] $(srcip) $(protocol) $(url)</description>"]
        if key in G.STAGE_MITRE:
            L.append(f"    <mitre><id>{G.STAGE_MITRE[key]}</id></mitre>")
        L += [f"    <group>{group},</group>", "  </rule>"]
    L += ["", "  <!-- 빈도: 같은 출발지 IP 가 짧은 시간에 반복 -->"]
    for key, _off, level, target, _n, _t, group, label, mitre in G.BURSTS:
        n, t, ign = bursts[key]
        L += [f'  <rule id="{ids[key]}" level="{level}" frequency="{n}" timeframe="{t}"' + (f' ignore="{ign}"' if ign else "") + ">",
              f"    <if_matched_sid>{ids[target]}</if_matched_sid>", "    <same_srcip />",
              f"    <description>[Shadow API {label}] $(srcip) {t}초 안에 {target} {n}회 이상</description>",
              f"    <mitre><id>{mitre}</id></mitre>", f"    <group>{group},</group>", "  </rule>"]
    L += ["", "</group>"]
    return "\n".join(L) + "\n"


def make_cases(ops, prefixes):
    """시험 케이스를 전부 대상 명세에서 만든다 — 팀 웹 경로를 쓰지 않는다."""
    def ev(method, path, status, note, expect):
        return {"note": note, "expect": expect,
                "log": {"timestamp": "2026-11-16T10:00:00+09:00", "client_ip": "192.168.80.50", "method": method, "path": path,
                        "status": status, "response_bytes": 128, "user_agent": "shadow-api-testcase"}}
    cases = []
    for m, lst in ops.items():                                   # 명세 안: 경보 없음
        for o in lst:
            cases.append(ev(m, G.sample_path(o["template"]), 200, f"명세 안 {m} {o['template']}", None))
    first = next(((m, o["template"]) for m in ("GET", "POST") for o in ops.get(m, [])), None)
    if first:
        m, t = first
        p = G.sample_path(t)
        cases += [ev(m, p + "?page=2&sort=asc", 200, "명세 안 + 쿼리스트링", None),
                  ev(m, p + "/", 200, "명세 안 + 끝 슬래시", None),
                  ev(m, p, 401, "명세 안 + 401 (명세 API 의 인증 실패는 범위 밖)", None)]
        known = {mm for mm, lst in ops.items() if any(o["template"] == t for o in lst)}
        other = next((c for c in ("DELETE", "PUT", "PATCH", "POST", "GET") if c not in known), None)
        if other:
            cases.append(ev(other, p, 405, f"명세 경로 + 그 경로에 없는 메서드({other})", "L1"))
    for pre in prefixes:                                          # 범위 안 · 명세 밖
        u = pre + "/zz-undocumented-1"
        cases += [ev("GET", u, 404, f"{pre}: 없는 경로 탐색", "L1"), ev("GET", u, 401, f"{pre}: 숨은 API 인증 요구", "L2"),
                  ev("GET", u, 403, f"{pre}: 숨은 API 권한 거부", "L2"), ev("GET", u, 200, f"{pre}: 명세 밖 호출 성공", "L3"),
                  ev("GET", u, 500, f"{pre}: 명세 밖 호출 서버 오류", "L3E"), ev("GET", u, 400, f"{pre}: 명세 밖 + 기타 상태 코드", "OTHER"),
                  ev("GET", "/" + pre, 404, f"{pre}: 슬래시 겹침(//) 우회", "L1")]
    cases += [ev("TRACE", prefixes[0] + "/zz-undocumented-1", 405, "명세에 아예 없는 메서드", "L1")] if prefixes else []
    cases += [ev("GET", "/index.html", 200, "범위 밖 (정적 페이지)", None), ev("GET", "/zz-not-api/1", 404, "범위 밖 404", None)]
    return cases


def to_access_line(log, sec=0):
    m, s = divmod(sec, 60)
    return (f'{log["client_ip"]} - - [16/Nov/2026:09:{m:02d}:{s:02d} +0000] "{log["method"]} {log["path"]} HTTP/1.1" '
            f'{log["status"]} 128 "-" "{log.get("user_agent", "-")}"')


def cmd_build(a):
    import yaml
    raw = G.read_source(a.spec)
    spec = yaml.safe_load(raw)                                    # JSON 명세도 YAML 로 읽힌다
    if not isinstance(spec, dict) or "paths" not in spec:
        sys.exit(f"{a.spec}: OpenAPI 명세(paths)를 찾지 못했습니다")
    allowlist = G.load_allowlist(Path(a.allowlist)) if a.allowlist and Path(a.allowlist).exists() else []
    ops = G.collect_operations(spec, allowlist)
    templates = [o["template"] for lst in ops.values() for o in lst if o["source"] == "openapi"]
    scope = a.scope or derive_scope(templates)
    ids = G.rule_ids(a.base_id, list(ops.keys()))
    bursts = {"F1": (a.f1_count, a.f1_window, a.burst_ignore), "F2": (a.f2_count, a.f2_window, a.burst_ignore)}
    meta = {"generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "generator": "gen_shadow_rules_v2.py",
            "spec_source": a.spec, "spec_sha256": hashlib.sha256(raw).hexdigest(),
            "operation_count": sum(len(v) for v in ops.values()), "allowlist_count": len(allowlist),
            "status_option": "static", "log_format": a.log_format, "scope": scope, "scope_prefixes": scope_prefixes(templates),
            "rule_ids": ids, "bursts": bursts, "operations": ops}
    if a.log_format == "accesslog":
        xml = build_xml_accesslog(ops, ids, bursts, meta)
    else:
        G.API_SCOPE_REGEX = scope                                 # 팀 생성기의 JSON 로그용 XML 을 범위만 바꿔 그대로 쓴다
        xml = G.build_xml(ops, ids, bursts, meta)
    Path(a.out).write_text(xml, encoding="utf-8")
    Path(a.meta).write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    cases = make_cases(ops, meta["scope_prefixes"])
    with open(a.cases, "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(f"명세 작업 {meta['operation_count']}개 (예외 {len(allowlist)}건) · 로그 형식 {a.log_format} → {a.out}")
    print(f"  검사 범위: {scope}")
    print(f"  룰 ID {ids['base']}~ · 테스트 케이스 {len(cases)}개 → {a.cases}")


def cmd_test(a):
    meta = json.loads(Path(a.meta).read_text(encoding="utf-8"))
    meta["bursts"] = {k: tuple(v) for k, v in meta["bursts"].items()}
    G.API_SCOPE_REGEX = meta["scope"]
    clf = G.Classifier(meta)
    total = fails = 0
    for line in Path(a.cases).read_text(encoding="utf-8").splitlines():
        c = json.loads(line)
        got, _ = clf.classify(c["log"])
        total += 1
        if got != c["expect"]:
            fails += 1
            print(f"FAIL 기대={c['expect']}  결과={got}  {c['log']['method']:<6} {c['log']['path']} -> {c['log']['status']}  ({c['note']})")
    print(f"\n{total - fails}/{total} 통과 (파이썬 재현 — 구현 검증)")
    sys.exit(1 if fails else 0)


def cmd_lines(a):
    for i, line in enumerate(Path(a.cases).read_text(encoding="utf-8").splitlines()):
        print(to_access_line(json.loads(line)["log"], i))


def main():
    p = argparse.ArgumentParser(description="OpenAPI 명세 → Wazuh Shadow API 룰 (v2)")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--spec", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--meta", required=True)
    b.add_argument("--cases", required=True)
    b.add_argument("--allowlist", default="")
    b.add_argument("--log-format", choices=["accesslog", "applog"], default="accesslog")
    b.add_argument("--scope", default="", help="검사 범위 정규식. 비우면 명세에서 뽑는다")
    b.add_argument("--base-id", type=int, default=100500)
    b.add_argument("--f1-count", type=int, default=20)
    b.add_argument("--f1-window", type=int, default=30)
    b.add_argument("--f2-count", type=int, default=10)
    b.add_argument("--f2-window", type=int, default=60)
    b.add_argument("--burst-ignore", type=int, default=60)
    b.set_defaults(fn=cmd_build)
    t = sub.add_parser("test")
    t.add_argument("--meta", required=True)
    t.add_argument("--cases", required=True)
    t.set_defaults(fn=cmd_test)
    ln = sub.add_parser("lines")
    ln.add_argument("--cases", required=True)
    ln.set_defaults(fn=cmd_lines)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
