#!/usr/bin/env python3
"""행위 특징 v2.1 — v2(`../v2_portable/features.py`)를 고치지 않고, 세 번째 앱(VAmPI)에서 막힌 곳만 바꿔 끼운다.

  1) 검사 범위   v2: 'api' 조각이 없으면 명세의 첫 조각들(/users, /books)만 → 새 첫 조각(/admin, /debug)을 못 봄
                 v2.1: 명세 어디에도 'api' 조각이 없으면 "루트(/)와 정적 파일을 뺀 전부"가 범위
  2) 명세 대조   v2: 경로 파라미터는 무엇이든 [^/]+ → /users/v1/_internal 이 {username} 에 흡수
                 v2.1: 명세에 형식이 있으면 그 형식만 (integer → 숫자, uuid → UUID). 형식이 없으면 v2 와 같음
  3) 객체 ID     v2: 경로의 숫자 · UUID 만
                 v2.1: BOLA_TARGETS 틀의 자리({book_title})에 들어온 값은 형식과 무관하게 객체로 센다
                       → 서로 다른 객체 수가 id_span_log 에 잡힌다. 특징 이름 · 순서는 v2 와 같다

'api' 조각이 있는 명세(팀 웹 · crAPI)와 BOLA_TARGETS 가 비었을 때는 v2 와 같은 값이 나온다 (회귀: compare_v2_v2_1.py).

  python features.py extract <access.log> [--window 15] [--out features.csv] [--no-ip]
  python features.py scope
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(HERE, "..", "portable-workflow")
_s = importlib.util.spec_from_file_location("features", os.path.join(V2, "features.py"))
F = importlib.util.module_from_spec(_s)
sys.modules["features"] = F            # v2 스크립트들이 `import features` 하면 이 (바꿔 끼운) 모듈을 받는다
_s.loader.exec_module(F)

STATIC_EXT = r"css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|html?|txt"
ALL_BUT_STATIC = r"^/(?!(?:\?|$))(?![^?]*\.(?:" + STATIC_EXT + r")(?:\?|$))"
UUID = F._UUID
_v2_template, _v2_object_refs, _v2_derive_scope = F.template, F.object_refs, F.derive_scope


def has_api_segment(paths):
    return any(s.lower() == "api" for p in paths for s in p.split("/"))


def derive_scope(paths):
    if has_api_segment(paths):
        return _v2_derive_scope(paths)
    return re.compile(ALL_BUT_STATIC)


def _load_doc(path):
    text = open(path, encoding="utf-8").read()
    if text.lstrip().startswith("{"):
        return json.loads(text)
    import yaml                          # 형식 정보를 읽으려면 YAML 파서가 필요 (없으면 v2 처럼 형식 없이)
    return yaml.safe_load(text)


def param_formats(doc):
    r"""명세 → {경로 틀: {파라미터: 정규식}} — integer → \d+, uuid → UUID, 그 외 [^/]+"""
    out = {}
    for p, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        params = list(item.get("parameters") or [])
        for m, op in item.items():
            if isinstance(op, dict):
                params += op.get("parameters") or []
        fm = {}
        for pr in params:
            if not isinstance(pr, dict) or pr.get("in") != "path":
                continue
            sc = pr.get("schema") or pr
            t, f = sc.get("type"), sc.get("format")
            fm[pr.get("name")] = r"\d+" if t == "integer" else (UUID if f == "uuid" else r"[^/]+")
        out[p] = fm
    return out


def path_regex(tpl, formats):
    out, pos = [], 0
    for m in re.finditer(r"\{([^}]+)\}", tpl):
        out.append(re.escape(tpl[pos:m.start()]))
        out.append("(?:" + formats.get(m.group(1), r"[^/]+") + ")")
        pos = m.end()
    out.append(re.escape(tpl[pos:]))
    return re.compile("^" + "".join(out) + "/*$")


FORMATS = {}


def load_spec(path=None):
    path = path or next((p for p in F.SPEC_CANDIDATES if p and os.path.exists(p)), None)
    if not path:
        raise SystemExit("명세(openapi) 를 찾을 수 없음 (E2E_SPEC 로 지정)")
    items = F.read_spec_paths(path)
    try:
        FORMATS.update(param_formats(_load_doc(path)))
    except Exception as e:               # noqa: BLE001 — 형식을 못 읽어도 v2 와 같은 동작으로 계속
        print(f"[features v2.1] 파라미터 형식을 읽지 못해 v2 규칙으로 대조: {e}", file=sys.stderr)
    F.SPEC[:] = [(m, path_regex(p, FORMATS.get(p, {}))) for p, ms in items for m in ms]
    F.SPEC_PATHS[:] = items
    env = os.environ.get("E2E_API_SCOPE", "")
    F.SCOPE = re.compile(env) if env else derive_scope([p for p, _ in items])
    return path


def _targets():
    """BOLA_TARGETS → [(틀, 마지막 자리를 잡는 정규식)]"""
    out = []
    for t in filter(None, (x.strip() for x in os.environ.get("E2E_BOLA_TARGETS", "").split(","))):
        names = re.findall(r"\{([^}]+)\}", t)
        if not names:
            continue
        rx, pos = [], 0
        for i, m in enumerate(re.finditer(r"\{([^}]+)\}", t)):
            rx.append(re.escape(t[pos:m.start()]))
            rx.append("(?P<oid>[^/]+)" if i == len(names) - 1 else "[^/]+")
            pos = m.end()
        rx.append(re.escape(t[pos:]))
        out.append((t, re.compile("^" + "".join(rx) + "/*$")))
    return out


TARGETS = _targets()


def template(p):
    for t, rx in TARGETS:
        if rx.match(p):
            return t
    return _v2_template(p)


def object_refs(path, query):
    for t, rx in TARGETS:
        m = rx.match(path)
        if m:
            return [(t, m.group("oid"))] + [(t + "?" + k, v) for k, v in F.id_params(query)]
    return _v2_object_refs(path, query)


F.derive_scope, F.load_spec, F.template, F.object_refs = derive_scope, load_spec, template, object_refs

if __name__ == "__main__":
    sys.argv[0] = os.path.join(V2, "features.py")
    F.main()
    print("[features v2.1] 범위 · 형식 대조 · BOLA_TARGETS 객체 ID 적용", file=sys.stderr)
