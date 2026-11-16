#!/usr/bin/env python3
"""[엔드포인트 → 부품 도달성 정적 분석] 문서 14.

    python api-bom/reach/reachability.py --src ../team_one/web/src [--sbom <sbom-image.cdx.json>] [--findings <DT findings.csv>] [-o <출력폴더>]

하는 일
  1) 코드에서 엔드포인트를 뽑는다 — v2 `$router->add(...)`, v1 경로 분기, 화면 public/*.php
  2) 엔드포인트마다 실행되는 메서드를 따라간다 (메서드 단위 호출 그래프)
       공통 경로 = 프론트 컨트롤러 최상위 코드 (+ 인증 라우트는 AuthMiddleware::handle)
       라우트 경로 = 핸들러 메서드 → $this->prop->m() · Cls::m() · new Cls() · $var->m() 를 재귀로
       속성 타입은 생성자 매개변수 타입에서 추론 (`$this->x = $y` 와 `Type $y`)
  3) 도달한 메서드 본문에서 features.json 의 PHP 기능·외부 클래스를 찾아 SBOM 부품에 잇는다
  4) DT 스냅샷(findings.csv)으로 엔드포인트별 도달 부품의 Critical/High 를 센다
  5) 어떤 엔드포인트에서도 닿지 않는 취약 부품 = VEX not_affected 후보 (사람 승인 대상, 자동 적용 안 함)

원칙: 과대 추정(over-approximation) 쪽으로 — 해석 못 한 호출은 "미해석"으로 세어 보고서에 남긴다.
      "닿지 않음" 주장은 미해석 호출이 그 부품과 무관할 때만 의미가 있다 (문서 14 §5).
표준 라이브러리만 사용.
"""
import argparse
import collections
import csv
import datetime
import glob
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


# ---------- PHP 소스 다루기 (가벼운 파서) ----------
def strip_code(src):
    """주석·문자열 내용을 공백으로 바꾼다 (줄 번호·위치 유지). 문자열 따옴표는 남긴다."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i) or c == "#":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        elif c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            body = src[i + 1:j]
            out.append(c + re.sub(r"[^\n]", " ", body) + c); i = j + 1
        else:
            out.append(c); i += 1
    return "".join(out)


def block_end(code, start):
    """code[start] == '{' 의 짝 '}' 위치"""
    depth = 0
    for k in range(start, len(code)):
        if code[k] == "{":
            depth += 1
        elif code[k] == "}":
            depth -= 1
            if depth == 0:
                return k
    return len(code) - 1


def line_of(code, pos):
    return code.count("\n", 0, pos) + 1


class PhpFile:
    def __init__(self, path, root):
        self.path = path
        self.rel = os.path.relpath(path, root).replace("\\", "/")
        self.raw = open(path, encoding="utf-8", errors="replace").read()
        self.code = strip_code(self.raw)
        m = re.search(r"\bnamespace\s+([\w\\]+)\s*;", self.code)
        self.ns = m.group(1) if m else ""
        self.uses = {}
        for m in re.finditer(r"^\s*use\s+([\w\\]+)(?:\s+as\s+(\w+))?\s*;", self.code, re.M):
            full = m.group(1)
            self.uses[m.group(2) or full.rsplit("\\", 1)[-1]] = full
        self.classes = {}
        for m in re.finditer(r"\b(?:final\s+|abstract\s+)?class\s+(\w+)[^{]*\{", self.code):
            s = m.end() - 1
            self.classes[m.group(1)] = (s, block_end(self.code, s))

    def resolve(self, short):
        short = short.lstrip("\\")
        if "\\" in short:
            head, rest = short.split("\\", 1)
            return self.uses[head] + "\\" + rest if head in self.uses else short
        if short in self.uses:
            return self.uses[short]
        return (self.ns + "\\" + short) if self.ns else short


class Method:
    def __init__(self, cls, name, f, start, end, params):
        self.cls, self.name, self.f, self.start, self.end, self.params = cls, name, f, start, end, params

    @property
    def key(self):
        return f"{self.cls}::{self.name}"

    @property
    def body(self):
        return self.f.code[self.start:self.end]

    @property
    def raw(self):
        return self.f.raw[self.start:self.end]

    @property
    def where(self):
        return f"{self.f.rel}:{line_of(self.f.code, self.start)}"


class Index:
    def __init__(self, root):
        self.root = root
        self.files = [PhpFile(p, root) for p in sorted(glob.glob(os.path.join(root, "src", "**", "*.php"), recursive=True))
                      + sorted(glob.glob(os.path.join(root, "public", "**", "*.php"), recursive=True))]
        self.methods = {}       # "Ns\\Cls::m" → Method
        self.props = {}         # "Ns\\Cls" → {prop: FQCN}
        for f in self.files:
            for cname, (cs, ce) in f.classes.items():
                fq = f.resolve(cname) if f.ns else cname
                fq = (f.ns + "\\" + cname) if f.ns else cname
                body = f.code[cs:ce]
                for m in re.finditer(r"\bfunction\s+(\w+)\s*\(([^)]*)\)[^{;]*\{", body):
                    s = cs + m.end() - 1
                    e = block_end(f.code, s)
                    params = {}
                    for pm in re.finditer(r"(\??[\\\w]+)\s+&?\$(\w+)", m.group(2)):
                        t = pm.group(1).lstrip("?")
                        if t.lower() not in ("int", "string", "float", "bool", "array", "callable", "iterable", "object", "mixed", "self"):
                            params[pm.group(2)] = f.resolve(t)
                    self.methods[f"{fq}::{m.group(1)}"] = Method(fq, m.group(1), f, s, e, params)
                ctor = self.methods.get(f"{fq}::__construct")
                props = {}
                if ctor:
                    for am in re.finditer(r"\$this->(\w+)\s*=\s*\$(\w+)\s*;", ctor.body):
                        if am.group(2) in ctor.params:
                            props[am.group(1)] = ctor.params[am.group(2)]
                for pm in re.finditer(r"(?:private|protected|public)\s+(?:readonly\s+)?(\??[\\\w]+)\s+\$(\w+)", body):
                    t = pm.group(1).lstrip("?")
                    if t[0].isupper():
                        props.setdefault(pm.group(2), f.resolve(t))
                self.props[fq] = props


# ---------- 호출 따라가기 ----------
CALL_RES = [
    ("this_prop", re.compile(r"\$this->(\w+)->(\w+)\s*\(")),
    ("this", re.compile(r"\$this->(\w+)\s*\(")),
    ("static", re.compile(r"(?<![\w\\$>])(\\?[A-Z][\w\\]*|self|static|parent)::(\w+)\s*\(")),
    ("new", re.compile(r"\bnew\s+(\\?[A-Z][\w\\]*)\s*\(")),
    ("var", re.compile(r"\$(?!this\b)(\w+)->(\w+)\s*\(")),   # $this-> 는 위 두 규칙에서 (2026-11-05: 중복 미해석 버그)
]


def calls_in(text, f, cls, local_types, idx):
    """text 안의 호출 → [(대상 FQCN, 메서드, 종류)] · 미해석 목록"""
    found, unresolved = [], []
    for kind, rx in CALL_RES:
        for m in rx.finditer(text):
            if kind == "this_prop":
                t = idx.props.get(cls, {}).get(m.group(1))
                (found.append((t, m.group(2), kind)) if t else unresolved.append(f"$this->{m.group(1)}->{m.group(2)}()"))
            elif kind == "this":
                if cls:
                    found.append((cls, m.group(1), kind))
            elif kind == "static":
                c = m.group(1)
                t = cls if c in ("self", "static") else f.resolve(c)
                found.append((t, m.group(2), kind))
            elif kind == "new":
                found.append((f.resolve(m.group(1)), "__construct", kind))
            elif kind == "var":
                t = local_types.get(m.group(1))
                (found.append((t, m.group(2), kind)) if t else unresolved.append(f"${m.group(1)}->{m.group(2)}()"))
    return found, unresolved


def local_types_of(text, f, params=None):
    t = dict(params or {})
    for m in re.finditer(r"\$(\w+)\s*=\s*new\s+(\\?[A-Z][\w\\]*)\s*\(", text):
        t[m.group(1)] = f.resolve(m.group(2))
    # PDO 문장: $stmt = $this->db->prepare(...) / ->query(...) → PDOStatement (pdo 부품)
    for m in re.finditer(r"\$(\w+)\s*=\s*\$[\w>-]*->(prepare|query)\s*\(", text):
        t.setdefault(m.group(1), "PDOStatement")
    # catch (HttpException $e) → 예외 타입
    for m in re.finditer(r"catch\s*\(\s*(\\?[A-Z][\w\\]*)[^$)]*\$(\w+)\s*\)", text):
        t[m.group(2)] = f.resolve(m.group(1))
    for m in re.finditer(r"\$(\w+)\s*=\s*(\\?[A-Z][\w\\]*)::(\w+)\s*\(", text):
        # Database::connect() 처럼 정적 생성 함수 → 반환 타입은 메서드 선언의 ': Type'
        t.setdefault(m.group(1), ("?ret", f.resolve(m.group(2)), m.group(3)))
    return t


def ret_type(idx, fq, name):
    m = idx.methods.get(f"{fq}::{name}")
    if not m:
        return None
    hdr = m.f.code[:m.start]
    mm = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*:\s*\??([\\\w]+)\s*$", hdr)
    if not mm:
        return None
    return fq if mm.group(1) in ("self", "static") else m.f.resolve(mm.group(1))   # capture(): self → 그 클래스


class Walker:
    def __init__(self, idx, feats):
        self.idx, self.feats = idx, feats
        self.ext_classes = {c["class"]: c for c in feats["classes"]}

    def walk(self, seeds, skip=()):
        """seeds: [(FQCN, method)] → 도달 메서드 집합·외부 클래스 사용·미해석. skip: 따라가지 않을 메서드 키"""
        seen, ext, unresolved, edges = {}, collections.defaultdict(set), [], []
        stack = list(seeds)
        while stack:
            fq, name = stack.pop()
            key = f"{fq}::{name}"
            if key in seen or key in skip:
                continue
            m = self.idx.methods.get(key)
            if not m:
                short = fq.split("\\")[-1] if fq else "?"
                if fq in self.ext_classes or fq.lstrip("\\") in self.ext_classes:
                    ext[fq.lstrip("\\")].add(name)
                elif fq.split("\\")[0] in ("App",):
                    if name != "__construct":
                        unresolved.append(f"{key} (정의 못 찾음)")
                else:
                    ext[fq.lstrip("\\")].add(name)
                seen[key] = None
                continue
            seen[key] = m
            lt = local_types_of(m.body, m.f, m.params)
            for k, v in list(lt.items()):
                if isinstance(v, tuple):
                    lt[k] = ret_type(self.idx, v[1], v[2]) or None
            lt = {k: v for k, v in lt.items() if v}
            found, unres = calls_in(m.body, m.f, fq, lt, self.idx)
            unresolved += [f"{key}: {u}" for u in unres]
            for t, n, kind in found:
                edges.append((key, f"{t}::{n}"))
                stack.append((t, n))
        return {k: v for k, v in seen.items() if v}, ext, unresolved, edges


# ---------- 엔드포인트 뽑기 ----------
def endpoints(idx):
    out = []
    by = {f.rel: f for f in idx.files}
    v2 = by.get("public/api/index.php")
    if v2:
        lt = local_types_of(v2.code, v2)
        for k, v in list(lt.items()):
            if isinstance(v, tuple):
                lt[k] = ret_type(idx, v[1], v[2])
        for m in re.finditer(r"\$router->add\(\s*'(\w+)'\s*,\s*'([^']+)'\s*,\s*\[\s*\$(\w+)\s*,\s*'(\w+)'\s*\]\s*(?:,\s*(true|false))?", v2.raw):
            out.append({"endpoint_key": f"{m.group(1)} {m.group(2).replace('{product_id}', '{id}')}", "front": v2,
                        "handler": (lt.get(m.group(3)), m.group(4)), "auth": m.group(5) == "true",
                        "where": f"{v2.rel}:{line_of(v2.raw, m.start())}"})
    v1 = by.get("public/api/v1/index.php")
    if v1:
        for m in re.finditer(r"\$method\s*===\s*'(\w+)'\s*&&\s*(?:preg_match\('#\^([^$]+)\$#'|\$path\s*===\s*'([^']+)')[^{]*\{\s*(.*?)\n", v1.raw, re.S):
            path = m.group(3) or re.sub(r"\(\[\^/\]\+\)", "{id}", m.group(2))
            # 핸들러는 분기 본문 첫 줄(group 4)에서 찾는다 — m.end() 부터 찾으면 다음 분기 핸들러가 잡힘 (2026-11-05 버그)
            # 분기 본문({ ... } 끝까지)에서 찾는다 — 첫 줄이 변수 대입인 분기(ping)가 있음
            body_end = v1.raw.find("}", m.start(4))
            hm = re.search(r"\(new\s+(\w+)\(.*?\)\)->(\w+)\(", v1.raw[m.start(4):body_end])
            out.append({"endpoint_key": f"{m.group(1)} {path}", "front": v1,
                        "handler": (v1.resolve(hm.group(1)), hm.group(2)) if hm else (None, None), "auth": True,
                        "where": f"{v1.rel}:{line_of(v1.raw, m.start())}"})
    for f in idx.files:
        if re.match(r"public/[\w-]+\.php$", f.rel):
            meths = ["GET"] + (["POST"] if re.search(r"REQUEST_METHOD'\]\s*===\s*'POST'|\$_POST", f.raw) else [])
            for mt in meths:
                out.append({"endpoint_key": f"{mt} /{os.path.basename(f.rel)}", "front": f, "handler": (None, None),
                            "auth": None, "where": f"{f.rel}:1", "page": True})
    return out


def front_toplevel(f, idx):
    """프론트 컨트롤러에서 함수·클래스 밖 최상위 코드 (모든 요청이 실행)"""
    code = f.code
    for cname, (s, e) in f.classes.items():
        code = code[:s] + " " * (e - s) + code[e:]
    return code


def features_in(text, raw, feats, where_prefix, base_line):
    hits = []
    for ft in feats["functions"]:
        for m in re.finditer(ft["pattern"], text):
            ln = base_line + text.count("\n", 0, m.start())
            snippet = raw[m.start():m.start() + 60].split("\n")[0].strip()
            hits.append((ft["id"], f"{where_prefix}:{ln}", snippet))
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", required=True, help="팀 web/src 폴더")
    ap.add_argument("--sbom", help="이미지 SBOM (부품 존재·이름 확인용)")
    ap.add_argument("--findings", help="DT 스냅샷 findings.csv (엔드포인트별 Critical/High)")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    feats = json.load(open(os.path.join(HERE, "features.json"), encoding="utf-8"))
    ftab = {f["id"]: f for f in feats["functions"]}
    idx = Index(a.src)
    W = Walker(idx, feats)

    # 기준 자료
    if not a.findings:
        snaps = sorted(glob.glob(os.path.join(REPO, "api-bom", "dt_history", "sesac-shop-image", "*", "findings.csv")),
                       key=os.path.getmtime)
        snaps = [s for s in snaps if "upstream_backfill" not in s]
        a.findings = snaps[-1] if snaps else None
    vul = collections.defaultdict(lambda: {"CRITICAL": set(), "HIGH": set()})
    if a.findings:
        for r in csv.DictReader(open(a.findings, encoding="utf-8")):
            if r["severity"] in ("CRITICAL", "HIGH") and (r.get("analysis") or "").upper() not in ("NOT_AFFECTED", "FALSE_POSITIVE"):
                vul[r["component"]][r["severity"]].add(r["vulnId"])
    sbom_names = set()
    if not a.sbom:
        c = sorted(glob.glob(os.path.join(REPO, "sbom", "results", "20*", "sbom-image.cdx.json")))
        a.sbom = c[-1] if c else None
    if a.sbom:
        d = json.load(open(a.sbom, encoding="utf-8"))
        sbom_names = {c["name"] for c in d["components"] if c.get("type") != "file"}

    eps = endpoints(idx)
    runtime = feats["runtime"]
    results = []
    for ep in eps:
        f = ep["front"]
        seeds, notes = [], []
        top = front_toplevel(f, idx)
        if ep.get("page"):
            text, raw = f.code, f.raw
        else:
            # 최상위 코드에서 라우트 등록·분기 본문은 빼고 공통 부분만 (핸들러는 따로 시드)
            text, raw = top, f.raw
            if "v1" in f.rel:
                # v1: 분기 안 핸들러 줄은 해당 엔드포인트에서만
                text = re.sub(r"\(new\s+\w+\(.*?\)\)->\w+\([^;]*;", lambda m: " " * len(m.group(0)), text)
        lt = local_types_of(text, f)
        for k, v in list(lt.items()):
            if isinstance(v, tuple):
                lt[k] = ret_type(idx, v[1], v[2])
        lt = {k: v for k, v in lt.items() if v}
        found, unres = calls_in(text, f, None, lt, idx)
        top_seeds = [(t, n) for t, n, kind in found]
        if not ep.get("page") and "v1" not in f.rel:
            # v2: 라우터가 핸들러를 부르므로 $router->dispatch 는 공통, 핸들러는 시드로. 다른 라우트 핸들러 객체 생성은 공통(생성자만)
            top_seeds = [s for s in top_seeds if s[1] != "add"]
            if ep["auth"]:
                seeds.append(("App\\Api\\AuthMiddleware", "handle"))
        if ep["handler"][0]:
            seeds.append(ep["handler"])
        elif not ep.get("page"):
            notes.append("핸들러 해석 실패")
        # Router::dispatch 는 needAuth 일 때만 $this->auth->handle() — 공통 경로에서는 빼고 인증 라우트에만 시드로 넣는다
        common, ext_c, unres_c, _ = W.walk(top_seeds, skip={r"App\Api\AuthMiddleware::handle"} if "v1" not in f.rel else ())
        route, ext_r, unres_r, edges = W.walk(seeds)
        reached = {**common, **route}
        hits = features_in(text, raw, feats, f.rel, 1)
        for m in reached.values():
            hits += features_in(m.body, m.raw, feats, m.f.rel, line_of(m.f.code, m.start))
        comps = collections.OrderedDict()
        for c in runtime["components"]:
            comps.setdefault(c, set()).add("runtime: " + runtime["evidence"].split(" · ")[0])
        for mod, mv in runtime.get("apache_modules", {}).items():
            for c in mv["components"]:
                comps.setdefault(c, set()).add(f"apache mod_{mod} ({mv['confidence']})")
        seen_ids = set()
        for fid, where, snip in hits:
            ft = ftab[fid]
            if fid == "mbstring" and any(h[0] == "mb_regex" and h[1] == where for h in hits):
                continue
            for c in ft["components"]:
                comps.setdefault(c, set()).add(f"{fid} @ {where} `{snip}` ({ft['confidence']})")
            seen_ids.add(fid)
        for cls, ms in {**ext_c, **ext_r}.items():
            for ec in feats["classes"]:
                if cls == ec["class"]:
                    for c in ec["components"]:
                        comps.setdefault(c, set()).add(f"class {cls}::{','.join(sorted(ms))} ({ec['evidence']})")
        crit = sorted({v for c in comps for v in vul[c]["CRITICAL"]})
        high = sorted({v for c in comps for v in vul[c]["HIGH"]})
        results.append({**ep, "reached": reached, "comps": comps, "unresolved": unres + unres_c + unres_r,
                        "features": sorted(seen_ids), "crit": crit, "high": high, "notes": notes,
                        "common_n": len(common), "route_n": len(route), "edges": edges})

    # 부품 관점
    reach_by_comp = collections.defaultdict(set)
    for r in results:
        for c in r["comps"]:
            reach_by_comp[c].add(r["endpoint_key"])
    vuln_comps = sorted(vul, key=lambda c: (-len(vul[c]["CRITICAL"]), -len(vul[c]["HIGH"]), c))

    # 실행마다 새 폴더 — 덮어쓰지 않고 쌓는다 (2026-11-05 결정). 첫 결과 폴더 results/2026-11-05/ 는 그대로 둠
    out = a.out or os.path.join(HERE, "results", datetime.datetime.now().strftime("%Y-%m-%d_%H%M"))
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "reach.csv"), "w", encoding="utf-8", newline="") as fo:
        w = csv.writer(fo, lineterminator="\n")
        w.writerow(["endpoint_key", "auth", "where", "methods_common", "methods_route", "features", "components", "critical", "high", "unresolved", "notes"])
        for r in results:
            w.writerow([r["endpoint_key"], r["auth"], r["where"], r["common_n"], r["route_n"], ";".join(r["features"]),
                        ";".join(r["comps"]), len(r["crit"]), len(r["high"]), len(r["unresolved"]), ";".join(r["notes"])])
    with open(os.path.join(out, "components.csv"), "w", encoding="utf-8", newline="") as fo:
        w = csv.writer(fo, lineterminator="\n")
        w.writerow(["component", "in_sbom", "critical", "high", "reached_by_n", "reached_by", "vex_candidate"])
        for c in vuln_comps:
            n = reach_by_comp.get(c, set())
            w.writerow([c, c in sbom_names, len(vul[c]["CRITICAL"]), len(vul[c]["HIGH"]), len(n), ";".join(sorted(n)),
                        "not_affected 후보 (code_not_reachable)" if not n else ""])
    json.dump({"generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "src": os.path.abspath(a.src),
               "sbom": a.sbom and os.path.relpath(a.sbom, REPO), "findings": a.findings and os.path.relpath(a.findings, REPO),
               "endpoints": [{"endpoint_key": r["endpoint_key"], "where": r["where"], "auth": r["auth"],
                              "reached_methods": sorted(r["reached"]), "components": {c: sorted(v) for c, v in r["comps"].items()},
                              "unresolved": r["unresolved"], "critical": r["crit"], "high": r["high"]} for r in results]},
              open(os.path.join(out, "reach.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    # 보고서
    L = [f"# 엔드포인트 → 부품 도달성 (정적 분석) — {datetime.date.today()}", "",
         f"- 소스: `{a.src}` · SBOM: `{a.sbom and os.path.relpath(a.sbom, REPO)}` · DT findings: `{a.findings and os.path.relpath(a.findings, REPO)}`",
         f"- 엔드포인트 {len(results)} · 분석한 PHP 파일 {len(idx.files)} · 메서드 {len(idx.methods)}", "",
         "## 1. 엔드포인트별 도달 부품", "",
         "| 엔드포인트 | 인증 | 메서드(공통+라우트) | 기능 | 도달 부품 (런타임 제외) | Critical | High | 미해석 |", "|---|---|---|---|---|---|---|---|"]
    rt = set(runtime["components"]) | {c for mv in runtime.get("apache_modules", {}).values() for c in mv["components"]}
    for r in sorted(results, key=lambda r: (-len(r["crit"]), -len(r["high"]), r["endpoint_key"])):
        extra = [c for c in r["comps"] if c not in rt]
        L.append(f"| `{r['endpoint_key']}` | {'' if r['auth'] is None else ('필요' if r['auth'] else '없음')} | {r['common_n']}+{r['route_n']} | "
                 f"{', '.join(r['features']) or '-'} | {', '.join(extra) or '-'} | {len(r['crit'])} | {len(r['high'])} | {len(r['unresolved'])} |")
    L += ["", "런타임(모든 엔드포인트 공통): " + ", ".join(sorted(rt)), "",
          "## 2. 취약 부품 관점 — 어느 엔드포인트가 닿나", "",
          "| 부품 | Critical | High | 닿는 엔드포인트 수 | 판단 |", "|---|---|---|---|---|"]
    for c in vuln_comps[:40]:
        n = reach_by_comp.get(c, set())
        L.append(f"| {c} | {len(vul[c]['CRITICAL'])} | {len(vul[c]['HIGH'])} | {len(n)} | "
                 f"{'전체 공통(런타임)' if c in rt else ('**닿지 않음 → VEX not_affected 후보**' if not n else '일부')} |")
    nr = [c for c in vuln_comps if not reach_by_comp.get(c)]
    # CVE ID 단위 (같은 CVE 가 여러 바이너리 부품에 붙으므로 부품 단위 합은 과장됨)
    sev_of, reached_ids = {}, set()
    for c in vul:
        for s in ("CRITICAL", "HIGH"):
            for v in vul[c][s]:
                sev_of[v] = s
                if reach_by_comp.get(c):
                    reached_ids.add(v)
    un_ids = sorted(set(sev_of) - reached_ids)
    cnt = lambda ids, s: sum(1 for v in ids if sev_of[v] == s)
    with open(os.path.join(out, "cve_reach.csv"), "w", encoding="utf-8", newline="") as fo:
        w = csv.writer(fo, lineterminator="\n")
        w.writerow(["vulnId", "severity", "components", "reached", "reached_via"])
        for v in sorted(sev_of):
            comps_v = sorted(c for c in vul if v in vul[c]["CRITICAL"] | vul[c]["HIGH"])
            via = sorted(c for c in comps_v if reach_by_comp.get(c))
            w.writerow([v, sev_of[v], ";".join(comps_v), bool(via), ";".join(via)])
    L += ["", f"- 닿지 않는 취약 **부품**: {len(nr)}개 / {len(vuln_comps)} (부품 단위 합 Critical {sum(len(vul[c]['CRITICAL']) for c in nr)} · High {sum(len(vul[c]['HIGH']) for c in nr)} — 같은 CVE 중복 포함, 과장된 값)",
          f"- **CVE ID 단위** (중복 없음): Critical·High 고유 {len(sev_of)}개 (C{cnt(sev_of, 'CRITICAL')} · H{cnt(sev_of, 'HIGH')}) 중 "
          f"**어느 엔드포인트에서도 닿지 않는 CVE {len(un_ids)}개 (C{cnt(un_ids, 'CRITICAL')} · H{cnt(un_ids, 'HIGH')})** → VEX not_affected 후보 · "
          f"닿는 CVE {len(reached_ids)}개 (C{cnt(reached_ids, 'CRITICAL')} · H{cnt(reached_ids, 'HIGH')}) — `cve_reach.csv`",
          "", "## 3. 근거 (엔드포인트별 상세)", ""]
    for r in results:
        L.append(f"### `{r['endpoint_key']}` ({r['where']})")
        for c, ev in r["comps"].items():
            if c in rt:
                continue
            L.append(f"- **{c}** ← " + " · ".join(sorted(ev))[:400])
        if r["unresolved"]:
            L.append(f"- 미해석 호출 {len(r['unresolved'])}: " + ", ".join(sorted(set(r["unresolved"]))[:8]))
        L.append(f"- 도달 메서드: " + ", ".join(k.split("\\")[-1] for k in sorted(r["reached"])))
        L.append("")
    open(os.path.join(out, "reach_report.md"), "w", encoding="utf-8", newline="\n").write("\n".join(L) + "\n")
    print(f"엔드포인트 {len(results)} · 닿지 않는 취약 부품 {len(nr)}/{len(vuln_comps)} → {out}")
    # 대시보드 (reach_dashboard.html) — 같은 결과 폴더에
    import importlib.util
    spec = importlib.util.spec_from_file_location("reach_dashboard", os.path.join(HERE, "reach_dashboard.py"))
    rd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rd)
    print("도달성 대시보드:", rd.build(out))
    spec2 = importlib.util.spec_from_file_location("evidence_dashboard", os.path.join(HERE, "evidence_dashboard.py"))
    ed = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(ed)
    print("근거 통합 표:", ed.build(out))


if __name__ == "__main__":
    main()
