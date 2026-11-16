"""내부 정보(소스 코드)에서 API 기준 명세를 자동으로 만든다 — CycloneDX 1.6 API-BOM → Wazuh 룰 입력.

절차 (자세한 설명: api-bom/docs/01_명세_자동생성_기준선.md, 02_Wazuh_룰_연결_자동화.md):
    1) extract   : 소스 코드(라우트 정의) + 프런트(app.js 호출) [+ 기존 명세] [+ 이전 승인 결과] → 후보 CSV
    2) (사람)    : CSV의 decision 열을 검토·확정 (active / deprecated / exclude)
    3) cyclonedx : 확정된 CSV → CycloneDX 1.6 서비스 BOM(SaaSBOM) — 표준 형식의 기준 명세
    4) validate  : CycloneDX 공식 JSON 스키마로 검증
    5) openapi   : BOM → OpenAPI(허용 목록) — 팀 Wazuh 룰 생성기(gen_shadow_rules.py) 입력
    (선택) observe   : 실제 로그와 기준선 대조 (Wazuh·ELK 없이 미리 확인)
    (선택) inventory : 확정된 CSV → ELK api-inventory 적재용 NDJSON

사용법:
    python source_to_baseline.py extract   <web/src 경로> [--spec openapi.yaml] [--prev 이전baseline.csv] > baseline.csv
    python source_to_baseline.py cyclonedx <baseline.csv> <web/src 경로> [--base-url URL] [--owner 팀] [--sbom image.cdx.json] > baseline.cdx.json
    python source_to_baseline.py validate  <baseline.cdx.json>
    python source_to_baseline.py openapi   <baseline.cdx.json> > openapi.from-bom.json
    python source_to_baseline.py observe   <baseline.csv> <access.log> [access.log ...]
    python source_to_baseline.py inventory <baseline.csv> <service> <owner> > inventory.ndjson

경로 파라미터 {id}, {product_id} 등은 모두 {id}로 통일한다 (ingest pipeline 정규화 규칙과 맞춤).
표준 라이브러리만 사용 (--spec 이 YAML일 때만 pyyaml, validate 는 cyclonedx-python-lib[json-validation] 필요).
"""
import csv
import json
import os
import re
import subprocess
import sys
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

CSV_FIELDS = ["endpoint_key", "kind", "auth", "frontend", "in_spec", "source", "decision", "owner", "note"]
DECISIONS = {"active", "deprecated", "exclude", "review"}
STATIC_EXT = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|txt|ya?ml)$", re.I)

# 소스 코드의 라우트 정의 패턴 (이 쇼핑몰 기준. 다른 프레임워크는 문서 4장 표 참고)
#   v2: $router->add('GET', '/api/v2/products/{id}', [...], true);
ROUTER_ADD = re.compile(r"""->add\(\s*'(\w+)'\s*,\s*'([^']+)'\s*,\s*\[[^\]]*\]\s*(,\s*true)?""")
#   v1: $method === 'GET' && preg_match('#^/api/v1/users/([^/]+)$#', ...)  /  $path === '/api/v1/...'
V1_BRANCH = re.compile(r"""\$method\s*===\s*'(\w+)'\s*&&\s*(?:preg_match\(\s*'#\^(.+?)\$#'|\$path\s*===\s*'([^']+)')""")


# ── 공통: 경로 정규화 (02 가이드 5-4 ingest pipeline 과 같은 규칙) ──────────────────
def normalize(path):
    path = path.split("?", 1)[0]
    path = re.sub(r"\{[^}]+\}", "{id}", path)
    path = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}", path)
    path = re.sub(r"/[0-9a-fA-F]{16,}(?=/|$)", "/{id}", path)
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def regex_to_template(rx):
    """'/api/v1/users/([^/]+)' → '/api/v1/users/{id}'"""
    return re.sub(r"\((?:[^()]|\([^()]*\))*\)", "{id}", rx).replace("\\", "")


def line_no(text, pos):
    return text.count("\n", 0, pos) + 1


# ── 1) extract ───────────────────────────────────────────────────────────────
def routes_from_code(src):
    """서버 코드에 선언된 라우트 → {endpoint_key: (auth, source)}"""
    found = {}
    for php in sorted(src.glob("public/**/index.php")):
        text = php.read_text(encoding="utf-8")
        rel = php.relative_to(src).as_posix()
        token_only = "bearerToken()" in text
        for m in ROUTER_ADD.finditer(text):
            key = f"{m.group(1).upper()} {normalize(m.group(2))}"
            found[key] = ("required" if m.group(3) else "none", f"{rel}:{line_no(text, m.start())}")
        for m in V1_BRANCH.finditer(text):
            path = regex_to_template(m.group(2)) if m.group(2) else m.group(3)
            key = f"{m.group(1).upper()} {normalize(path)}"
            found[key] = ("required" if token_only else "unknown", f"{rel}:{line_no(text, m.start())}")
    return found


def pages_from_code(src):
    """public/ 바로 아래 .php 화면 → GET 엔드포인트"""
    found = {}
    for php in sorted((src / "public").glob("*.php")):
        rel = php.relative_to(src).as_posix()
        found[f"GET /{php.name}"] = ("none", rel)
        if php.name == "index.php":
            found["GET /"] = ("none", rel)
    return found


def call_text(js, start):
    """api( 의 여는 괄호부터 짝이 맞는 닫는 괄호까지 (문자열 안 괄호는 무시)"""
    depth, i, quote = 0, start, None
    while i < len(js):
        c = js[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return js[start:i + 1]
        i += 1
    return js[start:]


def calls_from_frontend(src):
    """app.js 의 api('/api/...', {method}) 호출 → 사용 중인 endpoint_key 집합 (휴리스틱)"""
    used = set()
    for js_path in (src / "public").rglob("*.js"):
        js = js_path.read_text(encoding="utf-8")
        for m in re.finditer(r"\bapi\(", js):
            text = call_text(js, m.end() - 1)
            mm = re.search(r"method\s*:\s*'(\w+)'", text)
            method = mm.group(1).upper() if mm else "GET"
            literals = re.findall(r"'([^']*)'", text)
            for i, lit in enumerate(literals):
                if not lit.startswith("/api/"):
                    continue
                path = lit.split("?", 1)[0]
                if path.endswith("/"):  # '/api/v2/orders/' + id + '/cancel'
                    path += "{id}"
                    nxt = literals[i + 1] if i + 1 < len(literals) else ""
                    if nxt.startswith("/") and not nxt.startswith("/api/"):
                        path += nxt
                used.add(f"{method} {normalize(path)}")
    return used


def keys_from_spec(spec_path):
    text = Path(spec_path).read_text(encoding="utf-8")
    if spec_path.lower().endswith(".json"):
        spec = json.loads(text)
    else:
        import yaml  # pip install pyyaml
        spec = yaml.safe_load(text)
    prefix = ""
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict):
        prefix = re.sub(r"^\w+://[^/]+", "", servers[0].get("url", "")).rstrip("/")
    keys = {}
    for path, ops in (spec.get("paths") or {}).items():
        for method, op in (ops or {}).items():
            if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}:
                deprecated = isinstance(op, dict) and op.get("deprecated") is True
                keys[f"{method.upper()} {normalize(prefix + path)}"] = deprecated
    return keys


def suggest(kind, frontend, in_spec, spec_deprecated):
    if spec_deprecated:
        return "deprecated", "명세에 deprecated 표시"
    if kind == "page":
        return "active", "화면(page)"
    if frontend == "y":
        return "active", "프런트에서 호출"
    if in_spec == "y":
        return "active", "명세에 있음(프런트 미사용)"
    return "review", "코드에만 있음 — 담당자 확인 필요 (shadow 후보)"


def cmd_extract(args):
    src = Path(args[0])
    spec = None
    if "--spec" in args:
        spec = keys_from_spec(args[args.index("--spec") + 1])

    routes = routes_from_code(src)
    if not routes:
        # 2026-11-10: 0개여도 통과해서 서비스 0개 API-BOM 이 커밋됐다 (sbom/results/2026-11-05). 빈 허용 목록 = 모든 호출이 Shadow
        sys.exit(f"[extract] 오류: {src} 에서 API 라우트 0개 — 소스 경로·구조 확인 (빈 기준선은 만들지 않는다)")
    pages = pages_from_code(src)
    used = calls_from_frontend(src)

    # 자동화(재실행) 때: 이전에 사람이 확정한 decision·owner·note 는 그대로 이어받는다.
    # 새로 생긴 엔드포인트는 추천값과 상관없이 review → 사람이 승인해야 기준선에 들어간다.
    prev = None
    if "--prev" in args:
        prev = {r["endpoint_key"]: r for r in read_baseline(args[args.index("--prev") + 1])}

    w = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    rows = [(k, "api", *v) for k, v in routes.items()] + [(k, "page", *v) for k, v in pages.items()]
    for key, kind, auth, source in sorted(rows, key=lambda r: (r[1], r[0].split(" ", 1)[1], r[0])):
        frontend = "-" if kind == "page" else ("y" if key in used else "n")
        in_spec = "" if spec is None else ("y" if key in spec else "n")
        decision, note = suggest(kind, frontend, in_spec, bool(spec and spec.get(key)))
        owner = ""
        if prev is not None:
            if key in prev:
                decision, owner, note = prev[key]["decision"], prev[key]["owner"], prev[key]["note"]
            else:
                decision, note = "review", f"신규 — 승인 필요 (자동 추천: {decision}, {note})"
                print(f"[신규] 이전 기준선에 없던 엔드포인트: {key}", file=sys.stderr)
        w.writerow({"endpoint_key": key, "kind": kind, "auth": auth, "frontend": frontend,
                    "in_spec": in_spec, "source": source, "decision": decision, "owner": owner, "note": note})

    if prev is not None:
        for key in sorted(set(prev) - {r[0] for r in rows}):
            print(f"[삭제] 코드에서 사라진 엔드포인트 (새 기준선에서 빠짐): {key}", file=sys.stderr)

    # 프런트는 부르는데 서버 코드에 없는 경로 = 깨진 호출이거나 추출 규칙 누락
    for key in sorted(used - set(routes)):
        print(f"[경고] 프런트 호출이 서버 라우트에 없음: {key}", file=sys.stderr)
    if spec is not None:
        for key in sorted(set(spec) - set(routes)):
            print(f"[경고] 명세에는 있는데 코드에 없음(미구현/삭제됨): {key}", file=sys.stderr)


# ── 3) inventory ─────────────────────────────────────────────────────────────
def read_baseline(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        if r["decision"] not in DECISIONS:
            sys.exit(f"decision 값이 잘못됨: {r['endpoint_key']} → '{r['decision']}' ({'/'.join(sorted(DECISIONS))})")
    return rows


def cmd_inventory(args):
    rows = read_baseline(args[0])
    service, owner = args[1], args[2]
    pending = [r["endpoint_key"] for r in rows if r["decision"] == "review"]
    for r in rows:
        if r["decision"] not in ("active", "deprecated"):
            continue  # exclude·review 는 인벤토리에 넣지 않는다 → 관측되면 shadow
        doc = {"endpoint_key": r["endpoint_key"], "service": service,
               "owner": r["owner"] or owner, "status": r["decision"]}
        print(json.dumps({"index": {}}))
        print(json.dumps(doc, ensure_ascii=False))
    if pending:
        print(f"[주의] 검토가 끝나지 않은 {len(pending)}건은 제외했습니다(관측되면 shadow): "
              + ", ".join(pending), file=sys.stderr)


# ── 4) observe ───────────────────────────────────────────────────────────────
ACCESS_LINE = re.compile(r'"(\w+) (\S+) HTTP/[\d.]+" (\d{3}) ')


def cmd_observe(args):
    rows = read_baseline(args[0])
    status_of = {r["endpoint_key"]: r["decision"] for r in rows}
    hits = defaultdict(Counter)  # endpoint_key → {상태코드 앞자리: 건수}
    for log in args[1:]:
        with open(log, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = ACCESS_LINE.search(line)
                if not m:
                    continue
                path = m.group(2).split("?", 1)[0]
                if STATIC_EXT.search(path) or path.startswith("/assets/"):
                    continue
                hits[f"{m.group(1).upper()} {normalize(path)}"][m.group(3)[0] + "xx"] += 1

    def label(key):
        d = status_of.get(key)
        if d == "active":
            return "documented"
        if d == "deprecated":
            return "ZOMBIE"
        if d in ("review", "exclude"):
            return "SHADOW(코드에 있음)"
        # 코드에도 없는 경로: 앱이 응답(2xx/3xx/5xx)했다면 추출 누락·숨은 경로, 전부 404/403 이면 스캔·차단
        c = hits[key]
        return "SHADOW(코드 밖)" if sum(v for k, v in c.items() if k not in ("4xx",)) else "noise(4xx만)"

    order = {"ZOMBIE": 0, "SHADOW(코드 밖)": 1, "SHADOW(코드에 있음)": 2, "documented": 3, "noise(4xx만)": 4}
    print(f"{'분류':<20} {'건수':>6}  상태코드        endpoint_key")
    for key in sorted(hits, key=lambda k: (order[label(k)], -sum(hits[k].values()))):
        codes = " ".join(f"{k}:{v}" for k, v in sorted(hits[key].items()))
        print(f"{label(key):<20} {sum(hits[key].values()):>6}  {codes:<15} {key}")

    unseen = [r["endpoint_key"] for r in rows if r["decision"] == "active" and r["endpoint_key"] not in hits]
    if unseen:
        print(f"\n[참고] 기준선(active)인데 로그 기간 중 호출 0건 {len(unseen)}개 — 미사용 후보: " + ", ".join(unseen))


# ── 5) cyclonedx ─────────────────────────────────────────────────────────────
# CycloneDX 1.6 services 로 기준선을 표현한다 (https://cyclonedx.org/docs/1.6/json/#services)
#   그룹 서비스(shop-api-v2 등) 아래에 operation 하나당 서비스 하나를 중첩한다.
#   CycloneDX endpoints 는 URL만 담고 HTTP 메서드 칸이 없으므로, 메서드·상태 등은 properties(sesac:*)로 넣는다.
SPEC_VERSION = "1.6"
TOOL_VERSION = "1.2"
OBSERVED_AS = {"active": "documented", "deprecated": "zombie", "review": "shadow", "exclude": "shadow"}

# 경로 → 데이터 분류 (위에서부터 먼저 맞는 것). 팀 정책에 맞게 고쳐 쓴다.
DATA_CLASS = [
    (r"/(users|signup|login)\b", "PII"),
    (r"/(orders|cart)\b", "customer-transaction"),
    (r"/diagnostics\b", "system"),
    (r".*", "public"),
]


def group_of(row):
    """endpoint_key → (그룹 이름, 그룹 경로)  예: GET /api/v2/cart → ('shop-api-v2', '/api/v2')"""
    path = row["endpoint_key"].split(" ", 1)[1]
    m = re.match(r"(/api/v\d+)", path)
    if row["kind"] == "page" or not m:
        return "shop-web-pages", "/"
    return f"shop-{m.group(1).strip('/').replace('/', '-')}", m.group(1)


def operation_service(row, base_url, owner):
    method, path = row["endpoint_key"].split(" ", 1)
    classification = next(c for rx, c in DATA_CLASS if re.search(rx, path))
    svc = {
        "bom-ref": f"op:{row['endpoint_key']}",
        "provider": {"name": row["owner"] or owner},
        "name": row["endpoint_key"],
        "description": row["note"],
        # {id} 의 중괄호는 URL에 쓸 수 없는 문자라 %7B %7D 로 인코딩한다 (원래 모양은 properties 의 path)
        "endpoints": [base_url + quote(path, safe="/")],
        "x-trust-boundary": True,
        "trustZone": "dmz",
        "data": [{"flow": "outbound" if method == "GET" else "bi-directional", "classification": classification}],
    }
    if row["auth"] in ("required", "none"):
        svc["authenticated"] = row["auth"] == "required"
    props = [
        ("sesac:api:endpoint_key", row["endpoint_key"]),
        ("sesac:api:method", method),
        ("sesac:api:path", path),
        ("sesac:api:kind", row["kind"]),
        ("sesac:baseline:decision", row["decision"]),
        ("sesac:baseline:observed-as", OBSERVED_AS[row["decision"]]),
        ("sesac:source:location", row["source"]),
        ("sesac:frontend:used", row["frontend"]),
    ]
    if row["in_spec"]:
        props.append(("sesac:openapi:present", row["in_spec"]))
    svc["properties"] = [{"name": n, "value": v} for n, v in props]
    return svc


def git_version(src):
    # 스냅샷(git 이 아닌 복사본)으로 재현할 때는 API_BOM_SRC_VERSION 으로 원래 커밋을 준다
    if os.environ.get("API_BOM_SRC_VERSION"):
        return os.environ["API_BOM_SRC_VERSION"]
    try:
        out = subprocess.run(["git", "-C", str(src), "log", "-1", "--format=%h", "--", "."],
                             capture_output=True, text=True, check=True).stdout.strip()
        return out or "unknown"
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def cmd_cyclonedx(args):
    rows = read_baseline(args[0])
    src = Path(args[1])
    opt = lambda name, default: args[args.index(name) + 1] if name in args else default
    base_url = opt("--base-url", "http://192.168.0.141:8000").rstrip("/")
    owner = opt("--owner", "웹팀")

    app = {"type": "application", "bom-ref": "app:sesac-shop", "group": "sesac-nobreak-team-one",
           "name": "sesac-shop", "version": git_version(src),
           "description": "쇼핑몰 웹 애플리케이션 (Apache/PHP, web/src)"}
    sbom_path = opt("--sbom", None)
    if sbom_path:
        # BOM-Link: urn:cdx:<serialNumber의 uuid>/<version>#<bom-ref> — 이미지 SBOM의 그 컴포넌트를 가리킨다
        sbom = json.loads(Path(sbom_path).read_text(encoding="utf-8"))
        link = f"urn:cdx:{sbom['serialNumber'].removeprefix('urn:uuid:')}/{sbom.get('version', 1)}"
        ref = (sbom.get("metadata", {}).get("component") or {}).get("bom-ref")
        app["externalReferences"] = [{
            "type": "bom", "url": link + (f"#{ref}" if ref else ""),
            "comment": f"이 서비스를 실행하는 이미지의 SBOM ({Path(sbom_path).name})",
        }]

    groups = {}
    for row in rows:
        name, prefix = group_of(row)
        g = groups.setdefault(name, {
            "bom-ref": f"svc:{name}", "provider": {"name": owner}, "group": "sesac-shop", "name": name,
            "endpoints": [base_url + (prefix if prefix != "/" else "/")],
            "x-trust-boundary": True, "trustZone": "dmz", "services": [],
        })
        g["services"].append(operation_service(row, base_url, owner))

    pending = sum(r["decision"] == "review" for r in rows)
    # 재현 가능한 빌드: SOURCE_DATE_EPOCH(reproducible-builds.org 관례)가 있으면 시각을 고정하고,
    # serialNumber 도 내용에서 결정적으로 만든다(uuid5) → 같은 입력이면 바이트 단위로 같은 BOM.
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    built_at = datetime.fromtimestamp(int(epoch), timezone.utc) if epoch else datetime.now(timezone.utc)
    bom = {
        "$schema": f"http://cyclonedx.org/schema/bom-{SPEC_VERSION}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": None,  # 아래에서 채움
        "version": 1,
        "metadata": {
            "timestamp": built_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            # 소스 코드에서 뽑은 것(빌드 전) — 트래픽에서 뽑았다면 discovery 단계가 된다
            "lifecycles": [{"phase": "pre-build"}],
            "tools": {"components": [{"type": "application", "name": "source_to_baseline.py",
                                      "version": TOOL_VERSION, "group": "sesac-nobreak-team-one"}]},
            "component": app,
            "properties": [
                {"name": "sesac:baseline:csv", "value": Path(args[0]).name},
                {"name": "sesac:baseline:operations", "value": str(len(rows))},
                {"name": "sesac:baseline:review-pending", "value": str(pending)},
            ],
        },
        "services": list(groups.values()),
        # 각 서비스는 쇼핑몰 애플리케이션(→ 이미지 SBOM) 위에서 돈다
        "dependencies": [{"ref": "app:sesac-shop"}]
                        + [{"ref": g["bom-ref"], "dependsOn": ["app:sesac-shop"]} for g in groups.values()],
    }
    serial = (uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(bom, ensure_ascii=False, sort_keys=True))
              if epoch else uuid.uuid4())
    bom["serialNumber"] = f"urn:uuid:{serial}"
    print(json.dumps(bom, ensure_ascii=False, indent=2))
    if pending:
        print(f"[주의] decision=review 가 {pending}건 남아 있습니다 (BOM에는 observed-as=shadow 로 기록).", file=sys.stderr)


# ── 6) validate ──────────────────────────────────────────────────────────────
def cmd_validate(args):
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        sys.exit('검증 라이브러리가 없습니다: python -m pip install "cyclonedx-python-lib[json-validation]"')
    text = Path(args[0]).read_text(encoding="utf-8")
    version = json.loads(text).get("specVersion", SPEC_VERSION)
    error = JsonStrictValidator(SchemaVersion.from_version(version)).validate_str(text)
    if error:
        detail = getattr(error.data, "message", str(error).splitlines()[0])
        where = "/".join(map(str, getattr(error.data, "absolute_path", [])))
        sys.exit(f"[실패] CycloneDX {version} 스키마 위반: {detail} (위치: {where or '-'})")
    print(f"[통과] CycloneDX {version} 공식 JSON 스키마(strict) 검증 통과: {args[0]}")


# ── 7) openapi ───────────────────────────────────────────────────────────────
def cmd_openapi(args):
    """BOM → OpenAPI 3.0 허용 목록. 팀 detection/shadow_api/gen_shadow_rules.py 의 --spec 으로 그대로 넣는다.

    허용 목록에는 decision=active 인 API만 넣는다.
      - deprecated : 빠짐 → 호출되면 Wazuh 경보 (zombie 도 경보 대상)
      - review/exclude : 빠짐 → 호출되면 Wazuh 경보 (shadow)
      - page(.php 화면) : 룰 생성기가 /api 만 보므로 넣지 않는다
    출력은 JSON 이다. JSON 은 YAML 의 부분집합이라 룰 생성기(yaml.safe_load)가 그대로 읽는다.
    """
    bom = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    prop = lambda svc, name: next((p["value"] for p in svc.get("properties", []) if p["name"] == name), None)

    paths, skipped = {}, Counter()
    for group in bom.get("services", []):
        for svc in group.get("services", []):
            decision = prop(svc, "sesac:baseline:decision")
            if prop(svc, "sesac:api:kind") != "api" or decision != "active":
                skipped[decision if prop(svc, "sesac:api:kind") == "api" else "page"] += 1
                continue
            method, path = prop(svc, "sesac:api:method").lower(), prop(svc, "sesac:api:path")
            op = {"summary": svc["name"], "x-bom-ref": svc["bom-ref"],
                  "responses": {"default": {"description": "see CycloneDX API-BOM"}}}
            if svc.get("authenticated"):
                op["security"] = [{"bearerAuth": []}]
            paths.setdefault(path, {})[method] = op

    app = bom["metadata"]["component"]
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": f"{app['name']} — CycloneDX API-BOM 에서 생성한 허용 목록",
            "version": app.get("version", "unknown"),
            "description": f"원본 BOM {bom['serialNumber']} (version {bom['version']}). 직접 고치지 말고 baseline.csv 를 고칠 것.",
        },
        "servers": [{"url": "/"}],
        "paths": dict(sorted(paths.items())),
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    }
    print(json.dumps(spec, ensure_ascii=False, indent=2))
    ops = sum(len(v) for v in paths.values())
    print(f"[openapi] 허용 {ops}개 operation · 제외 " + ", ".join(f"{k} {v}" for k, v in sorted(skipped.items())),
          file=sys.stderr)


def main():
    # Windows 콘솔(cp949)에서도 한글 경고·CSV가 깨지지 않게 UTF-8로 고정
    # 줄바꿈도 LF로 고정 — Windows 기본(CRLF)이면 OS마다 출력 바이트가 달라져 룰 생성기의 명세 해시가 달라진다
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8")
    commands = {"extract": cmd_extract, "inventory": cmd_inventory, "observe": cmd_observe,
                "cyclonedx": cmd_cyclonedx, "validate": cmd_validate, "openapi": cmd_openapi}
    if len(sys.argv) < 3 or sys.argv[1] not in commands:
        sys.exit(__doc__)
    if sys.argv[1] in ("inventory", "cyclonedx") and len(sys.argv) < (5 if sys.argv[1] == "inventory" else 4):
        sys.exit(__doc__)
    commands[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()
