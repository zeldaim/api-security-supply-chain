"""
소프트웨어 → 커널 ABI → 하드웨어 인터페이스 체인 대시보드
SBOM(sbom-image.cdx.json)에서 패키지를 계층 분류 후 vis-network 고정 레이아웃으로 출력.
"""

import json
import sys
from pathlib import Path

# ── 계층 분류 ─────────────────────────────────────────────────────────────────
TIER_RULES = [
    (0, ["libblkid", "libudev", "libdevmapper", "libpci",
         "libaudit", "libcap-ng", "libcap",
         "libnl", "libnetfilter", "libnfnetlink",
         "e2fsprogs", "libext2fs", "libcom-err",
         "libacl", "libattr", "libkmod", "kmod"]),
    (1, ["libc6", "libc-bin", "libc-dev", "libc6-dev",
         "libcrypt", "libpthread", "linux-libc-dev",
         "libgcc", "gcc-10-base", "gcc-9-base", "libcc1",
         "libasan", "libatomic", "libctf",
         "init-system-helpers", "dpkg", "libdpkg",
         "base-files", "base-passwd", "debianutils"]),
    (2, ["openssl", "libssl", "libcrypto",
         "apache2", "libapr", "libaprutil",
         "libcurl", "curl", "libsqlite", "sqlite3",
         "libbrotli", "libexpat", "libxml",
         "libz", "zlib", "gzip", "bzip2",
         "libdb5", "libgdbm", "ca-certificates",
         "libargon2", "libsodium", "libpcre", "libonig",
         "libreadline", "libtinfo", "libncurses",
         "libtirpc", "libbinutils", "binutils",
         "gcc", "cpp", "g++", "libgomp"]),
    (3, ["php", "pear", "archive_tar", "console_getopt",
         "structures_graph", "xml_util",
         "firebase", "php-jwt", "composer"]),
]

TIER_COLOR = {
    -1: "#c0392b",
     0: "#e74c3c",
     1: "#e67e22",
     2: "#3498db",
     3: "#2ecc71",
     9: "#7f8c8d",
}

TIER_LABEL = {
    -1: "Hardware (virtual)",
     0: "Tier 0 — HW Interface",
     1: "Tier 1 — Kernel ABI",
     2: "Tier 2 — System Services",
     3: "Tier 3 — Application",
     9: "Other",
}

VIRTUAL_HW = [
    {"id": "hw_cpu",   "label": "CPU / Memory",   "tier": -1},
    {"id": "hw_nic",   "label": "Network Card",    "tier": -1},
    {"id": "hw_disk",  "label": "Block Storage",   "tier": -1},
    {"id": "hw_audit", "label": "Audit Subsystem", "tier": -1},
]

HW_EDGES = [
    ("hw_cpu",   "libc6"),
    ("hw_cpu",   "libgcc"),
    ("hw_nic",   "libcurl4"),
    ("hw_disk",  "libblkid1"),
    ("hw_disk",  "e2fsprogs"),
    ("hw_audit", "libaudit1"),
    ("hw_audit", "libcap-ng0"),
]

MAX_GRAPH_PER_TIER = 15


def classify(name: str) -> int:
    n = name.lower()
    for tier, kws in TIER_RULES:
        if any(k in n for k in kws):
            return tier
    return 9


def spread_x(count: int, spacing: int = 220) -> list[float]:
    half = (count - 1) / 2
    return [(i - half) * spacing for i in range(count)]


def build(sbom_path: str, out_path: str):
    sbom = json.loads(Path(sbom_path).read_text(encoding="utf-8"))
    raw_comps = [c for c in sbom.get("components", [])
                 if c.get("type") in ("library", "application", "operating-system")]

    # 분류
    tier_buckets: dict[int, list[dict]] = {t: [] for t in [0, 1, 2, 3, 9]}
    pkg_id_map: dict[str, dict] = {}  # bom-ref → pkg info

    for c in raw_comps:
        name = c.get("name", "")
        tier = classify(name)
        node_id = "pkg:" + (c.get("bom-ref") or name)
        info = {
            "id": node_id,
            "bom_ref": c.get("bom-ref", ""),
            "label": name,
            "version": c.get("version", ""),
            "pkg_type": c.get("type", ""),
            "tier": tier,
            "color": TIER_COLOR[tier],
        }
        tier_buckets.setdefault(tier, []).append(info)
        pkg_id_map[c.get("bom-ref", name)] = info

    # 그래프용 노드 (각 tier 최대 MAX_GRAPH_PER_TIER)
    graph_nodes = list(VIRTUAL_HW)  # hw virtual nodes
    graph_node_ids: set[str] = {h["id"] for h in VIRTUAL_HW}

    TIER_Y = {-1: 0, 0: 200, 1: 400, 2: 600, 3: 800}
    for tier in [0, 1, 2, 3]:
        bucket = tier_buckets.get(tier, [])
        selected = bucket[:MAX_GRAPH_PER_TIER]
        xs = spread_x(len(selected))
        for i, pkg in enumerate(selected):
            graph_nodes.append({**pkg, "x": xs[i], "y": TIER_Y[tier]})
            graph_node_ids.add(pkg["id"])

    # HW 가상 노드 위치
    hw_xs = spread_x(len(VIRTUAL_HW), spacing=300)
    for i, hw in enumerate(graph_nodes[:4]):
        hw["x"] = hw_xs[i]
        hw["y"] = 0

    # SBOM 의존성 엣지
    sbom_deps = sbom.get("dependencies", [])
    edges = []
    seen_edges: set[tuple] = set()

    for dep in sbom_deps:
        ref = dep.get("ref", "")
        src_id = "pkg:" + ref
        if src_id not in graph_node_ids:
            continue
        for dep_ref in dep.get("dependsOn", []):
            tgt_id = "pkg:" + dep_ref
            if tgt_id not in graph_node_ids:
                continue
            key = (src_id, tgt_id)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"from": src_id, "to": tgt_id, "label": "dep", "color": "#4a5568"})

    # HW → Tier-0 엣지
    name_to_id: dict[str, str] = {n["label"].lower(): n["id"] for n in graph_nodes}
    for hw_id, pkg_name in HW_EDGES:
        tgt = name_to_id.get(pkg_name.lower())
        if tgt:
            edges.append({"from": hw_id, "to": tgt, "label": "device", "color": "#c0392b"})

    # Tier 간 대표 연결 (상위 3개씩)
    def top_ids(tier: int, n: int = 3):
        return [p["id"] for p in tier_buckets.get(tier, [])[:n] if p["id"] in graph_node_ids]

    for src_tier, dst_tier, lbl in [(0, 1, "syscall"), (1, 2, "link"), (2, 3, "runtime")]:
        srcs, dsts = top_ids(src_tier), top_ids(dst_tier)
        for s, d in zip(srcs, dsts):
            key = (s, d)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"from": s, "to": d, "label": lbl, "color": "#4a5568"})

    # KPI 집계
    kpis = {
        "hw_virtual": len(VIRTUAL_HW),
        "tier0": len(tier_buckets.get(0, [])),
        "tier1": len(tier_buckets.get(1, [])),
        "tier2": len(tier_buckets.get(2, [])),
        "tier3": len(tier_buckets.get(3, [])),
        "other": len(tier_buckets.get(9, [])),
        "total": len(raw_comps),
    }

    # 전체 테이블용 (모든 패키지)
    all_pkgs = []
    for tier in [0, 1, 2, 3, 9]:
        for p in tier_buckets.get(tier, []):
            all_pkgs.append(p)

    _write_html(graph_nodes, edges, kpis, all_pkgs, out_path)

    print("=== 계층별 패키지 수 ===")
    for t, lbl in TIER_LABEL.items():
        cnt = kpis.get({-1:"hw_virtual",0:"tier0",1:"tier1",2:"tier2",3:"tier3",9:"other"}[t], 0)
        if cnt:
            print(f"  {lbl}: {cnt}개")
    print(f"\n출력: {out_path}")


def _write_html(graph_nodes, edges, kpis, all_pkgs, out_path):
    nodes_js = json.dumps([
        {
            "id": n["id"],
            "label": n["label"],
            "title": f"{n['label']} {n.get('version','')}\n계층: {TIER_LABEL.get(n['tier'], '?')}",
            "x": n.get("x", 0),
            "y": n.get("y", 0),
            "fixed": True,
            "shape": "diamond" if n["tier"] == -1 else "box",
            "color": n.get("color", TIER_COLOR.get(n.get("tier", 9), "#7f8c8d")),
            "font": {"color": "#fff", "size": 12},
            "size": 20 if n["tier"] == -1 else 14,
        }
        for n in graph_nodes
    ], ensure_ascii=False)

    edges_js = json.dumps([
        {
            "from": e["from"], "to": e["to"],
            "label": e.get("label", ""),
            "color": {"color": e.get("color", "#4a5568"), "opacity": 0.7},
            "arrows": "to",
            "smooth": {"type": "cubicBezier", "forceDirection": "vertical"},
            "width": 0.8,
            "font": {"size": 9, "color": "#888"},
        }
        for e in edges
    ], ensure_ascii=False)

    legend_items = [
        ("#c0392b", "◆ Hardware (virtual)"),
        ("#e74c3c", "■ Tier 0 HW Interface"),
        ("#e67e22", "■ Tier 1 Kernel ABI"),
        ("#3498db", "■ Tier 2 System"),
        ("#2ecc71", "■ Tier 3 App"),
        ("#7f8c8d", "■ Other"),
    ]
    legend_html = "".join(
        f'<span style="color:{c};margin-right:12px;font-size:12px">{lbl}</span>'
        for c, lbl in legend_items
    )

    kpi_html = "".join([
        f'<div class="k"><div class="kl">HW (virtual)</div><div class="kv" style="color:#c0392b">{kpis["hw_virtual"]}</div><div class="ks">CPU·NIC·Disk·Audit</div></div>',
        f'<div class="k"><div class="kl">Tier 0 — HW Interface</div><div class="kv" style="color:#e74c3c">{kpis["tier0"]}</div><div class="ks">libblkid, libaudit …</div></div>',
        f'<div class="k"><div class="kl">Tier 1 — Kernel ABI</div><div class="kv" style="color:#e67e22">{kpis["tier1"]}</div><div class="ks">libc6, libgcc …</div></div>',
        f'<div class="k"><div class="kl">Tier 2 — System</div><div class="kv" style="color:#3498db">{kpis["tier2"]}</div><div class="ks">apache2, openssl …</div></div>',
        f'<div class="k"><div class="kl">Tier 3 — App</div><div class="kv" style="color:#2ecc71">{kpis["tier3"]}</div><div class="ks">php, php-jwt …</div></div>',
        f'<div class="k"><div class="kl">총 패키지</div><div class="kv">{kpis["total"]}</div><div class="ks">Other {kpis["other"]}개 포함</div></div>',
    ])

    tier_color_map = {t: TIER_COLOR[t] for t in TIER_COLOR}
    table_rows = ""
    for p in all_pkgs:
        c = tier_color_map.get(p["tier"], "#7f8c8d")
        lbl = TIER_LABEL.get(p["tier"], "Other")
        node_id = p["id"].replace('"', '\\"')
        table_rows += (
            f'<tr data-id="{node_id}" style="border-left:3px solid {c}">'
            f'<td style="color:{c}">{lbl}</td>'
            f'<td><code>{p["label"]}</code></td>'
            f'<td>{p.get("version","")}</td>'
            f'<td>{p.get("pkg_type","")}</td>'
            f'</tr>\n'
        )

    html = f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SW → Kernel → HW Chain</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/vis-network.min.js"></script>
<style>
:root{{--bg:#12151c;--card:#1b2029;--ink:#e8ebf1;--sub:#9aa4b2;--line:#2a313d}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:system-ui,'Malgun Gothic',sans-serif;background:var(--bg);color:var(--ink)}}
main{{max-width:1600px;margin:0 auto;padding:16px}}
h1{{font-size:20px;margin:4px 0 2px}}
.sub{{color:var(--sub);font-size:13px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:14px 0}}
.k{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}}
.kl{{font-size:12px;color:var(--sub)}}
.kv{{font-size:26px;font-weight:700}}
.ks{{font-size:12px;color:var(--sub)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;margin:12px 0}}
#g{{height:700px}}
.lg{{margin-bottom:8px;font-size:12px}}
.btns{{margin-bottom:8px}}
.btns button{{font-size:12px;margin-right:6px;background:#2a313d;color:var(--ink);border:1px solid var(--line);padding:4px 10px;border-radius:4px;cursor:pointer}}
.btns button:hover{{background:#3a414d}}
table{{border-collapse:collapse;width:100%;font-size:12.5px}}
th,td{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}}
th{{color:var(--sub);font-weight:600}}
tr{{cursor:pointer}}
tr:hover td{{background:rgba(255,255,255,.04)}}
.wrap{{overflow-x:auto}}
</style>
</head>
<body>
<main>
<h1>Software → Kernel ABI → Hardware Interface Chain</h1>
<div class="sub">SBOM(2026-11-07 run0095, Syft, Debian 11) 기반 · 패키지를 4계층으로 분류 · 그래프는 tier당 최대 15개 · 전체 목록은 하단 테이블</div>
<div class="kpis">{kpi_html}</div>
<div class="card">
  <div class="lg">{legend_html}<br>노드 클릭 → 연결 경로 강조 · 빈 곳 클릭 → 전체 보기</div>
  <div class="btns">
    <button id="all">전체 보기</button>
    <button id="fit">화면 맞춤</button>
  </div>
  <div id="g"></div>
</div>
<div class="card">
  <h3 style="margin:4px 0 10px">전체 패키지 목록</h3>
  <div class="wrap">
  <table>
  <tr><th>계층</th><th>패키지</th><th>버전</th><th>타입</th></tr>
  {table_rows}
  </table>
  </div>
</div>
</main>
<script>
const N=new vis.DataSet({nodes_js});
const E=new vis.DataSet({edges_js});
const net=new vis.Network(document.getElementById('g'),{{nodes:N,edges:E}},{{
  physics:false,
  edges:{{color:{{opacity:.6}},smooth:{{type:'cubicBezier',forceDirection:'vertical'}},width:.8}},
  nodes:{{font:{{size:12,color:'#e8ebf1'}},borderWidth:1}},
  interaction:{{hover:true,tooltipDelay:80,navigationButtons:true,zoomView:true}}
}});
const out={{}},inn={{}};
E.forEach(e=>{{(out[e.from]=out[e.from]||[]).push(e.to);(inn[e.to]=inn[e.to]||[]).push(e.from)}});
function reach(id,adj){{const s=new Set([id]),q=[id];while(q.length){{for(const n of(adj[q.pop()]||[]))if(!s.has(n)){{s.add(n);q.push(n)}}}}return s}}
function focus(id){{
  const k=new Set([...reach(id,out),...reach(id,inn)]);
  N.update(N.get().map(n=>({{'id':n.id,'opacity':k.has(n.id)?1:.1}})));
  E.update(E.get().map(e=>({{'id':e.id,'hidden':!(k.has(e.from)&&k.has(e.to))}})));
}}
function all(){{
  N.update(N.get().map(n=>({{'id':n.id,'opacity':1}})));
  E.update(E.get().map(e=>({{'id':e.id,'hidden':false}})));
}}
net.on('click',p=>p.nodes.length?focus(p.nodes[0]):all());
document.getElementById('all').onclick=all;
document.getElementById('fit').onclick=()=>net.fit();
document.querySelectorAll('tr[data-id]').forEach(tr=>tr.onclick=()=>{{
  const id=tr.dataset.id;
  focus(id);
  if(N.get(id)){{net.selectNodes([id]);net.focus(id,{{scale:1.2,animation:true}});document.getElementById('g').scrollIntoView({{behavior:'smooth'}})}}
}});
</script>
</body>
</html>"""

    Path(out_path).write_text(html, encoding="utf-8", newline="\n")
    print(f"출력: {out_path}")


if __name__ == "__main__":
    sbom = sys.argv[1] if len(sys.argv) > 1 else \
        r"D:\project\shadow_api_monitoring\sbom\results\2026-11-07_run0095\sbom-image.cdx.json"
    out = sys.argv[2] if len(sys.argv) > 2 else \
        r"D:\project\shadow_api_monitoring\api-bom\graph\sample\hw_kernel_chain.html"
    build(sbom, out)
