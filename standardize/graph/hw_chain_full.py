"""
소프트웨어 → 커널 → 하드웨어 체인 — 전체 패키지 + 계층 간 연결선
swim lane (모든 패키지 뱃지) + 런타임 SVG 화살표 (핵심 연결만)
"""

import json
import sys
from pathlib import Path

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

TIER_META = {
    -1: ("#c0392b", "◆ Hardware (virtual)",   "실제 하드웨어 장치"),
     0: ("#e74c3c", "Tier 0 — HW Interface",  "커널-하드웨어 직접 인터페이스"),
     1: ("#e67e22", "Tier 1 — Kernel ABI",    "syscall 래퍼 · C 런타임"),
     2: ("#3498db", "Tier 2 — System",        "시스템 서비스 계층"),
     3: ("#2ecc71", "Tier 3 — Application",   "애플리케이션"),
     9: ("#7f8c8d", "Other",                  "미분류"),
}

VIRTUAL_HW = [
    {"name": "CPU / Memory",   "id": "hw_cpu"},
    {"name": "Network Card",   "id": "hw_nic"},
    {"name": "Block Storage",  "id": "hw_disk"},
    {"name": "Audit Subsystem","id": "hw_audit"},
]

# 핵심 연결: (from_name, to_name, label)
# name은 패키지 이름 또는 가상HW id와 일치
KEY_CONNECTIONS = [
    ("hw_cpu",   "libc6",         "syscall"),
    ("hw_cpu",   "libgcc-10-base","ABI"),
    ("hw_nic",   "libcurl4",      "socket"),
    ("hw_disk",  "libblkid1",     "blkid"),
    ("hw_disk",  "e2fsprogs",     "fs ops"),
    ("hw_audit", "libaudit1",     "audit"),
    ("hw_audit", "libcap-ng0",    "caps"),
    ("libc6",        "apache2",       "runtime"),
    ("libc6",        "libssl1.1",     "runtime"),
    ("libcrypt1",    "libssl1.1",     "crypto"),
    ("libgcc-10-base","apache2",      "compiler rt"),
    ("apache2",      "php",           "mod_php"),
    ("libssl1.1",    "firebase/php-jwt","TLS"),
    ("libacl1",      "libc6",         "POSIX ACL"),
    ("e2fsprogs",    "libc6",         "fs util"),
]


def classify(name: str) -> int:
    n = name.lower()
    for tier, kws in TIER_RULES:
        if any(k in n for k in kws):
            return tier
    return 9


def main(sbom_path: str, out_path: str):
    sbom = json.loads(Path(sbom_path).read_text(encoding="utf-8"))
    comps = [c for c in sbom.get("components", [])
             if c.get("type") in ("library", "application", "operating-system")]

    tiers: dict[int, list[dict]] = {t: [] for t in [-1, 0, 1, 2, 3, 9]}
    tiers[-1] = [{"name": h["name"], "id": h["id"]} for h in VIRTUAL_HW]

    for c in comps:
        name = c.get("name", "")
        tier = classify(name)
        tiers[tier].append({"name": name, "version": c.get("version", ""), "id": name})

    # 계층별 뱃지 HTML
    def tier_section(tier: int) -> str:
        color, label, desc = TIER_META[tier]
        nodes = sorted(tiers[tier], key=lambda x: x["name"])
        if not nodes:
            return ""
        badge_html = ""
        for n in nodes:
            nid = n["id"]
            ver = n.get("version", "")
            badge_html += (
                f'<span class="badge" data-pkg="{nid}" '
                f'style="background:{color}" title="{ver}">'
                f'{n["name"]}'
                + (f'<small>{ver}</small>' if ver else "")
                + "</span>"
            )
        return f"""
<div class="tier-row" data-tier="{tier}">
  <div class="tier-hdr" style="border-left:4px solid {color};background:{color}18">
    <span class="tier-lbl" style="color:{color}">{label}</span>
    <span class="tier-cnt">{len(nodes)}개</span>
    <span class="tier-dsc">{desc}</span>
  </div>
  <div class="tier-body" id="tier{tier}">{badge_html}</div>
</div>
<div class="tier-arrow">▼</div>"""

    tiers_html = ""
    for t in [-1, 0, 1, 2, 3]:
        tiers_html += tier_section(t)
    # Other는 접을 수 있게
    color, label, desc = TIER_META[9]
    other_nodes = sorted(tiers[9], key=lambda x: x["name"])
    other_badges = "".join(
        f'<span class="badge" data-pkg="{n["name"]}" style="background:{color}" '
        f'title="{n.get("version","")}">{n["name"]}'
        + (f'<small>{n.get("version","")}</small>' if n.get("version") else "")
        + "</span>"
        for n in other_nodes
    )
    tiers_html += f"""
<details style="margin-top:8px">
  <summary style="cursor:pointer;padding:8px 16px;background:#1b2029;border:1px solid #2a313d;border-radius:8px;color:#9aa4b2">
    {label} — {len(other_nodes)}개 (클릭해서 펼치기)
  </summary>
  <div class="tier-row" style="margin-top:4px" data-tier="9">
    <div class="tier-body" id="tier9">{other_badges}</div>
  </div>
</details>"""

    # KPI 카드
    kpi_cards = "".join(
        f'<div class="k"><div class="kl">{TIER_META[t][1]}</div>'
        f'<div class="kv" style="color:{TIER_META[t][0]}">{len(tiers[t])}</div></div>'
        for t in [-1, 0, 1, 2, 3, 9]
    )

    conns_js = json.dumps(KEY_CONNECTIONS)

    html = f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>SW → Kernel → HW Chain (Full)</title>
<style>
:root{{--bg:#12151c;--card:#1b2029;--ink:#e8ebf1;--sub:#9aa4b2;--line:#2a313d}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--ink);font-family:'Segoe UI',system-ui,sans-serif}}
#wrap{{max-width:1500px;margin:0 auto;padding:20px;position:relative}}
h1{{font-size:17px;margin-bottom:4px}}
.sub{{color:var(--sub);font-size:12px;margin-bottom:14px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-bottom:16px}}
.k{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px}}
.kl{{font-size:11px;color:var(--sub)}}
.kv{{font-size:22px;font-weight:700}}
.tier-row{{border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-bottom:4px}}
.tier-hdr{{padding:8px 14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.tier-lbl{{font-weight:700;font-size:13px;min-width:200px}}
.tier-cnt{{background:#ffffff15;border-radius:10px;padding:1px 8px;font-size:11px}}
.tier-dsc{{font-size:11px;color:var(--sub)}}
.tier-body{{padding:10px 14px;display:flex;flex-wrap:wrap;gap:5px;background:#ffffff04}}
.tier-arrow{{text-align:center;font-size:20px;color:#3a414d;line-height:1.2;margin:2px 0}}
.badge{{
  display:inline-flex;flex-direction:column;padding:3px 9px;border-radius:5px;
  font-size:12px;font-weight:600;color:#fff;cursor:pointer;
  transition:transform .12s,box-shadow .12s;position:relative;
  outline:2px solid transparent;outline-offset:1px;
}}
.badge:hover{{transform:translateY(-2px);box-shadow:0 4px 12px #0005;z-index:5}}
.badge.active{{outline-color:#fff;outline-width:2px;transform:translateY(-2px)}}
.badge.dimmed{{opacity:.25}}
.badge small{{font-size:9px;font-weight:400;opacity:.65}}
/* SVG 오버레이 */
#svg-layer{{
  position:absolute;top:0;left:0;width:100%;height:100%;
  pointer-events:none;z-index:10;overflow:visible;
}}
.conn-line{{stroke-width:1.5;fill:none;opacity:0;transition:opacity .2s}}
.conn-line.visible{{opacity:.6}}
.conn-line.highlight{{opacity:1;stroke-width:2.5}}
</style>
</head>
<body>
<div id="wrap">
  <svg id="svg-layer" aria-hidden="true"></svg>
  <h1>Software → Kernel ABI → Hardware Interface Chain</h1>
  <div class="sub">SBOM(2026-11-07 run0095, Syft, Debian 11) · 모든 패키지 표시 · 화살표 = 핵심 연결</div>
  <div class="kpis">{kpi_cards}</div>
  <div id="lanes">{tiers_html}</div>
</div>

<script>
const CONNECTIONS = {conns_js};

// pkg name → badge element
function getBadge(name) {{
  return document.querySelector('[data-pkg="' + CSS.escape(name) + '"]');
}}

// 두 요소 사이의 중심점 (페이지 기준)
function center(el) {{
  const wrap = document.getElementById('wrap');
  const wr = wrap.getBoundingClientRect();
  const r = el.getBoundingClientRect();
  return {{
    x: r.left - wr.left + r.width / 2,
    y: r.top  - wr.top  + r.height / 2,
  }};
}}

const svg = document.getElementById('svg-layer');
const lineMap = {{}};  // "a->b" → <path>

function TIER_COLOR(tier) {{
  return ['#c0392b','#e74c3c','#e67e22','#3498db','#2ecc71'][tier+1] || '#7f8c8d';
}}

function drawLines() {{
  svg.innerHTML = '';
  // defs: arrowheads per color
  const defs = document.createElementNS('http://www.w3.org/2000/svg','defs');
  const colors = ['#c0392b','#e74c3c','#e67e22','#3498db','#2ecc71','#7f8c8d'];
  colors.forEach(col => {{
    const m = document.createElementNS('http://www.w3.org/2000/svg','marker');
    m.setAttribute('id','arr-'+col.slice(1));
    m.setAttribute('markerWidth','8');m.setAttribute('markerHeight','6');
    m.setAttribute('refX','7');m.setAttribute('refY','3');
    m.setAttribute('orient','auto');
    const p = document.createElementNS('http://www.w3.org/2000/svg','polygon');
    p.setAttribute('points','0 0, 8 3, 0 6');
    p.setAttribute('fill',col);
    m.appendChild(p); defs.appendChild(m);
  }});
  svg.appendChild(defs);

  CONNECTIONS.forEach(([from, to, label]) => {{
    const a = getBadge(from), b = getBadge(to);
    if (!a || !b) return;
    const ca = center(a), cb = center(b);
    const col = a.style.background || '#888';

    // cubic bezier: 중간에 수직 커브
    const mx = (ca.x + cb.x) / 2;
    const d = `M${{ca.x}},${{ca.y}} C${{ca.x}},${{(ca.y+cb.y)/2}} ${{cb.x}},${{(ca.y+cb.y)/2}} ${{cb.x}},${{cb.y}}`;

    const path = document.createElementNS('http://www.w3.org/2000/svg','path');
    path.setAttribute('d', d);
    path.setAttribute('stroke', col);
    path.setAttribute('class','conn-line visible');
    path.setAttribute('marker-end','url(#arr-'+col.slice(1)+')');
    path.dataset.from = from;
    path.dataset.to = to;
    path.dataset.label = label;

    // label
    const txt = document.createElementNS('http://www.w3.org/2000/svg','text');
    txt.setAttribute('x', mx);
    txt.setAttribute('y', (ca.y+cb.y)/2 - 3);
    txt.setAttribute('text-anchor','middle');
    txt.setAttribute('font-size','9');
    txt.setAttribute('fill','#8a8daa');
    txt.setAttribute('class','conn-line visible');
    txt.textContent = label;

    svg.appendChild(path);
    svg.appendChild(txt);
    lineMap[from+'->'+to] = {{path, txt}};
  }});

  // svg 높이 맞추기
  svg.setAttribute('height', document.getElementById('wrap').scrollHeight);
}}

// 호버 인터랙션
let activeEl = null;
document.querySelectorAll('.badge').forEach(b => {{
  b.addEventListener('mouseenter', () => highlight(b.dataset.pkg));
  b.addEventListener('mouseleave', () => clearHighlight());
  b.addEventListener('click', () => {{
    if (activeEl === b) {{ activeEl = null; clearHighlight(); }}
    else {{ activeEl = b; highlight(b.dataset.pkg); }}
  }});
}});

function highlight(name) {{
  const related = new Set([name]);
  CONNECTIONS.forEach(([f,t]) => {{
    if (f===name) related.add(t);
    if (t===name) related.add(f);
  }});
  document.querySelectorAll('.badge').forEach(b => {{
    b.classList.toggle('active', related.has(b.dataset.pkg));
    b.classList.toggle('dimmed', !related.has(b.dataset.pkg));
  }});
  Object.entries(lineMap).forEach(([key, {{path,txt}}]) => {{
    const [f,t] = key.split('->');
    const hl = f===name||t===name;
    path.classList.toggle('highlight', hl);
    txt.classList.toggle('highlight', hl);
    path.style.opacity = hl ? '1' : '0.15';
    txt.style.opacity  = hl ? '1' : '0';
  }});
}}

function clearHighlight() {{
  if (activeEl) return;  // 클릭으로 고정된 경우 유지
  document.querySelectorAll('.badge').forEach(b => {{
    b.classList.remove('active','dimmed');
  }});
  Object.values(lineMap).forEach(({{path,txt}}) => {{
    path.style.opacity = '0.6';
    txt.style.opacity  = '0.7';
  }});
}}

// 초기화 및 리사이즈 대응
window.addEventListener('load', () => {{ drawLines(); }});
window.addEventListener('resize', () => {{ drawLines(); }});
// details 열릴 때 재계산
document.querySelectorAll('details').forEach(d => d.addEventListener('toggle', () => drawLines()));
</script>
</body>
</html>"""

    Path(out_path).write_text(html, encoding="utf-8", newline="\n")

    total = sum(len(v) for v in tiers.values())
    print("=== 계층별 패키지 수 ===")
    for t in [-1, 0, 1, 2, 3, 9]:
        print(f"  {TIER_META[t][1]}: {len(tiers[t])}개")
    print(f"  총계: {total}개")
    print(f"\n출력: {out_path}")


if __name__ == "__main__":
    sbom = sys.argv[1] if len(sys.argv) > 1 else \
        r"D:\project\shadow_api_monitoring\sbom\results\2026-11-07_run0095\sbom-image.cdx.json"
    out = sys.argv[2] if len(sys.argv) > 2 else \
        r"D:\project\shadow_api_monitoring\api-bom\graph\sample\hw_kernel_chain_full.html"
    main(sbom, out)
