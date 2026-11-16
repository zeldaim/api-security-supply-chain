#!/usr/bin/env python3
"""[도달성 대시보드] reachability.py 결과 폴더 → reach_dashboard.html (파일 하나, 외부 라이브러리 없음, 서버 불필요).

    python api-bom/reach/reach_dashboard.py [결과 폴더]      # 기본: api-bom/reach/results/<최신>

화면 (운영에서 묻는 순서)
  1. 요약 — 고유 Critical·High CVE 중 닿음/닿지 않음
  2. 영향 조회 — CVE 번호·부품 이름 → 영향받는 엔드포인트 + 근거(file:line)   ← 새 CVE 가 떴을 때
  3. 엔드포인트 × 부품 — 어느 API 가 어느 부품에 닿나 (런타임 공통 제외)
  4. 취약 부품 — 닿음 / 런타임 공통 / 닿지 않음(VEX not_affected 후보)
reachability.py 가 끝날 때 자동으로 부른다.
"""
import csv
import glob
import html
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def build(out):
    reach = json.load(open(os.path.join(out, "reach.json"), encoding="utf-8"))
    comps = list(csv.DictReader(open(os.path.join(out, "components.csv"), encoding="utf-8")))
    cves = list(csv.DictReader(open(os.path.join(out, "cve_reach.csv"), encoding="utf-8")))
    feats = json.load(open(os.path.join(HERE, "features.json"), encoding="utf-8"))
    runtime = set(feats["runtime"]["components"]) | {c for m in feats["runtime"].get("apache_modules", {}).values() for c in m["components"]}

    eps = reach["endpoints"]
    extra_cols = []
    for e in eps:
        for c in e["components"]:
            if c not in runtime and c not in extra_cols:
                extra_cols.append(c)
    data = {
        "endpoints": [{"k": e["endpoint_key"], "where": e["where"], "auth": e["auth"], "n": len(e["reached_methods"]),
                       "unres": len(e["unresolved"]), "crit": len(e["critical"]), "high": len(e["high"]),
                       "comps": {c: v for c, v in e["components"].items()}} for e in eps],
        "components": [{"c": r["component"], "crit": int(r["critical"]), "high": int(r["high"]), "n": int(r["reached_by_n"]),
                        "by": [x for x in r["reached_by"].split(";") if x], "rt": r["component"] in runtime} for r in comps],
        "cves": [{"id": r["vulnId"], "sev": r["severity"], "comps": r["components"].split(";"), "reached": r["reached"] == "True",
                  "via": [x for x in r["reached_via"].split(";") if x]} for r in cves],
        "cols": extra_cols, "runtime": sorted(runtime),
        "meta": {"generated_at": reach["generated_at"], "sbom": reach.get("sbom"), "findings": reach.get("findings"), "folder": os.path.basename(out)},
    }
    tot = len(data["cves"])
    rc = [c for c in data["cves"] if c["reached"]]
    kp = {"tot": tot, "tc": sum(c["sev"] == "CRITICAL" for c in data["cves"]), "th": sum(c["sev"] == "HIGH" for c in data["cves"]),
          "r": len(rc), "rcrit": sum(c["sev"] == "CRITICAL" for c in rc), "rhigh": sum(c["sev"] == "HIGH" for c in rc)}
    kp["u"] = tot - kp["r"]
    kp["ucrit"] = kp["tc"] - kp["rcrit"]
    kp["uhigh"] = kp["th"] - kp["rhigh"]
    kp["pct"] = round(100 * kp["u"] / tot) if tot else 0
    kp["eps"] = len(eps)
    kp["unres"] = sum(e["unres"] for e in data["endpoints"])

    page = TEMPLATE.replace("/*DATA*/null", json.dumps(data, ensure_ascii=False)).replace("{{FOLDER}}", html.escape(data["meta"]["folder"]))
    for k, v in kp.items():
        page = page.replace("{{" + k + "}}", str(v))
    path = os.path.join(out, "reach_dashboard.html")
    open(path, "w", encoding="utf-8", newline="\n").write(page)
    return path


TEMPLATE = r"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>도달성 대시보드</title>
<style>
:root{color-scheme:light;--bg:#f6f6f4;--surface:#fcfcfb;--line:#e2e1dc;--text:#0b0b0b;--text2:#52514e;--muted:#77756f;
 --reach:#2a78d6;--reach-bg:#e6effa;--unreach:#a8a69f;--unreach-bg:#efeeea;--crit:#c0392b;--warn:#b26a00}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--bg:#121211;--surface:#1a1a19;--line:#2f2e2b;
 --text:#f0efec;--text2:#c3c2b7;--muted:#97958d;--reach:#3987e5;--reach-bg:#1d2b3d;--unreach:#6f6d66;--unreach-bg:#242422;--crit:#e66767;--warn:#e0a030}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#121211;--surface:#1a1a19;--line:#2f2e2b;--text:#f0efec;--text2:#c3c2b7;--muted:#97958d;
 --reach:#3987e5;--reach-bg:#1d2b3d;--unreach:#6f6d66;--unreach-bg:#242422;--crit:#e66767;--warn:#e0a030}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,"Malgun Gothic",sans-serif}
main{max-width:1180px;margin:0 auto;padding:20px 16px 48px}h1{font-size:22px;margin:0}h2{font-size:16px;margin:28px 0 8px}
.sub{color:var(--text2);margin:4px 0 0}.muted{color:var(--muted)}code{font-family:Consolas,monospace;font-size:12.5px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-top:16px}
.kpi b{display:block;font-size:28px;line-height:1.1;font-variant-numeric:tabular-nums}.kpi span{color:var(--text2);font-size:13px}
.split{display:flex;height:14px;border-radius:4px;overflow:hidden;gap:2px;margin:10px 0 4px}.split i{display:block;height:100%}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:13px;color:var(--text2)}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
input[type=search]{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);font:inherit}
.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:99px;border:1px solid var(--line);color:var(--text2);margin:2px 4px 2px 0}
.tag.r{background:var(--reach-bg);border-color:var(--reach);color:var(--text)}.tag.u{background:var(--unreach-bg)}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--text2);font-weight:600;position:sticky;top:0;background:var(--surface)}td.n{text-align:right;font-variant-numeric:tabular-nums}
td.dot{text-align:center}.on{color:var(--reach);font-weight:700;cursor:help}.off{color:var(--unreach)}
tr.ep{cursor:pointer}tr.ep:hover td{background:var(--reach-bg)}
.bar{display:flex;align-items:center;gap:6px}.bar i{display:block;height:8px;border-radius:0 4px 4px 0;min-width:2px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 10px}.filters button{padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--text);cursor:pointer;font:inherit}
.filters button[aria-pressed=true]{border-color:var(--reach);background:var(--reach-bg)}
#res .item{border-top:1px solid var(--line);padding:8px 0}.ev{font-size:12.5px;color:var(--text2);margin:2px 0 0 0;word-break:break-word}
details{margin-top:6px}summary{cursor:pointer;color:var(--text2)}
</style></head>
<body><main>
<h1>엔드포인트 ↔ 부품 도달성</h1>
<p class="sub">API-BOM(엔드포인트)과 SBOM(부품)을 <b>코드 호출 경로</b>로 이은 결과 · 결과 폴더 <code>{{FOLDER}}</code> · 정적 분석(과대 추정 쪽) · 문서 14</p>

<div class="kpis">
 <div class="card kpi"><b>{{tot}}</b><span>고유 Critical·High CVE (C{{tc}} · H{{th}})</span></div>
 <div class="card kpi"><b style="color:var(--reach)">{{r}}</b><span>엔드포인트에서 <strong>닿음</strong> (C{{rcrit}} · H{{rhigh}}) — 먼저 볼 것</span></div>
 <div class="card kpi"><b>{{u}}</b><span><strong>닿지 않음</strong> {{pct}}% (C{{ucrit}} · H{{uhigh}}) — VEX not_affected 후보</span></div>
 <div class="card kpi"><b>{{eps}}</b><span>엔드포인트 · 미해석 호출 {{unres}}</span></div>
</div>
<div class="card" style="margin-top:10px">
 <div class="split" role="img" aria-label="고유 CVE {{tot}} 중 닿음 {{r}}, 닿지 않음 {{u}}"><i style="flex:{{r}};background:var(--reach)" title="닿음 {{r}}"></i><i style="flex:{{u}};background:var(--unreach)" title="닿지 않음 {{u}}"></i></div>
 <div class="legend"><span><span class="sw" style="background:var(--reach)"></span>닿음 {{r}}</span><span><span class="sw" style="background:var(--unreach)"></span>닿지 않음 {{u}} ({{pct}}%)</span></div>
</div>

<h2>① 영향 조회 — 새 CVE·부품이 어느 API 에 닿나</h2>
<div class="card">
 <input type="search" id="q" placeholder="CVE 번호(DEBIAN-CVE-2023-…, CVE-…) 또는 부품 이름(curl, libssl1.1, apache2, php-jwt…)" autocomplete="off">
 <div id="res" class="muted" style="margin-top:8px">입력하면 결과가 나옵니다. 예: <code>libcurl4</code> · <code>apache2-bin</code> · <code>dash</code> · <code>firebase/php-jwt</code></div>
</div>

<h2>② 엔드포인트 × 부품 (런타임 공통 제외)</h2>
<p class="muted" style="margin:0 0 6px">● = 닿음 (마우스를 올리면 근거) · 모든 엔드포인트 공통 런타임: <span id="rt"></span> · 행을 누르면 상세</p>
<div class="card wrap"><table id="mx"></table></div>

<h2>③ 취약 부품 — 닿음 / 런타임 공통 / 닿지 않음</h2>
<div class="filters" role="group" aria-label="부품 필터">
 <button data-f="all" aria-pressed="true">전체</button><button data-f="reach" aria-pressed="false">닿음</button>
 <button data-f="rt" aria-pressed="false">런타임 공통</button><button data-f="un" aria-pressed="false">닿지 않음 (VEX 후보)</button>
</div>
<div class="card wrap"><table id="ct"></table></div>

<h2>활용 · 한계</h2>
<div class="card">
 <ul style="margin:0;padding-left:18px">
  <li><b>새 CVE</b>: DT 에 뜬 CVE 번호를 ①에 넣는다 → 닿는 API 가 있으면 우선 조치, 없으면 VEX not_affected(code_not_reachable) 후보</li>
  <li><b>우선순위</b>: 2,355건 중 "닿음"만 먼저 본다. 닿지 않는 것은 승인(8091) 후 DT 분석 상태로 기록 → 다음 판정에서 빠짐</li>
  <li><b>영향 범위</b>: ②에서 셸(dash)·JWT 처럼 일부 API 만 닿는 부품 = 그 API 만의 공격면</li>
  <li class="muted">한계: 정적 분석(조건 분기는 모두 실행으로 봄). PCRE·Apache 모듈(zlib) 은 이미지 확인 전 "추정". 라이브러리가 프로세스에 로드는 되지만 호출은 안 되는 경우를 "닿지 않음"으로 본다 — 문서 14 §5</li>
 </ul>
</div>
<p class="muted" id="meta"></p>
</main>
<script>
const D=/*DATA*/null;
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const RT=new Set(D.runtime);
document.getElementById("rt").textContent=D.runtime.join(", ");
document.getElementById("meta").textContent=`생성 ${D.meta.generated_at} · SBOM ${D.meta.sbom} · DT ${D.meta.findings}`;
const compBy=Object.fromEntries(D.components.map(c=>[c.c,c]));
// ② 행렬
(function(){
 const t=document.getElementById("mx");
 let h="<tr><th>엔드포인트</th><th>인증</th>"+D.cols.map(c=>`<th>${esc(c)}</th>`).join("")+"<th class='n'>Critical</th><th class='n'>High</th></tr>";
 const eps=[...D.endpoints].sort((a,b)=>(Object.keys(b.comps).length-Object.keys(a.comps).length)||a.k.localeCompare(b.k));
 for(const e of eps){
  h+=`<tr class="ep" data-k="${esc(e.k)}"><td><code>${esc(e.k)}</code></td><td>${e.auth===null?"화면":(e.auth?"필요":"없음")}</td>`;
  for(const c of D.cols){const ev=e.comps[c];h+=ev?`<td class="dot"><span class="on" title="${esc(ev.join("\n"))}" aria-label="닿음">●</span></td>`:`<td class="dot"><span class="off" aria-label="안 닿음">·</span></td>`}
  h+=`<td class="n">${e.crit}</td><td class="n">${e.high}</td></tr>`;
  h+=`<tr hidden data-d="${esc(e.k)}"><td colspan="${D.cols.length+4}"><div class="ev">${esc(e.where)} · 도달 메서드 ${e.n} · 미해석 ${e.unres}</div>`+
     Object.entries(e.comps).map(([c,ev])=>`<div class="ev"><b>${esc(c)}</b>${RT.has(c)?" (런타임)":""} ← ${esc(ev.join(" · "))}</div>`).join("")+"</td></tr>";
 }
 t.innerHTML=h;
 t.addEventListener("click",ev=>{const tr=ev.target.closest("tr.ep");if(!tr)return;const d=t.querySelector(`tr[data-d="${CSS.escape(tr.dataset.k)}"]`);d.hidden=!d.hidden});
})();
// ③ 부품 표
function drawComps(f){
 const t=document.getElementById("ct");const mx=Math.max(...D.components.map(c=>c.crit+c.high),1);
 let h="<tr><th>부품</th><th>판단</th><th>Critical · High</th><th class='n'>닿는 엔드포인트</th></tr>";
 for(const c of D.components){
  const st=c.rt?"rt":(c.n?"reach":"un");if(f!=="all"&&f!==st)continue;
  const lab=st==="rt"?'<span class="tag r">런타임 공통</span>':st==="reach"?'<span class="tag r">일부 닿음</span>':'<span class="tag u">닿지 않음 · VEX 후보</span>';
  const col=st==="un"?"var(--unreach)":"var(--reach)";
  h+=`<tr><td><code>${esc(c.c)}</code></td><td>${lab}</td><td><div class="bar" title="Critical ${c.crit} · High ${c.high}"><i style="width:${Math.round(160*(c.crit+c.high)/mx)}px;background:${col}"></i><span>C${c.crit} · H${c.high}</span></div></td><td class="n" title="${esc(c.by.join("\n"))}">${c.n}</td></tr>`;
 }
 t.innerHTML=h;
}
drawComps("all");
document.querySelectorAll(".filters button").forEach(b=>b.addEventListener("click",()=>{document.querySelectorAll(".filters button").forEach(x=>x.setAttribute("aria-pressed",x===b));drawComps(b.dataset.f)}));
// ① 조회
const q=document.getElementById("q"),res=document.getElementById("res");
q.addEventListener("input",()=>{
 const s=q.value.trim().toLowerCase();if(s.length<2){res.innerHTML='입력하면 결과가 나옵니다.';res.className="muted";return}
 res.className="";let out=[];
 const hitC=D.cves.filter(c=>c.id.toLowerCase().includes(s)).slice(0,20);
 for(const c of hitC){
  const eps=c.via.flatMap(v=>(compBy[v]||{by:[]}).by);const uniq=[...new Set(eps)];
  out.push(`<div class="item"><b><code>${esc(c.id)}</code></b> <span class="tag">${c.sev}</span> ${c.reached?`<span class="tag r">닿음</span> 경유 ${esc(c.via.join(", "))} → 엔드포인트 ${uniq.length}개`:'<span class="tag u">어느 엔드포인트에서도 닿지 않음 → VEX not_affected 후보</span>'}<div class="ev">부품: ${esc(c.comps.join(", "))}</div>${c.reached?`<details><summary>엔드포인트 ${uniq.length}개</summary><div class="ev">${uniq.map(esc).join("<br>")}</div></details>`:""}</div>`);
 }
 const hitP=D.components.filter(c=>c.c.toLowerCase().includes(s)).slice(0,10);
 for(const c of hitP){
  const evs=D.endpoints.filter(e=>e.comps[c.c]).map(e=>`<div class="ev"><code>${esc(e.k)}</code> ← ${esc((e.comps[c.c]||[]).slice(0,2).join(" · "))}</div>`);
  out.push(`<div class="item"><b><code>${esc(c.c)}</code></b> C${c.crit} · H${c.high} ${c.rt?'<span class="tag r">런타임 공통 — 모든 엔드포인트</span>':c.n?`<span class="tag r">닿음 ${c.n}개</span>`:'<span class="tag u">닿지 않음 → VEX 후보</span>'}${c.n&&!c.rt?`<details open><summary>근거</summary>${evs.join("")}</details>`:""}</div>`);
 }
 const hitE=D.endpoints.filter(e=>e.k.toLowerCase().includes(s)).slice(0,5);
 for(const e of hitE){out.push(`<div class="item"><b><code>${esc(e.k)}</code></b> 닿는 부품: ${Object.keys(e.comps).map(c=>`<span class="tag r">${esc(c)}</span>`).join("")}</div>`)}
 res.innerHTML=out.join("")||'<span class="muted">결과 없음 — 이 SBOM·DT 스냅샷에 없는 CVE/부품입니다 (새 CVE 라면 DT 반영 후 reachability.py 를 다시 실행)</span>';
});
</script>
</body></html>
"""


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else sorted(glob.glob(os.path.join(HERE, "results", "*")))[-1]
    print("도달성 대시보드:", build(out))
