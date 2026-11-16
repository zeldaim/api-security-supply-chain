#!/usr/bin/env python3
"""[근거 통합 표] 엔드포인트 한 줄에 동적·실증·정적 근거를 칸으로 나란히 — 그래프가 아니라 표라서 겹치지 않는다 (문서 14 §8).

    python api-bom/reach/evidence_dashboard.py [결과 폴더]     # 기본: api-bom/reach/results/<최신>

칸 (근거 종류별)
  [동적] 로그 관측   api-bom/inventory/endpoints_observed.csv  — 실제 호출 수·상태 코드·마지막 관측·클라이언트 수
  [동적] 블랙박스    api-bom/inventory/scan_endpoints.csv      — 외부에서 찔러 본 응답
  [동적] nuclei      graph risk.csv 의 observed/status          — 자산 스캐너 live 확인
  [실증] VEX         graph risk.csv 의 vex                      — 모의해킹으로 확인한 취약점
  [정적] 도달 부품    reach.json                                 — 코드 호출 경로로 닿는 부품 (런타임 공통 제외)
출력: <결과 폴더>/evidence_dashboard.html (파일 하나, 외부 라이브러리 없음)
"""
import csv
import glob
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
API = os.path.dirname(HERE)
REPO = os.path.dirname(API)
nk = lambda k: re.sub(r"\{\w+\}", "{id}", k)


def rows(p):
    return list(csv.DictReader(open(p, encoding="utf-8-sig"))) if p and os.path.exists(p) else []


def build(out):
    reach = json.load(open(os.path.join(out, "reach.json"), encoding="utf-8"))
    feats = json.load(open(os.path.join(HERE, "features.json"), encoding="utf-8"))
    rt = set(feats["runtime"]["components"]) | {c for m in feats["runtime"].get("apache_modules", {}).values() for c in m["components"]}
    risk_p = next((p for p in (os.path.join(API, "graph", "sample_dt_reach", "risk.csv"), os.path.join(API, "graph", "sample_dt", "risk.csv")) if os.path.exists(p)), None)
    risk = {nk(r["endpoint_key"]): r for r in rows(risk_p)}
    obs = {nk(r["endpoint_key"]): r for r in rows(os.path.join(API, "inventory", "endpoints_observed.csv"))}
    scan = rows(os.path.join(API, "inventory", "scan_endpoints.csv"))

    def scan_of(key):
        path = key.split(" ", 1)[1]
        rx = re.compile("^" + re.escape(path).replace(re.escape("{id}"), r"[^/]+") + "$")
        return [s for s in scan if rx.match(s["path"])]

    E = []
    keys = {nk(e["endpoint_key"]): e for e in reach["endpoints"]}
    for k in sorted(set(keys) | set(risk) | set(obs), key=lambda k: (-int((risk.get(k) or {}).get("risk") or 0), k)):
        e = keys.get(k)
        r = risk.get(k, {})
        o = obs.get(k)
        sc = scan_of(k)
        static = {c: v for c, v in (e or {}).get("components", {}).items() if c not in rt}
        E.append({
            "k": k, "risk": int(r.get("risk") or 0), "cls": r.get("class", ""),
            "log": ({"n": max(int(o.get("apache_n") or 0), int(o.get("app_n") or 0)), "waf": int(o.get("waf_n") or 0),
                     "codes": o.get("status_codes", ""), "last": (o.get("last_seen_utc") or "")[:10],
                     "clients": o.get("distinct_clients", ""), "verdict": o.get("verdict", "")} if o else None),
            "scan": [f"{s['path']} {s['status']} {s['verdict']}" for s in sc[:3]],
            "nuclei": (f"{r.get('observed')} {r.get('status')}" if r.get("observed") not in (None, "", "-") else ""),
            "vex": r.get("vex", ""),
            "static": {c: sorted(v)[:2] for c, v in static.items()},
            "in_code": e is not None, "where": (e or {}).get("where", ""),
        })
    data = {"rows": E, "rt": sorted(rt), "src": {"reach": os.path.relpath(os.path.join(out, "reach.json"), REPO),
            "risk": risk_p and os.path.relpath(risk_p, REPO), "logs": "api-bom/inventory/endpoints_observed.csv",
            "scan": "api-bom/inventory/scan_endpoints.csv"}}
    page = TEMPLATE.replace("/*DATA*/null", json.dumps(data, ensure_ascii=False)).replace("{{FOLDER}}", html.escape(os.path.basename(out)))
    path = os.path.join(out, "evidence_dashboard.html")
    open(path, "w", encoding="utf-8", newline="\n").write(page)
    return path


TEMPLATE = r"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>근거 통합 표</title>
<style>
:root{color-scheme:light;--bg:#f6f6f4;--surface:#fcfcfb;--line:#e2e1dc;--text:#0b0b0b;--text2:#52514e;--muted:#77756f;
 --dyn:#1baf7a;--dyn-bg:#e3f5ee;--stat:#2a78d6;--stat-bg:#e6effa;--proof:#c0392b;--proof-bg:#f9e5e3}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--bg:#121211;--surface:#1a1a19;--line:#2f2e2b;
 --text:#f0efec;--text2:#c3c2b7;--muted:#97958d;--dyn:#199e70;--dyn-bg:#17302a;--stat:#3987e5;--stat-bg:#1d2b3d;--proof:#e66767;--proof-bg:#3a1f1e}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#121211;--surface:#1a1a19;--line:#2f2e2b;--text:#f0efec;--text2:#c3c2b7;--muted:#97958d;
 --dyn:#199e70;--dyn-bg:#17302a;--stat:#3987e5;--stat-bg:#1d2b3d;--proof:#e66767;--proof-bg:#3a1f1e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:13.5px/1.5 system-ui,"Malgun Gothic",sans-serif}
main{max-width:1400px;margin:0 auto;padding:20px 16px 48px}h1{font-size:22px;margin:0}.sub{color:var(--text2);margin:4px 0 12px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px}.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}
th{color:var(--text2);font-weight:600;position:sticky;top:0;background:var(--surface);white-space:nowrap}
th.d{border-top:3px solid var(--dyn)}th.p{border-top:3px solid var(--proof)}th.s{border-top:3px solid var(--stat)}
code{font-family:Consolas,monospace;font-size:12.5px}.muted{color:var(--muted)}td.n{text-align:right;font-variant-numeric:tabular-nums}
.chip{display:inline-block;font-size:12px;padding:1px 7px;border-radius:99px;margin:1px 3px 1px 0;border:1px solid var(--line)}
.chip.d{background:var(--dyn-bg);border-color:var(--dyn)}.chip.s{background:var(--stat-bg);border-color:var(--stat)}.chip.p{background:var(--proof-bg);border-color:var(--proof)}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--text2);margin:6px 0 10px}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}.filters button{padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--text);cursor:pointer;font:inherit}
.filters button[aria-pressed=true]{border-color:var(--stat);background:var(--stat-bg)}.ev{font-size:12px;color:var(--text2)}
.cnt{font-weight:700}
</style></head><body><main>
<h1>근거 통합 표 — 엔드포인트별 동적 · 실증 · 정적</h1>
<p class="sub">한 줄 = 엔드포인트 하나. 칸 위 색 띠 = 근거 종류. 그래프처럼 선이 겹치지 않게 표로 · 결과 폴더 <code>{{FOLDER}}</code> · 문서 14</p>
<div class="legend"><span><span class="sw" style="background:var(--dyn)"></span>동적 = 실제로 호출·응답을 관측</span><span><span class="sw" style="background:var(--proof)"></span>실증 = 모의해킹으로 확인</span><span><span class="sw" style="background:var(--stat)"></span>정적 = 코드 호출 경로로 닿을 수 있음</span><span class="muted">런타임 공통(모든 엔드포인트): <span id="rt"></span></span></div>
<div class="filters" role="group" aria-label="필터">
 <button data-f="all" aria-pressed="true">전체</button><button data-f="multi" aria-pressed="false">근거 2종 이상</button>
 <button data-f="proof" aria-pressed="false">실증 있음</button><button data-f="special" aria-pressed="false">특수 부품 도달(셸·JWT 등)</button>
 <button data-f="nolog" aria-pressed="false">코드에 있지만 호출 관측 없음</button>
</div>
<div class="card wrap"><table id="t"></table></div>
<p class="muted" id="src"></p>
<div class="card" style="margin-top:10px"><b>읽는 법</b>
<ul style="margin:6px 0 0;padding-left:18px">
<li>근거가 <b>여러 종류 겹칠수록 확신이 높다</b> — 예: <code>GET /api/v1/diagnostics/ping</code> = 정적(셸 dash 도달) + 실증 대기(RCE) + 동적(호출 관측)</li>
<li>동적 칸이 비어 있는데 정적 칸만 있으면 = 코드에는 있으나 실제 호출을 못 봤다 (죽은 코드·숨은 API 후보)</li>
<li>정적은 "닿을 수 있음"(과대 추정), 동적 로그는 "이 API 가 불렸음"이지 "이 라이브러리가 실행됐음"은 아님 — 라이브러리 실행 관측(L3)은 문서 14 §9</li>
</ul></div>
</main><script>
const D=/*DATA*/null;const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
document.getElementById("rt").textContent=D.rt.join(", ");
document.getElementById("src").textContent="입력: "+Object.entries(D.src).map(([k,v])=>k+" "+v).join(" · ");
const SPECIAL=new Set(["dash","firebase/php-jwt","libonig5","libcurl4","libssl1.1","libxml2","libargon2-1"]);
function kinds(r){let n=0;if(r.log||r.scan.length||r.nuclei)n++;if(r.vex)n++;if(Object.keys(r.static).length)n++;return n}
function draw(f){
 let h=`<tr><th>위험</th><th>엔드포인트</th><th class="d">동적 · 로그 호출</th><th class="d">동적 · 스캔</th><th class="p">실증 · VEX</th><th class="s">정적 · 도달 부품 (런타임 제외)</th><th>근거 종류</th></tr>`;
 for(const r of D.rows){
  const sp=Object.keys(r.static).filter(c=>SPECIAL.has(c));
  if(f==="multi"&&kinds(r)<2)continue;if(f==="proof"&&!r.vex)continue;if(f==="special"&&!sp.length)continue;if(f==="nolog"&&!(r.in_code&&!r.log))continue;
  const log=r.log?`<span class="chip d"><span class="cnt">${r.log.n.toLocaleString()}</span>회</span><div class="ev">${esc(r.log.codes)}<br>마지막 ${esc(r.log.last)} · 클라이언트 ${esc(r.log.clients)}${r.log.waf?` · WAF ${r.log.waf}`:""}</div>`:'<span class="muted">관측 없음</span>';
  const sc=(r.scan.length?r.scan.map(s=>`<div class="ev">${esc(s)}</div>`).join(""):"")+(r.nuclei?`<span class="chip d">nuclei ${esc(r.nuclei)}</span>`:"")||'<span class="muted">-</span>';
  const vx=r.vex?`<span class="chip p">${esc(r.vex)}</span>`:'<span class="muted">-</span>';
  const st=Object.keys(r.static).length?Object.entries(r.static).map(([c,ev])=>`<span class="chip s" title="${esc(ev.join("\n"))}">${SPECIAL.has(c)?"<b>"+esc(c)+"</b>":esc(c)}</span>`).join(""):(r.in_code?'<span class="muted">런타임만</span>':'<span class="muted">코드에서 못 찾음</span>');
  h+=`<tr><td class="n"><b>${r.risk||""}</b></td><td><code>${esc(r.k)}</code><div class="ev">${esc(r.cls)} ${esc(r.where)}</div></td><td>${log}</td><td>${sc}</td><td>${vx}</td><td>${st}</td><td class="n">${kinds(r)}</td></tr>`;
 }
 document.getElementById("t").innerHTML=h;
}
draw("all");
document.querySelectorAll(".filters button").forEach(b=>b.addEventListener("click",()=>{document.querySelectorAll(".filters button").forEach(x=>x.setAttribute("aria-pressed",x===b));draw(b.dataset.f)}));
</script></body></html>
"""

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else sorted(glob.glob(os.path.join(HERE, "results", "*")))[-1]
    print("근거 통합 표:", build(out))
