#!/usr/bin/env python3
"""실시간 시연 한 번 → 정적 HTML 보고서 (기존 e2e 보고서와 같은 디자인, 다른 파일).
  python report_live.py <run 폴더>    → <run>/dashboard.html
기존 e2e_story/dashboard/index.html (팀 웹 기반 e2e) 은 건드리지 않는다 — 이 시연은 DVRA · 합성 트래픽이다.
입력: <run>/events.jsonl (파이프라인: 경보 · ML · 차단), <run>/access.log (nginx), <run>/demo_console.log (공격 시작 시각)
"""
import html
import importlib.util
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
_DASH = os.path.join(HERE, "..", "tools", "dashboard.py")      # 작업 레포: 기존 e2e 보고서의 CSS 를 그대로
if os.path.exists(_DASH):
    _spec = importlib.util.spec_from_file_location("e2e_dash", _DASH)
    _dash = importlib.util.module_from_spec(_spec)
    sys.path.insert(0, os.path.dirname(_DASH))
    _spec.loader.exec_module(_dash)
    CSS = _dash.CSS
else:                                                            # 공개 레포: 같은 CSS 사본
    CSS = open(os.path.join(HERE, "report.css"), encoding="utf-8").read()
KST = timezone(timedelta(hours=9))
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3})')
e = lambda s: html.escape(str(s if s is not None else ""))


def kst(t):
    return datetime.fromtimestamp(t, KST).strftime("%H:%M:%S")


def ts(s):
    return datetime.fromisoformat(s).timestamp()


def main():
    run = sys.argv[1]
    ev = [json.loads(l) for l in open(os.path.join(run, "events.jsonl"), encoding="utf-8") if l.strip()]
    acc = []
    ap = os.path.join(run, "access.log")
    fh = open(ap, encoding="utf-8", errors="replace") if os.path.exists(ap) else         __import__("gzip").open(ap + ".gz", "rt", encoding="utf-8", errors="replace")   # 커밋본은 access.log.gz
    for l in fh:
        m = LINE.match(l)
        if m:
            acc.append((m.group(1), datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").timestamp(), m.group(3),
                        m.group(4).split("?")[0], int(m.group(5))))
    starts = {}
    for l in open(os.path.join(run, "demo_console.log"), encoding="utf-8"):
        for key, word in (("probe", "탐색 공격 시작"), ("bola", "BOLA 공격 시작"), ("normal", "정상 사용자")):
            if word in l:
                starts[key] = l.split()[0]
    blocks = [x for x in ev if x["type"] == "block"]
    alerts = [x for x in ev if x["type"] == "alert"]
    mls = [x for x in ev if x["type"] == "ml"]
    lab = lambda ip: "normal" if ip.startswith("10.10.") else "probe" if ip.startswith("10.66.") else "bola" if ip.startswith("10.77.") else "other"

    def act(who):
        reqs = [r for r in acc if lab(r[0]) == who]
        b = next((x for x in blocks if lab(x["client_ip"]) == who), None)
        first = reqs[0][1] if reqs else None
        bt = ts(b["timestamp"]) if b else None
        before = [r for r in reqs if bt is None or r[1] < bt]
        after403 = [r for r in reqs if bt is not None and r[1] >= bt and r[4] == 403]
        ok_before = [r for r in before if 200 <= r[4] < 300]
        return {"reqs": reqs, "block": b, "first": first, "block_s": round(bt - first, 1) if b and first else None,
                "ok_before": len(ok_before), "after403": len(after403),
                "alerts": [a for a in alerts if lab(a["data"]["client_ip"]) == who],
                "ml": [m for m in mls if lab(m["client_ip"]) == who]}

    P, B, N = act("probe"), act("bola"), act("normal")
    normal_blocks = [x for x in blocks if lab(x["client_ip"]) == "normal"]
    normal_ml_high = [m for m in N["ml"] if m["level"] == "high"]
    badge = lambda ok: f"<span class='badge {'ok' if ok else 'no'}'>{'✓ 차단' if ok else '✗ 차단 안 됨'}</span>"
    flow = lambda *xs: "<div class='flow'>" + "<span class='arrow'>→</span>".join(f"<span class='step'>{e(x)}</span>" for x in xs) + "</div>"
    lv = Counter(f"L{a['rule']['level']} {a['rule']['description'].split(']')[0].strip('[')}" for a in P["alerts"])
    bml = max(B["ml"], key=lambda m: -m["score"]) if B["ml"] else {}
    cards = [
        f"<div class='card'><h3>1막 · 명세 밖 탐색 → Shadow 룰 {badge(bool(P['block']))}</h3>"
        f"<div class='row'><div><div class='big'>{len(P['alerts'])}/{len(P['reqs'])}</div><span class='sm'>룰 경보 / 요청</span></div>"
        f"<div><div class='big'>{e(P['block_s'])}초</div><span class='sm'>첫 요청 → 차단</span></div>"
        f"<div><div class='big'>{P['after403']}</div><span class='sm'>차단 뒤 403</span></div></div>"
        + flow("숨은 주소 15곳 두드림", "Wazuh 실시간 판정", "L3 숨은 API 성공", "nginx 차단 목록")
        + f"<div class='sm'>{e(' · '.join(f'{k} {n}' for k, n in lv.most_common()))}<br>차단 이유: {e(P['block']['reason'] if P['block'] else '-')}</div></div>",
        f"<div class='card'><h3>2막 · 명세 안 BOLA → ML {badge(bool(B['block']))}</h3>"
        f"<div class='row'><div><div class='big'>{B['ok_before']}</div><span class='sm'>차단 전 성공(2xx)</span></div>"
        f"<div><div class='big'>{e(B['block_s'])}초</div><span class='sm'>첫 요청 → 차단</span></div>"
        f"<div><div class='big'>{B['after403']}</div><span class='sm'>차단 뒤 403</span></div></div>"
        + flow("남의 주문 1..150 열거", "IP×5분 창 특징", f"ML high (점수 {bml.get('score', '-')})", "nginx 차단 목록")
        + f"<div class='sm'>Shadow 룰 경보 {len(B['alerts'])}건 — 명세 안 경로라 룰의 대상이 아니다<br>차단 근거: {e(B['block']['detail'] if B['block'] else '-')}</div></div>",
        f"<div class='card'><h3>정상 사용자 20명 — 오탐 {badge(not normal_blocks).replace('✓ 차단', '✓ 없음').replace('✗ 차단 안 됨', '✗ 있음')}</h3>"
        f"<div class='row'><div><div class='big'>{len(N['reqs'])}</div><span class='sm'>요청</span></div>"
        f"<div><div class='big'>{len(normal_blocks)}</div><span class='sm'>차단된 정상 IP</span></div>"
        f"<div><div class='big'>{len(normal_ml_high)}</div><span class='sm'>ML high 창 (차단 안 함: 요청 15건 미만)</span></div>"
        f"<div><div class='big'>{len(N['alerts'])}</div><span class='sm'>룰 경보</span></div></div>"
        + "<div class='sm'>ML 차단은 창에 요청 15건 이상일 때만 (접속 직후 몰린 짧은 창 오탐 방지 — 대응 정책)</div></div>",
    ]
    # BOLA 공격자 응답 — 10초 칸마다 2xx / 404 / 403
    svg = ""
    if B["reqs"]:
        t0 = B["reqs"][0][1]
        bins = defaultdict(Counter)
        for ip, t, m, p, st in B["reqs"]:
            bins[int((t - t0) // 5)]["403" if st == 403 else "2xx" if st < 300 else "4xx"] += 1
        nb = max(bins) + 1
        W, H, pad = 900, 180, 30
        bw = (W - 2 * pad) / nb
        mx = max(sum(c.values()) for c in bins.values())
        cols = {"2xx": "var(--bad)", "4xx": "var(--warn)", "403": "var(--s1)"}
        rects = []
        for i in range(nb):
            y = H - pad
            for k in ("2xx", "4xx", "403"):
                v = bins[i][k]
                if not v:
                    continue
                h = (H - 2 * pad) * v / mx
                y -= h
                rects.append(f"<rect x='{pad + i * bw:.1f}' y='{y:.1f}' width='{bw - 2:.1f}' height='{h:.1f}' fill='{cols[k]}' data-tip='{i * 5}~{i * 5 + 5}초: {k} {v}건'/>")
        bx = ""
        if B["block"]:
            xb = pad + (ts(B["block"]["timestamp"]) - t0) / 5 * bw
            bx = f"<line x1='{xb:.1f}' x2='{xb:.1f}' y1='{pad - 10}' y2='{H - pad}' stroke='var(--thr)' stroke-dasharray='4 3'/><text x='{xb + 4:.1f}' y='{pad - 2}'>자동 차단 {B['block_s']}초</text>"
        svg = (f"<div class='legend'><span><span class='sw' style='background:var(--bad)'></span>남의 주문 열람 성공(2xx)</span>"
               f"<span><span class='sw' style='background:var(--warn)'></span>없는 주문(4xx)</span>"
               f"<span><span class='sw' style='background:var(--s1)'></span>차단(403)</span></div>"
               f"<div class='wrap'><svg viewBox='0 0 {W} {H}' width='100%'>{''.join(rects)}{bx}"
               f"<text x='{pad}' y='{H - 8}'>공격 시작</text><text x='{W - pad - 60}' y='{H - 8}'>{nb * 5}초</text></svg></div>")
    btab = "".join(f"<tr><td>{kst(ts(b['timestamp']))}</td><td><code>{e(b['client_ip'])}</code></td><td>{e(b['source'])}</td><td>{e(b['reason'])}</td><td>{e(b['detail'])}</td><td>{e(b['label'])}</td></tr>" for b in blocks)
    atab = "".join(f"<tr><td>{kst(ts(a['timestamp']))}</td><td>L{e(a['rule']['level'])}</td><td><code>{e(a['data']['client_ip'])}</code></td><td>{e(a['data']['method'])} {e(a['data']['path'])}</td><td>{e(a['data']['status'])}</td><td>{e(a['label'])}</td></tr>" for a in alerts)
    mtab = "".join(f"<tr><td>{kst(ts(m['timestamp']))}</td><td><code>{e(m['client_ip'])}</code></td><td><b>{e(m['level'])}</b></td><td>{m['score']:+.4f}</td><td>{e(m['n_req'])}</td><td>{e(m['seq_id_run'])}</td><td>{e(m['label'])}</td></tr>" for m in mls)
    rid = os.path.basename(os.path.normpath(run)).replace("run_", "")
    page = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>실시간 보안 시연 (DVRA)</title><style>{CSS}</style></head><body class="viz-root"><main>
<h1>실시간 보안 시연 — 공격 → 탐지(Shadow 룰 · ML) → 자동 차단</h1>
<div class="mut">실행 {rid[:4]}-{rid[4:6]}-{rid[6:8]} {rid[9:11]}:{rid[11:13]} KST · <b>DVRA · 합성 트래픽</b> (개발에 쓰지 않은 앱) · 이 PC Docker:
nginx(차단 목록) · Wazuh manager 4.14.6 실시간 · ML v1.0(IsolationForest, 학습 창 365) · ES · Grafana<br>
팀 웹 기반 e2e 시연(<code>e2e_story/dashboard/index.html</code>)과는 별개다 — 그것을 대체하지 않는다.</div>
<div class="cards">{''.join(cards)}</div>
<h2>2막 BOLA 공격자 응답 (5초 칸) — 차단 전 성공, 차단 뒤 403</h2>{svg}
<h2>자동 차단 기록</h2><div class="wrap"><table><tr><th>시각</th><th>IP</th><th>탐지</th><th>이유</th><th>근거</th><th>정답</th></tr>{btab}</table></div>
<h2>Shadow 룰 경보 (실시간 Wazuh)</h2><div class="wrap"><table><tr><th>시각</th><th>레벨</th><th>IP</th><th>요청</th><th>상태</th><th>정답</th></tr>{atab}</table></div>
<details><summary>ML 판정이 바뀐 순간 (high · medium)</summary><div class="wrap"><table><tr><th>시각</th><th>IP</th><th>판정</th><th>점수</th><th>요청</th><th>연속 ID</th><th>정답</th></tr>{mtab}</table></div></details>
<h2>진행</h2><div class="wrap"><table><tr><th>시각</th><th>내용</th></tr>{''.join(f'<tr><td>{e(v)}</td><td>{e(k)}</td></tr>' for k, v in starts.items())}</table></div>
<p class="sm">차단 정책: ML high(창 요청 15건 이상) · Shadow 룰 L3 · F1 · F2 → nginx 차단 목록 / L1 · L2 → 기록만. 정답 라벨은 출발지 IP 로 붙인 화면용 — 판정에 쓰지 않는다.</p>
</main><div class="tip" id="tip"></div>
<script>
const tip=document.getElementById('tip');
document.querySelectorAll('[data-tip]').forEach(n=>{{
  n.addEventListener('mousemove',ev=>{{tip.innerHTML=n.dataset.tip;tip.style.display='block';
    tip.style.left=Math.min(ev.clientX+12,innerWidth-370)+'px';tip.style.top=(ev.clientY+12)+'px';}});
  n.addEventListener('mouseleave',()=>tip.style.display='none');}});
</script></body></html>"""
    out = os.path.join(run, "dashboard.html")
    open(out, "w", encoding="utf-8").write(page)
    print(f"→ {out} · 차단 {len(blocks)} (정상 {len(normal_blocks)}) · 경보 {len(alerts)} · ML 변화 {len(mls)}")


if __name__ == "__main__":
    main()
