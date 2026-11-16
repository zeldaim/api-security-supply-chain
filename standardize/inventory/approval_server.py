#!/usr/bin/env python3
"""[승인 대시보드] 추가 후보·review 항목을 웹 화면에서 보고 버튼으로 고른다 (문서 11 §13-2 A안).
Python 기본 기능만 사용 (설치할 것 없음). 데이터는 이 컴퓨터 밖으로 나가지 않는다.

    python3 api-bom/inventory/approval_server.py                 # http://127.0.0.1:8090
    python3 api-bom/inventory/approval_server.py --commit        # 고를 때마다 git 커밋
    python3 api-bom/inventory/approval_server.py --commit --push # 커밋 후 push 까지 (인증 설정 필요)
    옵션: --host 0.0.0.0 (다른 PC 에서 접속 허용) --port 8090 --user 이름

버튼 하나 = decisions.py 로 저장 → merge_inventory.py 로 인벤토리 재생성 → DT 업로드(~/.dt_env 있으면) → (선택) git 커밋.
보호: 실행할 때마다 새 토큰을 만들어 화면에 넣고, 토큰이 맞는 요청만 저장한다.
"""
import argparse
import html
import json
import os
import secrets
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import decisions as D

HERE = D.HERE
REPO = os.path.dirname(os.path.dirname(HERE))
TOKEN = secrets.token_urlsafe(16)
ARGS = None
FILES = ["api-bom/inventory/candidates.csv", "api-bom/inventory/baseline_v2.csv",
         "api-bom/inventory/decisions_log.csv", "api-bom/inventory/inventory.cdx.json", "api-bom/inventory/inventory.md",
         "api-bom/dt_history"]   # 승인 즉시 DT 업로드한 기록도 같이 커밋

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#5d6677;--line:#dfe3ea;--acc:#2563eb;--ok:#15803d;--warn:#b45309;--bad:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2c3340;--acc:#60a5fa;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,"Malgun Gothic",sans-serif}
main{max-width:1000px;margin:0 auto;padding:20px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.mut{color:var(--mut)}.flash{padding:10px 14px;border-radius:8px;background:var(--card);border:1px solid var(--line);margin:12px 0}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:120px}
.kpi b{display:block;font-size:22px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:10px 0}
.key{font-family:Consolas,monospace;font-size:15px;font-weight:600;word-break:break-all}.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:99px;border:1px solid var(--line);margin-left:6px;color:var(--mut)}
.shadow{color:var(--bad);border-color:var(--bad)}.exposure{color:var(--warn);border-color:var(--warn)}
dl{display:grid;grid-template-columns:80px 1fr;gap:2px 10px;margin:8px 0}dt{color:var(--mut)}dd{margin:0;word-break:break-word}
form .row{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}input[type=text]{flex:1;min-width:160px;padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
button{padding:7px 12px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg);cursor:pointer;font:inherit}
button:hover{border-color:var(--acc)}button.a{border-color:var(--ok);color:var(--ok)}button.r{border-color:var(--bad);color:var(--bad)}
table{width:100%;border-collapse:collapse;background:var(--card);font-size:13px}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.wrap{overflow-x:auto}
"""


def e(s):
    return html.escape(str(s or ""))


def counts():
    try:
        with open(os.path.join(HERE, "inventory.cdx.json"), encoding="utf-8") as f:
            props = {p["name"]: p["value"] for p in json.load(f)["metadata"].get("properties", [])}
        return {k.split(":")[-1]: v for k, v in props.items() if k.startswith("sesac:inv:count:")}
    except (OSError, ValueError, KeyError):
        return {}


def form(mode, layer, key, buttons, owner=""):
    hidden = "".join(f'<input type="hidden" name="{n}" value="{e(v)}">'
                     for n, v in (("token", TOKEN), ("mode", mode), ("layer", layer), ("key", key)))
    btns = "".join(f'<button name="choice" value="{e(v)}" class="{c}">{e(t)}</button>' for v, t, c in buttons)
    return (f'<form method="post" action="/decide">{hidden}<div class="row">'
            f'<input type="text" name="reason" placeholder="이유 (한 줄, 선택)">'
            f'<input type="text" name="owner" placeholder="담당자(owner)" value="{e(owner)}"></div>'
            f'<div class="row">{btns}</div></form>')


def page(msg=""):
    cands = D.pending_candidates()
    reviews = D.review_items()
    log = D.load(D.LOG)[1][-15:][::-1]
    c = counts()
    out = [f"<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>자산 승인</title><style>{CSS}</style></head><body><main>",
           "<h1>자산 승인 대시보드</h1>",
           f"<div class='mut'>기준선 v2 에 무엇을 넣을지 고릅니다 · 판정자 <b>{e(ARGS.user)}</b> · "
           f"{'고를 때마다 git 커밋' if ARGS.commit else '커밋 안 함 (--commit 으로 켜기)'}</div>"]
    if msg:
        out.append(f"<div class='flash'>{e(msg)}</div>")
    out.append("<div class='kpis'>"
               f"<div class='kpi'><b>{len(cands)}</b>선택 대기 후보</div><div class='kpi'><b>{len(reviews)}</b>review (다시 판단)</div>"
               + "".join(f"<div class='kpi'><b>{e(v)}</b>인벤토리 {e(k)}</div>" for k, v in sorted(c.items()))
               + "</div>")
    out.append("<h2>1. 추가 후보 — 인벤토리에 있는데 기준선에 없는 것</h2>"
               "<div class='mut'>기준: 우리가 의도해서 운영하는가? (정상·안전 여부와 별개. 위험한 설정은 따로 고친다)</div>")
    if not cands:
        out.append("<div class='card mut'>선택 대기 후보 없음</div>")
    for x in cands:
        cls = "shadow" if x["verdict"] == "shadow" else "exposure" if "노출" in x["verdict"] or x["verdict"] == "exposure" else ""
        out.append(f"<div class='card'><span class='key'>{e(x['key'])}</span><span class='tag'>{e(x['layer'])}</span>"
                   f"<span class='tag {cls}'>{e(x['verdict'])}</span><span class='tag'>{e(x['group'])}</span>"
                   f"<dl><dt>찾은 출처</dt><dd>{e(x['found_by'])}</dd><dt>근거</dt><dd>{e(x['evidence'])}</dd>"
                   f"<dt>참고</dt><dd>{e(x['suggested'])}</dd></dl>"
                   + form("candidate", x["layer"], x["key"],
                          [("add:active", "추가 (active)", "a"), ("add:deprecated", "추가 (deprecated)", ""),
                           ("add:review", "추가 (review · 나중에)", ""), ("reject", "추가 안 함 (없애야 함)", "r")])
                   + "</div>")
    out.append("<h2>2. review — 기준선에 '판단 보류'로 들어 있는 것</h2>")
    if not reviews:
        out.append("<div class='card mut'>review 항목 없음</div>")
    for x in reviews:
        out.append(f"<div class='card'><span class='key'>{e(x['endpoint_key'])}</span><span class='tag'>{e(x['layer'])}</span>"
                   f"<span class='tag shadow'>review</span><dl><dt>출처</dt><dd>{e(x['source'])}</dd>"
                   f"<dt>메모</dt><dd>{e(x['note'])}</dd><dt>추가</dt><dd>{e(x['added_by'])} {e(x['added_at'])}</dd></dl>"
                   + form("review", x["layer"], x["endpoint_key"],
                          [("active", "active", "a"), ("deprecated", "deprecated (폐기 예정)", ""),
                           ("remove", "remove (없애야 함)", "r")], owner=x["owner"])
                   + "</div>")
    out.append("<h2>최근 판정 이력</h2><div class='wrap'><table><tr><th>시각</th><th>누가</th><th>항목</th><th>이전 → 이후</th><th>담당</th><th>이유</th></tr>")
    for x in log:
        out.append(f"<tr><td>{e(x['at'])}</td><td>{e(x['by'])}</td><td>{e(x['layer'])} · {e(x['key'])}</td>"
                   f"<td>{e(x['before'])} → {e(x['after'])}</td><td>{e(x['owner'])}</td><td>{e(x['reason'])}</td></tr>")
    out.append("</table></div><p class='mut'>전체 이력: api-bom/inventory/decisions_log.csv · 인벤토리: inventory.md</p></main></body></html>")
    return "".join(out)


def after_decision(summary):
    """인벤토리 재생성 → (선택) 커밋·push. 실패해도 판정은 이미 저장됨."""
    notes = []
    r = subprocess.run([sys.executable, os.path.join(HERE, "merge_inventory.py")], capture_output=True, text=True, cwd=REPO)
    notes.append("인벤토리 재생성 " + ("완료" if r.returncode == 0 else "실패: " + (r.stderr.strip().splitlines() or ["?"])[-1]))
    # 승인 즉시 DT 반영 (2026-11-05) — ~/.dt_env 가 있을 때만. 내용이 같으면 dt_upload.sh 가 알아서 건너뜀
    if r.returncode == 0 and os.path.exists(os.environ.get("DT_ENV", os.path.expanduser("~/.dt_env"))):
        d = subprocess.run(["bash", "tools/dt_upload.sh", "api"], capture_output=True, text=True, cwd=REPO, timeout=240)
        notes.append((d.stdout.strip().splitlines() or ["DT 응답 없음"])[-1].replace("[DT] ", "DT: "))
    if ARGS.commit:
        subprocess.run(["git", "add", "--"] + FILES, cwd=REPO, capture_output=True)
        r = subprocess.run(["git", "commit", "-q", "-m", f"approve: {summary}"], cwd=REPO, capture_output=True, text=True)
        notes.append("커밋 " + ("완료" if r.returncode == 0 else "안 됨: " + (r.stdout + r.stderr).strip()[:120]))
        if ARGS.push and r.returncode == 0:
            # 다른 곳(이 PC 문서 커밋·cron)이 먼저 push 했을 수 있으니 받아서 위에 올린 뒤 push
            subprocess.run(["git", "pull", "-q", "--rebase", "--autostash"], cwd=REPO, capture_output=True, text=True)
            r = subprocess.run(["git", "push", "-q"], cwd=REPO, capture_output=True, text=True)
            notes.append("push " + ("완료" if r.returncode == 0 else "실패(인증 확인): " + r.stderr.strip()[:120]))
    return " · ".join(notes)


class H(BaseHTTPRequestHandler):
    def send(self, code, body, ctype="text/html; charset=utf-8", loc=None):
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Frame-Options", "DENY")
        if loc:
            self.send_header("Location", loc)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path != "/":
            return self.send(404, "없는 경로", "text/plain; charset=utf-8")
        msg = urllib.parse.parse_qs(u.query).get("msg", [""])[0]
        self.send(200, page(msg))

    def do_POST(self):
        if self.path != "/decide":
            return self.send(404, "없는 경로", "text/plain; charset=utf-8")
        n = int(self.headers.get("Content-Length") or 0)
        f = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(min(n, 65536)).decode("utf-8")).items()}
        if not secrets.compare_digest(f.get("token", ""), TOKEN):
            return self.send(403, "토큰이 맞지 않습니다. 화면을 새로고침하세요.", "text/plain; charset=utf-8")
        try:
            layer, key, choice = f["layer"], f["key"], f["choice"]
            owner, reason = f.get("owner", "").strip(), f.get("reason", "").strip()
            if f.get("mode") == "review":
                D.decide_review(layer, key, choice, owner, reason, ARGS.user)
            else:
                D.decide_candidate(layer, key, choice, owner, reason, ARGS.user)
            summary = f"{layer} {key} → {choice} ({ARGS.user})"
            msg = f"저장: {summary} · " + after_decision(summary)
        except (KeyError, ValueError) as ex:
            msg = f"저장 안 됨: {ex}"
        self.send(303, "", loc="/?msg=" + urllib.parse.quote(msg))

    def log_message(self, fmt, *a):
        sys.stderr.write("[승인] " + (fmt % a) + "\n")


def main():
    global ARGS
    ap = argparse.ArgumentParser(description="자산 승인 대시보드")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--user", default=D.git_user() or "unknown")
    ap.add_argument("--commit", action="store_true")
    ap.add_argument("--push", action="store_true")
    ARGS = ap.parse_args()
    srv = HTTPServer((ARGS.host, ARGS.port), H)
    print(f"승인 대시보드: http://{ARGS.host}:{ARGS.port}  (판정자 {ARGS.user}, 커밋 {'켬' if ARGS.commit else '끔'}) — Ctrl+C 로 종료")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
