#!/usr/bin/env python3
"""[v3 예외 승인 대시보드] 일반 기준 위반 목록(API 자산 G1~G9 + SBOM S1~S4, 문서 13)을 보고, 고치지 않고 둘 것만 '예외'로 승인한다 (문서 12 §1).
사람은 항목마다 "괜찮나?"를 고민하지 않는다 — 위반 중 예외만 고른다. 예외에는 사유와 만료일이 반드시 있다.

    python3 api-bom/policy/exception_server.py [--commit] [--push] [--port 8091] [--host 127.0.0.1]

버튼 → exceptions.csv 에 한 줄 추가 → judge.py 재실행(판정·보고서·v3 BOM 갱신) → (선택) git 커밋·push
v2 의 승인 대시보드(inventory/approval_server.py, 8090)와 별개다.
"""
import argparse
import csv
import html
import os
import secrets
import subprocess
import sys
import urllib.parse
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
EXC = os.path.join(HERE, "exceptions.csv")
JUDGE = os.path.join(HERE, "judgement.csv")
SBOM_JUDGE = os.path.join(HERE, "sbom_judgement.csv")   # 문서 13: SBOM 위반(S1~S4)도 같은 화면에서 예외 승인
TOKEN = secrets.token_urlsafe(16)
KST = timezone(timedelta(hours=9))
ARGS = None
FILES = ["api-bom/policy/exceptions.csv", "api-bom/policy/judgement.csv", "api-bom/policy/report.md",
         "api-bom/policy/inventory_v3.cdx.json", "api-bom/policy/compare_v2_v3.md",
         "api-bom/policy/sbom_judgement.csv", "api-bom/policy/sbom_report.md"]
CSS = """:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#5d6677;--line:#dfe3ea;--acc:#2563eb;--h:#b91c1c;--m:#b45309;--l:#4b5563}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2c3340;--acc:#60a5fa;--h:#f87171;--m:#fbbf24;--l:#9ca3af}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,"Malgun Gothic",sans-serif}
main{max-width:1000px;margin:0 auto;padding:20px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:26px 0 10px}.mut{color:var(--mut)}
.flash{padding:10px 14px;border-radius:8px;background:var(--card);border:1px solid var(--line);margin:12px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:10px 0}
.key{font-family:Consolas,monospace;font-weight:600;word-break:break-all}.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:99px;border:1px solid var(--line);margin-left:6px}
.h{color:var(--h);border-color:var(--h)}.m{color:var(--m);border-color:var(--m)}.l{color:var(--l)}
.ev{font-size:13px;color:var(--mut);word-break:break-word;margin:6px 0}
form{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}input,select{padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
input[name=reason]{flex:1;min-width:200px}button{padding:7px 12px;border-radius:6px;border:1px solid var(--acc);background:var(--bg);color:var(--acc);cursor:pointer;font:inherit}
table{width:100%;border-collapse:collapse;background:var(--card);font-size:13px}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left}.wrap{overflow-x:auto}"""


def e(s):
    return html.escape(str(s or ""))


def rows(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def page(msg=""):
    js = rows(JUDGE) + rows(SBOM_JUDGE)
    viol = [r for r in js if r["result"].startswith("위반")]
    exc = rows(EXC)
    cnt = {}
    for r in js:
        cnt[r["result"]] = cnt.get(r["result"], 0) + 1
    default_exp = (date.today() + timedelta(days=30)).isoformat()
    out = [f"<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>예외 승인 v3</title><style>{CSS}</style></head><body><main><h1>예외 승인 (v3 일반 기준)</h1>"
           f"<div class='mut'>위반은 기본적으로 <b>고칠 대상</b>입니다. 고치지 않고 둘 것만 예외로 승인하세요 (사유·만료일 필수) · 승인자 <b>{e(ARGS.user)}</b>"
           f" · {'고를 때마다 git 커밋' if ARGS.commit else '커밋 안 함'}</div>"]
    if msg:
        out.append(f"<div class='flash'>{e(msg)}</div>")
    out.append("<div class='mut'>" + " · ".join(f"{e(k)} {v}" for k, v in sorted(cnt.items())) + "</div>")
    out.append("<h2>위반 자산</h2>")
    for r in viol:
        sev = "h" if "높음" in r["result"] else "m" if "중간" in r["result"] else "l"
        out.append(f"<div class='card'><span class='key'>{e(r['asset'])}</span><span class='tag'>{e(r['layer'])}</span>"
                   f"<span class='tag {sev}'>{e(r['result'])}</span><span class='tag'>{e(r['violations'])}</span>"
                   f"<div class='ev'>{e(r['evidence'])}</div>")
        for g in r["violations"].split(";"):
            if not g:
                continue
            out.append(f"<form method='post' action='/except'><input type='hidden' name='token' value='{TOKEN}'>"
                       f"<input type='hidden' name='asset' value='{e(r['asset'])}'><input type='hidden' name='criterion' value='{g}'>"
                       f"<b style='align-self:center'>{g}</b><input name='reason' placeholder='예외 사유 (필수)' required>"
                       f"<input type='date' name='expires' value='{default_exp}' required><button>예외 승인</button></form>")
        out.append("</div>")
    out.append("<h2>승인된 예외</h2><div class='wrap'><table><tr><th>자산</th><th>기준</th><th>사유</th><th>만료</th><th>승인</th></tr>")
    for x in exc[::-1]:
        out.append(f"<tr><td>{e(x['asset'])}</td><td>{e(x['criterion'])}</td><td>{e(x['reason'])}</td><td>{e(x['expires'])}</td>"
                   f"<td>{e(x['approved_by'])} {e(x['approved_at'])}</td></tr>")
    out.append("</table></div><p class='mut'>판정 근거: api-bom/policy/report.md · sbom_report.md · 기준: docs/12_일반승인기준_v3.md · docs/13_SBOM_변화_승인_방법론.md</p></main></body></html>")
    return "".join(out)


def add_exception(asset, criterion, reason, expires):
    new = not os.path.exists(EXC) or os.path.getsize(EXC) == 0
    with open(EXC, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        if new:
            w.writerow(["asset", "criterion", "reason", "expires", "approved_by", "approved_at"])
        w.writerow([asset, criterion, reason, expires, ARGS.user, datetime.now(KST).strftime("%Y-%m-%d %H:%M KST")])
    notes = []
    for script in ("judge.py", "compare_v2_v3.py", "sbom_review.py"):
        r = subprocess.run([sys.executable, os.path.join(HERE, script)], capture_output=True, text=True, cwd=REPO)
        notes.append(f"{script} {'완료' if r.returncode == 0 else '실패'}")
    if ARGS.commit:
        subprocess.run(["git", "add", "--"] + FILES, cwd=REPO, capture_output=True)
        r = subprocess.run(["git", "commit", "-q", "-m", f"exception: {asset} {criterion} 예외 승인 ~{expires} ({ARGS.user})"],
                           cwd=REPO, capture_output=True, text=True)
        notes.append("커밋 " + ("완료" if r.returncode == 0 else "안 됨"))
        if ARGS.push and r.returncode == 0:
            # 다른 곳(이 PC 문서 커밋·cron)이 먼저 push 했을 수 있으니 받아서 위에 올린 뒤 push
            subprocess.run(["git", "pull", "-q", "--rebase"], cwd=REPO, capture_output=True, text=True)
            r = subprocess.run(["git", "push", "-q"], cwd=REPO, capture_output=True, text=True)
            notes.append("push " + ("완료" if r.returncode == 0 else "실패"))
    return " · ".join(notes)


class H(BaseHTTPRequestHandler):
    def send(self, code, body, loc=None):
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Frame-Options", "DENY")
        if loc:
            self.send_header("Location", loc)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path != "/":
            return self.send(404, "없는 경로")
        self.send(200, page(urllib.parse.parse_qs(u.query).get("msg", [""])[0]))

    def do_POST(self):
        if self.path != "/except":
            return self.send(404, "없는 경로")
        n = int(self.headers.get("Content-Length") or 0)
        f = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(min(n, 65536)).decode("utf-8")).items()}
        if not secrets.compare_digest(f.get("token", ""), TOKEN):
            return self.send(403, "토큰이 맞지 않습니다. 새로고침하세요.")
        reason, exp = f.get("reason", "").strip(), f.get("expires", "")
        try:
            if not reason:
                raise ValueError("사유가 비어 있음")
            if date.fromisoformat(exp) < date.today():
                raise ValueError("만료일이 지난 날짜")
            note = add_exception(f["asset"], f["criterion"], reason, exp)
            msg = f"예외 승인: {f['asset']} {f['criterion']} ~{exp} · {note}"
        except (KeyError, ValueError) as ex:
            msg = f"저장 안 됨: {ex}"
        self.send(303, "", loc="/?msg=" + urllib.parse.quote(msg))

    def log_message(self, fmt, *a):
        sys.stderr.write("[예외] " + (fmt % a) + "\n")


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8091)
    ap.add_argument("--user", default=subprocess.run(["git", "config", "user.name"], capture_output=True, text=True,
                                                     cwd=HERE).stdout.strip() or "unknown")
    ap.add_argument("--commit", action="store_true")
    ap.add_argument("--push", action="store_true")
    ARGS = ap.parse_args()
    print(f"예외 승인 대시보드: http://{ARGS.host}:{ARGS.port} (승인자 {ARGS.user}) — Ctrl+C 종료")
    try:
        HTTPServer((ARGS.host, ARGS.port), H).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
