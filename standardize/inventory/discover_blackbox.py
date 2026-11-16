#!/usr/bin/env python3
"""[출처 4 — 블랙박스 발견] 코드를 보지 않고 일반 경로 사전 + 포트 확인으로 자산을 찾는다 (문서 11 §11).

    python api-bom/inventory/discover_blackbox.py <대상 URL> <방화벽 WAN IP> <출력폴더>
    예: python api-bom/inventory/discover_blackbox.py http://192.168.0.141:8000 192.168.0.141 api-bom/inventory

비파괴: GET 요청만, 인증·바디 없음, 초당 10건 제한. User-Agent 'sesac-inventory-scan/1.0' (로그에서 구분 가능).
판정: 출처 3 과 같은 '처리 증거' 규칙(observe_logs.handled_code) + soft-404 보정(구역별 무작위 경로 응답과 비교).
출력: scan_endpoints.csv, scan_ports.csv, scan_summary.md
"""
import csv
import hashlib
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from observe_logs import handled_code, is_dir_redirect

UA = "sesac-inventory-scan/1.0"
RATE = 0.1  # 초당 10건
VERSIONS = ["v1", "v2", "v3", "v4", "v5"]
RESOURCES = ["users", "user", "products", "orders", "cart", "login", "auth", "token", "register", "signup",
             "admin", "config", "debug", "internal", "health", "status", "search", "upload", "files",
             "payments", "diagnostics", "ping", "export", "backup", "test"]
PORTS = [22, 80, 443, 1122, 2222, 3000, 3306, 3322, 3333, 5601, 8000, 8080, 8082, 8083, 8433, 8443, 9000, 9090, 9200]
CALIBRATE = ["/", "/api/", "/api/v1/", "/api/v2/", "/docs/"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with OPENER.open(req, timeout=5) as r:
            body = r.read(1 << 20)
            return str(r.status), r.headers.get("Content-Type", ""), body
    except urllib.error.HTTPError as e:
        body = e.read(1 << 20) if e.fp else b""
        return str(e.code), e.headers.get("Content-Type", "") if e.headers else "", body
    except Exception as e:  # 연결 실패 등
        return "ERR", type(e).__name__, b""
    finally:
        time.sleep(RATE)


def expand(lines):
    out = []
    for p in lines:
        p = p.strip()
        if not p or p.startswith("#"):
            continue
        vs = VERSIONS if "{v}" in p else [None]
        rs = RESOURCES if "{r}" in p else [None]
        for v in vs:
            for r in rs:
                out.append(p.replace("{v}", v or "").replace("{r}", r or ""))
    return list(dict.fromkeys(out))


def zone_of(path):
    best = "/"
    for z in CALIBRATE:
        if path.startswith(z) and len(z) > len(best):
            best = z
    return best


def main(target, wan_ip, outdir):
    target = target.rstrip("/")
    started = datetime.now(timezone.utc)
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "wordlist_generic.txt"), encoding="utf-8") as f:
        paths = expand(f)

    # 1) soft-404 보정: 구역마다 무작위 경로 2개
    calib = {}
    for z in CALIBRATE:
        seen = set()
        for _ in range(2):
            code, ctype, body = fetch(target + z + "zz" + uuid.uuid4().hex[:12])
            seen.add((code, len(body) // 64))
        calib[z] = seen

    # 2) 경로 사전
    rows = []
    for p in paths:
        code, ctype, body = fetch(target + p)
        soft = (code, len(body) // 64) in calib[zone_of(p)]
        evidence = (not soft) and handled_code(code, p.rstrip("/") + "/", "GET")
        if evidence:
            verdict = "발견(처리 증거)"
        elif is_dir_redirect(code, p.rstrip("/")) and not soft:
            verdict = "폴더 존재(301)"
        else:
            verdict = "없음/soft-404"
        rows.append([p, code, ctype.split(";")[0], len(body), hashlib.sha256(body).hexdigest()[:12],
                     "y" if soft else "", verdict])

    # 3) 포트 확인 (TCP 연결만)
    ports = []
    for port in PORTS:
        s = socket.socket()
        s.settimeout(1.5)
        try:
            s.connect((wan_ip, port))
            state = "open"
        except socket.timeout:
            state = "filtered"
        except OSError:
            state = "closed"
        finally:
            s.close()
        ports.append([wan_ip, port, state])

    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "scan_endpoints.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["path", "status", "content_type", "bytes", "body_sha256_12", "soft404_match", "verdict"])
        w.writerows(sorted(rows, key=lambda r: (r[6] != "발견(처리 증거)", r[6] != "폴더 존재(301)", r[0])))
    with open(os.path.join(outdir, "scan_ports.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["host", "port", "state"])
        w.writerows(ports)

    found = [r for r in rows if r[6] != "없음/soft-404"]
    md = ["# 출처 4 — 블랙박스 발견 요약", "",
          f"- 실행: {started:%Y-%m-%d %H:%M} UTC, 대상 `{target}`, 포트 대상 `{wan_ip}`, 출발지 이 PC",
          f"- 요청: GET {len(paths) + len(CALIBRATE) * 2}건 (사전 {len(paths)} + 보정 {len(CALIBRATE) * 2}), UA `{UA}`, 초당 10건",
          "- 사전: `wordlist_generic.txt` (코드·기준선과 독립인 일반 이름)", "",
          "## soft-404 보정 (무작위 경로 응답: 상태코드, 크기/64)", "", "| 구역 | 응답 |", "|---|---|"]
    md += [f"| `{z}` | {sorted(v)} |" for z, v in calib.items()]
    md += ["", f"## 발견 {len(found)}개", "", "| 경로 | 상태 | 형식 | 판정 |", "|---|---|---|---|"]
    md += [f"| `{r[0]}` | {r[1]} | {r[2]} | {r[6]} |" for r in found]
    md += ["", "## 포트 (WAN 주소 TCP 연결)", "", "| 포트 | 상태 |", "|---|---|"]
    md += [f"| {p[1]} | {p[2]} |" for p in ports]
    with open(os.path.join(outdir, "scan_summary.md"), "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
