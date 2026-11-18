#!/usr/bin/env python3
"""Damn Vulnerable RESTaurant 시험 트래픽 (시험 장치 — 제품 코드 아님). nginx 앞단(:8089), 출발지는 X-Client-IP 헤더.

  python dvra_traffic.py normal --users 12 --rounds 8    정상: 가입 · 토큰 · 메뉴 · 주문 · 내 주문 · 내 정보 (개발자 1명은 /docs 도 연다)
  python dvra_traffic.py probe                           명세 밖 탐색 (10.66.0.1) — 숨은 API 3개 포함, 정답지 work/probe_paths.txt
  python dvra_traffic.py bola                            남의 주문 번호 열거 (10.77.0.1)
표준 라이브러리만 쓴다.
"""
import argparse
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8089"


def req(method, path, ip, body=None, token=None, form=False):
    h = {"X-Client-IP": ip, "User-Agent": "Mozilla/5.0 (dvra-test)"}
    data = None
    if body is not None:
        data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def phone(name):
    """앱이 전화번호 중복을 막으므로 계정마다 다른 번호"""
    return "010-%04d-%04d" % (sum(map(ord, name)) % 10000, abs(hash(name)) % 10000)


def account(ip, name):
    pw = "Passw0rd!x"
    req("POST", "/register", ip, {"username": name, "password": pw, "phone_number": phone(name),
                                  "first_name": name, "last_name": "test"})
    st, body = req("POST", "/token", ip, {"username": name, "password": pw}, form=True)
    try:
        return json.loads(body)["access_token"]
    except (ValueError, KeyError):
        return None


def order(ip, tok):
    st, body = req("POST", "/orders", ip, {"delivery_address": "Seoul", "phone_number": "010-1111-2222",
                                           "items": [{"menu_item_id": random.randint(1, 5), "quantity": 1}]}, tok)
    try:
        return json.loads(body)["id"]
    except (ValueError, KeyError):
        return None


def normal(users, rounds, pause):
    accts = []
    for i in range(users):
        ip, name = f"10.10.0.{i + 1}", f"guest{i + 1:02d}"
        tok = account(ip, name)
        accts.append([ip, tok, [o for o in [order(ip, tok)] if o]])
    for r in range(rounds):
        for ip, tok, mine in accts:
            steps = [("GET", "/menu"), ("GET", "/orders"), ("GET", "/profile")]
            if mine:
                oid = random.choice(mine)
                steps += [("GET", f"/orders/{oid}"), ("GET", f"/orders/status/{oid}")]
            random.shuffle(steps)
            for m, p in steps[: random.randint(2, 4)]:
                req(m, p, ip, None, tok)
            if random.random() < 0.15:
                o = order(ip, tok)
                if o:
                    mine.append(o)
            time.sleep(pause)
    req("GET", "/docs", "10.10.0.1")              # 개발자가 문서 화면을 연다 (현실적인 정상 행동)
    req("GET", "/openapi.json", "10.10.0.1")
    print(f"정상: 사용자 {users} · {rounds}회")


PROBES = [  # 숨은 API 3개(소스에서 include_in_schema=False) + 흔한 탐색 경로
    ("GET", "/debug"), ("GET", "/delivery/orders"), ("GET", "/admin/reset-chef-password"),
    ("GET", "/admin"), ("GET", "/api/v1/users"), ("GET", "/swagger.json"), ("GET", "/actuator/health"),
    ("GET", "/orders/export"), ("GET", "/menu/abc"), ("GET", "/users"), ("POST", "/menu"), ("DELETE", "/orders/1"),
    ("GET", "/backup.zip"), ("GET", "/admin/stats/memory"), ("GET", "/internal/metrics"),
]


def probe():
    ip = "10.66.0.1"
    tok = account(ip, "prober2")
    with open("work/probe_paths.txt", "w", encoding="utf-8") as f:
        for m, p in PROBES:
            st, _ = req(m, p, ip, None, tok)
            f.write(f"{m} {p} {st}\n")
            time.sleep(0.3)
    print(f"탐색: {len(PROBES)}건 (출발지 {ip})")


def bola():
    ip = "10.77.0.1"
    tok = account(ip, "attacker2")
    order(ip, tok)
    for oid in range(1, 31):                       # 남의 주문 번호 열거
        req("GET", f"/orders/{oid}", ip, None, tok)
        req("GET", f"/orders/status/{oid}", ip, None, tok)
        time.sleep(0.15)
    print(f"BOLA: 주문 1~30 · 상태 1~30 (출발지 {ip})")


if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("mode", choices=["normal", "probe", "bola"])
    a.add_argument("--users", type=int, default=12)
    a.add_argument("--rounds", type=int, default=8)
    a.add_argument("--pause", type=float, default=0.3)
    x = a.parse_args()
    {"normal": lambda: normal(x.users, x.rounds, x.pause), "probe": probe, "bola": bola}[x.mode]()
