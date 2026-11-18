#!/usr/bin/env python3
"""VAmPI 시험 트래픽 (시험 장치 — 제품 코드 아님). nginx 앞단(:8088)으로 보내고, 출발지는 X-Client-IP 헤더로 나눈다.

  python vampi_traffic.py normal --users 12 --rounds 6     정상: 가입 · 로그인 · 책 목록 · 내 책 · 내 정보 · 이메일 변경
  python vampi_traffic.py probe                            명세 밖 탐색 (10.66.0.1) — 정답지 work/probe_paths.txt
  python vampi_traffic.py bola                             남의 책 제목 · 사용자 이름 열거 (10.77.0.1)
표준 라이브러리만 쓴다.
"""
import argparse
import json
import random
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8088"


def req(method, path, ip, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"X-Client-IP": ip, "User-Agent": "Mozilla/5.0 (vampi-test)"}
    if data:
        h["Content-Type"] = "application/json"
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def login(ip, user, pw):
    st, body = req("POST", "/users/v1/login", ip, {"username": user, "password": pw})
    try:
        return json.loads(body).get("auth_token")
    except ValueError:
        return None


def normal(users, rounds, pause):
    accounts = []
    for i in range(users):
        ip, name, pw = f"10.10.0.{i + 1}", f"normal{i + 1:02d}", "Passw0rd!x"
        req("POST", "/users/v1/register", ip, {"username": name, "password": pw, "email": f"{name}@example.test"})
        tok = login(ip, name, pw)
        title = f"book-{name}"
        req("POST", "/books/v1", ip, {"book_title": title, "secret": "my secret"}, tok)
        accounts.append((ip, name, pw, tok, title))
    for r in range(rounds):
        for ip, name, pw, tok, title in accounts:
            steps = [("GET", "/books/v1", None), ("GET", f"/books/v1/{title}", None), ("GET", "/me", None),
                     ("GET", "/users/v1", None)]
            random.shuffle(steps)
            for m, p, b in steps[: random.randint(2, 4)]:
                req(m, p, ip, b, tok)
            if random.random() < 0.2:
                req("PUT", f"/users/v1/{name}/email", ip, {"email": f"{name}.{r}@example.test"}, tok)
            if random.random() < 0.1:
                tok = login(ip, name, pw)
            time.sleep(pause)
    print(f"정상: 사용자 {users} · {rounds}회")


PROBES = [  # 명세 밖 탐색 — 범위 안(/users · /books · /me 로 시작)과 범위 밖을 섞는다
    ("GET", "/users/v2"), ("GET", "/users/v1/admin/list"), ("GET", "/users/v1/_internal"), ("POST", "/users/v1/reset"),
    ("GET", "/books/v1/export/all"), ("GET", "/books/v2"), ("DELETE", "/books/v1/bookTitle16"), ("PATCH", "/me"),
    ("GET", "/admin"), ("GET", "/api/v1/users"), ("GET", "/debug"), ("GET", "/swagger.json"), ("GET", "/actuator/health"),
    ("GET", "/users"), ("GET", "/books"),
]


def probe():
    ip = "10.66.0.1"
    with open("work/probe_paths.txt", "w", encoding="utf-8") as f:
        for m, p in PROBES:
            st, _ = req(m, p, ip)
            f.write(f"{m} {p} {st}\n")
            time.sleep(0.3)
    print(f"탐색: {len(PROBES)}건 (출발지 {ip})")


def bola():
    ip = "10.77.0.1"
    req("POST", "/users/v1/register", ip, {"username": "attacker1", "password": "Passw0rd!x", "email": "a1@example.test"})
    tok = login(ip, "attacker1", "Passw0rd!x")
    st, body = req("GET", "/books/v1", ip, None, tok)
    titles = [b["book_title"] for b in json.loads(body).get("Books", [])]
    users = sorted({b["user"] for b in json.loads(body).get("Books", [])})
    for t in titles:                                  # 남의 책 비밀 조회 (BOLA)
        req("GET", f"/books/v1/{t}", ip, None, tok)
        time.sleep(0.2)
    for u in users:                                   # 사용자 정보 열거
        req("GET", f"/users/v1/{u}", ip, None, tok)
        time.sleep(0.2)
    print(f"BOLA: 책 {len(titles)}권 · 사용자 {len(users)}명 (출발지 {ip})")


if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("mode", choices=["normal", "probe", "bola"])
    a.add_argument("--users", type=int, default=12)
    a.add_argument("--rounds", type=int, default=6)
    a.add_argument("--pause", type=float, default=0.5)
    x = a.parse_args()
    {"normal": lambda: normal(x.users, x.rounds, x.pause), "probe": probe, "bola": bola}[x.mode]()
