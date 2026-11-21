#!/usr/bin/env python3
"""spring-petclinic 시험 트래픽 (시험 장치 — 제품 코드 아님). nginx 앞단(:8099), 출발지는 X-Client-IP 헤더.

  python petclinic_traffic.py normal --users 12 --rounds 8    정상: 접수 직원이 보호자 검색 · 상세 · 수정 · 반려동물 · 방문 등록 · 수의사 목록
                                                             + 모니터링 서버가 /actuator/health 를 주기적으로 확인 (승인된 운영 호출)
  python petclinic_traffic.py probe                           명세 밖 탐색 (10.66.0.1) — 숨은 실제 경로 포함, 정답지 work/probe_paths.txt
  python petclinic_traffic.py bola                            보호자 번호 열거 (10.77.0.1) — 인증이 없는 앱이라 개인정보 긁어 가기
표준 라이브러리만 쓴다. 앱에 로그인 기능이 없어서 계정 · 토큰 단계는 없다.
"""
import argparse
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8099"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def req(method, path, ip, form=None):
    h = {"X-Client-IP": ip, "User-Agent": "Mozilla/5.0 (petclinic-test)"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with OPENER.open(r, timeout=30) as resp:
            return resp.status, resp.read(65536).decode(errors="replace"), resp.headers
    except urllib.error.HTTPError as e:   # 3xx(리다이렉트를 따라가지 않음) · 4xx · 5xx
        return e.code, e.read(65536).decode(errors="replace"), e.headers


def new_owner(ip, n):
    st, _, h = req("POST", "/owners/new", ip, {"firstName": f"Guest{n}", "lastName": f"Visitor{n}",
                                               "address": "1 Test St.", "city": "Seoul",
                                               "telephone": "01%08d" % random.randint(0, 99999999)})
    m = re.search(r"/owners/(\d+)", h.get("Location", "") if h else "")
    return int(m.group(1)) if m else None


def new_pet(ip, owner):
    req("GET", f"/owners/{owner}/pets/new", ip)
    req("POST", f"/owners/{owner}/pets/new", ip, {"name": "Pet%04d" % random.randint(0, 9999),
                                                  "birthDate": "2022-03-0%d" % random.randint(1, 9),
                                                  "type": random.choice(["cat", "dog", "hamster"])})


def normal(users, rounds, pause):
    staff = []
    for i in range(users):
        ip = f"10.10.0.{i + 1}"
        mine = random.sample(range(1, 11), 2)                 # 직원마다 담당 보호자 2명 (초기 데이터 1~10)
        req("GET", "/", ip)
        o = new_owner(ip, i + 1) if random.random() < 0.5 else None
        if o:
            mine.append(o)
        staff.append((ip, mine))
    for r in range(rounds):
        req("GET", "/actuator/health", "10.10.0.200")         # 모니터링 서버 (헬스 체크)
        for ip, mine in staff:
            o = random.choice(mine)
            steps = [("GET", "/owners/find"), ("GET", "/owners?lastName=" + random.choice(["Davis", "Franklin", ""])),
                     ("GET", f"/owners/{o}"), ("GET", "/vets.html"), ("GET", "/vets.html?page=2"),
                     ("GET", f"/owners/{o}/edit")]
            random.shuffle(steps)
            for m, p in steps[: random.randint(2, 4)]:
                req(m, p, ip)
            if random.random() < 0.15:
                new_pet(ip, o)
            if random.random() < 0.1:
                st, body, _ = req("GET", f"/owners/{o}", ip)
                pets = re.findall(rf"/owners/{o}/pets/(\d+)/visits/new", body) or re.findall(r"pets/(\d+)/visits/new", body)
                if pets:
                    p = pets[0]
                    req("GET", f"/owners/{o}/pets/{p}/visits/new", ip)
                    req("POST", f"/owners/{o}/pets/{p}/visits/new", ip, {"date": "2026-11-21", "description": "checkup"})
            time.sleep(pause)
    req("GET", "/oups", "10.10.0.1")                         # 메뉴의 'Error' 를 누른 직원 (화면에 있는 기능)
    print(f"정상: 직원 {users} · {rounds}회 · 헬스 체크 {rounds}회")


PROBES = [  # 숨은 실제 경로: /vets (JSON, 화면에 링크 없음) · actuator (설정으로 열림) + 흔한 탐색 경로
    ("GET", "/vets"), ("GET", "/actuator"), ("GET", "/actuator/env"), ("GET", "/actuator/heapdump"),
    ("GET", "/actuator/mappings"), ("GET", "/actuator/configprops"), ("GET", "/actuator/beans"),
    ("GET", "/admin"), ("GET", "/api/v1/users"), ("GET", "/v3/api-docs"), ("GET", "/h2-console"),
    ("GET", "/.env"), ("GET", "/owners/abc"), ("DELETE", "/owners/1"), ("GET", "/backup.zip"),
]


def probe():
    ip = "10.66.0.1"
    req("GET", "/", ip)
    with open("work/probe_paths.txt", "w", encoding="utf-8") as f:
        for m, p in PROBES:
            st, _, _ = req(m, p, ip)
            f.write(f"{m} {p} {st}\n")
            time.sleep(0.3)
    print(f"탐색: {len(PROBES)}건 (출발지 {ip})")


def bola():
    ip = "10.77.0.1"
    req("GET", "/owners/find", ip)
    for oid in range(1, 31):                                 # 보호자 번호 열거 (이름 · 주소 · 전화번호)
        req("GET", f"/owners/{oid}", ip)
        req("GET", f"/owners/{oid}/edit", ip)
        time.sleep(0.15)
    print(f"BOLA: 보호자 1~30 상세 · 수정 화면 (출발지 {ip})")


if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("mode", choices=["normal", "probe", "bola"])
    a.add_argument("--users", type=int, default=12)
    a.add_argument("--rounds", type=int, default=8)
    a.add_argument("--pause", type=float, default=0.3)
    x = a.parse_args()
    {"normal": lambda: normal(x.users, x.rounds, x.pause), "probe": probe, "bola": bola}[x.mode]()
