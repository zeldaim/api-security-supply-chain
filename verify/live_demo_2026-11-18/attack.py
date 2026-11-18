#!/usr/bin/env python3
"""실시간 시연용 공격 (시험 장치). 기존 dvra_traffic.py 의 함수를 그대로 쓰고, 차단이 보이도록 길게 보낸다.
  python attack.py probe          명세 밖 탐색 15건 (10.66.0.2)  — Shadow 룰 → 숨은 API 성공(L3) 이면 차단
  python attack.py bola [--n 150] 남의 주문 1..n 열거 (10.77.0.2, 0.4초 간격) — ML → 차단 뒤 403 이 보인다
"""
import argparse, time
import dvra_traffic as T

def probe():
    ip = "10.66.0.2"; tok = T.account(ip, "prober_live")
    for m, p in T.PROBES:
        st, _ = T.req(m, p, ip, None, tok); print(f"{m} {p} -> {st}", flush=True); time.sleep(0.5)

def bola(n):
    ip = "10.77.0.2"; tok = T.account(ip, "attacker_live"); first403 = None
    for oid in range(1, n + 1):
        st, _ = T.req("GET", f"/orders/{oid}", ip, None, tok)
        if st == 403 and first403 is None:
            first403 = oid; print(f"*** 차단됨: 주문 {oid} 부터 403 ***", flush=True)
        if oid % 10 == 0: print(f"주문 {oid} -> {st}", flush=True)
        time.sleep(0.4)
    print(f"끝: 열거 {n}건 · 첫 403 = {first403}", flush=True)

if __name__ == "__main__":
    a = argparse.ArgumentParser(); a.add_argument("mode", choices=["probe", "bola"]); a.add_argument("--n", type=int, default=150)
    x = a.parse_args(); probe() if x.mode == "probe" else bola(x.n)
