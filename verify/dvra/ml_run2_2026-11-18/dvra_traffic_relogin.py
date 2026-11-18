#!/usr/bin/env python3
"""dvra_traffic.py 의 normal 을 그대로 쓰되, 토큰이 만료돼 401 이 오면 다시 로그인(/token)하고 그 요청을 한 번 더 보낸다.
1차(dvra_ml_2026-11-18)는 DVRA 토큰 30분 만료로 정상 요청 절반이 401 이 됐다 — 그 문제만 고친 래퍼. 원본 생성기는 그대로.
  python dvra_traffic_relogin.py --users 30 --rounds 130 --pause 1.0
"""
import argparse
import dvra_traffic as T

_orig_req, _orig_account = T.req, T.account
_creds, _alias = {}, {}            # 토큰 → (ip, 이름) / 만료된 토큰 → 새 토큰


def account(ip, name):
    tok = _orig_account(ip, name)
    if tok:
        _creds[tok] = (ip, name)
    return tok


def login(ip, name):
    st, body = _orig_req("POST", "/token", ip, {"username": name, "password": "Passw0rd!x"}, form=True)
    try:
        return T.json.loads(body)["access_token"]
    except (ValueError, KeyError):
        return None


def req(method, path, ip, body=None, token=None, form=False):
    cur = _alias.get(token, token)
    st, b = _orig_req(method, path, ip, body, cur, form)
    if st == 401 and cur in _creds:          # 세션 만료 → 사람처럼 다시 로그인
        ip0, name = _creds[cur]
        new = login(ip0, name)
        if new:
            _creds[new] = (ip0, name)
            _alias[token] = _alias[cur] = new
            st, b = _orig_req(method, path, ip, body, new, form)
    return st, b


T.req, T.account = req, account

if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--users", type=int, default=30)
    a.add_argument("--rounds", type=int, default=130)
    a.add_argument("--pause", type=float, default=1.0)
    x = a.parse_args()
    T.normal(x.users, x.rounds, x.pause)
    print(f"재로그인 {len(_alias)}회 (만료된 토큰 수)")
