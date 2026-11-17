#!/usr/bin/env python3
"""offspec_triage.py 시나리오 시험 — 판정표(offspec_triage.md)의 각 칸이 의도대로 나오는지.

    python standardize/policy/test_offspec_triage.py

로그·명세·기준선은 시험 안에서 만든다(가짜 데이터). 탐지 정확도가 아니라 판정 규칙 구현을 확인한다.
"""
import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "offspec_triage.py")

SPEC = {"openapi": "3.0.0", "paths": {
    "/api/items": {"get": {}},
    "/api/items/{id}": {"get": {}},
    "/api/orders": {"get": {}, "post": {}},
}}

BASELINE = [
    # endpoint_key, decision, owner, frontend
    ("GET /api/export/report", "active", "data-team", "y"),   # 명세 누락 (승인·소유자 있음)
    ("GET /api/legacy/stock", "active", "", "n"),            # 승인됐으나 소유자 없음
    ("GET /api/v0/items", "deprecated", "catalog", "n"),       # Zombie, 소유자 있음
    ("GET /api/v0/orders", "deprecated", "", "n"),             # Zombie, 소유자 없음
    ("GET /api/debug/ping", "remove", "ops", "n"),             # 제거 결정인데 응답
    ("GET /api/beta/reviews", "review", "review-team", "n"),   # 검토 중 + 소유자 + 꾸준한 이용
    ("GET /api/old/never", "deprecated", "catalog", "n"),      # 로그에 없음
]

USERS = [f"10.0.0.{i}" for i in range(1, 6)]     # 정상 이용 이력 출발지 5곳
PROBER = "203.0.113.9"                            # 탐색 흔적 출발지


def line(ip, hour, method, path, status):
    return f'{ip} - - [10/Nov/2026:{hour:02d}:00:00 +0000] "{method} {path} HTTP/1.1" {status} 10 "-" "t"'


def build_log():
    L = []
    for h in (9, 10, 11):
        for ip in USERS:
            L += [line(ip, h, "GET", "/api/items", 200)] * 2
            L += [line(ip, h, "GET", f"/api/items/{h}", 200)]
            L += [line(ip, h, "GET", "/api/export/report", 200)]
            L += [line(ip, h, "GET", "/api/beta/reviews", 200)]
            L += [line(ip, h, "GET", "/api/partner/feed", 200)]       # 미등록인데 꾸준한 정상 이용
            L += [line(ip, h, "GET", "/api/admin/stats", 200)]        # 미등록 + 관리 이름 + 꾸준한 이용
    L += [line(USERS[0], 9, "GET", "/api/legacy/stock", 200)]
    L += [line(USERS[1], 9, "GET", "/api/v0/items", 200)]
    L += [line(USERS[1], 9, "GET", "/api/v0/orders", 200)]
    L += [line(USERS[2], 9, "GET", "/api/debug/ping", 200)]
    # 탐색 흔적: 서로 다른 없는 경로 6개 + 미등록 경로 하나에서 성공
    for i in range(6):
        L += [line(PROBER, 12, "GET", f"/api/guess{i}", 404)]
    L += [line(PROBER, 12, "GET", "/api/internal/dump", 200)]
    L += [line(PROBER, 12, "DELETE", "/api/items/7", 200)]           # 읽기 경로에 쓰기 메서드
    L += [line(PROBER, 12, "GET", "/api/maybe", 401)] * 2            # 존재 불명
    return "\n".join(L) + "\n"


class TriageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        p = lambda n: os.path.join(cls.tmp, n)
        with open(p("spec.json"), "w", encoding="utf-8") as f:
            json.dump(SPEC, f)
        with open(p("base.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["layer", "endpoint_key", "decision", "owner", "frontend"])
            for k, d, o, fe in BASELINE:
                w.writerow(["endpoint", k, d, o, fe])
        with open(p("access.log"), "w", encoding="utf-8") as f:
            f.write(build_log())
        r = subprocess.run([sys.executable, SCRIPT, "--spec", p("spec.json"), "--baseline", p("base.csv"),
                            "--log", p("access.log"), "--out-dir", p("out")], capture_output=True, text=True,
                           encoding="utf-8")
        if r.returncode:
            raise RuntimeError(r.stderr)
        with open(p("out/offspec_triage.csv"), encoding="utf-8") as f:
            cls.rows = {x["endpoint_key"]: x for x in csv.DictReader(f)}
        with open(p("out/offspec_notfound.csv"), encoding="utf-8") as f:
            cls.notfound = {x["endpoint_key"] for x in csv.DictReader(f)}
        with open(p("out/offspec_allowlist.yaml"), encoding="utf-8") as f:
            cls.allow = f.read()

    def check(self, key, cls_prefix, grade):
        self.assertIn(key, self.rows, f"{key} 가 결과에 없음")
        r = self.rows[key]
        self.assertTrue(r["class"].startswith(cls_prefix), f"{key}: {r['class']}")
        self.assertEqual(r["grade"], grade, f"{key}: {r['grade']} ({r['risk']} / {r['mitigation']})")
        return r

    # 승인 상태
    def test_approved_with_owner_is_doc_gap(self):
        self.check("GET /api/export/report", "명세 누락", "정보")
        self.assertIn("/api/export/report", self.allow)

    def test_approved_without_owner(self):
        self.check("GET /api/legacy/stock", "승인됐으나 소유자 없음", "낮음")
        self.assertNotIn("/api/legacy/stock", self.allow)

    def test_zombie_owner_matters(self):
        self.check("GET /api/v0/items", "폐기 예정", "중간")
        self.check("GET /api/v0/orders", "폐기 예정", "높음")

    def test_removed_but_alive(self):
        self.check("GET /api/debug/ping", "제거 결정", "높음")

    def test_review_with_owner_and_steady_use(self):
        r = self.check("GET /api/beta/reviews", "검토 중", "낮음")
        self.assertIn("정상 이용 이력", r["mitigation"])

    # 사용 맥락 (미등록)
    def test_unregistered_steady_use_is_low(self):
        self.check("GET /api/partner/feed", "미등록", "낮음")

    def test_unregistered_sensitive_name_with_steady_use_is_medium(self):
        self.check("GET /api/admin/stats", "미등록", "중간")

    def test_unregistered_success_only_from_prober_is_high(self):
        r = self.check("GET /api/internal/dump", "미등록", "높음")
        self.assertIn("탐색 흔적", r["risk"])

    def test_write_method_on_read_path_is_high(self):
        r = self.check("DELETE /api/items/{id}", "미등록", "높음")
        self.assertIn("쓰기 메서드", r["risk"])

    def test_unknown_existence(self):
        self.check("GET /api/maybe", "존재 불명", "낮음")

    def test_404_only_is_not_an_asset(self):
        self.assertIn("GET /api/guess0", self.notfound)
        self.assertNotIn("GET /api/guess0", self.rows)

    def test_baseline_only(self):
        self.check("GET /api/old/never", "기준선에만 있음", "정보")

    def test_in_spec_not_reported(self):
        self.assertNotIn("GET /api/items", self.rows)
        self.assertNotIn("GET /api/items/{id}", self.rows)


if __name__ == "__main__":
    unittest.main(verbosity=2)
