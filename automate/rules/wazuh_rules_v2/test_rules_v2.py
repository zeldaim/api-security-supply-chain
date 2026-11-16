r"""
rules_v2 시나리오 시험 — v1 과 v2 가 같은 세션에서 어떻게 다르게 판정하는지 기대값으로 고정한다.

  python api-bom/wazuh/rules_v2/test_rules_v2.py

기대값은 "의도"(정상이면 자동 차단 0, 빠른 성공 열거면 차단, 막힌 열거면 알림만)에서 정했다. 룰 출력을 보고 맞춘 게 아니다.
한계: 파이썬 재현(tools/rule_fp_check.py)이다. Wazuh 기본 룰 트리(31101 4xx · 31108 단순 2xx 요청)를 모델링하지 않으므로
      아래 표의 v1 열은 실제와 다르다(예: v1 100904 는 실제로 200 응답에는 안 울리고 403 에만 울린다).
      실제 판정 기준은 logtest_docker.sh (wazuh-logtest 4.14.6) 결과 — README.md 참조. 이 시험은 v2 의 기대값 고정용.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import rule_fp_check as R  # noqa: E402

HS256_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMiJ9.c2lnbmF0dXJl"   # 정상 HS256 토큰 모양
NONE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."                 # alg:none 위조


def line(ip, sec, url, status, method="GET"):
    m, s = divmod(sec, 60)
    return f'{ip} - - [10/Nov/2026:09:{m:02d}:{s:02d} +0000] "{method} {url} HTTP/1.1" {status} 312 "-" "Mozilla/5.0"'


def session(lines):
    return [R.parse_line(l) for l in lines]


# (이름, 세션, v2 기대 최고 레벨, v2 기대 룰 집합, 설명)
CASES = [
    ("정상: 자기 프로필 1회 조회", session([line("10.1.0.1", 0, "/api/v2/users/12", 200)]),
     0, set(), "단일 조회는 경보 없음"),
    ("정상: 자기 주문 5건 빠르게 확인", session([line("10.1.0.2", i, f"/api/v2/orders/{2000+i}", 200) for i in range(5)]),
     0, set(), "임계(10) 미만"),
    ("정상: 같은 주문 새로고침 15회", session([line("10.1.0.3", i, "/api/v2/orders/2001", 200) for i in range(15)]),
     0, set(), "서로 다른 URL 이 아님"),
    ("정상: HS256 토큰이 URL 에 실린 요청", session([line("10.1.0.4", 0, f"/me.php?token={HS256_JWT}", 200)]),
     0, set(), "표준 HS256 토큰은 정상 (v1 은 실제 Wazuh 에서도 L12)"),
    ("공격: 빠른 BOLA 성공 (20개, 1초 간격, 200)", session([line("10.2.0.1", i, f"/api/v2/orders/{3000+i}", 200) for i in range(20)]),
     12, {"100923"}, "성공 열거 → 자동 차단"),
    ("공격: 빠른 BOLA 거부 (20개, 403)", session([line("10.2.0.2", i, f"/api/v1/users/{i+1}", 403) for i in range(20)]),
     8, {"100924"}, "막힌 시도 → 알림만"),
    ("공격: alg:none JWT", session([line("10.2.0.3", 0, f"/api/v2/cart?token={NONE_JWT}", 200)]),
     12, {"100914"}, "위조 토큰은 계속 탐지"),
    ("공격: 명령 주입", session([line("10.2.0.4", 0, "/api/v1/diagnostics/ping?host=127.0.0.1;id", 200)]),
     14, {"100913"}, "서명 룰 유지"),
]


def main():
    v1, v2 = R.load_rules(R.V1), R.load_rules(R.V2)
    fails = 0
    print("| 시나리오 | v1 최고 레벨 | v2 최고 레벨 | v2 룰 | 기대 | 결과 |")
    print("|---|---|---|---|---|---|")
    for name, sess, exp_lvl, exp_rules, note in CASES:
        h1, h2 = R.run_session(sess, v1), R.run_session(sess, v2)
        l1, l2 = max((l for _, l in h1), default=0), max((l for _, l in h2), default=0)
        got = {rid for rid, _ in h2}
        ok = l2 == exp_lvl and got == exp_rules
        fails += not ok
        print(f"| {name} | {l1} | {l2} | {', '.join(sorted(got)) or '-'} | L{exp_lvl} {sorted(exp_rules) or ''} ({note}) | {'PASS' if ok else 'FAIL'} |")
    print(f"\n{len(CASES) - fails}/{len(CASES)} 통과")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
