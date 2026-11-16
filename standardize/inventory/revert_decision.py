#!/usr/bin/env python3
"""[정정] 기준선 v2 에서 이미 확정한 항목(active·deprecated·remove)을 다른 판정으로 바꾼다.
대시보드·approve.py 는 review 상태만 바꿀 수 있어서, 잘못 누른 판정을 되돌릴 때 쓴다 (2026-11-04 users/{id} 정정).

    python3 api-bom/inventory/revert_decision.py <layer> "<key>" <판정> "<사유>" [--by 이름] [--commit] [--push]
    예) python3 api-bom/inventory/revert_decision.py endpoint "GET /api/v1/users/{id}" review "BOLA 실증 — 담당자 확인 전 보류" --commit --push

인벤토리 파일은 VM 에서만 바꾼다 (원칙). 저장은 decisions.py 의 같은 함수 → decisions_log.csv 에 이전→이후·사유가 남는다.
사유는 필수.
"""
import argparse
import os
import subprocess
import sys

import decisions as D

FILES = ["api-bom/inventory/candidates.csv", "api-bom/inventory/baseline_v2.csv",
         "api-bom/inventory/decisions_log.csv", "api-bom/inventory/inventory.cdx.json", "api-bom/inventory/inventory.md"]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("layer", help="endpoint / service")
    ap.add_argument("key", help='예: "GET /api/v1/users/{id}", fw-ssh')
    ap.add_argument("decision", choices=sorted(D.REVIEW_CHOICES))
    ap.add_argument("reason")
    ap.add_argument("--by", default=None)
    ap.add_argument("--commit", action="store_true")
    ap.add_argument("--push", action="store_true")
    a = ap.parse_args()
    if not a.reason.strip():
        sys.exit("사유는 필수")
    by = a.by or D.git_user()

    bf, base = D.load(D.BASE2)
    r = next((r for r in base if r["layer"] == a.layer and r["endpoint_key"] == a.key), None)
    if r is None:
        sys.exit(f"기준선에 없음: {a.layer} {a.key}")
    before = r["decision"]
    if before == a.decision:
        sys.exit(f"이미 {before}")
    t = D.now()
    D.log_decision(at=t, by=by, mode="review", layer=a.layer, key=a.key, before=before, after=a.decision,
                   owner=r["owner"], reason=a.reason)
    r.update({"decision": a.decision,
              "note": (r["note"] + " | " if r["note"] else "") + f"{t} {by}: {a.decision} {a.reason}"})
    D.save(D.BASE2, bf, base)
    print(f"{a.layer} {a.key}: {before} → {a.decision} ({by}, {t})")

    repo = os.path.dirname(os.path.dirname(D.HERE))
    subprocess.run([sys.executable, os.path.join(D.HERE, "merge_inventory.py")], cwd=repo, check=True,
                   stdout=subprocess.DEVNULL)
    print("인벤토리 재생성 완료")
    if a.commit:
        subprocess.run(["git", "add", "--"] + FILES, cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", f"approve: {a.layer} {a.key} → {a.decision} ({by}, 정정)"],
                       cwd=repo, check=True)
        print("커밋 완료")
        if a.push:
            subprocess.run(["git", "pull", "-q", "--rebase"], cwd=repo)
            subprocess.run(["git", "push", "-q"], cwd=repo, check=True)
            print("push 완료")


if __name__ == "__main__":
    main()
