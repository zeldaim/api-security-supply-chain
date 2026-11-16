#!/usr/bin/env python3
"""[터미널판] 추가 후보를 보고 기준선 v2 에 넣을지 고른다 (사람 = 출처 6, 문서 11 §13).
웹 화면으로 하려면 approval_server.py. 저장 로직은 둘 다 decisions.py 를 쓴다.

    python api-bom/inventory/approve.py            # 새 추가 후보 고르기
    python api-bom/inventory/approve.py --review   # 기준선에 review 로 있는 것 다시 판단 (v1 의 review 2개 포함)

모든 선택은 decisions_log.csv 에 한 줄씩 쌓인다 (언제·누가·무엇을·이전→이후·이유).
"""
import sys

import decisions as D

CAND_KEYS = {"1": "add:active", "2": "add:deprecated", "3": "add:review", "4": "reject"}
REVIEW_KEYS = {"1": "active", "2": "deprecated", "3": "review", "4": "remove"}


def ask(prompt, valid):
    while True:
        k = input(prompt).strip().lower()
        if k in valid or k in ("s", "q"):
            return k


def main():
    me = D.git_user() or input("이름: ").strip()
    review = "--review" in sys.argv
    todo = D.review_items() if review else D.pending_candidates()
    print(f"{me} · {'review 다시 판단' if review else '추가 후보'} {len(todo)}개\n")
    last_owner = ""
    for i, c in enumerate(todo, 1):
        print("=" * 72)
        if review:
            key = c["endpoint_key"]
            print(f"[{i}/{len(todo)}] {c['layer']} · {key}   (출처: {c['source']})")
            print(f"  메모 : {c['note']}")
            k = ask("  판단 [1 active / 2 deprecated / 3 계속 review / 4 remove(없애야 함) / s / q] > ", REVIEW_KEYS)
        else:
            key = c["key"]
            print(f"[{i}/{len(todo)}] {c['layer']} · {key}   ({c['group']})")
            print(f"  판정 : {c['verdict']}   (찾은 출처: {c['found_by']})")
            print(f"  근거 : {c['evidence']}")
            print(f"  참고 : {c['suggested']}")
            k = ask("  선택 [1 추가(active) / 2 추가(deprecated) / 3 추가(review) / 4 추가 안 함 / s / q] > ", CAND_KEYS)
        if k == "q":
            break
        if k == "s":
            continue
        reason = input("  이유(한 줄, 선택) > ").strip()
        owner = ""
        if review or CAND_KEYS[k].startswith("add:"):
            default = c.get("owner") or last_owner
            owner = input(f"  담당자(owner) [{default or '없음'}] > ").strip() or default
            last_owner = owner
        if review:
            D.decide_review(c["layer"], key, REVIEW_KEYS[k], owner, reason, me)
            print(f"  → 저장: {REVIEW_KEYS[k]}")
        else:
            D.decide_candidate(c["layer"], key, CAND_KEYS[k], owner, reason, me)
            print(f"  → 저장: {CAND_KEYS[k]}")
    print("\n끝. 다음: python api-bom/inventory/merge_inventory.py 로 인벤토리에 반영")


if __name__ == "__main__":
    main()
