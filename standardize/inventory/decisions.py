"""사람 판정(출처 6) 저장 로직 — approve.py(터미널)와 approval_server.py(대시보드)가 같이 쓴다.

파일:
  candidates.csv     추가 후보 + 선택 기록 (choice·chosen_by·chosen_at·reason)
  baseline_v2.csv    기준선 v2 = 사람이 승인한 것
  decisions_log.csv  모든 판정 이력 (지우지 않고 쌓기만)
"""
import csv
import os
import subprocess
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CAND = os.path.join(HERE, "candidates.csv")
BASE2 = os.path.join(HERE, "baseline_v2.csv")
LOG = os.path.join(HERE, "decisions_log.csv")
KST = timezone(timedelta(hours=9))
LOG_FIELDS = ["at", "by", "mode", "layer", "key", "before", "after", "owner", "reason"]

# 후보 선택: 기준선에 넣을지
CAND_CHOICES = {"add:active": "추가(active)", "add:deprecated": "추가(deprecated)",
                "add:review": "추가(review)", "reject": "추가 안 함"}
# review 다시 판단: 기준선 안에서 판정 바꾸기
REVIEW_CHOICES = {"active": "active", "deprecated": "deprecated", "review": "계속 review", "remove": "remove(없애야 함)"}


def load(path):
    if not os.path.exists(path):
        return [], []
    with open(path, encoding="utf-8-sig", newline="") as f:
        r = csv.DictReader(f)
        return r.fieldnames, list(r)


def save(path, fields, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)  # 중간에 끊겨도 파일이 반쯤 쓰이지 않게


def now():
    return datetime.now(KST).strftime("%Y-%m-%d %H:%M KST")


def git_user():
    try:
        return subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, cwd=HERE).stdout.strip()
    except OSError:
        return ""


def log_decision(**kw):
    new = not os.path.exists(LOG)
    with open(LOG, "a", encoding="utf-8-sig" if new else "utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LOG_FIELDS, lineterminator="\n")
        if new:
            w.writeheader()
        w.writerow(kw)


def kind_of(layer, key):
    if layer == "service":
        return "service"
    path = key.split(" ", 1)[1]
    if path.startswith("/api/"):
        return "api"
    return "page" if path == "/" or path.endswith(".php") else "file"


def pending_candidates():
    return [c for c in load(CAND)[1] if not c["choice"]]


def review_items():
    return [r for r in load(BASE2)[1] if r["decision"] == "review"]


def decide_candidate(layer, key, choice, owner, reason, by):
    if choice not in CAND_CHOICES:
        raise ValueError(f"잘못된 선택: {choice}")
    cf, cands = load(CAND)
    c = next((c for c in cands if c["layer"] == layer and c["key"] == key), None)
    if c is None:
        raise ValueError(f"후보 없음: {layer} {key}")
    if c["choice"]:
        raise ValueError(f"이미 선택됨: {key} → {c['choice']} ({c['chosen_by']} {c['chosen_at']})")
    t = now()
    c.update({"choice": choice, "chosen_by": by, "chosen_at": t, "reason": reason})
    if choice.startswith("add:"):
        bf, base = load(BASE2)
        base.append({"layer": layer, "endpoint_key": key, "kind": kind_of(layer, key), "group": c["group"],
                     "decision": choice.split(":")[1], "owner": owner, "source": f"추가 ({c['found_by']})",
                     "added_by": by, "added_at": t, "note": reason})
        save(BASE2, bf, base)
    save(CAND, cf, cands)
    log_decision(at=t, by=by, mode="candidate", layer=layer, key=key, before="(후보)", after=choice,
                 owner=owner if choice.startswith("add:") else "", reason=reason)
    return t


def decide_review(layer, key, decision, owner, reason, by):
    if decision not in REVIEW_CHOICES:
        raise ValueError(f"잘못된 판정: {decision}")
    bf, base = load(BASE2)
    r = next((r for r in base if r["layer"] == layer and r["endpoint_key"] == key), None)
    if r is None:
        raise ValueError(f"기준선에 없음: {layer} {key}")
    if r["decision"] != "review":
        raise ValueError(f"review 상태가 아님: {key} → {r['decision']}")
    t = now()
    owner = owner or r["owner"]
    log_decision(at=t, by=by, mode="review", layer=layer, key=key, before=r["decision"], after=decision,
                 owner=owner, reason=reason)
    r.update({"decision": decision, "owner": owner,
              "note": (r["note"] + " | " if r["note"] else "") + f"{t} {by}: {decision} {reason}".strip()})
    save(BASE2, bf, base)
    return t
