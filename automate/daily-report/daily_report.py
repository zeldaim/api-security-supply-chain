#!/usr/bin/env python3
"""[자동 보안 일일 보고서] daily.sh 가 끝날 때 레포 안 결과로 보고서를 만든다 (양식: reports/보고서_양식_가이드.md).

    python3 tools/daily_report.py [실행 로그 파일]

출력: reports/auto/<날짜>_<시각>_보안일일보고서.md · reports/auto/<날짜>_<시각>.state.json (다음 보고의 '신규·해소' 비교용)
  실행마다 새 파일 — 덮어쓰지 않고 쌓는다. 사람이 쓴 reports/<날짜>_보안일일보고서.md 는 건드리지 않는다.
입력 (전부 레포 안): policy/sbom_judgement.csv · policy/judgement.csv · policy/exceptions.csv · graph/sample_dt/risk.csv
  · dt_history/sesac-shop-image/*/metrics.json · sbom/results/*/meta.txt · inventory/runs/<로그> · inventory/decisions_log.csv
표준 라이브러리만 사용.
"""
import csv
import glob
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KST = timezone(timedelta(hours=9))
P = lambda *a: os.path.join(REPO, *a)


def rows(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def rel(p):
    return os.path.relpath(p, REPO).replace("\\", "/")


def latest_snapshots():
    out = []
    for d in glob.glob(P("api-bom", "dt_history", "sesac-shop-image", "*")):
        mj = os.path.join(d, "metrics.json")
        if os.path.exists(mj) and os.path.exists(os.path.join(d, "findings.csv")):
            m = json.load(open(mj, encoding="utf-8"))
            if m.get("active") is not False:
                out.append((m.get("lastBomImport") or 0, d, m))
    out.sort(key=lambda x: x[0])
    return out


def main():
    now = datetime.now(KST)
    today = now.date().isoformat()
    stamp = now.strftime("%Y-%m-%d_%H%M")
    runlog = sys.argv[1] if len(sys.argv) > 1 else (sorted(glob.glob(P("api-bom", "inventory", "runs", "20*.txt"))) or [None])[-1]
    log = open(runlog, encoding="utf-8", errors="replace").read() if runlog and os.path.exists(runlog) else ""

    sb = rows(P("api-bom", "policy", "sbom_judgement.csv"))
    api = rows(P("api-bom", "policy", "judgement.csv"))
    viol = [r for r in sb + api if r["result"].startswith("위반")]
    keys = sorted(f"{r['asset']}|{r['violations']}" for r in viol)

    # 어제(이전) 상태와 비교 → 신규·해소
    os.makedirs(P("reports", "auto"), exist_ok=True)
    prev_states = sorted(p for p in glob.glob(P("reports", "auto", "*.state.json")) if not os.path.basename(p).startswith(stamp))
    prev = json.load(open(prev_states[-1], encoding="utf-8")) if prev_states else None
    prev_keys = set(prev["violations"]) if prev else set()
    new_keys = [k for k in keys if k not in prev_keys] if prev else []
    gone_keys = sorted(prev_keys - set(keys)) if prev else []

    snaps = latest_snapshots()
    cur_m = snaps[-1][2] if snaps else {}
    prev_m = snaps[-2][2] if len(snaps) > 1 else {}
    cm, pm = cur_m.get("metrics", {}), prev_m.get("metrics", {})

    risk = rows(P("api-bom", "graph", "sample_dt", "risk.csv"))
    risk.sort(key=lambda r: -int(r.get("risk") or 0))
    exc = rows(P("api-bom", "policy", "exceptions.csv"))
    exc_act = [x for x in exc if x.get("expires", "") >= today]
    soon = [x for x in exc_act if x["expires"] <= (now.date() + timedelta(days=7)).isoformat()]
    dec_today = [x for x in rows(P("api-bom", "inventory", "decisions_log.csv")) if str(x.get("at", "")).startswith(today)]
    exc_today = [x for x in exc if str(x.get("approved_at", "")).startswith(today)]

    metas = sorted(glob.glob(P("sbom", "results", "20*", "meta.txt")))
    meta = {}
    if metas:
        for line in open(metas[-1], encoding="utf-8"):
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()

    def logline(pat, ok, bad="⛔"):
        m = re.search(pat, log)
        return (ok, m.group(0).strip()) if m else (bad, "로그에 없음")

    high = [r for r in viol if "높음" in r["result"]]
    mid = [r for r in viol if "중간" in r["result"]]
    eol = [r for r in sb if r["violations"] == "S3" and r["result"].startswith("위반")]
    top = risk[0] if risk else None
    d = lambda a, b: "" if b in (None, "") or a in (None, "") else f" ({'+' if a - b >= 0 else ''}{a - b})"

    L = [f"# 보안 일일 보고서 (자동) — {today}", "",
         f"**프로젝트**: Shadow API 모니터링 · **생성**: `tools/daily_report.py` (VM daily 끝에서 자동) · **생성 시각**: {now:%Y-%m-%d %H:%M} KST",
         "**대상 시스템**: 팀 쇼핑몰 API (192.168.0.141:8000) · 이미지 `sesac-shop` · Dependency-Track",
         "> 사람이 쓰는 보고서는 `reports/<날짜>_보안일일보고서.md`. 자동 보고서는 실행마다 `reports/auto/` 에 새 파일로 쌓인다." + (f" 직전 보고: `{os.path.basename(prev_states[-1]).replace('.state.json', '_보안일일보고서.md')}`" if prev_states else ""), "", "---", "",
         "## 요약", "", "| 구분 | 내용 |", "|---|---|",
         f"| 기준 위반 | 높음 {len(high)} · 중간 {len(mid)} (SBOM {sum(1 for r in viol if r['layer']=='sbom')} · API 자산 {sum(1 for r in viol if r['layer']!='sbom')}) |",
         f"| 신규 / 해소 (직전 보고 대비) | " + (f"신규 {len(new_keys)} · 해소 {len(gone_keys)}" if prev else "첫 자동 보고 — 비교 없음") + " |",
         f"| 부품 취약점 (DT) | {cm.get('vulnerabilities')}{d(cm.get('vulnerabilities'), pm.get('vulnerabilities'))}건 · Critical {cm.get('critical')}{d(cm.get('critical'), pm.get('critical'))} · High {cm.get('high')}{d(cm.get('high'), pm.get('high'))} · 위험 부품 {cm.get('vulnerableComponents')}/{cm.get('components')} |",
         f"| 가장 위험한 API | " + (f"`{top['endpoint_key']}` 점수 {top['risk']} — {top['why']}" if top else "-") + " |",
         f"| 근본 원인 | " + (" · ".join(r["evidence"].split(" · 근거")[0].replace("S3: ", "") for r in eol) or "-") + " |",
         f"| 사람 결정 필요 | 예외 없는 위반 높음 {len(high)}건 → 고치거나 8091 예외 · 만료 7일 이내 예외 {len(soon)}건 |", "", "---", ""]

    L += ["## 보안 발견사항 (자동 판정, 높음)", "", "| ID | 심각도 | 기준 | 대상 | 근거 | 신규 |", "|---|---|---|---|---|---|"]
    for i, r in enumerate(high, 1):
        k = f"{r['asset']}|{r['violations']}"
        L.append(f"| AUTO-{i:03d} | 높음 | {r['violations']} | `{r['asset']}` | {r['evidence'].replace('|', '/')[:200]} | {'🆕' if k in new_keys else ''} |")
    if gone_keys:
        L += ["", "**해소된 위반 (직전 보고 대비)**: " + " · ".join(f"`{k}`" for k in gone_keys)]
    L += ["", f"중간 {len(mid)}건은 `api-bom/policy/sbom_report.md` · `api-bom/policy/report.md` 참고", "",
          "### 위험 상위 API (관계 그래프, DT 최신 기준)", "",
          "> 점수 = 자산(노출·분류) + 도달(실제 도달하는 부품 CVE) + 실증(모의해킹 VEX). 실증 0 이면 아직 '확인된' 취약점 없음 — 자산·도달만으로 높은 것.", "",
          "| 점수 | 자산/도달/실증 | 엔드포인트 | 이유 | VEX |", "|---|---|---|---|---|"]
    for r in risk[:5]:
        split = f"{r.get('asset','-')}/{r.get('reach','-')}/{r.get('proven','-')}" if r.get("asset") is not None else "-"
        L.append(f"| {r['risk']} | {split} | `{r['endpoint_key']}` | {r['why']} | {r.get('vex','')} |")

    infra = [("Actions SBOM 생성", ("✅" if meta.get("sbom_image", "").startswith("generated") else "⚠️"),
              f"{rel(os.path.dirname(metas[-1])) if metas else '-'} · team {meta.get('team_commit','?')} · sbom_image: {meta.get('sbom_image','?')}"),
             ("WEB 로그 수집",) + logline(r"\[1\][^\n]*", "✅"),
             ("블랙박스 스캔",) + logline(r"\[3\][^\n]*", "✅"),
             ("DT API-BOM",) + logline(r"\[6\] \[DT\] API-BOM[^\n]*", "✅"),
             ("DT SBOM",) + logline(r"\[6\] \[DT\] SBOM[^\n]*", "✅"),
             ("DT 분석 대기",) + logline(r"\[6\] \[DT\] 분석[^\n]*", "✅", "➖"),
             ("SBOM 판정",) + logline(r"\[6b\][^\n]*", "✅"),
             ("관계 그래프",) + logline(r"\[7\][^\n]*", "✅")]
    L += ["", "---", "", "## 모니터링 인프라 현황 (이번 실행)", "", "| 단계 | 상태 | 로그 |", "|---|---|---|"]
    for name, st, txt in infra:
        if "실패" in txt:
            st = "⛔"
        elif "오프라인" in txt:   # OFFLINE=1 (실습 서버 꺼진 날) — 직전 결과 사용 (2026-11-07)
            st = "➖"
        L.append(f"| {name} | {st} | {txt.replace('|', '/')[:150]} |")
    L.append(f"| DT 스냅샷 | ✅ | `{rel(snaps[-1][1]) if snaps else '-'}` |")

    L += ["", "---", "", "## 사람의 결정 (오늘)", ""]
    L += [f"- 예외 승인: `{x['asset']}` {x['criterion']} ~{x['expires']} ({x['approved_by']}) — {x['reason']}" for x in exc_today] or ["- 예외 승인 없음"]
    L += [f"- 자산 판정: {x.get('layer')} `{x.get('key')}` {x.get('before')} → {x.get('after')} ({x.get('by')})" for x in dec_today] or ["- 자산 판정 없음"]
    if soon:
        L += ["", "**만료 7일 이내 예외 (재검토)**"] + [f"- `{x['asset']}` {x['criterion']} ~{x['expires']}" for x in soon]

    pend = re.search(r"선택 대기 후보 (\d+)개", log)
    L += ["", "---", "", "## 미확인·보류", "",
          f"- 승인 대기 자산 후보: {pend.group(1) if pend else '?'}개 (8090)",
          f"- 기준 위반 높음 중 예외·조치 결정 안 된 것: {len(high)}건 (8091)",
          "- KEV·EPSS 미반영 (문서 13 §3) · PHP 런타임 CVE 는 NVD 키 필요 (07 §4)", "",
          "## 다음 단계", "", "1. (즉시) 🆕 표시 위반 확인 → 고치거나 8091 예외",
          "2. (이번 주) 근본 원인(지원 종료 베이스 이미지) 팀 공유",
          "3. 해당 없는 CVE 는 DT 에서 분석 상태 기록 (다음 판정에서 빠짐)", "",
          "## 참고", "", "| 자료 | 경로 |", "|---|---|",
          f"| 이번 실행 로그 | `{rel(runlog) if runlog else '-'}` |",
          "| SBOM 판정 | `api-bom/policy/sbom_report.md` |", "| API 자산 판정 | `api-bom/policy/report.md` |",
          "| 위험 점수 전체 | `api-bom/graph/sample_dt/risk.csv` |", "| DT 스냅샷 | `api-bom/dt_history/` |",
          "| 보는 법 | `docs/매일_치트시트.md` |"]
    out = P("reports", "auto", f"{stamp}_보안일일보고서.md")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    with open(P("reports", "auto", f"{stamp}.state.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"date": today, "stamp": stamp, "generated_at": now.isoformat(), "violations": keys,
                   "dt": {k: cm.get(k) for k in ("vulnerabilities", "critical", "high", "vulnerableComponents")}}, f, ensure_ascii=False, indent=1)
    print(f"자동 보고서: {rel(out)} (위반 높음 {len(high)}, 신규 {len(new_keys)}, 해소 {len(gone_keys)})")


if __name__ == "__main__":
    main()
