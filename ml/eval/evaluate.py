#!/usr/bin/env python3
"""고정된 모델로 ① 공격 변종 탐지율 ② 학습에 안 쓴 로그의 오탐률 을 잰다 (오프라인 재생).

  python evaluate.py --model ../ml/model --sessions sessions \
                     --holdout holdout/2026-11-05_w15_noip.csv holdout/2026-11-06_w15_noip.csv

- 탐지율: 각 공격 세션에서 '공격 IP 의 15분 창' 이 high 임계값 아래로 내려가면 탐지. IP 가 요청 5건 미만이면
  판단 불가(=미탐) — 이것도 그대로 결과. 변종별 '탐지/전체' 와 중간(medium 이상) 포함 탐지율.
- 오탐률: 학습에 쓰지 않은 날(11-05·11-06) 팀 웹 창 중, 스캐너·기존 규칙이 잡을 창(명세 밖 호출)을 뺀
  '조용한 정상' 창에서 ML 이 high/medium 을 내는 비율.
결과: eval/results.md · eval/eval_dashboard.html · eval/results.json
"""
import argparse
import csv
import json
import os
import sys

import joblib
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE) + "/ml")
from features import FEATURES, featurize, parse  # noqa: E402


class Scorer:
    def __init__(self, d):
        self.m = joblib.load(os.path.join(d, "model.joblib"))
        self.meta = json.load(open(os.path.join(d, "model_meta.json"), encoding="utf-8"))
        self.hi = self.meta["threshold_high"]
        self.md = self.meta["threshold_medium"]

    def score(self, ft):
        return float(self.m.decision_function(np.array([[ft[k] for k in FEATURES]]))[0])

    def sev(self, s):
        return "high" if s < self.hi else "medium" if s < self.md else "normal"


def rows_by_ip(lines, parse_tmp):
    open(parse_tmp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    reqs = parse(parse_tmp)
    by = {}
    for r in reqs:
        by.setdefault(r[0], []).append(r)
    return by


def eval_variants(sc, sdir):
    man = json.load(open(os.path.join(sdir, "manifest.json"), encoding="utf-8"))
    tmp = os.path.join(sdir, "_tmp.log")
    out = {}
    for v, info in man["variants"].items():
        sessions = [json.loads(l) for l in open(os.path.join(sdir, f"{v}.jsonl"), encoding="utf-8")]
        det_hi = det_md = scored = skipped = 0
        samples = []
        for s in sessions:
            by = rows_by_ip(s["lines"], tmp)
            atk = set(s["attacker_ips"])
            best = None  # 가장 이상한(낮은) 공격 IP 점수
            any_scored = False
            for ip, reqs in by.items():
                if ip not in atk:
                    continue
                if len(reqs) < 5:
                    continue
                any_scored = True
                sv = sc.score(featurize(reqs))
                best = sv if best is None else min(best, sv)
            if not any_scored:
                skipped += 1  # 모든 공격 IP 가 5건 미만 → 판단 불가(미탐)
                continue
            scored += 1
            if best < sc.hi:
                det_hi += 1
            elif best < sc.md:
                det_md += 1
            samples.append(round(best, 4))
        total = len(sessions)
        out[v] = {"desc": info["desc"], "is_attack": info["is_attack"], "total": total,
                  "scored": scored, "skipped_lt5": skipped, "detected_high": det_hi,
                  "detected_medium_plus": det_hi + det_md,
                  "miss": total - det_hi - det_md,  # 중간도 안 넘은 것 + 5건 미만
                  "rate_high": round(det_hi / total, 3), "rate_medium_plus": round((det_hi + det_md) / total, 3),
                  "sample_scores": sorted(samples)[:8]}
    if os.path.exists(tmp):
        os.remove(tmp)
    return out


def eval_fp(sc, csvs):
    fp = {}
    tmax = sc.meta.get("train_window_start_max")
    for path in csvs:
        rows = list(csv.DictReader(open(path, encoding="utf-8")))
        # 2026-11-10: 학습 기간 안의 창은 '학습에 안 쓴 데이터'가 아니다 → 빼고 몇 개 뺐는지 남긴다.
        #   (기존 holdout/2026-11-05·06 은 590행 전부가 학습 CSV 와 같았다)
        #   meta 에 학습 기간이 없는 옛 모델은 겹침을 확인할 수 없음 → leak_unknown (게이트는 실패 처리)
        leaked = [r for r in rows if tmax is not None and "window_start" in r and int(r["window_start"]) <= tmax]
        rows = [r for r in rows if r not in leaked]
        quiet =[r for r in rows if float(r["err_ratio"]) < 0.3 and float(r["n_req"]) < 1500 and float(r["offspec_ratio"]) == 0]
        hi = md = 0
        for r in quiet:
            s = sc.score({k: float(r[k]) for k in FEATURES})
            if s < sc.hi:
                hi += 1
            elif s < sc.md:
                md += 1
        fp[os.path.basename(path)] = {"total_windows": len(rows), "quiet_benign": len(quiet),
                                      "excluded_overlap_with_train": len(leaked), "leak_unknown": tmax is None,
                                      "flagged_high": hi, "flagged_medium_plus": hi + md,
                                      "fp_high": round(hi / len(quiet), 4) if quiet else None,
                                      "fp_medium_plus": round((hi + md) / len(quiet), 4) if quiet else None}
    return fp


DASH_CSS = """
.viz{color-scheme:light;--bg:#f6f6f4;--card:#fcfcfb;--line:#e4e3df;--ink:#0b0b0b;--mut:#52514e;--good:#008300;--warn:#b26b00;--bad:#c62f2f;--track:#e8e7e3}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .viz{color-scheme:dark;--bg:#121211;--card:#1a1a19;--line:#2f2f2d;--ink:#f0efec;--mut:#c3c2b7;--good:#3fb950;--warn:#e0a030;--bad:#f07070;--track:#262624}}
*{box-sizing:border-box}body{margin:0}.viz{background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,"Malgun Gothic",sans-serif;min-height:100vh}
main{max-width:900px;margin:0 auto;padding:22px 16px 40px}h1{font-size:20px;margin:0 0 2px}h2{font-size:15px;margin:24px 0 8px}.mut{color:var(--mut);font-size:12px}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;min-width:150px}
.tile b{display:block;font-size:24px}.bar{display:grid;grid-template-columns:200px 1fr 54px;gap:8px;align-items:center;margin:5px 0}
.bar .name{font-size:12.5px}.track{background:var(--track);border-radius:4px;height:16px;overflow:hidden}.fill{height:100%;border-radius:4px}
.lab{font-size:12px;text-align:right;font-variant-numeric:tabular-nums}
"""


def write_dashboard(res, out=HERE):
    v = res["variants"]
    atk = [(k, d) for k, d in v.items() if d["is_attack"]]
    def bar(name, desc, rate, caught):
        col = "var(--good)" if rate >= 0.8 else "var(--warn)" if rate >= 0.4 else "var(--bad)"
        return (f"<div class='bar'><div class='name' title='{desc}'>{name}</div>"
                f"<div class='track'><div class='fill' style='width:{rate * 100:.0f}%;background:{col}'></div></div>"
                f"<div class='lab'>{rate:.0%}</div></div>")
    b = v.get("B_normal", {})
    fp = res["false_positive"]
    fp_hi = [d["flagged_high"] for d in fp.values()]
    fp_q = [d["quiet_benign"] for d in fp.values()]
    tiles = [("회피 변종 7종", f"{sum(1 for _, d in atk if d['rate_high'] < 0.8)}/{len(atk)}", "high 80% 미만(놓침)"),
             ("대조군 오탐", f"{b.get('rate_high', 0):.0%}", "정상 사용자 high"),
             ("실로그 오탐(high)", f"{(sum(fp_hi) / sum(fp_q)) if sum(fp_q) else 0:.2%}", f"조용한 정상 {sum(fp_q)}창")]
    html = [f"<!doctype html><html lang=ko><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
            f"<title>ML 탐지 평가</title><style>{DASH_CSS}</style></head><body class=viz><main>",
            "<h1>ML 탐지 평가 — 고정 모델, 회피 변종 · 오탐률</h1>",
            f"<div class=mut>모델 고정 {res['model_trained_at']} · high&lt;{res['threshold_high']} · 학습 {res['n_train_windows']}창 · 변종은 회피 기법으로 설계(특징 겨냥 아님)</div>",
            "<div class=tiles>" + "".join(f"<div class=tile><span class=mut>{t}</span><b>{val}</b><span class=mut>{sub}</span></div>" for t, val, sub in tiles) + "</div>",
            "<h2>공격 변종별 탐지율 (high)</h2><div class=mut>초록 ≥80% · 주황 ≥40% · 빨강 &lt;40%. 세션 40회 반복</div>"]
    for k, d in atk:
        html.append(bar(k, d["desc"], d["rate_high"], True))
    html.append("<h2>오탐 — 학습에 안 쓴 날 팀 웹 로그</h2><div class=mut>스캐너·명세 밖 호출 창 제외한 '조용한 정상' 창에서 경보 비율</div>")
    for name, d in fp.items():
        html.append(bar(name.replace("_w15_noip.csv", ""), "조용한 정상 창 오탐(high)", d["fp_high"] or 0, False))
    html += [f"<p class=mut>V6(IP 분산)은 창당 5건 미만이라 판단 자체가 안 됨 — IP·시간창 단위 ML 의 구조적 한계. 상세: results.md</p>",
             "</main></body></html>"]
    open(os.path.join(out, "eval_dashboard.html"), "w", encoding="utf-8", newline="\n").write("\n".join(html))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.path.join(HERE, "..", "ml", "model"))
    ap.add_argument("--sessions", default=os.path.join(HERE, "sessions"))
    ap.add_argument("--holdout", nargs="*", default=[])
    ap.add_argument("--gate", action="store_true", help="배포 게이트 모드: 기준 통과하면 exit 0, 아니면 exit 1")
    ap.add_argument("--max-fp-high", type=float, default=0.02, help="조용한 정상 창 high 오탐률 상한")
    # 2026-11-10: help 의 '%' 는 '%%' 로 — Python 3.14+ argparse 가 즉시 ValueError (게이트가 항상 rc=1 이던 원인)
    ap.add_argument("--must-detect", default="", help="반드시 high 100%% 로 잡아야 할 변종(콤마)")
    ap.add_argument("--min-quiet", type=int, default=50,
                    help="게이트: 홀드아웃마다 조용한 정상 창이 이 수 이상이어야 오탐률을 믿는다 (0창이면 0%%로 통과하던 버그)")
    ap.add_argument("--out", default=HERE, help="results.json·results.md·대시보드 출력 폴더 (기존 결과를 덮지 않으려면 새 폴더)")
    a = ap.parse_args()
    sc = Scorer(a.model)
    variants = eval_variants(sc, a.sessions)
    fp = eval_fp(sc, a.holdout)
    res = {"model_trained_at": sc.meta["trained_at"], "threshold_high": sc.hi, "threshold_medium": sc.md,
           "n_train_windows": sc.meta["n_windows"], "variants": variants, "false_positive": fp}
    os.makedirs(a.out, exist_ok=True)
    json.dump(res, open(os.path.join(a.out, "results.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    if a.gate:
        reasons = []
        for name in [x for x in a.must_detect.split(",") if x]:
            r = variants.get(name, {}).get("rate_high", 0)
            if r < 1.0:
                reasons.append(f"{name} high탐지 {r:.0%}<100%")
        # 2026-11-10: 빈·부족·누수 홀드아웃은 '오탐 0%' 가 아니라 '잴 수 없음' → 실패
        if not fp:
            reasons.append("홀드아웃 없음 — 오탐률을 잴 수 없음")
        for name, d in fp.items():
            if d["leak_unknown"]:
                reasons.append(f"{name}: 모델에 학습 기간 기록 없음 — 학습 데이터와 겹치는지 확인 불가")
            if d["quiet_benign"] < a.min_quiet:
                reasons.append(f"{name}: 조용한 정상 창 {d['quiet_benign']}개 < {a.min_quiet} (학습 기간과 겹쳐 뺀 창 {d['excluded_overlap_with_train']}개)")
        worst_fp = max([d["fp_high"] or 0 for d in fp.values()], default=0)
        if worst_fp > a.max_fp_high:
            reasons.append(f"오탐률 {worst_fp:.1%}>{a.max_fp_high:.0%}")
        if reasons:
            print(f"[GATE] ❌ 실패 — {' · '.join(reasons)}")
            sys.exit(1)
        print(f"[GATE] ✅ 통과 — 필수변종 탐지 OK, 오탐 {worst_fp:.2%}≤{a.max_fp_high:.0%}")
        return

    L = ["# ML 탐지 평가 — 고정 모델, 독립 변종 · 오탐률 (2026-11-09)", "",
         f"- **고정 모델**: 학습 {sc.meta['trained_at']} · 학습 창 {sc.meta['n_windows']} · high<{sc.hi} · medium<{sc.md} (레포 `e2e_story/ml/model`)",
         "- 평가는 모델을 **바꾸지 않고** 오프라인 재생으로만. 변종은 특징이 아니라 회피 기법으로 설계 ([`variants.py`](variants.py))", "",
         "## 1. 공격 변종 탐지율 (변종별 세션 반복)", "",
         "| 변종 | 설명 | 세션 | high 탐지 | medium+ 탐지 | 5건미만(미탐) | high율 | medium+율 |",
         "|---|---|---|---|---|---|---|---|"]
    for v, d in variants.items():
        if not d["is_attack"]:
            continue
        L.append(f"| {v} | {d['desc']} | {d['total']} | {d['detected_high']} | {d['detected_medium_plus']} | {d['skipped_lt5']} | **{d['rate_high']:.0%}** | {d['rate_medium_plus']:.0%} |")
    b = variants.get("B_normal", {})
    L += ["",
          f"**대조군 B_normal (정상 사용자)**: {b.get('total')}세션 중 high {b.get('detected_high')} · medium+ {b.get('detected_medium_plus')} "
          f"→ 오탐(high) {b.get('rate_high', 0):.0%} (0 에 가까워야 정상)", "",
          "## 2. 오탐률 — 학습에 안 쓴 날의 팀 웹 로그 (조용한 정상 창만)", "",
          "> 스캐너 창(오류 30%↑·1500건↑)과 기존 규칙이 잡을 창(명세 밖 /api 호출)은 ML 의 몫이 아니라 제외. 나머지 '조용한 정상' 창에서 ML 이 경보를 내면 오탐.", "",
          "| 로그(날짜) | 전체 창 | 조용한 정상 창 | high 오탐 | medium+ 오탐 | high 오탐률 | medium+ 오탐률 |",
          "|---|---|---|---|---|---|---|"]
    for name, d in fp.items():
        L.append(f"| {name} | {d['total_windows']} | {d['quiet_benign']} | {d['flagged_high']} | {d['flagged_medium_plus']} | {d['fp_high']:.1%} | {d['fp_medium_plus']:.1%} |"
                 if d["fp_high"] is not None else f"| {name} | {d['total_windows']} | 0 | - | - | - | - |")
    L += ["", "## 3. 읽는 법 · 한계", "",
          "- 이 평가가 **줄이는 한계**: '답을 알고 낸 시험' → 모델을 고정하고, 조정 때 안 본 회피 변종으로 재고, 오탐을 학습에 안 쓴 날 로그로 잰다.",
          "- **여전히 남는 것**: 변종을 만든 사람(나)이 특징을 안다 → 완전 독립은 아님. 사람이 직접 변종을 추가하거나 외부 도구(ffuf·nuclei 지연 모드)로 보완 필요.",
          "- V6(IP 분산)·V5(매우 느림)에서 미탐이 많으면, 그것이 IP·시간창 단위 ML 의 구조적 한계 — 계정·토큰 단위 특징이 다음 단계.",
          "- '로그가 깨끗함' 한계는 §2 가 직접 해소(실제 팀 로그 분포로 오탐 측정). 단 재생이라 Wazuh·EDA 부하는 아직 측정 안 함.", ""]
    open(os.path.join(a.out, "results.md"), "w", encoding="utf-8", newline="\n").write("\n".join(L))
    write_dashboard(res, a.out)
    print("\n".join(L[4:6]))
    for v, d in variants.items():
        print(f"  {v:18s} high {d['rate_high']:.0%}  medium+ {d['rate_medium_plus']:.0%}  (미탐<5건 {d['skipped_lt5']})")
    for name, d in fp.items():
        print(f"  FP {name}: 조용한 정상 {d['quiet_benign']}창 중 high {d['flagged_high']} ({d['fp_high']})")


if __name__ == "__main__":
    main()
