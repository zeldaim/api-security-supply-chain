#!/usr/bin/env python3
"""정상 행위 학습 — IsolationForest (비지도). 팀 웹(읽기 전용 공유)의 실제 접근 로그에서 뽑은 특징 CSV 로 학습한다.

  python3 train.py <features.csv> [--out model/] [--contamination 0.02]

결과
  model/model.joblib     학습된 모델
  model/model_meta.json  특징 순서 · 임계값(high/medium) · 특징별 중앙값·척도(설명용) · 학습 데이터 요약 (IP 없음)
"""
import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURES  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "model"))
    ap.add_argument("--contamination", type=float, default=0.01, help="학습 데이터 안의 이상 비율 추정 (팀 웹 로그에는 모의해킹·스캔도 섞여 있다)")
    ap.add_argument("--source", default="", help="학습 데이터 출처 설명 (meta 에 기록)")
    ap.add_argument("--max-err", type=float, default=0.3, help="오류 비율이 이 이상인 창은 스캐너로 보고 학습에서 뺀다")
    ap.add_argument("--max-req", type=int, default=1500, help="요청 수가 이 이상인 창은 스캐너로 보고 학습에서 뺀다")
    ap.add_argument("--until", type=int, default=None,
                    help="window_start(epoch 초) 가 이 값 미만인 창만 학습 — 시간 분할 평가용 (2026-11-10). 이후 창은 평가에 쓴다")
    a = ap.parse_args()

    with open(a.csv, encoding="utf-8") as f:
        allrows = list(csv.DictReader(f))
    if a.until is not None:
        allrows = [r for r in allrows if int(r["window_start"]) < a.until]
    # 팀 웹 로그에는 모의해킹·스캐너(대량·404 위주)가 섞여 있다 → '정상 행위'만 학습 (novelty detection).
    # 스캐너는 이미 서명·빈도 규칙이 잡는다 — ML 은 그 규칙들을 통과하는 '조용한' 행위를 보는 역할
    # 기존 규칙이 이미 잡는 창도 뺀다: 명세 밖 /api 호출이 하나라도 있으면 Shadow API 규칙(1005xx)에 걸린다
    #   (팀 웹 로그의 BOLA 모의해킹 = /api/v1/users/{n} 열거가 여기 해당 — 2026-11-09 확인)
    scan = [r for r in allrows if not (float(r["err_ratio"]) < a.max_err and float(r["n_req"]) < a.max_req)]
    ruled = [r for r in allrows if r not in scan and float(r["offspec_ratio"]) > 0]
    rows = [r for r in allrows if r not in scan and r not in ruled]
    print(f"[train] 전체 창 {len(allrows)} → 스캐너 {len(scan)} · 규칙이 이미 잡는 창 {len(ruled)} 제외 → 학습 {len(rows)}")
    X = np.array([[float(r[k]) for k in FEATURES] for r in rows])
    if len(X) < 50:
        sys.exit(f"학습 창이 {len(X)}개뿐 — 50개 이상 필요")

    m = IsolationForest(n_estimators=300, contamination=a.contamination, random_state=42).fit(X)
    s = m.decision_function(X)            # 클수록 정상, 0 미만 = 모델이 이상으로 본 것
    thr_high = float(np.percentile(s, 0.5))
    thr_med = float(np.percentile(s, 2.0))
    med = np.median(X, axis=0)
    q1, q3 = np.percentile(X, 25, axis=0), np.percentile(X, 75, axis=0)
    scale = np.maximum((q3 - q1) / 1.349, np.std(X, axis=0) * 0.2)
    scale = np.where(scale <= 0, 1.0, scale)

    os.makedirs(a.out, exist_ok=True)
    joblib.dump(m, os.path.join(a.out, "model.joblib"))
    meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "sklearn IsolationForest(n_estimators=300, random_state=42)",
        "contamination": a.contamination,
        "source": a.source,
        "n_windows": int(len(X)),
        "n_windows_total": len(allrows),
        # 평가가 학습 기간과 겹치지 않는지 evaluate.py 가 확인한다 (2026-11-10: 기존 홀드아웃이 학습 데이터와 100% 겹쳤음)
        "train_window_start_min": min(int(r["window_start"]) for r in rows),
        "train_window_start_max": max(int(r["window_start"]) for r in rows),
        "filter": f"err_ratio < {a.max_err} and n_req < {a.max_req} (스캐너 제외) and offspec_ratio == 0 (Shadow API 규칙에 걸리는 창 제외)",
        "excluded": {"scanner": len(scan), "rule_hit": len(ruled)},
        "features": FEATURES,
        "threshold_high": round(thr_high, 5),
        "threshold_medium": round(thr_med, 5),
        "median": [round(float(v), 4) for v in med],
        "scale": [round(float(v), 4) for v in scale],
        "train_p99": [round(float(v), 4) for v in np.percentile(X, 99, axis=0)],
        "score_percentiles": {p: round(float(np.percentile(s, p)), 5) for p in (0.5, 1, 2, 5, 25, 50)},
    }
    with open(os.path.join(a.out, "model_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"[train] 창 {len(X)}개 학습 · 임계값 high<{thr_high:.4f} medium<{thr_med:.4f} → {a.out}")
    for k, v, p in zip(FEATURES, med, meta["train_p99"]):
        print(f"  {k:16s} 중앙값 {v:9.3f}  p99 {p:9.3f}")


if __name__ == "__main__":
    main()
