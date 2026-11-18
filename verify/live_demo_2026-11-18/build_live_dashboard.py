#!/usr/bin/env python3
"""실시간 시연 대시보드 JSON 생성 (Dashboards as Code) → grafana/dashboards/live_demo.json
   최근 15분 · 5초 새로고침. DVRA · 합성 트래픽이라는 표시를 제목에 단다 (팀 기반 e2e 와 섞이지 않게)."""
import json
from pathlib import Path

ACC = {"type": "elasticsearch", "uid": "live-access"}
ALR = {"type": "elasticsearch", "uid": "live-alerts"}
ML = {"type": "elasticsearch", "uid": "live-ml"}
RSP = {"type": "elasticsearch", "uid": "live-response"}
T = "timestamp"
LABELS = {"normal": "green", "probe": "orange", "bola": "red"}
_id = iter(range(1, 999))


def tgt(ds, q, metrics=None, buckets=None, alias="", ref="A"):
    return {"refId": ref, "datasource": ds, "query": q, "alias": alias, "timeField": T,
            "metrics": metrics or [{"id": "1", "type": "count"}],
            "bucketAggs": buckets if buckets is not None else [{"id": "2", "type": "date_histogram", "field": T,
                                                                "settings": {"interval": "10s", "min_doc_count": "0"}}]}


def terms(i, field, size=10, order_by="_count"):
    return {"id": i, "type": "terms", "field": field,
            "settings": {"size": str(size), "order": "desc", "orderBy": order_by, "min_doc_count": "1"}}


def raw():
    return [{"id": "1", "type": "raw_data", "settings": {"size": "200"}}]


def panel(t, title, x, y, w, h, targets, desc="", **kw):
    p = {"id": next(_id), "type": t, "title": title, "description": desc, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": targets}
    p.update(kw)
    return p


def stat(title, x, y, ds, q, color, metric=None, desc=""):
    return panel("stat", title, x, y, 4, 4, [tgt(ds, q, metrics=metric)], desc,
                 options={"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False}, "colorMode": "background",
                          "graphMode": "area", "textMode": "value"},
                 fieldConfig={"defaults": {"decimals": 0, "color": {"mode": "fixed", "fixedColor": color}}, "overrides": []})


def table(title, x, y, w, h, targets, desc="", rename=None, order=None, sort=None, colors=None):
    tr = [{"id": "organize", "options": {"renameByName": rename or {}, "indexByName": {c: i for i, c in enumerate(order or [])},
                                         "excludeByName": {k: True for k in ("_id", "_index", "_type", "highlight", "sort")}}}]
    if sort:
        tr.append({"id": "sortBy", "options": {"sort": [{"field": sort[0], "desc": sort[1]}]}})
    ov = [{"matcher": {"id": "byName", "options": f},
           "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}},
                          {"id": "mappings", "value": [{"type": "value", "options": {k: {"color": c, "index": i}
                                                                                     for i, (k, c) in enumerate(m.items())}}]}]}
          for f, m in (colors or {}).items()]
    return panel("table", title, x, y, w, h, targets, desc, transformations=tr,
                 fieldConfig={"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}}}, "overrides": ov})


P, y = [], 0
P += [
    stat("전체 요청", 0, y, ACC, "*", "text"),
    stat("차단된 요청 (403)", 4, y, ACC, "blocked:true", "red", desc="자동 차단 목록에 오른 IP 가 보낸 요청"),
    stat("Shadow 룰 경보 (실시간 Wazuh)", 8, y, ALR, "*", "orange"),
    stat("ML high 창", 12, y, ML, "level:high", "red"),
    stat("자동 차단 IP", 16, y, RSP, "*", "purple", metric=[{"id": "1", "type": "cardinality", "field": "client_ip"}]),
    stat("정상 사용자 차단 (오탐)", 20, y, RSP, "label:normal", "yellow", desc="0 이어야 한다"),
]
y += 4
P += [
    panel("timeseries", "요청 추이 — 정상 / 탐색 / BOLA / 차단(403)", 0, y, 14, 8,
          [tgt(ACC, "label:normal AND NOT blocked:true", alias="normal", ref="A"),
           tgt(ACC, "label:probe AND NOT blocked:true", alias="probe", ref="B"),
           tgt(ACC, "label:bola AND NOT blocked:true", alias="bola", ref="C"),
           tgt(ACC, "blocked:true", alias="차단(403)", ref="D")],
          fieldConfig={"defaults": {"custom": {"drawStyle": "bars", "stacking": {"mode": "normal"}, "fillOpacity": 80}},
                       "overrides": [{"matcher": {"id": "byName", "options": k},
                                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
                                     for k, c in {**LABELS, "차단(403)": "purple"}.items()]}),
    table("자동 차단 현황", 14, y, 10, 8, [tgt(RSP, "*", metrics=raw(), buckets=[])],
          "누가 · 왜 · 무엇으로 막혔나 (ML 또는 Shadow 룰)",
          rename={"timestamp": "차단 시각", "client_ip": "IP", "source": "탐지", "reason": "이유", "detail": "근거",
                  "label": "정답"},
          order=["timestamp", "client_ip", "source", "reason", "detail", "label"], sort=("차단 시각", True),
          colors={"label": {"bola": "red", "probe": "orange", "normal": "yellow"}}),
]
y += 8
P += [
    table("ML 창 (high · medium)", 0, y, 12, 8, [tgt(ML, "level:high OR level:medium", metrics=raw(), buckets=[])],
          rename={"timestamp": "창 시작", "client_ip": "IP", "level": "판정", "score": "점수", "n_req": "요청",
                  "seq_id_run": "연속 ID", "id_span_log": "id_span_log", "label": "정답"},
          order=["timestamp", "client_ip", "level", "score", "n_req", "seq_id_run", "id_span_log", "label"],
          sort=("점수", False), colors={"level": {"high": "red", "medium": "orange"}, "label": {"bola": "red", "probe": "orange", "normal": "green"}}),
    table("Shadow 룰 경보 (실시간 Wazuh)", 12, y, 12, 8, [tgt(ALR, "*", metrics=raw(), buckets=[])],
          rename={"timestamp": "시각", "rule.level": "레벨", "rule.description": "설명", "data.client_ip": "IP",
                  "data.path": "경로", "data.status": "상태", "label": "정답"},
          order=["timestamp", "rule.level", "rule.description", "data.client_ip", "data.path", "data.status", "label"],
          sort=("시각", True), colors={"label": {"bola": "red", "probe": "orange", "normal": "green"}}),
]
y += 8
P += [
    table("IP별 요청 수 Top 10", 0, y, 12, 7, [tgt(ACC, "*", buckets=[terms("2", "client_ip", 10)])],
          rename={"client_ip": "IP", "Count": "요청 수"}),
    table("IP별 서로 다른 경로 수 Top 10 (BOLA 단서)", 12, y, 12, 7,
          [tgt(ACC, "*", metrics=[{"id": "1", "type": "cardinality", "field": "path"}],
               buckets=[terms("2", "client_ip", 10, order_by="1")])],
          rename={"client_ip": "IP", "Unique Count": "서로 다른 경로 수"}),
]

dash = {"uid": "live-demo", "title": "실시간 시연 — DVRA · 합성 트래픽 (Shadow 룰 + ML → 자동 차단)",
        "tags": ["live", "dvra", "synthetic"], "timezone": "browser", "schemaVersion": 39, "refresh": "5s",
        "time": {"from": "now-15m", "to": "now"}, "panels": P}
out = Path(__file__).parent / "grafana" / "dashboards" / "live_demo.json"
out.write_text(json.dumps(dash, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"패널 {len(P)}개 → {out}")
