#!/usr/bin/env python3
"""DVRA 탐지 대시보드 JSON 생성기 (Dashboards as Code).

  python build_dashboard.py   → grafana/dashboards/dvra_detection.json  (Grafana 가 프로비저닝으로 읽는다)

설계 출처: 팀 대시보드(team_src/detection/shadow_api/grafana, "Shadow API 탐지") 의 단계 6개 · 위험 IP 순위 ·
명세 밖 엔드포인트 순위 · 최근 경보 구성을 따르고, 코드는 새로 썼다. 팀 것과 다른 점:
  - Grafana 기본 Elasticsearch 데이터 소스 (팀은 OpenSearch 플러그인)
  - ML(BOLA) 패널과 "정답지 대조"(룰 · ML 이 각각 무엇을 잡았나) 패널 추가
  - 경보 · 요청 · ML 을 서로 다른 인덱스(데이터 소스 3개)에서 읽는다
"""
import json
from pathlib import Path

ACC = {"type": "elasticsearch", "uid": "dvra-access"}
ALR = {"type": "elasticsearch", "uid": "dvra-alerts"}
ML = {"type": "elasticsearch", "uid": "dvra-ml"}
T = "timestamp"

STAGES = [  # (표시, 그룹, 색) — 팀 대시보드와 같은 단계 이름
    ("L1 정찰", "shadow_api_recon", "blue"),
    ("L2 발견", "shadow_api_discovery", "yellow"),
    ("L3 악용", "shadow_api_exploit", "orange"),
    ("L3-E 서버 오류", "shadow_api_error", "purple"),
    ("F1 자동화 정찰", "shadow_api_recon_burst", "light-blue"),
    ("F2 대량 유출", "shadow_api_mass_exfil", "red"),
]
LABEL_COLORS = {"normal": "green", "probe": "orange", "bola": "red"}

_id = iter(range(1, 1000))


def tgt(ds, query, metrics=None, buckets=None, alias="", ref="A"):
    return {"refId": ref, "datasource": ds, "query": query, "alias": alias, "timeField": T,
            "metrics": metrics or [{"id": "1", "type": "count"}],
            "bucketAggs": buckets if buckets is not None else [date_hist()]}


def date_hist(i="2", interval="1m"):
    return {"id": i, "type": "date_histogram", "field": T, "settings": {"interval": interval, "min_doc_count": "0"}}


def terms(i, field, size=10, order_by="_count"):
    return {"id": i, "type": "terms", "field": field,
            "settings": {"size": str(size), "order": "desc", "orderBy": order_by, "min_doc_count": "1"}}


def raw(size=500):
    return [{"id": "1", "type": "raw_data", "settings": {"size": str(size)}}]


def panel(ptype, title, x, y, w, h, targets, desc="", **extra):
    p = {"id": next(_id), "type": ptype, "title": title, "description": desc,
         "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": targets}
    p.update(extra)
    return p


def stat(title, x, y, ds, query, color, desc="", metric=None):
    return panel("stat", title, x, y, 4, 4, [tgt(ds, query, metrics=metric)], desc,
                 options={"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                          "colorMode": "background", "graphMode": "area", "textMode": "value"},
                 fieldConfig={"defaults": {"unit": "short", "decimals": 0,
                                           "color": {"mode": "fixed", "fixedColor": color}}, "overrides": []})


def table(title, x, y, w, h, targets, desc="", rename=None, order=None, sort=None, overrides=None):
    tr = [{"id": "organize", "options": {"renameByName": rename or {},
                                         "indexByName": {c: i for i, c in enumerate(order or [])},
                                         "excludeByName": {"_id": True, "_index": True, "_type": True, "highlight": True,
                                                           "sort": True, "data.url": True, "data.user_agent": True}}}]
    if sort:
        tr.append({"id": "sortBy", "options": {"sort": [{"field": sort[0], "desc": sort[1]}]}})
    return panel("table", title, x, y, w, h, targets, desc, transformations=tr,
                 fieldConfig={"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
                              "overrides": overrides or []}, options={"showHeader": True})


def color_by_value(field, mapping):
    return {"matcher": {"id": "byName", "options": field},
            "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}},
                           {"id": "mappings", "value": [{"type": "value", "options": {
                               k: {"color": c, "index": i} for i, (k, c) in enumerate(mapping.items())}}]}]}


panels = []
y = 0
# ── 1줄: 한눈에 ────────────────────────────────────────────────────────────────
panels += [
    stat("전체 요청", 0, y, ACC, "*", "text", "앞단 nginx 접근 로그 전부"),
    stat("명세 밖 경보 (Shadow 룰)", 4, y, ALR, "*", "orange", "실제 wazuh-logtest 판정에서 레벨 > 0 인 Shadow API 룰"),
    stat("명세 밖 호출 성공 (L3)", 8, y, ALR, "rule.groups:shadow_api_exploit", "red",
         "명세에 없는 경로가 2xx 로 응답 — 숨은 API 가 실제로 열려 있다"),
    stat("ML high 창 (BOLA 의심)", 12, y, ML, "level:high", "red", "IP × 5분 창 중 모델 점수가 high 기준 아래"),
    stat("룰 경보 IP 수", 16, y, ALR, "*", "purple", metric=[{"id": "1", "type": "cardinality", "field": "data.client_ip"}]),
    stat("ML high IP 수", 20, y, ML, "level:high", "purple", metric=[{"id": "1", "type": "cardinality", "field": "client_ip"}]),
]
y += 4
# ── 2줄: 추이 ─────────────────────────────────────────────────────────────────
panels += [
    panel("timeseries", "요청 추이 (정답 라벨별)", 0, y, 12, 8,
          [tgt(ACC, f"label:{k}", alias=k, ref=chr(65 + i)) for i, k in enumerate(LABEL_COLORS)],
          "라벨은 시험 장치의 출발지 IP 로 붙인 정답이다 (모델 입력 아님)",
          fieldConfig={"defaults": {"custom": {"drawStyle": "bars", "stacking": {"mode": "normal"}, "fillOpacity": 80}},
                       "overrides": [{"matcher": {"id": "byName", "options": k},
                                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
                                     for k, c in LABEL_COLORS.items()]}),
    panel("timeseries", "Shadow 룰 단계별 경보 추이", 12, y, 12, 8,
          [tgt(ALR, f"rule.groups:{g}", alias=n, ref=chr(65 + i)) for i, (n, g, _c) in enumerate(STAGES)],
          "팀 대시보드와 같은 단계 구분 (그룹 이름으로 거른다)",
          fieldConfig={"defaults": {"custom": {"drawStyle": "bars", "stacking": {"mode": "normal"}, "fillOpacity": 80}},
                       "overrides": [{"matcher": {"id": "byName", "options": n},
                                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
                                     for n, _g, c in STAGES]}),
]
y += 8
# ── 3줄: 정답지 대조 — 이 대시보드에만 있는 패널 ─────────────────────────────────
panels += [
    panel("bargauge", "정답지 대조 — Shadow 룰이 잡은 요청 (라벨별)", 0, y, 8, 7,
          [tgt(ALR, "*", buckets=[terms("2", "label")])],
          "탐색 공격은 룰이 잡는다. BOLA 는 명세 안의 경로라 룰이 잡지 않는 게 정상이다.",
          options={"orientation": "horizontal", "displayMode": "basic", "showUnfilled": True,
                   "reduceOptions": {"calcs": ["sum"], "fields": "", "values": True}},
          fieldConfig={"defaults": {"min": 0, "color": {"mode": "fixed", "fixedColor": "orange"}}, "overrides": []}),
    panel("bargauge", "정답지 대조 — ML high 창 (라벨별)", 8, y, 8, 7,
          [tgt(ML, "level:high", buckets=[terms("2", "label")])],
          "BOLA 는 ML 이 잡는다. normal 막대가 오탐이다.",
          options={"orientation": "horizontal", "displayMode": "basic", "showUnfilled": True,
                   "reduceOptions": {"calcs": ["sum"], "fields": "", "values": True}},
          fieldConfig={"defaults": {"min": 0, "color": {"mode": "fixed", "fixedColor": "red"}}, "overrides": []}),
    table("위험 IP 순위 (Shadow 룰)", 16, y, 8, 7,
          [tgt(ALR, "*", metrics=[{"id": "1", "type": "count"}, {"id": "3", "type": "max", "field": "rule.level"}],
               buckets=[terms("2", "data.client_ip", 10, order_by="3")])],
          rename={"data.client_ip": "IP", "Count": "경보 수", "Max": "최고 레벨"}),
]
y += 7
# ── 4줄: 무엇이 잡혔나 ─────────────────────────────────────────────────────────
panels += [
    table("명세 밖 엔드포인트 순위 (Shadow API 후보)", 0, y, 10, 8,
          [tgt(ALR, "*", buckets=[terms("2", "data.method", 10), terms("3", "data.path", 20)])],
          rename={"data.method": "메서드", "data.path": "경로", "Count": "호출 수"}),
    table("ML 경보 창 (high · medium)", 10, y, 14, 8,
          [tgt(ML, "level:high OR level:medium", metrics=raw(), buckets=[])],
          "IP × 5분 창. seq_id_run = 연속 ID 길이, id_span_log = 서로 다른 객체 수(log), offspec = 명세 밖 비율",
          rename={"timestamp": "창 시작", "client_ip": "IP", "level": "판정", "score": "점수", "n_req": "요청",
                  "seq_id_run": "연속 ID", "id_span_log": "id_span_log", "err_ratio": "오류 비율",
                  "offspec_ratio": "명세 밖", "label": "정답"},
          order=["timestamp", "client_ip", "level", "score", "label", "n_req", "seq_id_run", "id_span_log",
                 "err_ratio", "offspec_ratio"],
          sort=("점수", False),
          overrides=[color_by_value("level", {"high": "red", "medium": "orange"}),
                     color_by_value("label", {"bola": "red", "probe": "orange", "normal": "green"})]),
]
y += 8
panels += [
    table("IP별 요청 수 Top 10", 0, y, 12, 8,
          [tgt(ACC, "*", buckets=[terms("2", "client_ip", 10)])],
          "요청 수로 줄 세우면 BOLA 공격자(10.77.0.1)는 안 보인다 — 전체 31위, 공격 10분 13위",
          rename={"client_ip": "IP", "Count": "요청 수"}),
    table("IP별 서로 다른 경로 수 Top 10 (BOLA 단서)", 12, y, 12, 8,
          [tgt(ACC, "*", metrics=[{"id": "1", "type": "cardinality", "field": "path"}],
               buckets=[terms("2", "client_ip", 10, order_by="1")])],
          "서로 다른 경로(객체) 수로 줄 세우면 BOLA 공격자가 1위 — 공격 10분 63 vs 2위 29",
          rename={"client_ip": "IP", "Unique Count": "서로 다른 경로 수"}),
]
y += 8
# (sortBy 는 organize 뒤에 오므로 바뀐 이름으로 정렬한다)
# ── 5줄: 원본 ─────────────────────────────────────────────────────────────────
panels += [
    table("최근 Shadow 룰 경보 (원본)", 0, y, 24, 9,
          [tgt(ALR, "*", metrics=raw(), buckets=[])],
          rename={"timestamp": "시각", "rule.level": "레벨", "rule.description": "설명", "data.client_ip": "IP",
                  "data.method": "메서드", "data.path": "경로", "data.status": "상태", "label": "정답", "rule.id": "룰 ID"},
          order=["timestamp", "rule.level", "rule.description", "data.client_ip", "data.method", "data.path",
                 "data.status", "label", "rule.id"],
          sort=("시각", True),
          overrides=[color_by_value("label", {"bola": "red", "probe": "orange", "normal": "green"})]),
]

dash = {
    "uid": "dvra-detection", "title": "DVRA — Shadow API 룰 + ML(BOLA) 탐지", "tags": ["shadow-api", "bola", "dvra"],
    "timezone": "browser", "schemaVersion": 39, "editable": True, "refresh": "",
    "time": {"from": "2026-11-18T07:35:00.000Z", "to": "2026-11-18T08:55:00.000Z"},
    "description": "DVRA 2차 수집(정상 30명 73분 + 탐색 · BOLA 공격)을 실제 wazuh-logtest 판정과 ML 점수로 본다",
    "panels": panels,
}
out = Path(__file__).parent / "grafana" / "dashboards" / "dvra_detection.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(dash, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"패널 {len(panels)}개 → {out}")
