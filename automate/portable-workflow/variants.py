#!/usr/bin/env python3
"""공격 변종 생성 v2 — 원본 e2e_story/eval/variants.py 의 회피 기법(V1~V7)은 그대로 쓰고, '어느 경로를 공격하나'만 대상 명세에서 가져온다.

원본은 공격 대상이 /api/v2/orders/{id} 등 팀 웹 경로로 고정돼 있어, 다른 앱의 모델을 팀 웹 모양의 공격으로 시험하게 된다.

  E2E_SPEC=<명세> [E2E_BOLA_TARGETS="/a/{id},/b/{id}"] python3 variants.py --out-dir <dir> [--n 40] [--seed 100]

  E2E_BOLA_TARGETS  소유 자원 조회 경로(주문·내 정보처럼 주인만 봐야 하는 것). 첫 번째가 주 공격 대상.
                    비우면 명세의 'GET 이고 마지막 조각이 파라미터인 경로' 전부를 대상으로 본다(공개 자원도 섞이므로 지정을 권장).
"""
import importlib.util, os, re, sys
from _shim import HERE, require, use_v2_features

require("--out-dir")
use_v2_features()
import features  # v2

features.load_spec()
PARAM = re.compile(r"\{[^}]+\}")
gets = [p for p, ms in features.SPEC_PATHS if "GET" in ms]
param1 = [PARAM.sub("{id}", p) for p in gets if len(PARAM.findall(p)) == 1 and p.rstrip("/").endswith("}")]
plain = [p for p in gets if not PARAM.search(p)]
env = [t.strip() for t in os.environ.get("E2E_BOLA_TARGETS", "").split(",") if t.strip()]
targets = [PARAM.sub("{id}", t) for t in env] or sorted(param1)
if not targets:
    sys.exit("[variants v2] 명세에 ID 를 경로로 받는 GET 이 없습니다 — E2E_BOLA_TARGETS 로 지정하세요")
public_objects = [p.replace("{id}", "{r}") for p in sorted(param1) if p not in targets]   # 대상이 아닌 ID 경로 = 공개 자원(정상 사용자가 여러 개 본다)

_V1 = os.path.join(HERE, "..", "eval", "variants.py")              # 작업 레포
if not os.path.exists(_V1):                                         # 공개 레포
    _V1 = os.path.join(HERE, "..", "..", "ml", "eval", "variants.py")
spec = importlib.util.spec_from_file_location("variants_v1", _V1)
v1 = importlib.util.module_from_spec(spec); spec.loader.exec_module(v1)
v1.SPEC_TARGET = targets[0]
v1.OTHER_TARGETS = targets
v1.NORMAL_PAGES = ["/"] + sorted(plain) + public_objects
print(f"[variants v2] 주 대상 {targets[0]} · 대상 {len(targets)}개 · 정상 경로 {len(v1.NORMAL_PAGES)}개"
      + ("" if env else "  (E2E_BOLA_TARGETS 미지정 — 명세에서 자동 선택)"))
v1.main()
