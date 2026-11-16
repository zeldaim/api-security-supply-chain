"""
CycloneDX 1.6 VEX 자동 생성기
grype.json (CVE 목록) + attack_chain.csv (도달성) → vex.cdx.json

사용법:
  python tools/make_vex.py                          # 최신 run 자동 선택
  python tools/make_vex.py --run output/2026-11-08_143022
  python tools/make_vex.py --run output/latest --out /tmp/vex.json
"""

import argparse, csv, json, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT    = Path(__file__).parent.parent
OUT_DIR = ROOT / "output"

HIGH_SEV = {"Critical", "High"}


def _latest_run(out_dir: Path) -> Path | None:
    runs = sorted((d for d in out_dir.iterdir() if d.is_dir()), reverse=True) \
        if out_dir.exists() else []
    return runs[0] if runs else None


def load_grype(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    cves = []
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        cid = v.get("id", "")
        if cid.startswith("CVE-"):
            cves.append({"id": cid, "severity": v.get("severity", "Unknown")})
    seen = {}
    for c in cves:
        seen.setdefault(c["id"], c)
    return list(seen.values())


def load_active_endpoints(csv_path: Path) -> bool:
    if not csv_path.exists():
        return False
    with open(csv_path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            verdict = row.get("verdict", row.get("verdict_cls", "normal"))
            if verdict != "normal":
                return True
    return False


def make_vex(cves: list[dict], has_active_attack: bool) -> list[dict]:
    vulns = []
    for c in cves:
        cid   = c["id"]
        sev   = c.get("severity", "Unknown")
        url   = f"https://nvd.nist.gov/vuln/detail/{cid}"

        if has_active_attack and sev in HIGH_SEV:
            state = "exploitable"
            analysis = {
                "state": "exploitable",
                "detail": "Active attack path detected via threat correlation (attack_chain.csv)"
            }
        elif not has_active_attack and sev not in HIGH_SEV:
            analysis = {
                "state": "not_affected",
                "justification": "code_not_reachable",
                "detail": "No reachable attack path detected via threat correlation"
            }
        else:
            analysis = {
                "state": "under_investigation",
                "detail": "Reachability not yet determined"
            }

        vulns.append({
            "id": cid,
            "source": {"name": "NVD", "url": url},
            "analysis": analysis
        })
    return vulns


def build_doc(vulns: list[dict]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"name": "make_vex.py", "version": "1.0"}]
        },
        "vulnerabilities": vulns
    }


def main():
    ap = argparse.ArgumentParser(description="CycloneDX 1.6 VEX 자동 생성기")
    ap.add_argument("--run",  default=None, help="run 디렉터리 (없으면 최신 자동 선택)")
    ap.add_argument("--out",  default=None, help="출력 경로 (기본: run/vex.cdx.json)")
    ap.add_argument("--sbom", default=None, help="SBOM 경로 (현재 미사용, 호환용)")
    args = ap.parse_args()

    if args.run:
        run_dir = Path(args.run)
    else:
        run_dir = _latest_run(OUT_DIR)
        if run_dir is None:
            sys.exit(f"[ERROR] 실행 결과 없음: {OUT_DIR}")

    if not run_dir.exists():
        sys.exit(f"[ERROR] run 디렉터리 없음: {run_dir}")

    out_path = Path(args.out) if args.out else run_dir / "vex.cdx.json"

    print(f"[INFO] run 디렉터리: {run_dir}")

    cves = load_grype(run_dir / "grype.json")
    print(f"       CVE 목록: {len(cves)}개")

    has_attack = load_active_endpoints(run_dir / "attack_chain.csv")
    print(f"       활성 공격 경로: {'있음' if has_attack else '없음'}")

    vulns = make_vex(cves, has_attack)

    exploitable       = sum(1 for v in vulns if v["analysis"]["state"] == "exploitable")
    not_affected      = sum(1 for v in vulns if v["analysis"]["state"] == "not_affected")
    under_invest      = sum(1 for v in vulns if v["analysis"]["state"] == "under_investigation")

    doc = build_doc(vulns)
    out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")

    print(f"[OUT] {out_path}")
    print(f"      전체 {len(vulns)}개 — exploitable {exploitable} · not_affected {not_affected} · under_investigation {under_invest}")


if __name__ == "__main__":
    main()
