"""
SBOM Diff — CycloneDX JSON 두 버전 비교 → Markdown 보고서

사용법:
  python tools/sbom_diff.py --before sbom_old.cdx.json --after sbom_new.cdx.json
  python tools/sbom_diff.py --before old.json --after new.json --out diff.md
"""

import argparse, json, sys
from datetime import date
from pathlib import Path


def load_components(path: Path) -> dict[str, str]:
    """SBOM JSON → {name: version} 맵. 같은 이름 여러 버전은 최신 유지."""
    data = json.loads(path.read_text(encoding="utf-8"))
    comps = {}
    for c in data.get("components", []):
        name    = c.get("name", "")
        version = c.get("version", "")
        if name:
            comps[name] = version
    return comps


def diff(before: dict, after: dict) -> tuple[list, list, list, int]:
    added, removed, changed = [], [], []
    unchanged = 0

    all_names = set(before) | set(after)
    for name in sorted(all_names):
        b_ver = before.get(name)
        a_ver = after.get(name)

        if b_ver is None:
            added.append((name, a_ver))
        elif a_ver is None:
            removed.append((name, b_ver))
        elif b_ver != a_ver:
            changed.append((name, b_ver, a_ver))
        else:
            unchanged += 1

    return added, removed, changed, unchanged


def build_md(added, removed, changed, unchanged) -> str:
    today = date.today()
    lines = [f"## SBOM Diff — {today}", ""]

    if not added and not removed and not changed:
        lines += ["**변경 없음** — 두 SBOM이 동일합니다.", ""]
        return "\n".join(lines)

    lines += [
        "| 변경 | 이름 | 이전 버전 | 이후 버전 |",
        "|---|---|---|---|",
    ]
    for name, ver in added:
        lines.append(f"| ➕ 추가 | {name} | — | {ver or '(없음)'} |")
    for name, ver in removed:
        lines.append(f"| ➖ 삭제 | {name} | {ver or '(없음)'} | — |")
    for name, b_ver, a_ver in changed:
        lines.append(f"| 🔄 변경 | {name} | {b_ver or '(없음)'} | {a_ver or '(없음)'} |")

    n_add = len(added)
    n_rem = len(removed)
    n_chg = len(changed)
    lines += [
        "",
        f"**요약**: 추가 {n_add} · 삭제 {n_rem} · 변경 {n_chg} · 변경없음 {unchanged}",
        "",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="CycloneDX SBOM diff Markdown 보고서 생성")
    ap.add_argument("--before", required=True, help="이전 SBOM JSON 경로")
    ap.add_argument("--after",  required=True, help="이후 SBOM JSON 경로")
    ap.add_argument("--out",    default=None,  help="출력 파일 (기본 stdout)")
    args = ap.parse_args()

    b_path = Path(args.before)
    a_path = Path(args.after)

    for p in (b_path, a_path):
        if not p.exists():
            sys.exit(f"[ERROR] 파일 없음: {p}")

    before = load_components(b_path)
    after  = load_components(a_path)

    print(f"[INFO] before: {len(before)}개 부품  ({b_path})", file=sys.stderr)
    print(f"[INFO] after:  {len(after)}개 부품  ({a_path})", file=sys.stderr)

    added, removed, changed, unchanged = diff(before, after)
    md = build_md(added, removed, changed, unchanged)

    if args.out:
        Path(args.out).write_text(md, encoding="utf-8", newline="\n")
        print(f"[OUT] {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(md)


if __name__ == "__main__":
    main()
