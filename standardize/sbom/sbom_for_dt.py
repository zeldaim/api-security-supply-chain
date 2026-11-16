"""CI(syft) 가 만든 이미지 SBOM → Dependency-Track 업로드용 사본 + 이전 SBOM 과 비교.

사용법:
    python tools/sbom_for_dt.py <ci-sbom.cdx.json> [-o <dt-upload.cdx.json>] [--prev <이전 sbom.cdx.json>]

하는 일 (원본은 건드리지 않는다):
  1) type=file 항목 제거 — syft 1.42 는 이미지 안 파일 8천여 개를 부품으로 함께 적는다.
     취약점 매칭에는 패키지만 필요하고, 파일까지 올리면 DT DB 가 불필요하게 커진다.
  2) 라이선스 id/expression → name(자유 문자열) 으로 변환.
     syft 1.42 의 SPDX 목록이 DT 4.13.2 스키마보다 새로워 'Artistic-dist' 등에서
     "Schema validation failed" 400 이 난다 (2026-11-03). 라이선스는 취약점 매칭과 무관.
  3) --upstream 을 주면 deb 부품 purl 이름을 upstream= 값(원본 패키지 이름)으로 바꾼다.
     OSV Debian 은 원본 이름(curl, openssl)으로 기록돼 있어 바이너리 이름(libcurl4, libssl1.1)
     purl 로는 DT 가 매칭하지 못한다 (07 §4-1 보완 ①). 부품 name 은 그대로 두고 purl 만 바꾸며,
     원래 purl 은 property 'sesac:original-purl' 에 남긴다. upstream=이름@버전 이면 버전도 원본 버전으로 바꾼다.
  4) --prev 를 주면 패키지 purl 로 비교해 추가·삭제·버전 변경을 출력.
     purl 의 package-id 는 매번 달라지고, ':' ↔ '%3A' 표기는 syft 버전에 따라 달라서 정규화 후 비교.

표준 라이브러리만 사용.
"""
import argparse
import json
import re
from urllib.parse import quote, unquote


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def packages(d):
    return [c for c in d.get("components", []) if c.get("type") != "file"]


def norm_purl(c):
    p = c.get("purl") or f"name:{c['name']}@{c.get('version', '')}"
    p = re.sub(r"[?&]package-id=[0-9a-f]+", "", p)
    return unquote(p)


def key(purl):
    """버전 앞까지 = 같은 부품인지 판단하는 키"""
    return purl.split("@")[0]


# 원본 이름으로 바꾸지 않을 원본 패키지.
#  linux: linux-libc-dev(커널 헤더)가 원본 'linux' 로 바뀌면 커널 CVE 수천 건이 붙는다 (2026-11-05 실측 7,600+ 건,
#  DT finding 조회가 PostgreSQL 'stack depth limit exceeded' 로 실패). 컨테이너는 호스트 커널을 쓰므로
#  이미지 취약점이 아니다 → 이름 그대로 두어 매칭하지 않는다.
SKIP_SOURCES = {"linux"}


def upstream_purl(purl):
    """pkg:deb/debian/libcurl4@ver?...&upstream=curl → pkg:deb/debian/curl@ver?...
    upstream=src@srcver 이면 버전도 원본 버전으로 (gcc → gcc-defaults@1.190). 바뀔 게 없으면 None"""
    if not purl.startswith("pkg:deb/"):
        return None
    m = re.search(r"[?&]upstream=([^&]+)", purl)
    if not m:
        return None
    src, _, srcver = unquote(m.group(1)).partition("@")
    if src in SKIP_SOURCES:
        return None
    head, _, rest = purl.partition("@")
    ver, _, qual = rest.partition("?")
    ns, _, name = head.rpartition("/")
    qual = "&".join(q for q in qual.split("&") if q and not q.startswith("upstream="))
    ver = quote(srcver, safe=":~.-") if srcver else ver
    out = f"{ns}/{src or name}@{ver}" + (f"?{qual}" if qual else "")
    return None if (src or name) == name and ver == rest.partition("?")[0] else out


def to_upstream(d):
    n = 0
    for c in d["components"]:
        new = upstream_purl(c.get("purl", ""))
        if new:
            c.setdefault("properties", []).append({"name": "sesac:original-purl", "value": c["purl"]})
            c["purl"] = new
            n += 1
    return n


def to_dt(d):
    keep = packages(d)
    refs = {c.get("bom-ref") for c in keep} | {d.get("metadata", {}).get("component", {}).get("bom-ref")}
    n = 0
    for c in keep:
        new = []
        for x in c.get("licenses") or []:
            if "expression" in x:
                new.append({"license": {"name": x["expression"]}}); n += 1
            else:
                lic = x.get("license", {})
                if "id" in lic:
                    new.append({"license": {"name": lic["id"]}}); n += 1
                else:
                    new.append({"license": {"name": lic.get("name", "")}})
        if new:
            c["licenses"] = new
    d["components"] = keep
    d["dependencies"] = [
        {"ref": x["ref"], "dependsOn": [y for y in x.get("dependsOn", []) if y in refs]}
        for x in d.get("dependencies", []) if x["ref"] in refs
    ]
    return d, n


def diff(prev, cur):
    a = {key(p): p for p in map(norm_purl, packages(prev))}
    b = {key(p): p for p in map(norm_purl, packages(cur))}
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    tool = lambda d: ", ".join(f"{t['name']} {t['version']}" for t in d["metadata"].get("tools", {}).get("components", []))
    print(f"이전 {len(a)} 패키지 ({tool(prev)})  →  현재 {len(b)} 패키지 ({tool(cur)})")
    print(f"  버전 변경 {len(changed)}")
    for k in changed:
        print(f"    {k}: {a[k].split('@')[1].split('?')[0]} → {b[k].split('@')[1].split('?')[0]}")
    print(f"  추가 {len(added)}")
    for k in added:
        print(f"    + {b[k].split('?')[0]}")
    print(f"  삭제 {len(removed)}")
    for k in removed:
        print(f"    - {a[k].split('?')[0]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sbom")
    ap.add_argument("-o", "--out")
    ap.add_argument("--prev")
    ap.add_argument("--hash", action="store_true", help="부품 목록(purl·버전) 해시만 출력 — 시각·serialNumber 가 달라도 부품이 같으면 같은 값 (dt_upload.sh 중복 방지)")
    ap.add_argument("--upstream", action="store_true", help="deb purl 이름 → 원본(upstream) 이름 (07 §4-1 ①)")
    args = ap.parse_args()

    cur = load(args.sbom)
    if args.hash:
        import hashlib
        keys = sorted(norm_purl(c) for c in packages(cur))
        print(hashlib.sha256(chr(10).join(keys).encode()).hexdigest()[:16])
        return
    if args.prev:
        diff(load(args.prev), cur)
    if args.out:
        d, n = to_dt(load(args.sbom))
        u = to_upstream(d) if args.upstream else 0
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
        print(f"DT 업로드용: {args.out} (패키지 {len(d['components'])}, 라이선스 변환 {n}, upstream 이름 변환 {u})")


if __name__ == "__main__":
    main()
