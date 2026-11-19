# 이미지 서명 · 출처 증명 · 미서명 이미지 차단 (2026-11-19)

공급망 보안의 **무결성** 절반 — "이 이미지가 정말 우리 CI 가 만든 그대로인가". 취약성 절반(SBOM · VEX · 도달성)은 이 저장소의 `standardize/`.

```
빌드(GitHub Actions) → 서명 · SBOM 증명 · SLSA 출처 증명 → GHCR → 【배포 직전 검증 — Kyverno】 → 실행
```

## 1. CI — 서명과 증명 (api-defense-lab)

대상: [api-defense-lab](https://github.com/zeldaim/api-defense-lab) 도구 이미지 `ghcr.io/zeldaim/api-defense-lab/tools` — 실제로 사람들이 받는 이미지.
워크플로: [`release-image.yml`](https://github.com/zeldaim/api-defense-lab/blob/main/.github/workflows/release-image.yml) (첫 실행 1분 22초 통과)

| 붙이는 것 | 방법 |
|---|---|
| 서명 | cosign **keyless** — 키 파일 없이 워크플로 신원(GitHub OIDC)으로, 기록은 Sigstore 공개 로그(Rekor) |
| SBOM 증명 | Syft → CycloneDX → `cosign attest` |
| SLSA 출처 증명 | `actions/attest-build-provenance` → `slsa.dev/provenance/v1` (레포 · 워크플로 · 커밋) |
| CI 권한 축소 | `permissions: {}` 기본 → 작업에 4개만, 액션은 **커밋 SHA 고정**, `persist-credentials: false` |

CI 밖(로그인 없이)에서 확인: 서명 ✅ · SBOM 증명 ✅ · `gh attestation verify` ✅ · **다른 신원을 기대하면 `no matching CertificateIdentity` 로 실패** ✅

## 2. 배포 직전 차단 — Kyverno (쿠버네티스)

서명은 붙이기만 해서는 아무것도 못 막는다 — 실행 직전에 확인하고 거부하는 문지기가 있어야 한다. 쿠버네티스의 표준 문지기는 admission controller 다.

- 환경: 로컬 CKA 실습 클러스터 (k8s v1.34, 단일 노드, Calico) · **Kyverno v1.20.0** (공식 `install.yaml`)
- 정책: [`policy.yaml`](policy.yaml) — `ImageValidatingPolicy` (CEL). `lab-secure` 네임스페이스의 모든 이미지는
  ① `zeldaim/api-defense-lab` 의 `release-image.yml`(main) 이 keyless 서명했고 ② 같은 신원이 서명한 CycloneDX SBOM 증명이 있어야 실행.
  검증 못 하면 거부(`failurePolicy: Fail`), 태그는 검증한 digest 로 고정(`mutateDigest`).
- 시험: [`pods.yaml`](pods.yaml)

| 시험 | 이미지 | 결과 | Kyverno 가 남긴 이유 |
|---|---|---|---|
| A | `ghcr.io/zeldaim/api-defense-lab/tools:latest` (우리 CI 서명) | ✅ **허용** — 태그가 `@sha256:01a4e81d…` 로 고정돼 실행, 출력 `ok 1.5.2` | — |
| B | `docker.io/library/nginx:1.27-alpine` (서명 없음) | ⛔ **거부** | `failed to verify cosign signatures: no signatures found` |
| C | `cgr.dev/chainguard/cosign:latest` (**서명은 있다** — 발급자는 같은 GitHub Actions, 신원은 `chainguard-images/images/.../release.yaml`) | ⛔ **거부** | `no matching signatures: none of the expected identities matched` |
| 범위 | 같은 nginx 를 `default` 네임스페이스에 | ✅ 허용 (정책 대상 아님) · `lab-secure` 안에서는 다시 거부 | — |

C 가 중요하다: "서명이 있는가"만 보거나 발급자만 확인하는 정책이면 C 가 통과한다. 이 정책은 **누가(어느 레포 · 워크플로 · 브랜치) 서명했는가**까지 본다.

## 3. 막는 것 · 못 막는 것

| 막는다 | 못 막는다 |
|---|---|
| 레지스트리에서 이미지 바꿔치기 (서명이 안 맞음) | 이 레포의 코드 · 워크플로 자체가 오염된 경우 — 오염된 이미지도 정상 서명된다 (리뷰 · 브랜치 보호가 따로 필요) |
| 다른 곳에서 만든 이미지를 같은 이름으로 배포 | 서명된 이미지 안의 **알려진 취약점** — 그건 취약성 쪽(SBOM → CVE · VEX) 일 |
| 검증 뒤 태그를 다른 이미지로 옮기기 (digest 고정) | `lab-secure` 밖 네임스페이스 (정책 범위를 넓혀야 함) |
| 서명 · SBOM 증명이 없는 이미지 실행 | `docker run` · `docker compose` (쿠버네티스 밖에는 이 문지기가 없다 — 수동 `cosign verify` 뿐) |

## 4. 겪은 것 (기록)

| 문제 | 원인 | 조치 |
|---|---|---|
| kind 설치 막힘 | 실행 파일을 받아 실행하는 것을 작업 환경 권한 정책이 거부 | 이미 있는 CKA 실습 클러스터 사용 |
| 새 Pod 가 전부 `ContainerCreating` (`calico ... connection is unauthorized`) | VM 을 껐다 켠 뒤 이전 Pod 들이 `Unknown` 으로 남고 calico-apiserver 가 죽어 Calico 가 회복 못 함 | `Unknown` Pod 강제 삭제 → 다시 만들어지며 calico-node Ready, CoreDNS 정상 |
| `ClusterPolicy` 적용 거부 | **Kyverno 1.20 은 예전 `kyverno.io/v1` 정책을 더 이상 실행하지 않는다** (읽기 · 삭제만) | `policies.kyverno.io/v1` `ImageValidatingPolicy`(CEL) 로 다시 작성 — 클러스터의 `kubectl explain` 으로 스키마 확인 |
| 시험 A 첫 시도 **시간 초과** (거부) | 첫 검증 때 Sigstore 신뢰 루트를 받느라 서명 확인만 32초 → SBOM 증명 확인 중 웹훅 제한(30초) 초과 (`getting trusted root: context canceled`) | 재시도 27.5초로 통과(캐시). **한계:** 느린 네트워크에서는 정상 배포도 막힐 수 있다 — 운영이면 신뢰 루트를 미리 넣어 두거나(`trustedRoot`) 레지스트리 · Rekor 접근을 가깝게 |
| 시험 A 이미지 받기 16분 | VM 네트워크가 느림 (Kyverno 이미지 32MB 에 약 5분) | 기다림 — 검증과 무관 |

## 다시 해 보기

```bash
# 쿠버네티스 클러스터(kubectl 접근) + 인터넷
kubectl apply --server-side -f https://github.com/kyverno/kyverno/releases/download/v1.20.0/install.yaml
kubectl apply -f policy.yaml
kubectl apply -f pods.yaml        # A 만 생성되고 B · C 는 거부 메시지
kubectl -n lab-secure logs a-signed-ours
```
