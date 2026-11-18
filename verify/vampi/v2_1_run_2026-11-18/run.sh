#!/usr/bin/env bash
# VAmPI 에서 bootstrap v2 를 돌린다 (Docker 실행 환경 e2e-runner 필요 — automate/portable-workflow-v2.1/Dockerfile.runner).
#   bash run.sh [단계|all]        기본 all
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../../.." && pwd)"
WIN_REPO="$(cd "$REPO" && pwd -W 2>/dev/null || echo "$REPO")"
ENVS="-e CONFIG_ENV=verify/vampi/v2_1_run_2026-11-18/config.vampi.v2_1.env"; while IFS= read -r l; do case "$l" in ''|\#*) continue;; esac; ENVS="$ENVS -e $l"; done < "$HERE/config.vampi.v2_1.env"
export MSYS_NO_PATHCONV=1
# shellcheck disable=SC2086
docker run --rm -v "$WIN_REPO:/repo" -w /repo $ENVS e2e-runner bash automate/portable-workflow-v2.1/bootstrap.sh "${1:-all}"
