#!/usr/bin/env bash
# Build the production image on this Mac and push it. The Dockerfile's Rust
# stage cross-compiles natively for the target, so only the runtime stage's
# apt step runs under emulation (OrbStack's Rosetta). If amd64 containers fail
# with "exec format error", OrbStack lost its Rosetta registration: run
# `orb stop && orb start` (restarting just the docker engine isn't enough).
#
#   build/mac-image.sh [tag]        (or: just docker-push [tag])
#
# Builds the committed tree (vcs_archive), as benchbox-image.sh does, so
# uncommitted edits never reach an image.
#
# Env: IMAGE (ghcr.io/jazware/vlpds), PLATFORM (linux/amd64), FEATURES
# (cargo features, e.g. profiling), CARGO_BUILD_JOBS, PUSH=0 (load only).
set -euo pipefail
IMAGE=${IMAGE:-ghcr.io/jazware/vlpds}
vcs="$(dirname "$0")/../../../scripts/vcs.sh"
if [ -f "$vcs" ]; then
  . "$vcs"
else
  # the public repo: a git clone, without mono's scripts/
  vcs_short() { git rev-parse --short=12 HEAD; }
  vcs_delta_git_sha() { :; }
fi
cd "$(dirname "$0")/.."
tag=${1:-$(vcs_short)}
git_sha=$(vcs_delta_git_sha)
t_start=$(date +%s)
ctx=$(mktemp -d)
cfg=$(mktemp -d)
trap 'rm -rf "$ctx" "$cfg"' EXIT
build/context.sh "$ctx"
docker buildx build --platform "${PLATFORM:-linux/amd64}" \
  --build-arg "VLPDS_GIT_REV=$tag" \
  ${FEATURES:+--build-arg "VLPDS_FEATURES=$FEATURES"} \
  ${CARGO_BUILD_JOBS:+--build-arg "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS"} \
  ${git_sha:+--label "dev.example.delta.git-sha=$git_sha"} \
  -t "$IMAGE:$tag" --load "$ctx"
if [ "${PUSH:-1}" = 1 ]; then
  # DOCKER_HOST keeps the current context's daemon (contexts live in DOCKER_CONFIG)
  host=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
  gh auth token | DOCKER_CONFIG=$cfg DOCKER_HOST=$host docker login ghcr.io -u "$(gh api user -q .login)" --password-stdin >/dev/null
  DOCKER_CONFIG=$cfg DOCKER_HOST=$host docker push -q "$IMAGE:$tag"
fi
printf 'mac-image: %s:%s in %ds\n' "$IMAGE" "$tag" $(($(date +%s) - t_start)) >&2
