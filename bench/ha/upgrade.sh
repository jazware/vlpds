#!/usr/bin/env bash
# Two-build HA scenarios (hactl.py upgrade-*; DESIGN.md "Rolling upgrades and
# format versioning", ops/RUNBOOK.md "Rolling upgrade, finalize, rollback").
# Builds, into $VLPDS_UPGRADE_DIR (default target/upgrade):
#   prev/vlpds    the previous release: $VLPDS_PREV_REV, default the newest
#                 `vlpds-v*` tag merged into HEAD, else PREV_PINNED below
#                 (built once per rev and kept: prev/REV records which)
#   new/vlpds     this tree
#   new-tl/vlpds  this tree with --features test-level (the test-only feature
#                 level 2: segment magic VLSEGT1 + a retain/ report field), so
#                 finalize changes formats between the two builds
# plus loadgen and the Go tools, then runs the scenarios named (default: all
# upgrade-*).
#
#   bench/ha/upgrade.sh                          # every upgrade-* scenario
#   bench/ha/upgrade.sh upgrade-rolling          # one
#   bench/ha/upgrade.sh --minio upgrade-rolling  # on a throwaway MinIO container
#   SKIP_BUILD=1 bench/ha/upgrade.sh ...         # reuse the binaries
#
# MinIO: $VLPDS_HA_S3 (default 127.0.0.1:9200) with a `vlpds` bucket
# (minioadmin/minioadmin); --minio starts one there (tmpfs, removed on exit).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PKG="$(cd "$HERE/../.." && pwd)"
# The oldest "previous release" a rolling upgrade to this tree is promised
# to work from: the first build that writes 40-byte repo stats rows (S/, the
# repo's bytes) and filter counts in the totals rows. That change got no
# feature level, so older builds can't read what newer ones write and the
# upgrade from them is one-way (docs/operations/upgrades.md, "Upgrading from
# builds before 2026-10-06"). Found by a line that commit introduced, so it
# survives rebases.
PREV_PINNED="$(git -C "$PKG" log --reverse --format=%h -S'LEN_COUNTS: usize = 24' -- src/state.rs | head -1)"
export VLPDS_UPGRADE_DIR="${VLPDS_UPGRADE_DIR:-$PKG/target/upgrade}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$VLPDS_UPGRADE_DIR/target}"
export VLPDS_BIN_DIR="${VLPDS_BIN_DIR:-$VLPDS_UPGRADE_DIR/new}"
export HA_RUN_ID="${HA_RUN_ID:-upgrade-$(date +%Y%m%d-%H%M%S)}"
export VLPDS_HA_S3="${VLPDS_HA_S3:-127.0.0.1:9200}"

MINIO=""
if [[ "${1:-}" == --minio ]]; then
  shift
  MINIO="vlpds-upgrade-minio-$$"
  port="${VLPDS_HA_S3##*:}"
  docker run -d --rm --name "$MINIO" -p "127.0.0.1:$port:9000" --tmpfs /data:size=4g \
    -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin vlpds-minio:local server /data >/dev/null
  trap 'docker rm -f "$MINIO" >/dev/null 2>&1 || true' EXIT
  for _ in $(seq 1 60); do curl -sf "http://$VLPDS_HA_S3/minio/health/live" >/dev/null && break; sleep 0.5; done
  docker exec "$MINIO" sh -c 'mc alias set l http://127.0.0.1:9000 minioadmin minioadmin >/dev/null && mc mb -p l/vlpds >/dev/null'
fi

prev_rev() {
  if [[ -n "${VLPDS_PREV_REV:-}" ]]; then echo "$VLPDS_PREV_REV"; return; fi
  local tag
  tag="$(git -C "$PKG" tag --merged HEAD --sort=-creatordate --list 'vlpds-v*' | head -1)"
  echo "${tag:-$PREV_PINNED}"
}

if [[ "${SKIP_BUILD:-}" != 1 ]]; then
  REV="$(prev_rev)"
  SHA="$(git -C "$PKG" rev-parse --short "$REV^{commit}")"
  mkdir -p "$VLPDS_UPGRADE_DIR/prev" "$VLPDS_UPGRADE_DIR/new" "$VLPDS_UPGRADE_DIR/new-tl"
  if [[ "$(cat "$VLPDS_UPGRADE_DIR/prev/REV" 2>/dev/null)" != "$SHA" || ! -x "$VLPDS_UPGRADE_DIR/prev/vlpds" ]]; then
    echo "building the previous release $REV ($SHA)"
    src="$VLPDS_UPGRADE_DIR/prev-src"
    rm -rf "$src" && mkdir -p "$src"
    # (from the repo root: in a subdirectory git archive limits a tree to it)
    git -C "$(git -C "$PKG" rev-parse --show-toplevel)" archive "$SHA:$(git -C "$PKG" rev-parse --show-prefix)" | tar -x -C "$src"
    # (no .git in the archive: name the rev for vlpds_build_info / leases)
    (cd "$src" && VLPDS_GIT_REV="$SHA" cargo build --profile dev-release --bin vlpds)
    cp "$CARGO_TARGET_DIR/dev-release/vlpds" "$VLPDS_UPGRADE_DIR/prev/vlpds"
    echo "$SHA" > "$VLPDS_UPGRADE_DIR/prev/REV"
    rm -rf "$src"
  fi
  (cd "$PKG" && cargo build --profile dev-release --bin vlpds --bin loadgen)
  cp "$CARGO_TARGET_DIR/dev-release/vlpds" "$CARGO_TARGET_DIR/dev-release/loadgen" "$VLPDS_UPGRADE_DIR/new/"
  (cd "$PKG" && cargo build --profile dev-release --bin vlpds --features test-level)
  cp "$CARGO_TARGET_DIR/dev-release/vlpds" "$VLPDS_UPGRADE_DIR/new-tl/vlpds"
  (cd "$HERE/faultproxy" && go build -o faultproxy .)
  (cd "$HERE/fhaudit" && go build -o fhaudit .)
  (cd "$PKG/checker" && go build -o checker .)
fi
echo "previous: $(cat "$VLPDS_UPGRADE_DIR/prev/REV" 2>/dev/null || echo '?')  current: $(git -C "$PKG" rev-parse --short HEAD)$(git -C "$PKG" diff --quiet HEAD -- . || echo '+dirty')"

SCEN="${*:-$(python3 "$HERE/hactl.py" list | awk '{print $1}' | grep '^upgrade-' | tr '\n' ' ')}"
rc=0
# shellcheck disable=SC2086
python3 "$HERE/hactl.py" run $SCEN || rc=$?
echo; echo "summary: $HERE/out/$HA_RUN_ID/summary.md"
cat "$HERE/out/$HA_RUN_ID/summary.md"
exit $rc
