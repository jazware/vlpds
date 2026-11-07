#!/usr/bin/env bash
# Spaces migration e2e (README.md "Spaces"): local PLC, mail catcher and a
# reference PDS at the Spaces alpha in docker, two local vlpds with --spaces
# (the target, and a source for the vlpds -> vlpds move), then spaces.mjs.
# Tears everything down afterwards unless KEEP=1.
#
#   bench/migrate/spaces.sh      (or: just migrate-spaces-e2e)
#
# Env: VLPDS_BIN (default: build target/dev-release/vlpds), KEEP=1, HEADED=1,
# REF_SPACES_IMAGE (another reference image than the pinned native build).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cd "$here"

PLC_PORT=2782 MAIL_PORT=2785 REF_SPACES_PORT=2786 VLPDS_PORT=2787 SRC_PORT=2788
export PLC_PORT MAIL_PORT REF_SPACES_PORT COMPOSE_PROFILES=spaces
export VLPDS="http://127.0.0.1:$VLPDS_PORT" SRC_VLPDS="http://localhost:$SRC_PORT" REF_SPACES="http://localhost:$REF_SPACES_PORT" PLC="http://127.0.0.1:$PLC_PORT" MAILPIT="http://127.0.0.1:$MAIL_PORT"
project=vlpds-migrate-spaces

# The reference at the pin bench/spaces/refpds.sh builds (the published
# pds-spaces-alpha tag moves, and is amd64 only), built the first time.
if [ -z "${REF_SPACES_IMAGE:-}" ]; then
  "$root/bench/spaces/refpds.sh"
  pin="$(sed -n 's/^PIN=//p' "$root/bench/spaces/refpds.sh")"
  REF_SPACES_IMAGE="vlpds-spaces-refpds:${pin:0:8}"
fi
export REF_SPACES_IMAGE

for p in $PLC_PORT $MAIL_PORT $REF_SPACES_PORT $VLPDS_PORT $SRC_PORT; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is in use (an earlier run? docker compose -p $project down -v)" >&2
    exit 1
  fi
done

bin="${VLPDS_BIN:-}"
if [ -z "$bin" ]; then
  (cd "$root/ui" && npm install --no-audit --no-fund --silent && npm run build --silent)
  (cd "$root" && cargo build --profile dev-release --bin vlpds)
  bin="${CARGO_TARGET_DIR:-$root/target}/dev-release/vlpds"
fi
npm install --no-audit --no-fund --silent
npx playwright install chromium >/dev/null

pids=()
cleanup() {
  if [ "${KEEP:-}" = 1 ]; then
    echo "KEEP=1: left running (vlpds pids ${pids[*]}); stop with: kill ${pids[*]}; docker compose -p $project down -v"
    return
  fi
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  docker compose -p "$project" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -p "$project" up -d --wait plc mail ref-spaces

mkdir -p out/spaces
# fixed dev rotation keys: each vlpds signs PLC operations with its own (local PLC only)
start() { # name port public-url handle-domain rotation-key
  "$bin" --memory --dev-mode --spaces \
    --listen "127.0.0.1:$2" --public-url "$3" \
    --handle-domain "$4" --service-did "did:web:$4" \
    --plc-url "$PLC" --plc-mode directory \
    --plc-rotation-key "$5" >"out/spaces/$1.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$2/xrpc/_health" >/dev/null && return
    sleep 0.2
  done
  tail -20 "out/spaces/$1.log"
  exit 1
}
start vlpds "$VLPDS_PORT" "$VLPDS" vlpds.test 9f2c1d4e5b6a79880716253443526170f1e2d3c4b5a69788a9b8c7d6e5f40312
start src "$SRC_PORT" "$SRC_VLPDS" src.test 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809

node spaces.mjs
