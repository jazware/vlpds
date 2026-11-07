#!/usr/bin/env bash
# Spaces harness (README.md): local PLC, two reference PDSes and MinIO in
# docker, this checkout's vlpds (build-vlpds.sh), then one of the Node
# drivers. Tears the stack down afterwards unless KEEP=1.
#
#   bench/spaces/run.sh e2e [config ...]        (just spaces-e2e)
#   bench/spaces/run.sh sim [seed] [scale]      (just spaces-sim)
#   bench/spaces/run.sh fault [seed]            (just spaces-fault)
#   bench/spaces/run.sh cost                    (just spaces-cost)
#   bench/spaces/run.sh boards [config ...]     (just spaces-boards; boards/README.md)
#   bench/spaces/run.sh boards-ui               (just spaces-boards-ui; UI_E2E=1 runs the headless check and exits)
#   bench/spaces/run.sh boards-prod             (just spaces-boards-prod; the production server; UI_E2E=1 likewise)
#
# Env: VLPDS_BIN (skip the build; "none" for reference-only configs), BRANCH
# (build that ref instead of this checkout), CLUSTER=1 (3 vlpds nodes on MinIO behind a balancer),
# MEMORY=1 (vlpds --memory), KEEP=1, REF_PDS_IMAGE (use a prebuilt image),
# STORE=r2 (vlpds on a real bucket under bench/<run-id>/, keys from R2_ENV,
# default ~/.config/cloudflare/vlpds-bench-r2.env; README.md "Real R2").
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
mode="${1:-e2e}"
shift || true

# Runs may overlap (two checkouts, or two agents): each takes a block of 40
# ports from PORT_BASE (lib/env.mjs lays it out), its own compose project, and
# its own out/ and boards/.local/ dirs; the first block, 2860, keeps the
# plain names. Locks are mkdir dirs holding the owner's pid.
locks="${TMPDIR:-/tmp}/vlpds-spaces-locks"
mkdir -p "$locks"
claim() {
  local d="$locks/$1" pid
  if mkdir "$d" 2>/dev/null; then echo $$ >"$d/pid"; return 0; fi
  pid="$(cat "$d/pid" 2>/dev/null || true)"
  if [ -z "$pid" ] || kill -0 "$pid" 2>/dev/null; then return 1; fi
  rm -rf "$d"
  mkdir "$d" 2>/dev/null && echo $$ >"$d/pid"
}
release() { if [ "$(cat "$locks/$1/pid" 2>/dev/null)" = $$ ]; then rm -rf "${locks:?}/$1"; fi; }
listening="$(lsof -nP -iTCP -sTCP:LISTEN -Fn 2>/dev/null | sed -n 's/^n.*:\([0-9]*\)$/\1/p' | sort -u)"
block_busy() { for p in $(seq "$1" $(( $1 + 39 ))); do grep -qx "$p" <<<"$listening" && return 0; done; return 1; }

if [ -n "${PORT_BASE:-}" ]; then
  claim "ports-$PORT_BASE" || { echo "PORT_BASE=$PORT_BASE belongs to a running harness (pid $(cat "$locks/ports-$PORT_BASE/pid" 2>/dev/null))" >&2; exit 1; }
else
  for b in $(seq 2860 40 3220); do
    claim "ports-$b" || continue
    if block_busy "$b"; then release "ports-$b"; continue; fi
    PORT_BASE=$b
    break
  done
  [ -n "${PORT_BASE:-}" ] || { echo "no free block of 40 ports in 2860-3259" >&2; exit 1; }
fi
export PORT_BASE
export PLC_PORT=$PORT_BASE REF_A_PORT=$(( PORT_BASE + 1 )) REF_B_PORT=$(( PORT_BASE + 2 )) VLPDS_PORT=$(( PORT_BASE + 3 )) MINIO_PORT=$(( PORT_BASE + 8 ))
export FWD_FIRST=$(( PORT_BASE + 1 )) FWD_LAST=$(( PORT_BASE + 29 ))
if [ "$PORT_BASE" = 2860 ]; then
  export COMPOSE_PROJECT_NAME=vlpds-spaces OUT="$here/out/" LOCAL_DIR="$here/boards/.local/"
else
  export COMPOSE_PROJECT_NAME="vlpds-spaces-$PORT_BASE" OUT="$here/out/$PORT_BASE/" LOCAL_DIR="$here/boards/.local/$PORT_BASE/"
fi
# a stack left up by KEEP=1 is reused, so its own ports may be listening
running="$(docker compose ps -q 2>/dev/null | wc -l | tr -d ' ')"
for p in $(seq "$PORT_BASE" $(( PORT_BASE + 39 ))); do
  case "$p" in $PLC_PORT|$REF_A_PORT|$REF_B_PORT|$MINIO_PORT) [ "$running" != 0 ] && continue ;; esac
  if grep -qx "$p" <<<"$listening"; then
    echo "port $p is in use (an earlier run? KEEP=1 leftovers: docker compose -p $COMPOSE_PROJECT_NAME down -v)" >&2
    release "ports-$PORT_BASE"
    exit 1
  fi
done
echo "harness: ports $PORT_BASE-$(( PORT_BASE + 39 )) (vlpds :$VLPDS_PORT, boards :$(( PORT_BASE + 28 ))/:$(( PORT_BASE + 29 ))), stack $COMPOSE_PROJECT_NAME, out $OUT"

ui=""
bridge=""
# only our own children, never pid 0 or 1
stop_child() {
  local pid="$1" comm="$2"
  case "$pid" in "" | 0 | 1) return 0 ;; esac
  # node names its main thread node-MainThread
  case "$(ps -o comm= -p "$pid" 2>/dev/null)" in "$comm" | "$comm"-*) ;; *) return 0 ;; esac
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  stop_child "$ui" node
  stop_child "$bridge" node
  release setup
  if [ "${KEEP:-}" = 1 ]; then
    echo "KEEP=1: stack left up; stop with: docker compose -p $COMPOSE_PROJECT_NAME down -v (PORT_BASE=$PORT_BASE reuses it)"
  else
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  release "ports-$PORT_BASE"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# shared by every run of this checkout: the images, the vlpds build, node_modules
until claim setup; do sleep 1; done
./refpds.sh
if [ "${VLPDS_BIN:-}" = none ]; then
  unset VLPDS_BIN
else
  if [ -z "${VLPDS_BIN:-}" ]; then
    VLPDS_BIN="$(./build-vlpds.sh | tail -1)"
  fi
  export VLPDS_BIN
fi
export VLPDS_REV="$(cat .scratch/built-branch 2>/dev/null || echo '?') $(cut -c1-12 .scratch/built-rev 2>/dev/null || echo '?')"
npm install --no-audit --no-fund --silent
# lib/space.mjs and lib/syncer.mjs run on the boards app's Spaces code (packages/boards)
boards="$here/../../../boards"
(cd "$boards" && npm install --no-audit --no-fund --silent)
case "$mode" in
  boards-ui | boards-prod)
    # a build of its own: vite empties its outDir first, under a page another run may be serving
    export BOARDS_WEB_DIR="${OUT}web"
    built="$(cd "$boards/web" && npm install --no-audit --no-fund --silent && npm run build --silent -- --outDir "$BOARDS_WEB_DIR" --emptyOutDir 2>&1)" || { echo "$built" >&2; exit 1; }
    if [ "${UI_E2E:-}" = 1 ]; then (cd "$boards/e2e" && npm install --no-audit --no-fund --silent && npx playwright install chromium >/dev/null); fi
    ;;
esac
release setup

if [ "${STORE:-minio}" = r2 ]; then
  r2env="${R2_ENV:-$HOME/.config/cloudflare/vlpds-bench-r2.env}"
  [ -r "$r2env" ] || { echo "STORE=r2: no $r2env" >&2; exit 2; }
  set -a
  . "$r2env"
  set +a
  export STORE R2_PREFIX="${R2_PREFIX:-bench/$(date -u +%Y%m%d-%H%M%S)-$mode-$PORT_BASE}"
  echo "STORE=r2: prefix $R2_PREFIX (delete it afterwards: ./r2-clean.sh $R2_PREFIX)"
  docker compose up -d --wait ref-a ref-b
else
  docker compose up -d --wait ref-a ref-b minio
  docker compose run --rm minio-init >/dev/null
fi

# Docker on Linux has no route from a container to the host's 127.0.0.1
# (Docker Desktop does): lib/hostbridge.mjs listens on the bridge gateway
if [ "$(uname -s)" = Linux ]; then
  gw="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
  node lib/hostbridge.mjs "$gw" "$FWD_FIRST" "$FWD_LAST" "$REF_A_PORT" "$REF_B_PORT" &
  bridge=$!
fi

mkdir -p "$OUT"
case "$mode" in
  e2e) node e2e.mjs "$@" ;;
  sim) node sim.mjs "$@" ;;
  fault) FAULTS=1 node sim.mjs "$@" ;;
  cost) node cost.mjs "$@" ;;
  boards) node boards/scenarios.mjs "$@" ;;
  boards-ui | boards-prod)
    if [ "$mode" = boards-ui ]; then runner=boards/ui.mjs seed="${LOCAL_DIR}seed-accounts.json" check=ui.mjs shots="${OUT}boards-ui/"
    else runner=boards/prod.mjs seed="${LOCAL_DIR}prod-seed.json" check=prod.mjs shots="${OUT}boards-prod/"; fi
    if [ "${UI_E2E:-}" = 1 ]; then
      rm -f "$seed"
      node "$runner" &
      ui=$!
      until [ -f "$seed" ]; do kill -0 "$ui" 2>/dev/null || exit 1; sleep 1; done
      rc=0
      (cd "$boards/e2e" && SEED_FILE="$seed" SHOTS="$shots" node "$check") || rc=$?
      exit "$rc"
    fi
    START_SERVER=1 node "$runner"
    ;;
  *) echo "unknown mode $mode (e2e | sim | fault | cost | boards | boards-ui | boards-prod)" >&2; exit 2 ;;
esac
