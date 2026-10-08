# vlpds: atproto PDS on object storage. The web UI (ui/, React + Vite) is
# built into ui/dist, which vlpds reads at startup (--ui-dir; src/xrpc/webui.rs).

# Site-specific recipes (a dedicated bench host), absent in a plain checkout
import? 'bench/benchbox/recipes.just'

target_dir := env_var_or_default("CARGO_TARGET_DIR", "target")

# Build the web UI into ui/dist (served from the next vlpds start)
ui:
    cd ui && npm install --no-audit --no-fund && npm run build

# Validate the docs site (docs/*.md: front matter, heroes, diagrams, links) and print its nav
docs-check:
    cd ui && npm install --no-audit --no-fund && npm run check-docs

# Vite dev server on :5620, proxying /xrpc, /oauth, /metrics to a local vlpds (VLPDS_URL, default http://127.0.0.1:2620)
dev-ui url="http://127.0.0.1:2620":
    cd ui && npm install --no-audit --no-fund && VLPDS_URL={{url}} npm run dev

# Build the UI, then the vlpds and loadgen binaries (dev-release profile)
build: ui
    cargo build --profile dev-release --bins

# Release build, and the UI it serves from ui/dist
build-release: ui
    cargo build --release --bins

# An in-memory dev server with the UI on :2620 (admin token: dev-admin-token)
dev: build
    {{target_dir}}/dev-release/vlpds --memory --listen 127.0.0.1:2620 --public-url http://127.0.0.1:2620 --dev-mode --no-rate-limits

# Seed a running dev server with accounts and records (password: hunter2)
seed accounts="3" records="200":
    {{target_dir}}/dev-release/loadgen --host http://127.0.0.1:2620 setup --accounts {{accounts}} --records {{records}}

test *args:
    cargo test {{args}}

# Two-build HA scenarios (bench/ha/upgrade.sh: builds the previous release + this tree, plain and
# with the test feature level, then runs hactl.py upgrade-*). `--minio` first = throwaway MinIO container
upgrade-ha *args:
    bench/ha/upgrade.sh {{args}}

# Rolling-upgrade CI gate (DESIGN.md "Tests and CI"): format fixtures + MANIFEST freeze, the
# level-gating test with the test feature level, and one two-build scenario on a throwaway MinIO
upgrade-ci scenario="upgrade-rolling":
    cargo test --test all formats::
    cargo test --features test-level --test level_gating
    VLPDS_HA_S3=127.0.0.1:9260 bench/ha/upgrade.sh --minio {{scenario}}

# bench/ha/hactl.py's log segment parser against the golden segments this build writes
ha-parser-test:
    python3 -m unittest bench/ha/test_hactl.py

# Local MinIO (build/docker-compose.yml) on :9000 (console :9001), with the `vlpds` bucket created
minio:
    docker compose -f build/docker-compose.yml up -d --build --wait minio
    docker compose -f build/docker-compose.yml run --rm minio-init

# Stop the local MinIO (keeps its volume; `docker compose -f build/docker-compose.yml down -v` wipes it)
minio-down:
    docker compose -f build/docker-compose.yml down

# Vault Transit KEK tests (tests/all/vault_transit.rs) against throwaway Vault dev servers on 127.0.0.1:<port>
# (http) and <port+1> (TLS on a private CA), removed afterwards. image=openbao/openbao:latest runs them on
# OpenBao; another port lets two runs share a host.
vault-test image="hashicorp/vault:latest" port="18200":
    #!/usr/bin/env bash
    set -euo pipefail
    name="vlpds-vault-test-{{port}}-$$"
    tls_port=$(({{port}} + 1))
    tls=$(mktemp -d "${TMPDIR:-/tmp}/vlpds-vault-tls.XXXXXX")
    chmod 777 "$tls"
    trap 'docker rm -f "$name" "$name-tls" >/dev/null 2>&1; rm -rf "$tls"' EXIT
    # host.docker.internal: the Kubernetes test's TokenReview mock runs in the test process
    docker run -d --name "$name" -p "127.0.0.1:{{port}}:8200" --add-host=host.docker.internal:host-gateway \
        -e SKIP_SETCAP=1 {{image}} server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200 >/dev/null
    docker run -d --name "$name-tls" -p "127.0.0.1:$tls_port:8200" -v "$tls:/tls" -e SKIP_SETCAP=1 {{image}} \
        server -dev-tls -dev-tls-cert-dir=/tls -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200 >/dev/null
    for _ in $(seq 100); do curl -sf "http://127.0.0.1:{{port}}/v1/sys/health" >/dev/null && break; sleep 0.2; done
    for _ in $(seq 100); do [ -f "$tls/vault-ca.pem" ] && curl -sf --cacert "$tls/vault-ca.pem" "https://127.0.0.1:$tls_port/v1/sys/health" >/dev/null && break; sleep 0.2; done
    VLPDS_TEST_VAULT_ADDR="http://127.0.0.1:{{port}}" VLPDS_TEST_VAULT_TOKEN=root \
        VLPDS_TEST_VAULT_TLS_ADDR="https://127.0.0.1:$tls_port" VLPDS_TEST_VAULT_TLS_CA="$tls/vault-ca.pem" \
        cargo test --test all vault_transit::

# bench/step.sh writes ./target/release whatever CARGO_TARGET_DIR says; env ACCOUNTS, RECORDS, DURATION, OUT.
# One benchmark step on a fresh RAM-backed MinIO: just bench <name> <rate> [hot_rate] [inject_put_ms] [vlpds args...]
bench name rate *args:
    docker compose -f build/docker-compose.yml build minio
    CARGO_TARGET_DIR=target cargo build --release --bins
    bench/step.sh {{name}} {{rate}} {{args}}

# Spaces sync micro-bench, in process and alone (bench/results/spaces-sync.md; env SPACES_BENCH_*)
spaces-microbench *args:
    cargo test --profile dev-release --features bench-jemalloc --test all spaces_side::bench::spaces_microbench {{args}} -- --ignored --nocapture --test-threads=1

# Account migration e2e (bench/migrate/README.md): local PLC, reference PDS and mail catcher in docker,
# a local vlpds, then /migrate driven headlessly for several accounts and both sides verified (KEEP=1 leaves it up)
migrate-e2e:
    bench/migrate/run.sh

# The Spaces step of /migrate (bench/migrate/README.md "Spaces"): space repos move from the reference PDS (Spaces
# alpha) and from a second vlpds, through the page's OAuth sign-ins, and verify on vlpds with @atproto/space
migrate-spaces-e2e:
    bench/migrate/spaces.sh

# Passkeys in headless Chromium (bench/passkeys/README.md): a CDP virtual authenticator registers a passkey and
# signs in with it (second step, passwordless) on a local in-memory vlpds; screenshots in bench/passkeys/out/shots
passkeys-e2e:
    bench/passkeys/run.sh

# The account page's Spaces tab in headless Chromium (bench/account-spaces/README.md): connect, the lists, the owner
# grant, members, deleting a space and revocation on a local vlpds; screenshots in bench/account-spaces/out/shots
account-spaces-e2e:
    bench/account-spaces/run.sh

# Spaces e2e matrix (bench/spaces/README.md): local PLC, two reference PDSes at the Spaces alpha and MinIO in
# docker, vlpds from this checkout; each role on vlpds or a reference PDS, pass / fail / not impl. per step
# (configs: ref-ref vlpds-authority ref-authority vlpds-only; default all; KEEP=1 leaves it up, CLUSTER=1 for 3 nodes)
spaces-e2e *configs:
    bench/spaces/run.sh e2e {{configs}}

# Randomized Spaces workload with invariants (no lost acked write, syncers converge, LtHash, spaceRev order);
# scale: small | medium | large | <ops>; HOSTS=ref-a,ref-b runs it all-ref
spaces-sim seed="1" scale="small":
    bench/spaces/run.sh sim {{seed}} {{scale}}

# The sim under faults: notify drops/delays/duplicates on both hops, vlpds kill -9 and SIGTERM mid-burst
# (CLUSTER=1: a node dies, its shards move), syncer restarts; the same invariants after recovery
spaces-fault seed="1" scale="small":
    bench/spaces/run.sh fault {{seed}} {{scale}}

# Spaces sync cost against the targets: no-op poll and delta pull server time, notify latency, bucket ops per
# space write, public commit p99 under a space write load, warm sequential write latency with vlpds's commit
# stages (host: vlpds | ref-a; steps: a comma list, e.g. `just spaces-cost vlpds warm-writes`)
spaces-cost host="vlpds" steps="":
    bench/spaces/run.sh cost {{host}} {{steps}}

# boards (packages/boards), a Reddit-like private board on Spaces (bench/spaces/boards/README.md): user stories against
# its appview's API and direct space reads (configs: all-vlpds vlpds-owner ref-owner; default all; CLUSTER=1 adds the kill -9 story)
spaces-boards *configs:
    bench/spaces/run.sh boards {{configs}}

# The boards web UI on the local stack until Ctrl-C: vlpds (--spaces --dev-mode), the appview and UI on
# http://127.0.0.1:2888, a seeded demo board (handles printed; passwords in bench/spaces/boards/.local/);
# UI_E2E=1 instead runs the headless two-person check (screenshots in bench/spaces/out/boards-ui/) and exits
spaces-boards-ui:
    bench/spaces/run.sh boards-ui

# The boards production server (as deployed at boards.example.com) on the local stack until Ctrl-C: confidential OAuth
# at http://boards.localhost:2889 against vlpds, notifies to did:web:127.0.0.1%3A2889, a seeded board; UI_E2E=1 instead
# runs the headless sign-in / post / invite / remove / restart check (screenshots in bench/spaces/out/boards-prod/)
spaces-boards-prod:
    bench/spaces/run.sh boards-prod

# The WebAuthn verifier (src/webauthn.rs) against 1Password's passkey-rs; its own crate, since passkey-types
# turns on serde_json's preserve_order, which would change every vlpds test build
passkey-differential:
    cargo test --manifest-path passkey-differential/Cargo.toml

# Build the Go sync 1.1 firehose checker and run it against a vlpds (extra flags e.g. -cursor 0 -strict)
checker host="http://127.0.0.1:2620" *args:
    cd checker && go build -o checker . && ./checker -host {{host}} {{args}}

# Build the Rust sync 1.1 checker (checker-rs, on shrike) and run it against a vlpds (extra flags e.g. -cursor 0 -strict)
checker-rs host="http://127.0.0.1:2620" *args:
    cd checker-rs && cargo run --release --quiet -- -host {{host}} {{args}}

# Production image (Dockerfile: UI build, release build, slim non-root runtime)
docker-build tag="vlpds:local":
    if [ -f ../../scripts/oci/lib.sh ]; then ctx=$(mktemp -d); build/context.sh "$ctx"; else ctx=.; fi; docker build -t {{tag}} "$ctx"

# Build the production amd64 image from the committed tree and push it; prints the ref. In the
# monorepo: zigbuild + crane onto the pinned base, no Docker build (build/oci-image.sh); elsewhere
# the Dockerfile (build/mac-image.sh). FEATURES=profiling, PUSH=0 to only build it.
image-push tag=`../../scripts/vcs.sh short 2>/dev/null || git rev-parse --short=12 HEAD`:
    if [ -f ../../scripts/oci/lib.sh ]; then build/oci-image.sh {{tag}}; else build/mac-image.sh {{tag}}; fi

alias docker-push := image-push

# Rebuild the runtime base (Dockerfile's runtime-base stage) and pin its digest in build/oci-base
image-base:
    build/oci-image.sh base

# The same image from the Dockerfile with docker buildx (build/mac-image.sh; PUSH=0 to only load it)
docker-push-buildx tag=`../../scripts/vcs.sh short 2>/dev/null || git rev-parse --short=12 HEAD`:
    build/mac-image.sh {{tag}}

# Observability stack for load tests (bench/obs/README.md): Prometheus (1 s scrapes) :9090,
# Grafana (vlpds dashboard, anonymous admin) :3300, Pyroscope :4040, all on 127.0.0.1
obs-up:
    python3 bench/obs/minio-token.py
    docker compose -f bench/obs/docker-compose.yml up -d --wait
    @echo "grafana http://127.0.0.1:3300/d/vlpds  prometheus http://127.0.0.1:9090  pyroscope http://127.0.0.1:4040"

# Stop the observability stack (keeps its data; `docker compose -f bench/obs/docker-compose.yml down -v` wipes it)
obs-down:
    docker compose -f bench/obs/docker-compose.yml down

# Regenerate the vlpds Grafana dashboards (operator `vlpds` + `vlpds-internals`) (--check: exit 1 if any is stale)
dashboards *args:
    python3 bench/obs/grafana/gen_dashboard.py {{args}}

# CPU profile of a running vlpds (built with --features profiling): top functions by self and cumulative time
profile host="127.0.0.1:2583" seconds="10" *args:
    bench/obs/profile.sh {{args}} {{host}} {{seconds}}
