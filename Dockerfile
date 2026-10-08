# syntax=docker/dockerfile:1.7
# Production vlpds image: release builds of the vlpds (and vlpds-bucket-probe)
# binaries and the web UI (ui/, built with node; served from VLPDS_UI_DIR) on a
# slim non-root runtime. The two builds are independent stages, so a UI- or
# docs-only change reuses the cached binary and rebuilds only the last layer.
#
# This is the reproducible build: CI's image workflow and anyone with docker
# build from it. The monorepo's `just image-push` makes the same image without
# Docker, putting a cross-compiled binary and the UI on the runtime-base stage.
#
#   docker build -t vlpds:local .            (or: just docker-build; in the
#                                            monorepo build/context.sh makes .)
#   docker run -p 2583:2583 -e VLPDS_S3_ENDPOINT=... -e VLPDS_JWT_SECRET=... \
#     -e VLPDS_ADMIN_TOKEN=... -e VLPDS_INTERNAL_TOKEN=... vlpds:local
#
# Configuration is all VLPDS_* env vars (see `vlpds --help`). Prometheus
# metrics are served at /metrics on VLPDS_METRICS_LISTEN only (default
# 127.0.0.1:9583, i.e. inside the container: set 0.0.0.0:9583 and publish it
# on a private address to scrape it). Thread pools default to
# the container's CPUs (cgroup quota aware): --io-threads = cores, --workers =
# cores/2. vlpds raises its soft open-files limit to the hard limit at startup
# (docker run --ulimit nofile=1048576:1048576 sets the hard limit).

# --- web UI -----------------------------------------------------------------
# the UI build is the same on every platform, so it runs natively
FROM --platform=$BUILDPLATFORM node:26-bookworm-slim AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY ui/ ./
# the docs site (/docs) is rendered from ../docs at build time
COPY docs/ /src/docs/
RUN npm run build

# --- rust release build -----------------------------------------------------
# Runs on the build machine and cross-compiles for the target platform:
# emulating the whole compile (an amd64 image built on an arm64 Mac) is many
# times slower than compiling natively for another target.
FROM --platform=$BUILDPLATFORM rust:1.99.0-bookworm AS build
ARG TARGETARCH
ARG BUILDARCH

# cmake/clang: aws-lc-sys (rustls) and the vendored libsecp256k1 / jemalloc C
# builds; a cross build adds the target's gcc and libc
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang \
    && if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
         case "$TARGETARCH" in \
           amd64) apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross ;; \
           arm64) apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
           *) echo "no cross toolchain for $TARGETARCH" >&2; exit 1 ;; \
         esac; \
       fi \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY rust-toolchain.toml ./
# installs the pinned toolchain if the base image's differs, plus the target
RUN case "$TARGETARCH" in amd64) t=x86_64-unknown-linux-gnu ;; arm64) t=aarch64-unknown-linux-gnu ;; esac \
    && rustup show active-toolchain && rustup target add "$t" && echo "$t" > /rust-target
COPY Cargo.toml Cargo.lock ./
# the shared vlsync crates (build/context.sh adds the monorepo's)
COPY vlsync/Cargo.toml ./vlsync/
COPY vlsync/crates ./vlsync/crates
COPY src ./src
COPY lexicons ./lexicons
# embedded by `vlpds dashboards` (src/cli/dashboards.rs)
COPY bench/obs/grafana/dashboards ./bench/obs/grafana/dashboards
# the manifest declares the test binary; it is never built here
RUN mkdir -p tests/all && touch tests/all/main.rs
# Extra cargo features, e.g. --build-arg VLPDS_FEATURES=profiling for
# --pyroscope-url (continuous CPU profiles).
ARG VLPDS_FEATURES=""
# no debug info in the image (Cargo.toml keeps debug = 1 for local profiling;
# with debug = 0 cargo also strips std's): ~half the image. Symbols stay, so
# panics and backtraces still name functions.
ENV CARGO_PROFILE_RELEASE_DEBUG=0
# Unset builds with every core; benchbox-image.sh lowers it while the batch
# pipeline runs.
ARG CARGO_BUILD_JOBS
# Both binaries in one invocation: the probe reuses the crate's compiled lib
# and its LTO link runs beside vlpds's (+3 s; its own profile recompiled
# the lib after the vlpds build, +40-55 s).
# arm64: jemalloc aborts on a kernel page larger than the one it was built
# for, and arm64 kernels use 4K, 16K (Raspberry Pi 5, Asahi) or 64K pages.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    t=$(cat /rust-target) \
    && if [ "$TARGETARCH" = arm64 ]; then export JEMALLOC_SYS_WITH_LG_PAGE=16; fi \
    && if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
         gnu=$(echo "$t" | sed 's/-unknown-linux-gnu//')-linux-gnu; T=$(echo "$t" | tr a-z- A-Z_); \
         export "CARGO_TARGET_${T}_LINKER=$gnu-gcc" "CC_$(echo "$t" | tr - _)=$gnu-gcc" \
                "CXX_$(echo "$t" | tr - _)=$gnu-g++" "AR_$(echo "$t" | tr - _)=$gnu-ar"; \
       fi \
    && cargo build --release --locked --target "$t" --bin vlpds --bin vlpds-bucket-probe ${VLPDS_FEATURES:+--features "$VLPDS_FEATURES"} \
    && mkdir -p /out \
    && cp target/$t/release/vlpds target/$t/release/vlpds-bucket-probe /out/ \
    && if [ "$TARGETARCH" = "$BUILDARCH" ]; then /out/vlpds --help >/dev/null && /out/vlpds-bucket-probe --help >/dev/null; fi

# --- runtime ----------------------------------------------------------------
# runtime-base is everything but the binaries, the UI and the commit: the base
# build/oci-image.sh puts its layers on (pinned in build/oci-base), so the image
# config lives here for both builds.
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 vlpds \
    && useradd --system --uid 10001 --gid vlpds --home-dir /var/lib/vlpds --create-home vlpds
USER vlpds:vlpds
WORKDIR /var/lib/vlpds
ENV VLPDS_LISTEN=0.0.0.0:2583 \
    VLPDS_UI_DIR=/usr/share/vlpds/ui \
    RUST_LOG=info
# 2583: XRPC, web UI, /internal (cluster: private network only)
# 9583: /metrics (Prometheus) when VLPDS_METRICS_LISTEN=0.0.0.0:9583
EXPOSE 2583
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=3 \
    CMD curl -sf http://127.0.0.1:2583/xrpc/_health || exit 1
# tini forwards SIGTERM so vlpds drains and releases its shards gracefully
ENTRYPOINT ["/usr/bin/tini", "--", "vlpds"]

FROM runtime-base AS runtime
# vlpds-bucket-probe: the bucket pre-flight (DESIGN.md "Choosing a bucket"),
# run with --entrypoint from the node's own env
COPY --from=build /out/vlpds /out/vlpds-bucket-probe /usr/local/bin/
# Last: the layer a UI-only change replaces (and pushes).
COPY --from=ui /src/ui/dist /usr/share/vlpds/ui
# vlpds_build_info's rev label (the build context has no .git to describe),
# read at run time: as a build-time env of the cargo step it would rebuild
# the binary on every commit.
ARG VLPDS_GIT_REV=""
ENV VLPDS_GIT_REV=${VLPDS_GIT_REV}
