# vlpds HA end-to-end results: per-node-log design

These results are for the **per-node-log design**:
- 65,536 hash slots grouped into `--shards N` (64 here, plus 256 for the 5-node runs);
- one log per node incarnation;
- node leases;
- CAS shard assignments;
- fencing of dead logs.

The previous baseline, on the per-partition-lease design, is summarised under "Comparison with the old baseline" below, with its bug list B1–B9 and each bug's status today.

- **Run IDs:** `final` is the whole native matrix. `final2` and `final3` re-run the scenarios affected by the last fix (the log-stream idle timeout). `final-rep` holds repeats. `final-256` and `final3-256` are the 256-shard runs. `final2-ctr` (and `final-ctr`) are the containers. Outputs are in `bench/ha/out/<run>/<scenario>/`.
- **Setup:** native processes on one Mac (14 cores), with native MinIO on 127.0.0.1:9200.
- **Lease TTL:** 3 s, so renew and skew margin are both 600 ms.
- **Load:** 150 creates/s through **every** node, using one `loadgen` per node over all accounts, so most writes are forwarded.
- **Probes:** 32 probe writers at 10 Hz, one per sampled shard, sent through n1.
- **Node flags:** `--shards N --no-rate-limits --dev-mode --workers 2 --io-threads 3`.
- **Host load:** the host was shared with other agents' builds and benchmarks. The load average was 25–67 during `final` and 8–25 later. Absolute latencies are therefore pessimistic, but failover and outage times are dominated by TTL and skew.
- **Binaries:** every run used binaries built from the tree with all of the HA fixes below. The exception is the final idle-timeout fix in `remote.rs`. The `final` native matrix predates it, so every scenario that could involve a peer stream stall was re-run after it (`final2`, `final3`, `final2-ctr`).

## How to run

```
bench/ha/run_all.sh                    # whole matrix (native + containers); builds everything first
bench/ha/run_all.sh native             # native-process scenarios only
bench/ha/run_all.sh ctr                # container scenarios (docker network disconnect, docker pause, libfaketime)
bench/ha/run_all.sh kill9-1of3 zombie  # named scenarios
SKIP_BUILD=1 HA_RUN_ID=x VLPDS_HA_PARTITIONS=256 bench/ha/run_all.sh baseline-5 kill9-2of5
python3 bench/ha/hactl.py list         # scenario catalogue
```

**Knobs** (environment variables):

| Variable | Default | What it sets |
|---|---|---|
| `VLPDS_HA_NODE_ARGS` | see below | Node flag template. Placeholders: `{listen} {url} {peer_listen} {advertise} {tls_dir} {s3} {prefix} {id} {ttl_ms} {partitions}`. |
| `VLPDS_HA_PARTITIONS` | 64 | Shard count: passed as `--shards`, and used for the probe shard mapping. |
| `VLPDS_HA_TTL_MS` | 3000 | Lease TTL. |
| `VLPDS_HA_RATE` | 150 | Writes/s per loadgen. |
| `VLPDS_HA_PROBES` | 32 | Probe writers, each on a shard sampled at random with a fixed seed. |
| `VLPDS_HA_INJECT_PUT_MS` | 25 | Injected median latency on every node's segment PUTs (`--inject-put-ms`), so PUTs overlap. 0 turns it off. |
| `VLPDS_HA_LOG_INFLIGHT` | 4 | Segment PUTs in flight per node log (`--log-inflight`). |
| `VLPDS_HA_CLEANUP` | 1 | Delete the scenario's bucket prefix once its results are recorded. Deletion runs through `mc` in `vlpds-minio:local`. |
| `VLPDS_HA_RETENTION_S` | 45 | `--log-retention` of the `retention-*` scenarios, in seconds. |
| `VLPDS_HA_INTERNAL_TOKEN` | `dev-internal-token` | The `x-vlpds-internal` token for the harness's status calls. |
| `VLPDS_HA_PEER_TLS_DIR` | `bench/ha/out/peer-tls` | The nodes' shared dev-mode `--peer-tls-dir`: the first node creates the cluster CA, each node its certificate; the harness reads node status (`/internal/v1/cluster`) on each node's mTLS peer listener with that node's certificate. |
| `VLPDS_HA_BASE_PORT`, `VLPDS_BIN_DIR`, `VLPDS_HA_S3`, `VLPDS_HA_IMAGE`, `VLPDS_HA_DOCKER_S3` | | As before. |

The default node template is:

```
--listen {listen} --public-url {url} --peer-listen {peer_listen} --advertise-url {advertise} --peer-tls-dir {tls_dir}
--s3-endpoint {s3} --prefix {prefix} --node-id {id} --lease-ttl-ms {ttl_ms} --shards {partitions} --no-rate-limits
--dev-mode --workers 2 --io-threads 3 --firehose-ring-mb 256
```

Peers talk mTLS only (DESIGN.md "Exposure"): node `i`'s peer
listener is on `BASE_PORT+800+i`, behind its peer faultproxy (`+200+i`, the
advertised `https://` address); containers publish it on `+1400+i`.
`bench/ha/upgrade.sh`'s default previous release is the first build with
40-byte repo stats rows (2026-10-06): older builds can't read them, so the
upgrade from one of those is one-way (docs/operations/upgrades.md).

**Harness changes for the new design:**
- **Shard mapping:** the probe mapping now follows `src/slots.rs`: `(top 16 bits of sha256(did)) * N / 65536`.
- **`--shards` and `--no-rate-limits`** replace the old flags.
- **Probe sampling:** probe shards are sampled across all nodes. Before, they were the first N in account order, which meant only n1 and n2's shards.
- **Outage metric:** the per-shard outage is now the longest *contiguous* window. It no longer spans from a kill to the rebalance blip at a later restart.
- **Late joiners:** a node that joined mid-run was not judged on cursor-replay completeness. Since the O1 fix every survivor is judged.
- **Replay window:** the replay window is 30 s when a rejoined node backfills from S3, versus 8 s otherwise.
- **New checks:**
  - **History diff:** a cross-node comparison of merged history, over (seq, did, rev) sequences. It covers both the cursor replays and the live audits over their common range.
  - **Exit codes:** expected exit codes, e.g. a zombie must exit 3 or 5.
  - **Unexpected exits:** a scenario fails on any unexpected exit (used by `grow-1-to-3`).
- **Diagnostics added to the code:**
  - a `checkpoint start` log line, which `kill9-mid-checkpoint` keys off;
  - `acquired shards` and `releasing extra shards` log lines;
  - a firehose-merger warning for late events (an event at or below the emitted watermark). It never fired in any run.

### What each scenario checks

These are as before:
1. **Acked writes:** every create acknowledged by any loadgen or probe is readable (`loadgen verify`).
2. **Checker:** the sync-1.1 checker reports `-strict` PASS on n1. Some scenarios also run a second, cursor-based checker.
3. **Live firehose audit:** for every node that stayed up, every acked create is on its live firehose.
4. **Replay audit:** a cursor replay from before the run on each survivor is complete.
5. **Merged-history agreement (new):** every node that stayed up emits the identical commit sequence, both in the replay and in the live audit.
6. **Availability:** probe outage windows. A probe is bad if it failed or took more than 2 s.
7. **Exit codes:** these are recorded, and expected codes are checked where a scenario sets them.

## Two-build upgrade scenarios (`upgrade-*`, 2026-10-02): rolling upgrades phase 2

DESIGN.md "Rolling upgrades and format versioning". `bench/ha/upgrade.sh [--minio] [scenario...]` builds into
`target/upgrade/` the **previous release** (`VLPDS_PREV_REV`, else the newest `vlpds-v*` tag, else the pinned
`a9d1df7`, the first build with feature levels; cached per rev) and **this tree**, plain (`new`, levels 1..=1) and with
the test-only feature level (`new-tl`, `--features test-level`, levels 1..=2: segment magic `VLSEGT1` with a body
checksum, `retain/` reports with `min_seg_format`). Native processes, 3 nodes, 64 shards, TTL 3 s, 150 writes/s per
node + probes, checker on n1, on a throwaway MinIO container (`--minio`, tmpfs). Besides `judge`, each run checks the
finalize responses, the segment magics in the bucket right before the finalize and at the end (8-byte range GETs over
`log/`), that refused nodes exited 7 (and an extra refused node left no lease, writer claim or log), and that no node
exited otherwise. Previous = a9d1df7, current = a9d1df7 + this change (uncommitted tree).

| Scenario | Verdict | Acked / lost | Checker | Bucket before finalize → end | Notes |
|---|---|---|---|---|---|
| `upgrade-rolling` (old ×3 → new-tl one by one at 8/18/28 s, finalize at 36 s) | PASS | 38,185 / 0 | PASS (+ cursor checker) | VLSEG06 3041 → VLSEG06 3765 + VLSEGT1 1077 | finalize 200 (active 2); replay + live audits complete, histories agree; probe outage 0.9 s total |
| `upgrade-rolling-l1` (old ×3 → new, the real release path) | PASS | 34,244 / 0 | PASS | VLSEG06 only | finalize to 2: 400 "this node runs levels 1..=1" |
| `upgrade-rollback` (2 of 3 → new-tl, finalize, both back to old) | PASS | 38,213 / 0 | PASS | VLSEG06 only | finalize 409 `IncompatibleNodes` naming n1 (old, live) |
| `upgrade-old-refused` (all → new-tl, finalize; extra old n4; n2 → old; n2 → new-tl) | PASS | 37,385 / 0 | PASS | VLSEG06 1743 → + VLSEGT1 2312 | n4 exit 7 at its startup gate ("cluster level 2 is outside this build's levels 1..=1"), no objects left; n2 on old exit 7 in 0.8 s, back on new-tl fine |
| `upgrade-raise-race`, old n4 started 300 ms / 20 ms before the finalize | PASS ×2 | 30,456 / 0, 30,910 / 0 | PASS | → + VLSEGT1 | raise 409 (n4's lease was listed), n4 kept running; then n4 stopped and the finalize went through |
| `upgrade-raise-race`, finalize started 5 ms before old n4 | PASS | 30,680 / 0 | PASS | → + VLSEGT1 1348 | raise 200, n4 exit 7 |

One run each (the race delay is random from {-50, -5, 20, 150} ms unless `VLPDS_HA_RACE_DELAY_MS` is set). The first
`upgrade-rollback` run failed in the harness, not the product: the finalize asked the first live node (an old build)
for the target level and so requested level 1; the finalize now asks the node it is sent through. The old build reported
`rev unknown` (built from a `git archive`, no `.git`); `upgrade.sh` now sets `VLPDS_GIT_REV` for it. Wall time: ~2 min per scenario; the three cold builds ~15 min.

## Log retention under kill -9 (`ret1`–`ret3`): fa0975c, `retention-kill9`

New scenario `retention-kill9`: 3 nodes with `--log-retention 45s`
(`VLPDS_HA_RETENTION_S`) under the usual load (150 writes/s per node, 32
probes) for 240 s. n2 is kill -9'd at 75 s and restarted at 135 s. Passes run
every 60 s per node (`DEFAULT_INTERVAL`), so each node makes 3–4 passes and the
leader prunes n2's dead log mid-run. The generic post-run replay from before
the run is off (`replay=False`): with a 45 s window it is OutdatedCursor by
design. The scenario checks instead:

- **Acked writes:** the usual `loadgen verify`, checker `-strict` on n1, and
  complete live audits on n1 and n3.
- **No replay needed a pruned segment:** no node log has an open, backfill,
  dead-log drain, follower-skip ("log pruned ahead of its follower"),
  retained-floor, retention-pass, close, spill read-back or late-event
  error. `vlpds_retention_ticks_total{result="error"}` is 0 on every node.
- **Dead-log pruning down to the fence:** within 150 s after the load, a
  survivor logs "dead log retired". The dead log in S3 is exactly one
  object, the fence. Its `retain/` report is gone. `audit_dead_log` passes
  (fence at the first hole, every span ends there, fencers agree).
- **Live logs pruned too:** `vlpds_retention_deleted_objects_total{log="own"}`
  is above 0.
- **Old cursor:** at 200 s an `fhaudit` subscribes on every node (n2
  restarted) from a cursor taken at 5 s. Each must get `#info OutdatedCursor`
  first. It must then get exactly n1's history from its first event to the
  end of the run (it stays live), skipping nothing above the retained floor
  read after it subscribed. `fhaudit` now records `#info` names
  (`info_names`).
- **Restarted node clean:** n2's live audit attached at restart matches n1's
  history over the common range. Exit codes are n2 `[-9]` only. The final
  split is 22/20/22.

Binaries were built from a `git archive` of fa0975c plus this lane's
`caches.rs` / `xrpc/server.rs` change (the working tree was mid-edit by
the shard split lane) and copied to a scratch dir. MinIO was shared with
another agent's capacity runs (`dry1m`).

| Run | Verdict | Acked / lost | Dead log after | Retired (after kill) | Objects deleted own (n1/n2/n3), dead | Old-cursor subscribers | Probe windows (s) |
|---|---|---|---|---|---|---|---|
| ret1 | PASS | 173,660 / 0 | fence 2374 only | +103 s (n3) | 4086 / 422 / 4047, 2008 | 3 × OutdatedCursor, 70,761 commits = n1, 0 skipped | 75.0–79.5, 136.2–137.0 |
| ret2 | PASS | 172,785 / 0 | fence 2321 only | +102 s (n1) | 4073 / 443 / 4086, 1943 | 3 × OutdatedCursor, 69,758 = n1, 0 skipped | 75.0–79.8, 136.7–137.0 |
| ret3 | PASS | 166,045 / 0 | fence 2315 only | +104 s (n3) | 3981 / 419 / 3935, 2315 | 3 × OutdatedCursor, 70,525 = n1, 0 skipped | **75.0–112.0**, 136.4–136.7 |

(n2's own count is from its second incarnation.)

**Result: every check passes in all 3 runs.**
- No acked write was lost.
- No replay, backfill or follower error appeared.
- Each dead log ended as its fence alone, retired about 100 s after the kill
  (window 45 s, plus the wait for the next pass).
- The old-cursor subscribers continued from the floor (the first event right
  above it) through the live tail.
- No retention bug was found, and `src/retention.rs` is unchanged.

**ret3's 37 s outage was not retention.** At 21:53:28, 5 s before the first
retention pass and 24 s before the kill, one S3 request on n1 and one on n3
stopped getting answers from MinIO. Which requests they were isn't logged. Each timed out after the
store's 30 s request timeout, at 21:53:58. A second request, started at
21:53:34, timed out at 21:54:04. The faultproxy saw the client cancel; MinIO
never answered. Segment PUTs kept flowing the whole time (commit p50 ~48 ms).

Both survivors fenced n2's log and took over only at 21:54:28: 36 s after
the kill, not ~4 s. Their first retention passes finished at the same moment
(21:54:25 and 21:54:28). This fits the cluster step, one sequential loop
(the `cluster.rs` step task), sitting in a hung request and its retry.
- **Cause:** the stall is attributed to the shared MinIO (another agent's
  capacity run was writing `dry1m` at the time). The same passes took about
  0.2 s in ret1 and ret2.
- **Finding for the cluster lane:** an S3 call in the step is bounded only by
  the store-wide 30 s timeout plus retries, so one stuck control-plane
  request delays failover by 30–60 s. A per-call deadline on the step's
  reads (a few × TTL), or a step that doesn't block takeover detection on
  one request, would bound it.
- **Status:** not fixed. `cluster.rs` belongs to the shard-split lane.

## Pipelined segment PUTs round (`k2*`, `k3*` runs): commit 2e64422, K = 4

This round validates 2e64422 (K segment PUTs in flight per node log, VLSEG03
`prefix_end`, the hole rule and fence at the first hole, handback to a joiner
with nudges and draining leases).

- **Binaries:** built from a clean export of 2e64422 (`git archive`) plus two
  test-only CLI knobs: `--max-segment-mb` takes fractions, and
  `--firehose-merge-queue-mb` sets the merger's spill budget. Wave C
  (748039d) has both. The working tree was being edited by other agents during
  the run, and one of them rebuilt `target/agent-tests` in the middle of a
  first pass (`k1`, discarded). Every run here used the isolated binaries.
  `k3*` adds the N10 fix below.
- **Setup:** the same as O3, plus 25 ms injected median latency on every
  segment PUT (`--inject-put-ms 25`, lognormal sigma 0.5; the harness default
  is now `VLPDS_HA_INJECT_PUT_MS=25`) and `--log-inflight 4`
  (`VLPDS_HA_LOG_INFLIGHT`).
  - The container image is rebuilt from the same tree.
  - Another agent's storage benchmark ran on the host the whole time, using
    about 1.2 cores. Load average was 7–14.
- **New harness pieces:**
  - a SigV4 S3 client (`s3_list` / `s3_get`) and a VLSEG03 parser;
  - `audit_dead_log`;
  - `kill_on_hole`, which polls a node's log LIST every 5 ms and kill -9s it
    the moment ordinal n is missing while a later one has landed;
  - `stop_with_puts_held`;
  - handoff timing from the node logs;
  - PUT/hedge counters;
  - a Prometheus query.

**Result: after the N10 fix, every scenario passes.**
- On 2e64422 itself, 37 of 39 runs passed. The two failures, `s3-slow-all` and
  `rolling-restart` at 256 shards, were both bug N10: duplicate firehose
  events on nodes that had restarted.
- No acked write was lost in any run.
- Across the K scenarios there were 6 kill -9 / zombie dead logs. In every one,
  the fence sat at the first hole and the garbage past it never reached a
  firehose.

### Native, 64 shards (`k2`, 2e64422)

| Scenario | Verdict | Acked / lost | Max shard outage (o3) | Exits | Notes |
|---|---|---|---|---|---|
| baseline-2 | PASS | 19342 / **0** | 0.0 s (0.0) | – |  |
| baseline-3 | PASS | 23967 / **0** | 0.0 s (0.0) | – |  |
| baseline-5 | PASS | 32992 / **0** | 0.0 s (0.0) | – |  |
| kill9-1of3 | PASS | 41870 / **0** | 4.76 s (4.55) | n2 -9 |  |
| kill9-2of5 | PASS | 55531 / **0** | 4.84 s (5.1) | n3 -9, n4 -9 |  |
| sigterm | PASS | 35991 / **0** | 0.11 s (1.14) | n2 0 |  |
| rolling-restart | PASS | 38700 / **0** | 0.21 s (1.85) | n1 0, n2 0, n3 0 |  |
| zombie | PASS | 41019 / **0** | 6.0 s (6.01) | n2 5 |  |
| zombie-short | PASS | 38143 / **0** | 4.69 s (5.3) | n2 5 |  |
| s3-partition | PASS | 38377 / **0** | 4.58 s (4.89) | n2 5 |  |
| peer-partition | PASS | 36532 / **0** | 12.03 s (12.02) | – |  |
| full-partition | PASS | 38214 / **0** | 6.29 s (6.0) | n2 5 |  |
| s3-slow | PASS | 41139 / **0** | 1.34 s (1.76) | n2 -9 |  |
| s3-slow-all | FAIL | 22801 / **0** | 21.61 s (22.07) | n1 5, n2 5, n3 5 | 1373 duplicate events on rejoined nodes' firehoses (bug N10) |
| s3-5xx | PASS | 43355 / **0** | 4.14 s (4.97) | n2 5 |  |
| add-remove | PASS | 36730 / **0** | 4.55 s (4.54) | n3 -9, n4 0 |  |
| cas-contention | PASS | 7200 / **0** | converged in 1.82 s | – | |
| handoff-firehose | PASS | 40755 / **0** | 4.54 s (4.76) | n2 0, n3 -9, n4 0 |  |
| kill9-rebalance-drainer | PASS | 39285 / **0** | 4.24 s (4.37) | n2 -9 |  |
| kill9-rebalance-joiner | PASS | 42410 / **0** | 4.75 s (5.94) | n4 -9 |  |
| kill9-rebalance-joiner-after-writes | PASS | 34515 / **0** | 4.9 s (4.86) | n4 -9 |  |
| zombie-check | PASS | 29725 / **0** | 6.0 s (6.01) | n2 5 |  |
| grow-1-to-3 | PASS | 16084 / **0** | 0.22 s (1.16) | – |  |
| s3-5xx-all | PASS | 37813 / **0** | 0.0 s (0.0) | – |  |
| s3-slow-one-long | PASS | 35129 / **0** | 6.89 s (7.2) | n2 5 |  |
| kill9-mid-checkpoint | PASS | 44315 / **0** | 4.42 s (4.55) | n2 -9/-9 |  |
| k-kill9-holes | PASS | 30967 / **0** | 5.14 s (new) | n2 -9/-9 | fence 219 = first hole 219; garbage ordinals [220, 221, 222] (34 events, 0 on any FH); 22 spans and fencers ['n1', 'n3'] all end at 219; fence 186 = first hole 186; garbage ordinals [187] (5 events, 0 on any FH); 20 spans and fencers ['n1', 'n3'] all end at 186 |
| k-zombie-inflight | PASS | 27956 / **0** | 6.01 s (new) | n2 5 | fence 533 = first hole 533; garbage ordinals [534, 535] (10 events, 0 on any FH); 22 spans and fencers ['n1', 'n3'] all end at 533 |
| k-sigterm-saturated | PASS | 56526 / **0** | 0.22 s (new) | n2 0 |  |
| k-s3-slow-lowload | PASS | 2395 / **0** | 0.0 s (new) | – |  |
| k-spill-holes | PASS | 18045 / **0** | 4.78 s (new) | n2 -9 | fence 234 = first hole 234; garbage ordinals [235, 236] (25 events, 0 on any FH); 20 spans and fencers ['n1', 'n3'] all end at 234 |

### 256 shards (`k2-256`, 2e64422)

| Scenario | Verdict | Acked / lost | Max shard outage (o3) | Exits | Notes |
|---|---|---|---|---|---|
| baseline-5 | PASS | 33081 / **0** | 0.0 s (0.0) | – |  |
| sigterm | PASS | 35853 / **0** | 0.74 s (1.64) | n2 0 |  |
| rolling-restart | FAIL | 38304 / **0** | 0.82 s (2.37) | n1 0, n2 0, n3 0 | checker FAIL; 3906 duplicate events on rejoined nodes' firehoses (bug N10) |
| grow-1-to-3 | PASS | 18559 / **0** | 0.85 s (1.63) | – |  |
| kill9-2of5 | PASS | 56054 / **0** | 4.51 s (5.41) | n3 -9, n4 -9 |  |

### Containers (`k2-ctr`, 2e64422)

| Scenario | Verdict | Acked / lost | Max shard outage (o3) | Exits | Notes |
|---|---|---|---|---|---|
| ctr-baseline-3 | PASS | 21603 / **0** | 0.0 s (0.0) | – |  |
| ctr-partition | PASS | 31321 / **0** | 6.12 s (4.73) | n2 5 |  |
| ctr-pause | PASS | 33989 / **0** | 6.05 s (5.09) | n2 5 |  |
| ctr-skew-small | PASS | 32422 / **0** | 4.54 s (4.95) | n2 137 |  |
| ctr-skew-large | PASS | 33218 / **0** | 5.28 s (5.31) | n2 137 |  |
| ctr-skew-steady | PASS | 21508 / **0** | 0.0 s (0.0) | – |  |

### Re-run with the N10 fix (`k3`, `k3-rep`, `k3-256`, `k3-256-rep`, `k3-ctr`)

These are the scenarios where a node restarts at the same address, plus both
N10 failures (each twice), plus the K scenarios.

| Scenario | Verdict | Acked / lost | Max shard outage (o3) | Exits | Notes |
|---|---|---|---|---|---|
| s3-slow-all | PASS | 22828 / **0** | 21.56 s (22.07) | n1 5, n2 5, n3 5 |  |
| rolling-restart | PASS | 38989 / **0** | 0.11 s (1.85) | n1 0, n2 0, n3 0 |  |
| kill9-1of3 | PASS | 42276 / **0** | 4.63 s (4.55) | n2 -9 |  |
| kill9-2of5 | PASS | 55982 / **0** | 5.42 s (5.1) | n3 -9, n4 -9 |  |
| sigterm | PASS | 36237 / **0** | 0.11 s (1.14) | n2 0 |  |
| zombie-short | PASS | 38427 / **0** | 4.79 s (5.3) | n2 5 |  |
| handoff-firehose | PASS | 41158 / **0** | 4.31 s (4.76) | n2 0, n3 -9, n4 0 |  |
| kill9-mid-checkpoint | PASS | 43929 / **0** | 4.52 s (4.55) | n2 -9/-9 |  |
| grow-1-to-3 | PASS | 16967 / **0** | 0.21 s (1.16) | – |  |
| k-kill9-holes | PASS | 31718 / **0** | 4.35 s (new) | n2 -9/-9 | fence 245 = first hole 245; garbage ordinals [246, 247] (25 events, 0 on any FH); 21 spans and fencers ['n1', 'n3'] all end at 245; fence 228 = first hole 228; garbage ordinals [230] (5 events, 0 on any FH); 20 spans and fencers ['n1', 'n3'] all end at 228 |
| k-zombie-inflight | PASS | 27807 / **0** | 6.0 s (new) | n2 5 | fence 535 = first hole 535; garbage ordinals [536, 537] (11 events, 0 on any FH); 20 spans and fencers ['n1', 'n3'] all end at 535 |

| Scenario | Verdict | Acked / lost | Max shard outage (o3) | Exits | Notes |
|---|---|---|---|---|---|
| s3-slow-all | PASS | 22725 / **0** | 21.56 s (22.07) | n1 5, n2 5, n3 5 |  |
| rolling-restart | PASS | 38644 / **0** | 0.21 s (1.85) | n1 0, n2 0, n3 0 |  |

| Scenario | Verdict | Acked / lost | Max shard outage (o3) | Exits | Notes |
|---|---|---|---|---|---|
| rolling-restart | PASS | 38297 / **0** | 0.63 s (2.37) | n1 0, n2 0, n3 0 |  |
| sigterm | PASS | 35773 / **0** | 0.58 s (1.64) | n2 0 |  |

| Scenario | Verdict | Acked / lost | Max shard outage (o3) | Exits | Notes |
|---|---|---|---|---|---|
| rolling-restart | PASS | 38292 / **0** | 0.62 s (2.37) | n1 0, n2 0, n3 0 |  |

| Scenario | Verdict | Acked / lost | Max shard outage (o3) | Exits | Notes |
|---|---|---|---|---|---|
| ctr-skew-small | PASS | 35076 / **0** | 4.63 s (4.95) | n2 137 |  |
| ctr-partition | PASS | 33740 / **0** | 6.06 s (4.73) | n2 5 |  |

All 18 `k3*` runs pass. Every replay and start audit has 0 duplicates, and
history agrees on every node.

### New K-in-flight scenarios: what each checks

Every scenario below also runs the standard checks: verify, `-strict`
checker, live, replay and start audits, and cross-node history agreement.

**`k-kill9-holes` (a).** Setup:
- segments ~52 KB, so they seal at ~13 KB while a PUT is in flight;
- 150 ms median injected PUT latency with sigma 1.0, so PUTs complete out of
  order;
- `vlpds_segment_puts_inflight` peaks at 6–8 attempts per node;
- n2 is killed with kill -9 the instant its S3 listing shows a hole, then
  restarted, twice per run.

`audit_dead_log` reads the dead log back from S3 and checks:
1. Exactly one fence, at the first non-segment ordinal.
2. Every `assign/*` span of that log ends there (20–22 shards).
3. Every fencer's `fenced dead node's log fence_ordinal=` agrees (n1 and n3).
4. No seq from a segment past the fence appears in any firehose audit: live,
   replay or start.
5. The prefix's last 20 seqs are on every survivor's firehose, so check 4
   isn't vacuous.

Results:

| Run | Holes seen at kill | Fence = first hole | Garbage past the fence | On any firehose |
|---|---|---|---|---|
| k2 | 219 (220–222 landed); 186 (187 landed) | 219; 186 | 220–222 (34 ev); 187 (5 ev) | 0 |
| k3 | 245; 228 | 245; 228 | 246–247 (25 ev); 230 (5 ev) | 0 |

**`k-zombie-inflight` (b).** Steps:
1. n2's S3 is blackholed until at least 4 segment PUT attempts hang (two
   ordinals plus their hedges).
2. n2 gets SIGSTOP for 4 × TTL. n1 and n3 fence its log at the first missing
   ordinal (533 in `k2`, 535 in `k3`).
3. The proxy is healed while n2 is still stopped, so its held PUTs reach
   MinIO. The PUT at the fence ordinal collides. The PUTs above it land as
   garbage (534–535 with 10 events, and 536–537 with 11).
4. SIGCONT.

Results:
- No acked write is lost, and no garbage event is on any firehose.
- **n2 exits 5, not 3.** At wake-up, the lease watchdog (`node lease lapsed
  past takeover`) fires before the 412 at the fence is processed. Both are
  fail-stops and nothing is acked: the finalizer checks the lease before any
  ack. Exit 3 (fence collision) would need the PUT response to win that race.

**`k-sigterm-saturated` (c).** Setup: 300 writes/s per node, 100 ms PUT
latency and small segments. n2 already had 4 PUT attempts in flight at
SIGTERM.

| Event | Handed | Close + barrier (ms) | Release → serving on the receiver (ms) |
|---|---|---|---|
| n4 joins: n1, n2 and n3 hand it 4–6 shards each | 16 | 187–247 | 17–55 |
| SIGTERM n2 (draining lease): n1, n3 and n4 | 16 | 247 | 98–109 |
| n2 restarts: n1, n3 and n4 hand back | 16 | 142–235 | 39–90 |

- Nudges: 15 sent and 21 received, with no lost nudge or fallback step.
- The 503 windows on probes are 0.2–0.4 s per move. In O3 they were 1.1–1.9 s
  (handback waited for a step).

**`k-s3-slow-lowload` (d).** Setup: 5 writes/s per node plus 4 probes. S3 on
n2 gets 400 ± 400 ms for 20 s.

| Window | Segments/s | Hedges | PUT requests/s | PUTs per segment |
|---|---|---|---|---|
| Before (10 s) | 14.8 | 0 | 14.8 | 1.0 |
| Slow S3 (20 s) | 1.65 | 34 for 33 segments (+1 in flight) | 3.35 | 2.03 |

- At most one hedge per ordinal.
- At low load, only one PUT is in flight, so the PUT rate falls with latency
  instead of exploding.

**`k-spill-holes` (e).** Setup: the `k-kill9-holes` settings plus a 0.25 MiB
merger budget.

Results:
- The survivors' mergers spill all the time: 40–43 spills per node, and
  226–233 segments read back after the kill.
- n2 is killed at a hole: the fence is at 234 and 235–236 are garbage.
- Followers drain to the fence, and spilled read-back stops at the hole or
  fence.
- The audits are complete, no garbage is emitted, and history agrees.

### Outages compared with O3

- **Handback gap: gone.**
  - sigterm: 0.11 s (64 shards), 0.58–0.74 s (256), versus 1.14 / 1.64 s.
  - rolling-restart: 0.11–0.21 s (64), 0.6–0.8 s (256), versus 1.85 / 2.37 s.
  - grow-1-to-3: 0.21 s, versus 1.16 s.
- **kill -9: still TTL + skew.**
  - kill9-1of3 4.6–4.8 s, kill9-2of5 4.8–5.4 s, kill9-mid-checkpoint
    4.4–4.5 s, versus 4.4–5.4 s.
  - The K scenarios are 4.3–5.1 s even with 150 ms PUTs.
- **Unchanged:** zombie, zombie-check, full-partition and ctr-pause are 6.0 s
  (TTL + skew + the forward deadline). peer-partition is 12 s (O2).
  s3-slow-all is 21.6 s (every node fail-stops, then the harness restarts
  them).
- **ctr-partition: 6.1 s, versus 4.7 s in O3.** It now matches the other
  hung-forward cases (zombie, ctr-pause), and every write was still acked.

### Bugs found and fixed in this round

**N10: a follower of a restarted node's previous log streamed the new log under the old id, duplicating firehose events.** Severity: high (firehose correctness). Files: `src/remote.rs`, `src/xrpc/internal.rs`.

- **Cause:**
  - `/internal/v1/log/stream` always served the node's *current* log, and the
    follower didn't say which log it wanted.
  - A peer that started following X's old log (from a lease read before X's
    new incarnation rewrote it) connected to X's unchanged address. It got the
    new log's batches labeled with the old log id.
  - Once the new log's ordinals passed the old log's fence ordinal, the
    follower accepted them. The merger queued every such event under both log
    ids and emitted it twice.
  - `stream_live` also ignored that its S3 catch-up had reached the fence.
- **Evidence:**
  - `k2/s3-slow-all`: all three nodes restarted at once. The n1 replay had 488
    identical (seq, did, rev) duplicates, all n3's writer, starting ~16 s after
    the restart, which is when n3's new log passed old fence 468. The n2
    replay had 885 duplicates. n3, which followed only new logs, had 0.
  - `k2-256/rolling-restart`: 1,953 duplicates on n2. Its cursor checker
    failed with `seq_reorder` and `chain_*`.
  - This is a latent bug of the per-node-log design: it depends on lease-read
    timing at restart.
- **Fix:**
  - The follower names the log (`?log=<id>`), and the owner refuses any other
    log (400 `WrongLog`).
  - A follower whose catch-up reaches the fence stops streaming. Its next
    round drains and retires the log.
- **Test:** `tests/all/firehose_startup.rs::log_stream_serves_only_the_named_log`.
- **After the fix:** the `k3*` runs pass. That includes s3-slow-all ×2 and
  256-shard rolling-restart ×2, with 0 duplicates anywhere.

**Not a bug: zombie exit code.** With PUTs in flight, the lease watchdog
fail-stops a woken zombie (5) before the fence collision can (3). Both are
safe. The `k-zombie-inflight` scenario accepts either.

### Code changes in this round

| File | Change |
|---|---|
| `src/remote.rs` | N10: the follower names the log it follows, and stops streaming once its catch-up has reached the fence. |
| `src/xrpc/internal.rs` | N10: `/internal/v1/log/stream?log=` refuses any log other than the node's current one. |
| `src/main.rs` | `--max-segment-mb` takes fractions; new `--firehose-merge-queue-mb`. Both are in 748039d. |
| `tests/all/firehose_startup.rs` | `log_stream_serves_only_the_named_log`. |
| `bench/ha/hactl.py` | `VLPDS_HA_INJECT_PUT_MS` (25) and `VLPDS_HA_LOG_INFLIGHT` (4) on every node; per-scenario node flags, env and probe count; the S3 client and log audit; `k-kill9-holes`, `k-zombie-inflight`, `k-sigterm-saturated`, `k-s3-slow-lowload`, `k-spill-holes`. |

On the clean 2e64422 tree with the fix: `cargo test` gives 92 lib tests and
331 in `tests/all`, all passing. In the shared working tree, the lib builds
with the fix, but the bin doesn't compile because of other agents'
unfinished `server::Config` fields.

## O3–O6 round (`o3*` runs): clock-free liveness, cheap control plane, batched drains

This round fixes O3–O6 (see "Open issues"). All runs use one binary built from the
tree with these changes (it also carries other agents' in-progress `nodelog.rs`,
`firehose.rs` and `remote.rs` work at that point, including the replay span fix the
new `kill9-rebalance-joiner-after-writes` scenario targets). Same setup as above:
TTL 3 s, 150 creates/s per node, 32 probes. The `CP req/s` column is the new
`vlpds_cluster_store_requests_total` counter (every control-plane GET/LIST/PUT/DELETE:
leases, assignments, writer claims, fences) per stayed-up node over the load phase.

**Every scenario passes: 25 native at 64 shards, 5 at 256 shards, 6 container runs
(including ctr-skew-large and ctr-skew-steady, which used to fail), and the new
scenario. No acked write was lost and the checker passed `-strict` everywhere.**

Outputs: `out/o3*/` holds the logs (gzipped), the probes and `result.json`. The raw firehose-audit and acked-set dumps were deleted after the verdicts, since every run passed.


### Native, 64 shards (`o3`, every native scenario)

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits | CP req/s per node |
|---|---|---|---|---|---|---|---|---|---|
| baseline-2 | PASS | 19579 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – | 6.3 6.3 |
| baseline-3 | PASS | 24073 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – | 9.7 9.7 9 |
| baseline-5 | PASS | 33078 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – | 13.1 13.4 13.3 13.1 13.2 |
| kill9-1of3 | PASS | 41844 / **0** | PASS | all 0 | yes / yes | 15–19.6 (510), 40.3–41.6 (150) | 4.55 s | n2 -9 | 9.4 9.3 |
| kill9-2of5 | PASS | 55342 / **0** | PASS | all 0 | yes / yes | 15–20.2 (591), 40.3–41.8 (175) | 5.1 s | n3 -9, n4 -9 | 12.6 12.5 12.5 |
| sigterm | PASS | 35825 / **0** | PASS | all 0 | yes / yes | 15–16.1 (92), 35.3–36.4 (137) | 1.14 s | n2 0 | 9.1 9.1 |
| rolling-restart | PASS | 37809 / **0** | PASS | – | yes / yes | 10–11.9 (202), 22–23.9 (214), 34–35.8 (255) | 1.85 s | n1 0, n2 0, n3 0 | – |
| zombie | PASS | 40911 / **0** | PASS | all 0 | yes / yes | 15–21.1 (26), 45.2–46.4 (107) | 6.01 s | n2 5 | 8.6 8.8 |
| zombie-short | PASS | 37870 / **0** | PASS | all 0 | yes / yes | 15–20.3 (251), 40.2–41.4 (96) | 5.3 s | n2 5 | 8.7 8.7 |
| s3-partition | PASS | 38477 / **0** | PASS | all 0 | yes / yes | 15–20 (155), 40.1–41.4 (91) | 4.89 s | n2 5 | 8.6 8.7 |
| peer-partition | PASS | 36842 / **0** | PASS | all 0 | yes / yes | 15–27.1 (49) | 12.02 s | – | 8.9 9.1 9.1 |
| full-partition | PASS | 38075 / **0** | PASS | all 0 | yes / yes | 15–21.1 (24), 40.1–41.8 (136) | 6.0 s | n2 5 | 8.9 8.7 |
| s3-slow | PASS | 41333 / **0** | PASS | all 0 | yes / yes | 42–43.8 (152) | 1.76 s | n2 -9 | 9.3 9.3 |
| s3-slow-all | PASS | 22446 / **0** | PASS | – | yes / yes | 15–37.1 (5732) | 22.07 s | n1 5, n2 5, n3 5 | – |
| s3-5xx | PASS | 43100 / **0** | PASS | all 0 | yes / yes | 29.9–34.9 (174), 45.1–46.4 (146) | 4.97 s | n2 5 | 9.4 9.9 |
| add-remove | PASS | 36465 / **0** | PASS | all 0 | yes / yes | 10.2–11.4 (141), 20.3–21.6 (98), 32–32.5 (37), 44–48.6 (587) | 4.54 s | n3 -9, n4 0 | 9.8 9.9 |
| cas-contention | PASS | 0 / **0** | PASS | – | yes / yes | converged in 1.49 s |  s | – | – |
| handoff-firehose | PASS | 39904 / **0** | PASS | all 0 | yes / yes | 10–11.6 (153), 18.3–19.4 (99), 26–30.8 (375), 34.2–35.6 (133), 42–44.1 (117) | 4.76 s | n2 0, n3 -9, n4 0 | 13.2 |
| kill9-rebalance-drainer | PASS | 39173 / **0** | PASS | all 0 | yes / yes | 12.5–18 (528), 32.3–33.6 (109) | 4.37 s | n2 -9 | 10.5 10.8 |
| kill9-rebalance-joiner | PASS | 42013 / **0** | PASS | all 0 | yes / yes | 12.5–18.5 (450), 32.3–33.5 (91) | 5.94 s | n4 -9 | 10.6 10.6 10.6 |
| zombie-check | PASS | 29639 / **0** | PASS | all 0 | yes / yes | 15–21.1 (22) | 6.01 s | n2 5 | 7.7 7.6 |
| grow-1-to-3 | PASS | 16231 / **0** | PASS | all 0 | yes / yes | 8.3–9.5 (144), 16.2–17.4 (105) | 1.16 s | – | 9.8 |
| s3-5xx-all | PASS | 38298 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – | 8.1 8 8 |
| s3-slow-one-long | PASS | 34749 / **0** | PASS | all 0 | yes / yes | 15–22.2 (503), 35.5–36.7 (106) | 7.2 s | n2 5 | 8.6 9.1 |
| kill9-mid-checkpoint | PASS | 43563 / **0** | PASS | all 0 | yes / yes | 8.3–12.5 (444), 25.3–26.6 (125), 35–39.6 (434), 50.1–51.9 (148) | 4.55 s | n2 -9/-9 | 9.8 10.1 |

### 256 shards (`o3-256`)

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits | CP req/s per node |
|---|---|---|---|---|---|---|---|---|---|
| baseline-5 | PASS | 33099 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – | 11.6 12.8 12.3 12.7 11.6 |
| sigterm | PASS | 35767 / **0** | PASS | all 0 | yes / yes | 15–16.3 (83), 35.1–36.8 (167) | 1.64 s | n2 0 | 14.2 14.2 |
| rolling-restart | PASS | 37488 / **0** | PASS | – | yes / yes | 10–11.9 (149), 22–24.3 (271), 34–36.4 (440) | 2.37 s | n1 0, n2 0, n3 0 | – |
| grow-1-to-3 | PASS | 18368 / **0** | PASS | all 0 | yes / yes | 8.4–9.9 (220), 16.2–17.9 (118) | 1.63 s | – | 17.5 |
| kill9-2of5 | PASS | 55253 / **0** | PASS | all 0 | yes / yes | 15–20.5 (529), 40.3–42 (202) | 5.41 s | n3 -9, n4 -9 | 15.8 15.3 15.7 |

### Containers (`o3-ctr`): docker network disconnect, docker pause, libfaketime clock skew

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits | CP req/s per node |
|---|---|---|---|---|---|---|---|---|---|
| ctr-baseline-3 | PASS | 21742 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – | 8.1 8.2 7.6 |
| ctr-partition | PASS | 33721 / **0** | PASS | all 0 | yes / yes | 15.1–19.9 (387), 40.9–42.1 (97) | 4.73 s | n2 5 | 9 8.7 |
| ctr-pause | PASS | 33725 / **0** | PASS | all 0 | yes / yes | 15–20.2 (33), 40.7–42.1 (130) | 5.09 s | n2 5 | 8.7 8.7 |
| ctr-skew-small | PASS | 34447 / **0** | PASS | all 0 | yes / yes | 15.1–20.1 (352), 35.6–37.3 (105) | 4.95 s | n2 137 | 8.9 8.8 |
| ctr-skew-large | FAIL | 34184 / **0** | PASS | [128, 123] | yes / yes | 15.1–20.5 (412), 35.5–37.3 (150) | 5.37 s | n2 137 | 8.9 9.1 |
| ctr-skew-steady | FAIL | 21526 / **0** | PASS | [164, 158, 153] | yes / yes | none | 0.0 s | – | 8.4 8.2 8.2 |

### Skew re-run after the harness fix (`o3-ctr2`)

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits | CP req/s per node |
|---|---|---|---|---|---|---|---|---|---|
| ctr-skew-large | PASS | 34564 / **0** | PASS | all 0 | yes / yes | 15.1–20.4 (403), 35.5–36.9 (110) | 5.31 s | n2 137 | 9 9 |
| ctr-skew-steady | PASS | 21540 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – | 8.2 8.2 8.4 |

### New scenario (`o3-jaw`)

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits | CP req/s per node |
|---|---|---|---|---|---|---|---|---|---|
| kill9-rebalance-joiner-after-writes | PASS | 34403 / **0** | PASS | all 0 | yes / yes | 12.5–13.7 (84), 17.2–22.1 (327) | 4.86 s | n4 -9 | 9.7 9.5 9.7 |

The `o3-ctr` skew rows failed only the live firehose audit, by 110–165 commits each,
while the replays were complete (0 missing) and the histories agreed. The missing
commits were exactly the probe writes from the last ~1.6 s before the audits
stopped. With ±2.5 s skew the merged live stream emits at the min watermark, so it
trails the fast node by the 5 s clock spread, and the harness stopped the audits 3 s
after the probes. The harness now waits for the clock spread (`clock_spread_s`) after
stopping the probes; `o3-ctr2` is that re-run.

### What the skew runs show (O3)

- **No fencing under ±2.5 s skew.** n3 (clock −2.5 s) is never presumed dead, and
  there are no exits apart from the harness's kill.
  - In `final-ctr`, n3 looked expired to its peers 1.1 s after each renewal, was
    fenced, and exited 3. Setup never finished.
  - Takeover after `kill -9` of n2 (clock +2.5 s) takes 5.3–5.5 s, about the same
    as ctr-skew-small (4.95 s) and native kill9 (4.4–5.1 s).
- **Per-repo order across handoffs.** The checker passes `-strict` with 0 reorders.
  Shards moving from the fast node to the slow one commit-wait:
  - `waited for our clock to pass the previous owner's last seq`: 2.3 s on the
    initial handoffs (≈ the 5 s spread minus the join time), 0.38 s on the kill
    takeover (the 5 s spread minus TTL + skew + step).
  - Without the seq floor, the slow node's first commits for those repos would
    sort before the fast node's last ones.
- **Merge latency = clock spread.** The live merged firehose trails by up to the
  largest clock offset, on every node. This is expected (DESIGN.md "Why safety
  needs no clocks").

### Control-plane requests (O5)

Idle 3-node cluster, 256 shards, per node (`cpmeasure`: two scrapes of the
counter 30–60 s apart):

| TTL | Before: GET / LIST / PUT (total req/s) | After: GET / LIST / PUT (total req/s) |
|---|---|---|
| 3 s (bench) | 431 / 1.7 / 1.7 (**434**) | 3.3 / 3.3 / 1.7 (**8.3**) |
| 10 s (production default) | 129 / 0.5 / 0.5 (**130**) | 0.8 / 1.0 / 0.5 (**2.3**) |
| 3 s, single node | 436 / 1.7 / 1.7 (**439**) | 0 / 3.3 / 1.7 (**5.0**) |

How the after column breaks down:
- Each step now makes one LIST of `nodes/` and one of `assign/`, plus one GET per
  peer renewal. A shard's assignment is GET only when its ETag changes, and all of
  them are re-read every 150 steps as a safety net.
- With a 30-step resync, GETs were 20/s at TTL 3 s; 150 steps is about 5 min at the
  production TTL.
- Under load and rebalancing (tables above) it is 8–10 req/s per node at 64 shards
  and 12–17 at 256 shards with TTL 3 s, versus ~107 and ~430 before.
- An S3 LIST costs as much as a PUT. At the production TTL that is 1 LIST/s plus
  ~1 GET/s per node: about $13 a month per node, versus ~$130.

### Drain (O6)

`close_many` closes every released shard at once:
- every barrier is queued back to back, so they share one segment PUT;
- one 30 s deadline covers all the barriers;
- checkpoints and closes run 32 at a time;
- releases CAS against the cached assignments.

| Drain | Before | After |
|---|---|---|
| Graceful SIGTERM under load, 22 shards | 0.5–0.9 s exit | shards released in 46 ms, exit in 0.17 s |
| Graceful SIGTERM under load, 86 shards (256-shard run) | – | 202 ms, exit in 0.33 s |
| Idle single node holding 256 shards (`cpmeasure`, process exit) | 0.96 s | 0.53–0.67 s |
| Idle 3-node cluster, one node holding ~86 shards (`cpmeasure`, process exit) | 0.39 s | 0.14–0.29 s |

### Failure-path fix from the storage/log review (close failures)

- **Problem:** `close()` keyed off the routing table. If a close failed (for example,
  its barrier wait timed out on a slow PUT), the shard was already unrouted. The next
  step's `close` then returned Ok at once, and `release` published
  `span end = durable_end()` while that shard's entries could still be in flight at
  or after that ordinal. `shutdown` ignored close errors in the same way, then fenced
  its own log while uploads might still be running.
- **Fix:**
  - `close_many` keys off the shard's sink (what the log still applies into).
  - A shard whose close failed is never released: the node fail-stops (exit 5), and
    a successor fences its log and replays it to the fence.
  - Shutdown waits for the log to quiesce (`wm.idle()`) before fencing. If it
    doesn't quiesce, the node fail-stops without fencing, and its peers fence it.
- **Test:** unit test `cluster::failed_close_is_not_released`.

### New scenario: `kill9-rebalance-joiner-after-writes`

- **Setup:**
  - n4 joins three loaded nodes and takes 16 shards.
  - It acks forwarded writes for them: 567 segments in about 4 s.
  - It is killed with `kill -9` 4 s after taking them, before its first 10 s
    checkpoint, so those writes exist only in its log. There is no restart.
- **Result:** the survivors fence n4's log at 567, replay all 567 segments, and
  lose nothing (PASS).
- **Caveat:** this binary already contains the concurrent replay span fix
  (`nodelog::marker_span`). The scenario was not run on the pre-fix tree.

### Outage notes

- **zombie / full-partition: 6.0 s, was 12 s.** That gain comes from the concurrent
  O2 forward deadline, not from this round.
- **s3-slow-one-long: 7.2 s, was 4.3 s.**
  - An observer credits a renewal from when it *saw* the lease change.
  - n2's last renewal PUTs took ~1.5 s to land, so peers' TTL + skew window started
    up to one renewal RTT plus one step later than n2's own validity, which counts
    from the send.
  - n2 still fail-stopped at its own lapse (exit 5). The extra outage is bounded by
    the renewal RTT.
- **Elsewhere, takeover after a crash is unchanged:** 4.4–5.4 s, i.e. TTL + skew +
  at most one step + replay.

## Results (previous round: `final*`, before the O3–O6 fixes)

How to read the tables:
- "Outage windows" are relative to load start: `start–end s (failed probes)`. Long windows with few failed probes are hung requests (see O2).
- "Max shard outage" is the longest contiguous outage of a single shard.
- Exit code −9 is the harness's kill, 0 a graceful exit, 5 a lease fail-stop, 3 a fenced-log fail-stop, and 137 a docker kill.

### Native, 64 shards (`final`, every native scenario)

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up nodes) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits |
|---|---|---|---|---|---|---|---|---|
| baseline-2 | PASS | 19365 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – |
| baseline-3 | PASS | 24092 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – |
| baseline-5 | PASS | 33084 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – |
| kill9-1of3 | PASS | 41804 / **0** | PASS | all 0 | yes / yes | 15–19.7 (745), 40.2–42 (110) | 4.73 s | n2 -9 |
| kill9-2of5 | PASS | 55522 / **0** | PASS | all 0 | yes / yes | 15–19.8 (410), 40.4–41.6 (115) | 4.73 s | n3 -9, n4 -9 |
| sigterm | PASS | 35884 / **0** | PASS | all 0 | yes / yes | 15–16.1 (134), 35.3–36.5 (172) | 1.13 s | n2 0 |
| rolling-restart | PASS | 37411 / **0** | PASS | – | yes / yes | 10.3–12.5 (296), 22.1–22.7 (13), 34–36.7 (587) | 2.76 s | n1 0, n2 0, n3 0 |
| zombie | PASS | 40547 / **0** | PASS | all 0 | yes / yes | 15–27 (13), 45.7–46.8 (93) | 12.01 s | n2 5 |
| zombie-short | PASS | 38212 / **0** | PASS | all 0 | yes / yes | 15–18.6 (75), 40.3–41.5 (162) | 3.61 s | n2 5 |
| zombie-check | PASS | 28665 / **0** | PASS | all 0 | yes / yes | 15–27 (15) | 12.01 s | n2 5 |
| s3-partition | PASS | 38241 / **0** | PASS | all 0 | yes / yes | 15–19.8 (161), 40.2–41.4 (82) | 4.67 s | n2 5 |
| peer-partition | PASS | 37178 / **0** | PASS | all 0 | yes / yes | 15–27.1 (0) | 12.09 s | – |
| full-partition | PASS | 36829 / **0** | PASS | all 0 | yes / yes | 15–27 (16), 40.4–41.7 (114) | 12.02 s | n2 5 |
| s3-slow | PASS | 40248 / **0** | PASS | all 0 | yes / yes | 42–43.8 (242) | 1.78 s | n2 -9 |
| s3-slow-one-long | PASS | 35416 / **0** | PASS | all 0 | yes / yes | 15–19.3 (180), 35.1–36.4 (101) | 4.27 s | n2 5 |
| s3-slow-all | PASS | 22038 / **0** | PASS | – | yes / yes | 15–40 (5405) | 24.98 s | n1 5, n2 5, n3 5 |
| s3-5xx | PASS | 43020 / **0** | PASS | all 0 | yes / yes | 30.1–34 (261), 45.5–46.6 (85) | 3.94 s | n2 5 |
| s3-5xx-all | PASS | 38240 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – |
| add-remove | PASS | 36237 / **0** | PASS | all 0 | yes / yes | 10.3–11.4 (91), 20.3–21.6 (89), 32–33.7 (108), 44–48.5 (330) | 4.46 s | n3 -9, n4 0 |
| grow-1-to-3 | PASS | 15881 / **0** | PASS | all 0 | yes / yes | 8.4–9.5 (129), 16.2–17.4 (92) | 1.14 s | – |
| cas-contention | PASS | 9600 / **0** | PASS | – | – / – | converged in 1.65 s |  | – |
| handoff-firehose | PASS | 40189 / **0** | PASS | all 0 | yes / yes | 10–12 (297), 18.2–19.8 (105), 34.3–35.4 (168), 42–43.8 (89) | 1.96 s | n2 0, n3 -9, n4 0 |
| kill9-rebalance-drainer | PASS | 39110 / **0** | PASS | all 0 | yes / yes | 12.6–18.7 (632), 32.5–33.6 (57) | 5.0 s | n2 -9 |
| kill9-rebalance-joiner | PASS | 41925 / **0** | PASS | all 0 | yes / yes | 12.1–13.3 (86), 13.7–17.5 (267), 32.5–33.7 (144) | 5.43 s | n4 -9 |
| kill9-mid-checkpoint | PASS | 43526 / **0** | PASS | all 0 | yes / yes | 8.1–11.9 (538), 25.2–26.4 (110), 35.1–38.9 (337), 50.3–51.5 (196) | 3.83 s | n2 -9/-9 |

### Re-run after the log-stream idle-timeout fix (`final2`, `final3`, 64 shards)

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up nodes) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits |
|---|---|---|---|---|---|---|---|---|
| peer-partition | PASS | 37908 / **0** | PASS | all 0 | yes / yes | 15–27.1 (0) | 12.08 s | – |
| full-partition | PASS | 37657 / **0** | PASS | all 0 | yes / yes | 15–27 (11), 40.2–41.4 (130) | 12.0 s | n2 5 |
| zombie | PASS | 40314 / **0** | PASS | all 0 | yes / yes | 15–27 (12), 45.1–46.8 (96) | 11.98 s | n2 5 |
| zombie-short | PASS | 38245 / **0** | PASS | all 0 | yes / yes | 15–19 (88), 40.2–41.3 (116) | 4.0 s | n2 5 |
| zombie-check | PASS | 28910 / **0** | PASS | all 0 | yes / yes | 15–27 (12) | 12.01 s | n2 5 |
| kill9-1of3 | PASS | 41791 / **0** | PASS | all 0 | yes / yes | 15–19.5 (463), 40.2–41.4 (99) | 4.44 s | n2 -9 |
| s3-partition | PASS | 38264 / **0** | PASS | all 0 | yes / yes | 15–19.4 (135), 40.4–41.5 (121) | 4.4 s | n2 5 |
| handoff-firehose | PASS | 39673 / **0** | PASS | all 0 | yes / yes | 10–12 (232), 18.3–19.8 (77), 26–30.6 (441), 34.2–35.4 (91), 42–43.9 (161) | 4.57 s | n2 0, n3 -9, n4 0 |
| sigterm | PASS | 35742 / **0** | PASS | all 0 | yes / yes | 15–16.1 (115), 35.4–36.5 (111) | 1.14 s | n2 0 |
| kill9-2of5 | PASS | 55418 / **0** | PASS | all 0 | yes / yes | 15–19.5 (523), 40.4–41.7 (168) | 4.48 s | n3 -9, n4 -9 |

### 256 shards (`final-256`, `final3-256`)

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up nodes) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits |
|---|---|---|---|---|---|---|---|---|
| baseline-5 | PASS | 33128 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – |
| sigterm | PASS | 35989 / **0** | PASS | all 0 | yes / yes | 15–16.4 (73), 35.6–36.8 (153) | 1.34 s | n2 0 |
| rolling-restart | PASS | 37307 / **0** | PASS | – | yes / yes | 10.2–12.4 (175), 23.5–24.7 (61), 34–36.8 (720) | 2.79 s | n1 0, n2 0, n3 0 |
| grow-1-to-3 | PASS | 17230 / **0** | PASS | all 0 | yes / yes | 8.5–9.9 (140), 16.3–17.8 (83) | 1.44 s | – |
| kill9-2of5 | PASS | 55307 / **0** | PASS | all 0 | yes / yes | 15–19.9 (616), 40.2–42.1 (200) | 4.87 s | n3 -9, n4 -9 |

`baseline-5` at 256 shards converged in 2.47 s (52/52/52/52/48 shards). In `grow-1-to-3`, n1 took all 256 shards alone on first start (the lead's lease-lapse repro, now passing) and then rebalanced to 86/86/84 under load.

### Repeats of the race-prone scenarios (`final-rep`)

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up nodes) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits |
|---|---|---|---|---|---|---|---|---|
| kill9-rebalance-drainer | PASS | 39263 / **0** | PASS | all 0 | yes / yes | 12.6–17.9 (478), 32.4–33.5 (85) | 4.3 s | n2 -9 |
| kill9-rebalance-joiner | PASS | 41910 / **0** | PASS | all 0 | yes / yes | 12.1–13.5 (92), 13.7–17.6 (315), 32.1–33.8 (138) | 5.24 s | n4 -9 |
| zombie-short | PASS | 37949 / **0** | PASS | all 0 | yes / yes | 15–19.8 (196), 40.3–41.4 (60) | 4.75 s | n2 5 |

`zombie-short` ran twice in `final-rep`. Both runs passed (`out/final-rep/summary.md`); the table shows the second, whose `result.json` overwrote the first.

### Containers (`final2-ctr`): docker network disconnect, docker pause, libfaketime clock skew

| Scenario | Verdict | Acked / lost | Checker | FH missing (live, stayed-up nodes) | History agree (replay / live) | Outage windows [start–end s, failed probes] | Max shard outage | Exits |
|---|---|---|---|---|---|---|---|---|
| ctr-baseline-3 | PASS | 19363 / **0** | PASS | all 0 | yes / yes | none | 0.0 s | – |
| ctr-partition | PASS | 33027 / **0** | PASS | all 0 | yes / yes | 15.1–30.1 (423), 41–42.2 (79) | 15.01 s | n2 5 |
| ctr-pause | PASS | 31154 / **0** | PASS | all 0 | yes / yes | 15–27.1 (14), 41.4–42.9 (44) | 12.09 s | n2 5 |
| ctr-skew-small | PASS | 30424 / **0** | PASS | all 0 | yes / yes | 15.2–20.3 (374), 36.8–38.1 (57) | 4.93 s | n2 137 |

| Scenario | Verdict | Notes |
|---|---|---|
| ctr-skew-large (n2 +2.5 s, n3 −2.5 s) | ERROR on that binary | Clock skew of 2.5 s exceeded the 600 ms skew margin. See O3; fixed, PASS in `o3-ctr2`. |
| ctr-skew-steady (same skew, no faults) | ERROR (same cause) | Same as above (`final-ctr`). |

In both skew-large runs, n3 (clock −2.5 s) wrote leases that looked expired to its peers 1.1 s after each renewal. Its peers declared it dead and took the shards it had opened a second earlier (its SlateDBs logged `Fenced`), fenced its log, and n3 exited 3 (`our log was fenced by a successor`). Setup failed because n3 died mid-`createAccount`. Safety held, availability did not.

### Specific checks

- **No acknowledged write was lost in any run.** That covers 35 native runs at 64 shards (`final`, `final2`, `final3`), 6 at 256 shards, 4 repeats and 4 container runs, plus every earlier smoke run. Checker `-strict` passed in every run on the final binaries.
- **Merged history agrees across nodes everywhere** (the old B5). Replays from one cursor give identical (seq, did, rev) sequences on every node that stayed up. The live audits agree over their common range in every scenario. The merger's late-event warning never fired.
- **Zombie (SIGSTOP 4×TTL, then SIGCONT):**
  - n2 exits 5 within about 0.5 s of waking (`node lease lapsed past takeover` or `lapsed before renewal`), and acks nothing stale: verify finds 0 lost and the checker passes.
  - With a short pause (1.1×TTL, waking around takeover) n2 also exits 5 and nothing is lost. Before the fixes below, this exact scenario produced a firehose chain break and two permanently unloadable repos (N6, N7).
- **kill -9 mid-checkpoint (twice):** the kill lands about 10–30 ms after `checkpoint start`. The successors replay the whole log tail (1,284 and 1,388 segments) in 0.4–0.6 s, and every survivor ends its span at the same fence ordinal. Nothing is lost.
- **kill -9 mid-rebalance:**
  - Killing the draining node 0.4 s into the join, or the joining node while it opens its shards, loses nothing.
  - Windows are about 5–6 s: TTL + skew plus the rebalance.
- **CAS contention:** 8 nodes started at the same instant converge in 1.65–2.1 s, with exactly 8 shard opens per node: no CAS churn and no double ownership.
- **Failover time:**
  - Takeover after kill -9 is 4.4–4.9 s (TTL 3 s + skew 0.6 s + replay), versus 9.9–10.6 s before.
  - Shards opened with 1,100–1,900 segments replayed take 150–1,000 ms (`segments_replayed` in the logs).
  - A graceful SIGTERM moves its shards in 1.1–1.4 s, and exit is 0 after 0.5–0.9 s.
- **S3 brownouts:**
  - **400 ± 400 ms latency on one node:** no outage, no fail-stop (this used to fail-stop, see N2).
  - **1500 ms latency, on one node or on all nodes:** the affected nodes fail-stop with exit 5. This is a protocol limit at TTL 3 s, not a bug: renewals are sequential CAS PUTs and validity is send time + TTL − skew, so a renewal RTT above (TTL − skew)/2 = 1.2 s opens a validity gap. With the production default TTL of 10 s the tolerance is 4 s. With all three nodes down, the cluster is unavailable until the harness restarts them (25 s).
  - **30 % 503s on one node or on all nodes:** no outage at all; the retries absorb them.
  - **30 % 503s, then 100 % 500s on one node:** that node's lease lapses, it is fenced, and it exits 3 or 5. The outage is about 4 s.

## Comparison with the old baseline (`base1`, per-partition leases, 16 partitions)

| Scenario | Old verdict | Old outage / FH missing | New verdict | New outage / FH missing |
|---|---|---|---|---|
| baseline-2/3/5 | FAIL (B5 history disagreement) | – | PASS | identical history on all nodes |
| kill9-1of3 | FAIL (B1 firehose stall) | 10.6 s / 11.7k missing | PASS | 4.4–4.7 s / 0 |
| kill9-2of5 | FAIL (B1) | 9.9 s / 17.6k missing | PASS | 4.5 s (64 shards), 4.9 s (256) / 0 |
| sigterm | FAIL (B1, no SIGTERM handler) | 9.9 s / 8.9k missing | PASS | 1.1 s / 0, exit 0 |
| rolling-restart | PASS | 4.2–4.9 s per node | PASS | 0.6–2.7 s per node |
| zombie / zombie-short | FAIL (B1) | 12 s / 25.9 s, about 8.7k missing | PASS | 12 s (hung forwards, O2) / 4 s; 0 missing |
| s3-partition | FAIL (B1) | 12 s / 8.6k missing | PASS | 4.4 s / 0 |
| peer-partition | FAIL (B5) | 12.1 s (hung) | PASS | 12.1 s (hung, O2) |
| full-partition | FAIL (B1) | 12 s / 8.7k missing | PASS | 12 s (hung forwards, O2) / 0 |
| s3-slow, s3-slow-all, s3-5xx | ERROR (disk full) | – | PASS | see S3 brownouts above |
| add-remove, cas-contention, handoff-firehose, all `ctr-*` | not run | – | PASS (except ctr-skew-large and ctr-skew-steady, out of spec) | – |

### Status of the old bugs

- **B1 – followers never switch owners / firehose stalls: gone, with two regressions found and fixed.**
  - The design itself removes the old mechanism: followers follow node logs, and a dead log is drained to its fence.
  - It came back twice by other routes: graceful shutdown never fenced its log (N1), and half-open peer connections never timed out (N8). Both are fixed.
- **B2 – watermark cap on graceful handoff: not observed.**
  - The merger's late-event diagnostic never fired in any run, including joins, rebalances, handoffs and container skew within the margin.
  - Shards no longer move between per-shard streams; per-log watermarks plus the join grace cover it.
- **B3 – slow failover from the heartbeat liveness window: fixed by design.** Takeover is TTL + skew + replay, 4.4–4.9 s.
- **B4 – no graceful shutdown: fixed by design**, with a race fixed here (N1): the step loop could re-acquire shards during shutdown. Exit 0 in 0.5–0.9 s.
- **B5 – merged history differs between nodes: gone.** Every node that stayed up agrees on identical (seq, did, rev) sequences in every scenario.
- **B6 – 500 instead of 503 for an unowned shard: fixed by design.** Moving or unowned shards return 503 `PartitionUnavailable`.
- **B7 – firehose history starts at join: mostly fixed by another agent's S3 cursor backfill**, which landed during this work.
  - Rejoined nodes' cursor replays are now complete.
  - The seam at a node's start (O1) is fixed (`o1fix`, below).
- **B8 – forwards to an unreachable owner hang: partly fixed.**
  - The 1 s connect timeout fails fast when the peer is gone.
  - A peer whose TCP endpoint accepts but stalls (frozen process, blackholed path, disconnected container) still holds forwarded requests up to the 15 s total timeout (O2).
- **B9 – a lease renew error doesn't stop the node acking: fixed** (N4, N5). The node now fail-stops once its lease is past takeover. It no longer waits for the next PUT, which may be hung.

## Bugs found and fixed in this round (all in the HA files, each commented `HA fix` in the code)

**N1 – Graceful shutdown never fenced its log, so every peer's firehose stalled permanently.** Severity: high. File: `cluster.rs` (`shutdown`).

- **Cause:** shutdown released the shards and deleted the node lease, but never closed the log. Peers drain a dead log from S3 *up to its fence* before removing its watermark source. With no fence, they waited forever, and their merged firehose stopped at the dead node's last watermark. Since the lease was deleted, a restart with the same node id did not fence the old log either.
- **Evidence:** `new-smoke1/sigterm`. All three firehoses stopped at 05:39:53.64, the instant of the SIGTERM. 25.6k acked creates were missing on n1 and n3, and their logs never showed "dead peer log drained".
- **Fix:**
  - Shutdown fences its own idle log after releasing its shards.
  - It also sets a stop flag and takes a step lock, so a concurrent step cannot re-acquire the shards being released (B4's race).
- **After the fix:** sigterm passes (0 missing, exit 0), and so does rolling-restart.

**N2 – Lease renewal was serialised behind an O(shards) sequential scan, so a mild S3 brownout fail-stopped the node.** Severity: high. File: `cluster.rs`.

- **Cause:** the lease was renewed only at the top of `step()`. The step then made about 70 sequential S3 round trips: LIST, the node leases, and one GET per assignment.
- **Evidence:** `new-smoke2/s3-slow`. With 400 ± 400 ms latency, a step took about 25 s against a 2.4 s validity window, and n2 exited 5, 2.1 s into the brownout (`lease lapsed before segment PUT`).
- **Fix:**
  - Renewal runs on its own loop, every renew interval, independent of the step.
  - Assignment GETs are concurrent (32 in flight).
  - A node without a valid lease never acquires or releases shards.
- **After the fix:** s3-slow shows no outage and no fail-stop.

**N3 – Fresh lone node fail-stopped on first start: the inline first step outlived the lease.** Severity: high. File: `cluster.rs`. This is the lead and UI-agent report.

- **Cause:** `server::build` runs the first step inline, before the renew loop exists. A node starting alone acquires its whole share there: one CAS PUT per shard, then it opens all of them. For the UI agent that was 181 shards in 19 s against a 10 s TTL.
- **Repro:** a fresh prefix and 256 shards, with n1 starting 3 s before n2 and n3, at TTL 1 s. n1's inline step took 1.77 s, and n1 exited 5 right after "node ready" (`repro-alone-before`). A simultaneous start does not reproduce it: peers are visible, so the join grace defers acquisition to spawned steps.
- **Fix:**
  - The whole inline step runs under a keepalive that renews every interval. Renewals are never cancelled mid-flight, because a dropped CAS PUT could land with an ETag we never learn.
  - The renew loop and watchdog keep running through a graceful shutdown's drain, and stop only when the lease is deleted.
- **After the fix:**
  - At TTL 1 s and 3 s, all three nodes stay up and rebalance.
  - SIGTERM of a node holding 256 shards at TTL 1 s drains in 3.4 s with exit 0.
  - The `grow-1-to-3` regression scenario passes at 64 and at 256 shards.

**N4 – No lease watchdog: a node with hung S3 calls stayed up as a zombie.** Severity: medium. File: `cluster.rs`.

- **Cause:** validity was checked only before a segment PUT or an ack. A node whose PUT hung in an S3 blackhole kept client and forwarded requests open until the network healed, long after its peers had fenced its log.
- **Evidence:** in s3-partition, the longest shard outage was 12.0 s.
- **Fix:** a watchdog fail-stops (exit 5) once the lease has been invalid for longer than 2 × skew.
- **After the fix:** s3-partition's longest shard outage is 4.4 s.

**N5 – A zombie resurrected its own lapsed lease.** Severity: high (availability; it amplified N6). File: `cluster.rs`.

- **Cause:** after a SIGSTOP, the renew loop's CAS on our own lease object succeeds, because nobody else writes it, even though peers have already fenced our log. Peers then count the dead node as live for another TTL. They shrink their fair share and release the shards they had just taken over: n3 released 10 shards 20 ms after opening them, and they sat unowned for about 3 s.
- **Evidence:** `final` (pre-fix binary)/zombie-short. n3 logged `releasing extra shards owned=32 fair=22 live=3` right after taking n2's shards with live=2.
- **Fix:** never renew a lease that has already lapsed; fail-stop instead.

**N6 – Stale worker repo cache across a shard bounce: firehose chain break and permanently unloadable repos.** Severity: **critical** (data corruption). Files: `node.rs`, `nodelog.rs`. The root cause is in `worker.rs`, which is not in my ownership.

- **Cause:**
  - A repo load in flight when `close()` purged the workers completes afterwards and re-caches the repo, still bound to the closed shard.
  - Writes then build commits on that cached state. The cached head advances, but the entries cannot be durably applied.
  - When the node later takes the shard back, the next durable commit chains on those never-logged commits.
- **Evidence:** `final` (pre-fix binary)/zombie-short, combined with N5's bounce.
  - n3 logged 25 rejected log entries for shard 51 (my N7 guard), then re-acquired shard 51.
  - The checker reported `chain_since` and `chain_prevdata` failures for two repos: the `since` named a rev that was never on the firehose.
  - On the next owner both repos failed every load with `rebuilt MST root … != head data …`. That is a 20 s outage window that never recovers for those repos: their stored records no longer match their head.
- **Fix:**
  - `open_many` purges every worker's cache for a shard before serving it.
  - `close()` purges again after the drain.
- **After the fix:** zombie-short passes 4 out of 4 (`final`, `final-rep` ×2, `final2`), and so do all the rebalance scenarios.
- **Still wanted:** a fix in `worker.rs`, so that a `Loaded` result whose shard has since changed (`Arc::ptr_eq` against the current partition) is dropped. The lead has queued it.

**N7 – Writes for a shard the node no longer holds were acked but never replayable (lost acked writes).** Severity: high. File: `nodelog.rs` (`Open::push`).

- **Cause:** such an entry got epoch 0 and was acked. Replay applies only entries whose epoch matches a span, so the successor never saw it.
- **Fix:** reject the entry (the ack fails, so the client gets an error) instead of logging it under epoch 0.
- **Evidence:** this is the path the N6 race took (25 rejections). Without the guard, those 25 writes would have been acknowledged and lost.

**N8 – A half-open peer log stream hung the follower forever: a permanent firehose stall after a network partition.** Severity: high. File: `remote.rs`.

- **Cause:**
  - `stream_live` awaited `ws.next()` with no timeout. The follower only re-checks whether its peer is alive after the socket ends.
  - With `docker network disconnect`, the dead peer never sends a FIN or RST, so the survivors never drained its log to the fence.
  - The native faultproxy tests miss this because healing the proxy releases the held connection.
- **Evidence:** `final-ctr/ctr-partition`. n1 and n3 were each missing 24,499 acked creates, and neither logged "dead peer log drained", although n3 had fenced n2's log at ordinal 3045.
- **Fix:** a 2 s idle timeout on the stream (heartbeats come every 5 ms), and a 2 s connect timeout.
- **After the fix:** `final2-ctr/ctr-partition` passes with 0 missing, and so do peer-partition, full-partition, the zombies and handoff-firehose (`final2`).

**N9 – Survivors stacked extra fences on an already-fenced log.** Severity: low. File: `cluster.rs` (`fence`).

- **Cause:** a second survivor's LIST counted the first survivor's fence object as a segment and wrote another fence after it.
- **Evidence:** `new-smoke2/kill9-1of3` (n1 fenced at 2742, then n3 at 2743).
- **Fix:** if the last object is already a fence, its ordinal is the log's end.
- **After the fix:** every survivor used the same end ordinal (`kill9-mid-checkpoint`: 1284 on both).

## Open issues

**O1 – Firehose seam on a node that just (re)started.** Severity: medium. Files: `remote.rs`, `firehose.rs`. **Fixed** (see "O1 fix and re-run" below).

- **Cause:**
  - A first-time follower skips every peer batch broadcast before its subscription, but the ring floor is set from the first merged batch.
  - Another peer's skipped events can have seqs above that floor, so they are in neither the ring nor the S3 backfill.
  - Live subscribers of the new node miss them too.
- **Evidence:**
  - `final/kill9-2of5` (pre-fix run): n3's replay is missing 15 commits, all in 07:19:10.843–.878, at n3's join.
  - `final/rolling-restart` (pre-fix run): the cursor checker on n2 reports `chain_since` FAILs for 4 repos, at 07:22:34.55–.73, just after n2 restarted.
  - `final2-ctr/ctr-skew-small`: 74 missing on the rejoined n2.
  - Nodes that stayed up are unaffected, and so is every acked write.
- **Suggested fix:** use max over the initial followers of their first heartbeat watermark as the start floor. Drop events at or below it, and let the S3 backfill serve them.

### O1 fix and re-run (`o1fix`)

- **Root cause, confirmed.** Two holes, both in `remote.rs`:
  - A first-time follower (no known ordinal) skipped everything its peer broadcast before the subscription, while the ring floor came from the first merged batch. A peer subscribed later lost its events in between: in neither the ring nor the backfill (<= floor). The new in-process test reproduces it every run on the old code (thousands of events missing on a joining node).
  - The S3 catch-up on reconnect started right after the websocket handshake, but the owner subscribes only after the upgrade. A batch PUT in between was in neither, and the first heartbeat already covered it. That is also why the suggested max(w0) floor alone would not do: the finalizer broadcasts a batch before it advances the watermark, so w0 can trail a batch the subscription missed.
- **Fix:**
  - The merged stream starts at a floor F, the clock at startup. The ring floor starts at F, and cursors <= F backfill from S3 once the merger's min watermark has passed F (so every log's events <= F are in S3).
  - Every follower owes every event of its log above its floor: F for the followers registered by the first step (the merger starts only after it), or the merger's position when a later log is followed (`Firehose::add_remote`, taken under the sources lock). Its first ordinal is the first segment in S3 past that floor (`backfill::seek`).
  - On every (re)connect, the follower waits for the owner's first message, so it knows it is subscribed, then catches up from S3 and dedupes by ordinal. A dead log is drained to its fence even if it was never streamed.
  - The merger drops events at or below its position. Events <= F are expected; any above it are logged as late.
- **Harness:** every survivor's cursor replay is now judged, including rejoined and late-joined nodes, and all must agree. New `audit_from_start` attaches a live audit the moment a node (re)starts. It must match a stayed-up node's replay over its range, with no gaps. kill9-2of5 and grow-1-to-3 also run a cursor checker on the (re)started node.

| Scenario | Verdict | Acked / lost | Checker / cursor checker | Replay missing (all survivors) | Live audit from (re)start | History agree |
|---|---|---|---|---|---|---|
| kill9-2of5 | PASS | 55453 / **0** | PASS / n3 PASS | all 0 (55270 commits on every node, n3 and n4 rejoined) | n3, n4: identical to n1 (23.9k commits each) | yes / yes |
| rolling-restart | PASS | 37767 / **0** | PASS / n2 PASS | all 0 (37738 on every node, all rejoined) | n2, n3, n1: identical to n1 (31.0k / 22.2k / 13.7k) | yes / yes |
| grow-1-to-3 | PASS | 15037 / **0** | PASS / n3 PASS | all 0 (15035 on every node, n2 and n3 joined mid-run) | n2, n3: identical to n1 (12.4k / 9.7k) | yes / yes |

No merger late-event warnings and no follower stream gaps in any node log. Tests: `tests/all/firehose_startup.rs` (4 nodes join one by one under load; each node's cursor-0 subscriber attached at its start, live subscriber attached at its start, and post-hoc cursor-0 replay must equal the union of all logs in S3).

**O2 – Forwarded requests hang for up to 15 s on an owner that accepts TCP but doesn't respond** (the rest of B8). Severity: medium (availability). Files: `forward.rs` and the client in `server.rs`.

- **Affected scenarios:** peer-partition, full-partition, zombie, ctr-pause and ctr-partition all show a 12–15 s window with very few failed probes.
- **Cause:** those are requests hung on the frozen or unreachable owner. Takeover itself happens at about 3.6 s, and new requests route to the new owner.
- **Possible fix:** a time-to-first-byte deadline for buffered JSON requests (for example 3–5 s, returning 503). Streaming blob uploads need the long timeout.
- **Why it wasn't changed here:** it changes client-visible semantics (at-least-once on retry).

**O3 – Lease liveness compares wall clocks across nodes.** Severity: medium (availability only). File: `cluster.rs`. **Fixed** (O3–O6 round): peers judge liveness by seeing a lease change, timed on their own monotonic clocks. Handoffs carry a `seq_floor`, so a new owner whose clock is behind commit-waits. ctr-skew-large and ctr-skew-steady pass.

- **Cause:** a node whose clock is behind by more than the skew margin (TTL/5) looks dead to its peers between renewals, and gets fenced repeatedly. Safety holds: SlateDB fencing plus log fencing, and the node exits 3.
- **Evidence:** `ctr-skew-large`; see above.
- **Possible fix:** peers could judge liveness by observing the lease object *change* (ETag or version), timed on their own monotonic clock. With that, no cross-node wall-clock comparison is needed.

**O4 – Renewal-RTT ceiling.** Severity: low. **Documented**: the `--lease-ttl-ms` help text, a startup warning below 10 s outside dev mode, and DESIGN.md. The CLI default is 10 s. Validity has gaps once the renewal RTT exceeds (TTL − skew)/2 (1.2 s at TTL 3 s, 4 s at TTL 10 s). A cluster-wide S3 brownout above that fail-stops every node at once (s3-slow-all). That is inherent to sequential CAS renewals; keep the TTL at 10 s or more in production.

**O5 – Control-plane GET volume (observation).** Severity: low. **Fixed**: LIST plus an ETag cache, 130 → 2.3 req/s per node at TTL 10 s with 256 shards. Every node reads every assignment object on every step (renew/5 of TTL). At 256 shards and the production TTL of 10 s, that is about 128 GET/s per node: roughly $130/month per node on S3 Standard. That is fine at 5 nodes, but at planet scale a LIST plus an ETag cache, or a single assignment-map object, would be better.

**O6 – Graceful drain cost (observation).** Severity: low. **Fixed**: `close_many` puts one barrier segment under every shard being released. Closing a shard writes a barrier segment and a checkpoint flush. Draining 256 shards on SIGTERM takes about 3.4 s (one segment PUT per shard). Batching the barriers would make that one PUT.

## Code changes (HA files only)

| File | Change |
|---|---|
| `src/cluster.rs` | N1, N2, N3, N4, N5 and N9, plus `acquired shards` / `releasing extra shards` logs. The unit test now keeps b renewing while a's lease runs out, since a node that stops renewing now fail-stops. |
| `src/node.rs` | N6: `purge_worker_caches` on open, and again at the end of close. |
| `src/nodelog.rs` | N7: reject entries for shards we don't hold. Also the `checkpoint start` log line. |
| `src/remote.rs` | N8: stream idle and connect timeouts (2 s). |
| `src/firehose.rs` | A diagnostic warning when the merger emits an event at or below the already-emitted watermark. It never fired. Another agent's S3 backfill also landed in this file during this work. |
| `bench/ha/*` | The harness changes above; the new scenarios `kill9-rebalance-drainer`, `kill9-rebalance-joiner`, `zombie-check`, `s3-5xx-all`, `s3-slow-one-long`, `kill9-mid-checkpoint` and `grow-1-to-3`; the Dockerfile now copies `lexicons/` and `ui/dist` (new compile-time inputs). |

**O3–O6 round:**

| File | Change |
|---|---|
| `src/cluster.rs` | O3: observed-change liveness (per-peer ETag/`renewals` seen time on the observer's monotonic clock); dead once fenced; fail-stop when a held shard is reassigned. Writer claims are taken over only from holders without a lease, and confirmed by CAS. `Assignment.seq_floor`, plus the dead log's last seq from `fence()`. O5: LIST + ETag assignment cache, a 150-step full resync, releases CAS against the cache, and the `vlpds_cluster_store_requests_total` counter. O6 and the review fix: `close_and_release` (batched close, no release after a failed close; fail-stop), and `quiesce` before shutdown fences. New unit tests: `failed_close_is_not_released`, `skewed_clocks_stay_live`, `dead_peer_with_future_clock_is_taken_over`, `steady_state_reads_are_cheap`. |
| `src/node.rs` | `close_many` (sink-keyed, one barrier segment, one deadline, concurrent checkpoints), `wait_seq_floor` (commit-wait, capped at 30 s), `seq_high`, `quiesce`. |
| `src/main.rs` | `--lease-ttl-ms` documents the renewal RTT ceiling; a warning when it is below 10 s outside dev mode. |
| `src/metrics.rs`, `src/xrpc/webui.rs` | The counter; `NodeLease.renewals`. |
| `tests/all/ha_liveness.rs` | 3 in-process nodes with ±4 s control-plane clock offsets (TTL 1.5 s) under writes: nobody fenced, fair shares held, a graceful drain moves shards in one batch. |
| `bench/ha/hactl.py` | `cp_req_per_s` per node, live-audit settle by the clock spread, the new scenario `kill9-rebalance-joiner-after-writes`. |

`cargo test --lib`: 59 passed.
