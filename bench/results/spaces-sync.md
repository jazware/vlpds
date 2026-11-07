# Spaces sync micro-bench

Run on 2026-10-05 at `spaces-1` 3ebf852d (C1 through C7 plus the side lane), alone on
benchbox (Ryzen AI Max+ 395, 16C/32T, 62 GB, rustc 1.99.0) between batch pipeline runs,
under a 16 GB memory cap. Every target is met and nothing needed fixing.

These numbers are from the October 1 Spaces wire. Since the November 5 one, a credential
read of a commit or record (getLatestCommit, getRepo, listRepoOps, getRecord) derives a
per-request secret by ECDH against the account's `#atproto_kem` key and answers an HMAC
instead of a commit signature, getRepo is a STAR archive, and members are managed with
`com.atproto.memberspace.putMember`. Re-measure before comparing against them.

## How to run

```text
cd packages/vlpds
systemd-run --user --scope -p MemoryMax=16G env CARGO_TARGET_DIR=<target> \
  cargo test --profile dev-release --features bench-jemalloc --test all \
  spaces_side::bench::spaces_microbench -- --ignored --nocapture --test-threads=1
```

`just spaces-microbench` runs the same thing. It's one in-process node with
`--spaces` on and an in-memory bucket, and its log segment PUTs are delayed like S3
(`SPACES_BENCH_PUT_MS`, 25 ms median, lognormal sigma 0.3). Below 5 ms the delay is a
thread sleep, since tokio's timer rounds up to whole milliseconds. Metrics are
process-wide, so nothing else may run in that test binary at the time.

Knobs (env):

| Variable | Default | What |
|---|---|---|
| `SPACES_BENCH_ONLY` | `noop,delta,cred,conc,bucket,load` | sections to run |
| `SPACES_BENCH_SECS` | 20 | each timed window of `bucket` and `load` |
| `SPACES_BENCH_REQS` | 20000 | sequential no-op polls |
| `SPACES_BENCH_DELTA` / `_DELTA_REQS` | `1,10,100` / 2000 | delta sizes K, pulls per K |
| `SPACES_BENCH_CREDS` | 200 | fresh credentials for the miss path |
| `SPACES_BENCH_CONC` | `1,4,16` | concurrent writers on one account (`conc`) |
| `SPACES_BENCH_N` / `_M` / `_K` | 20 / 5 / 3 | spaces, members per space, pollers per space |
| `SPACES_BENCH_SYNCERS` | 1 | registered syncers per space, each pulling on every notify |
| `SPACES_BENCH_POLL_MS` / `_WRITE_MS` | 1000 / 500 | poll interval, space write interval per writer |
| `SPACES_BENCH_PUBLIC` | 16 | public writers posting back to back |

Members (`_M` > 0) need simplespace `putMember` (C3), and syncers need
`registerNotify` and fan-out (C3, C4). With only C1 in, run with
`SPACES_BENCH_M=0 SPACES_BENCH_SYNCERS=0`.

## What each number means

- No-op poll: `listRepoOps` with `since` at the head. The client loop is
  sequential over loopback. Server CPU per request is the process CPU of that
  loop minus the same loop against `/xrpc/_health`, so the client's share and
  the HTTP stack mostly cancel out. The server histogram
  (`vlpds_space_list_repo_ops_seconds{path="noop"}`) is handler time after auth.
- Delta pull: `listRepoOps` returning the last K ops with values, so a scan of K
  `sO` rows joined to `sR`.
- Credential miss vs hit: the first use of each of 200 fresh credentials, then
  one credential reused. Before C2 there's no cache and both rows verify the
  whole chain.
- One repo, C concurrent: C writers on one account back to back for half a
  window, public `createRecord` and then space `createRecord`, with log segment
  PUTs per write. A space write should share segments the way a public one does.
- Bucket ops per space write: object-store requests by op and component
  (`vlpds_object_store_requests_total`) while 16 public writers run, first alone
  and then with space writes on top. Added PUTs per space write is the PUT rate
  difference over the space write rate. That moves with the public commit rate,
  so the bench also prints PUTs per write of either kind, which drops when space
  writes share segments with public ones.
- Public commit p99 under load: client-side `createRecord` latency for the
  public writers, alone and then with N x M space writers, K pollers per space
  and the syncers' notify-driven pulls running.

## Targets and the reference baseline

The targets are from the phase 1 brief. The reference column is the Mac
harness's client-side numbers for the reference PDS at 5b95b2f2.

| | Target | Reference PDS |
|---|---|---|
| No-op poll | well under 1 ms of server time | 6.7 ms p50 |
| Delta pull | a few ms | 8.3 ms |
| Notify (write to syncer) | | 4.5 ms p50, 8.3 ms p99 |
| Added bucket PUTs per space write | 0 | |
| Public commit p99 under space load | unchanged | 29 ms to 39 ms |

## Results

One full run with the defaults, then `SPACES_BENCH_ONLY=load SPACES_BENCH_SECS=30`
three more times (the public p99 rows) and `SPACES_BENCH_ONLY=conc` (the one-repo
rows, which came later). Log segment PUTs are delayed 25 ms median, so any write's
latency is mostly waiting for its segment.

| Measurement | p50 | p99 | CPU/req |
|---|---|---|---|
| No-op `listRepoOps`, client | 0.165 ms | 0.288 ms | 178 µs process, ~143 µs above `_health` |
| No-op `listRepoOps`, server histogram | 0.05 ms (mean 0.014 ms) | 0.099 ms | |
| No-op `listRepoOps`, client, cold signing key | 0.195 ms | 0.636 ms | |
| Delta pull K = 1, client | 0.180 ms | 0.398 ms | 204 µs |
| Delta pull K = 10, client | 0.216 ms | 0.732 ms | 277 µs |
| Delta pull K = 100, client | 0.522 ms | 0.927 ms | 561 µs |
| Delta pull K = 1 / 10 / 100, server histogram | 0.05 / 0.05 / 0.30 ms | 0.10 / 0.19 / 0.42 ms | |
| Credential miss (full chain), 200 fresh | 0.298 ms | 0.449 ms | 317 µs |
| Credential hit (cache), 1,000 | 0.241 ms | 0.519 ms | 261 µs |
| Polls under the load (all deltas), client | 0.44 ms | 1.0 ms | |
| Member write ack to authority ack (`vlpds_space_notify_ack_seconds`) | 52 ms | 125 ms | |
| Member write sent to syncer notified | 93 ms | 142 ms | |
| Syncer notified to pull done | 1.9 ms | 5.5 ms | |

CPU/req is process CPU (client and server share it) over the loop. The cache counter
showed 200 misses then 1,000 hits, so the two credential rows measure what they say.
The hit row costs more CPU than the no-op row above it although it's the same request.
It's 1,000 requests right after the miss phase against 20,000, so that's noise.

Write ack to authority ack is one more durable entry (the authority's `sW`/`sQ`
entry), so it costs what a public commit does (52 ms against 54 ms here). Write sent to
syncer notified is two of them in a row, ~93 ms.

| Bucket ops (16 public writers, 20 s windows) | Alone | With space writes |
|---|---|---|
| Commits/s, space writes/s | 285.5, 0 | 288.9, 219.9 |
| PUT/s (all) | 40.79 | 39.60 |
| Log segment PUT/s | 35.69 | 36.15 |
| Added PUTs per space write | | -0.005 (0 within noise) |
| PUTs per write (public + space) | 0.143 | 0.078 |

| One repo, C concurrent writers | Public PUTs/write | Space PUTs/write | Public p50 / p99 | Space p50 / p99 |
|---|---|---|---|---|
| 1 | 1.000 | 1.000 | 28.0 / 52.0 ms | 27.7 / 51.8 ms |
| 4 | 0.500 | 0.501 | 55.4 / 83.4 ms | 53.9 / 85.7 ms |
| 16 | 0.125 | 0.126 | 52.3 / 89.4 ms | 52.3 / 85.4 ms |

Space writes to one repo share segments exactly like public ones at S3 latency. With
fast PUTs they don't quite, and the next section has why.

### Fast PUTs (one repo, 4 concurrent)

The Mac harness on MinIO (sub-ms PUTs, one account, 300 writes, 4 at a time) measured
0.94 segment PUTs per space write against 0.60 for public writes. At the default 25 ms
the in-process bench can't see that, and asking it for 0.5 ms didn't help either: tokio's
timer rounded the delay up to 1-2 ms. With the delay as a thread sleep, it shows up.

Run on 2026-10-05 at `spaces-2b` on top of 007c36e0, alone on benchbox between batch pipeline
runs, `SPACES_BENCH_ONLY=conc SPACES_BENCH_CONC=4 SPACES_BENCH_SECS=10`, two runs each of
the old and new binary in alternating order (the means below). "Public" posts with a session
token, as the harness's public writer does. "Public over OAuth" posts with a DPoP-bound OAuth
token, which every space write needs.

| PUT delay | Public | Public over OAuth, before → after | Space, before → after | Space p50, before → after |
|---|---|---|---|---|
| 0 | 0.764 | 0.982 → 0.989 | 0.993 → 0.993 | 0.358 → 0.285 ms |
| 0.1 ms | 0.542 | 0.791 → 0.717 | 0.776 → 0.670 | 0.597 → 0.538 ms |
| 0.2 ms | 0.503 | 0.657 → 0.602 | 0.616 → 0.557 | 0.758 → 0.652 ms |
| 0.3 ms | 0.501 | 0.581 → 0.535 | 0.555 → 0.515 | 0.881 → 0.815 ms |
| 0.5 ms | 0.500 | 0.519 → 0.507 | 0.507 → 0.503 | 1.227 → 1.243 ms |

Space writes track public writes over OAuth at every delay, so the space write path isn't
what's missing segments. The worker already builds a repo's next space entry while the one
before it is in flight, the same as a commit, and server time from the handler to the ack
was ~80 µs at no delay against ~120 µs for a public commit.

The gap is the OAuth check. A writer's requests only share a segment if they reach the log
while a PUT is in flight. A DPoP-bound request spent ~186 µs in auth (~145 µs checking the
proof, nearly all of it the P-256 signature, and ~30 µs reading the session and account)
against ~1 µs for a session token. That spreads the four writers' arrivals out, so with PUTs this fast fewer of them
line up behind one. The harness also signs a DPoP proof per request on the client side,
which spreads them out further.

"After" checks ES256 signatures with ring instead of the p256 crate. That's ~30 µs a
signature instead of ~110, and it took OAuth auth from ~186 µs to ~86 µs a request. Space
writes at 0.2 ms went from 0.62 to 0.56 PUTs per write, and every OAuth request got
~100 µs cheaper. The brief's target (space within 0.05 of public at 0.5 ms) is met by both
binaries: 0.507 and 0.503 against 0.500.

What's left is the session and account reads and the client's own signing. At 0.1 ms and
below, any OAuth writer pays for them. For the harness, comparing space writes with public
writes made over OAuth isolates the space path.

| Public commit latency (16 writers) | Alone p50 / p99 | With the spaces load p50 / p99 |
|---|---|---|
| Run 1 (20 s) | 54.5 / 80.3 ms | 53.4 / 87.4 ms |
| Run 2 (30 s) | 54.2 / 85.6 ms | 53.1 / 84.6 ms |
| Run 3 (30 s) | 53.9 / 85.3 ms | 54.5 / 82.6 ms |
| Run 4 (30 s) | 53.7 / 85.9 ms | 53.6 / 85.3 ms |

The load is 20 spaces x 5 members x 3 pollers a second, one syncer per space pulling
on every notify, and a space write every ~0.5 s per writer (~220 space writes/s,
~5,500 notifies in 30 s, all delivered, no retries). Run 1's +7 ms p99 didn't repeat
in the next three runs, so public commit latency is unchanged.

### Targets

| | Target | Measured | |
|---|---|---|---|
| No-op poll | well under 1 ms of server time | ~0.014 ms handler mean, ~143 µs CPU end to end, 0.29 ms p99 client | met |
| Delta pull | a few ms | 0.4 / 0.7 / 0.9 ms p99 client for 1 / 10 / 100 ops | met |
| Added bucket PUTs per space write | 0 | -0.005, and 0.50 vs 0.50 at 4 on one repo | met |
| Public commit p99 under space load | unchanged | 85.6 / 85.3 / 85.9 ms alone vs 84.6 / 82.6 / 85.3 ms with | met |

The flag-off comparison against main (the benchbox A/B grid) is in
`docs/spaces/operating.md` under "What it costs".

### Notify on a cluster with fast PUTs

The Mac harness saw notify p99 go from 5.5 ms to 18 ms between two runs (p50 1.7 → 0.68 ms).
The bench's `cluster` section measures the same path in process: a member writes on one node,
its outbox tells the authority on another node, the authority sequences it in a durable entry and
forwards it to the space's syncers. Run on 2026-10-05 at `spaces-2b` (f6b0dd25), 20 spaces x 5
members, `SPACES_BENCH_ONLY=cluster`, with the thread-sleep PUT delay.

| PUT delay, syncers per space | Writes | Write ack to authority ack p50 / p99 | Write sent to syncer notified p50 / p99 / max | Notified to pulled p50 / p99 |
|---|---|---|---|---|
| 0.5 ms, 1 (20 s) | 4,785 | 0.89 / 1.99 ms | 2.12 / 3.51 / 4.58 ms | 0.58 / 1.22 ms |
| 0.5 ms, 3 (15 s) | 3,591 | 0.99 / 2.83 ms | 2.19 / 3.74 / 8.26 ms | 0.45 / 1.17 ms |
| 25 ms, 1 (20 s) | 4,421 | 46.6 / 120 ms | 82.2 / 135 / 154 ms | 2.1 / 7.8 ms |

Write sent to syncer notified is two durable entries (the member's and the authority's) and
three HTTP hops, so ~2 ms at 0.5 ms PUTs. Every send succeeded, nothing was retried, and the
outbox folded ~17% of the writes into a later notify of the same repo. Across ~5,000 notifies
the slowest took 4.6 ms with one syncer and 8.3 ms with three, so an 18 ms p99 doesn't show up
here. The 25 ms row matches the earlier run (93 / 142 ms). Nothing on the outbox or fan-out path
needed fixing. If the harness run is small, its p99 is its slowest one or two notifies, and a
cold connection or signing key is enough for that, so it's worth re-measuring there on a quiet box.

### createAccount under the benchbox methods sample

The A/B's methods sample showed `createAccount` (64 in flight, right after the `createRecord`
phase) with a second mode at ~250-300 ms. It was in 4 of 4 runs of `3ebf852d` (p99 286 / 298 /
247 / 227 ms) and 1 of 4 runs of `36f0be7b` (p99 290 ms). It comes from the bench's MinIO disk,
and vlpds and `--spaces` have nothing to do with it.

`bench/benchbox/catail.py` reproduces it. It runs `createAccount` alone and then `createRecord`
followed by `createAccount`, three times on one node, and samples `/metrics`, the host's dirty
pages, the NVMe's counters and MinIO's CPU every 0.5 s. Here's createAccount's p99 per phase
(`spaces2c-ca-tail-2026-10-05`):

| Build | MinIO data | createAccount p99 per phase (ms) |
|---|---|---|
| `3ebf852d` (Spaces) | disk | 78 · 289 · 311 · 83 · 160 · 128 |
| `36f0be7b` (main) | disk | 71 · 242 · 326 · 82 · 605 · 85 |
| `3ebf852d` (Spaces) | tmpfs | 66 · 68 · 68 · 69 · 68 · 68 |

So main shows the mode as often as the Spaces build does, and it doesn't need to follow a
`createRecord` phase directly (phases 3 and 5 are `createAccount` alone). With MinIO's data on a
tmpfs it's gone from all six phases, and the max stays under 100 ms.

The slow stretches last 2-6 s. In each one, every bucket PUT on the node gets 3-10x slower. The
handle and email claims (`account_index` put_create) go from ~8-16 ms to 50-130 ms, and segment
PUTs from ~7-13 ms to 40-50 ms. Meanwhile the NVMe sits at ~93% busy while writing only ~27 MB/s
(~60% and ~75 MB/s otherwise), MinIO's CPU drops from ~3.2 cores to ~0.7 because it's waiting on
fsync, and the host's dirty pages keep growing. Each stretch ends with a writeback burst of
~300 MB/s that drops the dirty pages from ~200 MB to ~60 MB. SlateDB compaction isn't the cause.
The longest stretch had no compaction reads at all, and 40 s of steady compaction later had none.

`createAccount` shows it more than any other method because it waits on the most PUTs: two
conditional claim PUTs (in parallel with the Argon2 hash) and then the account's segment PUT. Its
p50 is ~56 ms, mostly Argon2, so 50-100 ms more of PUT latency moves a few hundred requests a
second into the tail. In production the bucket is R2 or S3, which doesn't fsync on the PDS's own
disk, so there's nothing here to fix in vlpds. For A/Bs of the account path on benchbox, alternate the builds and
count a run as an outlier only when both builds show the mode, or run MinIO on a tmpfs
(`MINIO_TMPFS=4g`).
