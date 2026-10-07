---
title: Configuration
section: Operations
order: 103
status: ready
summary: "The flags that matter, the memory budget and how caches size themselves, shard count and lease TTL, and the trade-offs behind the defaults."
---

```hero
diagram:
  caption: "How a node sizes its memory. Fixed costs come off the top of the budget; the cache pool goes first to the SST metadata cache (what the owned shards need), then evenly to the block and repo caches. It is re-planned every 5 s as shards come and go."
  nodes:
    - { id: limit, label: memory limit, sub: cgroup memory.max or RAM, at: [0, 3.5], size: [10, 3] }
    - { id: budget, label: budget, sub: "`--memory-budget-mb`", at: [13, 3.5], size: [8, 3], tone: accent }
    - { id: fixed, label: fixed costs, sub: "rings · buffers · headroom", at: [25, 0], size: [10, 3], tone: muted }
    - { id: pool, label: cache pool, sub: the rest, at: [25, 7], size: [10, 3], tone: accent }
    - { id: meta, label: SST metadata, sub: "filters · indexes, first", at: [39, 3.2], size: [10, 2.6], tone: blue }
    - { id: block, label: SST blocks, sub: half of the rest, at: [39, 7.2], size: [10, 2.6], tone: blue }
    - { id: repo, label: repo cache, sub: "MST paths, other half", at: [39, 11.2], size: [10, 2.6], tone: blue }
  edges:
    - limit -> budget
    - budget.r -> fixed.l
    - budget.r -> pool.l
    - pool.r -> meta.l
    - pool -> block
    - pool.r -> repo.l
facts:
  - { value: "1", unit: number, label: to set for memory, note: "the container's memory limit; every cache sizes itself from it" }
  - { value: "~1.4 GiB", label: of caches in 3 GiB, note: "a small VPS (tiny profile); ~16 GiB in a 32 GB standard node", tone: blue }
  - { value: "64 / 1", unit: shards, label: standard / tiny, note: "set once per prefix; split and merge online after", tone: amber }
  - { value: "10 s / 60 s", label: lease TTL, note: "takeover after a crash ~12 s; a lone node's crash restart ~53 s", tone: violet }
```

Most deployments only set a few things. There's the identity (`--public-url`, `--handle-domain`,
`--service-did`), the bucket, the secrets, a memory limit, and the profile's shard count and lease
TTL. Everything else has a measured default. The settings below are the ones that change how a node
behaves, each with the trade-off behind its default.

> [!WARNING]
> `--public-url` is also the passkeys' relying party. The browser binds each passkey to its host, and
> vlpds only accepts an assertion made on exactly that origin. Changing the hostname makes every passkey
> on the PDS stop working (users fall back to their password with TOTP or a recovery code). Passkeys also
> don't work on any other address of the node, such as the tailnet console's, so the account page hides
> them there. See [Passkeys](../oauth-2fa.md#passkeys).

## Where configuration comes from

```diagram
caption: "The sources a node reads at start, and the settings that live in the bucket instead. `--shards` only applies to a new prefix; afterwards the layout stored in `assign/layout` wins."
nodes:
  - { id: flags, label: flags, sub: "`vlpds --help`", at: [0, 0], size: [8, 3] }
  - { id: env, label: "`VLPDS_*` env", sub: one per flag, at: [0, 4], size: [8, 3] }
  - { id: files, label: secret files, sub: "`VLPDS_*_FILE`", at: [0, 8], size: [8, 3] }
  - { id: ref, label: "`PDS_*` env", sub: reference PDS fallbacks, at: [0, 12], size: [8, 3], tone: muted }
  - { id: node, label: vlpds node, at: [14, 0], size: [8, 15], tone: accent }
  - { id: bucket, label: bucket, sub: "layout · rate limits\ncrawlers · feature level", at: [28, 5], size: [10, 5], shape: store, tone: amber }
edges:
  - flags -> node
  - env -> node
  - files -> node
  - "ref ~> node"
  - "bucket <-> node: live settings"
```

- Every flag has a `VLPDS_*` variable (`--lease-ttl-ms` is `VLPDS_LEASE_TTL_MS`). A few tuning
  flags don't have one (`--firehose-ring-mb`, `--max-segment-mb`, `--cache-per-worker`), so the
  Ansible role passes those as command arguments.
- Every secret can also come from a file, with a `--<secret>-file` / `VLPDS_*_FILE` form. That
  covers the JWT secret, the admin and internal tokens, the S3 keys, the SMTP URLs, the rate-limit
  bypass key, the KEK, the PLC rotation key, GCP credentials and the Vault AppRole role ID (the Vault token,
  secret ID and service-account token only come from files). Use the files in production, since
  environment variables show up in `docker inspect`. The node refuses to start if a file is empty or
  unreadable, or if both forms are set. The Vault credential files are read later, at each login or token
  refresh, and a missing `--vault-token-file` only defers the Vault check (a Vault Agent may not have
  written it yet). The procedure is RUNBOOK "Secrets as files".
- Where the reference PDS has a setting, its `PDS_*` variable works as a fallback
  (`PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`, `PDS_EMAIL_SMTP_URL`, `PDS_INVITE_INTERVAL`, ...), so
  an existing `pds.env` mostly carries over.
- Some settings live in the bucket. The shard layout, the active feature level, the rate-limit config
  and the relay list are cluster-wide, and you change them at runtime from the
  [admin console](admin-console.md) or `vlpds admin`. A crawler list set in the console overrides
  `--crawlers` until it's reset.
- To check a config, run `vlpds --memory-plan` with the same flags. It prints the memory plan as JSON
  and exits non-zero if it doesn't fit. At start, the node logs its threads, memory budget, cache caps
  and disk-cache size.

## Memory budget and autosizing

The budget is the node's memory limit. That's the tightest cgroup `memory.max` above the process (a
container's `--memory`), or physical RAM if there isn't one. `--memory-budget-mb` lowers it, in MiB or
as a percentage (`80%`). Set the container limit and leave the cache flags alone.

| Fixed cost | Size | Flags |
|---|---|---|
| Runtime | 256 MiB | threads, connection buffers, allocator |
| In-memory caches | 10% of the budget | `--cache-budget-mb` for tokens, DID docs, OAuth clients, ... (`--cache-entries` caps one) |
| MST node cache | 256 MiB (tiny: 64) | `--lazy-mst-node-cache-mb` |
| Firehose | ring + live ring + merge queue: 512 + 128 + 256 MiB (tiny: 64 + 32 + 32) | `--firehose-ring-mb`, `--live-ring-mb`, `--firehose-merge-queue-mb` |
| Backfill | cache + read-ahead × backfills: 256 + 64 × 16 MiB (tiny: 32 + 16 × 4) | `--backfill-cache-mb`, `--backfill-readahead-mb`, `--firehose-max-backfills` |
| Exports | ~8 MiB per getRepo stream + their read-ahead pool: 32 streams (tiny: 4) | `--max-exports` |
| Imports | 1/16 of the budget, 192 MiB to 1 GiB | `--import-memory-mb` |
| Space exports | with `--spaces`, room for 4 full-size `space.getRepo` streams: 4 × (128 B per record × 100,000 + 1 MiB), ~53 MiB | `--space-repo-max-records` |
| Headroom | 15% of the budget, at least 512 MiB | memtables, request bodies, allocator slack |

What's left is the **cache pool**, and it's split in this order:

1. The SST metadata cache comes first. Every point read checks a bloom filter per sorted run, so the
   filters and indexes of every owned SST have to fit. Otherwise reads fetch whole filters from the
   store. The target starts at what the owned SSTs need, measured from their manifests. That's
   multiplied by N/(N−1) for N live nodes (room to take over a dead peer's shards, at most ×2) and by
   1.25 for compactions in flight.
2. The SST block cache and the repo cache split the rest evenly. The repo cache holds the loaded MST
   paths of recently written repos (~10–20 KB each, ~3 KB once trimmed back to the root).

A background thread re-plans every 5 s. A larger target applies at once, but a smaller one waits
until it has held for 5 minutes, so a takeover and its hand-back don't thrash the caches. A cache
given an explicit size (`--meta-cache-mb`, `--block-cache-mb`, `--repo-cache-mb`) keeps it, and the
node refuses to start if the explicit sizes don't fit the budget.

| Node | Budget | Fixed | Pool | Initial split (meta / block / repo) |
|---|---|---|---|---|
| tiny profile, 3 GiB limit (small VPS) | 3 GiB | ~1.6 GiB | ~1.4 GiB | ~160 / ~630 / ~630 MiB |
| standard, 32 GB host | ~27 GiB (85%) | ~11 GiB | ~16 GiB | the metadata cache grows with the owned SSTs |

When the pool can't hold the metadata target, the node logs an error and `VlpdsSstMetaCacheTooSmall`
fires. Give the node more memory or add nodes. Watch `vlpds_memory_cache_bytes{cache, kind}` (target,
capacity, used) and `vlpds_meta_cache_shortfall_bytes`. Details:
[State storage](../state-storage.md#caches), RUNBOOK "VlpdsMemoryHigh".

## Shards and lease TTL

```diagram
caption: "One lease, four numbers. The node renews by CAS every TTL/5; its own validity ends 0.8 × TTL after the last renewal was sent; a renewal slower than 0.4 × TTL fail-stops it; peers take over after 1.2 × TTL without a change."
nodes:
  - { id: r, label: renew, sub: every TTL/5, at: [0, 0], size: [8, 3], tone: accent }
  - { id: c, label: ceiling, sub: "0.4 × TTL round trip", at: [11, 0], size: [9, 3], tone: rust }
  - { id: v, label: valid until, sub: "0.8 × TTL after send", at: [23, 0], size: [9, 3], tone: violet }
  - { id: t, label: takeover, sub: "1.2 × TTL unchanged", at: [35, 0], size: [9, 3], tone: danger }
edges:
  - r -> c
  - c -> v
  - v -> t
```

| `--lease-ttl-ms` | Renew every | Renewal ceiling | Peer takeover after a crash | Lone node's crash restart, first write | Idle control-plane cost |
|---|---|---|---|---|---|
| 10,000 (default, standard) | 2 s | 4 s | ~12 s, or 3–5 s if the port refuses | ~11 s (measured) | 3 Class A per 2 s |
| 60,000 (tiny) | 12 s | 24 s | ~72 s | ~53 s (measured) | ~0.3 M Class A/mo in all |
| 300,000 | 60 s | 120 s | ~6 min | ~281 s (measured) | saves pennies more |

A graceful restart (SIGTERM) can write again in about a second at any TTL, because the node fences its
own log and deletes its lease on the way out. Only a crash waits, since the new process can't write
until its clock passes the last renewal's send time plus a TTL. Keep the TTL at 10 s or more in
production. Below that, a brief store hiccup over the ceiling stops the node. Safety never depends on
the TTL, which only decides when a takeover happens. See [Architecture](../architecture.md#leases).

The keyspace is 65,536 hash slots grouped into shards. `--shards` (default 64, at most 65,536) only
sets the initial layout of a new prefix. After that, shards split and merge online
(`vlpds admin shard-split`, or a policy with `--reshard-split-mb` / `--reshard-split-writes`).
Shard count drives the object-store bill, because each shard polls its manifest and compactor, flushes
checkpoints and runs GC whatever its load. One shard idles at ~$0 on R2, and 64 shards on one node
idle at ~$50/mo. A single node gets nothing from more shards, so the tiny profile uses 1. A cluster
needs enough shards to spread out (each node takes `ceil(shards / nodes)`), so it starts at 64. See
[Scaling and clustering](scaling-and-clustering.md#shard-split-and-merge).

`--slatedb-manifest-poll` (10 s, or 60 s on tiny) only delays picking up compaction results. A node
is its shards' only writer, so it always reads its own writes. At 60 s, a tiny node's idle Class B
requests drop by ~30%.

## Log and firehose

| Flag | Default | What it trades |
|---|---|---|
| `--log-inflight` | 4 | Segment PUTs in flight per node log, finalized in order. More hides store latency under load. |
| `--max-segment-mb` | 8 | Segment size cap. A busy node seals at this size, and a quiet one PUTs whatever is queued. |
| `--hedge-after-ms` | 100 | A segment PUT still pending this long gets one duplicate. On a store slower than this at p50 (R2), most PUTs are hedged (see [Object store](object-store.md#latency-and-failure)). |
| `--log-compression` | 1 (zstd level) | Real commits store ~2× smaller for ~5 µs of CPU each. 0 stores segments raw. |
| `--log-retention` | 72h | The firehose backfill window. Older segments that no replay needs are deleted, and older cursors get `OutdatedCursor`. `off` keeps everything. |
| `--log-retention-interval` | 60s | Between retention passes (1 s to 10 min). Idle passes cost nothing. |
| `--fence-retention` | 7d | How long a dead log's fence is kept after it's pruned. |
| `--checkpoint-every` | 10s | Each owned shard is checkpointed this often, which bounds how much log a successor replays after a crash. |
| `--firehose-ring-mb` | 512 (tiny 64) | Recent events in memory for live subscribers and short catch-ups. |
| `--firehose-merge-queue-mb` | 256 (tiny 32) | The cross-node merger's queues before it spills a log to read-back from the bucket. |
| `--firehose-max-lag-mb` | 128 (tiny 64) | A live subscriber this far behind gets `ConsumerTooSlow`. |
| `--firehose-max-backfills` | 16 (tiny 4) | Cursor backfills at once. Each holds `--backfill-readahead-mb` (64, tiny 16). |
| `--firehose-max-per-ip` | 256 | subscribeRepos connections per client IP (per /64 on IPv6). |
| `--firehose-threads` | 4 (tiny 1) | Threads serving subscribers, apart from the request runtime. |

Details: [Firehose](../firehose.md), [State storage](../state-storage.md#checkpoints).

## Disk cache

```diagram
caption: "The local SST cache. Its budget is divided by every shard in the layout, not just the owned ones, so it still fits if this node ends up holding all of them."
nodes:
  - { id: dir, label: "`--cache-dir`", sub: "empty = no disk cache", at: [0, 0], size: [9, 3] }
  - { id: total, label: "`--disk-cache-mb`", sub: node total, at: [13, 0], size: [9, 3], tone: accent }
  - { id: shard, label: per shard, sub: "total ÷ layout shards\nat least 64 MiB", at: [26, 0], size: [10, 3.6], tone: blue }
  - { id: per, label: "`--disk-cache-shard-mb`", sub: explicit cap wins, at: [26, 6], size: [10, 3], tone: muted }
edges:
  - dir -> total
  - total -> shard
  - "per -> shard: or"
```

- `--cache-dir` turns the cache on. Without it, every SST read that misses memory goes to the store.
  Put it on local NVMe for a busy node. The root disk is fine for a personal one. The fail-stop exit record
  (`vlpds-exit-<node-id>.json`) is kept there too.
- `--disk-cache-mb` is the node's total. With neither size flag, SlateDB's own default is 16 GiB per
  shard (1 TiB at 64 shards), which is rarely what you want.
- `--disk-cache-shard-mb` sets the per-shard cap directly. In an N-node cluster where each node holds
  ~1/N of the shards, size the disk for the failover case.
- A cap applies when a shard opens, which is at start, after a takeover, or for the new shards of a
  split. The start-up line `SST disk cache (per shard)` shows `shard_mb`.

The Ansible role uses 4 GiB on the root disk for tiny (plus 10 GiB that must stay free), and 80% of a
dedicated cache filesystem for standard (`vlpds_disk_cache_mb: auto`). See
[Deploy](deploy.md#profiles).

## Limits and admission

```facts
- { value: "20k", label: writes in flight, note: "`--max-inflight-writes` · more get 503", tone: accent }
- { value: "1 / core", label: password hashes at once, note: "Argon2, at most 16 · a login waits ≤ 2 s, then 503 Overloaded", tone: rust }
- { value: "1 GiB", label: largest repo import, note: "`--max-import-mb` · memory reserved per import from a budget", tone: amber }
- { value: "100 MB", label: largest blob, note: "`--max-blob-mb`", tone: blue }
```

A node sheds load before it runs out of memory. Each limit returns an error the client can retry:

| Flag | Default | Limit |
|---|---|---|
| `--max-inflight-writes` | 20,000 | Write requests in flight. More get 503. |
| `--max-queued-reads` | 20,000 | Repo-view reads (getRepo, getRecord, getBlocks) queued at the repo workers. |
| `--max-connections` | 50,000 | Open connections per listener. More wait in the accept queue (`--listen-backlog` 16,384, and raise `net.core.somaxconn` too). |
| `--max-exports`, `--export-stall-secs` | 32, 60 | getRepo streams at once (more wait 10 s, then 503). A stream whose client reads nothing for 60 s is ended. |
| `--max-import-mb`, `--import-memory-mb` | 1,024, 1/16 of the budget | Largest CAR importRepo takes, and the memory imports may hold at once. |
| `--max-blob-mb` | 100 | Largest uploadBlob. |
| `--blob-quota-gb`, `--blob-uploads-per-day` | 25, 500 | Per-account blob bytes stored and uploads per UTC day (0 means unlimited). The console overrides them per account. See [Email and moderation](email-and-moderation.md#upload-quotas). |
| `--blob-quarantine-days` | 30 | How long a taken-down blob's bytes are kept (restorable) before they're deleted. |
| Argon2 permits | one per core, at most 16 | Password hashing. Sign-ins wait at most 2 s for a turn, then get 503 `Overloaded` with Retry-After. |

Rate limits are the reference PDS's buckets plus a few of vlpds's own, tunable live from the
console. Set `--trusted-proxies` to your TLS proxy's address, or every client looks like the proxy.
`--rate-limit-bypass-key` and `--no-rate-limits` are for trusted services and benchmarks. Every
bucket, the flags and the live config are on [Rate limits](rate-limits.md).

Two flags size the threads. `--workers` is the number of repo workers that build and sign commits
(default half the cores), and `--io-threads` sizes the request runtime (default all cores). On a
2-vCPU host shared with Caddy and Alloy, the defaults (1 worker and 2 I/O threads) are right.

## Reference of every flag

`vlpds --help` has the full list, with each flag's default and environment variable. The table below
has the flags the sections above don't cover.

| Group | Flags |
|---|---|
| Identity | `--public-url`, `--handle-domain`, `--service-did` (`did:web:<hostname>`), `--node-id` (default `single`, keep it stable across restarts) |
| Listeners | `--listen` (`0.0.0.0:2583`), `--metrics-listen` (`127.0.0.1:9583`, or `app` for the app port), `--listen-backlog`, `--admin-listen` (unset: none; the console for operators only) |
| Operator sign-in | `--admin-proxy-header`, `--admin-proxy-from`, `--admin-operators`: a proxy in front of `--admin-listen` names the operator, and the token form is skipped. All three or none. See [Sign-in through a proxy](admin-console.md#sign-in-through-a-proxy). |
| Peers (clusters only) | `--peer-listen`, `--peer-tls-dir`, `--advertise-url` (all three or none, see [Scaling and clustering](scaling-and-clustering.md#peer-tls)), `--peer-connections` |
| Object store | `--s3-endpoint`, `--s3-bucket`, `--s3-region`, `--s3-access-key[-file]`, `--s3-secret-key[-file]`, `--prefix`, `--store-inflight` (1,024), `--log-store-inflight` (256) |
| Secrets | `--jwt-secret[-file]`, `--admin-token[-file]`, `--internal-token[-file]` (32+ bytes, all different) |
| Keys | `--kek[-file]`, `--kek-old[-file]`, `--gcp-kms-key`, `--gcp-kms-old-key`, `--gcp-credentials-file`, `--kms-concurrency` (see [KEK and key rotation](kek-and-key-rotation.md)) |
| Vault KEK | `--vault-addr`, `--vault-transit-key` (`<mount>/<key>`), `--vault-transit-old-key`, `--vault-namespace`, `--vault-ca-file`, and one auth method: `--vault-token-file`, `--vault-approle-role-id[-file]` with `--vault-approle-secret-id-file` and `--vault-approle-mount` (`approle`), or `--vault-k8s-role` with `--vault-k8s-mount` (`kubernetes`) and `--vault-k8s-jwt-file` (see [Vault Transit](kek-and-key-rotation.md#vault-transit)). `--vault-ca-only` trusts only that CA. `--vault-addr` must be https (http only to loopback or in dev mode). A node refuses to start if Vault answers its startup check with a 403/404 or refuses the login, and starts anyway if Vault is down or sealed, unless its PLC rotation key file is Vault-wrapped. |
| PLC | `--plc-url`, `--plc-mode` (`auto`, `directory`, `unregistered`), `--plc-rotation-key-file`, `--plc-rotation-key-old[-file]`, `--plc-recovery-did-key`, and the one-shot `--wrap-plc-rotation-key` and `--generate-did-key` |
| Services | `--appview`, `--report-service` (`<url>,<did>`), `--bsky-app-view-cdn-url-pattern`, `--mod-service-did` |
| Spaces | `--spaces` (off): AT Protocol Spaces, permissioned data, tracking the reference's alpha. With it on, `com.atproto.space.*` and `com.atproto.simplespace.*` are served here and never proxied. `--space-repo-max-records` (100,000) caps one account's repo in one space, and `--space-oplog-retention` (`7d`) is how long `listRepoOps` keeps ops. See [Operating Spaces](../spaces/operating.md). |
| Relays | `--crawlers` (`bsky.network`), `--crawl-interval-secs` (1,200). See [Relays and crawling](relays-and-crawling.md). `--asn-lookup` (`bgp.tools`) looks up the AS of each firehose subscriber for the console's Firehose page. It sends subscriber addresses to bgp.tools' whois, batched and cached for a day. `off` turns it off. |
| Accounts | `--invite-required`, `--invite-interval-ms`, `--invite-epoch-ms`, `--trusted-device-days` (30, 0 turns "Trust this browser" off), `--resolve-lexicons`, `--privacy-policy-url`, `--terms-of-service-url`, `--contact-email-address`, `--delete-after` (on) and `--delete-after-min-hold-days` (3) (see [Scheduled deletion](email-and-moderation.md#scheduled-deletion)) |
| Email | `--email-smtp-url[-file]` or `--email-api-url` with `--email-api-token[-file]`, `--email-from-address`, `--email-brand-name` and the other branding flags, `--moderation-email-smtp-url[-file]` or `--moderation-email-api-url` (`--moderation-email-api-token[-file]`), `--moderation-email-address` (see [Email and moderation](email-and-moderation.md)) |
| SlateDB | `--sst-compression` (`zstd`), `--compaction-polling` (`adaptive`), `--compaction-poll` (30 s), `--slatedb-gc-min-age` (10 min), `--slatedb-checkpoint-lifetime` (1 h), `--slatedb-detach-interval` |
| Resharding | `--reshard-split-mb`, `--reshard-split-writes`, `--reshard-gc-grace` (1 h), `--forced-detach-after` (5 min), `--full-compaction-every` (off) |
| Takeover | `--preload-recent` (2,048 repos per shard), `--forwarded-write-start-ms` (1,000), `--retry-unapplied-writes` (on), `--checkpoint-stagger` (on) |
| Repo cache | `--cache-per-worker` (50,000 repos), `--lazy-mst-prefetch-kb` (1,024) |
| Blobs | `--max-blob-mb`, `--blob-gc-grace-secs` (6 h), `--blob-quota-gb`, `--blob-uploads-per-day`, `--blob-quarantine-days` |
| Web UI | `--ui-dir` (the image's `/usr/share/vlpds/ui`). Startup fails if it isn't a complete build. |
| Logging | `--log-format` (`text`, `json`), `RUST_LOG` (`info,slatedb=warn`), `--exit-state-file`, `--pyroscope-url` (profiling builds) |
| Development | `--dev-mode`, `--memory` (in-memory store), `--allow-bulk-create`, `--no-rate-limits`, `--inject-put-ms`, `--lexicon-authority-override <authority>=<did>` (repeatable, `--dev-mode` only: lexicons of that NSID authority come from the DID's repo with no DNS lookup) |
