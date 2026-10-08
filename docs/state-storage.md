---
title: State storage
section: vlPDS
order: 3
status: ready
summary: "SlateDB with its WAL turned off. The key layout, how durable segments get applied, checkpoints, compaction and the caches in front of the bucket."
---

```hero
diagram:
  caption: Writes enter from durable log segments, reach the memtable before the ack, and reach the bucket as SSTs at checkpoints. Reads try memory, then the local disk, then the bucket.
  nodes:
    - { id: seg, label: durable segment, sub: from the node log, at: [0, 0.5], size: [8, 3], tone: accent }
    - { id: fin, label: Finalizer, sub: one batch per shard, at: [11, 0.5], size: [8, 3], tone: accent }
    - { id: mem, label: Memtable, sub: readable at once, at: [23.5, 0.5], size: [8, 3], tone: accent }
    - { id: l0, label: L0 SSTs, sub: "16 MiB each · ≤ 32", at: [36, 0.7], size: [9, 2.6], shape: store, tone: amber }
    - { id: rd, label: Reads, sub: getRecord · listRecords, at: [0, 8], size: [8, 3], tone: blue }
    - { id: bc, label: RAM caches, sub: blocks · filters · indexes, at: [11, 8], size: [8, 3], tone: blue }
    - { id: dc, label: Disk cache, sub: "`--cache-dir` · NVMe", at: [23.5, 8], size: [8, 3], tone: blue }
    - { id: sr, label: Sorted runs, sub: 64 MiB SSTs, at: [36, 8.2], size: [9, 2.6], shape: store, tone: amber }
  groups:
    - { label: "state/{shard}/ · one SlateDB per shard", around: [l0, sr], tone: amber }
  edges:
    - seg -> fin
    - "fin -> mem: apply"
    - "mem -> l0: flush"
    - "l0 -> sr: compact"
    - rd -> bc
    - "bc -> dc: miss"
    - "dc -> sr: miss"
facts:
  - { value: "0", unit: extra writes, label: for durability, note: "SlateDB's WAL is off; the node log is the WAL" }
  - { value: "10 s", label: checkpoint per shard, note: "applied marker + memtable flush; bounds replay (`--checkpoint-every`)", tone: violet }
  - { value: "~3.4 KB", unit: /commit, label: into state, note: "records, head, MST interior nodes (measured)", tone: amber }
  - { value: "2.5×", label: SST compression, note: "zstd on 16 KiB blocks of a real repo (`--sst-compression`)", tone: blue }
```

Everything vlpds serves from storage (repo heads, records, accounts, sessions, indexes) lives in
one [SlateDB](https://slatedb.io) database per shard, under `state/{shard}/` in the bucket. SlateDB
is an LSM tree that writes its SSTs and manifest straight to object storage. vlpds turns off
SlateDB's own write-ahead log, since the commit log already is one. A write is made durable once, in
a log segment, and applied to the shard's memtable before it's acknowledged.

## Why an LSM, and why SlateDB

| State needs | What provides it |
|---|---|
| Point reads: a repo head, `getRecord`, an account | memtable, then a bloom filter per SST, then one block |
| Ordered scans: `listRecords`, `listRepos`, a cold MST load | keys sorted by repo and path |
| Far more records than RAM, ~3 KB written per commit | immutable SSTs in the bucket, merged in the background |
| A new owner opening a shard in a fraction of a second | opening reads a manifest and copies nothing to the node |
| Cheap split and merge | a clone references the parent's SSTs instead of copying them |

vlpds uses SlateDB as a sorted key-value store. It builds SlateDB from a fork (`jazware/slatedb`),
which is upstream `main` plus a few patches: a faster scan path, cheaper cache hits, metadata-cache
seeding for compaction output, and bug fixes. The fork is pinned in one place, the `vlsync-slatedb`
crate in [vlsync](https://github.com/jazware/vlsync), and its Cargo.toml lists each patch.

## Key layout

```diagram
caption: "Every per-account key starts with its account's slot, so a shard's slot range [lo, hi) is exactly the key range [01‖lo, 01‖hi)."
nodes:
  - { id: k1, label: "`0x01`", sub: tag, at: [0, 0], size: [4, 3], tone: accent }
  - { id: k2, label: slot, sub: 2 bytes · BE, at: [4, 0], size: [6, 3], tone: accent }
  - { id: k3, label: family, sub: "`h/` `R/` `M/` …", at: [10, 0], size: [7, 3] }
  - { id: k4, label: routing key, sub: "usually `{did}\\0`", at: [17, 0], size: [8, 3] }
  - { id: k5, label: "`{gen}`", sub: LEB128, at: [25, 0], size: [5, 3] }
  - { id: k6, label: rest, sub: "collection/rkey, CID…", at: [30, 0], size: [9, 3] }
notes:
  - { at: [0, 4.6], text: "`{gen}` only in repo-content families. `meta/applied2` and `meta/recent` are plain ASCII and sort outside every slot.", align: start }
```

| Key | Value | Used for |
|---|---|---|
| **Repo** | | |
| `h/{did}` | commit CID, data CID, rev, signed commit | the repo head, where every write and sync read starts |
| `R/{did}\0{gen}{collection}/{rkey}` | record CID, rev, record bytes | `getRecord`, `listRecords`, exports |
| `M/{did}\0{gen}{cid digest}` | MST node block | interior nodes of the current tree. Leaves are derived from `R/` ([Record storage](record-storage.md#what-is-stored-and-what-is-derived)) |
| `c/{did}\0{gen}{cid8}{path}` | empty | record CID → path index for `getBlocks` |
| `b/{did}\0{gen}{blob cid}\0{path}` | rev | which records reference a blob ([Blobs](blobs.md#references)) |
| `bl/{did}\0{gen}{code}{subject}` | rkeys | likes, reposts, follows and blocks of a subject (duplicate pruning) |
| `S/{did}` | 3 counters | records, MST nodes and blobs for `checkAccountStatus` |
| `G/{did}` | import state | a staged `importRepo` and generations left to sweep |
| **Account** | | |
| `a/{did}` | account row | handle, email, password hash, status. The signing key is stored only wrapped under the KEK ([Keys and security](keys-security.md#secrets-at-rest)) |
| `n/{handle}` | DID | handle lookup (in the DID's slot) |
| `C/{collection}\0{did}` | empty | `listReposByCollection` |
| `D/{did}` | `deleteAfter` | deactivated accounts scheduled for deletion ([Scheduled deletion](operations/email-and-moderation.md#scheduled-deletion)) |
| `p/{routing}\0{name}` | varies | private state: sessions, app passwords, email tokens, 2FA, OAuth, `sec/` security controls, the sign-in log and trusted browsers (`signin/`, `trust/`) |
| `T/` | totals | the slot's account counts (`vlpds_accounts`) and its active accounts by handle suffix ([handle domains](operations/handle-domains.md#counting-accounts)) |
| **Shard** | | |
| `meta/applied2` | log id, ordinal | the applied marker, which is where replay starts |
| `meta/recent` | DIDs | recently written repos the next owner preloads |

With `--spaces`, space repos and the spaces an account runs get twelve `s*` families of their own,
in the same slots ([Spaces storage](spaces/storage.md#key-families)).

`{gen}` is the repo's generation. An import writes the new repo under a fresh generation and
switches the account to it in one entry, and old generations get swept in the background.
Cross-account scans (`listRepos`, `searchAccounts`) walk slot by slot and seek past empty slots, so
they return results in `(slot, DID)` order whatever the layout.

## Applying the log

```steps
- title: A segment becomes durable
  body: "Its PUT and the PUTs for every earlier ordinal have completed. The finalizer takes segments strictly in ordinal order."
- title: One write batch per touched shard
  body: "The batch holds the segment's mutations for that shard (puts and deletes, in log order) plus the applied marker `meta/applied2 = (log id, ordinal)`. Shards are written concurrently, each under its own apply lock."
- title: Into the memtable, not the bucket
  body: "With the WAL off, the write returns once the batch is in the memtable. A read right after the ack sees it."
- title: Ack, firehose, watermark
  body: "Then the node re-checks its lease and acks the writes. It hands the events to the firehose and advances the log's durable watermark."
```

Nothing in a shard's state is durable in the bucket until a flush writes it as an SST. That's fine,
since the log segment is the durable copy. After a crash, the shard's next owner opens the DB, reads
`meta/applied2` and replays every span of the shard's history after it. It fetches each log segment
once for all the shards it's opening. If the marker names no span of the history (meaning a span it
needs was dropped), replay refuses to run instead of serving without acked writes.

A failed apply means the node's state and its log disagree, so the node fail-stops (exit 4,
`state_apply`). If a shard's L0 is full, its writes wait for compaction and the finalizer waits with
them. That holds back acks on the whole node, and it's what `VlpdsSlateDbL0Stalls` catches.

## Checkpoints

```diagram
caption: "Checkpoints are staggered: with 64 shards and the default 10 s, one shard every ~160 ms. Each is an applied marker and a memtable flush."
nodes:
  - { id: c0, label: shard 0, sub: "+0.16 s", at: [0, 0], size: [7, 2.6], tone: accent }
  - { id: c1, label: shard 1, sub: "+0.31 s", at: [9, 0], size: [7, 2.6], tone: accent }
  - { id: dots, label: "…", at: [18, 0], size: [5, 2.6], shape: note, tone: muted }
  - { id: c63, label: shard 63, sub: "+10 s, then again", at: [25, 0], size: [8, 2.6], tone: accent }
  - { id: st, label: "`state/{shard}/`", sub: L0 SST PUT · manifest CAS, at: [9, 6], size: [14, 2.6], shape: store, tone: amber }
edges:
  - { from: c0.b, to: st.t15 }
  - { from: c1.b, to: st.t50 }
  - { from: c63.b, to: st.t85 }
```

Every `--checkpoint-every` (10 s), each owned shard writes its applied marker (and its recent-repos
list) and then flushes its memtable. That's one L0 SST PUT and one manifest update. It bounds a
successor's replay to roughly the last 10 s of the log, and it lets
[log retention](firehose.md#retention) advance. A shard that's already checkpointed at the log's
current durable ordinal gets skipped, so an idle node makes no checkpoint requests.
`--checkpoint-stagger` (on) spreads the shards over the interval instead of flushing them back to
back.

Between checkpoints, SlateDB also flushes a memtable once it reaches 16 MiB. Graceful closes
(handoff, split, shutdown) checkpoint the shard as part of the close. The metric is
`vlpds_checkpoint_shard_seconds` and the alert is `VlpdsCheckpointsStalled`.

## Compaction and garbage collection

```diagram
caption: "Each shard runs its own compactor. Adaptive polling (the default) is cheap while L0 is shallow and fast while an ingest fills it."
nodes:
  - { id: slow, label: Slow polls, sub: "every 30 s · L0 shallow", at: [0, 0], size: [10, 3], tone: accent }
  - { id: fast, label: Fast polls, sub: every 500 ms, at: [24, 0], size: [10, 3], tone: violet }
edges:
  - { from: slow.r30, to: fast.l30, label: "L0 reaches 8 SSTs" }
  - { from: fast.l70, to: slow.r70, label: "≤ 2 SSTs for 15 s" }
```

```facts
- { value: "32", unit: L0 SSTs, label: before writes stall, note: "16 MiB each, which leaves room for a bulk import between compactions" }
- { value: "1 h", label: replaced SSTs stay readable, note: "`--slatedb-checkpoint-lifetime` · a scan or export has to finish within it", tone: violet }
- { value: "10 s", label: manifest poll, note: "`--slatedb-manifest-poll` · 60 s on tiny · writes are visible regardless", tone: blue }
- { value: "4×", label: transient space during imports, note: "size-tiered compaction rewrites rows ~3 times", tone: amber }
```

- Compaction is size-tiered and runs per shard (`--compaction-polling adaptive`,
  `--compaction-poll 30s`). Compacted SSTs roll at 64 MiB, so a cache miss on one fetches less.
- Polling. The node is its shards' only writer, so its reads see its own writes whatever the
  manifest poll is set to. A poll only picks up compaction results, so the interval changes the
  request count and not read latency. A writer whose L0 is 8 or more deep refreshes every 500 ms
  anyway. At these defaults, per-shard polling is ~0.4 GETs/s, down from 3.2 at SlateDB's defaults.
- Garbage collection. SlateDB deletes an SST once no manifest or live checkpoint references it and
  it's older than `--slatedb-gc-min-age` (10 min). Before each compaction replaces SSTs, it pins the
  old manifest for `--slatedb-checkpoint-lifetime` (1 h), which lets a long `getRepo` keep reading.
  After a bulk import, peak transient space is about the last hour's compaction output.
- Tombstones get dropped when they reach the bottom run. `--full-compaction-every` (off) forces that
  periodically. The soak tests found no read cost from leaving it off.
- Bucket settings. Replaced SSTs are deleted for good, so disable GCS soft delete and add the
  abort-incomplete-multipart rule on S3 and R2. See [Lifecycle rules](operations/object-store.md#lifecycle-rules).

## Caches

```diagram
caption: "A point read, in the order it looks. The metadata cache is checked once per SST (every L0, plus one per sorted run); data blocks come from the block cache, then the disk cache, then the bucket."
nodes:
  - { id: rq, label: Point read, sub: head · record · account, at: [0, 0], size: [8, 3], tone: blue }
  - { id: mt, label: Memtable, sub: unflushed writes, at: [11, 0], size: [8, 3], tone: accent }
  - { id: mc, label: Metadata cache, sub: filters · indexes, at: [23.5, 0], size: [9, 3], tone: blue }
  - { id: bc, label: Block cache, sub: decoded 16 KiB blocks, at: [23.5, 6], size: [9, 3], tone: blue }
  - { id: dc, label: Disk cache, sub: SST files per shard, at: [11, 6], size: [8, 3], tone: blue }
  - { id: sb, label: "`state/{shard}/`", sub: ranged GET, at: [0, 6.2], size: [8, 2.6], shape: store, tone: amber }
edges:
  - rq -> mt
  - "mt -> mc: not there"
  - "mc -> bc: may hold it"
  - "bc -> dc: miss"
  - "dc -> sb: miss"
```

| Cache | Default size | Flag |
|---|---|---|
| SST metadata (filters, indexes) | what every owned SST needs × N/(N−1) for a failover × 1.25 for compactions | `--meta-cache-mb` |
| SST block cache | half of the cache pool left after metadata | `--block-cache-mb` |
| Repo cache (MST paths in the workers) | the other half | `--repo-cache-mb`, `--cache-per-worker` |
| Local disk cache | `--disk-cache-mb` ÷ the layout's shard count, floor 64 MiB · an explicit `--disk-cache-shard-mb` wins · 16 GiB per shard with neither flag | `--cache-dir`, `--disk-cache-mb`, `--disk-cache-shard-mb` |

The three memory caches are shared by every shard on the node. They're sized from its **memory
budget**, which is the cgroup limit or physical RAM (`--memory-budget-mb` overrides it). Fixed costs
come off the top: a 256 MiB baseline, 10% for small in-memory caches, firehose rings, export and
import working sets, and max(15%, 512 MiB) of headroom for memtables and request bodies. The rest is
the cache pool. A thread re-plans every 5 s as shards come and go. Growth applies at once, but
shrinking waits until the lower target has held for 5 minutes, so a takeover and its handback don't
thrash. `vlpds --memory-plan` prints the plan, and a node whose explicit sizes don't fit refuses to
start. A 2.5 GiB tiny container gets a ~0.9 GiB pool, and a 32 GB host gets ~17 GiB.

The metadata cache has to hold every owned SST's filter and index. A point read checks a filter per
sorted run and every L0, and SlateDB's filters cover a whole SST, so a miss fetches megabytes to
answer one key. When the 100M-account capacity test outgrew the cache, bulk creation fell from 78k
to 3k accounts/s. Budget ~29 MB per million accounts. `vlpds_sst_meta_bytes` is the encoded need and
`vlpds_meta_cache_shortfall_bytes` is the gap. The alerts are `VlpdsSstMetaCacheTooSmall` and
`VlpdsSstMetaRefetching`.

The disk cache is divided over every shard of the layout, including the ones this node doesn't own,
so it still fits when the node takes them all after a failover. In steady state, an N-node cluster
uses about 1/N of it. Put it on local NVMe. For the flags in detail, see
[Memory budget and autosizing](operations/configuration.md#memory-budget-and-autosizing) and
[Disk cache](operations/configuration.md#disk-cache).

## Shard split and merge

```diagram
caption: "A split clones the frozen parent twice, each clone projected to its half of the slot range. Clones reference the parent's SSTs instead of copying them, until their own compaction rewrites them."
nodes:
  - { id: p, label: "`state/{P}/`", sub: "slots [lo, hi) · frozen", at: [0, 3], size: [10, 3], shape: store, tone: amber }
  - { id: c1, label: "`state/{C1}/`", sub: "slots [lo, mid)", at: [21, 0], size: [10, 3], shape: store, tone: amber }
  - { id: c2, label: "`state/{C2}/`", sub: "slots [mid, hi)", at: [21, 6], size: [10, 3], shape: store, tone: amber }
  - { id: gc, label: Reshard GC, sub: deletes P when unused, at: [37, 3], size: [10, 3], tone: muted }
edges:
  - { from: p.r30, to: c1.l, label: clone · projected, labelAt: [15.5, 4.5] }
  - { from: p.r70, to: c2.l }
  - { from: c1.r, to: gc.l30, dash: true, label: detach }
  - { from: c2.r, to: gc.l70, dash: true }
```

Since keys are slot-major, a shard's state is one key range. SlateDB can clone a database
restricted to a range by writing a new manifest that points at the parent's SSTs. So a split or
merge costs one manifest, whatever the shard's size.

```steps
- title: Plan
  body: "An admin call (or the split policy) CASes the layout to record the op and allocate the children's ids. Only one op runs at a time, cluster-wide."
- title: Freeze
  body: "Each parent's owner closes it like a handoff (barrier, checkpoint, close) and marks its assignment frozen. Its slots answer 503 and get retried until the flip."
- title: Clone
  body: "The driver clones the children from the frozen parents and writes their fresh assignments. The step is idempotent, so a crashed driver's successor just re-runs it."
- title: Flip
  body: "The driver CASes the layout to the new version, and that's the commit point. Then it opens the children and nudges every peer. Fair shares spread them out later."
```

No acked write is lost, because a slot is applied by exactly one open shard at a time and the clone
is taken of a parent whose DB already holds every acked entry. Every step resumes from bucket state
after a crash, and `vlpds admin reshard-abort` works until the flip.

Afterwards, the parent is reclaimed in the background:

- Forced detach. If a child is still reading inherited SSTs `--forced-detach-after` (5 min) after
  it opened, it gets one compaction that rewrites them. Otherwise size-tiered compaction might never
  touch a quiet child's bottom run. SlateDB then drops the parent from the child's manifest
  (`--slatedb-detach-interval`, 10 min).
- Dir GC. The owner of slot 0 deletes retired `state/{id}/` directories once no live checkpoint
  pins them, no other manifest lists their SSTs, and their manifest is older than
  `--reshard-gc-grace` (1 h). Then it deletes their `assign/` record. An idle pass costs one GET.
- Alerts. `VlpdsRetiredStateGrowing`, `VlpdsRetiredStateReferenced`, `VlpdsForcedDetachFailing`,
  `VlpdsReshardGcFailing`.

For when and how to split, see [Shard split and merge](operations/scaling-and-clustering.md#shard-split-and-merge).
