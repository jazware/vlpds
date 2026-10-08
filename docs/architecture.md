---
title: Architecture
section: vlPDS
order: 2
status: ready
summary: "How a request moves through a node, how nodes share shards, and what happens when one fails."
---

```hero
diagram:
  caption: One node. Requests for shards it owns go to its repo workers and its log; the rest are forwarded to their owner. The cluster loop keeps the node's lease and its shard assignments in the bucket.
  nodes:
    - { id: cl, label: Client, sub: via Caddy, at: [0, 0.5], size: [7, 3] }
    - { id: http, label: XRPC server, sub: axum · IO runtime, at: [10, 0.5], size: [8, 3], tone: accent }
    - { id: w, label: Repo workers, sub: MST · sign commit, at: [21, 0.5], size: [8, 3], tone: accent, stack: true }
    - { id: lg, label: Node log, sub: sequencer · finalizer, at: [32.5, 0.5], size: [8, 3], tone: accent }
    - { id: seg, label: "`log/{log}/`", sub: segments, at: [45, 0.7], size: [9, 2.6], shape: store, tone: amber }
    - { id: peer, label: Peer node, sub: owns other shards, at: [0, 7.2], size: [7, 3] , tone: accent }
    - { id: db, label: Shard DBs, sub: SlateDB per shard, at: [32.5, 7], size: [8, 3], tone: accent, stack: true }
    - { id: st, label: "`state/{shard}/`", sub: SSTs · manifest, at: [45, 7.2], size: [9, 2.6], shape: store, tone: amber }
    - { id: cp, label: Cluster loop, sub: lease · assignments, at: [21, 11.5], size: [8, 3], tone: accent }
    - { id: ctl, label: "`nodes/` `assign/`", sub: leases · ownership, at: [45, 11.7], size: [9, 2.6], shape: store, tone: amber }
  groups:
    - { label: one vlpds node, around: [http, w, lg, db, cp], tone: accent }
  edges:
    - "cl.r -> http.l: HTTPS"
    - "http.r -> w.l: own shard"
    - "w.r -> lg.l: commit"
    - "lg.r -> seg.l: PUT"
    - "lg.b -> db.t: apply, ack"
    - "db.r -> st.l: flush · read"
    - { from: http.b, to: peer.r, via: [[14, 8.7]], label: forward · mTLS }
    - { from: cp.r, to: ctl.l, label: CAS every 2 s, dash: true }
facts:
  - { value: "10 s", label: node lease TTL, note: "renewed by CAS every 2 s; 60 s on the tiny profile (`--lease-ttl-ms`)" }
  - { value: "~12 s", label: to take over a crashed node, note: "1.2 × TTL; 3–5 s when its port refuses connections", tone: violet }
  - { value: "~0.2 s", label: per planned shard move, note: "graceful stop or rebalance; caches warmed first", tone: blue }
  - { value: "0", label: acked writes lost on takeover, note: "fencing and CAS decide who writes; clocks only decide when", tone: amber }
```

A vlpds cluster is a set of identical processes pointed at one bucket. Each node owns some shards
and keeps one lease. Ownership, leases and the commit log are all objects in the bucket, so nodes
don't talk to a coordinator and no node's disk holds anything that can't be rebuilt. Read this page
before you run more than one node, or when an ownership alert fires.

## Components of a node

| Component | What it does | Code |
|---|---|---|
| XRPC server | axum on the IO runtime. Handles auth, rate limits, validation, routing and forwarding to the owner | `src/http.rs`, `src/xrpc/`, `src/forward.rs` |
| Partition table | the layout (slot ranges → shard ids), each shard's owner, and the shards open here | `src/partitions.rs`, `vlsync-store/src/slots.rs` |
| Repo workers | one OS thread each, and a DID always hashes to the same worker. Holds active repos' MST paths, builds and signs commits | `src/worker.rs` |
| Node log | one sequencer and one finalizer per node. Groups commits into segments and PUTs them, then applies, acks and feeds the firehose in ordinal order | `src/nodelog.rs` |
| Shard DBs | one SlateDB per owned shard. Holds heads, records, accounts and indexes. SlateDB's WAL is off: the node log is the write-ahead log for every shard the node owns, and a write is in it before the 200 | `src/partition.rs`, [State storage](state-storage.md) |
| Firehose | follows every peer's log, merges them and serves `subscribeRepos` | `vlsync-firehose/src/firehose.rs`, `src/remote.rs` |
| Cluster loop | lease renewal, membership, acquiring and releasing shards, fencing dead logs, split/merge steps | `src/cluster.rs`, `src/node.rs` |
| Background passes | log retention, retired-state GC, checkpoints, memory re-planning | `src/retention.rs`, `src/reshard_gc.rs`, `src/memory.rs` |

`vlsync-store` and `vlsync-firehose` are crates in [vlsync](https://github.com/jazware/vlsync),
which vlpds shares with vlRelay. They hold the object-store client, the log segment format and the
firehose merger. The atproto data model, signing and firehose frames are in
[vlatproto](https://github.com/jazware/vlatproto).

```diagram
caption: Three object-store clients, each with its own connection pool and permit cap, so a takeover's burst of state reads can never delay a lease renewal or a segment PUT.
nodes:
  - { id: u1, label: Node log, sub: segment PUTs · replay, at: [0, 0], size: [9, 3], tone: accent }
  - { id: u2, label: Shard DBs, sub: SlateDB · blobs, at: [0, 4.5], size: [9, 3], tone: accent }
  - { id: u3, label: Cluster loop, sub: leases · fences, at: [0, 9], size: [9, 3], tone: accent }
  - { id: c1, label: log client, sub: 256 reads · PUTs reserved, at: [13, 0], size: [10, 3] }
  - { id: c2, label: state client, sub: "1,024 requests", at: [13, 4.5], size: [10, 3] }
  - { id: c3, label: control client, sub: 64 · 8 kept for leases, at: [13, 9], size: [10, 3] }
  - { id: b, label: bucket, sub: one prefix per PDS, at: [28, 4.2], size: [9, 3.6], shape: store, tone: amber }
edges:
  - u1 -> c1
  - u2 -> c2
  - u3 -> c3
  - c1.r -> b.l25
  - c2.r -> b.l
  - c3.r -> b.l75
```

The caps are `--log-store-inflight` (256, plus max(64, 4 × `--log-inflight`) permits that only
segment PUTs may use) and `--store-inflight` (1,024). The control client's 64 is fixed. A saturated
state client is the usual cause of slow cold loads after a takeover. See
`VlpdsObjectStorePermitsSaturated` in [Runbook](operations/runbook.md#slow-or-failing-object-store).

The write path itself (coalescing, pipelining, segments) is covered in [Record storage](record-storage.md#write-coalescing-and-pipelining)
and [Firehose](firehose.md). [The path of a commit](the-path-of-a-commit.md) follows one write
through every stage, with its latency and what a crash at each stage leaves behind.

## Request routing and forwarding

```diagram
caption: Any node accepts any request. The entry node forwards to the shard's owner and resends a write only when the answer proves nothing was applied.
nodes:
  - { id: cl, label: Client, at: [0, 4], size: [7, 3] }
  - { id: en, label: Entry node, sub: routes by DID, at: [10, 4], size: [8, 3], tone: accent }
  - { id: ow, label: Owner node, sub: holds the shard, at: [23, 4], size: [8, 3], tone: accent }
  - { id: a1, label: "200", sub: applied · acked, at: [36, 0], size: [10, 2.6], tone: solid }
  - { id: a3, label: no answer in 3 s, sub: "503 `PartitionUnavailable`", at: [36, 4.2], size: [10, 2.6], tone: danger }
  - { id: a2, label: not applied, sub: "`RepoLoading` · `ShardMoved`", at: [36, 8.4], size: [10, 2.6], tone: ok }
edges:
  - cl.r -> en.l
  - "en.r -> ow.l: mTLS · HTTP/2"
  - ow.r -> a1.l
  - ow.r -> a3.l
  - ow.r -> a2.l
  - { from: a2.b, to: en.b, via: [[41, 13], [14, 13]], label: resend to the current owner (≤ 20 s), dash: true }
```

The entry node works out a routing key and looks up the owner of its shard. For `com.atproto.*`
and `vlpds.*`, the key is the repo or account the call names (the query parameter first, then the
token's DID, then the JSON body). Every other method (`app.bsky.*`, `chat.bsky.*`) routes by the
token's DID. That's because the caller's session and signing key live at its owner, which proxies to
the AppView (see [Proxying](proxying.md)). A forward carries the client's original bytes, an
internal marker and the client's address. The owner serves it no matter what its own routing table
says, so forwards never loop.

What comes back decides what the entry node does:

- Applied (200, or any normal error). The answer goes straight to the client.
- Not applied. The owner couldn't start the write within 1 s (`--forwarded-write-start-ms`) because
  the repo was still loading (`RepoLoading`), or the shard is moving (`ShardMoved`). A refused
  connection counts the same, since nothing was sent. The entry node resends to whoever owns the
  repo by then, with backoff, for up to 20 s (`--retry-unapplied-writes`). XRPC queries get resent
  on the same answers.
- Unknown. No first byte came back within 3 s (30 s for exports, uploads and AppView proxying). The
  entry node presumes the owner is frozen, and the client gets 503 `PartitionUnavailable` with
  `Retry-After: 1`. The write may have been applied, so it's never resent. If the owner really is
  stuck, its lease lapses and the shard moves.

So a takeover or a cold start shows up as latency instead of errors. `vlpds_write_retries_total{reason}`
counts resends, and the alerts are `VlpdsForwardErrorsHigh` and `VlpdsWriteResendsSustained`.

## Shards and ownership

```diagram
caption: A DID maps to a slot forever; the layout maps slots to shards; each shard's assignment names its one owner. The layout and the assignments are objects in the bucket.
nodes:
  - { id: did, label: "did:plc:…", sub: "sha256 → top 16 bits", at: [0, 0], size: [8, 3] }
  - { id: slot, label: slot, sub: "0 – 65,535 · fixed", at: [10.5, 0], size: [8, 3], tone: muted }
  - { id: lay, label: "`assign/layout`", sub: slot ranges → shard ids, at: [21, 0], size: [10, 3], shape: store, tone: amber }
  - { id: as, label: "`assign/{shard}`", sub: owner · epoch · spans, at: [33.5, 0], size: [10, 3], shape: store, tone: amber }
  - { id: nd, label: owner node, sub: "lease `nodes/{node}`", at: [46, 0], size: [8, 3], tone: accent }
edges:
  - did -> slot
  - slot -> lay
  - lay -> as
  - as -> nd
notes:
  - { at: [21, 4.6], text: "64 shards by default (`--shards`); split and merged online", align: start }
```

- Slots. There are 65,536 hash slots, fixed for the life of the bucket prefix. Every state key
  starts with its account's slot, so a shard's data is one contiguous key range.
- Shards. The versioned layout (`assign/layout`) groups slots into contiguous ranges, and each range
  gets a u32 id that's never reused. A shard is the unit of ownership and of state. It has one
  SlateDB at `state/{id}/` and one assignment at `assign/{id}` (ids are 10 zero-padded digits, so
  shard 42 is `state/0000000042/`). `--shards` only sets a new prefix's first layout. After that the
  stored layout wins, and it changes by [split and merge](state-storage.md#shard-split-and-merge).
- Assignments. `assign/{id}` holds the owner, its log, an epoch, a `seq_floor` and the shard's
  **span history**, which says which ordinals of which node's log hold its entries. It changes only
  by compare-and-swap on its ETag, and only when the shard moves.
- Fair share. Each node takes free or orphaned shards up to ⌈shards ÷ live nodes⌉ and hands extras
  to nodes that are short of theirs. A node marked `draining` (stopping) doesn't count. Shards
  rebalance by themselves as nodes join and leave.

Each cluster step (every 2 s) LISTs `nodes/` and `assign/` and GETs only the objects whose ETag
changed. Every 150 steps (~5 min) it also does a full re-read as a safety net. Never edit `assign/`
by hand. See [Shards unowned or flapping](operations/runbook.md#shards-unowned-or-flapping).

## Leases

```diagram
caption: "One node's lease at the default 10 s TTL, when renewals stop landing. Renewal interval and skew margin are each TTL/5."
nodes:
  - { id: r0, label: 0 s, sub: last renewal sent, at: [0, 0], size: [8, 3], tone: accent }
  - { id: r1, label: 2 s, sub: next renewal due, at: [11, 0], size: [8, 3], tone: accent }
  - { id: v, label: 8 s, sub: own validity ends, at: [24, 0], size: [8, 3], tone: rust }
  - { id: d, label: 12 s, sub: peers presume it dead, at: [37, 0], size: [9, 3], tone: danger }
edges:
  - r0 -> r1
  - "r1 -> v: fails"
  - "v -> d: stops acking"
```

A node holds one lease, `nodes/{node_id}`, for all its shards. The lease carries the node's log
id, address, writer id and a renewal counter, and the node renews it by CAS every TTL/5 (2 s). Every
renewal changes the object, and that change is all peers look at:

- Peers. Each peer notes, on its own monotonic clock, when it last saw each lease change. A lease
  that's unchanged for TTL + skew (1.2 × TTL, 12 s) is presumed dead. Once a node has missed a
  renewal, peers also try a TCP connect to its advertised address each step. If the connection is
  refused, the process is gone and it's presumed dead at once (3–5 s after the crash).
- The node itself. A node is valid until the send time of its last successful renewal plus
  TTL − skew (0.8 × TTL, 8 s). Past that it stops PUTting segments and acking, and it never renews a
  lapsed lease. A watchdog fail-stops it (exit 5) at about the time peers can first presume it dead.
- The renewal ceiling. Renewals are sequential, so a slow one delays the next send. Round trips
  longer than 0.4 × TTL (4 s) leave a gap in validity and the node fail-stops. A cluster-wide object-store brownout past that point
  stops every node, so keep the TTL at 10 s or more (`--lease-ttl-ms` warns below it).

No node compares its wall clock with another's. The metrics are `vlpds_lease_renew_ttl_ratio` and
`vlpds_lease_ttl_seconds`, and the alerts are `VlpdsLeaseRenewalNearCeiling` and
`VlpdsLeaseValidityLow`. For procedures, see [Lease trouble](operations/runbook.md#lease-trouble).

## Failure and takeover

```steps
- title: A peer presumes the node dead
  body: Its lease hasn't changed for 1.2 × TTL of the peer's own time, or its port refuses connections. Meanwhile, writes for its shards are refused at connect and the entry node resends them.
- title: The peer fences the dead log
  body: "The peer does a create-only PUT of a fence object at the dead log's first missing ordinal (the end of its durable prefix). If the old process later PUTs at that ordinal, the PUT collides and the process exits (code 3)."
- title: New owners take the shards by CAS
  body: Each survivor CASes `assign/{shard}` to name itself, up to its fair share. The new assignment has epoch + 1 and closes the dead span at the fence.
- title: Replay, then commit-wait
  body: "The new owner opens the shard's SlateDB and replays every span after its applied marker (one pass over the dead log for all its shards). It warms caches for up to 5 s, then waits until its clock passes the shard's `seq_floor` (at most 30 s) so the repo's firehose order holds."
- title: Serve
  body: Routing on every node catches up within a step. The shard's recently written repos (`meta/recent`) get preloaded in the background.
```

```diagram
caption: "The dead node's log after fencing. Everything below the fence is replayed; anything a zombie lands past it is never read."
nodes:
  - { id: s0, label: "…", at: [0, 0], size: [5, 2.6], shape: store, tone: amber }
  - { id: s1, label: "`40.seg`", at: [6, 0], size: [7, 2.6], shape: store, tone: amber }
  - { id: s2, label: "`41.seg`", at: [14, 0], size: [7, 2.6], shape: store, tone: amber }
  - { id: f, label: "`42` fence", sub: create-only PUT, at: [22, 0], size: [8, 2.6], tone: danger }
  - { id: z, label: "`43.seg`", sub: never read, at: [31, 0], size: [7, 2.6], shape: note, tone: muted }
groups:
  - { label: "the dead node's log", around: [s0, s1, s2, f, z], tone: amber }
notes:
  - { at: [0, 4.4], text: replayed by the new owners, align: start }
  - { at: [22, 4.4], text: "the old process's PUT here collides: exit 3", align: start }
```

Here's why no acknowledged write is lost, whatever the clocks do:

- A write is acked only when it's durable and the lease is valid. Its segment and every earlier one
  are in the bucket, and the node checked its lease after applying.
- Fencing closes the log. Acks go out in ordinal order, so the old process can't ack anything at or
  past the fence. Everything it did ack is below the fence and gets replayed.
- CAS gives each epoch one owner. SlateDB's own writer epoch also fences a second writer of a
  shard's state.
- When in doubt, the node exits. It fail-stops when its validity ends, a renewal CAS conflicts, a
  shard it holds is reassigned, a close fails, or its log is fenced. A supervisor restarts it and it
  rejoins.

So a wrong "it's dead" guess costs a fence, a fail-stop and a few seconds of resends, but never
data. The remaining assumptions are that clocks drift at a rate under 20 % and that no VM is
suspended longer than `--fence-retention` (7 days). Work in the dead node's memory that wasn't
durable yet was never confirmed to anyone or sent on the firehose, so dropping it is safe. A write
that was durable but not acked yet is below the fence, so it's replayed and kept, and it may already
be on the firehose ([a crash at each point](the-path-of-a-commit.md#a-crash-at-each-point)). In
the HA matrix (`bench/ha/RESULTS.md`), a kill -9 under load costs only the writes that were in
flight on the dead node (a few hundred at 6–9k writes/s), with 0 errors after the takeover.

The exit codes are listed in [Exit codes and fail-stops](operations/runbook.md#exit-codes-and-fail-stops).

## Handoff, handback and joining

```steps
- title: Pick recipients and prewarm
  body: "The releasing node picks a recipient per shard and asks it to warm the shard's SST filters, indexes and newest L0s, and its recently written repos (`/internal/v1/cluster/prewarm`, at most 10 s). It keeps serving in the meantime."
- title: One barrier segment
  body: "The node writes a single barrier for all the shards it's releasing. Once the barrier is durable, every earlier entry of those shards is durable and applied. Later writes for them are answered `ShardMoved` and resent."
- title: Checkpoint and close
  body: It writes the applied marker, flushes the memtable and closes the DB.
- title: CAS the assignment to the recipient
  body: "The new assignment has epoch + 1, closes the releaser's span at the barrier and opens a span in the recipient's log. Then the node nudges the recipient and every other peer, so routing follows at once."
- title: The recipient serves
  body: "It opens SlateDB (~11 sequential store calls, ~0.2 s), waits out `seq_floor` and serves with warm caches."
```

The same handoff runs in three situations:

- Rebalance (handback). A node holding more than its fair share hands the extras straight to peers
  that are short of theirs, like a node that just joined or restarted.
- Graceful shutdown. SIGTERM marks the lease `draining`, so peers stop counting it toward fair
  shares. The node hands out every shard, fences its own log and deletes the lease. Then it serves
  500 ms more so in-flight forwards get an answer instead of a dropped connection (a node without
  peers skips this). It stops accepting connections, closes its firehose subscribers and exits once
  every request still in flight is answered, waiting 30 s at most. If it can't fence
  its log within min(TTL, 30 s), it exits 8 and leaves the lease for a peer or its own restart to
  fence.
- Joining. A new or restarted node takes no shards until every live peer confirms it's following
  the joiner's log, so the merged firehose can't miss its first events (see
  [Firehose](firehose.md#joining-and-leaving)). It forwards writes in the meantime. Then it publishes
  `joined` in its lease, and peers hand back its share at their next step. A node restarted with the
  same `--node-id` fences its previous incarnation's log at startup. Once it has joined, it reclaims
  the shards still assigned to that incarnation without waiting for a handback.

Rolling deploys rely on this. See [Rolling deploy](operations/upgrades.md#rolling-deploy) and
[Adding a node](operations/scaling-and-clustering.md#adding-a-node).

## Threads and runtimes

| Pool | Threads (default) | Runs |
|---|---|---|
| IO runtime (tokio) | all available cores, cgroup-aware (`--io-threads`) | HTTP, JSON and CBOR, auth, forwarding, the log sequencer and finalizer, SlateDB, the cluster loop |
| Repo workers | half the cores, min 1 (`--workers`) | MST updates, commit signing, repo views. A DID always lands on the same worker |
| Firehose runtime | 4 (`--firehose-threads`, and 0 shares the IO runtime) | `subscribeRepos` sockets, so fan-out never competes with requests |
| Commit pool | a quarter of the cores, 2–8 | segment compression only. Nothing a request starts runs here |
| tokio blocking pool | on demand | getRepo walks, cold repo loads, Argon2 (one per core, 16 max), segment decoding |
| Small helpers | 1 each | memory re-planning every 5 s, stalled-connection sweep |

A panic in a thread or task the node can't run without (a repo worker, the log sequencer or
finalizer, the firehose merger) fail-stops the process with exit 9, so it doesn't stay up wedged. A
10 ms ticker on the IO runtime measures how late it runs (`vlpds_runtime_tick_late_seconds`,
`VlpdsRuntimeStalls`). Sustained lateness means the runtime is starved of CPU or something is
blocking it. Lowering `--io-threads` caps how much CPU proxy-heavy load can take from commits.

## Single-node mode

```facts
- { value: "1", unit: shard, label: on the tiny profile, note: "the default `--shards 64` also works on one node" }
- { value: "60 s", label: lease TTL on tiny, note: "renewal every 12 s · ~53 s of write downtime after a crash, 0.8 s after SIGTERM (measured)", tone: violet }
- { value: "~0.12", unit: Class A/s, label: idle object-store writes, note: "plus ~0.41 Class B/s · $0 on R2, ~$2/mo on S3", tone: blue }
```

A single node runs the same code as a one-node cluster. It holds the only lease, owns every shard
and writes the same objects. Two things differ:

- No peer transport. Without `--peer-listen`, `--peer-tls-dir` and `--advertise-url`, the node has
  no peer listener and makes no peer calls. To grow to a cluster, start every node with all three
  (see [Peer TLS](keys-security.md#peer-tls)) on the same bucket and prefix. No data moves.
- It lists less. While `nodes/` holds only its own lease, a step LISTs `nodes/` once per TTL and
  `assign/` every 25 steps instead of every step. That removes most of an idle node's requests
  (`vlpds_cluster_lone_skips_total`). A joiner's greeting, or its lease showing up in the next
  listing, switches it back at once.

The long TTL is the tiny profile's trade-off. The node sends one renewal PUT every 12 s instead of
every 2 s, but after a crash (not a graceful restart) it waits about one TTL before it acks writes
again. See [Profiles](operations/deploy.md#profiles).
