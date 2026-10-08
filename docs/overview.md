---
title: Overview
section: vlPDS
order: 1
summary: An atproto PDS whose only durable storage is an object store. Any node serves any request, one node can run a personal server for free, and a few nodes can carry all of Bluesky's write load.
---

```hero
diagram:
  caption: Clients reach any node through Caddy. A node owns some shards, forwards the rest to their owners, and keeps everything durable in the bucket. The local disk is only a cache.
  nodes:
    - { id: apps, label: Apps, sub: XRPC · OAuth, at: [0, 1], size: [7, 3] }
    - { id: relays, label: Relays, sub: firehose consumers, at: [0, 10], size: [7, 3] }
    - { id: caddy, label: Caddy, sub: TLS · handle certs, at: [10, 5.5], size: [7, 3] }
    - { id: n1, label: vlpds node 1, sub: shards 0–21 · log 1, at: [21, 1], size: [9, 3], tone: accent }
    - { id: n2, label: vlpds node 2, sub: shards 22–42 · log 2, at: [21, 5.5], size: [9, 3], tone: accent }
    - { id: n3, label: vlpds node 3, sub: shards 43–63 · log 3, at: [21, 10], size: [9, 3], tone: accent }
    - { id: log, label: "`log/`", sub: segments · WAL + firehose, at: [35, 0.5], size: [10, 2.6], shape: store, tone: amber }
    - { id: state, label: "`state/{shard}/`", sub: SlateDB per shard, at: [35, 4], size: [10, 2.6], shape: store, tone: amber }
    - { id: ctl, label: "`nodes/` `assign/`", sub: leases · ownership, at: [35, 7.5], size: [10, 2.6], shape: store, tone: amber }
    - { id: blob, label: "`blob/`", sub: images · video, at: [35, 11], size: [10, 2.6], shape: store, tone: amber }
    - { id: appview, label: AppView, sub: proxied app reads, at: [10, 16], size: [7, 2.6], tone: muted }
    - { id: plc, label: PLC directory, sub: DID documents, at: [21, 16], size: [9, 2.6], tone: muted }
    - { id: kms, label: Cloud KMS, sub: optional KEK, at: [35, 16], size: [10, 2.6], tone: muted }
  groups:
    - { label: vlpds cluster, around: [n1, n2, n3], tone: accent }
    - { label: object store · the only durable state, around: [log, state, ctl, blob], tone: amber }
  edges:
    - "apps.r -> caddy.l30: HTTPS"
    - "caddy.l70 -> relays.r: subscribeRepos"
    - caddy.r -> n1.l
    - "caddy.r -> n2.l: any node"
    - caddy.r -> n3.l
    - "n1 <-> n2: forward to owner"
    - n2 <-> n3
    - "n1.r30 -> log.l: append, then ack"
    - { from: n1.r70, to: state.l, label: apply · read }
    - { from: n2.r, to: ctl.l, label: lease CAS, dash: true }
    - { from: n3.r, to: blob.l, label: blobs }
    - { from: n3.b15, to: appview.t, label: app.bsky.* }
    - { from: n3.b50, to: plc.t50, label: identity ops }
    - { from: n3.b85, to: kms.t, label: unwrap keys, dash: true }
facts:
  - { value: "1", unit: bucket, label: is the whole database, note: "log, state, leases and blobs live in S3 / R2 / GCS" }
  - { value: "~60k", unit: commits/s, label: per 16-core node, note: "measured; Bluesky averages ~330/s today", tone: amber }
  - { value: "$0", unit: /mo, label: object store for a personal PDS, note: "on R2's free tier; ~$2–4 on S3", tone: blue }
  - { value: "~12 s", label: to notice a crashed node, note: "then fence, replay, serve; a planned handoff is ~0.2 s", tone: violet }
```

vlpds is an [atproto](https://atproto.com) personal data server (PDS) written in Rust that uses an
object store as its database. Every acknowledged write is already in the bucket and nodes only keep
caches, so adding capacity just means adding nodes that point at the same bucket. It speaks the same
XRPC, OAuth and sync 1.1 firehose as the reference PDS, so apps, relays and AppViews can't tell the
difference.

Each section below links to the page with the details.

## The shape of the system

```diagram
caption: The write path. A commit is acknowledged only after the segment holding it, and every earlier one, is in the object store.
nodes:
  - { id: req, label: createRecord, sub: any node, at: [0, 0], size: [7, 3] }
  - { id: worker, label: Repo worker, sub: MST path · sign commit, at: [10, 0], size: [8, 3], tone: accent }
  - { id: seq, label: Log writer, sub: group commit, at: [21, 0], size: [8, 3], tone: accent }
  - { id: seg, label: "`log/…/{ordinal}.seg`", sub: If-None-Match PUT, at: [32, 0], size: [9, 3], shape: store, tone: amber }
  - { id: slate, label: SlateDB memtable, sub: apply for reads, at: [32, 6.5], size: [9, 2.6] }
  - { id: ack, label: HTTP 200, sub: cid · rev, at: [21, 6.5], size: [8, 2.6], tone: solid }
  - { id: fh, label: Firehose, sub: merged across nodes, at: [10, 6.5], size: [8, 2.6], tone: blue }
edges:
  - req -> worker
  - "worker -> seq: commit"
  - "seq -> seg: segment"
  - "seg -> slate: durable, then apply"
  - "slate -> ack: then 200"
  - { from: seg.b10, to: fh.t, label: sealed segments, tone: blue }
```

- Repo workers keep each active repo's MST paths in memory, apply the operations and sign the
  commit. A worker can build a repo's next commit while the previous one is still uploading, but
  nothing is acked early: each 200 waits until that commit and every one before it are durable.
  That pipelining is how a single repo can take hundreds of commits a second.
- The log batches the commits for every shard on a node into segments. Whatever queued up while
  the previous PUT was in flight (up to 8 MiB) becomes the next segment, written with
  `If-None-Match: *`. The log is both the write-ahead log and the firehose, so every write is
  stored once.
- A write is durable before its 200. The 200 goes out only after the segment holding the commit,
  and every earlier segment, is in the bucket. One log per node is the write-ahead log for all of
  that node's shards, so each shard doesn't need a WAL of its own: a node pays one PUT per round
  trip however many shards it owns.
- State (records, repo heads, accounts and MST interior nodes) lives in one SlateDB per shard,
  with SlateDB's own WAL off because the node log already does that job. A durable segment is
  applied to the shard's memtable before the 200, so a read right after a write sees it. SlateDB
  writes SSTs to the bucket afterwards, and a checkpoint every 10 s records how far each shard has
  got. If a node dies in between, the shard's next owner replays the log from that checkpoint, so
  every acknowledged write comes back.
- The firehose on every node merges the logs from every node. It emits an event once every log's
  durable watermark has passed it, so every node sends events in the same order.

Details: [The path of a commit](the-path-of-a-commit.md) (one write, stage by stage, and a crash
at each stage), [Architecture](architecture.md), [Record storage](record-storage.md),
[State storage](state-storage.md), [Firehose](firehose.md).

## Shards, leases and ownership

```diagram
caption: 65,536 fixed hash slots grouped into shards (64 by default). Each shard has exactly one owner, recorded in `assign/{shard}`; each node holds one lease in `nodes/{node}`. Nothing else coordinates the nodes.
nodes:
  - { id: did, label: "did:plc:…", sub: sha256 → slot, at: [0, 2], size: [7, 3] }
  - { id: slots, label: "65,536 slots", sub: permanent, at: [10, 2], size: [8, 3], tone: muted }
  - { id: s0, label: shard 0, at: [21, 0], size: [6, 2], tone: accent }
  - { id: s1, label: shard 1, at: [21, 2.5], size: [6, 2], tone: accent }
  - { id: s63, label: shard 63, at: [21, 5], size: [6, 2], tone: blue }
  - { id: na, label: node A, sub: "lease `nodes/a`", at: [31, 0.5], size: [8, 3], tone: accent }
  - { id: nb, label: node B, sub: "lease `nodes/b`", at: [31, 4.5], size: [8, 3], tone: blue }
edges:
  - did -> slots
  - slots.r -> s0.l
  - slots.r -> s1.l
  - "slots.r -> s63.l"
  - "s0.r -> na.l40: owner"
  - s1.r -> na.l70
  - "s63.r -> nb.l: owner"
notes:
  - { at: [21, 8.6], text: "split / merge online" }
```

Every DID hashes to one of 65,536 slots, and that never changes. Slots are grouped into contiguous
shards. A shard is the unit of ownership and of state (it gets its own SlateDB), and you can split
or merge shards online.

Each node takes up to its fair share of shards (shards ÷ live nodes). A node renews one lease for
itself, no matter how many shards it owns. Leases and assignments are compare-and-swap writes on
objects in the bucket, so there's no ZooKeeper, Raft or quorum to run. Two nodes are enough for
high availability.

Any node accepts any request. If a node gets a write or a repo read for a shard it doesn't own, it
forwards the request to the owner over HTTP/2 with mutual TLS. App reads go to the account's owner,
which proxies them to the AppView. See [Architecture](architecture.md#shards-and-ownership) and
[Proxying](proxying.md).

## How big it gets

```facts
- { value: "~60k", unit: commits/s, label: one 16-core node, note: "measured with 25 ms injected store latency; ~90k with none", tone: amber }
- { value: "~300k", unit: req/s, label: AppView proxying per node, note: "about 50 µs of CPU per request" }
- { value: "100M", unit: accounts, label: bulk-created in a test cluster, note: "4 nodes on one MinIO", tone: blue }
- { value: "~$1.7k", unit: /mo, label: "S3 bill for all of Bluesky's writes", note: "modeled; 3 nodes · 64 shards · in-region", tone: violet }
```

These are round numbers from the benchmark runs in `bench/results/`. The object-store bill at
Bluesky's load is modeled from measured request rates (`bench/results/cost-model-2026-10-02`).
Here's how they compare for a personal server and for all of Bluesky:

| | Personal | Bluesky today |
|---|---|---|
| Accounts | a handful | 56 M repos, 24 B records |
| Commits/s | a few a day | ~330 avg, ~900 bursts |
| Nodes | 1 small VM (`tiny` profile) | 3 × 6–8 cores, 32 GB, NVMe |
| Busy cores, fleet-wide | ~0 | ~3 |
| Object store requests | $0 on R2, ~$2–4 on S3 | ~$1.7k/mo (S3), ~$1.5k (R2), modeled |

A few things about where the costs come from:

- Most of the CPU goes to logins and proxying. A commit costs ~185–240 µs of whole-process CPU
  at 25–50k commits/s, HTTP and cold repo loads included (measured on a 16-core node), and an
  Argon2 login costs ~20 ms.
- The object-store bill depends on how many shards and nodes you run, not on how fast you write.
  Whenever anything is queued, a node PUTs about one segment per store round trip (~27/s), whether
  that segment holds 300 commits or 20,000. Per-shard polling and checkpoints are fixed costs too.
  That's why the default is 64 shards and a personal server runs one.
- Memory depends on how many repos are active. Only the MST paths that recent writes visited stay
  in memory (~10–20 KB per active repo), so at Bluesky's scale a 32 GB node holds a day's worth of
  writers.

Details: [Scaling and clustering](operations/scaling-and-clustering.md),
[Configuration](operations/configuration.md).

## Design philosophy

- The bucket is the one source of truth. It holds everything durable, so losing a node or a disk
  only costs cache. A new host just needs the bucket's credentials and its secrets.
- Commits are grouped. If we wrote one object per commit, we'd pay ~$43k a day in PUTs at 100k
  commits/s. Instead, vlpds batches the commits from every repo on a node into one segment, so
  request cost grows with the number of nodes instead of with traffic.
- Commits are pipelined. A repo's next commit builds on the in-memory head while the previous one
  is still uploading. Acks still wait: each goes out only once its commit is durable, in log order.
  So the object store's latency adds to each write's latency but doesn't cap how fast a repo can
  write.
- The log is both the WAL and the firehose. A write is stored once, and recovery replays the same
  segments that relays receive.
- vlpds derives what it can. MST leaves are rebuilt from records instead of being stored, and
  record values are rebuilt from a commit's CAR at replay. That means less to write and fewer
  copies that could disagree.
- If a node isn't sure it's still allowed to write, it exits and its supervisor restarts it. Being
  unavailable for a while is recoverable, but a forked repo isn't.
- The dependencies are boring: S3-compatible storage, Caddy in front, Prometheus metrics, and a
  single static binary next to its built web UI.

## Robustness

```steps
- title: A node stops renewing its lease
  body: It crashed, lost the network, or fail-stopped on purpose. Peers notice when its lease object hasn't changed for 1.2 × TTL (12 s by default), or within a few seconds if its port refuses connections.
- title: A peer fences the dead node's log
  body: It conditionally creates a fence object at the end of the log's durable prefix. After that, the old process can't append anything to that log, even if it's still running.
- title: The new owner replays and serves
  body: It takes the shards by compare-and-swap on `assign/{shard}`, replays the dead log's tail for those shards from the bucket, waits out the old owner's last sequence number, and starts serving.
```

- A write is acked only after its segment and every earlier one are in the object store, and only
  while the node's lease is valid. If a node dies before a write is durable, that write was never
  confirmed to anyone or sent on the firehose, so it's safe to throw away. A write that was durable
  but not acked yet is kept. The next owner replays it, and it may already be on the firehose (see
  [A crash at each point](the-path-of-a-commit.md#a-crash-at-each-point)).
- Safety doesn't depend on clocks. Fencing and compare-and-swap decide who may write, and lease
  timing only decides when a takeover happens. If a peer wrongly decides a node is dead, it costs
  some availability but never an acked write.
- Fail-stop is the safety valve. If a segment PUT can't succeed, a lease renewal takes too long or
  a critical thread panics, the process exits with a specific code. The supervisor restarts it and
  it rejoins the cluster.
- Planned moves are fast. On a graceful shutdown or a rebalance, the node warms the recipient's
  caches, writes one barrier segment and hands each shard over in ~0.2 s. Rolling deploys cause
  almost no errors.
- Log segments are kept for 72 h for firehose backfill, and they're never deleted while any shard
  could still need them for replay.

Details: [Architecture](architecture.md#failure-and-takeover),
[Runbook](operations/runbook.md), [Backups and recovery](operations/backups-and-recovery.md).

## One node or many

```diagram
caption: The same binary and bucket layout either way. A single node owns every shard; a cluster spreads them, and shards move on their own as nodes join and leave.
nodes:
  - { id: one, label: one node, sub: owns all shards, at: [0, 1], size: [8, 3], tone: accent }
  - { id: b1, label: bucket, at: [11, 1], size: [7, 3], shape: store, tone: amber }
  - { id: c1, label: node 1, at: [24, 0], size: [6, 2.2], tone: accent }
  - { id: c2, label: node 2, at: [24, 2.6], size: [6, 2.2], tone: accent }
  - { id: c3, label: node 3, at: [24, 5.2], size: [6, 2.2], tone: accent }
  - { id: b2, label: bucket, at: [34, 2.2], size: [7, 3], shape: store, tone: amber }
groups:
  - { label: personal · tiny profile, around: [one, b1], tone: muted }
  - { label: cluster · standard profile, around: [c1, c2, c3, b2], tone: muted }
edges:
  - one <-> b1
  - c1.r -> b2.l
  - c2.r -> b2.l
  - c3.r -> b2.l
```

| | Single node (`tiny`) | Cluster (`standard`) |
|---|---|---|
| Shards | 1 | 64, split or merged online |
| Lease TTL | 60 s (a crash restart waits ~1 TTL) | 10 s (takeover in ~12 s) |
| Good for | a personal or small community PDS | many accounts, high availability |
| Grows by | adding a second node with the same bucket and prefix | adding nodes (shards rebalance by themselves) |

Going from one node to several doesn't need a migration. Start another node on the same bucket and
prefix, and it joins the cluster, follows the other nodes' logs and takes its share of shards. See
[Deploy](operations/deploy.md) and [Scaling and clustering](operations/scaling-and-clustering.md).

## Where to go next

- If you're running a server, start at [Operations](operations/index.md), then
  [Deploy](operations/deploy.md).
- To move an account here, see [Migration](migration.md).
- Spaces, atproto's permissioned-data alpha, is off unless you start nodes with `--spaces`. See
  [Spaces](spaces/index.md).
- For how identity and keys are protected, see [Keys and security](keys-security.md) and
  [OAuth and 2FA](oauth-2fa.md).
- `DESIGN.md` in the repository is the full design log, with every measurement and rejected
  alternative. These pages only cover how things work today.
