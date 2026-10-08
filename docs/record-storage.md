---
title: Record storage
section: vlPDS
order: 4
status: ready
summary: "Records are the source of truth. vlpds stores the MST's interior nodes, rebuilds the leaves, and keeps only the visited paths in memory."
---

```hero
diagram:
  caption: "One repo in the shard's SlateDB. The head names the MST root; interior nodes are `M/` rows, leaves are never stored (each is rebuilt from the `R/` records between its parent's keys), and the repo worker holds only the paths recent writes visited."
  nodes:
    - { id: head, label: "`h/{did}`", sub: signed commit · rev, at: [11, 0], size: [10, 2.6], shape: store, tone: amber }
    - { id: root, label: "`M/` root", sub: interior node, at: [11, 4.5], size: [10, 2.6], shape: store, tone: amber }
    - { id: i1, label: "`M/` node", sub: height 1, at: [2, 9], size: [11, 2.6], shape: store, tone: amber }
    - { id: i2, label: "`M/` node", sub: height 1, at: [19, 9], size: [11, 2.6], shape: store, tone: amber }
    - { id: l1, label: leaf, sub: not stored, at: [0, 13.5], size: [6.5, 2.4], shape: note, tone: muted }
    - { id: l2, label: leaf, sub: not stored, at: [8.5, 13.5], size: [6.5, 2.4], shape: note, tone: muted }
    - { id: l3, label: leaf, sub: not stored, at: [17, 13.5], size: [6.5, 2.4], shape: note, tone: muted }
    - { id: l4, label: leaf, sub: not stored, at: [25.5, 13.5], size: [6.5, 2.4], shape: note, tone: muted }
    - { id: rec, label: "`R/` records", sub: "cid · rev · record bytes: the truth", at: [0, 18], size: [32, 2.6], shape: store, tone: amber }
    - { id: worker, label: Repo worker, sub: "LazyTree: visited paths", at: [37, 4.3], size: [10, 3], tone: accent }
  edges:
    - "head.b -> root.t: data"
    - root.b30 -> i1.t
    - root.b70 -> i2.t
    - i1.b11 -> l1.t
    - i1.b89 -> l2.t
    - i2.b11 -> l3.t
    - i2.b89 -> l4.t
    - { from: rec.t10, to: l1.b, dash: true }
    - { from: rec.t37, to: l2.b, dash: true, label: rebuild }
    - { from: rec.t63, to: l3.b, dash: true }
    - { from: rec.t90, to: l4.b, dash: true }
    - { from: worker.l, to: root.r, label: load on demand, dash: true }
facts:
  - { value: "+28 B", unit: /record, label: "for persisted interior nodes", note: "`M/`: about a quarter of the tree's nodes; leaves cost nothing" }
  - { value: "~10–20 KB", label: in memory per active repo, note: "its visited paths, whatever the repo's size; ~3 KB once idle", tone: blue }
  - { value: "1", unit: "`M/` scan", label: to load a cold repo's tree, note: "covers repos up to ~35k records, after the head and account reads", tone: violet }
  - { value: "200", unit: ops, label: per coalesced commit, note: "queued writes to one repo share a commit; no added delay", tone: amber }
```

Each account's repo lives in its shard's SlateDB: the records, the Merkle Search Tree (MST) over
them and the signed commit. How that's laid out decides what a node's memory is spent on, what a
cold repo costs to open, and which metrics show trouble.

Records are the source of truth. vlpds also stores the tree's interior nodes, so after a few fixed
reads (head, account) a cold repo's tree loads with one range scan, and the leaves are rebuilt from
records when they're needed. A repo worker only keeps the paths that recent writes touched in
memory.

## Repos, commits and the MST

```diagram
caption: "An atproto repo. The signed commit names the MST root; the tree maps each `collection/rkey` to a record CID. Changing one record rewrites one root-to-leaf path and produces a new signed commit."
nodes:
  - { id: commit, label: Signed commit, sub: "did · rev · data · sig", at: [0, 0], size: [9, 3], tone: accent }
  - { id: root, label: MST root, at: [13, 0], size: [8, 3] }
  - { id: path, label: Interior nodes, sub: "~log₄ n deep", at: [25, 0], size: [8, 3] }
  - { id: leaf, label: Leaves, sub: "keys → record CIDs", at: [37, 0], size: [8, 3] }
  - { id: rec, label: Records, sub: DAG-CBOR blocks, at: [37, 5.5], size: [8, 3] }
edges:
  - "commit -> root: data"
  - root -> path
  - path -> leaf
  - "leaf -> rec: CID"
```

Every account has one repo. A **record** is a DAG-CBOR block stored under a key `collection/rkey`
(`app.bsky.feed.post/3l…`). The **MST** is a sorted tree over those keys whose shape is fixed by
the keys alone, so the same set of records always gives the same root. The **commit** names the
root (`data`), carries a revision (`rev`, a TID) and is signed with the account's key.

A write changes one leaf and every node above it, which is a path of 8–12 nodes for repos of
10k–1M records. The commit's CAR (the changed nodes, the new records, and the neighbour nodes a sync 1.1
inversion proof needs) goes into the [log](firehose.md) and out on the firehose unchanged.

## What is stored and what is derived

```diagram
caption: "Applying one commit. The log segment holds the commit's CAR and the `M/` deletes; everything else is derived from the CAR, both live and at replay. All of it lands in one SlateDB write batch."
nodes:
  - { id: seg, label: "`log/` segment", sub: "#commit CAR · `M/` deletes", at: [0, 4.2], size: [10, 3], shape: store, tone: amber }
  - { id: apply, label: Apply, sub: one state batch, at: [14, 4.2], size: [8, 3], tone: accent }
  - { id: h, label: "`h/{did}`", sub: head commit, at: [27, 0], size: [11, 2.4], shape: store, tone: amber }
  - { id: r, label: "`R/` `c/`", sub: records · CID index, at: [27, 3], size: [11, 2.4], shape: store, tone: amber }
  - { id: m, label: "`M/`", sub: node puts · deletes, at: [27, 6], size: [11, 2.4], shape: store, tone: amber }
  - { id: b, label: "`b/` `bl/` `C/` `S/`", sub: "blob refs · backlinks · counts", at: [27, 9], size: [11, 2.4], shape: store, tone: amber }
groups:
  - { label: "shard SlateDB · `state/{shard}/`", around: [h, r, m, b], tone: amber, pad: 0.7 }
edges:
  - "seg -> apply: durable"
  - apply.r20 -> h.l
  - apply.r40 -> r.l
  - apply.r60 -> m.l
  - apply.r80 -> b.l
```

| Data | Stored as | Notes |
|---|---|---|
| Repo head | `h/{did}` | commit CID, data root, rev and the signed commit block |
| Records | `R/{did}\0{gen}{collection}/{rkey}` | CID, rev and the record bytes (the source of truth for the tree) |
| Record CID index | `c/{did}\0{gen}…` | lets `getBlocks` find a record by CID |
| Interior MST nodes | `M/{did}\0{gen}{cid}` | height ≥ 1, about a quarter of all nodes, +28 B per record |
| MST leaves | not stored | rebuilt from the `R/` range between the parent's separator keys |
| Blob references, backlinks, counts | `b/`, `bl/`, `C/`, `S/` | written in the same batch (see [Blobs](blobs.md#references)) |

Each commit's state batch is ~3.3–3.5 KB into SlateDB: the records, the head, ~7 node puts and ~7
node deletes. The `M/` puts, records and head are rebuilt from the commit's CAR, so the log stores
them once, as the firehose frame. Only the `M/` deletes (the replaced nodes, ~7 × 33 B) are
stored in the segment. Since puts and deletes land in one batch, `M/{did}` always holds exactly
the interior nodes of the tree `h/{did}` points at.

`{gen}` is the repo's **generation**, which is usually one byte. An import writes the new repo
under a fresh generation and switches to it in one entry ([Imports](#imports)). Every key starts
with the DID's slot, so a shard's rows are one contiguous range. The full key layout is in
[State storage](state-storage.md#key-layout).

## Partial trees in memory

```diagram
caption: "What a repo worker holds for a write at key K. K's path and the paths to its neighbours P and S are loaded (a delete merges their spines, and the sync 1.1 proof carries them). Every other subtree is only a CID."
nodes:
  - { id: root, label: root, sub: loaded, at: [14, 0], size: [8, 2.6], tone: accent }
  - { id: u1, label: subtree, sub: CID only, at: [2, 4.5], size: [8, 2.6], shape: note, tone: muted }
  - { id: n1, label: node, sub: loaded, at: [14, 4.5], size: [8, 2.6], tone: accent }
  - { id: u2, label: subtree, sub: CID only, at: [26, 4.5], size: [8, 2.6], shape: note, tone: muted }
  - { id: lp, label: "P's leaf", at: [5, 9], size: [7, 2.6], tone: accent }
  - { id: lk, label: "K's leaf", sub: written, at: [14.5, 9], size: [7, 2.6], tone: solid }
  - { id: ls, label: "S's leaf", at: [24, 9], size: [7, 2.6], tone: accent }
edges:
  - { from: root.b15, to: u1.t, dash: true }
  - root.b -> n1.t
  - { from: root.b85, to: u2.t, dash: true }
  - n1.b15 -> lp.t
  - n1.b -> lk.t
  - n1.b85 -> ls.t
```

Each repo belongs to one **repo worker** thread, picked by a hash of the DID. There are
`--workers` of them (half the cores by default). The worker keeps a `LazyTree` for each cached
repo. It holds the nodes on the paths recent operations visited, and every other subtree is just
its CID. Inserts, deletes, CIDs and proofs run the same MST code a fully loaded tree would (the
`mst` module of [vlatproto](https://github.com/jazware/vlatproto)), so commits are byte-identical. A written repo costs ~10–20 KB of memory whether it has 100 records or
10 million, and ~3 KB once it drops back to its root.

The worker's cache has two limits:

- Bytes, set by `--repo-cache-mb`. The default is half of the memory budget's cache pool after the
  SST metadata cache. Over budget, the least recently used idle repos drop back to their root
  first, and then the least recently used repos are evicted. Both steps skip a repo with a commit
  or a fetch in flight, so it stays until that finishes. A repo charged over 1 MiB (an import, a
  rebuild, or a repo written without pause) drops everything but the nodes its in-flight commits
  wrote.
- Repo count, set by `--cache-per-worker` (50,000 repos per worker). Past it, the least recently
  used repos are evicted the same way.

There are two more caches next to it. The process keeps loaded nodes by CID for readers and path
fetches (`--lazy-mst-node-cache-mb`, 256 MiB). Each shard also remembers the 2,048 repos it wrote
to most recently (`--preload-recent`), and its next owner opens those in the background after a
restart, takeover or handback.

Watch `sum(vlpds_repo_cache_bytes)` against `vlpds_repo_cache_capacity_bytes`, the unload rate
`vlpds_lazy_mst_unloads_total`, and `vlpds_repo_cache_lookups_total{result}`. A sustained miss rate
fires `VlpdsRepoCacheMissRateHigh`
([runbook](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#vlpdsrepocachemissratehigh)).
For sizing the pool, see [Configuration](operations/configuration.md#memory-budget-and-autosizing).

## Cold opens and verification

```steps
- title: Read the head and account
  body: "`h/{did}` and `a/{did}`, plus the import and count rows (`G/`, `S/`). If every store GET takes 20 ms, these fixed reads set a floor of ~100 ms."
- title: Prefetch the repo's `M/` range
  body: "One range scan of up to 1 MiB (`--lazy-mst-prefetch-kb`) covers every interior node of repos up to ~35k records. Bigger repos read their path node by node. That's 7–11 dependent reads, which still isn't proportional to the repo's size."
- title: Load the root and the first request's paths
  body: "The root comes from the head's `data` link. The paths the queued writes need load on the blocking pool, so the worker thread never waits on the store."
- title: Check every node on the way
  body: "Each loaded node must hash to the CID its parent links, and each rebuilt leaf too. The root must be the head's `data`."
```

With empty caches and 20 ms added to every store GET, a cold write takes ~110 ms for repos of
1k–100k records and ~460 ms at 1M records (measured). In production most of these reads hit the
node's NVMe disk cache. Blob references are read only when a write needs them (an update, a
delete, or a create that carries blobs). `vlpds_repo_load_seconds` shows cold-load latency.

If a root or node is missing or doesn't match its link, then `M/` is wrong and the repo itself is
fine. The open rebuilds the whole tree from `R/`, checks its root against the signed head, writes
the correct `M/` back through the log and carries on. The result is correct but slower, and it's
counted in `vlpds_lazy_mst_fallbacks_total{reason}` (`missing`, `missing_node`, `invalid`).
`invalid` fires `VlpdsLazyMstInvalid`. That should never happen, so file a bug with the logged DID
([runbook](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#vlpdslazymstinvalid)).

`vlpds admin check-repo` checks one repo offline: the commit, every record, the tree rebuilt
from the records, `M/`, and the indexes. `rebuild-repo` rewrites the derived rows under a new
signed commit. Neither helps if the records themselves no longer hash to the signed root, and
that case needs a restore. See [Admin console](operations/admin-console.md#admin-cli).

## Write coalescing and pipelining

```diagram
caption: "One repo's worker. Writes queued while it was busy become one commit. Commit N+1 is built on N's in-memory head while N is still uploading; acks go out in log order."
nodes:
  - { id: q, label: Queued writes, sub: "w1 · w2 · w3", at: [0, 0], size: [8, 3] }
  - { id: w, label: Repo worker, sub: drain · validate · sign, at: [12, 0], size: [9, 3], tone: accent }
  - { id: c2, label: commit N+1, sub: building, at: [25, 0], size: [8, 3], tone: accent }
  - { id: c1, label: commit N, sub: segment PUT in flight, at: [25, 5], size: [8, 3], tone: amber }
  - { id: ack, label: Acks, sub: "N, then N+1", at: [12, 5], size: [9, 3], tone: solid }
edges:
  - "q -> w: drain all"
  - w -> c2
  - "c2.b -> c1.t: builds on"
  - "c1 -> ack: durable"
```

When a repo's worker runs, it drains every queued write for that repo into one commit, up to 200
operations or 1 MB of record bytes. There's no timer. An idle repo gets one-operation commits and
a busy one gets bigger batches, so one repo can take far more writes per second than commits. A
few rules apply to a batch:

- A write with `swapCommit` starts a fresh commit, so the check is against a real commit boundary.
- `applyWrites` is one all-or-nothing unit inside the batch.
- Each write is validated against the batch so far, so a conflicting write (a duplicate create, a
  failed `swapRecord`) fails alone.
- Every write in the batch is acked with the shared commit CID and rev.

The worker doesn't wait for a commit to be durable before building the next one. `swapCommit`
and `swapRecord` compare against the in-memory head (pending commits included). That's safe
because the log keeps their order. Acks go out in log order, so a client never sees N+1 acked
before N. A commit costs ~44 µs of CPU on the worker thread with warm paths (measured with
`worker::bench_commit_cpu` on a 16-core Linux box). On the same box, the whole process spends
~185–240 µs of CPU per commit at 25–50k commits/s, counting HTTP and cold repo loads (measured).
When too many writes are queued, new ones get 503 `Overloaded` (`VlpdsWritesShed`). For what happens after the commit leaves the worker, see [Architecture](architecture.md#components-of-a-node).

## Reads: getRecord, getRepo, getBlocks

```diagram
caption: "Readers never touch the worker's tree. Each takes the repo's durable view (the tree at its latest durable commit) with a SlateDB snapshot of the same version."
nodes:
  - { id: view, label: Durable view, sub: "partial tree + snapshot", at: [0, 4.5], size: [10, 3], tone: accent }
  - { id: gr, label: sync.getRecord, sub: proof walk, at: [15, 0], size: [10, 2.6], tone: blue }
  - { id: rp, label: getRepo, sub: streamed CAR, at: [15, 4.7], size: [10, 2.6], tone: blue }
  - { id: gb, label: getBlocks, sub: "by CID", at: [15, 9.4], size: [10, 2.6], tone: blue }
  - { id: m, label: "`M/`", sub: nodes · read ahead, at: [30, 1.8], size: [9, 2.6], shape: store, tone: amber }
  - { id: r, label: "`R/` `c/`", sub: records · CID index, at: [30, 7.6], size: [9, 2.6], shape: store, tone: amber }
edges:
  - view.r20 -> gr.l
  - view.r -> rp.l
  - view.r80 -> gb.l
  - gr.r -> m.l30
  - rp.r30 -> m.l70
  - rp.r70 -> r.l30
  - gb.r -> r.l70
```

| Read | What it touches |
|---|---|
| `repo.getRecord`, `listRecords` | an `R/` point read or scan at the latest applied state, with no tree involved |
| `sync.getRecord` | the proof path from the durable view, walked against the snapshot |
| `getRepo` | a streamed CAR: commit first, then the tree in preorder with each record after the node naming it |
| `getBlocks` | loaded nodes, `M/` point reads, record CIDs via `c/`, and leaves through a per-repo index built on first use |

A durable segment is applied to the memtable before its writes are acked, so a read right after a
write sees it. Repo reads go to the account's owner
([Architecture](architecture.md#request-routing-and-forwarding)).

`getRepo` streams its CAR. It reads the repo's `M/` range ahead with one scan. It also runs one
forward `R/` scan that feeds the tree walk and supplies the record blocks, and the leaves are
rebuilt from those records and checked against their links. Memory per export stays at one path
plus ~4 MiB of records ahead, whatever the repo's size. The first byte goes out in milliseconds,
and a 10M-record repo (2.8 GB CAR) exports in ~8 s on a laptop (measured). These flags limit
exports:

| Flag | Default | What happens past it |
|---|---|---|
| `--max-exports` | 32 at once | waits up to 10 s for a slot, then 503 `Overloaded` |
| `--export-stall-secs` | 60 | an export whose client reads nothing ends with an error, never a short CAR |
| `M/` read-ahead pool | 512 MiB per node | the export drops the height-1 nodes and rebuilds them from records |

Watch `vlpds_sync_exports{state}` and `vlpds_sync_exports_ended_total{reason}`.

## Imports

```steps
- title: Begin
  body: "Reserve a new generation and the rev of the import's commit (`G/{did}`). From here on, writes to the repo get a 400 (\"a repo import is in progress\")."
- title: Rows
  body: "As the CAR streams in, vlpds writes verified records and rebuilt `M/` nodes in batches of 4,096 records or 4 MiB under the new generation. No reader looks at that generation yet."
- title: Commit
  body: "One small entry holds the new signed head, the account switched to the new generation, counts and indexes, and one `#sync` on the firehose."
- title: Sweep
  body: "vlpds deletes the old generation's rows in batches of 8,192 keys."
```

`importRepo` (account migration) writes the new repo beside the old one and switches in one log
entry, so readers see either the old repo or the new one and never a mix. If the node crashes or
the shard moves before the Commit step, the old repo stays, and the client gets a retryable 503
and imports again. The node that owns the shard sweeps leftover staged rows within a minute.

vlpds parses a CAR in the spec's streamable order in one pass, holding only the current path. Any
other order falls back to a buffered parse, which stays in memory up to 16 MiB and then goes to a
temp file. Memory is bounded. A 1M-record import peaks at ~375 MB of heap and 5M at ~1 GB
(measured), and most of that is the write path's own buffers.

| Setting | Default | Meaning |
|---|---|---|
| `--max-import-mb` | 1,024 MiB | largest CAR accepted |
| `--import-memory-mb` | 1/16 of the memory budget, 192 MiB to 1 GiB | shared budget · each import reserves 512 KiB to 80 MiB by size |
| large share | half the budget | imports over 8 MiB together never hold more than half, so small ones always get in |

An import that waits more than 30 s for admission, or 10 s to grow its reservation (a body larger than
its Content-Length promised), fails with 503 `Overloaded`. The metrics are
`vlpds_imports{state}`, `vlpds_import_reserved_bytes`, `vlpds_import_budget_bytes` and
`vlpds_import_admissions_total{result}`. [Migration](migration.md) covers the whole move, blobs
and identity included.
