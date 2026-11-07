---
title: Writing and sync
section: Spaces
order: 202
status: draft
summary: "A space write from request to syncer: durable before the 200, a notify outbox that survives a crash, ordered fan-out, and pulls that are mostly answered from memory."
---

```hero
timeline:
  caption: "One createRecord into a space whose authority is on another host, then a syncer pulling it. There's no relay and no firehose. Times are client-side p50s from the interop harness (one node, MinIO). Spacing isn't to scale."
  scale: 46
  lanes:
    - { id: app, label: Author's app, sub: OAuth session, tone: ink }
    - { id: w, label: Author's node, sub: repo worker · log, tone: accent }
    - { id: store, label: Object store, sub: "`log/` segments", tone: amber }
    - { id: ob, label: Outbox, sub: "`sP` row", tone: accent }
    - { id: host, label: Authority, sub: space host, tone: violet }
    - { id: fan, label: Fan-out lane, sub: one per syncer, tone: violet }
    - { id: sync, label: Syncer, sub: app or indexer, tone: blue }
  spans:
    - { lane: w, from: 0.5, to: 2.6, label: build · batch }
    - { lane: store, from: 2.8, to: 5.6, label: segment PUT, tone: amber }
    - { lane: w, from: 5.8, to: 7.6, label: apply · ack }
    - { lane: ob, from: 8.2, to: 13.4, label: send · wait for 200 }
    - { lane: host, from: 8.6, to: 13.0, label: policy · spaceRev · PUT }
    - { lane: fan, from: 13.6, to: 15.6, label: forward, tone: violet }
    - { lane: w, from: 16.4, to: 19.6, label: oplog scan }
  arrows:
    - { from: app, to: w, at: 0.3, label: createRecord }
    - { from: w, to: store, at: 2.7 }
    - { from: w, to: app, at: 7.8, side: left, label: "200", tone: accent }
    - { from: ob, to: host, at: 8.4, label: notifyWrite }
    - { from: host, to: ob, at: 13.2, label: "200" }
    - { from: fan, to: sync, at: 13.8, label: "notifyWrite · spaceRev", tone: blue }
    - { from: sync, to: w, at: 16.1, side: left, label: listRepoOps, tone: blue }
    - { from: w, to: sync, at: 19.8, side: left, label: ops · signed commit, tone: blue }
  marks:
    - { at: 5.6, label: durable, tone: amber }
    - { at: 7.8, label: 200 sent }
    - { at: 13.0, label: sequenced, tone: violet }
    - { at: 19.8, label: synced, tone: blue }
  ticks:
    - { at: 0, label: "0" }
    - { at: 7.8, label: "~0.8 ms" }
    - { at: 13.8, label: "~1.7 ms" }
facts:
  - { value: "1", unit: log entry, label: per space write, note: "record · head · oplog · outbox row, all durable before the 200", tone: amber }
  - { value: "~0.8 ms", label: write p50, note: "1.3 ms p99 · reference ~4.2 ms p50 (interop harness)" }
  - { value: "~1.7 ms", label: notify end to end, note: "5.5 ms p99 · reference 4.5 / 8.3 ms", tone: violet }
  - { value: "~0.3 ms", label: "a no-op poll", note: "answered from memory · 0 bucket ops · reference 6.7 ms", tone: blue }
```

A space write is durable before its 200, the same as a public commit. What's different is what
happens next. Nothing goes on the firehose. The author's PDS tells the space's authority with
`notifyWrite`, the authority puts the writer into a space-wide order, and syncers pull the new ops
from the author's PDS.

## One write, one entry

```diagram
caption: "The repo worker turns a space write into one private log entry. Its rows all land in the same segment, so they're durable together. When the author is also the authority, the writer rows go in the same entry and no notify is sent."
nodes:
  - { id: app, label: createRecord, sub: "or put · delete · applyWrites", at: [0, 3], size: [9, 3], tone: ink }
  - { id: wk, label: Repo worker, sub: the author's, at: [12, 3], size: [8, 3], tone: accent }
  - { id: e, label: Private log entry, sub: "`frames: []`", at: [23, 3], size: [9, 3], tone: accent }
  - { id: sr, label: "`sR`", sub: record, at: [36, 0], size: [6, 2.2], tone: amber }
  - { id: so, label: "`sO`", sub: oplog ops, at: [36, 2.6], size: [6, 2.2], tone: amber }
  - { id: sh, label: "`sH`", sub: new head, at: [36, 5.2], size: [6, 2.2], tone: amber }
  - { id: sp, label: "`sP`", sub: outbox row, at: [36, 7.8], size: [6, 2.2], tone: amber }
  - { id: sw, label: "`sW` `sQ`", sub: self-authority only, at: [23, 8], size: [9, 2.2], shape: note, tone: violet }
groups:
  - { label: one segment PUT, around: [sr, so, sh, sp], tone: amber }
edges:
  - "app -> wk"
  - "wk -> e: one rev"
  - e.r -> sr.l
  - e.r -> so.l
  - e.r -> sh.l
  - e.r -> sp.l
  - { from: e.b, to: sw.t, dash: true }
```

- The worker serializes space writes with the account's status changes, so a write can't slip past a
  takedown or a deactivation.
- Ops in one `applyWrites` share a rev and land as one batch (200 ops at most). A write that would
  grow a space repo past `--space-repo-max-records` (100k) gets `InvalidRequest`.
- The 200 goes out once the segment is in the bucket, applied, and the lease re-checked. That's the
  same path as a public commit ([The path of a commit](../the-path-of-a-commit.md)).
- `clearRecords` is one entry too. It claims the repo (writes to it wait, as during an import),
  reads every record, blob ref and oplog row once the account's earlier entries are applied, checks
  a `delete` grant for each collection, and writes the deletes with the new head: a new rev over the
  empty set, so `data` is the empty repo's digest, and an empty oplog. In the authority's own repo
  the published `com.atproto.space.policy` and `com.atproto.memberspace.member` records stay and the
  head covers them. A repo with nothing to delete is left alone. The authority hears the new rev like
  any write, and the repo stays in the writer set.
- The space host's changes to a space (`createSpace`, `updateSpace`, `putMember`, `removeMember`)
  write the config and the records it publishes in one entry on the authority's worker, as the
  authority's own write to its repo there.
- Space writes share segments the way public commits do. The in-tree bench measured 0.50 segment
  PUTs per write with 4 writers on one repo and 0.125 with 16, the same for space and public writes
  ([Operating](operating.md#server-cost-on-one-node)).

## The outbox

```timeline
caption: "Single-flight per (repo, space). Revs 2 and 3 are acked while rev 1's notify is in flight, so they only move the row. The next send carries rev 3, whose hash covers rev 2."
scale: 46
lanes:
  - { id: w, label: Author's writes, tone: accent }
  - { id: ob, label: "`sP` row", sub: one per repo and space, tone: accent }
  - { id: h, label: Authority, tone: violet }
spans:
  - { lane: ob, from: 0.8, to: 6.0, label: rev 1 in flight }
  - { lane: h, from: 1.2, to: 5.6, label: sequence rev 1, tone: violet }
  - { lane: ob, from: 6.4, to: 10.4, label: rev 3 in flight }
  - { lane: h, from: 6.8, to: 10.0, label: sequence rev 3, tone: violet }
events:
  - { lane: w, at: 0.5, label: rev 1 }
  - { lane: w, at: 2.8, label: rev 2 }
  - { lane: w, at: 4.6, label: rev 3 }
arrows:
  - { from: ob, to: h, at: 1.0, label: notifyWrite }
  - { from: h, to: ob, at: 5.8, side: left, label: "200" }
  - { from: ob, to: h, at: 6.6, label: notifyWrite }
  - { from: h, to: ob, at: 10.2, side: left, label: "200" }
```

The `sP` row is written in the write's own entry, so a notify for every acked write survives a crash
or a takeover. The sending side lives in memory on the shard's owner.

| | Behaviour |
|---|---|
| When it sends | as soon as nothing is in flight for that (repo, space), with no linger |
| Where it sends | a local authority is told on its own worker with no HTTP. One on another cluster node gets `/internal/v1/space/notify`. When that node says the cluster doesn't host the authority, the sender remembers it for 5 min and goes straight to HTTP. Anything else gets `notifyWrite` at its `#atproto_space_host` (or `#atproto_pds`) with the writer's service auth, a 10 s timeout and the SSRF-guarded client |
| Retries | from 1 min, doubling to 1 h with 50–100% jitter, until 24 h after the rev was owed (written, renotified after a takedown, or found when its shard opened), not 24 h after the rev's own time, so an old rev (an import, a writer back from deactivation) gets its retries too. A permanent refusal drops the row |
| Inactive writers | a taken-down or deactivated account's rows wait and resume on reactivation |
| Cleanup | a delivered row's `sP` delete rides the author's next space write, so delivery costs no PUT |
| Bounds | 262,144 rows held in memory (the rest are rescanned once it drains to half) and 256 sends in flight. One authority gets 8 at most, and authorities whose last send failed share 32, so a slow one can't hold up the rest |

## At the authority

```steps
- title: Check the rev
  body: "`repoRev` more than 5 min in the future gets `FutureRev`. The writer must pass the space's policy: under `memberspace` `publicWrite` or a member with `write`, under `managedspace` the managing app (`checkUserAccess` with `access=write`, no `clientId`), under `personalspace` only the authority."
- title: Sequence it on the authority's worker
  body: "A `repoRev` below the writer's last one is a no-op, and so is the same `repoRev` with the same hash, so a resent notify is harmless. The same `repoRev` with another hash is a record takedown or its reversal changing what the writer serves ([Privacy](privacy.md#takedowns)), so it's sequenced again. From another host, it's sequenced only once the writer's PDS serves a signed commit with that hash at that rev, and at most 3 times per writer and space in 10 min. The rest are dropped and left to polls. The push isn't logged either, so if the author's host crashes before it goes, syncers find out on their next poll. Otherwise the worker assigns the next `spaceRev` (a TID) and writes `sW` plus the `sQ` swap as one private entry. One worker per authority means no lock."
- title: Leave the writer set
  body: "`removeWriter`, `removeMember` and a `putMember` without write delete the writer's `sW` row and its `sQ` entry on the same worker. Nothing tells syncers, and the writer's records stay where they are. Its next write the policy allows puts it back. `updateSpace` leaves the writer set as it is."
- title: Answer 200 once it's durable
  body: "The writer's outbox only drops its row after this."
- title: Fan out
  body: "Sequenced writes leave the worker in ack order for the fan-out, off the request path."
```

## Fan-out

```diagram
caption: "Each (space, service) gets its own lane, which sends one forward at a time in spaceRev order. A slow syncer holds up only its own lane. Bounds are per lane (256), per service host (4,096 queued, 16 sends in flight, with a host counted by its registrable domain or IP address, and each tenant of a hosting platform like fly.dev or github.io counted as its own host), per dispatcher (8 of them, 4,096 queued each), 65,536 queued and 16,384 lanes in all, and 512 sends in flight in all."
nodes:
  - { id: hw, label: Authority's worker, sub: acks in spaceRev order, at: [0, 4], size: [9, 3], tone: violet }
  - { id: d, label: Dispatcher, sub: reads `sN` registrations, at: [12.5, 4], size: [9, 3], tone: violet }
  - { id: l1, label: Lane, sub: space · syncer A, at: [25, 0], size: [9, 2.6], tone: violet }
  - { id: l2, label: Lane, sub: space · syncer B, at: [25, 4.2], size: [9, 2.6], tone: violet }
  - { id: l3, label: Lane, sub: space · syncer C, at: [25, 8.4], size: [9, 2.6], tone: violet }
  - { id: s1, label: Syncer A, at: [39, 0], size: [8, 2.6], tone: blue }
  - { id: s2, label: Syncer B, at: [39, 4.2], size: [8, 2.6], tone: blue }
  - { id: s3, label: Syncer C, sub: slow, at: [39, 8.4], size: [8, 2.6], tone: muted }
edges:
  - "hw -> d: sequenced"
  - d.r -> l1.l
  - d.r -> l2.l
  - d.r -> l3.l
  - "l1 -> s1: notifyWrite"
  - l2 -> s2
  - { from: l3, to: s3, label: retry · backoff, dash: true }
```

- A forward waiting in a lane is replaced by a newer one from the same writer, since only a writer's
  newest state is worth sending.
- The `prevSpaceRev` a lane sends is the last spaceRev it tried to send, delivered or not, so a
  replaced forward leaves no gap. After a forward lost for good (a full queue, retries run out), and
  on the first forward to each registration after the shard changes hands, it's the spaceRev
  sequenced just before, which `sQ` keeps. The syncer may never have heard that one, and the gap
  sends it to `listRepos`. That's fine. What must never happen is two forwards naming one
  `prevSpaceRev` with different successors, a fork in the chain the syncer follows, and a lane's
  memory from before a takeover could do that. The takeover tests check no syncer ever sees one.
- A failed forward is retried with jittered backoff from 1 s, but only while nothing newer from its
  writer waits.
- Registrations (`registerNotify`) last 24 h, and a space takes 256 at most, one authority's spaces 1,024 together, and one credential makes 60 an hour. An account governs 1,000 live spaces at most and creates 100 a day. A did:web can point each of its fragments at its own address, so only these and the global queue and lane caps keep slow endpoints from growing the fan-out's memory: past them a lane's oldest forward goes, marked as a gap, and a syncer catches up with `listRepos`. Expired ones are pruned. The prune's delete runs on the authority's worker and checks the expiry again there, so a syncer that renews while a prune is under way keeps its registration.
- Lanes live in memory. When a shard opens on a new owner, each of its spaces with a live
  registration sends one catch-up forward of its newest writer, naming the spaceRev before it. A
  syncer that's current ignores it, and one that missed a forward sees the gap and pulls `listRepos`.
  A catch-up that a newer write has passed by the time it's sent is dropped, so forwards stay in
  spaceRev order.
- A taken-down space forwards nothing, catch-ups included.

The reference sends each forward as it's sequenced, with no order. Its syncers see about 3–5
`prevSpaceRev` gaps per ~80 forwards, and each one costs a `listRepos` call.

## How a syncer pulls

| Call | Served from | Measured on vlpds | Reference |
|---|---|---|---|
| `listRepoOps`, `since` = head | the in-memory head, no state read | 0.28 ms p50 · 0.54 ms p99 · 0.12 ms server · 0 bucket ops | 6.7 ms p50 |
| `listRepoOps`, a delta | a range scan of `sO` from `since`, values joined from `sR` | 0.41 ms p50 · 1.9 ms p99 · 0.17 ms server | 8.3 ms |
| `getRepo` | two streamed passes over one snapshot, under an export slot | bounded by the 100k record cap | |
| `listRepos` (at the authority) | a cursor scan of `sQ` joined to `sW` | | |

When a page of `listRepoOps` reaches the head it includes the commit, signed for this response. The
syncer checks its running LtHash against the commit's hash. If they differ it falls back to
`getRepo`. That's also what happens when `since` is older than the 7-day oplog window, since vlpds
answers from the window's start and the replayed hash can't match. Numbers are client-side from the
interop harness at `8f837fa8` (one node, MinIO).

## A crash at each point

```timeline
caption: "Where a crash can land. Each number matches a row of the table below."
scale: 44
lanes:
  - { id: c, label: App, tone: ink }
  - { id: n, label: Author's node, tone: accent }
  - { id: s, label: "`log/`", sub: segments, tone: amber }
  - { id: ob, label: Outbox, tone: accent }
  - { id: h, label: Authority, tone: violet }
spans:
  - { lane: n, from: 0, to: 2.3, label: build · batch }
  - { lane: s, from: 2.5, to: 5, label: segment PUT, tone: amber }
  - { lane: n, from: 5.2, to: 7.2, label: apply · ack }
  - { lane: ob, from: 7.6, to: 12.4, label: send notifyWrite }
  - { lane: h, from: 8, to: 11.4, label: sequence · PUT, tone: violet }
  - { lane: n, from: 14.4, to: 17.4, label: next space write }
arrows:
  - { from: n, to: c, at: 7, label: "200", tone: accent }
marks:
  - { at: 1.2, label: "1", tone: danger }
  - { at: 6.1, label: "2", tone: danger }
  - { at: 8.2, label: "3", tone: danger }
  - { at: 12.0, label: "4", tone: danger }
  - { at: 13.5, label: "5", tone: danger }
  - { at: 5, label: durable, tone: amber }
```

| # | Crash | The app saw | What recovery does |
|---|---|---|---|
| 1 | before the segment is durable | no 200 | Nothing to replay. The app retries. |
| 2 | durable, before the 200 | no 200 | The next owner replays the entry, `sP` row included, so the notify still goes out. A blind retry is a second write. |
| 3 | after the 200, before the authority's 200 | the 200 | The `sP` row is in the bucket. Whichever node opens the shard next rescans `sP` and sends the newest rev. |
| 4 | at the authority, after its entry is durable | the 200 | The authority keeps the spaceRev. The fan-out was only in memory, so the next owner sends each registration one catch-up forward, and a syncer that missed one catches up with `listRepos`. |
| 5 | delivered, before the `sP` delete lands | the 200 | The row is resent once. The authority ignores a `repoRev` it has already seen. |

The reference stores a notify for retry only after a send fails, so an acked write's notify can be
lost if the process dies first. vlpds doesn't have that window, since the row is in the same entry as
the write. In a kill -9
test on three nodes (33k–39k acked writes per run), nothing acked was lost and spaceRevs only moved
forward.
