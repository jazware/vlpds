---
title: Operating Spaces
section: Spaces
order: 205
status: draft
summary: "Turning Spaces on, its limits, what to watch and what it costs: flags, metrics, the dashboard row, the alerts, and measured numbers next to the reference PDS."
---

```hero
diagram:
  caption: "Three things to watch and the alert on each. A node without --spaces exports no vlpds_space_* series, and one with it exports what these alerts read at 0 from the start."
  nodes:
    - { id: cr, label: Credential reads, sub: "`…_credential_checks_total`", at: [0, 0], size: [13, 3], tone: blue }
    - { id: ob, label: notifyWrite outbox, sub: "`…_outbox_oldest_seconds`", at: [16, 0], size: [13, 3], tone: accent }
    - { id: fo, label: Fan-out to syncers, sub: "`…_notify_total{hop=fanout}`", at: [32, 0], size: [13, 3], tone: violet }
    - { id: a3, label: VlpdsSpaceCredentialRejectsHigh, sub: "> 25% refused · 15 min", at: [0, 6], size: [13, 3], tone: danger }
    - { id: a1, label: VlpdsSpaceOutboxBacklog, sub: "oldest row > 1 h · 10 min", at: [16, 6], size: [13, 3], tone: danger }
    - { id: a2, label: VlpdsSpaceNotifyFanoutFailing, sub: "> 50% failing · 30 min", at: [32, 6], size: [13, 3], tone: danger }
  edges:
    - cr -> a3
    - ob -> a1
    - fo -> a2
facts:
  - { value: off, label: by default, note: "`--spaces` turns it on", tone: rust }
  - { value: "100k", unit: records, label: per space repo, note: "`--space-repo-max-records`", tone: amber }
  - { value: "7 d", label: of oplog, note: "`--space-oplog-retention`", tone: violet }
  - { value: "5", unit: alerts, label: four tickets and a page, note: "`VlpdsSpace*` in `ops/alerts.yml`", tone: blue }
```

Spaces is an alpha that changes every week upstream, so leave it off unless you're testing against
it. With no space traffic, a node with it on makes one conditional GET of the revocations object every
5 min and runs an oplog sweep about every 6 h, which skips repos younger than the window.

## What you get with `--spaces`

A node with the flag serves every Spaces method a PDS serves at the `5b95b2f2` pin, in both roles.
As a repo host it holds your accounts' space repos. As a simplespace host it runs the spaces your
accounts govern. Nothing is proxied to another host.

| Area | What's served |
|---|---|
| Space records | `space.createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `getRecord`, `listRecords`, `listSpaces` |
| Sync | `space.getLatestCommit`, `listRepoOps`, `getRepo`, `listBlobs`, `getBlob` |
| Credentials | `space.getDelegationToken`, `getSpaceCredential`, `notifyCredentialRevoked` |
| simplespace host | `simplespace.createSpace`, `getSpace`, `updateSpace`, `deleteSpace`, `putMember`, `removeMember`, `listMembers`, and `space.notifyWrite`, `listRepos`, `registerNotify`, `unregisterNotify` |
| vlpds only | `vlpds.space.importRepo`, operator reads (`vlpds.admin.getSpaceRepo`, `listSpaceRecords`, `getSpaceRecord`), `vlpds.admin.checkSpace`, space takedowns |

A method under `com.atproto.space.*` or `com.atproto.simplespace.*` that a PDS doesn't serve
(`notifySpaceDeleted` and `checkUserAccess` go to syncers and managing apps) answers 501 here.

Turn `--spaces` on only once every node in the cluster runs a build that knows Spaces, and don't
roll back below that build afterwards. Space writes put private entries in the node logs and space
rows in the shards, and a build from before Spaces doesn't know either. The feature level doesn't
guard this. Spaces shipped inside level 1 (vlpds hadn't been released), so no cluster level can say
"Spaces yet or not", and a node can't check it at startup ([Upgrades](../operations/upgrades.md#compatibility-contract)).

A few rules decide what your users and their apps can do:

- Space data is OAuth only. An app needs a `space:` scope, and app passwords and password sessions
  get no space reads, writes or delegation tokens. `getServiceAuth` mints a token for a space
  method only to an OAuth app whose `space:` grant covers it ([Reading a space](reading.md#oauth-only)).
- That includes `vlpds.space.importRepo`, so an account moving in imports its space repos after it's
  activated here, with OAuth. Syncers see none of its space data for that short gap
  ([Moving a repo in](storage.md#moving-a-repo-in)).
- `sync.getBlob` serves a blob only once a public record names it. A blob only space records name
  is served by `space.getBlob` to a credential for that space ([Blobs](privacy.md#blobs)).
- The oplog keeps 7 days. A syncer further behind falls back to `getRepo`, which the reference
  consumer already does on a hash mismatch ([Retention](storage.md#retention-caps-and-deletion)).
- Moderators and admins can read space records for terms-of-service work, and every read is
  audited ([Operator access](privacy.md#operator-access)).

## Enabling on a single node

This is the order for turning Spaces on for one production node deployed with the Ansible role. A
cluster is the same, once every node runs a build that knows Spaces (see above).

1. Set `vlpds_spaces: true` in the node's inventory. It maps to `--spaces`. The knobs below keep
   vlpds' defaults while they're empty, and those defaults are fine for an alpha:

   | Variable | Flag | Default |
   |---|---|---|
   | `vlpds_spaces` | `--spaces` | `false` |
   | `vlpds_space_repo_max_records` | `--space-repo-max-records` | 100000 |
   | `vlpds_space_oplog_retention` | `--space-oplog-retention` | `7d` |
   | `vlpds_max_import_mb` | `--max-import-mb` | 1024 (Caddy's `importRepo` cap follows it, +64 MiB) |

2. Deploy with `--tags vlpds-deploy,vlpds-verify`. The compose file changes, so it's one graceful
   restart. The role refuses `--dev-mode` and `--lexicon-authority-override`, so lexicons resolve
   through DNS as they would for anyone else.
3. Open the Spaces row on the `vlpds internals` dashboard. Every panel should show 0 or a note like "no space writes" right
   away, since a node with the flag exports the `vlpds_space_*` series at 0 from the start. If the
   row stays empty, the flag didn't take.
4. Check that vmalert has the five `VlpdsSpace*` rules from `ops/alerts.yml` loaded. The one that
   catches most problems is `VlpdsSpaceOutboxBacklog` (the oldest outbox row over 1 h for 10 min).
   `VlpdsSpaceNotifyFanoutFailing`, `VlpdsSpaceCredentialRejectsHigh` and
   `VlpdsSpaceDigestMismatch` cover the rest ([Alerts](#alerts)). Those four are tickets.
   `VlpdsSpaceRevocationsSaturated` pages, since remote authorities' credentials stop working.

An app that was approved for a bare `space:` grant that writes before the flag was on has no
collections recorded for it. Its next refresh gets `invalid_grant`, so the user signs in again and
approves the writes on the consent screen.

### The first day

| Watch | Where | Healthy |
|---|---|---|
| Outbox depth and age | `vlpds_space_outbox_rows`, `vlpds_space_outbox_oldest_seconds` | a few rows, oldest under a few minutes |
| Notify failures | `notifyWrite failure ratio by hop` | ~0 for `out` and `in`. `fanout` fails while a syncer is down |
| Unconfirmed same-rev notifies | `vlpds_space_notify_total{hop="in",result=~"same_rev_unverified\|same_rev_capped"}` | 0. These only come with record takedowns |
| Credential cache hit rate | `Credential cache hit ratio` | high under steady polling |
| Digest mismatches | `vlpds_space_digest_mismatch_total` | 0, always |
| Throttling | `vlpds_object_store_throttled_total{kind}` | 0. R2 answers the odd 429 on lease writes, and the client retries it |
| Segment PUTs per write | `sum(rate(vlpds_segments_total[5m])) / (sum(rate(vlpds_commits_total[5m])) + sum(rate(vlpds_space_writes_total{result="ok"}[5m])))` | at most 1. Space writes add no PUTs of their own ([cost](#server-cost-on-one-node)) |

A digest mismatch only counts once `vlpds admin check-space` runs, so run it on a space or two at the
end of the day.

### Turning it back off

Set `vlpds_spaces: false` and deploy again. That's another graceful restart, and it's safe on the
same build. What isn't safe is rolling the image back below the build that knows Spaces, for the
reasons above. With the flag off, the space methods stop being served here, new tokens carry no space
permissions, and the space data stays in the bucket. Space-only blobs stay private, since a node
without the flag still answers `BlobNotFound` for a blob only space records name
([Blobs](privacy.md#blobs)).

## Console

The operator console has a Spaces tab. On a node without `--spaces` it says Spaces is off, and the
methods behind it answer 501.

- The overview counts the spaces your accounts govern, the space repos stored here, their members,
  writers and records. Its health table asks every node for `vlpds.admin.getSpacesStatus` every
  10 s and shows the notify outbox, pending fan-out, revocations and the credential cache against
  their caps (amber past half, red past 90%). A node whose revocation list is stale or not read yet
  gets a red banner. The table below lists every space hosted in the cluster, sorted by last write,
  members, writers, records or newest. Records only count space repos stored here, since a writer on
  another PDS keeps its own.
- A space's page shows its policies, members, writers (repoRev, spaceRev and the first 8 bytes of
  the set hash), the newest spaceRev of each writer, its notify registrations (the endpoint's host
  only), its records taken down here and its audit entries. You can take the space down or restore
  it, and remove a registration with a reason. A removed service can register again with a
  credential, so take the space down to keep it out.
- An account's page lists the spaces it writes in and the ones it governs.
- The audit log has a Spaces filter.

Everything on these pages is metadata (DIDs, revs, counts, times and policies), and none of it
writes an audit entry. A record's value only shows after you ask for it with a reason. Writers'
"Records…" and the lookup's "Read record…" go through `listSpaceRecords` and `getSpaceRecord`,
which write a `space.read` entry first, one per page ([Operator access](privacy.md#operator-access)).
Removing a registration writes `space.registration.remove`.

The console can't show when a member was added, since member rows only hold read and write. It also
can't show each registration's last delivery, since fan-out keeps that in memory only. There's no
"revoke every credential for this space" button yet.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--spaces` (`VLPDS_SPACES`) | off | serves `com.atproto.space.*` and `com.atproto.simplespace.*` here |
| `--space-repo-max-records` | 100000 | the most records one account's repo in one space may hold. A write past it gets `InvalidRequest` |
| `--space-oplog-retention` | `7d` | how long ops stay for `listRepoOps`. `off` keeps them all |
| `--max-import-mb` | 1024 | the largest CAR `vlpds.space.importRepo` takes, as for `com.atproto.repo.importRepo`. Its blocks are capped besides ([Moving a repo in](storage.md#moving-a-repo-in)), and it reserves from the same import budget |
| `--max-exports`, `--export-stall-secs` | as for `sync.getRepo` | `space.getRepo` takes the same export slots and stall timeout |

A `space.getRepo` holds every path and CID of the repo while it streams (~128 B a record), so it
also takes that much room from the memory plan's space exports. The room fits 4 exports of a full
100,000-record repo (~53 MiB). Smaller repos take less, so only a pile-up of the biggest ones waits
(10 s, then 503 `Overloaded`).

## Fixed limits

| Limit | Value |
|---|---|
| Space credential lifetime | 10 min minted by vlpds, 3,600 s accepted at most, 5 s of clock skew |
| Delegation token and client attestation | 60 s minted, 300 s accepted at most, single use |
| `Signature-Input` and `Signature` headers | 8 KiB each |
| Revocations | 1–100 `jti`s per call (up to 128 characters each), each held 3,610 s · only ones with a stake here are stored · 2,000 live per authority, 1,000 per space, 5,000 per account here, 50,000 in all · one past a cap blocks its space, past 100 of an authority's the authority, past 1,000 authorities every remote one (`VlpdsSpaceRevocationsSaturated`, never local authorities), each for 3,610 s · 8 waiting per node · credential reads 503 after 6 min without a good read |
| `applyWrites` | 200 ops |
| `notifyWrite` with a future `repoRev` | refused past 5 min |
| Outbox | 262,144 rows in memory, 256 sends in flight, 8 per authority and 32 in all to authorities whose last send failed, retries for 24 h |
| Fan-out | 4,096 queued for each of 8 dispatchers, 256 per lane, 4,096 and 16 sends in flight per service host, 65,536 queued and 16,384 lanes in all (past those, drops marked as gaps: syncers catch up with `listRepos`), 512 sends in flight in all |
| Notify registrations | 24 h · 256 per space, 1,024 across one authority's spaces · 60 an hour per credential (`space-register`) · service ids up to 512 bytes |
| Spaces | 1,000 live per account · 100 created a day per account (`space-create`) |
| `listRecords` and `listRepoOps` pages | end early with a cursor past 4 MiB of values |
| Memory | space heads cache 64 MiB, credential cache 50,000 entries |

## Metrics

| Metric | What it shows |
|---|---|
| `vlpds_space_writes_total{op,result}` | space writes by method and result |
| `vlpds_space_reads_total{method,auth}` | reads by method and auth (`credential` or `oauth`) |
| `vlpds_space_list_repo_ops_total{path}`, `vlpds_space_list_repo_ops_seconds{path}` | `noop` (answered from memory) vs `scan`, and server time for each |
| `vlpds_space_notify_total{hop,result}` | notify hops: `out` (this node's writes), `in` (as an authority), `fanout` (to syncers). `in` counts `same_rev_unverified` and `same_rev_capped` for a same-rev notify from another host that its PDS didn't confirm or that came over the cap ([Privacy](privacy.md#takedowns)) |
| `vlpds_space_notify_ack_seconds` | a write's ack to the authority's 200 |
| `vlpds_space_outbox_rows`, `vlpds_space_outbox_oldest_seconds` | outbox depth and the age of its oldest row (rows held for an inactive writer don't count toward the age) |
| `vlpds_space_outbox_overflow_total` | rows left in the bucket because the outbox was full |
| `vlpds_space_fanout_queue_depth`, `vlpds_space_fanout_dropped_total{reason}`, `vlpds_space_fanout_coalesced_total` | fan-out backlog, drops and replaced forwards |
| `vlpds_space_credential_cache_total{result}` | credential cache hits and misses |
| `vlpds_space_credential_checks_total{result}` | `ok`, or why a read was refused: `bad_sig`, `expired`, `revoked`, `audience`, `space` |
| `vlpds_space_credentials_issued_total{result}`, `vlpds_space_delegations_total` | credentials issued as an authority, delegation tokens minted |
| `vlpds_space_revocations` | revoked credentials in force |
| `vlpds_space_export_bytes`, `vlpds_space_oplog_pruned_total` | `getRepo` memory, oplog ops pruned |
| `vlpds_space_sign_seconds` | signing one commit for a reader (every `getLatestCommit`, `listRepoOps` and `getRepo` signs its own) |
| `vlpds_space_digest_mismatch_total` | space repos whose head disagreed with the set hash recomputed from their records. Should stay 0 |
| `vlpds_space_repos` | space repos in this node's shards, counted by the oplog retention sweep every ~6 h |
| `vlpds_space_imports_total{result}` | `vlpds.space.importRepo` calls: `ok`, `refused` (a bad CAR, signature or hash), `error` |
| `vlpds_space_operator_reads_total{method}` | audited operator reads of space data |

The internals dashboard has a Spaces row built from these: writes, write → notify ack, outbox rows and
oldest row per node, notifies by hop and their failure ratio, `listRepoOps` noop vs scan and its
server time, reads by auth, the credential cache hit ratio, credential checks by result, issuance,
the fan-out queue and drops, and revocations held.

## Alerts

| Alert | Fires when | First thing to check |
|---|---|---|
| `VlpdsSpaceOutboxBacklog` | a node's oldest outbox row is over 1 h old for 10 min | `notifyWrite by hop and result`: `out retry` means the authority is failing. Inactive writers' rows wait without aging the outbox |
| `VlpdsSpaceNotifyFanoutFailing` | over 50% of fan-out sends fail, at over 0.1/s, for 30 min | one syncer down (nothing to do) or this node's egress |
| `VlpdsSpaceCredentialRejectsHigh` | over 25% of credential reads are refused, at over 0.5/s, for 15 min (expired ones left out) | which `result` dominates. One client stuck on `bad_sig` is that app's bug |
| `VlpdsSpaceRevocationsSaturated` (page) | the revocation blocks are saturated: every remote authority's credentials are refused | `vlpds_space_revocation_blocks{kind}` and the `space revocation not stored` warnings. It clears 3,610 s after the last block ([runbook](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#vlpdsspacerevocationssaturated)) |
| `VlpdsSpaceDigestMismatch` | a space repo's head disagrees with its records | run `vlpds admin check-space DID SPACE` |

Each has a section in `ops/RUNBOOK.md`. All but `VlpdsSpaceRevocationsSaturated` are tickets, since
a space write is durable and readable at its 200 whatever these say. For an outbox backlog, one failing authority needs nothing
from you (the next retry, at most ~1 h away, delivers the newest rev). Many failing at once points at
this node's DNS or egress.

`VlpdsSpaceDigestMismatch` counts what `vlpds.admin.checkSpace` finds, so it fires only once that
check runs (`vlpds admin check-space`). A refused `importRepo` with a bad set hash is the
uploader's problem and counts in `vlpds_space_imports_total{result="refused"}` instead.

## What it costs

Measured on a laptop with the interop harness against the reference PDS at `5b95b2f2`, with one
vlpds node on MinIO. All of these are client-side.

| | vlpds | Reference PDS |
|---|---|---|
| Space write (createRecord, putRecord, applyWrites) | 0.80 ms p50 · 1.33 ms p99 | ~4.2 ms p50 · 6.5 ms p99 |
| Sequential write throughput, one account | 1,184 writes/s | 232 writes/s |
| No-op `listRepoOps` poll | 0.28 ms p50 · 0.54 ms p99 · 0 bucket ops | 6.7 ms p50 |
| Delta pull | 0.41 ms p50 · 1.9 ms p99 | 8.3 ms |
| Notify end to end | 1.7 ms p50 · 5.5 ms p99 | 4.5 ms p50 · 8.3 ms p99 |
| `listRecords` | 0.5 ms | 5.7 ms |
| `getDelegationToken` | 0.5 ms | 2.5 ms |
| Public commit p99 with the spaces load on | 9.4 → 6.3 ms | 29 → 39 ms |

- Server time for a space write averages 0.59 ms. 0.44 ms of that is the durable commit, nearly all
  of it the segment PUT. Waiting for a segment and applying take ~0.01 ms each.
- Server time for a no-op poll averages 0.12 ms, and 0.17 ms for a delta pull.
- Public commit p99 held up with the spaces load running, but p50 went from 1.3 to 3.1 ms.
- Sequential writes cost one bucket PUT each, the same as public writes. At a concurrency of 4 on
  one repo with sub-ms MinIO PUTs, the harness measured 0.94 PUTs per space write against 0.60 for
  public writes. That gap comes from the OAuth check, since space writes are OAuth-only and the
  harness's public writer uses a session token (see "Server cost on one node").

### Server cost on one node

The in-tree micro-bench (`just spaces-microbench`) runs one `--spaces` node in process on an
in-memory bucket with log segment PUTs delayed like S3 (25 ms median). It measures what the
harness can't see from outside: CPU per sync request, bucket requests by kind, and public commit
latency with and without a spaces load. These numbers are from a 32-thread desktop (Ryzen AI Max+
395) at `3ebf852d` on 2026-10-05, with nothing else running. The full output and every knob
are in `bench/results/spaces-sync.md`.

| | p50 | p99 | Target |
|---|---|---|---|
| No-op `listRepoOps`, handler | 0.05 ms (mean 0.014 ms) | 0.10 ms | well under 1 ms · met |
| No-op `listRepoOps`, client | 0.17 ms | 0.29 ms | |
| No-op poll, signing key unwrapped first | 0.20 ms | 0.64 ms | |
| Delta pull of 1 / 10 / 100 ops, client | 0.18 / 0.22 / 0.52 ms | 0.40 / 0.73 / 0.93 ms | a few ms · met |
| Credential first use (full chain) / cached | 0.30 / 0.24 ms | 0.45 / 0.52 ms | |
| Member write ack to authority ack | 52 ms | 125 ms | |
| Syncer notified to its pull done | 1.9 ms | 5.5 ms | |

- A no-op poll costs ~143 µs of process CPU more than `/xrpc/_health` on the same client. That's
  the P-256 signature check, a fresh secp256k1 commit signature and the JSON. 100 polls at the head
  read nothing from the bucket (`spaces_side::accept`).
- Notify to a local authority is one more durable entry after the member's write, so it costs what a
  public commit does (52 ms against 54 ms here, both mostly the 25 ms segment PUT and the wait for
  the one ahead of it).
- Space writes add no bucket PUTs. With 16 public writers at ~286 commits/s, adding ~220 space
  writes/s moved log segment PUTs from 35.7/s to 36.2/s, and PUTs per write of either kind went
  from 0.143 to 0.078.
- On one repo, space writes share segments the same way public ones do. 4 concurrent writers cost
  0.50 PUTs per write for both, and 16 cost 0.125.
- With fast PUTs, space writes share segments the way public writes over OAuth do. Writes only
  share a segment if they reach the log while a PUT is in flight, and a DPoP-bound request spends
  longer in auth than one with a session token, so fewer of them line up. At 0.2 ms PUTs and 4
  writers on one repo, a session-token public writer gets 0.50 PUTs per write, an OAuth one 0.60
  and a space writer 0.56. At 0.5 ms all three are within 0.01 of 0.50.
- vlpds checks DPoP signatures with ring (~30 µs a signature against ~110 µs with the p256 crate).
  That took OAuth auth from ~186 µs to ~86 µs a request, and space writes at 0.2 ms from 0.62 to
  0.56 PUTs per write. The sweep is in `bench/results/spaces-sync.md`.
- Public commit p99 didn't move under 20 spaces x 5 members x 3 pollers a second plus a syncer per
  space. Four runs gave 80 / 86 / 85 / 86 ms alone and 87 / 85 / 83 / 85 ms with the load.

With the flag off, the commit path matched its base. An A/B on the same box (the bench grid's bisect
shape, 10k accounts / 5k active at 25 ms injected PUT latency, two rounds in alternating order) put
`3ebf852d` with and without `--spaces` next to its base `36f0be7b`:

| Rate | `36f0be7b` p99 | `3ebf852d` p99 | `3ebf852d --spaces` p99 | CPU µs/commit |
|---|---|---|---|---|
| 10k/s | 130 / 133 ms | 123 / 131 ms | 125 / 143 ms | 215-218 for all three |
| 25k/s | 119 / 130 ms | 121 / 135 ms | 133 / 114 ms | 206-208 |
| 50k/s | 164 / 245 ms | 249 / 269 ms | 303 / 190 ms | 235-238 |
| 75k/s | 437 / 392 ms | 403 / 379 ms | 426 / 424 ms | 276-282 |
| 100k/s (saturated) | 71.1k / 72.0k achieved | 71.2k / 72.1k | 70.6k / 70.0k | 300-305 |

The 50k/s step is the knee, and its p99 swings by 2x between identical runs (it ran 350 to 700 ms
across earlier rounds). The reads (`getRecord`, `getLatestCommit`) and `createRecord` matched within
1-2%. Results are in `bench/results/spaces1-ab-2026-10-05/`.

### On Cloudflare R2

The harness also ran against a real R2 bucket from the same desktop on wired home internet on
2026-10-05 (a release build of `8346b200`, one node with 16 shards, and a 3-node cluster at the
default 10 s lease TTL). Everything follows from R2's PUT latency. A 64 KiB PUT takes ~200 ms p50 (380 ms p99),
and a GET ~60 ms, while the TCP and TLS round trip to the edge is under 20 ms. So the time goes to
R2's storage path.

| | R2 |
|---|---|
| Space write ack | ~200 ms p50 · 413 ms p99, one segment PUT (the rest of the commit path adds 0.5 ms) |
| Notify, write readable → syncer notified | 219 ms p50 · 374 ms p99, one more PUT for the authority's entry |
| No-op `listRepoOps` poll, client | 0.57 ms p50 · 1.25 ms p99 · 0 bucket ops |
| Delta pull, client | 1.3 ms p50 · 3.0 ms p99 |
| Public commit p99, alone → with 8 space writers | 643 → 630 ms |
| Cluster `kill -9` of one node during the harness's 16-writer boards load | 0 acked writes lost, all of its shards owned again ~10 s after the kill |

- Polls and delta pulls never touch the bucket, so R2 doesn't slow them down. They stay well
  under the 1 ms and few-ms targets.
- A lone writer gets ~4-5 sequential writes a second per repo, since each write waits for its PUT.
- The space load didn't move public commit p99, and p50 moved by 43 ms (305 → 348 ms).
- Expect a wide tail. One control-plane GET at cluster start took over 3 s, which is why the
  cluster ran at the 10 s lease TTL. R2 also answered two 429s on lease-object writes, and
  object_store's retry absorbed both.

The full write-up, with the bucket-op counts and the failover timeline, is in
`bench/results/spaces-r2-2026-10-05.md`.
