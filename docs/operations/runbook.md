---
title: Runbook and incidents
section: Operations
order: 109
status: ready
summary: "The first page to open when an alert fires: exit codes, fail-stops, lease trouble, a slow or failing object store, a stalled firehose, and what not to do."
---

```hero
diagram:
  caption: "Triage. Every alert links its own RUNBOOK section; this page is the map of the common ones. Start from one node's view of the cluster, then follow the symptom. When several nodes misbehave at once, suspect the object store first."
  nodes:
    - { id: alert, label: Alert fires, sub: runbook_url, at: [0, 5], size: [8, 3], tone: danger }
    - { id: status, label: cluster status, sub: from any healthy node, at: [11, 5], size: [9, 3], tone: accent }
    - { id: exit, label: Restarts, sub: exit codes 2–9, at: [24, 0], size: [9, 2.6] }
    - { id: lease, label: Lease trouble, sub: renewal ÷ TTL, at: [24, 3.4], size: [9, 2.6], tone: violet }
    - { id: store, label: Object store, sub: "errors · latency", at: [24, 6.8], size: [9, 2.6], shape: store, tone: amber }
    - { id: fh, label: Firehose, sub: "stalled · lagging", at: [24, 10.2], size: [9, 2.6], tone: blue }
    - { id: fix, label: Procedure, sub: RUNBOOK section, at: [37, 5], size: [8, 3], tone: solid }
  edges:
    - alert -> status
    - status.r -> exit.l
    - status.r -> lease.l
    - status.r -> store.l
    - status.r -> fh.l
    - exit.r -> fix.l
    - lease.r -> fix.l
    - store.r -> fix.l
    - fh.r -> fix.l
facts:
  - { value: "2–9", label: fail-stop exit codes, note: "the supervisor must restart on every one", tone: rust }
  - { value: "~12 s", label: to take over a crashed node, note: "1.2 × TTL; 3–5 s if its port refuses connections", tone: blue }
  - { value: "0.4", unit: × TTL, label: renewal ceiling, note: "4 s at the default TTL; past it a node fail-stops", tone: violet }
  - { value: "never", label: edit objects in the bucket by hand, note: "log/, assign/, nodes/, state/, cluster/…", tone: amber }
```

`ops/RUNBOOK.md` is the per-alert reference. Every rule in `ops/alerts.yml` links its own section
there, with what it means, how to confirm it and what to do. This page groups the common incidents
and explains the few ideas you need under pressure. Links marked RUNBOOK open that file.

First, from any node that's up:

```bash
vlpds admin cluster status                         # with VLPDS_ADMIN_TOKEN set
docker exec vlpds vlpds admin cluster status       # on the host: reads the node's token file
```

It shows every node's lease, reachability, owned shards and build. It also shows unowned shards, a
split or merge in progress, fenced logs, the firehose sources and their watermarks, and the feature
level. The console's [Nodes & shards page](admin-console.md#pages) shows the same thing live.

## Exit codes and fail-stops

```diagram
caption: "A node that can't be sure it may still write exits with a code, rather than risk a forked repo. The next process exports how the last one ended; a peer that fenced a dead incarnation counts it too."
nodes:
  - { id: run, label: Node running, sub: owns shards, at: [0, 3], size: [8, 3], tone: accent }
  - { id: exit, label: Fail-stop, sub: "exit 2–9 · writes reason", at: [12, 3], size: [9, 3], tone: danger }
  - { id: file, label: exit-state file, sub: in --cache-dir, at: [12, 9], size: [9, 2.6], shape: note, tone: muted }
  - { id: peer, label: Peer fences log, sub: takes the shards, at: [30, 0], size: [9, 3], tone: blue }
  - { id: next, label: Next process, sub: "vlpds_last_exit_reason_info", at: [30, 6], size: [11, 3], tone: ok }
edges:
  - run -> exit
  - { from: exit.r, to: peer.l, label: lease goes quiet, labelAt: [26, 0.6] }
  - { from: exit.r, to: next.l, label: supervisor restarts, labelAt: [26, 8.6] }
  - { from: exit.b, to: file.t, dash: true }
  - { from: file.r, to: next.b, dash: true, via: [[35.5, 10.3]] }
```

| Code | Reason | Means |
|---|---|---|
| 2 | `segment_upload` | the segment upload task failed |
| 3 | `fenced`, `ordinal_taken` | a successor fenced this node's log (it was presumed dead), or another process wrote its segment ordinal |
| 4 | `state_apply` | SlateDB failed to apply a durable segment |
| 5 | `lease_lost`, `lease_lapsed` | the lease was lost or lapsed (slow renewals, a CAS conflict, a reassigned shard, a failed close) |
| 6 | `signature_fault` | three signatures failed self-verification within a minute. Suspect the host's memory or CPU. |
| 7 | `incompatible_level` | this build can't run the cluster's feature level (see [Upgrades](upgrades.md#feature-levels)) |
| 8 | `shutdown_fence` | a graceful stop couldn't fence its own log. Its shards were already handed out. |
| 9 | `critical_task_panicked` | a repo worker, the log sequencer or finalizer, or the firehose merger panicked. That's a bug. |

`vlpds_last_exit_reason_info` also reports `clean` (a graceful stop), `error` (exit 1, a startup or
serve error), `crash` or `none`. `crash` means the file still says running (SIGKILL, OOM kill, host
loss). `none` means a first start or no exit-state file. Keep `--cache-dir` (or `--exit-state-file`)
on a disk that survives restarts, or every exit reads as `none`.

What to do, by code:

- One restart that rejoined (it owns its fair share again within a step or two): nothing, once the
  cause is understood. Read the error line just before the exit.
- Exit 2 or 4: the object store. Look before it repeats.
- Exit 3 right after another process started with the same `--node-id`: two processes are fencing
  each other. Stop one.
- Exit 5 with `node lease renew error` warnings before it: a slow store. See
  [Lease trouble](#lease-trouble).
- Exit 6: drain the host now and keep vlpds off it until its memory and CPU are checked
  (RUNBOOK [VlpdsSignatureFault](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#vlpdssignaturefault)).
  No bad signature was ever sent.
- A crash loop (3+ restarts an hour): SIGTERM the node and leave it down while you diagnose. Its
  shards move to peers. Roll back the image if the loop began with a deploy.

Alerts: `VlpdsNodeRestarted`, `VlpdsNodeFailStopped`, `VlpdsUncleanNodeExit`,
`VlpdsNodeCrashLooping`, `VlpdsNodeDown`. RUNBOOK:
[Tools, logs, exit codes](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#tools-endpoints-cli-logs-exit-codes).

## Lease trouble

```diagram
caption: "At the default 10 s TTL. A node renews every 2 s and is valid for 8 s after a renewal's send time, so one renewal that takes over 4 s leaves a gap and the node stops acking and exits 5. At the tiny profile's 60 s TTL every number is six times larger."
nodes:
  - { id: ok, label: "≤ 0.2 × TTL", sub: "normal: 25–50 ms", at: [0, 0], size: [9, 3], tone: ok }
  - { id: near, label: "> 0.2 × TTL", sub: "2 s: ticket", at: [13, 0], size: [9, 3], tone: amber }
  - { id: at, label: "> 0.4 × TTL", sub: "4 s: page", at: [26, 0], size: [9, 3], tone: danger }
  - { id: stop, label: exit 5, sub: peers take over, at: [39, 0], size: [8, 3], tone: rust }
edges:
  - ok -> near
  - near -> at
  - "at -> stop: gap"
```

- One node: its network path to the store, or its CPU. A starved runtime delays the renewal task
  itself. Check `VlpdsRuntimeStalls` and `tokio runtime stall` lines.
- Several nodes at once: the store is browning out, and past the ceiling it stops the whole
  cluster. Go to [Slow or failing object store](#slow-or-failing-object-store).
- Don't lower `--lease-ttl-ms` to recover faster. It shrinks the ceiling and causes more
  fail-stops. Never below 10 s in production.

Signals: `vlpds_lease_renew_ttl_ratio`, `vlpds_lease_renew_seconds`, `vlpds_lease_validity_seconds`
(sampled at scrape time), `vlpds_lease_renew_errors_total{kind}`. Four failed renewals in a row lapse
a lease. Alerts: `VlpdsLeaseRenewalSlow`, `…NearCeiling`, `…AtCeiling`, `VlpdsLeaseRenewErrors`,
`VlpdsLeaseValidityLow`. RUNBOOK
[VlpdsLeaseRenewalNearCeiling](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#vlpdsleaserenewalnearceiling).
Background: [Architecture](../architecture.md#leases).

## Slow or failing object store

```steps
- title: Confirm it's the store
  body: "Check the provider status page. On every node, check `vlpds_object_store_requests_total{result=~\"error|timeout\"}` and `vlpds_object_store_request_seconds` by component, lease renewal times and control-plane timeouts. Many nodes at once means the store. One node means its network."
- title: Keep the supervisor restarting nodes
  body: "With backoff. Segment PUTs retry until they succeed, acks stop, and admission control sheds with 503 `Overloaded`. Past the renewal ceiling, nodes exit 5. No acked write is lost, because acks require durable segments."
- title: Change nothing in the bucket
  body: "Don't delete anything. Don't lower the lease TTL. Raising the TTL during an incident isn't a supported live operation."
- title: After recovery, watch the catch-up
  body: "Restarted nodes fence the dead incarnations' logs (their own previous ones too) and replay. Watch `VlpdsShardsUnowned`, replay time (`vlpds_shard_open_seconds{kind=\"replay\"}`), who fail-stopped, firehose emit delay and retention catching up."
```

vlpds' own reads can saturate the store too. When the SST metadata cache is too small for a node's
shards, point reads fetch whole filters and indexes. In the 100 M-account test that reached
1–2.4 GB/s of GETs per node and lapsed the leases of 3 of 4 nodes. The signs come in this order:
`VlpdsSstMetaRefetching` / `VlpdsSstMetaCacheTooSmall`, then `VlpdsObjectStorePermitsSaturated`,
`VlpdsControlPlaneLatencyHigh`, then the lease alerts. Pause bulk imports and backfills, then give
the node more memory or add nodes. A store shared with other tenants can do the same to the leases,
so keep the cluster's store to itself.

RUNBOOK: [Object-store outage](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#object-store-outage),
[Store saturated by the node's own reads](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#store-saturated-by-the-nodes-own-reads),
[VlpdsObjectStoreBrownout](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#vlpdsobjectstorebrownout).

## Firehose stalled or lagging

```diagram
caption: "Every node merges every node's log and emits an event once every log's watermark has passed it. One slow, stuck or unfenced log holds the firehose back on every node."
nodes:
  - { id: l1, label: log of node A, sub: watermark now, at: [0, 0], size: [9, 2.6], tone: accent }
  - { id: l2, label: log of node B, sub: watermark now, at: [0, 3.6], size: [9, 2.6], tone: accent }
  - { id: l3, label: dead log of C, sub: "unfenced: stuck", at: [0, 7.2], size: [9, 2.6], tone: danger }
  - { id: merge, label: merger, sub: emits ≤ min watermark, at: [14, 3.3], size: [9, 3.2], tone: blue }
  - { id: subs, label: subscribers, sub: relays · AppViews, at: [28, 3.3], size: [9, 3.2], tone: blue }
edges:
  - l1.r -> merge.l
  - l2.r -> merge.l
  - { from: l3.r, to: merge.l, label: holds it back, tone: danger }
  - "merge -> subs: in seq order"
```

Find the laggard. `firehose.sources[]` in `vlpds admin cluster status` lists each log's watermark,
and `nodes[].log` names the node that owns each log. Seqs are `unix_micros × 256 + writer`, so divide
by 256 for microseconds.

- A slow node (check its commit latency and watermark lag): fix it, or SIGTERM it. A graceful stop
  fences its own log, so every follower drains it and drops it as a source.
- A dead log nobody fenced (`VlpdsDeadLogUnfenced`): its node died owning no shards, so no takeover
  fenced it. Restart that node id, and startup fences its previous incarnation's log. Never write a
  fence by hand.
- Clocks. An idle log advertises its node's clock, so a node whose clock is behind holds the merge
  back. The merged stream lags by the largest offset between nodes. Keep NTP or chrony running
  everywhere.
- Slow subscribers past `--firehose-max-lag-mb` (128 MiB) are cut off with `ConsumerTooSlow` and
  resume from their cursor. Isolated cases are the consumer's problem.

Alerts: `VlpdsFirehoseEmitDelayHigh` / `…Critical`, `VlpdsFirehoseStalled`, `VlpdsDeadLogUnfenced`,
`VlpdsFirehoseMergeSpilling`. RUNBOOK
[VlpdsFirehoseStalled](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#vlpdsfirehosestalled).
How the merge works: [Firehose](../firehose.md#the-merger).

## Shards unowned or flapping

```facts
- { value: "seconds", label: a normal takeover, note: "3–5 s for a gone process, ~12 s for a frozen one, plus replay" }
- { value: "2 min", label: unowned pages, note: "VlpdsShardsUnowned: requests for those repos fail or wait 20 s", tone: rust }
- { value: "> 4", unit: opens/h, label: per shard is flapping, note: "every move costs a checkpoint, an open, replay and cold repos", tone: amber }
```

Shards unowned for minutes means the survivors can't take them. Usual causes:

- A frozen node. Its socket still accepts, so the fast path doesn't fire, and takeover waits
  1.2 × TTL before the fence and replay. Kill the frozen process so the refused connection speeds
  it up.
- Control-plane calls timing out, or the store failing. See the store section above.
- Shard opens failing (`VlpdsShardOpenErrors`), from SlateDB open or replay errors. A hole in a log
  span means someone deleted segments by hand.
- Commit-wait. A new owner waits up to 30 s for its clock to pass the previous owner's last seq
  (`waited for our clock to pass`). Fix clock sync.

Flapping (`VlpdsOwnershipFlapping`) is nearly always a node restarting over and over, or a node
whose renewals keep lapsing. Stabilize or stop that node. Over-owned (`VlpdsShardsOverOwned`, the
same shard on two nodes) is a zombie that hasn't hit its fence yet. SIGKILL it. It can't ack
anything. Imbalanced (`VlpdsOwnershipImbalanced`) usually settles, and a graceful restart of the
full node spreads its shards.

Don't edit `assign/` objects to unstick anything. RUNBOOK
[VlpdsShardsUnowned](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#vlpdsshardsunowned).

## Memory pressure

```facts
- { value: "85%", label: of the memory limit, note: "VlpdsMemoryHigh (ticket)", tone: amber }
- { value: "95%", label: of the memory limit, note: "VlpdsMemoryCritical (page): an OOM kill is close", tone: rust }
- { value: "SIGTERM", label: before the OOM killer, note: "a handoff without replay beats a crash and a replay", tone: blue }
```

The limit is the cgroup limit or physical RAM, whichever is lower (`vlpds_memory_limit_bytes`). The
node sizes its caches to a budget below it. Caches stay within the plan, so RSS past it is usually
allocator retention, memtables or bodies in flight. Compare `vlpds_process_resident_bytes` with
`vlpds_memory_budget_bytes{part}` and `vlpds_jemalloc_bytes{stat}`, and print the plan with
`vlpds --memory-plan`. Then lower `--memory-budget-mb` or move to a bigger box. An OOM kill is a
crash, so peers take over and replay. Nothing acked is lost.

`VlpdsCacheAtCapacity` (a bounded cache full for 6 hours) only matters with a symptom, like proxy
latency, PLC lookups or KMS unwraps on cold writes. If you see one, raise `--cache-budget-mb` or
one cache's `--cache-entries`. Budget details: [Configuration](configuration.md#memory-budget-and-autosizing).

## What not to do

- Never run two processes with the same `--node-id`. Each start fences the other's log, so with a
  supervisor restarting both, they fence each other forever.
- Never delete or edit objects by hand under `log/`, `assign/`, `nodes/`, `writers/`, `retain/`,
  `state/` or `cluster/`. A missing segment is a hole that replay stops at. Fences are what make a
  zombie fail-stop. `assign/` holds what successors replay. `cluster/version` only changes through
  `cluster finalize` / `cluster lower`. Retention and GC delete safely, so let them.
- Never run `--lease-ttl-ms` below 10 s in production. The renewal ceiling is 0.4 × TTL.
- Don't SIGKILL for routine restarts. SIGTERM and wait (60 s or more).
- Don't suspend or snapshot-pause a running node's VM. When it wakes, it believes its lease is
  still valid and serves stale reads until its next PUT hits the fence. A pause longer than
  `--fence-retention` (7 days) wakes up after the fence is gone.
- Don't let host clocks drift. Offsets don't affect safety, but they delay the merged firehose and
  make new owners wait up to 30 s.
- Don't point two clusters at the same bucket and prefix. Don't change `--shards` expecting a
  reshard either, since it only applies to a new prefix.
- Don't retire an old KEK before `rewrap-secrets --dry-run` reports nothing stale on every node.
  Never destroy KEK material that backups still need.
- Don't shrink `--log-retention` below what firehose consumers need to resume. Older cursors get
  `OutdatedCursor`.
- Don't restart nodes or move shards during a KMS outage. A restart empties the signing-key cache
  and makes every account the node owns unwritable until KMS is back.

## The full runbook

```facts
- { value: "91", label: alert sections, note: "Means, Causes, Confirm, Do for the 92 alerts in ops/alerts.yml" }
- { value: "26", label: procedures, note: "deploys, upgrades, keys, peer TLS, outages, users locked out", tone: blue }
- { value: "1", label: "list of metric gaps", note: "signals the alerts would want that no metric exports", tone: muted }
```

`ops/RUNBOOK.md` stays the reference that the alerts' `runbook_url`s point at. Its procedures:

| Area | Procedures |
|---|---|
| Deploys | [Rolling deploy](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#rolling-deploy), [Rolling upgrade, finalize, rollback](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#rolling-upgrade-finalize-rollback) |
| Hosts and nodes | [Replacing a dead host](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#replacing-a-dead-host), [Adding a node](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#adding-a-node), [Shard split / merge](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#shard-split--merge) |
| Store | [Object-store outage](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#object-store-outage), [Store saturated by the node's own reads](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#store-saturated-by-the-nodes-own-reads) |
| Keys | [Secrets as files](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#secrets-as-files), [KEK provisioning](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#kek-provisioning), [KEK rotation](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#kek-rotation), [Key service (KMS) outage](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#key-service-kms-outage), [PLC rotation key](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#plc-rotation-key-provisioning), [PLC rotation key rotation](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#plc-rotation-key-rotation), [Operator recovery key](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#operator-recovery-key), [PLC directory outage](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#plc-directory-outage) |
| Cluster | [Peer TLS](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#peer-tls-mtls-between-nodes) |
| Users and mail | [Email](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#email-smtp-moderation-mail-branding), [Moderation service, earned invites, external handles](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#moderation-service-earned-invites-external-handles), [A user locked out by a second factor](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#a-user-locked-out-by-a-second-factor), [A user locked out by OAuth only](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#a-user-locked-out-by-oauth-only), [A sign-in alert that didn't arrive](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#a-sign-in-alert-that-didnt-arrive), [A user lost their passkeys](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#a-user-lost-their-passkeys), [Resetting a user's second factors](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#resetting-a-users-second-factors), [A passkey flagged as copied](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#a-passkey-flagged-as-copied), [Cancelling a scheduled deletion](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#cancelling-a-scheduled-deletion), [A handle check that fails](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#a-handle-check-that-fails) |

It also has the [admin CLI](admin-console.md#admin-cli) mapping from `pdsadmin`, the serving limits
table, and the [metric gaps](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#metric-gaps).
