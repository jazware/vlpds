---
title: Upgrades
section: Operations
order: 108
status: ready
summary: "Rolling deploys, feature levels and format versioning: how to upgrade a cluster without downtime, finalize, and roll back."
---

```hero
diagram:
  caption: "A build that can write new formats keeps writing the cluster's active level until you finalize. Until then rollback is a plain redeploy of the old image; after it, only a fixed build moves forward."
  nodes:
    - { id: old, label: build A, sub: levels 1..=L, at: [0, 2], size: [8, 3] }
    - { id: mixed, label: Mixed or new fleet, sub: "writes level L · soak", at: [12, 2], size: [10, 3], tone: amber }
    - { id: final, label: Finalized, sub: active = L+1, at: [27, 2], size: [9, 3], tone: accent }
    - { id: fix, label: build B′, sub: forward-fix only, at: [27, 8], size: [9, 2.6], tone: danger }
  edges:
    - { from: old.r, to: mixed.l, label: roll B }
    - { from: mixed.r, to: final.l, label: finalize }
    - { from: mixed.t, to: old.t, label: redeploy A, dash: true, via: [[17, 0], [4, 0]] }
    - { from: final.b, to: fix.t, label: a bug now, dash: true }
facts:
  - { value: "≥ 60 s", label: stop grace for SIGTERM, note: "the close barrier may wait 30 s and the quiesce 10 s" }
  - { value: "~0", unit: errors, label: per clean rolling restart, note: "a handful when a forward is in flight; writes resent for up to 20 s", tone: blue }
  - { value: "24 h", label: default soak before finalize, note: "VlpdsFeatureLevelUnfinalized after 14 days", tone: amber }
  - { value: "exit 7", label: an old build after finalize, note: "refuses before reading or writing anything", tone: rust }
```


Upgrading vlpds means restarting each node on a new image, one at a time. Every format a node
persists or sends belongs to a **feature level**, and every node writes the cluster's active level
no matter what its build can do. So mixed versions are safe, and rolling back is just a redeploy
until you finalize.

> [!NOTE]
> Today every release runs level 1 only (`baseline`), so there hasn't been a level to finalize yet.
> The machinery (the `cluster/version` object, the startup check, finalize and lower) is built and
> tested with a test-only level 2.

## Rolling deploy

```steps
- title: SIGTERM one node
  body: "Never SIGKILL. The node marks its lease `draining` and closes each shard with one barrier segment and a checkpoint. It hands each shard straight to a settled peer and waits up to 10 s for its log to quiesce. Then it fences its own log, deletes its lease and exits 0."
- title: Wait for the stop
  body: "Give the supervisor a stop timeout of at least 60 s. If the timeout ends in SIGKILL, the handoff turns into a crash and peers fence and replay instead. Exit 8 means the node couldn't fence its own log, and peers or the restart will do it."
- title: Start the new image with the same `--node-id`
  body: "Use the same bucket, prefix, tokens and `--advertise-url`. The node greets its peers, and they hand back its fair share at their next step."
- title: Check before the next node
  body: "`sum(vlpds_owned_partitions)` should equal `vlpds_shard_layout_shards`, and the node should own about shards ÷ nodes. Look for `vlpds_last_exit_reason_info{reason=\"clean\"}`, every lease valid and `vlpds_build_info{rev}` on the new rev. Commit p99 and `vlpds_write_retries_total` should be back to baseline."
```

Clients see almost nothing. A forward that's in flight at the moment of exit can fail (a handful of
errors per restart). Writes that hit a shard in motion get a retryable 503, and the entry node
resends them for up to 20 s. Expect a burst of resends and some cold repo loads on the moved shards.

A single node is different, because every restart is a short outage. A graceful stop takes ~0.1 s
idle and ~0.2 s under write load, and the restarted node takes its first write ~1.3 s after it
starts (measured on a dev box against MinIO). The stop waits only for requests already in flight.
Writes that arrive while it stops get a 503 (nothing done) right away, and firehose subscribers get a
going-away close, so relays reconnect with their cursor. On a real server add the container's own
restart, so expect a few seconds of Caddy 502s and pick a quiet time. The Ansible role
does this with `--tags vlpds-deploy,vlpds-verify` after you set the new image tag (see
[Deploy](deploy.md)).

## Feature levels

```diagram
caption: "A build declares the levels it can run; the cluster's active level is one object in the bucket. A node starts only if the active level is inside its window, and every writer emits the active level's formats."
nodes:
  - { id: cv, label: "cluster/version", sub: "active · target · history", at: [0, 3], size: [10, 3], shape: store, tone: amber }
  - { id: n1, label: node on build A, sub: "window 1..=1", at: [15, 0], size: [10, 3], tone: accent }
  - { id: n2, label: node on build B, sub: "window 1..=2", at: [15, 6], size: [10, 3], tone: accent }
  - { id: out, label: segments · leases · rows, sub: "level 1 bytes from both", at: [30, 3], size: [11, 3], tone: solid }
edges:
  - { from: cv.r, to: n1.l, label: read at start }
  - { from: cv.r, to: n2.l }
  - { from: n1.r, to: out.l30 }
  - { from: n2.r, to: out.l70, label: write active, labelAt: [28.5, 9.4] }
```

- A level is an integer in `vlsync-store/src/version.rs`. Each persisted or wire format change gets the next
  one. A level is either persistent (it puts new bytes in the bucket) or wire-only.
- A build runs `MIN_LEVEL..=MAX_LEVEL`. It reads everything in that window and writes the active
  level, so a new build at level L writes exactly what the old one writes.
- `cluster/version` holds the active level, a `target` while a raise is running, and the history.
  A fresh prefix starts at its first node's highest level. Only `vlpds admin cluster finalize` and
  `cluster lower` change it, so never edit it by hand.
- The startup gate. A node reads `cluster/version` before it touches anything, again right after
  writing its lease, and once per lease TTL while running. A build whose window doesn't contain
  the active level (or a running raise's target) exits 7 `incompatible_level`.
- Leases advertise each node's `rev`, `min_level`, `max_level` and the level it last saw, so every
  node knows the whole cluster's window. `vlpds admin cluster status` and the console's Nodes &
  shards page show it. When every node can run the next level, the status prints the finalize
  command and the console shows a "ready to finalize" banner with a Finalize button.

## Rolling upgrade, finalize, rollback

```steps
- title: Pre-flight
  body: "Run `vlpds admin cluster status`. Every node should be healthy, with `Feature level: L active`. The new build's `MIN_LEVEL` must be ≤ L (it's in `vlsync-store/src/version.rs`, along with which levels are persistent)."
- title: Roll the new build
  body: "Do it exactly like a rolling deploy. Also check that each restarted node's row shows the new rev and a window reaching L+1, and that `vlpds_format_errors_total` stays flat."
- title: Soak at level L
  body: "The default is 24 h with the whole fleet on the new build. Rollback is a plain redeploy of the previous image, node by node, in any order, since no byte of level L+1 exists yet."
- title: Finalize
  body: "Run `vlpds admin cluster finalize --level L+1`. It asks first (pass `--yes` off a terminal). It writes a raise target and checks every live lease's window. Then it either sets active = L+1, or refuses with 409 `IncompatibleNodes` and changes nothing. Watch format errors, commit p99 and firehose lag for one TTL."
- title: After finalize, forward-fix only
  body: "An old build exits 7 at startup, so ship a fixed build. A wire-only level can be lowered when its new behaviour is the bug (`vlpds admin cluster lower --level L`), but a persistent level never can."
```

| Alert | Means |
|---|---|
| `VlpdsMixedVersions` | more than one `rev` for over an hour. Finish or roll back the deploy |
| `VlpdsIncompatibleNode` | a node exited 7. Deploy a build whose window contains the active level |
| `VlpdsFeatureLevelUnfinalized` | every node could run a higher level for 14 days. Finalize or roll back |
| `VlpdsFormatErrors` | a node met a format marker it doesn't know (it pages, and should never happen) |

A raise that a dying node left half-done shows up as "raising to N" in `cluster status`. Clear it
with `vlpds admin cluster finalize --level <active> --yes`. The full procedure is in the RUNBOOK
under [Rolling upgrade, finalize, rollback](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#rolling-upgrade-finalize-rollback).

## Compatibility contract

```facts
- { value: "readers", label: accept every level in their window, note: "unknown segment magics, stream messages or markers are errors and are never guessed" }
- { value: "writers", label: emit the active level only, note: "each segment is one level, so a change takes effect at the next one", tone: accent }
- { value: "objects", label: tolerant both ways, note: "shared control objects keep fields an older node doesn't know", tone: blue }
```

Every release keeps these promises, so a rolling upgrade and a rollback are always safe.

- Upgrade one window at a time. A build only starts if the active level is inside its window, and
  skipping releases is fine whenever that holds. A build drops support for level L (raises
  `MIN_LEVEL`) only once data at L can no longer exist.
- Control objects survive older nodes. Whichever node acts does a read-modify-CAS on assignments,
  the layout and `cluster/version`, so they keep unknown fields (`serde(flatten)`) and default
  missing ones. A field that an old node has to honour is still level-gated.
- Peer protocols are additive. Paths stay `/v1`, and a new endpoint or message is only used once
  the peer's lease advertises a level that has it. A 404 from a peer reads as "unsupported", and
  the log stream skips message types it doesn't know.
- SlateDB is a format. A SlateDB version bump, or a flag that changes stored bytes (log or SST
  compression codec), is a level. What the new version writes must open under the old one until the
  level is raised.
- Spaces sits outside the levels. Its log entries and rows are part of level 1, so the active level
  can't keep a pre-Spaces build away from them. Turn `--spaces` on only once every node runs a
  Spaces-aware build, and after that never roll back to a build from before it
  ([Spaces: operating](../spaces/operating.md#what-you-get-with-spaces)).
- Client tokens are a format too. If the old build can't verify a session JWT or OAuth token, a
  rollback turns into a forced logout, so a change to them belongs to a level.

The format inventory (every persisted and wire format, and how it's versioned) is in DESIGN.md under
"Rolling upgrades and format versioning".

## Testing an upgrade

```steps
- title: "`just upgrade-ci`"
  body: "Run it before any release with a new level. It runs the format fixtures and the MANIFEST freeze (`testdata/formats/L1/`), the level-gating test, and the two-build `upgrade-rolling` HA scenario against the previous release, on a throwaway MinIO."
- title: "`just upgrade-ha`"
  body: "Every `upgrade-*` scenario (`bench/ha/upgrade.sh`): rolling upgrade, rollback before finalize, old-node refusal after it, and a node starting during a raise."
- title: Never deploy a test build
  body: "The scenarios use the cargo feature `test-level`, which adds a fake level 2 with a different segment format. A build like that logs `TEST BUILD` at startup."
```

Results of the last two-build run are in `bench/ha/RESULTS.md` ("Two-build upgrade scenarios").
