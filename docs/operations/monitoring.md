---
title: Monitoring
section: Operations
order: 104
status: ready
summary: "Metrics, dashboards and alerts: what a healthy node looks like, the handful of graphs to watch, and how alerts map to the runbook."
---

```hero
diagram:
  caption: "The Ansible deployment's pipeline. Each node serves Prometheus text on a loopback port; the host's Alloy scrapes it and ships the container's JSON logs. vmalert evaluates `ops/alerts.yml`; Grafana shows two generated dashboards. The console's Live metrics page reads every node's last few minutes through `vlpds.admin.getNodeMetrics`."
  nodes:
    - { id: node, label: vlpds node, sub: "/metrics · 127.0.0.1:9583", at: [0, 3.5], size: [10, 3], tone: accent }
    - { id: console, label: Live metrics, sub: "/admin/metrics · 2 s", at: [0, 9.5], size: [10, 2.6], tone: accent }
    - { id: alloy, label: Alloy, sub: "scrape 10 s · logs", at: [16, 3.5], size: [8, 3], tone: muted }
    - { id: prom, label: Prometheus, sub: VictoriaMetrics, at: [28, 0], size: [9, 2.6], tone: muted }
    - { id: vmalert, label: vmalert, sub: "92 alerts · ops/alerts.yml", at: [28, 3.7], size: [9, 2.6], tone: muted }
    - { id: loki, label: Loki, sub: JSON log lines, at: [28, 7.4], size: [9, 2.6], tone: muted }
    - { id: grafana, label: Grafana, sub: operator · internals, at: [41, 3.5], size: [8, 3], tone: blue }
  edges:
    - "node -> alloy: metrics + logs"
    - { from: alloy.r, to: prom.l, label: remote_write }
    - { from: alloy.r, to: loki.l }
    - { from: prom.b, to: vmalert.t, label: rules }
    - { from: prom.r, to: grafana.l30 }
    - { from: vmalert.r, to: grafana.l, label: firing }
    - { from: loki.r, to: grafana.l70 }
    - { from: console.t, to: node.b, label: polls }
facts:
  - { value: "~200", unit: metrics, label: "vlpds_* names per node", note: "Prometheus text; histograms for every latency that matters" }
  - { value: "92", unit: alerts, label: in eleven groups, note: "18 page, 74 ticket · each links its RUNBOOK section", tone: blue }
  - { value: "0.4", unit: × TTL, label: lease renewal ceiling, note: "vlpds_lease_renew_ttl_ratio; past it the node fail-stops", tone: violet }
  - { value: "~150 ms", label: commit p99 on S3, note: "design target; alerts at 500 ms (ticket) and 2 s (page)", tone: amber }
```

vlpds exports everything an operator needs as Prometheus metrics, and the code ships with alert
rules and two Grafana dashboards. Every alert links to its procedure in the [Runbook](runbook.md).

## What to watch

```diagram
caption: Where the six health signals are measured. Most incidents show up first in one of these; the alerts below are built on the same metrics.
nodes:
  - { id: req, label: Requests, sub: "5xx ratio · p99", at: [0, 0], size: [8, 3] }
  - { id: commit, label: Commit, sub: enqueue → durable + acked, at: [12, 0], size: [10, 3], tone: accent }
  - { id: store, label: Object store, sub: "errors · latency · permits", at: [28, 0], size: [10, 3], shape: store, tone: amber }
  - { id: mem, label: Memory, sub: RSS ÷ limit, at: [0, 6], size: [8, 3] }
  - { id: fh, label: Firehose, sub: emit delay p99, at: [12, 6], size: [10, 3], tone: blue }
  - { id: lease, label: Lease, sub: renewal ÷ TTL, at: [28, 6], size: [10, 3], tone: violet }
edges:
  - req -> commit
  - "commit -> store: segment PUT"
  - { from: commit.b, to: fh.t, label: durable segments, tone: blue }
  - { from: lease.t, to: store.b, label: "CAS every TTL/5", dash: true }
```

| Signal | Metric | Healthy | Alerts |
|---|---|---|---|
| Commit latency | `vlpds_commit_durable_seconds` (p99) · stages in `vlpds_commit_stage_seconds{stage}` | ~40–50 ms p50, ~150 ms p99 on S3 | 500 ms ticket, 2 s page |
| Firehose emit delay | `vlpds_firehose_emit_delay_seconds` (p99) | well under 2 s | 2 s ticket, 20 s page, nothing emitted for 5 min page |
| Lease renewal | `vlpds_lease_renew_ttl_ratio` (p99, by node) | ~0.005 or less (a 25–50 ms PUT against a 10 s TTL) | 0.2 ticket, 0.4 page |
| Object-store failures | `vlpds_object_store_requests_total{result=~"error\|timeout"}` | ~0 | 1/s on a node ticket, two nodes at once page |
| Memory | `vlpds_process_resident_bytes` ÷ `vlpds_memory_limit_bytes` | under 85% | 85% ticket, 95% page |
| Ownership | `sum(vlpds_owned_partitions)` vs `vlpds_shard_layout_shards` | equal | short for 2 min page |
| Errors | 5xx share of `vlpds_http_requests_total` (AppView-proxied calls excluded) | under 1% | 5% page |

The lease ratio is the one to understand. A node renews its lease every TTL/5 and stays valid for
0.8 × TTL after a renewal's send time. So if a renewal round trip takes over 0.4 × TTL, it opens a
gap and the node fail-stops. That's 4 s at the default 10 s TTL, or 24 s on the `tiny` profile's
60 s. A slow object store shows up here before anywhere else. See
[Architecture](../architecture.md#leases) for why.

Some signals don't have a metric. Per-log firehose watermark lag and clock offset between nodes only
show up in `vlpds admin cluster status` (the console's Nodes & shards page). The specific cause of an exit 5
is only in the log line before it. RUNBOOK
[Metric gaps](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#metric-gaps)
keeps the list.

## Metrics endpoint

```diagram
caption: A node's three listeners. Only `--listen` faces clients; metrics and the profiler stay on loopback unless you say otherwise; peers use mutual TLS.
nodes:
  - { id: clients, label: Clients, sub: through Caddy, at: [0, 0], size: [8, 2.6] }
  - { id: scraper, label: Scraper, sub: "Alloy · Prometheus", at: [0, 4], size: [8, 2.6], tone: muted }
  - { id: peers, label: Peer nodes, sub: node certificate, at: [0, 8], size: [8, 2.6], tone: accent }
  - { id: listen, label: "--listen", sub: "0.0.0.0:2583", at: [13, 0], size: [9, 2.6], tone: accent }
  - { id: metrics, label: "--metrics-listen", sub: "127.0.0.1:9583", at: [13, 4], size: [9, 2.6], tone: accent }
  - { id: peer, label: "--peer-listen", sub: "mTLS · e.g. :2584", at: [13, 8], size: [9, 2.6], tone: accent }
  - { id: l1, label: "XRPC · OAuth · UI", sub: "404s /internal/*", at: [26, 0], size: [10, 2.6], shape: note, tone: muted }
  - { id: l2, label: "/metrics · /debug/pprof", sub: pprof only if built in, at: [26, 4], size: [10, 2.6], shape: note, tone: muted }
  - { id: l3, label: "everything + /internal/*", sub: forwards · log streams, at: [26, 8], size: [10, 2.6], shape: note, tone: muted }
edges:
  - clients -> listen
  - scraper -> metrics
  - peers -> peer
  - listen -- l1
  - metrics -- l2
  - peer -- l3
```

- `/metrics` is Prometheus text on `--metrics-listen` (default `127.0.0.1:9583`). With
  `--dev-mode` it moves to the app port so local multi-node runs don't collide.
  `--metrics-listen app` does the same in production. That makes it public unless the proxy in
  front blocks `/metrics` (the Ansible Caddy blocks it, along with `/internal/*`, `/debug/*`,
  `/admin` and `vlpds.admin.*`).
- `/debug/pprof` only exists in a build with `--features profiling` (`just profile <node:port>`
  takes a CPU profile). That build can also push continuous profiles to Pyroscope with
  `--pyroscope-url`.
- Every node exports its own view, so per-node gauges (`vlpds_owned_partitions`, `vlpds_accounts`
  for the shards it holds) sum across nodes. `vlpds_build_info{rev}` names the build, and
  `vlpds_lease_ttl_seconds` and friends export the lease settings the alerts scale with.
- The next process exports how the previous one ended, in
  `vlpds_last_exit_reason_info{reason,code}`. It reads that from the exit-state file in
  `--cache-dir`, so keep that directory on a disk that survives restarts. See
  [exit codes](runbook.md#exit-codes-and-fail-stops).
- Passkeys have their own counters. `vlpds_passkeys_total{event}` counts registrations, removals
  and operator resets, `vlpds_passkey_failures_total{reason}` counts refused ceremonies by the check
  that failed, and `vlpds_passkey_counter_regressions_total{result}` counts counters that went
  backwards. Passkey sign-ins show up in `vlpds_logins_total{method="passkey"}` and
  `vlpds_sign_in_factors_total{factor="passkey"}` (`factor="recovery"` for a recovery code), and
  `vlpds_logins_total{result="passkey_required"}` counts `createSession` refusals. See
  [Passkeys](../oauth-2fa.md#passkeys).

### Per-connection firehose series

| Metric | Labels | What it counts |
|---|---|---|
| `vlpds_firehose_subscribers` | none | subscribeRepos connections open on this node |
| `vlpds_firehose_connections_total` | `mode` | connections upgraded: `live` (no cursor) or `backfill` (with a cursor) |
| `vlpds_firehose_disconnects_total` | `reason` | `client_gone`, `client_closed`, `too_slow`, `write_stalled`, `future_cursor`, `backfill_failed`, `kicked`, `shutdown` |
| `vlpds_firehose_rejected_total` | `reason` | refused before the upgrade (`per_ip`: over `--firehose-max-per-ip`) |
| `vlpds_firehose_events_total` | none | events this node's merger put on the firehose, once each (the rate a caught-up subscriber gets) |
| `vlpds_firehose_subscriber_events_total` | `ip`, `conn`, `relay` | events sent to one connection |
| `vlpds_firehose_subscriber_bytes_total` | `ip`, `conn`, `relay` | websocket bytes sent to one connection |

The two per-subscriber counters have one series per connection. `ip` is the client address
(`--trusted-proxies` aware, IPv6 cut to its /64), `conn` is the node-local connection number the
console's Firehose page shows, and `relay` is the configured relay it matched (empty if none). A
connection's series are removed when it closes. Past 1,000 open connections on a node, the newer ones
share one `ip="other", conn="other"` series, which keeps `/metrics` small if someone opens thousands.
The operator dashboard's "Firehose: events/s per connection vs this PDS" panel draws each connection
against `vlpds_firehose_events_total`.

> [!NOTE]
> These labels carry subscriber IP addresses, so they end up in your metrics store. If you don't want
> that, drop them at scrape time. In Prometheus that's
> `metric_relabel_configs: [{source_labels: [__name__], regex: "vlpds_firehose_subscriber_(events|bytes)_total", action: drop}]`,
> and in Alloy a `prometheus.relabel` rule with the same `source_labels`, `regex` and `action = "drop"`.

## Dashboards

```facts
- { value: "vlpds", label: operator dashboard, note: "Is my PDS up · users · sign-in security · content · federation · moderation · cost · alerts, in plain words with every row open" }
- { value: "internals", label: engineer's dashboard, note: "a Health row for incidents, then 16 collapsed rows per subsystem", tone: blue }
- { value: "2 s", label: console Live metrics, note: "charts from getNodeMetrics, no Prometheus needed", tone: violet }
```

- `vlpds` (uid `vlpds`) is for someone running a PDS for a community. It shows request outcomes,
  how long common actions take, accounts and sign-ups, sign-in security (second factors and passkeys, trusted
  browsers, new-device alerts, OAuth-only refusals, app permissions) and scheduled deletions, posts
  and likes written, relay and PLC health (firehose subscribers, connects and drops, events/s per
  connection against the PDS's own), moderation actions, resources and cost, and firing alerts. It reads the same for one
  server and for a cluster.
- `vlpds internals` (uid `vlpds-internals`) opens on a Health row (requests, 5xx, 429s, read and
  write p99, commit p99, firehose lag and subscribers, nodes up, shards owned, lease renewal ÷ TTL,
  store errors and permit waits, restarts, fail-stops, firing alerts). Below that it has one
  collapsed row per subsystem: commit pipeline, log and retention, firehose, repo workers, HTTP and
  proxy, rate limits, accounts (scheduled deletion, sign-in security, OAuth scopes), Spaces, leases
  and failover, forwarding and resharding, object-store clients, SlateDB, process and runtime,
  KMS / PLC / mail, MinIO (bench only), CPU profiles. Pick the cluster and node in the variables at the top.
- `bench/obs/grafana/gen_dashboard.py` generates both into `bench/obs/grafana/dashboards/`
  (`just dashboards`), and the vlpds binary embeds that copy. `--check` fails if one is stale.
  Edit the generator and leave the JSON alone.
- The [operator console](admin-console.md#pages) has a Nodes & shards page (ownership map, nodes,
  firehose merge, feature level), which polls `getClusterStatus` every 2 s. Its Live metrics page
  (`/admin/metrics`) reads `getNodeMetrics` every 2 s, which gathers every node's last 3 minutes over
  the peer listener. So it works through a plain SSH tunnel too, with no `/metrics` on the console's
  origin.

### Import into your own Grafana

The binary prints both dashboards, so you don't need the repo:

```bash
vlpds dashboards --name vlpds > vlpds.json
vlpds dashboards --name internals > vlpds-internals.json
# from the image
docker run --rm ghcr.io/jazware/vlpds dashboards --name vlpds > vlpds.json
```

In Grafana, go to Dashboards → New → Import, upload a file and pick your Prometheus when it asks.
The console's Live metrics page has download buttons for both. The same files are in the repo at `bench/obs/grafana/dashboards/`
([vlpds.json](https://raw.githubusercontent.com/jazware/vlpds/main/bench/obs/grafana/dashboards/vlpds.json),
[vlpds-internals.json](https://raw.githubusercontent.com/jazware/vlpds/main/bench/obs/grafana/dashboards/vlpds-internals.json)).

What they need:

- **Grafana 10 or newer.** The internals dashboard uses the state timeline and flame graph panels.
- **Prometheus scraping `/metrics` on every node.** That's `127.0.0.1:9583` by default, so either
  run the scraper on the same host or set `--metrics-listen` to a private address
  ([Metrics endpoint](#metrics-endpoint)). Any job name works: the dashboards find the jobs that
  export `vlpds_build_info`.
- **`ops/alerts.yml` loaded** into whatever evaluates rules for that Prometheus, for the alert
  panels. Without it they stay empty. The rules expect job `vlpds` ([Alerts](#alerts)).
- **A `cluster` label is optional.** Without one, the cluster picker shows All and every query
  still matches.
- **Pyroscope is optional.** Only the internals dashboard's collapsed CPU profile row uses it.

The Prometheus picker at the top of each dashboard (and the internals dashboard's Pyroscope
picker) switches datasources later.
Grafana file provisioning doesn't answer the import prompt, so for provisioning print a copy
bound to your datasource: `vlpds dashboards --out DIR --datasource-uid <uid>` (or
`--datasource-uid default` for the default datasource).

## Alerts

```diagram
caption: "Every rule carries a severity and a `runbook_url` whose anchor is the alert's own section in `ops/RUNBOOK.md`."
nodes:
  - { id: rules, label: "ops/alerts.yml", sub: 92 alerts · 11 groups, at: [0, 2], size: [9, 3], tone: accent }
  - { id: eval, label: vmalert, sub: or Prometheus, at: [13, 2], size: [8, 3], tone: muted }
  - { id: page, label: page, sub: "17: act now", at: [25, 0], size: [8, 2.6], tone: danger }
  - { id: ticket, label: ticket, sub: "69: act today", at: [25, 4], size: [8, 2.6], tone: amber }
  - { id: rb, label: RUNBOOK section, sub: "Means · Confirm · Do", at: [40, 2], size: [9, 3], tone: solid }
edges:
  - rules -> eval
  - eval.r -> page.l
  - eval.r -> ticket.l
  - page.r -> rb.l30
  - ticket.r -> rb.l70
```

| Group | Rules | Pages on |
|---|---|---|
| `vlpds-liveness` | 11 | a node down, nothing scraped, a crash loop, format errors |
| `vlpds-ownership` | 6 | shards unowned for 2 min |
| `vlpds-leases` | 5 | a renewal past 0.4 × TTL |
| `vlpds-writes` | 15 | commit p99 over 2 s, the commit log stalled, 5xx over 5% |
| `vlpds-forwarding` | 3 | (tickets only) |
| `vlpds-firehose` | 6 | emit delay over 20 s, the firehose stalled |
| `vlpds-object-store` | 11 | a brownout on two or more nodes |
| `vlpds-durability` | 9 | (tickets only: checkpoints, retention, dead logs, reshard GC) |
| `vlpds-resources` | 18 | memory over 95%, KMS or PLC directory down, a signature fault |
| `vlpds-accounts` | 3 | (tickets only: scheduled deletions failing or surging, sign-in alerts not mailed) |
| `vlpds-spaces` | 5 | saturated revocation blocks |

A `vlpds-derived` group holds the recording rules (`vlpds:layout_shards`). Read the header of
`ops/alerts.yml` before loading it anywhere. The main points:

- The rules expect scrape job `vlpds` and one cluster per Prometheus. With several clusters, scope
  the rule set with a `cluster` label. The Ansible deployment scopes it to its own `cluster` label,
  so other nodes scraped under the same job never fire it.
- The lease alerts scale with each node's TTL through `vlpds_lease_ttl_seconds`, so the same rules
  fit a 10 s cluster and a 60 s `tiny` node.
- Thresholds are marked `design` or `guess`. Tune the guesses against a week of real traffic.
- `VlpdsNotScraped` fires when no node of the cluster is scraped at all. Without it, every other
  alert would go quiet without anyone noticing.

The example deployment evaluates them with vmalert on the monitoring host, without an
Alertmanager. Firing alerts show up in Grafana and in vmalert's UI. Any Prometheus-compatible rule
evaluator works.

## Logs

```facts
- { value: json, label: "--log-format in production", note: "one object per line on stderr: timestamp, level, target, message, fields" }
- { value: "info", label: default RUST_LOG, note: "info,slatedb=warn", tone: blue }
- { value: stdout, label: is machine output only, note: "wrapped keys, vlpds admin tables and --json", tone: violet }
```

Logs go to stderr, and `text` (the default) only uses colour on a terminal. In the Ansible
deployment, the container's json-file logs reach Loki through the host's Alloy, with `level` lifted
into a label:

```text
{container="vlpds"} | json | message="shards opened"
```

Lines worth knowing, most at info or warn:

| Line | Means |
|---|---|
| `acquired shards` / `shards opened` / `shards closed` | ownership changes, with `segments_replayed` and `replayed_ms` on opens |
| `handing back extra shards` | a node above its fair share is giving shards to a joiner |
| `fenced dead node's log` | a takeover or a same-id restart (`log_id`, `fence_ordinal`) |
| `peer missed a renewal and refuses connections: presumed dead` | fast takeover of a gone process |
| `node lease renew error (will retry)` | a renewal failed · four in a row lapse the lease |
| `control-plane <op> timed out after` | a lease, assignment or fence call took over min(TTL, 5 s) |
| `tokio runtime stall` | the runtime was blocked (`late_ms`) |
| `secrets at rest`, `PLC registration on`, `SST disk cache (per shard)` | startup checks (KEK id, rotation key, cache size) |

The fail-stop lines and their exit codes are in the [Runbook](runbook.md#exit-codes-and-fail-stops).

## Object-store request accounting

```diagram
caption: "Every request on the wire is counted once, below SlateDB and the log, by the pool that sent it and the bucket prefix it touched. Disk-cache hits never reach the counter; retries and hedged PUTs do."
nodes:
  - { id: log, label: log client, sub: "segments · replay · backfill", at: [0, 0], size: [10, 2.6], tone: accent }
  - { id: state, label: state client, sub: "SlateDB · blobs · indexes", at: [0, 3.6], size: [10, 2.6], tone: accent }
  - { id: ctl, label: ctl client, sub: "leases · assignments", at: [0, 7.2], size: [10, 2.6], tone: accent }
  - { id: count, label: objstats, sub: "op · component · client · result", at: [14, 3.3], size: [11, 3.2], tone: violet }
  - { id: bucket, label: bucket, sub: what the bill counts, at: [29, 3.3], size: [9, 3.2], shape: store, tone: amber }
edges:
  - log.r -> count.l
  - state.r -> count.l
  - ctl.r -> count.l
  - "count -> bucket: request"
```

`vlpds_object_store_requests_total{op,component,client,result}` counts what an S3, GCS or R2 bill
counts. `op` is the billable operation (`put`, `put_create`, `put_cas`, `get`, `get_range`, `head`,
`list` per 1,000-key page, `delete`, `delete_batch`, `copy`, `mpu_*`). `component` is the prefix:

| Component | Prefix |
|---|---|
| `log_segment` | `log/` (segment PUTs, fences, replay, firehose backfill, follower catch-up) |
| `state_wal`, `state_manifest`, `state_sst`, `state_compactions`, `state_gc_boundary`, `state_other` | `state/{shard}/` (SlateDB) |
| `ctl_lease`, `ctl_assign`, `ctl_writer`, `ctl_version` | `nodes/`, `assign/`, `writers/`, `cluster/` |
| `retention_report`, `account_index`, `blob` | `retain/`, `handle/` + `email/`, `blob/` |

`result` is `ok`, `not_found`, `precondition`, `timeout`, `error` or `cancelled`. A `precondition`
is a lost compare-and-swap, which is normal. `cancelled` means the caller gave up (a control-plane
deadline or a lost hedge). Latency is in `vlpds_object_store_request_seconds{op,component}`, bytes
in `vlpds_object_store_bytes_total`, and permit queueing in
`vlpds_object_store_permit_waits_total{client,lane}`.

Here's what normal looks like, measured:

- A `tiny` node at idle makes ~0.12 Class A (PUT, LIST) and ~0.41 Class B (GET, HEAD) requests a
  second. 89% of the Class A requests are the lease and membership LISTs. That's inside R2's free
  tier (`bench/results/tiny-pds-idle-2026-10-02`).
- A busy node makes ~27 segment PUTs a second at any load up to ~20k commits/s, plus per-shard
  checkpoints, compaction and polling. Request cost follows the number of nodes and shards
  (`bench/results/cost-model-2026-10-02`).

To estimate a month's bill from a running node, sum `increase(...[30d])` by `op` and multiply by your
provider's price per request class. Details: [Object store](object-store.md#cost-by-provider).

## tokio-console

The image carries [tokio-console](https://github.com/tokio-rs/console)'s subscriber, off by
default. Start the PDS with `TOKIO_CONSOLE_BIND=127.0.0.1:6669` and it serves the console's
gRPC API there and logs `tokio-console listening`. Then `tokio-console http://127.0.0.1:6669` shows
every task: what it waits on, its polls, wakes and busy time, and the timers and locks it holds.
Logs keep their format and level filter.

- **Loopback only.** The console's API has no auth and names every task and the code that spawned
  it. The PDS refuses any other address, keeps the console off and logs why. In a container
  that's the container's own loopback, so reach it from inside the container's network namespace
  (`nsenter -t <pid> -n`) or tunnel to it.
- **Off.** The image is built with `--cfg tokio_unstable` and tokio's `tracing` feature, which the
  console needs. With the console off, no subscriber layer is added, but tokio still runs its
  instrumented paths: about 60 ns more per task spawn, 55 ns per timer and 3 ns per channel
  message in a spawn-only microbenchmark (+21% there). An HTTP endpoint under keep-alive load
  measured within noise.
- **On.** The console records every task and resource (each channel, timer and lock). Code that
  sends a lot through channels pays most: the same microbenchmark's channel ping-pong ran 24x
  slower with the console on and its spawns 3.4x, while the HTTP benchmark didn't move. On a busy
  node, turn it on briefly and off again.
- **Retention.** The console keeps finished tasks, resources and async ops for
  `TOKIO_CONSOLE_RETENTION`, 60 s by default (`500ms`, `60s`, `5m`, `1h` or bare seconds), so it
  shows only the last minute of finished tasks. Live tasks show for as long as they run.
  console-subscriber's own default is an hour, and a process that spawns many short-lived tasks
  holds every one of them for that hour. Each task costs the console about 50 KiB, live or
  finished, most of it two latency histograms, so the console holds about 50 KiB for every live
  task and every task spawned within the retention. In a 10-minute test of 100 fresh HTTP
  connections a second (a task each), a relay with an hour's retention grew 4.9 MiB a second to
  2790 MiB and was still climbing, with 60 s it held flat at 343 MiB from the first minute on, and
  with the console off it stayed at 29 MiB. At 800 connections a second, 60 s still held 2386 MiB,
  so on a node that spawns tasks that fast, set a shorter retention. Retention bounds memory only.
  The CPU cost of tokio's instrumentation stays while the console is on.
- **Buffers.** `TOKIO_CONSOLE_BUFFER_CAPACITY` (16384 by default, against console-subscriber's
  102400) caps the events queued for the console's aggregator. Past it they're dropped, and the
  console says how many. `TOKIO_CONSOLE_CLIENT_BUFFER_CAPACITY` (64 by default, a minute of
  updates, against 4096) caps the updates queued for each console client. A client that falls
  further behind is disconnected. An unparseable or zero value keeps the console off and logs why.
- A binary built without `--cfg tokio_unstable` (a plain `cargo build`) logs that
  `TOKIO_CONSOLE_BIND` is set and stays off.
