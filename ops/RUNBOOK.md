# vlpds operator runbook

Companion to `ops/alerts.yml`. Each alert has a section below, and its heading is
the alert name (the `runbook_url` anchors point here). Everything here comes from
`DESIGN.md` and `src/`. Anything inferred instead of read from the code is marked
**(unverified)**.

- [Background you need](#background-you-need)
- [Tools: endpoints, CLI, logs, exit codes](#tools-endpoints-cli-logs-exit-codes)
- [Admin CLI](#admin-cli)
- [Alerts](#alerts)
- [Procedures](#procedures)
- [What NOT to do](#what-not-to-do)
- [Metric gaps](#metric-gaps)

---

## Background you need

- All durable state lives in the object store, under `--prefix` in `--s3-bucket`.
  The local disk is only a SlateDB SST cache. The bucket holds
  `log/{log_id}/{ordinal}.seg` (each node incarnation's commit log), `state/{id}/`
  (one SlateDB per shard, with its WAL disabled), `assign/{id}` + `assign/layout`
  (who owns what, and the slot -> shard map), `nodes/{node_id}` (node leases),
  `writers/{w}` (a unique seq low byte per live node), `retain/{log_id}` (retention
  reports), `cluster/version` (the cluster's active feature level and its
  history), `handle/`, `email/` and `blob/`. `{id}` is the shard id as 10
  zero-padded decimal digits, so shard 42 is `state/0000000042/`.
- There are 65,536 hash slots, grouped into shards (default `--shards 64`,
  changed online by split/merge). Each shard has exactly one owner node at a time.
  A node takes free or orphaned shards up to its fair share, `ceil(shards / live
  nodes)`, and hands extras to joiners.
- Each node incarnation writes one log. A write is acked only after its segment
  and every earlier one are durable, and only while the node's lease is valid.
  Segments are `If-None-Match` PUTs, up to `--log-inflight` 4 in flight, finalized
  in order.
- A node CAS-renews its lease `nodes/{node_id}` every TTL/5. That's 2 s at the
  default `--lease-ttl-ms 10000` and 12 s at the tiny profile's 60 s. The node's
  own validity ends `TTL - skew` = 0.8 x TTL (8 s / 48 s) after the send time of
  its last successful renewal. Renewals are sequential, so once a round trip takes
  longer than the renew interval the next one goes out only when it returns. With
  round trips over `0.4 x TTL` (4 s / 24 s), two in a row outlast the 0.8 x TTL of
  validity, and the node fail-stops. If the whole object store browns
  out past that ceiling, every node stops. Each node exports its settings
  (`vlpds_lease_ttl_seconds`, `vlpds_lease_renew_interval_seconds`,
  `vlpds_lease_skew_seconds`) and its renewals as a fraction of the TTL
  (`vlpds_lease_renew_ttl_ratio`), and the lease alerts are relative to them.
- Peers presume a node dead once its lease hasn't changed for `TTL + skew` =
  1.2 x TTL of their own monotonic time (12 s at the default, 72 s at 60 s). If
  its advertised port refuses TCP connections (the process is gone), they presume
  it dead within ~1.5-2.5 renew intervals (3-5 s at the default). The new owner
  fences the dead log (a conditional create at the end of its durable prefix),
  CASes the assignment and replays the shard's spans. Then it waits out the
  previous owner's `seq_floor` (commit-wait, max 30 s) and serves.
- A lone node lists less (there's no flag for it). While `nodes/` holds only its
  own lease, a node LISTs `nodes/` once per TTL and `assign/` every 25 steps
  (`vlpds_cluster_lone_skips_total`). A joiner is seen at once through its hello,
  or within a TTL if the hello is lost. An `assign/` object edited by hand in the
  bucket (never do this) is noticed within 25 steps instead of at the next one.
- Retention passes run every `--log-retention-interval` (default 60 s, range
  1 s..=10 m), and `VlpdsRetentionNotRunning` expects a pass every 15 min. A pass
  LISTs only what can be due, so idle passes make no requests
  (`vlpds_retention_lists_skipped_total`). A longer interval saves little more,
  and it delays deletes and dead-log retirement by up to one interval.
- Fail-stop is the safety mechanism. A node that might be wrong exits, and the
  supervisor restarts it so it rejoins. A wrong "dead" presumption costs
  availability but never an acked write (DESIGN "Why safety needs no clocks").
- Every node merges every node's log into the firehose and emits an event once
  `seq <= min watermark` over all logs. So one slow, stalled or unfenced log holds
  the firehose back on every node. The merged emit lags by the largest wall-clock
  offset between nodes.
- Any node accepts any request. Repo writes and reads for a shard a node doesn't
  own are proxied to the owner with a 3 s time-to-first-byte deadline (30 s for
  exports, uploads and proxying). If the owner doesn't answer in time, the client
  gets 503 `PartitionUnavailable` (ambiguous, so it's never resent). If the owner
  can't start a forwarded write within `--forwarded-write-start-ms` (1 s), it
  answers 503 `RepoLoading` (never applied). A write that finds the shard moving
  gets 503 `ShardMoved`. The entry node resends those (and connect-refused
  forwards) to the current owner for up to 20 s.

## Tools: endpoints, CLI, logs, exit codes

**Endpoints** (any node). `/metrics` and `/debug/pprof` are served only on
`--metrics-listen` (default `127.0.0.1:9583`). With `--dev-mode` or
`--metrics-listen app` they're on the app port, which is public unless a proxy
blocks it. Peer traffic goes to `--advertise-url` over peer mTLS, the only
node-to-node transport (DESIGN.md "Exposure"). That covers forwards (which carry
users' tokens), `/internal/*` and log streams. There are two setups:
- Cluster: `--peer-listen`, `--peer-tls-dir` ([Peer TLS](#peer-tls-mtls-between-nodes))
  and `--advertise-url https://<host>:<peer port>`, always together. The peer
  listener serves everything `--listen` does plus `/internal/*`, with the peer
  HTTP/2 settings, and only to clients with a node certificate of the cluster CA.
  It serves `/metrics` and `/debug/pprof` only where `--listen` has them.
- Single host (none of the three, as the Ansible role runs it): a lone node with
  no peer listener, no `/internal/*` and no peer calls.

Either way, `--listen` serves clients only. It 404s `/internal/*` and drops
`x-vlpds-forwarded`, `x-vlpds-internal` and `x-vlpds-client-ip` from requests,
which are served as the client requests they are. Block `/internal/` at the edge
anyway (the Ansible Caddy does).

Production refuses the MinIO default S3 credentials, and
`vlpds.admin.bulkCreate` needs `--dev-mode` or `--allow-bulk-create`.

| What | How |
|---|---|
| Liveness | `GET /xrpc/_health` -> `{"version":"vlpds"}` |
| Caddy on-demand TLS | `on_demand_tls { ask http://127.0.0.1:2583/tls-check }`. `GET /tls-check?domain=D` is 200 for the `--public-url` host and handles of active accounts here, 400 outside `--handle-domain` and 404 for unknown/deactivated handles (any node answers) |
| Service DID document | `GET /.well-known/did.json` returns the `did:web` `--service-did`'s document (`#atproto_pds` at `--public-url`). 404 for any other DID method |
| Metrics | `GET http://127.0.0.1:9583/metrics` (Prometheus text, `--metrics-listen`) |
| Cluster view (admin) | `GET /xrpc/vlpds.admin.getClusterStatus` with `Authorization: Basic base64(admin:$VLPDS_ADMIN_TOKEN)`. Returns `node`, `log`, `logDurableOrdinal`, `owned` (shard ids), `shards`, `table` (owner per shard in slot order, `null` = unowned), `layout` (`version`, `shards`, `op` = split/merge in progress), `leaseValid`, `leaseExpiresMs`, `fencedLogs`, `firehose.{lastEmitted,minWatermark,sources[{log,watermark,local}]}`, `version` (feature levels, see [Rolling upgrade](#rolling-upgrade-finalize-rollback): `active`, `target` while a raise runs, `history`, this build's `binary.{min,max,rev}`, `mixedBuilds`, `revs`, `finalizable`, `finalizedAt`), and `nodes[]` with each peer's `reachable`, `leaseValid`, `logDurableOrdinal`, `owned` count, `writer`, `expiresMs`, `rev`, `minLevel`, `maxLevel`, `seenLevel` (peers fetched with a 1.5 s timeout). |
| Feature level raise (admin) | `POST /xrpc/vlpds.admin.setFeatureLevel {"level": N}` (CLI `vlpds admin cluster finalize`). Returns 200 with the new `cluster/version`, 409 `IncompatibleNodes` naming live nodes whose build can't run N (nothing changed), or 400 below the active level or past the asked node's build. With `"lower": true` (CLI `vlpds admin cluster lower`) it lowers instead, with 400 past a persistent level or during a raise and 409 while a live node can't run N. |
| Cluster view (node-to-node) | `GET /internal/v1/cluster` on the peer address (`--advertise-url`) with header `x-vlpds-internal: $VLPDS_INTERNAL_TOKEN`. With peer TLS it needs a node certificate (`curl --cacert ca.crt --cert node.crt --key node.key`), so prefer getClusterStatus above. Returns this node's `owned`, `table`, `layout`, `peers`, `lease_valid`, `log_durable_ordinal`, `firehose_last_emitted`, `firehose_min_watermark`. |
| Operator console | `/admin` (Cluster page polls getClusterStatus), `/admin/metrics` (live metrics). |
| Shard layout | `vlpds admin layout --url http://<node>:2583` (or `vlpds admin --url ... layout`, with `VLPDS_ADMIN_TOKEN` in the env), or `GET /xrpc/vlpds.admin.getShardLayout`. Also `shard-split`, `shard-merge` and `reshard-abort` (abort only before the flip). |
| Accounts, identity, repos | `vlpds admin ...`, the pdsadmin equivalents. See [Admin CLI](#admin-cli). |
| CPU profile | `just profile <node:port> [seconds]` (`/debug/pprof/`). Only in a build with `--features profiling`, like the image built with that feature. A default build has no profiler and the endpoint is absent |

A quick cluster check:

```sh
curl -s -u "admin:$VLPDS_ADMIN_TOKEN" http://NODE:2583/xrpc/vlpds.admin.getClusterStatus \
  | jq '{node, leaseValid, owned: (.owned|length), shards, unowned: ([.table[]|select(.==null)]|length),
         op: .layout.op, fenced: .fencedLogs,
         nodes: [.nodes[] | {node, reachable, leaseValid, owned, logDurableOrdinal}],
         firehose: .firehose.minWatermark}'
```

**Exit codes** (fail-stops). The supervisor must restart on any of them.

| Code | `reason` | Meaning | Log line (error level) |
|---|---|---|---|
| 2 | `segment_upload` | Segment upload task failed | `segment upload task failed: ...; exiting` |
| 3 | `fenced` / `ordinal_taken` | A successor fenced our log, or another writer took our segment ordinal | `our log was fenced by a successor: fail-stop` / `segment ordinal taken by another writer: fail-stop` |
| 4 | `state_apply` | SlateDB apply of a durable segment failed | `state apply failed: ...; exiting` |
| 5 | `lease_lost` / `lease_lapsed` | Lease lost or lapsed (any reason) | `node lease lost unexpectedly: fail-stop` (`lease_lost`), preceded by one of `node lease lost (CAS conflict)`, `node lease lapsed before renewal`, `node lease lapsed past takeover` (watchdog), `a shard we hold was reassigned`, `a shard failed to close cleanly`, `our log did not quiesce`. Or `node lease lapsed before segment PUT` / `before ack` (`lease_lapsed`) |
| 6 | `signature_fault` | 3 signatures failed verification right after signing within a minute (suspected memory/CPU fault, see [VlpdsSignatureFault](#vlpdssignaturefault)) | `repeated signature faults: fail-stop (suspect this host's memory or CPU)`, preceded by `signature failed verification against the signing key's public key` (purpose, recent) |
| 7 | `incompatible_level` | This build can't run the cluster's feature level (`cluster/version`). Checked before the node reads or writes anything, again right after its lease write (lease deleted), and once per TTL while running. Either an old image after a finalize, or a new image whose `MIN_LEVEL` is past the cluster's (see [VlpdsIncompatibleNode](#vlpdsincompatiblenode)) | `incompatible feature level: cluster level N is outside this build's levels A..=B` / `cluster is raising its level to N, past this build's max level B; fail-stop (exit 7)` |
| 8 | `shutdown_fence` | A graceful stop couldn't fence its own log within min(TTL, 30 s) of retries. It keeps its lease, so peers presume it dead and fence the log, or the restart (same `--node-id`) does. Its shards were already handed out | `fencing our log on shutdown failed: giving up`, then `...: exiting nonzero without dropping our lease` |
| 9 | `critical_task_panicked` | A thread or task the node can't run without panicked. That's a repo worker thread (`repo_worker`), the log sequencer or finalizer (`log_sequencer`, `log_finalizer`), or the firehose merger (`firehose_merger`). It's a bug, and the panic message and location are on stderr just before. Peers take its shards over and the restart is clean | the panic (`thread '...' panicked at src/...`), then `critical task panicked: fail-stop (exit 9)` (`task` field) |

**How the previous process ended** is a metric on the next one
(`vlsync-store/src/lifecycle.rs`). Each fail-stop writes its `reason` and code to the
exit-state file just before exiting (`--exit-state-file`, default
`vlpds-exit-<node-id>.json` in `--cache-dir`, and with neither set nothing is
kept). The next start exports `vlpds_last_exit_reason_info{reason,code}` = 1 for
as long as it runs. Besides the reasons in the table, there's `clean` (graceful
stop, code 0), `error` (code 1, a startup or serve error), `crash` (the file
still says `running`, so SIGKILL, OOM kill, abort or host loss) and `none` (first
start or no file). `vlpds_process_start_time_seconds` (and the standard
`process_start_time_seconds`) dates the restart. On the cluster side, whoever
fences an incarnation that ended without fencing its own log counts
`vlpds_peer_takeovers_total{reason="peer"|"restart"}`. A graceful stop fences
its own log, so it never counts. This counter survives a node that never comes
back.

**Serving limits** (DESIGN.md "HTTP", "Firehose", "Stage 3: readers"):

| Flag (env) | Default | Bounds | Past it |
|---|---|---|---|
| `--max-connections` (`VLPDS_MAX_CONNECTIONS`) | 50,000 | open connections per listener | accepts pause (connections wait in the accept queue) |
| `--peer-listen` (`VLPDS_PEER_LISTEN`) | unset (lone node) | the peer listener (mTLS), with the large h2 windows (4 MiB / 64 MiB, 1,024 streams). Needs `--peer-tls-dir` and `--advertise-url` pointing at it. `--listen` always has the client settings (1 MiB / 8 MiB windows, 256 streams per connection) | - |
| `--peer-tls-dir` (`VLPDS_PEER_TLS_DIR`) | unset | `ca.crt`, `<node-id>.crt`, `<node-id>.key` for peer mTLS on `--peer-listen` and in the peer clients ([Peer TLS](#peer-tls-mtls-between-nodes)). Re-read on SIGHUP and on file change (60 s poll). `--dev-mode` creates what's missing | a node cert from another CA, or for another node or host, gets its handshake refused (`vlpds_peer_tls_handshake_failures_total`) |
| `--max-exports` (`VLPDS_MAX_EXPORTS`) | 32 | getRepo exports streaming at once | waits 10 s for a slot, then 503 `Overloaded` (`vlpds_sync_exports_ended_total{reason="shed"}`) |
| `--export-stall-secs` (`VLPDS_EXPORT_STALL_SECS`) | 60 | how long an export waits for a client that reads nothing | export ended, body errors (`reason="stalled"`) |
| `--max-queued-reads` (`VLPDS_MAX_QUEUED_READS`) | 20,000 | repo-view reads (getRepo, getRecord, getBlocks, ...) queued at the repo workers | 503 `Overloaded` |
| `--firehose-max-backfills` (`VLPDS_FIREHOSE_MAX_BACKFILLS`) | 16 | cursor backfills running at once (x `--backfill-readahead-mb` of read-ahead) | waits for a slot (`vlpds_firehose_backfills{state="waiting"}`) |
| `--firehose-max-per-ip` (`VLPDS_FIREHOSE_MAX_PER_IP`) | 256 | subscribeRepos connections per client IP (IPv6 /64) | 429 `RateLimitExceeded` (`vlpds_firehose_rejected_total{reason="per_ip"}`) |

Some limits aren't flags. A subscriber that takes no bytes for 30 s outside the
live path (backfill, pongs) is dropped
(`vlpds_firehose_disconnects_total{reason="write_stalled"}`). Argon2 runs at most
one per core at once (16 max). Request-path password checks and hashes wait up
to 2 s for a turn, then answer 503 `Overloaded` (`vlpds_argon2_shed_total`,
[VlpdsPasswordHashingShed](#vlpdspasswordhashingshed)), while admin password
changes wait. Accept errors are retried every 50 ms
(`vlpds_http_server_accept_errors_total`, log `accept failed (retrying)`), and
they usually mean the node is out of file descriptors.

**Logs** go to stderr. stdout carries only machine output (wrapped keys,
`vlpds admin` tables and `--json`). Use `--log-format json` (`VLPDS_LOG_FORMAT`)
in production for one JSON object per line. `text` (the default) colours only
when stderr is a terminal and `NO_COLOR` is unset. Filter with `RUST_LOG`
(default `info,slatedb=warn`).

**Disk cache sizing**. Put `--cache-dir` on local NVMe and set `--disk-cache-mb`
(`VLPDS_DISK_CACHE_MB`) to the space you give it on that node. Each shard's cap
is that divided by the layout's shard count, so the total fits even if this node
takes every shard. In steady state an N-node cluster uses about 1/N of it. If
the disk is sized for failover, set the per-shard cap instead
(`--disk-cache-shard-mb`). Unset, it's 16 GiB per shard (1 TiB at 64 shards).
The start-up line `SST disk cache (per shard)` shows `dir` and `shard_mb`.

**Account totals** (`vlpds_accounts`, `vlpds_repos_written_within`) are kept
exact per slot with every account change and commit. The node holding each shard
exports them, so sum over nodes. There's no periodic scan and no flag. A dip
during a failover lasts until the shards reopen elsewhere. The windows count
whole UTC days ("1d" = yesterday and today). If the totals ever look wrong,
compare with a fresh count. `vlpds::xrpc::scan_totals` (used by
`tests/all/account_totals.rs`) reads every account and head row of a node's
shards. That's expensive, so don't run it on a schedule.

**Useful log lines** (tracing, info/warn unless noted):
`acquired shards` (shards, owned, fair, live), `shards opened` (shards,
`segments_replayed`, `replayed_ms`, `elapsed_ms`), `shards closed`,
`handing back extra shards`, `fenced dead node's log` (log_id, fence_ordinal),
`peer missed a renewal and refuses connections: presumed dead`,
`node lease renew error (will retry)`, `control-plane <op> timed out after`,
`waited for our clock to pass the previous owner's last seq`,
`previous owner's clock is more than 30s ahead of ours: serving anyway` (error),
`tokio runtime stall` (late_ms), `log retention pass failed`,
`reshard step failed (retried next step)`, `fencing our log on shutdown failed`.

---

## Admin CLI

`vlpds admin [--url URL] [--admin-token T] [--json] <command>` talks admin XRPC
to one node. The three flags work before or after the command. `--url` defaults
to `http://127.0.0.1:2583` (env `VLPDS_URL`). The token comes from
`VLPDS_ADMIN_TOKEN`, or else from the file that `--admin-token-file` /
`VLPDS_ADMIN_TOKEN_FILE` names, the same as the node's. So `docker exec vlpds vlpds admin
...` needs no token argument.

Any node will do. Calls naming a DID are routed to the repo's owner. The
per-node maintenance commands (`rotate-plc-keys`, `rewrap-secrets`) are sent to
every node that `getClusterStatus` lists (`--node-only` for just `--url`).
Shards that moved between two nodes' calls are rerun on their new owner (rows
marked `(rerun)`), and shards no node scanned fail the command.

Output is a table or a short message, and `--json` prints the raw results. The
command exits 1 on an XRPC error, on any failed item of a batch (the other items
still run, as the reference scripts do), and from `check-repo` when it finds a
problem. Destructive commands (`account delete`, `rebuild-repo`) ask for
confirmation, and off a terminal they refuse without `--yes`.

| Reference (`pdsadmin` / `node run-script.js`) | vlpds | Via |
|---|---|---|
| `pdsadmin account list` | `vlpds admin account list [--email PREFIX]` | `admin.searchAccounts` (every node's shards, paged, and warns on `unreachableNodes` / `missingShards`) |
| `pdsadmin account create EMAIL HANDLE` | `vlpds admin account create EMAIL HANDLE [--password P] [--invite-code C]` | a single-use invite only if `describeServer.inviteCodeRequired`, then `server.createAccount`. Prints the generated 24-char password once |
| `pdsadmin account delete DID` | `vlpds admin account delete DID [--yes]` | `admin.deleteAccount` |
| `pdsadmin account takedown DID` | `vlpds admin account takedown DID [--ref R]` | `admin.updateSubjectStatus` (repoRef, `ref` default unix time) |
| `pdsadmin account untakedown DID` | `vlpds admin account untakedown DID` | same, `applied: false` |
| `pdsadmin account reset-password DID` | `vlpds admin account reset-password DID [--password P]` | `admin.updateAccountPassword`, prints the new password |
| (none) | `vlpds admin account info DID` | `admin.getAccountInfo` + `getSubjectStatus` |
| `pdsadmin create-invite-code` | `vlpds admin create-invite-code [--uses N] [--count N] [--for-account DID]` | `server.createInviteCode`, one code per line |
| `pdsadmin request-crawl [RELAY,...]` | `vlpds admin request-crawl [RELAY,...]` | `vlpds.admin.requestCrawl`. The node asks each relay (default its `--crawlers`) to crawl its `--public-url` host. Per-relay result, exit 1 if any refused |
| `pdsadmin update` | (none) | roll the image, see [Rolling deploy](#rolling-deploy) |
| `publish-identity DID...` / `publish-identity-file F` | `vlpds admin publish-identity [DID...] [--file F]` | `vlpds.admin.publishIdentity`. Sends `#identity` for each DID (any status but deleted) and drops DID-document caches |
| `rotate-keys DID...` / `rotate-keys-file F` | `vlpds admin rotate-keys [DID...] [--file F]` | `vlpds.admin.publishIdentity {syncPlc: true}`. A did:plc whose PLC `atproto` key isn't the signing key held here gets a PLC update (server rotation key). Then the repo is re-signed (an empty commit) with `#identity` + `#sync`, as the reference does, so relays that failed commits against the old document resync |
| (admin `updateAccountSigningKey`) | `vlpds admin rotate-keys --generate DID...` | a fresh signing key. It's recorded as pending (the account's writes get a retryable 503 `KeyUnavailable` meanwhile), PLC is updated, then the repo is re-signed with `#identity` + `#sync`. A PLC refusal changes nothing. After an outage or a crash the rotation stays pending and the node finishes it (DESIGN "Signing-key rotation") |
| (`PDS_PLC_ROTATION_KEY` change) | `vlpds admin rotate-plc-keys [--dry-run]` | `vlpds.admin.rotatePlcKeys` on every node ([PLC rotation key rotation](#plc-rotation-key-rotation)) |
| (`PDS_RECOVERY_DID_KEY` set after accounts exist) | `vlpds admin ensure-recovery-key [--dry-run] [--per-second N]` | `vlpds.admin.ensureRecoveryKey` on every node ([Operator recovery key](#operator-recovery-key)) |
| (none) | `vlpds admin rewrap-secrets [--dry-run] [--check-versions]` | `vlpds.admin.rewrapSecrets` on every node ([KEK rotation](#kek-rotation)) |
| `rebuild-repo DID` | `vlpds admin rebuild-repo DID [--dry-run] [--yes]` | `vlpds.admin.rebuildRepo`, see below |
| (none) | `vlpds admin check-repo DID` | `vlpds.admin.checkRepo`, see below |
| `sequencer-recovery`, `recovery-repair-repos`, `rotate-keys-recovery` | (none) | there's no single sequencer DB to replay. Durability is the log + SlateDB per shard (DESIGN "Backups and restore") |
| (none) | `vlpds admin cluster status` | `vlpds.admin.getClusterStatus`. Shows this node, layout, unowned shards, firehose, feature level (and the finalize/mixed-builds banner), and a row per node (`*` = the one asked) with its rev and level window |
| (none) | `vlpds admin cluster finalize [--level N] [--yes]` | `vlpds.admin.setFeatureLevel` (default N = active + 1, asks first). See [Rolling upgrade](#rolling-upgrade-finalize-rollback) |
| (none) | `vlpds admin cluster lower --level N [--yes]` | `vlpds.admin.setFeatureLevel {"level": N, "lower": true}`, only past wire-only (non-persistent) levels. See [Rolling upgrade](#rolling-upgrade-finalize-rollback) |
| (none) | `vlpds admin layout`, `shard-split`, `shard-merge`, `reshard-abort` | [Shard split / merge](#shard-split--merge) |

Per-DID batches (`publish-identity`, `rotate-keys`) run one DID at a time, like
the reference scripts without their sleep. A file is one DID per line, with blank
lines and `#` comments skipped. For millions of DIDs, split the file and run
several in parallel against different nodes. The PLC directory rate-limits, so
keep `rotate-keys` at a few in flight per IP.

**check-repo** reads the repo's state from one shard snapshot, so it doesn't need
the repo to load. It checks the head commit (hashes to its CID, names the head's
data root and the DID, signature valid for the account's key), every record
(hashes to its CID), the MST rebuilt from the records against the head's data
root, the persisted interior nodes (`M/`, for missing, extra and corrupt nodes)
against that tree, and the record-CID, blob-ref and collection indexes. A missing
or wrong `M/` node heals itself, because the next cold load rebuilds from `R/`
and backfills (`vlpds_lazy_mst_fallbacks_total`). So a check with only node or
index problems isn't an emergency. Run `rebuild-repo` to clean it up now.

**rebuild-repo** is the reference script. It re-derives the repo from its records
(MST, `M/` written whole with stale nodes deleted, record-CID, blob-ref and
collection indexes) under a new signed commit (rev bumped) and a `#sync`. A
deactivated account gets no `#sync`, since activation sends it. It prints the
check first and asks. It's refused with `RepoUnrecoverable` when the records
can't be the repo, meaning one doesn't hash to its CID or they don't rebuild to
the head's data root. That means records were lost and the repo can't load.
Re-signing what's left would silently drop data, so restore from a backup
instead. It's also refused for a taken-down account (untakedown first). A write
landing between the check and the rewrite makes it fail with `InvalidSwap`. Run
it again.

---

## Alerts

### VlpdsNodeDown

**Means:** Prometheus can't scrape a node for 2 minutes. If the process is gone,
peers took its shards within 3-5 s (refused probe) or TTL + skew (12 s at the
default TTL, 72 s at 60 s) plus replay. If the host is up but frozen or
partitioned, its socket still exists and takeover waits the full TTL + skew. The
frozen node's own watchdog fail-stops it 2 x skew after its validity lapses.

**Causes:** crash or fail-stop without a restart, OOM kill, host loss, a network
partition between Prometheus and the node, or a misconfigured `--metrics-listen`.

**Confirm:** run `getClusterStatus` from another node. Is the node in `nodes[]`,
and is it `reachable`? Is `VlpdsShardsUnowned` firing? Check host and supervisor
status and the last log lines (exit code table above). A bench-scrape config
lists ~30 ports that are normally down, so check this is a real node.

**Do:** If `VlpdsShardsUnowned` isn't firing, nothing is urgent. The cluster is
just running with less capacity. Restart the process (same `--node-id`) or
follow [Replacing a dead host](#replacing-a-dead-host). If several nodes are down at
once, look for an object-store outage first ([procedure](#object-store-outage)).

### VlpdsNotScraped

**Means:** no `up{job="vlpds"}` series at all for 10 minutes (for this cluster,
when the rule set is scoped with `extra_labels`). Nothing scrapes the nodes, so
every other vlpds alert is blind, including `VlpdsNodeDown`. That's different
from a node that's scraped and down (`up == 0`).

**Causes:**
- The host's Alloy isn't running or doesn't carry the `vlpds-monitoring`
  fragment. On the prod inventory `vlpds_manage_alloy` is off until the host's
  existing setup is reviewed, so this fires there until then.
- remote_write from Alloy to VictoriaMetrics is failing.
- A renamed job or `cluster` label (`deploy_env`).
- The monitoring host itself is unhealthy (then other deployments' alerts go
  quiet too).

**Confirm:** check `up{job="vlpds"}` by `cluster` in Grafana / VictoriaMetrics.
Check Alloy's UI and logs on the vlpds host (`systemctl status alloy`, its
`prometheus.scrape` and `prometheus.remote_write` components). Run `curl -s
127.0.0.1:9583/metrics | head` on the host. If the node answers locally, the
pipeline is broken and vlpds is fine.

**Do:** fix the scrape pipeline (deploy roles/alloy with the `vlpds-monitoring`
fragment, or repair remote_write). Meanwhile, check the cluster by hand
(`vlpds admin cluster status`). Silence it only for a cluster that's
intentionally unmonitored.

### VlpdsNodeRestarted

**Means:** `vlpds_process_start_time_seconds` changed, so there's a new process.
Expected during a deploy. Otherwise it's a fail-stop, crash or OOM kill.

**Confirm:**
- `vlpds_last_exit_reason_info` on the node gives the reason and code (table
  above, `crash` = no exit recorded). Then find the error line just before the
  exit.
- `vlpds_build_info{rev}` changed? Then it was a deploy.
- Kernel/cgroup OOM logs.
- Exit 5 with `renew error` warnings before it: store latency (see
  [VlpdsLeaseRenewalNearCeiling](#vlpdsleaserenewalnearceiling)).
- Exit 3: a peer presumed this node dead and fenced it (it was frozen,
  partitioned, or its renewals were slow).
- Exit 3 right after another process started with the same `--node-id`: see
  [What NOT to do](#what-not-to-do).

**Do:** nothing if it rejoined (it owns ~fair share again within a step or two)
and the cause is understood. Investigate exit 2/4 (store errors / SlateDB apply)
before they repeat.

### VlpdsNodeFailStopped

**Means:** the node restarted in the last 30 minutes, and its previous process
ended with a fail-stop (`reason` and `code` labels, see the exit code table) or
a `crash` (no exit recorded, so SIGKILL, OOM kill, abort or host loss). `error`
means the previous process failed to start or serve (exit 1). The alert needs
the exit-state file (`--exit-state-file`, or `--cache-dir`) on a disk that
survives restarts.

**Confirm / Do:** as [VlpdsNodeRestarted](#vlpdsnoderestarted) for that reason.
For `crash`, check kernel/cgroup OOM logs and supervisor logs.

### VlpdsUncleanNodeExit

**Means:** some node fenced the log of an incarnation that ended without fencing
it itself. `reason="peer"` means a survivor took over a dead peer's shards
(crash, kill -9, OOM, fail-stop, partition, frozen past TTL + skew).
`reason="restart"` means a node fenced its own previous incarnation at startup,
because it came back before a peer took over. Graceful stops never count. A live
node does the counting, so this reports deaths of nodes that never come back.
Every node exports both reasons at 0 from startup (`metrics::init_counters`), so
`increase()` sees the first takeover. Without that, a counter series that first
appeared at 1 had no earlier sample and the alert missed it. A `restart` lands
before the new process is first scraped, but in the series its predecessor
exported at 0.

**Confirm:** `fenced dead node's log` (log_id) in the fencer's logs, and the dead
incarnation's `vlpds_last_exit_reason_info` once it restarts.

**Do:** as [VlpdsNodeRestarted](#vlpdsnoderestarted).

### VlpdsNodeCrashLooping

**Means:** 3+ restarts in an hour. Each restart moves its shards out and back,
which means ownership churn, cold repo loads and write resends.

**Causes:**
- Persistent store errors (exit 2/4).
- Renewals regularly over 0.4 x TTL (exit 5).
- Two processes with the same `--node-id` fencing each other. Exit 3 alternates,
  because each start fences the previous incarnation's log at join
  (`vlpds_peer_takeovers_total{reason="restart"}`).
- OOM (see [VlpdsMemoryCritical](#vlpdsmemorycritical)).
- A bad binary.

**Do:** stop the node (SIGTERM) and leave it down while you diagnose. Its shards
move to peers. Roll back the binary if the loop began with a deploy. Never "fix"
a crash loop by deleting objects.

### VlpdsPeerPresumedDead

**Means:** a node saw a peer miss a renewal and its address refuse TCP. The peer
process is gone, and takeover starts immediately (fence, CAS, replay).

**Confirm:** `peer missed a renewal and refuses connections` and `fenced dead
node's log` in the observer's logs, then the dead node's exit code.

**Do:** treat it like [VlpdsNodeRestarted](#vlpdsnoderestarted) for the dead peer.

### VlpdsMixedVersions

**Means:** more than one `rev` in `vlpds_build_info` for over an hour. Normal
for the minutes of a rolling deploy.

**Do:** finish or roll back the deploy ([Rolling upgrade](#rolling-upgrade-finalize-rollback)).
Mixed builds are safe while the cluster's feature level is one every node's
build can run, since they all write that level's formats. `vlpds admin
cluster status` shows each node's rev and level window. This is tested with two
real builds. The `upgrade-*` HA scenarios (rolling upgrade, rollback, old-node
refusal, raise race) pass, see `bench/ha/RESULTS.md` "Two-build upgrade
scenarios".

### VlpdsFormatErrors

**Means:** a node failed to decode something on an unknown or malformed format
marker (`vlpds_format_errors_total{format}`):
- `segment`: magic not in this build's levels, or an unknown codec.
- `log_stream`: a peer sent a message type this build doesn't know (skipped).
- `applied_marker`: a shard's `meta/applied2` doesn't decode, so the shard won't
  open.
- `cluster_version`: `cluster/version` is unreadable.

With levels working this never happens. A writer emits a format only once its
level is active, and only builds that can read it run.

**Confirm:** check the node's logs at that time (`bad segment magic`, `skipping a
log stream message of an unknown type`, `malformed applied marker`). Then run
`vlpds admin cluster status`. Is a node on a build whose `maxLevel` is above the
active level writing early (a bug), or is the object corrupt?

**Do:** if one build is at fault, stop the writer that emits it by rolling it
back (before finalize that's a plain redeploy). For corruption of a segment or
marker, treat it like [VlpdsShardOpenErrors](#vlpdsshardopenerrors). Never edit
`cluster/version` by hand.

### VlpdsIncompatibleNode

**Means:** the previous process on this node exited 7 `incompatible_level`. Its
build can't run the cluster's feature level (`cluster/version`), so it left
before reading or writing anything. A process looping on exit 7 never serves
`/metrics` (it stops before serving), so expect [VlpdsNodeDown](#vlpdsnodedown)
for it too. This alert shows once a good image runs there again.

**Confirm:** the node's log line `incompatible feature level: ...` names the
active level (and a raise `target`, if one was running) and its build's window.
`vlpds admin cluster status` shows `version.active`.

**Do:** deploy a build whose level window contains the active level (the current
release). After a finalize, an older image can never rejoin. That's intended,
since rollback after finalize is forward-fix only. If a raise in progress
(`target` set) made a starting node refuse, it finishes or aborts by itself
within seconds, so start the node again afterwards. A `target` that stays (the
finalizing node died between its steps, and `cluster status` keeps saying
"raising to N") is cleared by `vlpds admin cluster finalize --level
<active> --yes`.

### VlpdsFeatureLevelUnfinalized

**Means:** for 14 days every node has run a build that supports a higher feature
level than the cluster's active one. That's fine during a soak, but the upgrade
was never finished. The next release can't drop support for the old formats
while the window is open.

**Do:** if the build has soaked cleanly, finalize ([Rolling
upgrade](#rolling-upgrade-finalize-rollback) step 4). If not, decide whether
to roll back instead.

### VlpdsShardsUnowned

**Means:** for 2 minutes, scraped nodes own fewer shards than the layout has.
The layout's count is `vlpds:layout_shards` (the nodes' `vlpds_shard_layout_shards`,
or the last value seen in the past hour when none is up). Requests for repos in
those shards fail or wait for the 20 s resend window to run out. A normal
takeover takes seconds, and 2 minutes isn't normal.

**Causes:**
- A frozen (not dead) node. Its socket accepts, so takeover waits TTL + skew
  (12 s at the default TTL, 72 s at 60 s), then fence + replay. A long replay (see
  [VlpdsTakeoverReplaySlow](#vlpdstakeoverreplayslow)) stretches it.
- Survivors can't take shards. Control-plane calls time out
  ([VlpdsControlPlaneTimeouts](#vlpdscontrolplanetimeouts)), fence or assignment
  CAS fails, or SlateDB open fails ([VlpdsShardOpenErrors](#vlpdsshardopenerrors)).
- Commit-wait. The previous owner's clock was ahead, and a new owner waits up to
  30 s (`waited for our clock to pass`).
- A merge just lowered the count, and a node that was down during it reports its
  old layout from the past hour (only while no node is up).
- A node is up but not scraped. Its gauge is missing, but it still owns its
  shards.

**Confirm:** in `getClusterStatus`, look at `table` entries that are `null`,
`layout.op`, and each node's `owned` and `leaseValid`. On survivors, check the
logs (`acquired shards`, `shards opened` with `segments_replayed` and
`replayed_ms`, control-plane timeouts) and
`vlpds_shard_open_seconds{kind="replay"}` and `vlpds_shards_opened_total{result}`.

**Do:** fix the blocker (the store, or a frozen host). For a frozen host, kill the
frozen process so the refused probe kicks in. Don't edit `assign/` objects. If
all nodes are down, start them, and each takes its share at its first steps.

### VlpdsShardsOverOwned

**Means:** for 5 minutes, the nodes' `vlpds_owned_partitions` sum to more than
the layout's shard count (`vlpds:layout_shards`).

**Causes:** nodes disagreeing on the layout for that long, i.e. a split/merge
stuck mid-flip (`layout.op`, `vlpds_shard_layout_version` per node). Otherwise
it's a zombie, a node that still believes it owns shards it lost. Safety holds,
because its next segment PUT collides with the fence and it exits 3, and a step
that sees a reassigned shard exits 5. But a zombie whose monotonic clock was
paused (VM suspend) serves stale reads until then.

**Confirm:** compare `owned` lists across nodes in `getClusterStatus`. The same
shard on two nodes identifies the zombie. `vlpds admin layout` gives the count.

**Do:** for layout disagreement, see [Shard split / merge](#shard-split--merge).
For a zombie, SIGKILL it. It has nothing it may ack, and a successor already
fenced its log.

### VlpdsOwnershipFlapping

**Means:** more than 4 shard opens per shard in an hour. Every move costs a close
barrier + checkpoint, a fence or handoff, a SlateDB open, replay, and cold repo
loads on the new owner.

**Causes:** nodes restarting repeatedly (see [VlpdsNodeCrashLooping](#vlpdsnodecrashlooping)),
a node whose renewals keep lapsing (slow store or CPU starvation, see
[VlpdsRuntimeStalls](#vlpdsruntimestalls)), repeated deploys, or reshard activity
(`vlpds_reshard_events_total`).

**Confirm:** `sum by (instance) (increase(vlpds_lease_events_total[1h]))` by
`event`. Which node's `opened`/`closed` dominate? Check for restarts.

**Do:** stabilize the flapping node (stop it if needed). Don't lower the TTL to
"speed up" recovery. It shrinks the renewal ceiling and causes more fail-stops.

### VlpdsOwnershipImbalanced

**Means:** one node holds over 1.5x the fair share for 30 minutes.

**Causes:** a joiner hasn't been greeted or settled (handback only goes to peers
seen for the join grace or that confirmed the hello), the over-full node's
releases fail, or nodes are `draining`. A reshard in progress keeps parents in
place.

**Confirm:** `handing back extra shards` log lines on the full node, the joiner's
`nodes[]` entry (`reachable`/`leaseValid`), and `layout.op`.

**Do:** it usually resolves by itself. If not, a graceful restart (SIGTERM) of
the over-full node hands its shards out evenly.

### VlpdsShardOpenErrors

**Means:** shard opens failed on this node (`vlpds_shards_opened_total{result="error"}`).
That's the SlateDB open, the replay of previous owners' log spans, or the
post-replay flush. A failed shard is released (nothing was logged for it) and
the next step retries it, here or elsewhere.

**Confirm:** `open failed: ...; releasing` and `replay failed` log lines (shard,
error). Check [VlpdsObjectStoreRequestErrors](#vlpdsobjectstorerequesterrors) for
`log_segment` reads and [VlpdsObjectStoreErrors](#vlpdsobjectstoreerrors) for
shard state (SlateDB). Replay treats a hole inside a span as an error, so check
whether someone deleted log objects by hand.

**Do:** fix the store problem. Don't edit `assign/` or `log/` to "unstick" a
shard.

### VlpdsTakeoverReplaySlow

**Means:** a batch of shard opens that replayed a dead owner's log tail took over
20 s before serving (`vlpds_shard_open_seconds{kind="replay"}`). The replay step
alone is `vlpds_recovery_replay_seconds`, and its size is
`vlpds_recovery_replayed_segments_total`. Those shards were unavailable for that
long on top of the takeover delay.

**Causes:** the dead node hadn't checkpointed for a while
([VlpdsReplayBacklogHigh](#vlpdsreplaybackloghigh),
[VlpdsCheckpointsStalled](#vlpdscheckpointsstalled)), slow `log_segment` GETs
(`vlpds_object_store_request_seconds{component="log_segment"}`), or slow SlateDB
opens (store latency).

**Do:** fix checkpointing on the nodes and investigate store latency.

### VlpdsLeaseRenewalNearCeiling

**Means:** at least one lease renewal (one CAS PUT of `nodes/{node_id}`) took
over 0.2 x TTL in the last 5 minutes (`vlpds_lease_renew_ttl_ratio`). That's 2 s
at the default 10 s TTL and 12 s at 60 s. Validity ends TTL - skew (0.8 x TTL)
after a renewal's send time, and renewals go out every 0.2 x TTL, one at a time. A
round trip slower than that delays the next send until it returns, so round trips
over 0.4 x TTL lapse the lease and the node fail-stops (exit 5). Several nodes
at once means a store brownout that will stop the whole cluster past the ceiling.
Thresholds follow each node's `vlpds_lease_ttl_seconds`.

**Confirm:**
- `vlpds_lease_validity_seconds` (dips below ~0.6 x TTL), renew errors, and
  `vlpds_lease_renew_seconds` (absolute round trips).
- `vlpds_object_store_request_seconds{component="ctl_lease"}` and the other
  components on the same node, to tell node-side network from the store.
- Runtime stalls ([VlpdsRuntimeStalls](#vlpdsruntimestalls)). A starved runtime
  delays the renew task itself, and the store isn't at fault.

**Do:** for one node, look at its network path to the store and its CPU. For
many, follow the [Object-store outage](#object-store-outage) procedure. Don't
lower the TTL.

### VlpdsLeaseRenewalAtCeiling

**Means:** a renewal took over 0.4 x TTL (4 s at the default TTL, 24 s at 60 s),
which is past the ceiling. The node's validity gapped, so it stopped acking and
fail-stopped (exit 5) or is about to. `VlpdsNodeRestarted` /
`VlpdsNodeFailStopped` follow. On several nodes at once, the store is browning
out and the cluster is stopping.

**Do:** as [VlpdsLeaseRenewalNearCeiling](#vlpdsleaserenewalnearceiling), now.
For many nodes, go straight to [Object-store outage](#object-store-outage).

### VlpdsLeaseRenewalSlow

**Means:** renewal p99 over 0.1 x TTL for 10 minutes. Normal is one small PUT,
~25-50 ms on S3 and a few hundred ms on R2. It isn't dangerous yet, but the trend
toward the 0.4 x TTL ceiling is.

**Do:** as [VlpdsLeaseRenewalNearCeiling](#vlpdsleaserenewalnearceiling), without
the urgency.

### VlpdsLeaseRenewErrors

**Means:** renewals failed with a store error (`kind="error"`) or the HTTP
client's timeout (`kind="timeout"`) and will be retried at the next tick
(TTL / 5). Every failed renewal eats into the 0.8 x TTL validity, and four in a
row lapse it. `kind="conflict"` (someone rewrote our lease) and `kind="lapsed"`
(validity ended before a renewal) fail-stop at once and show up as restarts.

**Confirm:** `node lease renew error (will retry)` warnings with the error text,
and [VlpdsObjectStoreRequestErrors](#vlpdsobjectstorerequesterrors) for
`ctl_lease`. `transport error of kind Connect` on every client at once means the
host is out of ephemeral ports (`ss -s` shows thousands in TIME_WAIT). vlpds'
object-store clients bound their connections (see
[VlpdsObjectStorePermitsSaturated](#vlpdsobjectstorepermitssaturated)), so look
for another process on the host churning connections.

**Do:** check credentials, throttling, network and provider status.

### VlpdsLeaseValidityLow

**Means:** a scrape saw this node with under 0.4 x TTL of lease validity left
(`vlpds_lease_validity_seconds` against `vlpds_lease_ttl_seconds`). Normal is
0.6-0.8 x TTL, i.e. 6-8 s at the default TTL and 36-48 s at 60 s. Its renewals
were 0.2 x TTL or more overdue, so it came within 0.4 x TTL of a fail-stop. This
is sampled at scrape time, so short dips can be missed. The renewal histograms
are the complete record.

**Do:** as [VlpdsLeaseRenewalNearCeiling](#vlpdsleaserenewalnearceiling).

### VlpdsCommitLatencyHigh

**Means:** p99 enqueue -> durable + applied + acked over 500 ms for 10 minutes.
The design is ~40-50 ms p50 and ~150 ms p99 on S3 Standard.

**Confirm:** break it down with `vlpds_commit_stage_seconds{stage}`:
- `seal_wait`: queueing before the PUT (load, or too few PUT slots).
- `put`: the object store (see `vlpds_segment_put_seconds`, hedges).
- `apply_lock`: shard locks held by exports or checkpoints.
- `apply`: SlateDB (L0 stalls, backpressure).
- `ack`.

Check `vlpds_runtime_tick_late_seconds` for CPU starvation.

**Do:** store slow -> see [VlpdsSegmentPutLatencyHigh](#vlpdssegmentputlatencyhigh).
CPU -> add nodes or shed load. Apply slow -> [VlpdsSlateDbL0Stalls](#vlpdsslatedbl0stalls).

### VlpdsCommitLatencyCritical

**Means:** p99 over 2 s. Forwarded writes start failing at the 3 s deadline. If
the store is the cause, the node is within 2x of the 4 s renewal ceiling (at the
default 10 s TTL).

**Do:** as [VlpdsCommitLatencyHigh](#vlpdscommitlatencyhigh), urgently. If every
node is affected, assume an object-store brownout ([procedure](#object-store-outage)).

### VlpdsCommitLogStalled

**Means:** entries are queued for the sequencer, but no segment became durable in
2 minutes. Segment PUTs retry until they succeed (fail-stop policy), so a stall
means a store that keeps failing or hanging, or a wedged finalizer.

**Confirm:** `vlpds_segment_puts_inflight`, `vlpds_segment_put_attempts_total{result}`,
`vlpds_segment_put_hedges_total`, logs for PUT errors, and `leaseValid` (an
invalid lease stops PUTs, then the node exits 5).

**Do:** store problem -> [object-store outage](#object-store-outage). If a node
is wedged with a healthy store, SIGTERM it. If it doesn't exit within a minute,
SIGKILL it. A successor fences its log and replays everything it acked.

### VlpdsWatermarkLagHigh

**Means:** for 5 minutes, while it owns shards, the node's own log watermark
(every event <= it is durable) is over 2 s behind its clock. An idle log
advertises the clock, so lag means entries were assigned seqs but aren't durable.

**Do:** as [VlpdsCommitLatencyHigh](#vlpdscommitlatencyhigh). Every node's firehose
waits for this log, so expect [VlpdsFirehoseEmitDelayHigh](#vlpdsfirehoseemitdelayhigh) too.

### VlpdsSegmentPutLatencyHigh

**Means:** p99 log segment PUT (including hedges and retries) over 250 ms for 10
minutes. The design is ~25 ms, and a hedged duplicate PUT starts at 100 ms
(`--hedge-after-ms`).

**Causes:** object-store latency (a region/AZ issue, or throttling with S3 503
SlowDown), network saturation on the `log` HTTP pool, or oversized segments
(`vlpds_segment_bytes`).

**Confirm:** compare the `vlpds_object_store_bytes_total{client="log",dir="up"}`
rate with the NIC, and check `vlpds_segment_stall_seals_total`. SlateDB's latency
on the same store (`slatedb_object_store_request_duration_seconds`) tells the
store apart from the node.

**Do:** on the store side, check provider status and request rate per prefix.
On the node side, check the network. Don't raise `--max-segment-mb` to
compensate, because bigger PUTs are slower (DESIGN "Pipelined segment PUTs").

### VlpdsSegmentPutErrors

**Means:** segment PUT attempts are failing. `already_exists` doesn't count,
since that's a lost hedge race verified by content. Failed PUTs are retried and
acks wait. An unrecoverable failure of the upload task exits 2.

**Confirm:** node logs for the store error text, then
[VlpdsObjectStoreRequestErrors](#vlpdsobjectstorerequesterrors) (`log_segment`)
and [VlpdsObjectStoreErrors](#vlpdsobjectstoreerrors) (shard state) on the same
node (credentials, bucket policy, throttling).

**Do:** fix credentials, permissions or quotas. The code handles a `segment PUT
conflicted but no object is there; retrying` warning on its own.

### VlpdsWritesShed

**Means:** writes rejected with 503 `Overloaded` because more than
`--max-inflight-writes` (20,000) are in flight. This is admission control
working. Without it, a latency blip snowballs into connection storms.

**Do:** find why writes are slow (commit latency, cold loads) or add capacity.
Raising the limit only helps if the node has headroom.

### VlpdsPasswordHashingShed

**Means:** password checks and hashes on request paths (createSession,
createAccount, OAuth sign-in/sign-up, resetPassword, deleteAccount,
disableTotp) answered 503 `Overloaded` + `Retry-After: 1` (a 503 page for the
OAuth forms). Every Argon2 permit stayed busy for 2 s. There's one permit per
core, at most 16, and each hash takes ~20 ms of CPU and 19 MiB. Shedding keeps a
login flood from queueing without bound, and admin password changes still wait
their turn. The counter is `vlpds_argon2_shed_total`.

**Confirm:** `rate(vlpds_http_requests_total{method="com.atproto.server.createSession"}[5m])`
by status, `vlpds_rate_limited_total`, and host CPU. Rate limits are checked
before any hashing, so a flood from a few IPs or identifiers should show up as
429s instead of 503s.

**Do:** for a flood spread over many IPs, tighten the sign-in rate limits or
block upstream. For legitimate load, add cores (the permit count follows them, up
to 16) or nodes.

### VlpdsProxyAccountCapSustained

**Means:** proxied (AppView/service) requests for one account were refused with
429 `RateLimitExceeded` at 64 in flight on its owner node
(`vlpds_proxy_rejected_total{reason="account_cap"}`). A slot is held until the
response body is done, so a slow upstream or a client that stops reading holds
slots too. Bodies whose client stopped reading for 30 s are dropped and counted
in `vlpds_http_stalled_bodies_total` (proxied and forwarded responses).

**Confirm:** the access log for the account sending the requests, upstream
latency, and whether `vlpds_http_stalled_bodies_total` grows alongside.

**Do:** for a misbehaving client, rate limit it or take it down per policy. For
a slow upstream, follow the upstream's health. There's nothing to tune here.

### VlpdsMailNodeBudgetExhausted

**Means:** this node refused account mail (confirmation, update, reset, delete,
PLC operation, sign-in codes) because its `mail-node-hour` bucket is spent (200
per hour per node by default). You'll see
`vlpds_mail_suppressed_total{reason="node_limit"}` and the warning `mail not
sent: this node's mail budget (mail-node-hour) is spent`. Users get 429
`RateLimitExceeded` ("Too many emails sent to this account"). Password-reset
requests are answered OK but not mailed. Admin `sendEmail` is exempt. The budget
protects the sender's reputation from a flood that the per-recipient budget
doesn't catch (many accounts at once).

**Confirm:** `vlpds_mail_messages_total{result="sent"}` by `purpose` on the node
shows which kind is surging. Check the console's Rate limits tab (top consumers
of `mail-recipient-hour`, rejections by `mail:<purpose>` route) and
`vlpds_signups_total` for a signup wave.

**Do:** for a burst of real users (signups, a migration wave), raise
`mail-node-hour` `points` in the console's Rate limits tab (live, no restart).
The day's total stays capped by `mail-cluster-day`. For abuse (many fresh
accounts asking for mail), find the accounts in the top consumers and take them
down, or tighten the endpoint's buckets.

### VlpdsMailClusterBudgetExhausted

**Means:** the cluster's daily mail budget (`mail-cluster-day`, default
`--mail-daily-budget`, 900 per UTC day) is spent. Every node refuses account
mail until the day ends (00:00 UTC). You'll see
`vlpds_mail_suppressed_total{reason="cluster_limit"}` and the warning `mail not
sent: the cluster's mail budget (mail-cluster-day) is spent`. Users get the same
429 as for the node budget, password resets are answered OK but not mailed, and
admin `sendEmail` is exempt. The budget stands in for the mail provider's daily
quota, which is per provider account. Past that quota the provider rejects mail
anyway.

**Confirm:** `vlpds_mail_budget_remaining{window="day"}` at 0.
`vlpds_mail_messages_total{result="sent"}` by `purpose`, summed over nodes,
shows which kind used it up. Check `vlpds_signups_total` for a signup wave and
the console's Rate limits tab (the `mail-cluster-day` count, top consumers of
`mail-recipient-*`).

**Do:**
- Real users: if the provider's quota has room (a higher plan, or the budget was
  set low), raise `mail-cluster-day` `points` in the console (live). To keep it,
  set `--mail-daily-budget` / `vlpds_mail_daily_budget` and drop the console
  change. Never set it above the provider's quota. The provider then rejects the
  mail instead, after the token is minted.
- Abuse: as for VlpdsMailNodeBudgetExhausted.
- Resetting the day's count means deleting `{prefix}/budget/mail.json`. Only do
  that if the provider's own count was reset.

### VlpdsMailClusterBudgetLow

**Means:** under 20% of the day's `mail-cluster-day` budget is left
(`vlpds_mail_budget_remaining{window="day"}` against
`vlpds_mail_budget_limit`). At the current rate, mail may stop before 00:00 UTC.

**Confirm / Do:** as for VlpdsMailClusterBudgetExhausted, before it runs out.

### VlpdsMailBudgetUncounted

**Means:** a node mailed accounts without spending the cluster budget. Its bucket
object (`{prefix}/budget/mail.json`) couldn't be read or written within 5 s, or
stayed contended (`vlpds_mail_budget_errors_total`, warning `cluster mail budget
unavailable`). Mail goes out instead of being refused. Only `mail-node-hour`
bounds it meanwhile, so the provider's quota can be overrun.

**Confirm:** object-store errors and latency on the node
(`vlpds_cluster_store_timeouts_total`, the lease alerts), and the warning's error.

**Do:** fix the store path as for any store trouble. If it lasts and the quota
matters more than delivery, lower `mail-node-hour` until the store is back.

### VlpdsWriteInternalErrors

**Means:** writes failing with `internal` or `unavailable`. Other kinds such as
`invalid_swap`, `invalid` and `repo_not_found` are client errors.

**Confirm:** node logs around the errors, `vlpds_repo_loads_total{result="error"}`,
and store errors.

**Do:** follow the underlying cause. `unavailable` usually tracks shard moves or
loads (see [VlpdsWriteResendsSustained](#vlpdswriteresendssustained)).

### VlpdsHttp5xxHigh

**Means:** over 5% of locally served XRPC requests return 5xx (appview-proxied
calls excluded). Every 503 vlpds sends carries `Retry-After: 1`.

**Confirm:** `sum by (method, status) (rate(vlpds_http_requests_total{status=~"5.."}[5m]))`
shows which methods. A 503 on repo writes means shard moves, `Overloaded` or
`PartitionUnavailable`. A 500 means internal errors in the logs.

**Do:** follow the matching alert (ownership, commit latency, forwards, store).

### VlpdsForwardErrorsHigh

**Means:** over 5% of forwards to shard owners return 5xx. That includes an
unreachable owner, or one past its 3 s TTFB deadline (presumed frozen, and the
client gets 503 `PartitionUnavailable`).

**Causes:** an owner node that's frozen or overloaded, the network between nodes,
an owner that just died (until takeover), or `--advertise-url` not reachable from
peers.

**Confirm:** `vlpds_forward_seconds` p99, the target owner's commit latency and
runtime stalls, and `vlpds_http_client_connects_total{role="peer"}` climbing (it
should stay flat under steady load).

**Do:** fix the owner. A frozen owner should lose its shards after TTL + skew.

### VlpdsForwardLatencyHigh

**Means:** p99 forward to the owner's response head over 1 s (the deadline is
3 s).

**Do:** look at the owners' latency (commit, cold loads in
`vlpds_repo_load_seconds`, runtime) and the peer network.

### VlpdsWriteResendsSustained

**Means:** an entry node keeps resending writes. They were answered `RepoLoading`
(`reason="loading"`, the owner's worker didn't start them within 1 s, usually a
cold repo load) or `ShardMoved` (`moved`), or hit unreachable owners. Bursts for
seconds after a restart or handoff are expected, but 10 minutes isn't.

**Confirm:** `vlpds_read_retries_total` (queries are resent the same way),
`vlpds_writes_abandoned_total` on the owners, `vlpds_repos_loading`,
`vlpds_repo_load_seconds` p99, and `vlpds_lease_events_total` (moves).

**Do:**
- `loading`: cold loads are too slow (store latency, or a repo cache that's too
  small, see [VlpdsRepoCacheMissRateHigh](#vlpdsrepocachemissratehigh)).
- `moved`: ownership flapping.
- `unreachable`: an owner is down but still assigned.

### VlpdsFirehoseEmitDelayHigh

**Means:** p99 from seq assignment of a batch's oldest event to its emit is over
2 s. The merger emits only at the minimum watermark over every node log. So one
slow log, a slow peer stream or a large wall-clock offset between nodes delays
the firehose on every node.

**Confirm:** in `getClusterStatus` `firehose.sources[]`, find the log whose
`watermark` trails. Seqs are `unix_micros x 256 + writer`, so divide by 256 for
micros. Which node owns that log (`nodes[].log`)? Check its commit latency and
watermark lag, clock sync on all hosts (NTP/chrony offset), and
`vlpds_firehose_merge_queue_bytes`.

**Do:** fix the slow node or the clock sync.

### VlpdsFirehoseEmitDelayCritical

**Means:** p99 over 20 s. Relays and consumers will soon see minutes-old data.

**Do:** as above. If one node's log is the laggard and the node is unhealthy,
SIGTERM it. A graceful stop fences its own log, so followers drain it and drop it
as a source.

### VlpdsFirehoseStalled

**Means:** the cluster commits, but this node's merger emitted nothing for 5
minutes. The merge is held at some log's watermark.

**Causes:**
- A dead log that nobody fenced. Followers drain a log only up to a fence, and
  DESIGN notes that an unfenced log stalls every peer's firehose.
- A peer stream stuck while S3 catch-up fails.
- A node whose clock is far behind (its idle watermark advertises its clock).

**Confirm:** `firehose.minWatermark` and `sources[]` in `getClusterStatus`, then
the stuck log's lease (`nodes[]`) and `fencedLogs`.

**Do:** a dead node's log is fenced by the node that takes over its shards. If
there were none left to take, restart the dead node with the same `--node-id`,
which fences its previous log at join
(`vlpds_peer_takeovers_total{reason="restart"}`). Fix clocks. Restart the stalled
node as a last resort.

### VlpdsFirehoseConsumersTooSlow

**Means:** subscribers more than `--firehose-max-lag-mb` behind (default 128 MiB,
and the node's value is `vlpds_firehose_max_lag_bytes`) are cut off with
`ConsumerTooSlow` and resume from their cursor. Isolated cases are the consumer's
problem. A high rate across subscribers points at the server.

**Confirm:** `vlpds_firehose_subscribers`, the `vlpds_firehose_bytes_sent_total`
rate against the NIC, `vlpds_runtime_tick_late_seconds`, and `--firehose-threads`
(default 4) CPU. The console's Firehose page lists each subscriber's lag and the
recent disconnects with their reason.

**Do:** server-side, look at the network or the firehose threads. Consumer-side,
there's nothing to do.

### VlpdsFirehoseMergeSpilling

**Means:** a log exceeded the merger's queue budget while waiting for the minimum
watermark (`--firehose-merge-queue-mb`, default 256 MiB,
`vlpds_firehose_merge_queue_budget_bytes`). The merger now reads it back from S3
in chunks (`vlpds_firehose_merge_spill_segments_total`, extra GETs).

**Do:** find the laggard log as in [VlpdsFirehoseEmitDelayHigh](#vlpdsfirehoseemitdelayhigh).

### VlpdsPeerLogStreamLagging

**Means:** a peer following this node's log fell behind the 128 MiB live ring
(`--live-ring-mb`) and was dropped. It catches up from S3 segments.

**Do:** look at the follower node (CPU, network). Frequent drops raise S3 GETs
and firehose delay.

### VlpdsControlPlaneTimeouts

**Means:** control-plane object-store calls (`get`, `put`, `list`, `delete`,
`fence`, `fence-scan`) were abandoned at `min(TTL, 5 s)`, and the step retries
next tick. Lease renewals are separate. They're never timed out and aren't
counted here (they have their own metrics, `vlpds_lease_renew_seconds` and
`vlpds_lease_renew_errors_total`). But a store that takes 5 s for control-plane
calls is past the 0.4 x TTL renewal ceiling at the default TTL (4 s), so lease
lapses (exit 5) are likely next. At 60 s the ceiling is 24 s and there's more
room.

**Confirm:** logs (`control-plane <op> timed out`, `node lease renew error`),
`vlpds_object_store_request_seconds{component=~"ctl_.*"}` and SlateDB latency on
the same node, and `vlpds_object_store_requests_total{result="cancelled"}` (the
abandoned calls). Is it one node or many (see
[VlpdsObjectStoreBrownout](#vlpdsobjectstorebrownout))?

**Do:** single node -> its network path to the store. Many -> provider status.

### VlpdsObjectStoreBrownout

**Means:** in the same 5 minutes, two or more nodes are either timing out
control-plane calls or failing over 1/s of their object-store requests
(`vlpds_object_store_requests_total{result=~"error|timeout"}`, any component).
Those are the failures that [VlpdsObjectStoreErrors](#vlpdsobjectstoreerrors) and
[VlpdsObjectStoreRequestErrors](#vlpdsobjectstorerequesterrors) count on one
node. Per DESIGN, a cluster-wide brownout past the 0.4 x TTL renewal ceiling (4 s
at the default TTL) stops every node.

**Confirm:** `sum by (instance, component, result) (rate(vlpds_object_store_requests_total{result=~"error|timeout"}[5m]))`
and `sum by (instance, op) (increase(vlpds_cluster_store_timeouts_total[5m]))`
across nodes, and the store provider's status page.

**Do:** follow the [Object-store outage](#object-store-outage) procedure.

### VlpdsObjectStoreRequestErrors

**Means:** for 5 minutes, over 1/s of this node's own object-store requests
failed (`result` `error` or `timeout`) on one key component outside shard state.
They're counted at the bottom of vlpds' store clients (`vlsync-store/src/objstats.rs`). The
components are the control plane (`ctl_lease`, `ctl_assign`, `ctl_writer`,
`ctl_version`), `log_segment` (segment PUTs, fences, replay, firehose backfill
and follower catch-up), `retention_report`, `account_index` and `blob`. Shard
state (`state_*`, SlateDB's requests) is
[VlpdsObjectStoreErrors](#vlpdsobjectstoreerrors), with the same counter and
threshold. `not_found` and `precondition` (a lost CAS / create race) are normal
answers. `cancelled` is a caller that gave up (a control-plane deadline, a lost
hedge).

**Confirm:** `sum by (component, op, result) (rate(vlpds_object_store_requests_total{instance="..."}[5m]))`
and the matching warn/error log lines.

**Do:** check credentials, permissions, throttling (S3 503 SlowDown) and provider
status.

### VlpdsObjectStoreThrottled

**Means:** for 10 minutes, over 0.05/s of this node's object-store answers were
429 Too Many Requests or 503 SlowDown on one key kind
(`vlpds_object_store_throttled_total{kind}`). object_store retries both inside
its client, so they're counted at the HTTP layer (`vlsync-store/src/throttle.rs`), one per
answer. A 503 without SlowDown is an outage and isn't counted here. `lease` is
the control plane (node leases, assignments, writer claims, the cluster
version), by key for single-object requests and by `prefix=` for LISTs. A bulk
delete names its keys only in its body, so it counts as `other`. `segment` and
`other` are account-wide request rates.

R2 takes about one write a second to one key. A node's writes to its own lease
retry a throttled answer from min(1 s, renew interval), then up to 4 s apart.
Assignment and writer-claim CASes keep object_store's 100 ms start, since they
run under the step's 5 s call deadline and the next step retries them. A renewal
earns validity from its first send, so at the 10 s TTL it survives about 3
throttled answers (6-7 with the 100 ms start). Past that the node fail-stops
as for any slow renewal.

A node also keeps its own lease writes at least min(1 s, renew interval) apart.
A renewal right after a write that landed is skipped, and one carrying a new
`joined` or `draining` flag waits out the gap (under the renew lock), so peers
can see either flag up to 1 s late. That costs liveness only. When the validity
left is short, the renewal goes at once, throttled or not.

**Confirm:** `sum by (kind) (rate(vlpds_object_store_throttled_total{instance="..."}[5m]))`,
`vlpds_lease_renew_seconds` against the 0.4 x TTL ceiling, and the provider's
rate-limit docs and dashboard.

**Do:** on `lease`, look for something else writing the same keys (another
cluster or a tool on the same `--prefix`) or a node restarting in a loop. Don't
lower `--lease-ttl-ms` (renewals get more frequent). On `segment` or `other`,
the bucket is past the provider's request rate: spread the load or ask for a
higher limit.

### VlpdsObjectStorePermitsSaturated

**Means:** for 10 minutes, over 1/s of this node's object-store requests found
every in-flight permit of their client taken and queued
(`vlpds_object_store_permit_waits_total{client,lane}`). Each client (`log`,
`state`, `ctl`) bounds its requests in flight and keeps as many connections
pooled (DESIGN.md §7, "Object-store clients"). So a burst (a takeover's shard
opens, replay and cold loads) queues instead of opening a connection per request.
Without the bound, that once took every ephemeral port on a host, failed the
lease renewals and fail-stopped the survivors of a kill -9. Brief waits during a
takeover are expected. Sustained ones mean the pool is too small for the load,
or the store got slower (so permits are held longer).

**Confirm:**
- `vlpds_object_store_inflight` against `vlpds_object_store_inflight_limit` by
  `client` and `lane`. Pinned at the limit means saturated.
- `vlpds_object_store_permit_wait_seconds` p99.
- Whether `vlpds_object_store_request_seconds` rose at the same time
  ([VlpdsObjectStoreLatencyHigh](#vlpdsobjectstorelatencyhigh)). If it did, the
  store is slow and more permits won't help.
- On the host, `ss -tn dst <store addr> | wc -l` for the store connections and
  `ss -s` for TIME_WAIT. With the bound, connections stay at or under the permits
  and TIME_WAIT stays flat.

**Do:**
- `state` main lane at its limit while the store is healthy: raise
  `--store-inflight` (default 1,024). For the `log` main lane, raise
  `--log-store-inflight` (default 256). A node holds at most about the sum of its
  permits in connections, so keep (nodes per host x permits) well under the
  ephemeral port range (`net.ipv4.ip_local_port_range`, 28k ports by default).
- `log` reserved lane (segment PUTs): its size is max(64, 4 x `--log-inflight`).
  Waits there mean PUTs are slow, see
  [VlpdsSegmentPutLatencyHigh](#vlpdssegmentputlatencyhigh).
- `ctl` reserved lane (lease renewals, 8 permits): renewals stuck behind each
  other mean the store isn't answering lease PUTs. Treat it as
  [VlpdsLeaseRenewalSlow](#vlpdsleaserenewalslow).

### VlpdsControlPlaneLatencyHigh

**Means:** p99 of control-plane object-store requests (`ctl_*` components, i.e.
leases, assignments and writer claims) over 1 s for 10 minutes. It's normally
tens of ms. Every takeover step is a few of these in sequence, and the lease
renewal is one, so past 0.4 x TTL nodes fail-stop.

**Confirm:** `vlpds_object_store_request_seconds` by `component` and `op` on the
node, [VlpdsLeaseRenewalSlow](#vlpdsleaserenewalslow), and the same on other
nodes.

**Do:** as [VlpdsControlPlaneTimeouts](#vlpdscontrolplanetimeouts).

### VlpdsObjectStoreErrors

**Means:** for 5 minutes, over 1/s of this node's shard-state object-store
requests failed (`result` `error` or `timeout`) on one `state_*` component
(`state_wal`, `state_manifest`, `state_sst`, `state_compactions`,
`state_gc_boundary`, `state_other`). Shard state is SlateDB's traffic (WAL,
memtable flushes, manifests, SST reads, compaction, GC). vlpds counts it under
SlateDB (`vlpds_object_store_requests_total`, `vlsync-store/src/objstats.rs`), like
[VlpdsObjectStoreRequestErrors](#vlpdsobjectstorerequesterrors) does for every
other component. SlateDB retries, and a persistent apply failure exits 4.

This alert doesn't use SlateDB's own `slatedb_object_store_error_count_total`.
That counter counts every call that didn't succeed, including the not-found GETs
of normal traffic (each node's compactors poll for manifests and compactions
about 12 times a second) and lost CAS races, and it has no label to tell them
apart. A steady rate there isn't trouble by itself. It's only useful next to
this one.

**Confirm:** `sum by (component, op, result) (rate(vlpds_object_store_requests_total{instance="...",component=~"state_.*",result!="ok"}[5m]))`
and logs. Failures only on `state_compactions` / `state_gc_boundary`
(compaction, GC) don't affect acks directly, but they let L0 grow.

**Do:** check credentials, permissions, throttling and provider status.

### VlpdsObjectStoreLatencyHigh

**Means:** SlateDB's store p99 over 1 s. It hurts cold repo loads, checkpoints
(normally ~37 ms each) and apply.

**Do:** as [VlpdsSegmentPutLatencyHigh](#vlpdssegmentputlatencyhigh). Check that
the local SST disk cache (`--cache-dir`) is set and healthy (hit rates in
`slatedb_db_cache_access_count_total`).

### VlpdsSlateDbL0Stalls

**Means:** SlateDB blocked writes because a shard has too many L0 SSTs, so
compaction is behind. Segment apply (and so acks) waits.

**Confirm:** `slatedb_db_l0_sst_count`, `vlpds_compaction_poll_switches_total`,
failed shard-state requests in
`vlpds_object_store_requests_total{component=~"state_.*",result=~"error|timeout"}`
([VlpdsObjectStoreErrors](#vlpdsobjectstoreerrors), and note that SlateDB's
`slatedb_object_store_error_count_total{component="compactor"}` also counts its
normal not-found polls), and `vlpds_commit_stage_seconds{stage="apply"}`.

**Do:** fix store errors or latency, and check CPU for the compactor.
`--compaction-polling` is `adaptive` by default (500 ms polls only while a shard's
L0 runs deep), and switching to `fast` may help.

### VlpdsSstMetaCacheTooSmall

**Means:** the bloom filters + indexes of every SST in this node's shards are
over 90% of its metadata cache (`vlpds_meta_cache_capacity_bytes`). Their size is
`vlpds_sst_meta_need_bytes`, the encoded `vlpds_sst_meta_bytes` x the measured
decode ratio (`vlpds_sst_meta_decode_ratio`, ~1.3). By default the node sizes
that cache itself from its memory budget (src/memory.rs). It takes the need x
N/(N-1) for N live nodes x 1.25, first out of the cache pool. So this alert means
the pool can't fit it (`vlpds_meta_cache_shortfall_bytes` > 0, logged at error
when it starts), or `--meta-cache-mb` pins it too small.

Each point read checks a filter per sorted run of its shard, so under uniform
keys (bulk imports, random repo loads) the whole set is hot. Past the cache,
reads that miss fetch a whole filter or index (MBs for a big compacted SST), and
the node's own reads can saturate the store. The 100M capacity run
(bench/results/benchbox-2026-10-02-round2, block 6) pulled 1-2.4 GB/s of SST GETs
per node for 10 MB/s of writes, and lease renewals then lapsed (see
[Store saturated by the node's own reads](#store-saturated-by-the-nodes-own-reads)).
It's about 29 MB decoded per million accounts at the capacity test's records
distribution. 100M accounts on 4 nodes is ~0.72 GB per node, or ~0.96 GB with one
node down.

**Do:** give the node more memory (container limit, or `--memory-budget-mb`), or
add nodes. With an explicit `--meta-cache-mb`, raise it (restart) to at least
1.25x the footprint the node would hold after losing a peer (its share x N /
(N - 1)), or drop it to let the node size it. The budget's breakdown is in
`vlpds_memory_budget_bytes{part}` and `vlpds --memory-plan`. Check
`VlpdsSstMetaRefetching` to see whether it bites yet.

### VlpdsSstMetaRefetching

**Means:** for 10 minutes the node fetched over 20 SST filters/indexes per second
from the store (`vlpds_meta_cache_loads_total{result="fetched"}`).
`result="shared"` counts reads that waited on another read's fetch of the same
entry. Flushes and compactions put their SSTs' metadata in the cache, so steady
state is near 0. Shard opens and takeovers fetch theirs once.

**Confirm:** `vlpds_sst_meta_bytes` against `vlpds_meta_cache_bytes` /
`vlpds_meta_cache_capacity_bytes`, and
`vlpds_object_store_bytes_total{dir="down",component="state_sst"}` (MB/s of SST
reads) against `dir="up"`.

**Do:** as [VlpdsSstMetaCacheTooSmall](#vlpdssstmetacachetoosmall).

### VlpdsCheckpointsStalled

**Means:** the node writes segments but hasn't checkpointed any shard for 10
minutes. A checkpoint is an applied marker + memtable flush, one shard every
`interval/shards`. Checkpoints bound a successor's replay and let retention
delete the log.

**Confirm:** logs for flush/write errors, `vlpds_checkpoint_shard_seconds`, and
`vlpds_retention_replay_hold_segments` growing.

**Do:** fix store errors. A node that can't checkpoint will cost a long replay
on takeover. Consider a graceful restart once the store is healthy, since a
graceful close checkpoints every shard and the successor replays nothing.

### VlpdsReplayBacklogHigh

**Means:** this node keeps over ~15 minutes of its log only because a crash
replay could need it (`vlpds_retention_replay_hold_segments`, divided by the
segment rate). A takeover would replay about that much before serving those
shards. For past takeovers' replay, see `vlpds_recovery_replayed_segments_total`,
`vlpds_recovery_replay_seconds` and `vlpds_shard_open_seconds{kind="replay"}` on
the nodes that took over.

**Do:** as [VlpdsCheckpointsStalled](#vlpdscheckpointsstalled).

### VlpdsRetentionFailing

**Means:** most retention passes in the last hour failed (`log retention pass
failed`). Logs stop shrinking, so storage and LIST cost grow. Nothing is lost.

**Do:** read the error. It's usually store permissions (DELETE) or throttling.
Never delete log objects by hand to compensate.

### VlpdsRetentionNotRunning

**Means:** no pass (ok or error) for 15 minutes on a scraped node. A pass runs
every `--log-retention-interval` (default 60 s). A pass that hangs on a store
call would look like this. Retention sets no deadline of its own, so each call only
has the store client's 30 s request timeout and its retries.
`vlpds_retention_pass_seconds` shows how long the finished passes took, and a
creeping p99 comes before a hang. For the store side, see
`vlpds_object_store_requests_total{result="cancelled"}` and request latency for
`log_segment` and `retention_report`.

**Do:** check the logs. Restart the node gracefully if the task is wedged.

### VlpdsDeadLogUnfenced

**Means:** for 30 minutes, the dead-log pruner (the owner of slot 0's shard) has
seen a log with no live writer that nobody fenced
(`vlpds_retention_dead_logs{state="unfenced"}`). Followers drain a log only up to
its fence. So an unfenced dead log holds every node's merged firehose at its
watermark, and retention never prunes it (`vlpds_retention_dead_log_segments`
counts what dead logs still hold).

**Causes:** its node died owning no shards (nobody takes over, so nobody
fences), or its shards' takeover keeps failing
([VlpdsShardOpenErrors](#vlpdsshardopenerrors), control-plane errors).

**Confirm:** `fencedLogs` and `firehose.sources[]` in `getClusterStatus`. The
log id in `log/` (`<node-id>.<micros>`) names the node.

**Do:** restart that node id (startup fences its previous incarnation's log) or
fix the failing takeover. Never write a fence object by hand.

### VlpdsReshardGcFailing

**Means:** most retired-state GC passes failed in the last hour (`reshard GC pass
failed`, on the owner of slot 0's shard). Split/merge parents' state dirs
(`state/{id}/`) and their `assign/` records stop going away. Storage grows with
each op, and so does the `assign/` LIST every step makes. Nothing is lost.

**Causes:** store permissions (DELETE) or throttling, the node's lease not being
valid (`node lease not valid: no deletes`, a node about to fail-stop), or a dir
SlateDB refuses to delete.

**Do:** read the error. The next pass finishes a dir that a failed pass
half-deleted (SlateDB's `.deleting` marker). Never delete `state/` objects by
hand, because a live shard may read a retired dir's SSTs (DESIGN.md "Retired
state GC").

### VlpdsRetiredStateReferenced

**Means:** a retired shard's dir holds no checkpoint, yet some shard's manifest
lists SSTs in it (`vlpds_reshard_gc_retired_dirs{state="referenced"}`). Every
clone pins what it reads with a checkpoint, so a SlateDB invariant is broken (a
bug, or hand edits). The GC keeps the dir, so nothing is lost now. A later fix
that deletes the reference would let it go.

**Confirm:** the log line `retired state dir holds no checkpoint but a manifest
lists its SSTs` names the shard. The `slatedb` admin `read_manifest` on each live
shard shows which one lists it in `external_dbs`.

**Do:** keep the dir and file a bug with both manifests.

### VlpdsRetiredStateGrowing

**Means:** more retired state dirs than live shards for 6 hours
(`vlpds_reshard_gc_retired_dirs{state="total"}`). Dirs normally go within the
grace (`--reshard-gc-grace`, 1 h) after the shards that read them detached.

**Look at:** `vlpds_reshard_gc_retired_dirs` by state on the GC leader:
- `checkpoint`: a clone still reads it (see `vlpds_shards_with_inherited_ssts`
  per node and [VlpdsForcedDetachFailing](#vlpdsforceddetachfailing)), or a
  reader or backup holds a named checkpoint.
- `grace`.
- `other`: no manifest without a delete marker, or an assignment with an owner
  (log `a shard out of the layout has an owner`).

A reshard op left pending blocks the dir half entirely (`getClusterStatus`
layout `op`). Abort or finish it.

**Do:** fix the cause. GC catches up by itself (8 dirs per pass).

### VlpdsForcedDetachFailing

**Means:** this node's forced detach compactions keep failing SlateDB's
validation, and none completed for 2 hours. A shard still reading SSTs of a
split/merge parent gets one `--forced-detach-after` after it opened. Occasional
failures are normal (the shard's own compaction took a source first, and it's
resubmitted next pass). The parents stay pinned, so their dirs stay.

**Look at:** `slatedb::compactor` `compaction validation failed` lines for the
shard, `vlpds_shards_with_inherited_ssts`, and L0 depth (no forced compaction is
submitted while L0 runs deep).

**Do:** usually nothing. A shard under steady ingest compacts its L0 itself and
the next submission lands. If one shard never detaches, a graceful restart of
the node hands it to a peer that starts over.

### VlpdsMemoryHigh

**Means:** RSS over 85% of `vlpds_memory_limit_bytes` for 10 minutes. That's
physical RAM, or the cgroup limit when lower, as the node reads it. A node that
can't read either exports no limit, and these alerts stay silent.

**Confirm:**
- `vlpds_jemalloc_bytes{stat}` (allocated vs resident vs retained).
- `vlpds_memory_budget_bytes{part}`, the node's plan (fixed costs and the cache
  pool, sized from the limit, see `vlpds --memory-plan`).
- `vlpds_memory_cache_bytes{cache,kind}` (the pool's SST metadata, SST block and
  repo caches).
- `sum by (instance) (vlpds_repo_cache_bytes)` (loaded MST paths) against
  `vlpds_repo_cache_capacity_bytes`.
- The `mst_store` node cache (`--lazy-mst-node-cache-mb`, 256 MiB),
  `vlpds_cache_bytes` (`--cache-budget-mb`, default 10% of the budget),
  `vlpds_firehose_ring_bytes`, `vlpds_log_live_ring_bytes`,
  `vlpds_firehose_merge_queue_bytes` and `slatedb_db_total_mem_size_bytes`.

The caches stay within the plan, so RSS past it is usually allocator retention
(`vlpds_jemalloc_bytes`), memtables, or bodies in flight.

**Do:** lower the budget (`--memory-budget-mb`, e.g. 80%) or the fixed costs that
dominate, or move to a bigger box.

### VlpdsMemoryCritical

**Means:** RSS over 95%, so an OOM kill is close. An OOM kill is a crash. Peers
take over in 3-5 s (refused probe) and replay, and nothing acked is lost.

**Do:** a graceful restart (SIGTERM) now is cheaper than the OOM, since it hands
off without replay. Then fix it as in [VlpdsMemoryHigh](#vlpdsmemoryhigh).

### VlpdsRepoCacheMissRateHigh

**Means:** for 30 minutes, over 20% of repo lookups for queued requests start a
cold load (head + account reads, `M/` prefetch, MST root and paths).

**Confirm:** the `vlpds_repo_evictions_total` rate, `vlpds_repo_cache_bytes` near
`--repo-cache-mb`/workers, `vlpds_cached_repos` near `--cache-per-worker`
(50,000), ownership churn (each move empties the cache for those shards), and
`vlpds_lazy_mst_fallbacks_total` (opens rebuilt from all records, which are
slow).

**Do:** raise `--repo-cache-mb` / `--cache-per-worker` if memory allows, and stop
the churn.

### VlpdsRepoLoadErrors

**Means:** cold repo loads fail (`result="error"`, while `not_found` and `stale`
aren't errors). Requests for those repos fail.

**Do:** check the logs for the repo, shard and error, and check store errors on
the node.

### VlpdsLazyMstInvalid

**Means:** a repo's persisted MST node (or rebuilt subtree) didn't match its
link, so the repo was rebuilt from its records (correct result, slower). That
means the derived state was inconsistent, and it shouldn't happen.

**Do:** capture the log lines (repo DID, shard) and file a bug. There's no
operator action on data.

### VlpdsKeyServiceUnavailable

**Means:** calls to the KEK's key service (Cloud KMS or Vault Transit) fail or time out
(`vlpds_kms_requests_total{result="unavailable"}`). The `key service unavailable`
warn log names the key and the error. Accounts whose signing key is cached keep
writing. Cold accounts (first write since the node started or took the shard)
get 503 `KeyUnavailable`, and nothing is written. createAccount,
reserveSigningKey, setupTotp and TOTP logins fail with 503. Reads, exports, the
firehose and the proxy for warm accounts are unaffected.

**Do:** follow [Key service (KMS) outage](#key-service-kms-outage).

### VlpdsSecretUnwrapRejected

**Means:** a wrapped secret failed authentication under its KEK. That's a KEK
file with the right id but other bytes, a Cloud KMS key that rejects the
ciphertext, a Vault Transit 400 (a version below `min_decryption_version`, a
ciphertext of another key), or a corrupt row. That account's writes fail with 500. A blob under a
KEK the node doesn't have at all fails the same way but only logs (`wrapped under
unknown key-encryption key L…/G…/V…`). That's usually an old KEK retired before the
rewrap finished.

**Do:** find the DID in the `secret unwrap failed` / `repo load failed` logs. If
the kid is unknown, add the old KEK back (`--kek-old-file` / `--gcp-kms-old-key` /
`--vault-transit-old-key`)
on every node and rerun the rewrap ([KEK rotation](#kek-rotation)). Otherwise,
compare the node's KEK config with its peers'. Never "fix" a row by hand.

### VlpdsPlcDirectoryUnavailable

**Means:** writes to the PLC directory (`--plc-url`) fail as unavailable
(`vlpds_plc_requests_total{result="unavailable"}`, which covers 5xx, 429,
timeouts and connection errors). The `PLC directory request failed` warn log has
the DID, op and error.
- New accounts' DIDs are registered before the account exists, so createAccount
  (and OAuth sign-up) fails with 500 and leaves nothing behind (the handle and
  email are free again).
- updateHandle, admin updateAccountHandle and updateAccountSigningKey fail the
  same way with no local change.
- signPlcOperation can't read the last op, and submitPlcOperation can't forward.

Everything else (logins, writes, reads, firehose, sync) is unaffected, because
existing DIDs resolve from the directory's own replicas.

**Do:** follow [PLC directory outage](#plc-directory-outage).

### VlpdsPlcOpsRejected

**Means:** the directory refused (4xx) an op this server built and signed (`op`
label). The usual causes:
- The DID no longer lists this server's rotation key. The account migrated away,
  or a user removed the key and the account wasn't told (`update_handle` /
  `update_signing_key`).
- A rotation key the directory doesn't accept.
- A bug in op construction (`create`, where every signup fails).

The directory's message is in the warn log and in the 500 the client got.

**Do:**
- For `create`, treat it as an incident, since no one can sign up. Check the log
  message (`Invalid signature`, `Operation too large`, ...), the node's `PLC
  registration on` startup line (rotation key did:key), and whether a deploy
  changed op construction. If it did, roll back.
- For updates of single DIDs, fetch `$PLC/{did}/log/last`. If its `rotationKeys`
  lack this server's key (current or retired), this server can't update the
  account anymore. Tell the user, since they hold the remaining rotation keys.
- For `rotate_key`, the DID's last op was signed after this server read it.
  Retry `rotatePlcKeys`.

### VlpdsSignatureFault

Also covers VlpdsSignatureFaultFailStop (the previous process exited with code
6, `signature_fault`).

**Means:** a signature failed verification against the key's own public key
right after it was made (`vlpds_signature_verify_failures_total{purpose}`, with
purposes `commit`, `service_auth`, `oauth_token` and `plc_operation`, plus
`key_load` when a cached signing key's scalar no longer derives its public key).
Correct code never does this. The CPU or memory of this host computed something
wrong (bad DIMM, Rowhammer, overheating, failing CPU). The bad signature wasn't
emitted. The node signed once more with a fresh nonce, and if that failed too
the write got a 503 `SignatureFault` with nothing applied. Nonces are hedged, so
a faulty signature leaks nothing even if one had got out, but the host isn't
trustworthy anymore. Three failures within a minute fail-stop the node (exit 6).
The supervisor restarts it on the same host, so expect it to recur.

**Confirm:** `signature failed verification against the signing key's public
key` error logs (`purpose`, `recent`) and
`vlpds_last_exit_reason_info{reason="signature_fault"}`. On the host, check
`journalctl -k | grep -iE 'mce|edac|machine check|hardware error'`,
`edac-util -v` (or `/sys/devices/system/edac/mc/mc*/ce_count`/`ue_count`),
`rasdaemon`/`ras-mc-ctl --summary` if installed, CPU temperatures, and the
cloud provider's host-maintenance or hardware-degradation events.

**Do:**
1. Drain the host now, even after a single fault. Stop vlpds there gracefully
   (`SIGTERM`, and peers take its shards over) and keep the supervisor from
   restarting it on that host.
2. Check ECC/EDAC and machine-check logs as above. Climbing corrected-error
   counts, any uncorrected error, or MCEs mean a hardware fault.
3. Replace the host before it serves again. On a cloud, stop/start it onto new
   hardware or recreate the VM. On bare metal, pull it and run memtest86+ / the
   vendor diagnostics. Don't return it on the strength of a clean restart.
4. There's nothing to repair in data. No faulty signature was sequenced, and the
   failed writes were refused with a retryable 503.
5. Faults on several hosts at once point at a software or build problem instead
   of hardware. Compare the vlpds versions (VlpdsMixedVersions) and escalate to
   development.

### VlpdsCacheAtCapacity

**Means:** a bounded in-memory cache (`session_tokens`, `oauth_tokens`,
`proxy_accounts`, `proxy_jwts`, `did_docs`, `lexicons`, `oauth_clients`,
`permission_sets`, `security_controls`, `signing_keys`, `recent_writes`) has
been at its entry cap for 6 hours. A full LRU is normal for hot caches. It only
matters with symptoms (proxy latency, PLC lookups, KMS calls).
`vlpds_proxy_cache_total{result}` gives a hit ratio for the proxy fast path, and
`vlpds_signing_key_cache_total{result}` does the same for unwrapped signing keys.
A full `signing_keys` cache with many misses means KMS unwraps on cold writes.
The others have no hit/miss metric.

**Do:** if a symptom correlates, raise `--cache-budget-mb` or set
`--cache-entries <cache>=<n>`.

### VlpdsFirehoseMergeQueueNearBudget

**Means:** the merger holds over 80% of its byte budget while waiting for the
minimum watermark (`--firehose-merge-queue-mb`, default 256 MiB, exported as
`vlpds_firehose_merge_queue_budget_bytes`). Past the budget it spills (see
[VlpdsFirehoseMergeSpilling](#vlpdsfirehosemergespilling)).

**Do:** find the laggard log (same as emit delay).

### VlpdsRuntimeStalls

**Means:** the 10 ms ticker on the tokio runtime was late over 5% of the time,
so runtime threads are blocked or starved. Lease renewals, step loops and acks
run on it, so heavy stalls risk lease lapses.

**Confirm:** `tokio runtime stall` logs (late_ms), host CPU and load, and a CPU
profile (`just profile`, on a `--features profiling` build).

**Do:** reduce co-located load, add CPU, or profile for blocking work on the
runtime.

### VlpdsRuntimeSaturated

**Means:** tokio workers over 90% busy for 15 minutes, so the node is CPU bound
(DESIGN: ~12k commits/s per core including HTTP).

**Do:** add nodes (shards rebalance automatically) or use bigger instances.

### VlpdsPeerTlsCertExpiring

**Means:** `vlpds_peer_tls_cert_expiry_seconds{cert}` (notAfter, Unix seconds)
is under 14 days away. `cert="node"` is this node's certificate, and `cert="ca"`
is the earliest-expiring CA in `ca.crt` (`--peer-tls-dir`). Once a node cert
expires, every peer refuses it. Forwards to and from it fail, and its log stream
stalls every peer's firehose. The node won't start or reload with it either.

**Do:** [renew the node certificate](#peer-tls-mtls-between-nodes) (`cert="node"`)
or rotate the CA (`cert="ca"`). `vlpds admin tls show <cert>` prints what a file
holds.

### VlpdsPeerTlsReloadFailing

**Means:** the peer TLS files changed (or the node got SIGHUP), but the new set
didn't load. A file may be unreadable, the cert may not chain to the CA file, be
expired or name another node (`vlpds://node/<id>` must be this `--node-id`), or
the key may not match. The node keeps using the previous set.

**Confirm:** the `peer TLS reload failed` error log says which.

**Do:** fix the files. A half-copied set reloads on the next 60 s poll or
`kill -HUP`. Run `vlpds admin tls show` on the cert.

### VlpdsPeerTlsHandshakeFailures

**Means:** peer TLS handshakes keep failing. `side="server"` means callers of
this node's `--peer-listen` were refused (no client certificate, one from another
CA, expired, or a handshake timeout, and port scans show up here too).
`side="client"` means this node refused a peer's server certificate (another CA,
the advertise host not in its SANs, or a node id other than the one the lease at
that address names).

**Confirm:** the `peer TLS handshake failed` (server) / `refused the peer's
certificate` (client) warn logs name the address and reason.

**Do:** compare `vlpds admin tls show` of each node's cert with its `--node-id`
and `--advertise-url` host, and compare their `ca.crt` files. All nodes must
trust the CA every node's cert comes from (both CAs, mid CA rotation).

### VlpdsScheduledDeletionFailing

**Means:** at least 3 of a node's scheduled-deletion sweeps (every 10 min) in
the last hour failed, for an hour. A sweep deletes the deactivated accounts on
the node's shards whose `deleteAfter` and minimum hold have passed. It fails
when a shard's `D/` scan fails, or when an account's deletion does
(`vlpds_scheduled_deletion_accounts_total{result="failed"}`). The account is
kept and retried every sweep, so a lasting failure is usually one account.

**Confirm:** the node's warnings `scheduled deletion failed (retried next
sweep)` (with the DID and error) or `scheduled deletions: scan failed` (with
the shard). The internals dashboard's Accounts row shows the sweeps by result.

**Do:**
- Store errors or timeouts in the error: fix the store path as for any store
  trouble. The sweep catches up by itself.
- `account row unreadable`: the account row doesn't decode. Look at it with
  `vlpds admin account info DID`. Deleting it by hand
  (`com.atproto.admin.deleteAccount`) deletes it fully, and the next sweep
  drops its `D/` row.
- An error that names the account's private rows or handle: a deletion that
  stopped partway. `com.atproto.admin.deleteAccount` for the DID finishes it.
- To stop the sweep while you look, set `--delete-after false` (rolling
  restart). Scheduled accounts then stay deactivated.

### VlpdsScheduledDeletionsSurge

**Means:** over 50 more accounts (and over 0.1% of all accounts) have a
`deleteAfter` than a day ago
(`vlpds_scheduled_deletion_accounts{state="scheduled"}`, summed over nodes as of
their last sweep). `deactivateAccount` takes `deleteAfter` from the account's
own session, including an OAuth app holding `account:status?action=manage`, so
a wave like this is either many users leaving at once or one app deactivating
the accounts it holds. They're deleted only once
`--delete-after-min-hold-days` (3) have passed since deactivation, so there is
time.

**Confirm:** `vlpds_account_events_total{event="deactivated"}` jumps at the same
time. Sample a few accounts in the console (`deletionScheduledAt`) and their
recent OAuth sessions and sign-ins. One client in common points at that app.

**Do:**
- Users leaving (a migration away, a protest): nothing to do.
- An app doing it: set `--delete-after false` on every node (rolling restart)
  before the hold ends. That keeps every account deactivated. Revoke the app's
  sessions, reactivate the affected accounts ("Cancelling a scheduled deletion"),
  then turn the sweep back on.

### VlpdsSignInAlertsSuppressed

**Means:** a sign-in from a new device wasn't mailed to the account's owner
because that recipient's mail budget (`mail-recipient-hour` 10,
`mail-recipient-day` 30) was spent
(`vlpds_mail_suppressed_total{purpose="sign_in_alert",reason="recipient_limit"}`).
Sign-in alerts are capped at 3 a day, a tenth of the day's budget, so other mail
to that inbox used it up first: password resets, sign-in codes, email changes.
Flooding an inbox and then signing in from a new device is how an account
takeover would stay unnoticed. (A spent node or cluster budget has its own
alerts, VlpdsMailNodeBudgetExhausted and VlpdsMailClusterBudgetExhausted.)

**Confirm:** the console's Rate limits tab: the top consumers of
`mail-recipient-*` name the account, and the rejections by route
(`mail:<purpose>`) show what filled its budget.
`vlpds_password_resets_total` and `vlpds_logins_total` by result at the same time
show resets or failed sign-ins.

**Do:** contact the owner out of band, or ask them to check Recent sign-ins on
the Security tab. If a sign-in isn't theirs: reset the password (revokes every
session) and have them turn on a second factor. If the mail came from someone
requesting resets or codes for the account, the per-account buckets are already
holding it. Lift the budget early only for a real user (a DID override in the
Rate limits tab).

### VlpdsSpaceOutboxBacklog

**Means:** a node has owed some space authority a `notifyWrite` for over an
hour (`vlpds_space_outbox_oldest_seconds`). Every space write is durable and
readable at its 200. The outbox only tells the authority that the repo moved,
so syncers find the write later than they should. Each (repo, space) has one
row that always carries the newest rev. Sends retry from 1 min, doubling to
1 h, and a row is dropped 24 h after its rev was owed (written, renotified,
or found when its shard opened). The row's `sP` key survives a
restart or a takeover, and the next owner sends it again.

**Causes:** the authority's PDS is down or answering 5xx, its DID doesn't
resolve to an `#atproto_space_host` or `#atproto_pds` endpoint. A deactivated
or taken-down writer's rows wait for a restore. They're left out of the age,
so they never fire this alert.

**Confirm:** the internals dashboard's Spaces row: `notifyWrite by hop and
result` shows `out retry` (the authority is failing). The node logs `space notifyWrite retry: <why>` with the DID, space
and rev on every failed send.

**Do:**
- One authority failing: nothing to fix on this side. Its PDS has to come back.
  Once it does, the next retry (at most ~1 h away) delivers the newest rev.
- Many authorities failing at once: look at this node's outbound path (DNS,
  egress, `http::guarded` refusals in the logs).
- A row past 24 h is dropped. The authority's `listRepos` then lags for that
  repo until its next write. Syncers still catch up from `listRepoOps`.

### VlpdsSpaceDigestMismatch

**Means:** check-space found a space repo whose stored head (`sH`: set hash,
record count, rev) doesn't match what it recomputed from the records (`sR`)
(`vlpds_space_digest_mismatch_total`). Only check-space counts here. An
importRepo whose CAR doesn't hash to its commit is the uploader's fault and
counts in `vlpds_space_imports_total{result="refused"}` instead. Syncers check
every pull against the signed commit's hash, so a wrong head makes them refetch
the whole repo with `getRepo`, and the mismatch never goes away on its own.
This is a bug, not load.

**Confirm:** the node logs `check-space: records don't hash to the space head`
with the DID and space. Run `vlpds admin check-space DID SPACE`
(`vlpds.admin.checkSpace`) for that repo again. It reports the recomputed hash and count against
the head, any record newer than the head, and whether the oplog replays onto
the records.

**Do:**
- Keep the check-space output and the node's logs around the repo's last
  writes. Open an issue with both.
- Don't delete or rewrite `s*` rows by hand. The repo's writes keep working,
  and its syncers fall back to `getRepo`.

### VlpdsSpaceNotifyFanoutFailing

**Means:** over half of the notifies this node forwards to registered syncers
fail, at over 0.1/s, for 30 min
(`vlpds_space_notify_total{hop="fanout"}`). Syncers register with
`registerNotify` and are third-party services. A failed fan-out only delays a
syncer, since it pulls from its last rev on the next notify or poll and
`listRepos` covers gaps. Fan-out runs off the write path, so writes aren't
slowed by it.

**Causes:** one big syncer down or refusing (the usual case on a small node),
or this node's egress failing.

**Confirm:** the Spaces row's `Fan-out queue depth and drops` and the failure
ratio by hop. `out` failing at the same time points at egress. The logs name
the syncer's service id (`space notify forward failed` or `refused`, with
`service` and `status`) per failure.

**Do:**
- One syncer down: nothing to do. Its registrations expire 24 h after their
  last `registerNotify` and are pruned once they keep failing past that.
- Egress: same as any outbound trouble (DNS, firewall, `http::guarded`
  refusals in the logs).

### VlpdsSpaceCredentialRejectsHigh

**Means:** over a quarter of space credential reads are refused, at over
0.5/s, for 15 min (`vlpds_space_credential_checks_total`, expired left out).
The `result` label says why: `bad_sig` (the request or credential signature
didn't verify), `audience` (the audience header isn't the repo being read),
`space` (a credential for another space), `revoked` (the authority revoked it).

**Causes:** a client app with a signing bug, an authority that rotated its
key while members still hold credentials it signed, members still reading
after an authority revoked their access, or someone probing.

**Confirm:** `Credential checks by result` on the Spaces row. One result
dominating is usually one client. The access log's route and client show
which.

**Do:**
- `revoked` after an authority removed members: expected, and it stops when
  those clients give up.
- `bad_sig` right after an authority's key rotation: clients recover by
  fetching a new credential. Nothing to do if it falls off within the hour.
- A single client stuck on `bad_sig`, `audience` or `space`: it's that app's
  bug. Reads stay refused, so there's no data exposure. Contact the app if it
  keeps up.

### VlpdsSpaceRevocationsSaturated

**Means:** the revocation blocks are saturated
(`vlpds_space_revocations_saturated` is 1), so every space credential whose
authority isn't hosted here is refused with a 503. Local authorities' spaces
keep working. A revocation that can't be stored (its caps are full) blocks
its space; over 100 blocked spaces of one authority become one block of the
authority; over 1,000 blocked authorities, every remote one is refused.
Blocks never fail open, so this is what's left when they're full.

**Causes:** someone flooding `notifyCredentialRevoked` from many authorities
with stakes here (accounts here holding repos in their spaces), or caps far
too low for real traffic.

**Confirm:** `vlpds_space_revocation_blocks{kind}` on the Spaces row, and
the `space revocation not stored` warnings in the logs (their `space` and
`refused` fields). `{prefix}/spaces/revocations.json` lists the blocks
(`blocked`, `blocked_authorities`, `remote_blocked_until`).

**Do:**
- It clears on its own: each block ends 3,610 s after it was made, once
  every credential it stood for has expired. Nothing carries over.
- A flood: find the accounts here giving the stake (each stored entry's
  `aud`) and take them down if they're abusive. Their spaces' revocations
  then need no stake here.
- Don't delete blocks from the object by hand: a block stands for a
  revocation that wasn't stored, and removing it lets a revoked credential
  read again.

---

## Procedures

### Secrets as files

Every secret setting can be read from a file instead of the environment, since
env vars show up in `docker inspect` and in a compose file. The node reads each
file once at startup and drops one trailing newline. It refuses to start on an
unreadable or empty file, or when the plain form is also set (flag or env).

| Secret | Plain | File |
|---|---|---|
| JWT secret | `VLPDS_JWT_SECRET` | `--jwt-secret-file` / `VLPDS_JWT_SECRET_FILE` |
| Admin token | `VLPDS_ADMIN_TOKEN` | `--admin-token-file` / `VLPDS_ADMIN_TOKEN_FILE` (also `vlpds admin`) |
| Internal token | `VLPDS_INTERNAL_TOKEN` | `--internal-token-file` / `VLPDS_INTERNAL_TOKEN_FILE` |
| S3 access / secret key | `VLPDS_S3_ACCESS_KEY`, `VLPDS_S3_SECRET_KEY` | `--s3-access-key-file`, `--s3-secret-key-file` / `VLPDS_S3_*_KEY_FILE` (also `vlpds-bucket-probe`) |
| SMTP URLs (credentials) | `VLPDS_EMAIL_SMTP_URL`, `VLPDS_MODERATION_EMAIL_SMTP_URL` | `--email-smtp-url-file`, `--moderation-email-smtp-url-file` / `VLPDS_*_SMTP_URL_FILE` |
| Mail API tokens | `VLPDS_EMAIL_API_TOKEN`, `VLPDS_MODERATION_EMAIL_API_TOKEN` | `--email-api-token-file`, `--moderation-email-api-token-file` / `VLPDS_*_API_TOKEN_FILE` |
| Rate-limit bypass key | `VLPDS_RATE_LIMIT_BYPASS_KEY` | `--rate-limit-bypass-key-file` / `VLPDS_RATE_LIMIT_BYPASS_KEY_FILE` |
| KEK, PLC rotation key, GCP credentials | `VLPDS_KEK`, `VLPDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` | `--kek-file`, `--plc-rotation-key-file`, `--gcp-credentials-file` ([KEK provisioning](#kek-provisioning)) |
| Vault credentials | `VLPDS_VAULT_APPROLE_ROLE_ID` (no env form for the rest) | `--vault-approle-role-id-file` (read once at startup), `--vault-approle-secret-id-file` and `--vault-k8s-jwt-file` (read at every login), `--vault-token-file` (read every minute and after a 403) |

The Ansible role (`deploy/ansible/roles/vlpds`) writes each one to
`<vlpds_secrets_path>/<name>` (0400, uid 10001), mounted read-only at
`/run/vlpds`, and sets only the `_FILE` variables. A changed secret restarts
the node gracefully on the next run.

### KEK provisioning

Repo signing keys, reserved keys and TOTP secrets are stored wrapped under a
key-encryption key (DESIGN "Secrets at rest"). Outside `--dev-mode` a node
refuses to start without one. Every node of a cluster needs the same KEK set.

- Cloud KMS (production on GCS). Create a symmetric ENCRYPT_DECRYPT key in a
  multi-region or dual-region location, e.g.
  `gcloud kms keyrings create vlpds --location us` and
  `gcloud kms keys create secrets --keyring vlpds --location us --purpose encryption`.
  Grant the nodes' service account `roles/cloudkms.cryptoKeyEncrypterDecrypter`
  on that key only. Nobody routinely gets `cloudkms.cryptoKeyVersions.destroy`.
  Set the destroy-scheduled duration to its maximum. Start nodes with
  `--gcp-kms-key projects/P/locations/us/keyRings/vlpds/cryptoKeys/secrets`
  (`VLPDS_GCP_KMS_KEY`).
  On GCE, tokens come from the metadata server (`GCE_METADATA_HOST` overrides
  it). Elsewhere, create a key for a service account holding only that role
  (`gcloud iam service-accounts keys create
  sa.json --iam-account ...`), distribute it like the other secrets (mode
  0400) and pass `--gcp-credentials-file sa.json`
  (`VLPDS_GCP_CREDENTIALS_FILE`, and `GOOGLE_APPLICATION_CREDENTIALS` also
  works). Only `service_account` key files are accepted. The node exchanges a
  signed JWT for an access token on first use, caches it for about an hour, and
  refreshes it before expiry or on a 401.
  Losing this key loses every account's signing key (each would need a PLC
  rotation), so it's part of the backup plan.
- Vault Transit (Vault 1.13+ or OpenBao). `vault secrets enable transit`,
  `vault write -f transit/keys/vlpds type=aes256-gcm96`, and a policy with only
  `update` on `transit/encrypt/vlpds` and `transit/decrypt/vlpds`. Start nodes
  with `--vault-addr https://vault.example:8200 --vault-transit-key transit/vlpds`
  plus one auth method: `--vault-token-file` (a Vault Agent sink),
  `--vault-approle-role-id-file` + `--vault-approle-secret-id-file`, or
  `--vault-k8s-role`. `--vault-ca-file` for a private CA. `--vault-addr` must be
  https (http only to loopback or in dev mode) and point at the active node or
  a load balancer in front of it, since standbys' redirects aren't followed.
  While Vault answers, the node refuses to start if it doesn't enforce
  `associated_data` (Vault before 1.13, an RSA or derived key), if it answers
  the startup check with a 403/404 or refuses the login, or if the secret-ID or
  service-account token file is missing. A refused token file is re-read 3
  times first. The error names the path and the likely cause (a missing key, a
  policy without `encrypt` or `decrypt`, a wrong role or secret ID). Unwrap-only
  keys are checked the same way. A Vault that doesn't answer (down, sealed)
  doesn't stop the start, unless the PLC rotation key file is Vault-wrapped. The
  kid doesn't include the address, so changing `--vault-addr` needs no rewrap.
  Never enable a Vault audit device with `log_raw` (it would log every signing
  key). The Ansible role doesn't support Vault yet. Details and the full policy:
  docs "KEK and key rotation", "Vault Transit".
- Local KEK. `openssl rand -out kek.bin 32` (raw 32 bytes, and 64 hex chars or
  base64 also work). Distribute it like the other secrets (sops / Ansible Vault),
  mode 0400. Pass `--kek-file /path/kek.bin` (`VLPDS_KEK_FILE`) or the value in
  `VLPDS_KEK`. Back it up offline, since it's the only way to read the stored
  keys.
- Check after start. The `secrets at rest` log line prints `kek=` (the current
  key id, `L…` local, `G…` Cloud KMS or `V…` Vault) and `unwrap_keks=`. It must match on
  every node. `vlpds_kms_requests_total` shows wraps (account creation) and
  unwraps (cold loads).
- The node caches unwrapped signing keys (`signing_keys` cache, sized from
  `--cache-budget-mb`, or set with `--cache-entries signing_keys=N`). Cloud KMS
  unwraps are limited to `--kms-concurrency` (64) in flight per node, 5 s each.
  Wraps have their own pool of a quarter of that (16), and their failures don't
  trigger the 1 s fail-fast. So a burst of reserveSigningKey or createAccount
  calls can't starve cold signing-key loads. reserveSigningKey is rate limited
  (100/h per IP, 5000 new reservations/day per node).

### KEK rotation

New wraps use the current KEK. Old blobs keep working as long as their KEK is
configured for unwrap.

1. Roll every node with the new KEK as current and the old one as unwrap-only:
   - local: `--kek-file new.bin --kek-old-file old.bin`.
   - Cloud KMS, new key version in the same CryptoKey: nothing to configure
     (`gcloud kms keys versions create` + set primary). KMS keeps decrypting
     old versions.
   - Cloud KMS, another CryptoKey (or local -> KMS): `--gcp-kms-key NEW
     --gcp-kms-old-key OLD` (or `--gcp-kms-key NEW --kek-file old.bin`, since
     with `--gcp-kms-key` set the local KEK is unwrap-only).
   - Vault Transit, new version of the same key: `vault write -f
     transit/keys/vlpds/rotate`, nothing to configure. The rewrap asks Vault for
     the latest version before it starts.
   - Vault Transit, another key or mount (or to/from local or Cloud KMS): two
     rolls. First add the new key as unwrap-only everywhere
     (`--vault-transit-old-key NEW`, `--gcp-kms-old-key` or `--kek-old-file`),
     then make it current with the old one unwrap-only
     (`--vault-transit-key NEW --vault-transit-old-key OLD`, or the old Vault key
     as `--vault-transit-old-key` next to `--gcp-kms-key` / `--kek-file`).
     Moving off Vault needs Vault reachable from every node until the rewrap is
     done.
2. Rewrap on every node, since each covers the shards it owns. Run
   `vlpds admin rewrap-secrets` (every node at once), or per node
   `curl -XPOST -u admin:$ADMIN -H 'content-type: application/json' -d '{}' $NODE/xrpc/vlpds.admin.rewrapSecrets`.
   For a version rotation inside one CryptoKey or Transit key, pass
   `{"checkVersions": true}` (one decrypt per secret). It reports `stale` (rewrapped), `failed` and
   the first errors. Rewrapping doesn't change keys, emits no events and doesn't
   evict repos. Re-run until `failed` is 0.
3. Verify on every node with `{"dryRun": true}` (plus `checkVersions` as above)
   until `stale` is 0. Shards that moved during step 2 show up here, so rerun
   step 2.
4. Only then drop the old KEK (`--kek-old-file`), or disable the old KMS
   version (Vault: raise `min_decryption_version` to at most the lowest
   `minKeyVersions` the rewrap's `--json` output reports across nodes, never
   `trim`). Before that, rewrap the PLC rotation key files and finish pending
   signing-key rotations, since `rewrap-secrets` covers neither. **Keep the old KEK material (or keep the version disabled, not
   destroyed) for the backup retention period**, because backups and log
   segments still hold blobs wrapped under it.

### Key service (KMS) outage

1. Confirm it with `vlpds_kms_requests_total{result="unavailable"}` on all
   nodes, the `key service unavailable` log (HTTP status or timeout), Google
   Cloud status, and IAM (a 403 from a removed role looks the same). On Vault,
   also check `vault status` (sealed is a 503), the policy, and the auth method
   (a revoked secret ID or a broken Agent shows as a failed login). A node
   started while Vault was down or sealed logs `key service check deferred to
   first use` and checks again on its first wrap or unwrap (a node whose PLC
   rotation key file is Vault-wrapped can't start then at all). A node started
   while Vault answers with a 403/404 refuses to start instead, so a crash loop
   with `is unusable` in the log is a setup problem (policy, key name, role),
   not an outage. Clients
   retry 503s. After a failure, a node fails cold unwraps fast for 1 s before it
   tries KMS again.
2. **Don't restart nodes and don't move shards** (no rolling deploys, splits or
   handbacks) while KMS is down. A restart or takeover empties the key cache,
   which turns warm accounts cold. Then every account the node owns is
   unwritable until KMS is back.
3. If one node is affected (network or metadata-server problem), drain it with
   SIGTERM. Its shards move to nodes that can reach KMS.
4. When KMS is back, cold writes succeed on their next retry. Nothing needs
   replaying, because refused writes were never applied.
5. If KMS is lost for good (key destroyed), restore the key from a backup if one
   exists. Otherwise, start nodes with a new KEK. Accounts can no longer sign,
   and each needs a new signing key installed (`admin.updateAccountSigningKey`)
   and a PLC rotation. That needs the PLC rotation keys the users or their
   recovery flow hold.

### PLC rotation key provisioning

Accounts' DIDs are registered with the PLC directory, and every DID lists
this deployment's **PLC rotation key** (DESIGN "PLC identity"). Outside
`--dev-mode` a node refuses to start without one (`--plc-mode unregistered`
is dev-only). Every node of a cluster needs the same key. If you lose it, the
server can't update its accounts' DIDs anymore (handle changes, migrations
out). Users with their own recovery key can still recover.

1. Generate it and wrap it under the KEK (Cloud KMS in production) on a host
   with the node's KEK config:
   `vlpds --gcp-kms-key projects/P/locations/us/keyRings/vlpds/cryptoKeys/secrets --wrap-plc-rotation-key </dev/null >plc-rotation.key`
   Empty stdin makes a new key. To wrap an existing key, pipe in 64 hex chars
   instead (e.g. a reference PDS's `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`).
   The did:key goes to stderr with the logs, so record it. stdout is only the
   wrapped key. Check that the file is one `vw1.` line
   (`head -c 4 plc-rotation.key`). Older builds logged to stdout and put log
   lines in it.
2. Distribute `plc-rotation.key` like the other secrets (sops / Ansible
   Vault), mode 0400, and start nodes with `--plc-rotation-key-file`
   (`VLPDS_PLC_ROTATION_KEY_FILE`). The file is useless without KMS decrypt
   on the KEK. You can instead pass the hex in
   `VLPDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`, but that's plaintext in the
   environment and not recommended.
3. Optional: `--plc-recovery-did-key did:key:...` (an offline key the
   operator holds) goes ahead of the server key in every new DID
   ([Operator recovery key](#operator-recovery-key)).
4. Check after start. The `PLC registration on` log line shows `plc_url` and
   `rotation_key` (the did:key from step 1) on every node, and
   `getRecommendedDidCredentials` returns it in `rotationKeys`.
5. Back up the wrapped file with the KEK backup plan. It needs the KEK to
   open, and it isn't in the bucket.

For local e2e runs, point `--plc-url` at a local did-method-plc server
(`docker run` its image with Postgres), or use `--dev-mode` without a key
(unregistered DIDs). Never point a test cluster at plc.directory.

### PLC rotation key rotation

1. Make a new key (step 1 above). Roll every node with the new key as
   current and the old one retired:
   `--plc-rotation-key-file new.key --plc-rotation-key-old-file old.key`.
   New DIDs list the new key. Any update of an old DID (handle change,
   signPlcOperation) is signed by the old key and lists the new one instead.
2. Run it on every node, since each covers the shards it owns.
   `vlpds admin rotate-plc-keys --dry-run` (every node at once), or per node
   `curl -XPOST -u admin:$ADMIN -H 'content-type: application/json' -d '{"dryRun": true}' $NODE/xrpc/vlpds.admin.rotatePlcKeys`,
   reports `current`, `rotated` (still on the old key), `foreign` (DIDs that
   list neither, i.e. migrated away or synthetic bulkCreate DIDs) and `failed`.
   Run it without `dryRun` to submit the updates (4 in flight per node). The
   directory rate-limits per DID and per IP, so expect it to take a while
   for millions of accounts. Re-run until `failed` is 0, then do dry runs
   until `rotated` is 0 on every node (rerun where shards moved).
3. Only then drop `--plc-rotation-key-old-file`. Keep the old key material
   offline until you're sure. An op signed by a key a DID no longer lists
   is refused, but a retired key that leaks can still sign for DIDs that
   list it. For a compromised key, also keep the 72 h recovery window in mind.
   A higher-priority key (the user's or `--plc-recovery-did-key`) can undo ops
   the attacker signed within 72 h.

### Operator recovery key

This is a secp256k1 key the operator keeps offline, listed in every hosted
DID's rotation keys just ahead of the server rotation key. It outranks the
server key. Within 72 h of an op signed by the server key (a leaked rotation
key, a bad deploy), an op signed by the recovery key can replace it. Keys a user
added themselves (the account page, /migrate's advanced option, createAccount
`recoveryKey`) stay ahead of it.

1. Make it on an offline machine. `vlpds --generate-did-key` prints
   `private key (hex): ...` and `did:key: ...` (it needs no other config).
   Store the hex offline (paper or hardware vault, two copies). It never
   goes on a node.
2. Roll every node with `--plc-recovery-did-key did:key:...`
   (`VLPDS_PLC_RECOVERY_DID_KEY`, or the reference's
   `PDS_RECOVERY_DID_KEY`). From then on, new accounts and
   `getRecommendedDidCredentials` (migrations in) list it.
3. For existing accounts, run `vlpds admin ensure-recovery-key --dry-run`
   (every node, or `--node-only` for the one at `--url`). It reports per node
   `present`, `added` (would be added), `foreign` (DIDs that list none of this
   server's keys, i.e. migrated away or synthetic), `full` (already 10 rotation
   keys, so nothing is added and they're listed in the errors) and `failed`.
   `--json` shows up to 50 `{did, before, after}` changes per node. Then run it
   without `--dry-run`. Each DID that lacks the key gets one PLC update signed
   by the server key, inserting it just before the server key (`[user keys...,
   recovery, server]`). It's paced at `--per-second` DIDs per node (default 4,
   4 in flight). Re-run until `failed` is 0, and then a dry run shows `added` 0.
   It's idempotent, and a race with another update is rebuilt on the new log.
4. Using it (emergency only): build the corrective `plc_operation` (prev =
   the last good op's CID, plus the good rotation keys, services and signing
   key). Sign it with the recovery key offline (e.g. `goat plc` tooling) and
   POST it to the directory within 72 h of the bad op. Then fix the server side
   by rotating the server rotation key ([PLC rotation key rotation](#plc-rotation-key-rotation)).

To change the recovery key, roll the new `--plc-recovery-did-key` and run
`ensure-recovery-key` (it adds the new one). The old one stays listed until
the DID's keys are rewritten. Remove it from DIDs only if it leaked.

### PLC directory outage

1. Confirm it with `vlpds_plc_requests_total{result="unavailable"}` on all
   nodes, the `PLC directory request failed` warn log (status or timeout), and
   the directory's status page. A 429 means this server is rate-limited (bulk
   `rotatePlcKeys`, a signup flood), so slow down.
2. While it lasts, createAccount / sign-up, updateHandle, admin handle and
   signing-key changes and submitPlcOperation return 500 with nothing changed,
   and clients may retry. Nothing queues on the server and nothing needs
   replaying afterwards. Existing accounts work normally.
3. Don't switch to `--plc-mode unregistered` to keep signups open. Those DIDs
   would never exist on the network.
4. If one node is affected (egress or DNS), drain it with SIGTERM. Its shards
   move to nodes that can reach the directory.
5. Afterwards: a createAccount whose local part failed after the directory
   accepted the genesis op tombstones the DID. If the tombstone itself failed
   (`tombstoning the DID of a failed account creation` error log), that DID is
   registered without an account. That's harmless, since nothing points users
   at it.

### Rolling deploy

1. One node at a time. Send SIGTERM (never SIGKILL). A graceful stop
   (`Cluster::shutdown`) marks its lease `draining` so peers stop counting it.
   It closes its shards with one barrier segment + checkpoint and hands them
   straight to settled peers (their nudges skip the control-plane read). Then it
   waits for its log to quiesce (up to 10 s), fences its own log, deletes its
   lease, nudges peers, keeps answering for 500 ms more and exits 0. If the
   fence keeps failing (store errors for min(TTL, 30 s) of retries), it keeps
   its lease and exits 8 (`shutdown_fence`). The supervisor's restart fences the
   old log at startup, and so do peers once the lease goes quiet. Without that,
   followers would wait on the log forever.
2. Give the supervisor a stop timeout well above the worst case. The close
   barrier may wait 30 s and the quiesce 10 s, so use at least 60 s (derived
   estimate). A stop that times out into SIGKILL becomes a crash (fence +
   replay by peers). Failing fence retries (up to min(TTL, 30 s) more) can run
   past 60 s. A SIGKILL there ends the same way as their exit 8. The shards are
   already handed out, and the kept lease gets the log fenced.
3. Start the new binary with the same `--node-id` and the same bucket, prefix,
   tokens and `--advertise-url`. It greets peers, and peers hand back its fair
   share at their next step.
4. Before the next node, confirm:
   - `sum(vlpds_owned_partitions)` equals `vlpds_shard_layout_shards`.
   - The restarted node's `owned` is about `shards / nodes`, and it shows
     `vlpds_last_exit_reason_info{reason="clean"}`.
   - `leaseValid: true` on all `nodes[]`.
   - `vlpds_build_info{rev}` is the new rev.
   - Commit p99 and `vlpds_write_retries_total` are back to baseline.
5. Expect zero client errors for a clean SIGTERM (3-8 when a forward is in
   flight at exit, per DESIGN), resend bursts, and cold-load latency on moved
   repos.

### Rolling upgrade, finalize, rollback

Every format a node persists or sends belongs to a **feature level**
(`vlsync-store/src/version.rs`, DESIGN.md "Rolling upgrades and format versioning"). A
build runs levels `MIN_LEVEL..=MAX_LEVEL`, and its release notes list them and
say whether each is persistent. The cluster's active level is in
`cluster/version`, and every node writes that level's formats whatever its
build. So a new build writes byte for byte what the old one writes until the
level is raised, and that's what makes rollback a plain redeploy.

**Upgrade** to build B (`MAX_LEVEL = L+1`) on a cluster at level L:

1. Pre-flight: `vlpds admin cluster status` shows every node healthy and
   `Feature level: L active`. Check that B's `MIN_LEVEL <= L` (a build whose
   `MIN_LEVEL` is past the active level refuses to start with exit 7).
2. Roll B out exactly as in [Rolling deploy](#rolling-deploy) (SIGTERM, >= 60 s
   stop timeout, same `--node-id`, step 4's checks between nodes). Also check
   that the restarted node's row shows B's rev and `1..=L+1`-style levels, and
   that `vlpds_format_errors_total` stays flat.
3. Soak with the whole fleet on B at level L (default 24 h). The console's
   Cluster page and `cluster status` say "every node can run level L+1:
   finalize available". Rollback is a plain redeploy of the previous build,
   node by node, in any order, at any time.
4. Finalize with `vlpds admin cluster finalize --level L+1` (it asks, so pass
   `--yes` off a terminal). It writes a raise `target` and lists every lease
   after that write. Each live node's build must run L+1. If one can't, it
   clears the target and names the nodes (409 `IncompatibleNodes`, nothing
   changed). Otherwise it sets `active = L+1`. A node starting during the raise
   re-reads the object after its lease write, and exits 7 if it can't run L+1.
   Watch format errors, commit p99 and firehose watermark lag for one TTL.
   **From now on rollback is forward-fix only.**

**Rollback before finalize:** redeploy the previous image node by node with the
same procedure. There's nothing to clean up, because no byte of level L+1
exists.

**Rollback after finalize:** a redeploy can't do it, because the old build exits
7 `incompatible_level` at startup, before touching data (VlpdsIncompatibleNode).
Ship B' = B + fix. A persistent level is never lowered (restore from a backup
taken at the old level instead). A level that only gates wire behavior
(non-persistent, and the release notes say which) can be lowered when its new
wire behavior is the bug. Use `vlpds admin cluster lower --level L` (it asks, so
pass `--yes` off a terminal), or `vlpds.admin.setFeatureLevel {"level": L, "lower": true}`.
It refuses with 400 to go past a persistent level or while a raise `target` is
set, and with 409 `IncompatibleNodes` while a live node's build can't run L.
Nodes pick up the lower level within one lease TTL and switch at their next
segment. Then the old build can be redeployed.

Feature levels never change by themselves. A node never raises the level at
startup, and finalize (or `cluster lower`) is the only writer of
`cluster/version` after its creation. A fresh prefix starts at its first node's
max level.

**Before a release** with a new level, run `just upgrade-ci`. It covers the
fixtures and the MANIFEST freeze, the level-gating test, and the two-build
`upgrade-rolling` scenario against the previous release. `just upgrade-ha` runs
every `upgrade-*` scenario (rollback, old-node refusal, raise race). The test
builds use the test-only feature level (cargo feature `test-level`). Never
deploy such a build (it logs `TEST BUILD` at startup).

### Replacing a dead host

1. Nothing needs doing for data safety. Peers fence the dead log and take its
   shards (3-5 s if the port refuses, or TTL + skew + replay if the host is
   unreachable, which is ~12 s at the default TTL and ~72 s at 60 s).
2. Make sure the old process can never come back on its own (power it off). If
   it did come back, it would find its log fenced or its shards reassigned and
   fail-stop, but don't rely on that.
3. Start the replacement. Reusing the old `--node-id` lets it fence and reclaim
   its previous incarnation's assignments right away, but a new id works too.
   The dead node's `nodes/` lease object is deleted automatically once all its
   shards have moved and its log is fenced.
4. Point `--cache-dir` at local NVMe. The cache starts cold, so expect cold-load
   latency for a while.
5. Verify as in rolling deploy step 4.

### Adding a node

1. Pick a unique `--node-id`. Use the same bucket, prefix, KEK flags,
   `--jwt-secret`, `--admin-token`, `--internal-token` and `ca.crt`. Issue its
   node certificate into its `--peer-tls-dir` (`vlpds admin tls issue --node-id <id>
   --host <advertise host>`, [Peer TLS](#peer-tls-mtls-between-nodes)). Set
   `--peer-listen` and `--advertise-url https://<host>:<peer port>` to an
   address all peers can reach. Nodes don't go in `--trusted-proxies`, because a
   forwarding node passes the client address over the internal token (DESIGN
   "Rate limits"). List only real proxies (load balancers) there.
2. Start it. After it greets every peer, each peer above the new fair share
   `ceil(shards / live)` hands extras to it at its next step.
3. Add the target to Prometheus (job `vlpds`).
4. Verify `owned` per node converges and `VlpdsOwnershipImbalanced` stays quiet.
5. Writer ids are a single byte (seq low byte), so a cluster can't exceed 256
   live node incarnations **(derived from the seq format)**.

### Peer TLS (mTLS between nodes)

Node-to-node traffic (forwards, `/internal/*`, log streams) runs h2 over TLS
1.3 with client certificates on `--peer-listen` (DESIGN.md "Exposure"). There's
no cleartext mode. A node certificate names its node with a URI SAN
`vlpds://node/<node-id>` and carries the DNS name or IP of its `--advertise-url`
host. It's good for both serverAuth and clientAuth. Besides the chain, peers
check the host, and that the cert names the node whose lease advertises that
address (for log streams, the log's node). The internal token is still required
on top.

**Create the CA** (once per cluster, on an operator machine, ECDSA P-256):

```sh
vlpds admin tls ca --out ./pki            # ./pki/ca.crt, ./pki/ca.key (0600)
```

Keep `ca.key` offline (a vault). Nodes get only `ca.crt`.

**Issue a node certificate** (per node, where `--host` repeats or takes a
comma-separated list of DNS names / IPs):

```sh
vlpds admin tls issue --ca ./pki/ca.crt --ca-key ./pki/ca.key --out ./pki \
  --node-id node-a --host 10.0.0.5 --host node-a.internal   # 365 days (--days)
vlpds admin tls show ./pki/node-a.crt
```

Install `ca.crt`, `node-a.crt` and `node-a.key` (0600, readable by the vlpds
user) in one directory on the node (not `ca.key`) and run it with:

```sh
--node-id node-a --peer-listen 0.0.0.0:2584 --advertise-url https://10.0.0.5:2584 \
--peer-tls-dir /run/vlpds/peer-tls
```

Startup refuses a cert that doesn't chain to the CA, is expired, lacks the
`vlpds://node/` SAN, names another `--node-id`, or doesn't match the key. It also
refuses an `http://` advertise URL (`--peer-listen`, `--peer-tls-dir` and
`--advertise-url` go together). Keep `--listen` behind the edge proxy as
before, and make `--peer-listen` reachable only by peers. It refuses anyone
without a node cert, but it doesn't need to be public.

**Dev mode** (local or bench clusters): point every node at one
`--peer-tls-dir`. The first node creates `ca.crt` + `ca.key` (under a lock),
and each node issues its own certificate from them at startup. Across hosts,
copy `ca.crt` and `ca.key` into each host's directory before starting its
nodes (a cross-host bench harness does). Never use it in production, since the
CA key sits next to the nodes.

**Renew a node certificate** (alert [VlpdsPeerTlsCertExpiring](#vlpdspeertlscertexpiring)
`cert="node"`, no restart):
1. `vlpds admin tls issue ... --node-id node-a --host ... --force` (same id
   and hosts).
2. Replace the cert and key files on the node. Write both, then `kill -HUP`
   the process or wait up to 60 s for the file poll. The node checks the new
   pair (chain, expiry, node id, key match) and switches. On failure it logs
   `peer TLS reload failed`, counts `vlpds_peer_tls_reloads_total{result="error"}`
   ([VlpdsPeerTlsReloadFailing](#vlpdspeertlsreloadfailing)) and keeps the old one.
3. Confirm `vlpds_peer_tls_cert_expiry_seconds{cert="node"}` moved. New peer
   connections use the new cert. Pooled ones keep the old one until they close,
   since they verified it once at the handshake.

**Rotate the CA** (`cert="ca"`, or a suspected CA key leak):
1. `vlpds admin tls ca --out ./pki-new`.
2. On every node, make `ca.crt` in `--peer-tls-dir` a bundle of old + new CA
   (`cat pki/ca.crt pki-new/ca.crt > ca.crt`), then SIGHUP (or wait for the
   poll). Every node now trusts certs from either CA.
3. Issue each node a cert from the new CA (`--ca ./pki-new/ca.crt --ca-key
   ./pki-new/ca.key`), install it and SIGHUP, one node at a time. Check that
   `vlpds_peer_tls_handshake_failures_total` stays flat.
4. Once every node presents a new-CA cert, make `ca.crt` the new CA
   alone on every node and SIGHUP. After a key leak, also restart the nodes
   (pooled connections authenticated under the old CA close then) and rotate
   `--internal-token`.

A file left half-written is retried on the next poll or SIGHUP. A cert or key
moved away mid-run doesn't matter, because the loaded set stays in memory.

### Object-store outage

What happens, from DESIGN and the code:
- Segment PUTs retry until they succeed. Commits queue, acks stop and write
  latency climbs. Then admission control sheds (`Overloaded`) and forwards time
  out.
- Renewals slower than 0.4 x TTL (4 s at TTL 10 s, 24 s at 60 s) open validity
  gaps, so nodes stop acking and fail-stop (exit 5). A cluster-wide brownout past
  that ceiling stops every node. No acked write is lost, because acks require
  durable segments.
- When the store recovers, restarted nodes rejoin, fence the dead incarnations'
  logs (including their own previous one) and replay.

What to do:
1. Confirm it's the store. Check provider status, `slatedb_object_store_*`,
   `vlpds_object_store_requests_total{result}` / `vlpds_object_store_request_seconds`,
   `vlpds_lease_renew_seconds` and `vlpds_cluster_store_timeouts_total` on all
   nodes, and the logs.
2. Make sure the supervisor keeps restarting nodes (with backoff) so they rejoin
   as soon as the store answers.
3. Don't lower `--lease-ttl-ms` (smaller ceiling) and don't delete anything.
   Raising the TTL during an incident isn't a live operation either.
   `--lease-ttl-ms` is read at start, so it means restarting every node, and until
   they all have, each node judges its peers' leases by its own TTL.
4. After recovery, watch `VlpdsShardsUnowned`, replay time
   (`vlpds_shard_open_seconds{kind="replay"}`, `shards opened` `replayed_ms`),
   `vlpds_last_exit_reason_info` / `vlpds_peer_takeovers_total` (who fail-stopped),
   firehose emit delay, and retention catching up.

### Store saturated by the node's own reads

The ctl client's reserved lane keeps lease renewals from queueing behind vlpds'
own requests in the client. It can't keep them from queueing behind other
requests in the store. When the store's disks or network saturate, a renewal
waits like everything else. The 100M capacity run lost 3 of 4 nodes this way
(that bench ran a 30 s TTL, and the leases had lapsed 35-48 s by the time the
nodes fail-stopped). Metadata-cache misses had turned point reads
into 1-2.4 GB/s of SST GETs per node on one MinIO box. The signs, in order, are
`VlpdsSstMetaRefetching` / `VlpdsSstMetaCacheTooSmall`, state SST download MB/s
far above upload MB/s, `VlpdsObjectStorePermitsSaturated` (state client),
`VlpdsControlPlaneLatencyHigh`, and then the lease alerts.

What to do:
1. Stop the read load that drives it. Pause bulk imports and backfills, and shed
   load at the edge if it's user traffic.
2. Fix the cause (raise `--meta-cache-mb`, add nodes) before resuming.
3. A store shared with other tenants or other clusters can do the same to
   vlpds' leases. Keep the cluster's store to itself, or give its prefix its own
   capacity/limits.

### Shard split / merge

`vlpds admin shard-split <shard> [--at <slot>]`, `shard-merge <left> <right>`,
`reshard-abort` (only before the flip), and `layout` to watch `op`. Shard ids are
u32 and never reused. Each split takes two new ids and each merge one from the
layout's `next_id` (aborted ops' ids stay used), so ids grow past the shard
count. They aren't positions. Every node's `vlpds_shard_layout_shards` /
`vlpds_shard_layout_version` follow the flip, and the ownership alerts read the
count from there.

### Email (SMTP, moderation mail, branding)

DESIGN "Email" has the details. Every node needs the same flags. A flag left
unset falls back to the reference PDS's variable, so a reference `pds.env`
works as is:

| Flag | Env | Reference env | Notes |
|---|---|---|---|
| `--email-smtp-url` | `VLPDS_EMAIL_SMTP_URL` | `PDS_EMAIL_SMTP_URL` | `smtp://user:pass@host:587` / `smtps://...:465`. Unset, mail is only logged |
| `--email-api-url` | `VLPDS_EMAIL_API_URL` | | Cloudflare Email Sending's REST API (`https://api.cloudflare.com/client/v4/accounts/<account_id>/email/sending/send`) for hosts that block outbound SMTP. Set this or `--email-smtp-url` |
| `--email-api-token-file` | `VLPDS_EMAIL_API_TOKEN_FILE` | | its bearer token (Email Sending: Edit). `--email-api-token` / `VLPDS_EMAIL_API_TOKEN` inline |
| `--email-from-address` | `VLPDS_EMAIL_FROM_ADDRESS` | `PDS_EMAIL_FROM_ADDRESS` | required with either URL |
| `--moderation-email-smtp-url` | `VLPDS_MODERATION_EMAIL_SMTP_URL` | `PDS_MODERATION_EMAIL_SMTP_URL` | admin `sendEmail` only. Unset, it uses the main mailer |
| `--moderation-email-api-url` | `VLPDS_MODERATION_EMAIL_API_URL` | | the same over the REST API. Token: `--moderation-email-api-token-file`, else the main one |
| `--moderation-email-address` | `VLPDS_MODERATION_EMAIL_ADDRESS` | `PDS_MODERATION_EMAIL_ADDRESS` | required with a moderation URL |
| `--email-brand-name` | `VLPDS_EMAIL_BRAND_NAME` | `PDS_SERVICE_NAME` | default "{hostname} PDS" |
| `--email-home-url` | `VLPDS_EMAIL_HOME_URL` | `PDS_HOME_URL` | footer link, default https://bsky.app |
| `--email-logo-url` | `VLPDS_EMAIL_LOGO_URL` | `PDS_LOGO_URL` | default is the Bluesky logo, as in the reference |
| `--email-primary-color` | `VLPDS_EMAIL_PRIMARY_COLOR` | `PDS_PRIMARY_COLOR` | default `#067df7` |
| `--email-disable-confirmation-link` | `VLPDS_EMAIL_DISABLE_CONFIRMATION_LINK` | `PDS_EMAIL_DISABLE_CONFIRMATION_LINK` | drops the bsky.app "click here" link |
| `--mail-daily-budget` | `VLPDS_MAIL_DAILY_BUDGET` | | account mails per UTC day for the whole cluster (`mail-cluster-day`). Default 900. Keep it under the provider's daily quota |

Setting a URL without its address (or the reverse) fails startup. If mail isn't
arriving, check `vlpds_mail_messages_total{result="failed"|"dropped"}` and the
`mail not sent` / `mail dropped` warnings (they log the recipient and purpose,
never the token). `purpose="admin"` is moderation mail. Dev mode keeps every
mail, with its HTML, in `vlpds.admin.getDevMail`.

**Mail rate limits** (DESIGN "Rate limits", mail budgets). All of them are
buckets in the console's Rate limits tab, editable live. Per-DID ones are counted
on the account's owner, so they hold cluster-wide. `mail-cluster-day` is one
count in the bucket (`budget/mail.json`) that every node spends.

| Mail | Endpoint buckets | Shared budgets |
|---|---|---|
| confirm_email (requestEmailConfirmation) | 5/h, 15/day per DID | recipient + node + cluster |
| update_email (requestEmailUpdate, and updateEmail turning the email factor off without a token) | 5/h, 15/day per DID, shared | recipient + node + cluster |
| delete_account (requestAccountDelete) | 5/h, 15/day per DID | recipient + node + cluster |
| plc_operation (requestPlcOperationSignature) | 5/h, 15/day per DID | recipient + node + cluster |
| reset_password (requestPasswordReset) | 15/h, 50/day per IP · `password-reset-account-*` 5/h, 15/day per account | recipient + node + cluster |
| auth_factor (createSession / OAuth sign-in with the email factor) | sign-in buckets, and no new code while the last is under a minute old | recipient + node + cluster |
| admin (admin `sendEmail`) | moderator auth only | exempt |

`mail-recipient-hour` / `-day` (10 / 30 per recipient, every kind together),
`mail-node-hour` (200 per node, a burst guard) and `mail-cluster-day` apply even
to bypassed requests (bypass key, admin auth, internal token). `mail-cluster-day`
is `--mail-daily-budget`, 900 per UTC day for the whole cluster. The provider's
quota is per account, so it must not grow with the node count. A DID override
lifts a recipient's budget. `--no-rate-limits` turns them off with the rest.

Over a budget, a user gets 429 `RateLimitExceeded` "Too many emails sent to this
account" (on the sign-in page, "Too many sign-in attempts"). The request mints no
token, so the last code mailed still works. requestPasswordReset over any of its
account or mail budgets answers 200 as if mailed. Mail not sent for a budget is
counted in `vlpds_mail_suppressed_total{purpose,reason}` (`recipient_limit`,
`node_limit`, `cluster_limit`, `account_limit`, `dedup`). The day's remaining
cluster budget is `vlpds_mail_budget_remaining{window="day"}`. If a user says the
code never came, check that counter and the account in the tab's top consumers.
A DID override (or waiting out the hour) fixes it.

### Moderation service, earned invites, external handles

Every node needs the same flags. As for email, an unset flag falls back to the
reference PDS's variable:

| Flag | Env | Reference env | Notes |
|---|---|---|---|
| `--mod-service-did` | `VLPDS_MOD_SERVICE_DID` | `PDS_MOD_SERVICE_DID` | the Ozone DID allowed to call the moderator admin methods with a service JWT. Unset, admin Basic auth only |
| `--invite-interval-ms` | `VLPDS_INVITE_INTERVAL_MS` | `PDS_INVITE_INTERVAL` | with `--invite-required`, one earned code per this much account age (at most 5 unused). Unset, none |
| `--invite-epoch-ms` | `VLPDS_INVITE_EPOCH_MS` | `PDS_INVITE_EPOCH` | Unix ms. Only account age after it earns codes (default 0) |

- Ozone gets 401 `UntrustedIss` "Untrusted issuer" on admin calls. The token's
  `iss` isn't `--mod-service-did` (or `<did>#atproto_labeler`), or the flag is
  unset on the node that answered. `BadJwtSignature` "jwt signature does not
  match jwt issuer" means the key in Ozone's DID document (`#atproto`, or
  `#atproto_label` for the labeler issuer) isn't the one it signs with. vlpds
  re-resolves the document once before refusing, so a just-rotated key works.
  `BadJwtAudience` means Ozone addressed the token to another DID instead of
  this PDS's `--service-did`. Ozone can call getAccountInfo(s),
  get/updateSubjectStatus, sendEmail, getInviteCodes, disableInviteCodes,
  enable/disableAccountInvites and read any account's preferences
  (`app.bsky.actor.getPreferences?did=`). Everything else (deleteAccount,
  updateAccountEmail/Handle/Password/SigningKey, createInviteCode(s), the
  `vlpds.admin.*` methods) stays admin Basic auth only.
- Earned invites. To stop new codes being earned, unset `--invite-interval-ms`
  (rolling restart). Codes already created stay. To cut one account off, use
  `com.atproto.admin.disableAccountInvites` (its codes are disabled, and codes it
  earns afterwards are created disabled). Changing `--invite-epoch-ms` to now
  restarts everyone's earning from zero.
- External handles. updateHandle to a domain outside `--handle-domain` needs a
  DNS TXT record `_atproto.<handle>` = `did=<the account's DID>` or
  `https://<handle>/.well-known/atproto-did` serving the DID. Both are tried at
  once with a 3 s deadline each, through the host's resolver
  (`/etc/resolv.conf`). If a user swears the handle is set up but gets "External
  handle did not resolve to DID", usually the node's resolver can't reach the
  zone (check `dig TXT _atproto.<handle>` from the node) or there's more than one
  `did=` record. Dev mode skips the check.
- Disposable email domains are refused at createAccount and updateEmail ("This
  email address is not supported, please use a different email."), as in the
  reference. The list is compiled in
  (`src/email_policy/disposable_email_domains.txt`), so updating it is a release.

### A user locked out by a second factor

There are two factors (DESIGN "Email second factor"). One is the reference's
email code (`emailAuthFactor`, what the Bluesky app offers) and the other is
vlpds TOTP. With both on, only TOTP is asked for.
- Too many wrong codes (429 `RateLimitExceeded` on createSession or the sign-in
  page). The factor is locked for 5 min, doubling per further lockout up to a
  day. It clears by itself, and there's nothing to reset.
- Too many wrong passwords from anywhere (429 on createSession or the sign-in
  page for one account, from every address). The `sign-in-account` bucket (100
  attempts per hour per account) is spent, e.g. by someone guessing. It clears
  within the hour. App-password createSession is refused too (the bucket is
  checked before the password); live sessions keep working. To lift it
  early, add a DID override for `sign-in-account` in the console's Rate limits
  tab.
- An OAuth client app gets 429 `rate_limit_exceeded` from `/oauth/token` or
  `/oauth/par`. Its backend shares one address for all its users (`oauth-ip`,
  3000 per 5 min per IP). Add an IP override for that address.
- Lost the inbox (email factor). After verifying the user out of band, set a new
  address with `com.atproto.admin.updateAccountEmail`, which drops the factor
  (any address change does, as in the reference). The user re-confirms and
  re-enables it.
- Lost the authenticator (TOTP). A recovery code works in place of a code.
  Lost the codes too: "Resetting a user's second factors".
- Lost a passkey: "A user lost their passkeys".
- Too many wrong codes count across TOTP and recovery codes (one lockout in
  the `mfa` row). A refused passkey never counts toward it.
- App passwords bypass every factor (reference behaviour), so a user with one
  can still use apps while sorting out the factor, unless they blocked app
  passwords (see the next section).

### A user locked out by OAuth only

The Security tab's OAuth-only switch makes `createSession` refuse the main
password, and "Block app passwords too" refuses app passwords (docs
`oauth-2fa.md` "OAuth only").
- The app shows 401 `OAuthRequired` (main password) or `AppPasswordsBlocked`
  (app password), counted as `vlpds_logins_total{result="oauth_required"}` and
  `{result="app_passwords_blocked"}` (takedowns are `{result="inactive"}`).
- Not an outage. Sign in through the app's OAuth option (this server's sign-in
  page, with the second factor), or with an app password if they aren't
  blocked.
- To turn it off, the user signs in on the account page (`/account`, it still
  takes the password and the second factor) and unticks it under Security,
  "Sign-in protection". There's no admin switch.
- Lost the second factor too: fix that first ("A user locked out by a second
  factor"). OAuth only stops applying while the account has no factor. Blocked
  app passwords stay blocked.
- Blocking app passwords only refuses new sign-ins. Apps already signed in with
  one keep working until the password is revoked.

### A sign-in alert that didn't arrive

Alerts go out for a sign-in from a device the account hasn't used in 180 days
(docs `oauth-2fa.md` "Sign-in alerts and recent sign-ins"). None is sent when:
- the device was seen before. A browser is its device cookie. An app is its user
  agent plus its address (a v6 address as its /64), so the same app on the same
  network doesn't alert twice.
- the user turned that kind off (Security, "Sign-in protection"), or the account
  has no email.
- the sign-in used an emailed code, or it's the first sign-in vlpds recorded for
  the account.
- the account already got 3 that UTC day.
- a mail budget is spent: `vlpds_mail_suppressed_total{purpose="sign_in_alert"}`.

`vlpds_sign_in_alerts_total{result}` counts every new-device sign-in by which
of these applied (`mailed`, `baseline`, `muted`, `no_email`, `email_code`,
`account_limit`, `budget`).
  Delivery failures: `vlpds_mail_messages_total{purpose="sign_in_alert",result="failed"}`.

Ask the user to check Recent sign-ins on the Security tab. A sign-in marked
"New" was a new device. Mail problems in general: "Email (SMTP, moderation
mail, branding)".

### A user lost their passkeys

Passkeys are a second factor, and a discoverable one with a PIN or biometric
replaces the password (docs `oauth-2fa.md` "Passkeys").
- An app shows 401 `PasskeyRequired` on createSession
  (`vlpds_logins_total{result="passkey_required"}`). The account has passkeys
  and no TOTP, so the password alone only works on this server's own pages.
  Not an outage. Sign in through the app's OAuth option, or use an app
  password.
- One passkey lost, others left: the user signs in with another one, then
  removes the lost one on the Security tab with "Sign out everywhere" ticked.
  Removing it ends what it signed in, and the box ends everything else.
- Every passkey lost: the user signs in with the password and a recovery code,
  on the OAuth sign-in page ("Use a recovery code instead") or on the account
  page. TOTP, if it's on, works too.
- No codes left either: "Resetting a user's second factors".
- The PDS changed hostname: every passkey stops working at once (they're bound
  to the `--public-url` host). Users fall back to the steps above.
- Passkeys don't move with the account. On a new PDS the user sets up new ones.

### Resetting a user's second factors

For a user who lost every passkey, their authenticator app and their recovery
codes. It removes passkeys, TOTP, the recovery codes (and the lockout) and
trusted browsers, and ends the sessions the passkeys signed in. The password
and the email factor stay.
- Verify the user out of band first. Whoever talks you into a reset still needs
  the password, and the user gets a mail ("Your Account's Sign-in Settings
  Changed", purpose `security_change`).
- Console: Accounts, the account, "Two-factor sign-in" panel. Give a reason and
  confirm.
- Or: `curl -XPOST -u admin:$ADMIN -H 'content-type: application/json' -d '{"did": "DID", "reason": "verified by video call", "actor": "you"}' $NODE/xrpc/vlpds.admin.resetSecondFactors`.
  The reason is required (2,000 characters at most).
- If someone other than the owner may be signed in now, tick "Also sign out
  everywhere" (`"revokeSessions": true`): it also ends every session and
  device sign-in, as a password change does.
- Audited as `second_factors.reset` in the console's Moderation page, Audit log
  tab: an entry marked `started` before anything changes, then one marked
  `done` with what was removed (`passkeys`, `totp`, `trustedBrowsers`,
  `signedOut`), or `failed` with the error. A `started` with no `done` after
  it means the reset may have stopped partway; run it again.
- Counted in `vlpds_passkeys_total{event="reset"}` when it removed passkeys.
- The user signs in with the password (plus an emailed code, if that's on) and
  sets up two-factor again on the Security tab.

### A passkey flagged as copied

A hardware key (one that can't be synced) reported a signature counter older
than the last one vlpds saw. That means a cloned key or a replayed signature.
- The sign-in is refused, the key is flagged (Security tab: "Refused: looks
  copied"), and the owner gets a `security_change` mail.
- Counted in `vlpds_passkey_counter_regressions_total{result="refused"}`.
  `{result="accepted"}` is a synced passkey (iCloud Keychain, Google Password
  Manager), whose copies are expected, so it isn't refused.
- A flagged key stays refused. The owner removes it on the Security tab and
  adds it again if it's theirs. If it wasn't them, tick "Sign out everywhere"
  and change the password.
- Many at once across accounts: check `vlpds_passkey_failures_total{reason}`
  for a pattern and look at the accounts' recent sign-ins.

### Cancelling a scheduled deletion

A deactivated account with a `deleteAfter` is deleted once that date and
`--delete-after-min-hold-days` (3) since deactivation have both passed (docs
`operations/email-and-moderation.md` "Scheduled deletion"). The deletion
can't be undone, so act before the date.
- Confirm: the console's account page shows "Scheduled for deletion on …", and
  `vlpds admin account info DID` shows `deletionScheduledAt`.
- The user reactivates on the account page ("Deactivate or delete", Reactivate
  account). That clears `deleteAfter`.
- Or as admin, reactivate:
  `curl -XPOST -u admin:$ADMIN -H 'content-type: application/json' -d '{"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "DID"}, "deactivated": {"applied": false}}' $NODE/xrpc/com.atproto.admin.updateSubjectStatus`.
  With `"applied": true` instead, the account stays deactivated and the
  deletion is cancelled.
- The sweep skips a taken-down or suspended account until the takedown is
  reversed.
- To stop every scheduled deletion, set `--delete-after false` on every node
  (rolling restart). Each node sweeps its own shards every 10 min.

### A handle check that fails

The account page checks a new handle with `vlpds.identity.checkHandle` before
switching (docs `operations/email-and-moderation.md` "Changing a handle on the
account page"). It shows the DNS and HTTPS results separately.
- "That domain points at a private address": the domain resolves to a private
  or other non-public address, so the guarded client won't fetch
  `/.well-known/atproto-did`. Use the DNS TXT record
  (`_atproto.<handle>` = `did=<DID>`), or point the domain at a public address.
- DNS found another DID: DNS wins over the file, so fix or remove that TXT record
  even if the file is right. Several `did=` records count as none.
- "Taken" means another account on this server holds the handle.
- DNS not found but the user says it's set: see "External handles" in
  "Moderation service, earned invites, external handles".
- 429: 60 checks per 5 min and 1,000 a day per account
  (`vlpds.identity.checkHandle-*`). Lift with a DID override in the console's
  Rate limits tab.

---

## What NOT to do

- Never run two processes with the same `--node-id`. At startup a node fences
  the log of the previous incarnation of its id. The one already running then
  hits the fence on its next segment PUT and exits 3. With a supervisor
  restarting both, they keep fencing each other.
- Never delete or edit objects by hand under `log/`, `assign/`, `nodes/`,
  `writers/`, `retain/`, `state/` or `cluster/` (`cluster/version`):
  - `log/`: segments are the WAL, and anything a shard hasn't checkpointed lives
    only there. A missing segment is a hole. Readers stop there, and replay
    treats a hole inside a span as an error.
  - Fence objects in `log/` are what makes a zombie of that incarnation
    fail-stop, whatever its clock says. Retention keeps a retired dead log's
    fence for `--fence-retention` (default 7 days, `off` = forever) and then
    deletes it (`vlpds_retention_deleted_objects_total{log="fence"}`). A zombie
    paused longer than that (a suspended VM whose monotonic clock stopped) would
    find no fence when it wakes. So don't pause VMs (below), and raise
    `--fence-retention` (or set it to `off`) where a pause that long is possible.
  - `cluster/version` is the cluster's feature level. Only `vlpds admin cluster
    finalize` / `cluster lower` change it.
  - `assign/` holds each shard's epoch and span history, which is what
    successors replay. `assign/layout` is the slot map.
  - `nodes/` and `writers/`: deleting a live lease or claim breaks liveness and
    seq uniqueness.
  - Retention deletes old log segments safely, so let it.
- Never run `--lease-ttl-ms` below 10 s in production (the node warns). The
  renewal ceiling is 0.4 x TTL.
- Don't SIGKILL for routine restarts. Use SIGTERM and wait.
- Don't suspend or snapshot-pause a running node's VM. A paused monotonic clock
  makes the node think its lease is still valid on wake. It serves stale reads
  until its next PUT hits the fence (it still acks nothing). That relies on the
  fence still existing, and a node paused longer than `--fence-retention`
  (7 days by default) wakes after its fence was deleted.
- Don't let host clocks drift. Offsets don't affect safety, but they delay the
  merged firehose by the largest offset, and a new owner waits out the previous
  owner's `seq_floor` (up to 30 s) before serving.
- Don't point two clusters at the same bucket + prefix. Don't change `--shards`
  expecting it to reshard an existing prefix either. It only applies when a
  prefix is created, so use split/merge.
- Never retire an old KEK (`--kek-old-file`, a KMS key version) before
  `vlpds.admin.rewrapSecrets` with `dryRun` reports `stale: 0` on every node.
  Never destroy KEK material that backups still need.
- Don't shrink `--log-retention` below what firehose consumers need for cursor
  resume. Older cursors get `OutdatedCursor`.

---


## Metric gaps

Signals these alerts would want, but that no metric exports today (so
`alerts.yml` doesn't invent them):

1. Per-log firehose watermark lag (merge input lag per source log) and clock
   offset between nodes. These are only visible in `getClusterStatus`.
2. A cluster identity label on metrics (all alerts assume one cluster per
   Prometheus).
3. Hit/miss counters for the in-memory caches other than the proxy fast path.
4. The specific cause of an exit 5 in `vlpds_last_exit_reason_info`.
   `lease_lost` covers a CAS conflict, a lapse before renewal, the watchdog, a
   reassigned shard, a failed close and an unquiesced log. The log line before
   the exit tells them apart. `vlpds_lease_renew_errors_total{kind="conflict"|"lapsed"}`
   covers two of them, but it dies with the process.
5. Lease validity between scrapes. `vlpds_lease_validity_seconds` is computed
   at scrape time, so dips shorter than the scrape interval are only visible
   through the renewal histogram.

Closed (these were gaps when the alerts were first written):

| Gap | Now |
|---|---|
| Lease renewal RTT and failures | `vlpds_lease_renew_seconds` (histogram, 1 ms .. 8 s), `vlpds_lease_renew_errors_total{kind=timeout\|error\|conflict\|lapsed}` |
| Lease validity remaining | `vlpds_lease_validity_seconds{node_id}` (at scrape, negative = lapsed) |
| Fail-stops unscrapeable | `vlpds_last_exit_reason_info{reason,code}` + `vlpds_last_exit_time_seconds` from the exit-state file on the next start, and `vlpds_peer_takeovers_total{reason=peer\|restart}` on the fencer ([exit codes](#tools-endpoints-cli-logs-exit-codes)) |
| Process start time | `vlpds_process_start_time_seconds` and `process_start_time_seconds` |
| Replay activity | `vlpds_recovery_replayed_segments_total` (wired), `vlpds_recovery_replay_seconds`, `vlpds_shard_open_seconds{kind=replay\|clean}`, `vlpds_shards_opened_total{result}` |
| Shard count (was the hand-kept `vlpds:expected_shards`) | `vlpds_shard_layout_shards`, and `vlpds:layout_shards` derives from it |
| Memory limit (was the hand-kept `vlpds:memory_limit_bytes`) | `vlpds_memory_limit_bytes` |
| Repo cache capacity | `vlpds_repo_cache_capacity_bytes` (all workers) |
| Object-store errors/latency on vlpds' own clients | `vlpds_object_store_requests_total{...,result=ok\|not_found\|precondition\|timeout\|error\|cancelled}`, `vlpds_object_store_request_seconds{op,component}` (every request through `objstats.rs`: control plane, segments, replay, backfill, retention, SlateDB) |
| Retention pass duration, dead-log holdings | `vlpds_retention_pass_seconds`, `vlpds_retention_dead_logs{state=unfenced\|needed\|pruning\|fenced}` (fenced = pruned to its fence, kept for `--fence-retention`), `vlpds_retention_dead_log_segments` |
| Lease configuration (alert thresholds were fixed for a 10 s TTL) | `vlpds_lease_ttl_seconds`, `vlpds_lease_renew_interval_seconds`, `vlpds_lease_skew_seconds`, `vlpds_lease_renew_ttl_ratio` (renewal round trip / TTL) |
| Firehose budgets (alerts hard-coded the defaults) | `vlpds_firehose_merge_queue_budget_bytes`, `vlpds_firehose_max_lag_bytes` |
