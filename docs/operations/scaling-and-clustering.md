---
title: Scaling and clustering
section: Operations
order: 107
status: ready
summary: "Growing from one node to many: adding and removing nodes, how shards rebalance, splitting and merging shards, peer TLS, and sizing rules."
---

```hero
diagram:
  caption: "Adding capacity is starting another node on the same bucket and prefix. Once every peer follows the new node's log, nodes above the fair share (shards ÷ live nodes) hand their extras straight to it. Three nodes and 64 shards shown; the counts are examples."
  nodes:
    - { id: a, label: node A, sub: "32 → 22 shards", at: [0, 0], size: [8, 3], tone: accent }
    - { id: b, label: node B, sub: "32 → 21 shards", at: [0, 6], size: [8, 3], tone: accent }
    - { id: c, label: new node C, sub: "0 → 21 shards", at: [14, 3], size: [9, 3], tone: blue }
    - { id: bucket, label: same bucket + prefix, sub: "assign/ · nodes/ · log/", at: [29, 3], size: [11, 3], shape: store, tone: amber }
  edges:
    - { from: a.r, to: c.l30, label: handback, dash: true, labelAt: [9.6, 4.5] }
    - { from: b.r, to: c.l70, dash: true }
    - "c -> bucket: lease · CAS"
    - { from: a.r, to: bucket.t, via: [[34.5, 1.5]] }
    - { from: b.r, to: bucket.b, via: [[34.5, 7.5]] }
facts:
  - { value: "2", unit: nodes, label: are enough for high availability, note: "leases and ownership are CAS on bucket objects; no quorum" }
  - { value: "60%", label: CPU after losing a node, note: "(nodes − 1) × cores × 0.6 ≥ busy cores", tone: amber }
  - { value: "~0.2 s", label: per shard handed over, note: "planned moves: barrier, checkpoint, open on the new owner", tone: blue }
  - { value: "64", unit: shards, label: default layout, note: "65,536 hash slots; split and merge online", tone: violet }
```

One node and a cluster run the same binary against the same bucket layout. A single node owns every
shard. More nodes spread the shards out, and shards move by themselves as nodes join and leave. The
mechanisms (leases, takeover, handback) are in [Architecture](../architecture.md#shards-and-ownership).

> [!NOTE]
> The Ansible role runs a lone node until `vlpds_cluster_enabled` is set. After that it sets the
> peer flags below on every node. See [With the Ansible role](#with-the-ansible-role).

## Sizing rules

```facts
- { value: "~185–240 µs", label: CPU per commit, note: "whole process at 25–50k/s, HTTP and cold loads included · measured on 16 cores" }
- { value: "~50 µs", label: CPU per proxied request, note: AppView reads dominate CPU, tone: blue }
- { value: "~20 ms", label: CPU per password login, note: "Argon2 · at most one per core (16 max) at once", tone: amber }
- { value: "10–20 KB", label: memory per active repo, note: only the MST paths recent writes touched, tone: violet }
```

Most of the CPU goes to logins and proxying. Size a cluster so that the survivors stay under ~60% CPU
after losing one node. That works out to (nodes − 1) × cores × 0.6 ≥ busy cores, fleet-wide.

| | Personal | Bluesky today | 10× Bluesky |
|---|---|---|---|
| Load | a few commits a day | ~330 commits/s avg, ~900 bursts · 20k proxied req/s (assumed) | ~3.3k avg, ~9k bursts · 200k req/s |
| Busy cores, fleet-wide | ~0 | ~3 | ~25 |
| Nodes | 1 small VM (`tiny` profile) | 3 × 6–8 cores, 32 GB, ~1 TB NVMe | 3 × 24 cores / 128 GB, or ~8 small nodes |
| Shards | 1 | 64 | 64, split the hot ones |

- Add a fourth node at ~2.4× today's load. That's ~7 busy cores (2 survivors × 6 cores × 60%).
- Memory follows active repos. A day's writers' MST paths come to ~5 GB per node at Bluesky's load
  on 3 nodes, and ~50–75 GB at 10×. The node sizes its caches from its memory limit (see
  [Configuration](configuration.md#memory-budget-and-autosizing)).
- The shard count drives the object-store bill, since polling, checkpoints and GC are per shard.
  Start at 64 (~875k repos each at Bluesky scale) and split hot or large shards. Running 64 instead
  of 256 saves ~$800/mo on S3.
- Writer ids are one byte (the low byte of every seq), so a cluster can't go past 256 live node
  incarnations.

These numbers come from DESIGN.md "Initial deployment sizing" and the benchmark campaigns
(`bench/results/`), and they're estimates. The largest runs so far are 100 M bulk-created accounts
on 4 nodes and ~60k commits/s on one 16-core node.

Full nodes serve AppView proxying and the firehose, and there's no separate read or fan-out tier.
To serve more, add full nodes. Consumers that can't take the whole stream use `?shard=k/n` (see
[Firehose](../firehose.md#sharded-subscriptions)).

## Adding a node

```steps
- title: Give it the cluster's identity
  body: "Its own unique `--node-id`, plus the same bucket, prefix, KEK, `--jwt-secret`, `--admin-token`, `--internal-token` and PLC rotation key as every other node."
- title: Give it a peer certificate
  body: "Issue a node certificate from the cluster CA for its id and peer host (see below). Set `--peer-listen`, `--peer-tls-dir` and `--advertise-url https://<host>:<peer port>`, using an address every peer can reach."
- title: Start it
  body: "It writes its lease and greets every peer. It doesn't count as joined until every live peer follows its log, so the merged firehose never misses its entries."
- title: Peers hand back shards
  body: "Each peer above the new fair share (`ceil(shards / live nodes)`) closes its extras with a barrier and checkpoint and hands them straight to the joiner. The joiner opens them with little or nothing to replay."
- title: Scrape it and check the balance
  body: "Add the target to Prometheus (job `vlpds`). The `owned` count per node in `vlpds admin cluster status` should converge, and `VlpdsOwnershipImbalanced` should stay quiet."
```

Don't list nodes in `--trusted-proxies`. A forwarding node already passes the client's address
over the internal token, so only real load balancers go there. Going from one node to two needs no
migration, because the lone node's prefix is already a cluster of one. The procedure is RUNBOOK
[Adding a node](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#adding-a-node).

## Removing a node

```steps
- title: Send SIGTERM
  body: "Don't use SIGKILL. The node marks its lease `draining`, so peers stop counting it toward fair shares."
- title: It hands its shards out
  body: "Each shard closes with one barrier segment and a checkpoint and goes straight to a settled peer, which opens it without replaying anything (~0.2 s a shard)."
- title: It fences its own log and deletes its lease
  body: "Followers drain the log up to the fence and drop it as a firehose source. The node keeps answering for 500 ms, closes its firehose subscribers (they resume from their cursors) and exits 0 as soon as its last request in flight is answered."
- title: Peers rebalance
  body: The fair share is recomputed over the remaining nodes. Don't restart the process if the node is leaving for good.
```

Give the supervisor a stop timeout of at least 60 s, since the close barrier may wait 30 s and the
quiesce 10 s. The Ansible role defaults to 90 s (`vlpds_stop_grace_period`) and refuses less than 60 s. A stop that times out into SIGKILL turns into a crash, which peers handle with a fence
and a replay. If the node can't fence its own log (store errors for min(TTL, 30 s)), it exits 8 and
keeps its lease. Peers then presume it's dead and fence it themselves. A crashed node is noticed once
its lease goes quiet. That takes ~12 s at the default 10 s TTL, or 3–5 s if its port refuses
connections (see [Architecture](../architecture.md#failure-and-takeover)).

## With the Ansible role

Every node in the inventory group shares the bucket, prefix, identity and secrets (group vars). Each
one has its own node id, sizing and peer address (host vars). Peers talk over the private network.
Each node publishes its peer port on loopback and `tailscale serve` forwards it from the node's
private address, so the peer port is never on a public interface. TLS passes straight through to
vlpds.

To add a node, starting from one running node:

```steps
- title: Make the cluster CA, once
  body: "Run `vlpds admin tls ca --out ./pki`. `ca.crt` goes in the group vars (`vlpds_peer_tls_ca_cert`). Keep `ca.key` offline and off every node."
- title: Issue a certificate per node
  body: "Run `vlpds admin tls issue --ca ./pki/ca.crt --ca-key ./pki/ca.key --out ./pki --node-id <node id> --host <its private address>` for every node, including the running one. Each node's certificate goes in its host vars (`vlpds_peer_tls_cert`), its key in its encrypted host vars (`vlpds_peer_tls_key`) and its address in `vlpds_peer_host`."
- title: Let the nodes reach each other
  body: "Allow node-to-node TCP on `vlpds_peer_port` (2584) in the private network's access policy. Nothing public changes."
- title: Make the running node a cluster of one
  body: "Set `vlpds_cluster_enabled: true` and run the playbook. The node restarts once, gracefully, with `--peer-listen`, `--advertise-url` and `--peer-tls-dir`. `vlpds admin cluster status` still shows it owning every shard."
- title: Provision the new node
  body: "Run `playbooks/bootstrap.yml` for the fresh host, then enable it in the inventory and run the playbook (one node at a time). It starts on the same bucket and prefix, and the running node hands it its fair share."
- title: Send it traffic
  body: "Point DNS at it too, or instead. With wildcard handle certificates, set `vlpds_caddy_hostname_dns01: true` first so the new node's Caddy holds the hostname's certificate before DNS sends it requests. Add its metrics target (Alloy does, through the same role)."
```

A prefix made with the `tiny` profile has one shard. One node owns it and the others forward to it,
which is enough for failover. Split it (below) to spread writes out. Takeover after a crash waits
about one lease TTL plus the skew (132 s on `tiny`) unless the dead node's port refuses connections.
A lower `vlpds_lease_ttl_ms` shortens that in exchange for more object-store requests and a shorter
stall margin.

To remove a node, move DNS away from it first. Then stop it with `docker compose down` in
`/opt/vlpds` and take it out of the inventory. The stop sends SIGTERM with the 90 s grace period, so
the node hands its shards out (see [Removing a node](#removing-a-node)). The playbook refuses to run
two enabled nodes while `vlpds_cluster_enabled` is off, because two lone nodes on one prefix never
talk to each other.

## Shard split and merge

```diagram
caption: "A split is a metadata-only SlateDB clone: each child's manifest references the frozen parent's SSTs and its own slot range, whatever the parent's size. Ids are never reused; a split takes two new ones. The children compact the inherited SSTs into their own over time, and the parent's directory is deleted after that."
nodes:
  - { id: p, label: shard 7, sub: "slots 7168–8191 · frozen", at: [0, 2.5], size: [10, 3], tone: muted }
  - { id: c1, label: shard 64, sub: "slots 7168–7679", at: [17, 0], size: [9, 3], tone: accent }
  - { id: c2, label: shard 65, sub: "slots 7680–8191", at: [17, 5], size: [9, 3], tone: accent }
  - { id: sst, label: "state/0000000007/", sub: SSTs read in place, at: [32, 2.5], size: [11, 3], shape: store, tone: amber }
edges:
  - { from: p.r, to: c1.l, label: clone }
  - { from: p.r, to: c2.l }
  - { from: c1.r, to: sst.l30, dash: true }
  - { from: c2.r, to: sst.l70, label: external SSTs, dash: true, labelAt: [30.5, 7.4] }
```

```steps
- title: Plan
  body: "Run `vlpds admin shard-split <shard> [--at <slot>]` or `shard-merge <left> <right>` (adjacent shards only) on any node. The op is recorded in `assign/layout` with its new shard ids. The cluster runs one op at a time."
- title: Freeze
  body: "Each parent's owner closes it like a release (barrier, checkpoint) and marks it frozen. From here its slots answer 503 `PartitionUnavailable`, which clients retry."
- title: Clone
  body: "The driver clones the children from the frozen parents. The work grows with the size of the manifest and doesn't depend on how much data the shard holds."
- title: Flip
  body: "A compare-and-swap moves the layout to the next version. The children become ordinary shards. The driver opens them and nudges every peer, and fair shares rebalance them later. `reshard-abort` only works before this point."
```

`vlpds admin layout` shows the layout and any op in progress. Every node exports
`vlpds_shard_layout_shards` and `vlpds_shard_layout_version`, and the ownership alerts read the
count from there. Shard ids are u32 and never reused, so after a few ops the ids no longer match
positions. `state/{id}/` and `assign/{id}` use ten-digit ids.

- Automatic splits are off by default. Set `--reshard-split-mb` (SST bytes) or
  `--reshard-split-writes` (state mutations per second), and the owner of slot 0's shard plans
  splits of shards past either threshold, one at a time.
- Retired parents stay around while a child still reads their SSTs. If a child hasn't rewritten
  them `--forced-detach-after` (5 min) after it opened, it gets one compaction to do it. The
  parent's state directory and assignment are deleted `--reshard-gc-grace` (1 h) after nothing
  references them. `VlpdsRetiredStateGrowing` and `VlpdsReshardGcFailing` watch this.
- `--shards` only applies to a new prefix. Changing it later does nothing, so use split and merge.
- The firehose, `?shard=k/n` subscriptions and `listRepos` cursors are by slot, so a reshard doesn't
  disturb consumers.

How the layout and clones work: [State storage](../state-storage.md#shard-split-and-merge).

## Peer TLS

```diagram
caption: "Node-to-node traffic (forwarded requests carrying users' tokens, `/internal/*`, log streams) runs over HTTP/2 with TLS 1.3 and client certificates on `--peer-listen`. There is no cleartext mode. The CA key stays offline."
nodes:
  - { id: ca, label: cluster CA, sub: "ca.key offline", at: [0, 3], size: [8, 3], tone: violet }
  - { id: na, label: node A, sub: "node-a.crt · ca.crt", at: [14, 0], size: [9, 3], tone: accent }
  - { id: nb, label: node B, sub: "node-b.crt · ca.crt", at: [14, 6], size: [9, 3], tone: accent }
  - { id: check, label: Peers check, sub: "chain · host · node id", at: [29, 3], size: [10, 3], shape: note, tone: muted }
edges:
  - { from: ca.r, to: na.l, label: issue }
  - { from: ca.r, to: nb.l }
  - "na <-> nb: mTLS"
  - { from: na.r, to: check.l30, dash: true }
  - { from: nb.r, to: check.l70, dash: true }
```

A lone node doesn't need any of this. Without `--peer-listen`, `--peer-tls-dir` and
`--advertise-url` (always set together), it opens no peer listener and makes no peer calls. A
cluster needs this:

```bash
vlpds admin tls ca --out ./pki                                  # once: ca.crt, ca.key (0600)
vlpds admin tls issue --ca ./pki/ca.crt --ca-key ./pki/ca.key --out ./pki \
  --node-id node-a --host 10.0.0.5                              # per node; 365 days (--days)
# on node-a: ca.crt, node-a.crt, node-a.key in one directory, then
vlpds --node-id node-a --peer-listen 0.0.0.0:2584 \
  --advertise-url https://10.0.0.5:2584 --peer-tls-dir /run/vlpds/peer-tls ...
```

- A node certificate names its node in a `vlpds://node/<node-id>` URI and carries its advertise host.
  Peers check the chain, the host, and that the certificate names the node whose lease advertises
  that address. The internal token is still required on top.
- Startup refuses a certificate that doesn't chain to the CA, is expired, names another node or
  doesn't match its key.
- Renew before `VlpdsPeerTlsCertExpiring` fires (14 days). Re-issue with `--force`, replace the
  files and send SIGHUP (or wait for the 60 s file poll). It doesn't need a restart. CA rotation goes
  through a bundle of the old and new CA.
- `--dev-mode` nodes sharing a `--peer-tls-dir` make their own CA and certificates. Don't use this
  in production, because the CA key sits next to the nodes.

Renewal and CA rotation, step by step: RUNBOOK
[Peer TLS](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#peer-tls-mtls-between-nodes).
Why it's built this way: [Keys and security](../keys-security.md#peer-tls).
