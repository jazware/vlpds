---
title: Backups and recovery
section: Operations
order: 105
status: ready
summary: "What is durable and where: one bucket prefix, the provider features that protect it, the two secrets to copy offline, and recovering from a lost host or a damaged repo."
---

```hero
diagram:
  caption: "Everything durable is in one prefix of one bucket; a node's disk is only a cache. Versioning, lifecycle rules and replication are features of the provider, set up there. The KEK and the PLC rotation key live outside the bucket and must be copied offline by hand."
  nodes:
    - { id: node, label: vlpds nodes, sub: disk is a cache, at: [0, 4], size: [8, 3], tone: accent }
    - { id: bucket, label: bucket + prefix, sub: "log · state · blobs · leases", at: [14, 4], size: [11, 3], shape: store, tone: amber }
    - { id: prov, label: Provider features, sub: "versioning · replication", at: [30, 4], size: [10, 3], shape: note, tone: muted }
    - { id: keys, label: "KEK · PLC key", sub: not in the bucket, at: [14, 10], size: [11, 2.6], tone: violet }
    - { id: offline, label: Offline copy, sub: by hand, at: [30, 10], size: [10, 2.6], tone: ok }
  edges:
    - "node -> bucket: every acked write"
    - { from: bucket.r, to: prov.l, label: optional, dash: true }
    - { from: keys.l, to: node.b, label: unwrap at start, via: [[4, 11.3]] }
    - { from: keys.r, to: offline.l, label: back up }
facts:
  - { value: "1", unit: prefix, label: holds all durable state, note: "a node's disk holds only caches", tone: amber }
  - { value: "2", unit: secrets, label: to copy offline, note: "the KEK and the wrapped PLC rotation key; without the KEK nothing in the bucket can sign", tone: violet }
  - { value: "0", label: data to restore after losing a host, note: "peers or a restart replay from the bucket", tone: blue }
```


Every acknowledged write is in the object store, so losing a node, a disk or a whole host loses
nothing. vlpds doesn't have backup or point-in-time restore tooling of its own. Beyond that, the
data is protected by the bucket's own durability and whatever you turn on at the provider.

## What is durable

All of a deployment's state is under one prefix of one bucket: `log/` (segments), `state/`
(SlateDB per shard), `blob/`, `assign/`, `nodes/`, `writers/`, `retain/`, `cluster/`, `handle/`,
`email/`, `config/` and the rest of the [bucket layout](object-store.md#bucket-layout). A node's `--cache-dir` only holds caches and the exit-state file, and
nothing in it has to survive.

| Protection | What it covers |
|---|---|
| Object-store durability | Losing hardware. S3 Standard is multi-AZ, and R2 and GCS have their own guarantees. It doesn't cover a delete, a bad build or losing the region. |
| Log segments (`--log-retention`, 72 h) | Firehose backfill and replay. They aren't a backup, because a bad build's entries are in them too. |
| `check-repo` / `rebuild-repo` | One repo whose derived state (MST nodes, indexes) is wrong. See [Repairing a repo](#repairing-a-repo). |
| Logical export | `com.atproto.sync.getRepo` CARs plus blobs per account (e.g. with goat). It's a cheap copy of a personal PDS's content, but it leaves out keys, password hashes, email, sessions and takedowns. |

Never delete or edit objects under the prefix by hand. The [Runbook](runbook.md#what-not-to-do)
explains why for each one.

## Provider features

These are settings on the bucket, and vlpds neither configures nor depends on them.

- Versioning (S3 and GCS, and GCS soft delete is similar) keeps an object's previous versions when
  it's overwritten or deleted, so you can bring a deleted object back at the provider. vlpds's
  conditional writes act on the current version. R2 has no object versioning.
- Lifecycle rules expire noncurrent versions after a number of days. vlpds's own retention and
  garbage collection delete objects all the time, so without such a rule versioning keeps every
  deleted segment and SST.
- Object Lock (S3) stops versions from being deleted before a retention date.
- Replication copies objects to another bucket, account or region. It's asynchronous and per
  object, so a replica can hold a manifest before the SSTs it names. That makes it a better fit for
  blobs (large, immutable) than for the log and state.

Give the nodes a key pair scoped to the bucket, with no right to delete object versions or change
bucket policy and lifecycle rules (on S3 IAM, no `s3:DeleteObjectVersion`). That way a leaked node
key can't undo versioning.

## Losing a host

```steps
- title: Nothing to do for data safety
  body: "In a cluster, peers fence the dead node's log and take its shards. That takes 3–5 s if its port refuses connections, and ~12 s plus replay if the host is unreachable (default 10 s lease). A lone node waits for you."
- title: Make sure the old process can't come back
  body: "Power it off. A zombie would find its log fenced or its shards reassigned and fail-stop, but don't rely on that."
- title: Start a replacement on the same bucket and prefix
  body: "Use the same secrets, and the same `--node-id` if you can (it fences its predecessor's log right away). It serves writes once its clock passes the predecessor's last lease expiry. That's ~11 s after a crash at a 10 s TTL, and ~53 s at the `tiny` profile's 60 s (measured)."
- title: Expect cold caches
  body: "Point `--cache-dir` at local NVMe. The SST disk cache starts empty, so the first reads and repo loads go to the bucket."
- title: Verify
  body: "Run `vlpds admin cluster status` and check that the lease is valid and every shard is owned. `vlpds_last_exit_reason_info` on the new process tells you how the old one ended."
```

There's nothing to restore. The bucket holds every acknowledged write, and the disk only ever held
a cache. The procedure is in the RUNBOOK under
[Replacing a dead host](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#replacing-a-dead-host),
and the takeover mechanics are in [Architecture](../architecture.md#failure-and-takeover).

## Repairing a repo

```steps
- title: Check it
  body: "`vlpds admin check-repo <did>` reads one shard snapshot and checks the head commit and signature, every record's hash, the MST rebuilt from the records, the persisted nodes and the indexes. It exits 1 if anything is wrong."
- title: Rebuild it
  body: "`vlpds admin rebuild-repo <did> [--dry-run]` re-derives the repo from its records under a new signed commit and emits `#sync`. It refuses if the records no longer rebuild to the head, because that means records were lost."
```

Node and index problems also heal on the next cold load. Details:
[Admin console and CLI](admin-console.md#admin-cli).

## Signing keys

```facts
- { value: "KEK", label: opens everything secret in the bucket, note: "signing keys, reserved keys and TOTP secrets are stored only wrapped under it", tone: violet }
- { value: "0", label: users who can sign after losing it, note: "every account would need a new key and a PLC rotation", tone: rust }
- { value: "> 72 h", label: keep a retired KEK at least, note: "longer than log retention and any copy holding secrets wrapped under it", tone: amber }
```

Account signing keys never sit in the bucket in the clear, so a copy of the bucket alone doesn't let
its reader sign as anyone. It does still hold password hashes (argon2id), app-password and
recovery-code hashes, and email-token digests. Two secrets live outside the bucket, and you have to
copy them offline when you set up a deployment:

- The KEK. If you lose a local KEK file, or a Cloud KMS key gets destroyed, no account can sign.
  Back the local KEK up offline (two copies). For Cloud KMS, use a multi-region key and the maximum
  destroy-scheduled duration, and use IAM to keep `cloudkms.cryptoKeyVersions.destroy` away from
  node and operator roles. For Vault Transit, keep `deletion_allowed` false and never `trim` the key.
  A Transit key can't be exported unless it was created exportable, so the key's only copy is in Vault's
  storage. Take Vault snapshots (`vault operator raft snapshot save`) on the same schedule as the bucket.
- The wrapped PLC rotation key. It needs the KEK to open.
- After a KEK rotation, keep the old KEK (or keep the old KMS version disabled rather than
  destroyed) for as long as any log segment or bucket copy may still hold secrets wrapped under it.

Details: [Keys and security](../keys-security.md#secrets-at-rest),
[KEK and key rotation](kek-and-key-rotation.md#kek-provisioning).
