---
title: Privacy guardrails
section: Spaces
order: 204
status: draft
summary: "What keeps space data private on vlpds: no firehose path, no proxy escape, the blob rule, audited operator access and takedowns. Each guardrail has a test."
---

```hero
diagram:
  caption: "The privacy line. A space write is stored and served only to credentialed readers. None of the paths on the right may ever carry it, and the leak tests plant sentinels to prove it."
  nodes:
    - { id: w, label: Space write, sub: "values · rkeys · URIs", at: [0, 4.2], size: [9, 3], tone: ink }
    - { id: e, label: Private entry, sub: "`s*` rows · empty frame", at: [12.5, 4.2], size: [9, 3], tone: accent }
    - { id: rd, label: Credentialed reads, sub: "space.* only", at: [12.5, 10], size: [9, 3], tone: ok }
    - { id: fh, label: Firehose, sub: "live · sharded · cursor · S3 · peers", at: [27, 0], size: [13, 3], tone: danger }
    - { id: pub, label: Public repo, sub: "sync.getRepo · rev · commit", at: [27, 4.2], size: [13, 3], tone: danger }
    - { id: px, label: Other hosts, sub: "via atproto-proxy", at: [27, 8.4], size: [13, 3], tone: danger }
  edges:
    - "w -> e"
    - { from: e.b, to: rd.t, label: served }
    - { from: e.r, to: fh.l, label: never, dash: true, tone: danger }
    - { from: e.r, to: pub.l, label: never, dash: true, tone: danger }
    - { from: e.r, to: px.l, label: "501 here", dash: true, tone: danger }
facts:
  - { value: "0", unit: sentinels, label: found on any public path, note: "single node and three nodes", tone: ok }
  - { value: "501", label: for an unhandled space method, note: "answered locally · never proxied", tone: rust }
  - { value: "3,610 s", label: a revocation is held, note: "longer than any credential can live", tone: violet }
  - { value: audited, label: operator reads, note: "admin or moderator · reason in the log", tone: muted }
```

A space controls who can read its data, but there's no encryption, so the guardrails are in how
vlpds stores and routes it. Each one below says how it holds and what tests it.

## No firehose leak

A space write is a private log entry with no frame ([How vlpds stores it](storage.md#private-log-entries)),
so nothing that reads frames can see it. The leak tests write records full of sentinel strings and
then look for them everywhere data leaves the node.

| Sentinels planted | Where the tests look |
|---|---|
| record values and field names | the live `subscribeRepos` stream |
| rkeys and the collection | a `?shard=k/n` stream |
| the space type, skey and URI | a cursor-0 replay from segments |
| the space id (`sid`) | a raw replay of the segments in the bucket |
| record CIDs | the author's `sync.*` and `repo.*` surface |
| | the peer log stream between nodes |

They also check that the author's public commit and rev don't move, and that every log entry with
`s*` keys has an empty frame. Nothing was found on one node or across three nodes (every stream,
shard, cursor replay, S3 backfill and peer log stream). The interop harness runs its own leak check in
every configuration, and it passes too.

## No proxy escape

With `--spaces` on, every `com.atproto.space.*` and `com.atproto.simplespace.*` method is answered on
this node. One that isn't built yet answers 501 `MethodNotImplemented`. It never reaches the
`atproto-proxy` fallback, where vlpds would mint service auth for it and send it to another host. With
`--spaces` off they answer 501 too and are never proxied either, so an app can't get the node to
sign a `notifyWrite` as one of its users and send it somewhere.

## Blobs

```diagram
caption: "With `--spaces` on, `sync.getBlob` serves a blob only once a public record references it. A blob that only space records reference is served by `space.getBlob`, to a credential for that same space."
nodes:
  - { id: up, label: uploadBlob, sub: "stored · no refs yet", at: [0, 4.2], size: [9, 3], tone: ink }
  - { id: pubr, label: Public record refs it, sub: "`b/`", at: [13, 0], size: [10, 2.8], tone: accent }
  - { id: spr, label: Only space records, sub: "`sb/`", at: [13, 4.3], size: [10, 2.8], tone: accent }
  - { id: none, label: Nothing refs it, at: [13, 8.6], size: [10, 2.8], tone: muted }
  - { id: s1, label: sync.getBlob serves it, at: [27, 0], size: [12, 2.8], tone: ok }
  - { id: s2, label: space.getBlob only, sub: same space's credential, at: [27, 4.3], size: [12, 2.8], tone: violet }
  - { id: s3, label: BlobNotFound, sub: "vlpds serves these today", at: [27, 8.6], size: [12, 2.8], tone: danger }
edges:
  - up.r -> pubr.l
  - up.r -> spr.l
  - up.r -> none.l
  - pubr -> s1
  - spr -> s2
  - none -> s3
```

The last row is a change. Without `--spaces`, vlpds serves a blob as soon as it's uploaded, which
would leave a window where a blob meant for a space can be fetched by CID before the space write.
With `--spaces` on, that window closes. The blob GC counts both `b/` and `sc/` refs, `sync.listBlobs`
lists only `b/`, and quotas stay bytes per account with space blobs included. A blob that only
taken-down records name is hidden from `space.getBlob` and `listBlobs` too.

Space refs outlive the flag, since the GC keeps their blobs whether it's on or not. So a node that
comes back without `--spaces` still answers `BlobNotFound` for a blob only space records name.
Everything else is served as it was without the flag.

That check costs nothing for most accounts. The node works out once per account whether any space
record names one of its blobs, and keeps the answer for as long as it holds the account's shard. An
account with no space blob refs reads no ref at all, so its getBlob is what it was before Spaces:
p50 30 µs against 37–43 µs with the per-blob check, over HTTP on one in-process node. An account
with space blob refs still checks each blob.

## Operator access

Nothing is encrypted, so whoever runs a PDS can read the space data on it. vlpds makes that an
explicit path with an audit trail. Moderators and admins can read space records for
terms-of-service work, and nobody else can use these methods (an account's own OAuth token, its
password session and its app passwords are all refused).

| Method | Returns |
|---|---|
| `vlpds.admin.getSpaceRecord` | one record as `space.getRecord` answers it (`uri`, `cid`, `value`), plus `takendown` |
| `vlpds.admin.listSpaceRecords` | an account's records in one space, values included, 100 a page |
| `vlpds.admin.getSpaceRepo` | the repo's rev, record count, creation time and taken-down records |

Each call writes a `space.read` entry to the moderation audit log (`vlpds.admin.getAuditLog`) before
it reads anything. The entry names who asked, from which IP, the space, the account and the record,
and the reason when one is given. A read that fails auth writes nothing. Taken-down records are
shown to the operator, flagged.

The console's Look up takes space URIs. A space record shows what it is (its author, whether it
exists, its takedown state) but never what it says. It leaves out the CID too, which would let an
operator confirm a guessed value. Reading the value is a separate
"Read record" step that asks for a reason and goes through `getSpaceRecord`, so every value an
operator sees has its own audit entry. `vlpds admin check-space` reports a repo's head and record
paths, so it writes an audit entry as well.

Logs and the console's rate-limit pages are the other places an operator could pick up space
metadata, since skeys and rkeys are often meaningful names. So vlpds logs a space by its 32-character
hex id and leaves member DIDs and record paths out of its log lines. That includes the errors of
its own outbound calls, whose URLs can name a space and a member in their query, so they're logged
without the URL. The two rate limits keyed by who
talks to which authority (`space-credential` and `space-read-credential`) show a keyed hash of the
pair in the console.

## Revoked credentials

A revoked credential never reads again. When a revocation can't be stored (its caps are full), the
space's credentials are refused instead, on every node and across restarts, until the credentials
it named have expired. Past 100 blocked spaces of one authority the whole authority is refused,
and past 1,000 such authorities every remote authority is, but never one hosted here. Nothing about
a block fails open ([Revocation](reading.md#revocation)).

## Takedowns

| Takedown | What happens to space data |
|---|---|
| Account | Credential reads of its space repos get `RepoTakendown`. Its space writes are refused. Its outbox rows wait and resume if the takedown is reversed. Its OAuth sessions are revoked and stay revoked after a reversal, so apps have to sign in again. |
| Record | Taken down by its space URI, through the same admin and moderation paths as a public record (`sec/td/space/{sid}/{collection}/{rkey}`). It's hidden from `getRecord`, `listRecords`, `listRepoOps` values and `getRepo`'s blocks. |
| Space | Taken down at its authority, by its space URI (`updateSubjectStatus` with a `strongRef`, or the console). `getSpaceCredential` answers `NotAuthorized`, `listRepos` and `registerNotify` answer `SpaceNotFound`, credential reads of members' repos on the authority's host answer `SpaceNotFound` too (a credential minted before the takedown included), and members' notifies are acknowledged and dropped. Registered syncers get no more forwards, the authority's own writes included. The records stay on their authors' hosts. A vlpds extension. |

No credential names a taken-down account either. A taken-down account mints no delegation tokens,
and `getSpaceCredential` refuses a taken-down member (`AccountTakedown`) and a space whose authority
is taken down (`RepoTakendown`). The authority's host methods (`listRepos`, `registerNotify`,
`unregisterNotify`) refuse a credential it issued before its takedown with `RepoTakendown`. The
reference admits all of these.

The reference has no record takedown for space data at all, so record takedowns are a vlpds
extension. The record stays in sR, and the LtHash stored with the head keeps it, the way a
taken-down public record stays in the signed repo.

```timeline
caption: "The takedown-adjusted view. While a takedown lasts, every read signs a commit over the repo without the record, so a syncer that held it sees a mismatch at the same rev, refetches and converges. A reversal flips it back the same way."
scale: 46
lanes:
  - { id: op, label: Operator, tone: muted }
  - { id: pds, label: Author's PDS, sub: vlpds, tone: accent }
  - { id: s, label: Syncer, sub: held the record, tone: blue }
spans:
  - { lane: pds, from: 1.4, to: 5.0, label: adjusted commit, dur: "set hash − the record" }
  - { lane: s, from: 5.6, to: 7.4, label: mismatch, tone: danger }
  - { lane: pds, from: 9.6, to: 13.4, label: getRepo without it }
arrows:
  - { from: op, to: pds, at: 0.6, label: take down record }
  - { from: s, to: pds, at: 1.2, side: left, label: listRepoOps, tone: blue }
  - { from: pds, to: s, at: 5.3, label: "same rev, new hash", tone: blue }
  - { from: s, to: pds, at: 8.8, label: getRepo, tone: blue }
  - { from: pds, to: s, at: 13.6, side: left, label: verified repo, tone: blue }
marks:
  - { at: 14.2, label: converged, tone: ok }
```

The adjusted view is cheap because a repo's taken-down set is tiny. The set hash is the LtHash state
minus the taken-down records' elements, and the commit is signed at serve time like every other one.
`listRepoOps` leaves the record's ops out while the takedown lasts, so the incremental and the full
views agree.

A syncer doesn't have to poll to find out. When a record is taken down or the takedown is reversed,
the author's host sends its authority a notify at the same rev with the hash it now serves, and the
authority sequences it like any other. So `listRepos` shows the new hash within a few milliseconds
(~1 ms for a takedown in the tests), and every registered syncer gets a forward with the same rev
and a different hash. That's the spec's signal to fall back to `getRepo`. The rev doesn't move,
since nothing was written. The push isn't logged, so if the author's host crashes before it goes,
syncers find out on their next poll instead. Every notify works out the served hash when it's sent,
so a resent row never puts the old hash back at the authority. An authority's own records work the
same way, and so do its writes while one of its records is down.

Every such forward sends each syncer to a full `getRepo`, and any writer's host can sign a notify for
its own accounts. So a host could repeat its current rev with made-up hashes and make every syncer
of the space refetch the whole repo, again and again. An authority checks a same-rev notify from
another host before it sequences one. It reads the writer's `getLatestCommit` from the writer's PDS
with a credential it issues itself, and sequences the notify only if that commit verifies against
the writer's key at that rev with the notified hash. A notify it can't confirm (a made-up hash, or a
host that doesn't answer within 5 s) is acknowledged and dropped, and polls catch a real one up. It
also checks at most 3 of them per writer and space in 10 min and drops the rest unchecked, so a
host can't make it fetch at will either. Both show up in `vlpds_space_notify_total{hop="in"}` as
`same_rev_unverified` and `same_rev_capped`. A moderator's takedown and its reversal take two of the
3. Notifies from this cluster's own nodes need no check, since the cluster worked out the hash
itself.
