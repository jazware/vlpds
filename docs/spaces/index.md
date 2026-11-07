---
title: Spaces
section: Spaces
order: 200
status: draft
summary: "Permissioned data on vlpds: every member keeps a private, signed space repo on their own PDS. It never reaches the firehose, and reading it takes a short-lived credential chain."
---

```hero
diagram:
  caption: "One space with three writers (simplified). alice's own DID is the authority, so her PDS also runs the space host. Each writer's records live in that writer's space repo on their own PDS. A reader who never writes has no repo."
  nodes:
    - { id: sp, label: Space, sub: "authority · type · skey", at: [13, 0], size: [14, 3], tone: violet }
    - { id: a, label: alice's PDS, sub: "authority · space host", at: [0, 6], size: [11, 3], tone: accent }
    - { id: b, label: bob's PDS, sub: member, at: [14.5, 6], size: [11, 3], tone: accent }
    - { id: c, label: carol's PDS, sub: member, at: [29, 6], size: [11, 3], tone: accent }
    - { id: ra, label: alice's space repo, sub: "records · LtHash · oplog", at: [0, 12], size: [11, 2.8], shape: store, tone: amber }
    - { id: rb, label: bob's space repo, sub: "records · LtHash · oplog", at: [14.5, 12], size: [11, 2.8], shape: store, tone: amber }
    - { id: rc, label: carol's space repo, sub: "records · LtHash · oplog", at: [29, 12], size: [11, 2.8], shape: store, tone: amber }
  edges:
    - { from: sp.b15, to: a.t, label: "members · policies", dash: true }
    - { from: sp.b, to: b.t, dash: true, arrow: none }
    - { from: sp.b85, to: c.t, dash: true, arrow: none }
    - a -> ra
    - b -> rb
    - c -> rc
facts:
  - { value: alpha, label: behind `--spaces`, note: "off by default · upstream changes weekly", tone: rust }
  - { value: "0", unit: events, label: on the firehose per space write, note: "space writes are private log entries", tone: blue }
  - { value: "~0.8 ms", label: space write p50, note: "measured, interop harness on MinIO · reference ~4.2 ms", tone: amber }
  - { value: "5b95b2f2", label: upstream pin, note: "bluesky-social/atproto PR #5187" }
```

A space is a group's private data. It has an authority (a DID) that decides who can read and write,
and its records are spread out across the members' own PDSes. Each member who writes keeps a space
repo for it on their PDS, and the space is the union of those repos. There's no encryption. A space
controls who can read the data, but the PDSes holding it can read it.

vlpds implements the reference's alpha as a repo host (your accounts' space repos) and as a
space host (spaces your accounts govern). It's off unless you start the node with `--spaces`.

## Addressing

| What | URI |
|---|---|
| A space | `at://{authority}/space/{spaceType}/{skey}` |
| A record in it | `at://{authority}/space/{spaceType}/{skey}/{author}/{collection}/{rkey}` |

The space type is an NSID that resolves to a lexicon declaration with `"type": "space"`, and it's
the unit an OAuth grant names. A public record may point into a space with the 7-segment `at-uri`,
and vlpds validates that whatever `--spaces` is set to.

## A space repo next to a public repo

| | Public repo | Space repo |
|---|---|---|
| Structure | MST | flat set of `{collection}/{rkey}` → CID |
| Commit | signed MST root | LtHash set hash over a 2,048 B state, signed per reader with a fresh `ikm` and an HMAC |
| Distribution | pushed on the firehose | pulled with `listRepoOps` and `getRepo` |
| Access | public | OAuth for your own repo, a space credential for anyone else's |
| History | commits | an oplog, kept 7 days on vlpds (`--space-oplog-retention`) |
| Signing key | the account's `#atproto` key | the same key |

The commit's signature is deniable. vlpds signs a fresh one for each response on the owner node,
so a key rotation doesn't need any space repo re-signed.

## Status

This tracks an alpha that ships breaking changes every Thursday. The pin is
bluesky-social/atproto PR #5187 at `5b95b2f2`, and the vendored lexicons and test vectors come
from it. vlpds has no back-compat for Spaces data yet, so a format change replaces the old one.

| Part | State |
|---|---|
| Space record writes and reads, `listRepoOps`, `getLatestCommit`, `getRepo` | built |
| The credential chain, revocations, the credential cache | built |
| space host: the baseline policies (`personalspace`, `memberspace`, `managedspace`), published policy and member records, members, `removeWriter`, `getSpaceCredential`, `notifyWrite`, `listRepos`, fan-out | built |
| The notifyWrite outbox, oplog retention, the 100k record cap | built |
| Space blobs (`space.getBlob`, `listBlobs`, the `sync.getBlob` rule) | built |
| The OAuth consent screen for `space:` scopes | built |
| Audited operator access to space records, `vlpds.space.importRepo`, space takedowns | built |
| Concurrent space writes to one repo sharing log segments, as public commits do | built |
| `/migrate` copies space repos (OAuth on both hosts, then `importRepo`) | built |
| Space repos in the account backup ZIP | not yet |

## Pages

```pages
{}
```
