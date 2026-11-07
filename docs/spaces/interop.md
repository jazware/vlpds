---
title: Interop and divergences
section: Spaces
order: 206
status: draft
summary: "Which upstream vlpds tracks, how each upstream change maps onto vlpds, where it deliberately differs from the reference PDS, and the gaps in the spec it works around."
---

```hero
diagram:
  caption: "vlpds speaks the reference's wire in every role, and the interop harness runs it both ways: ref-ref, vlpds-authority, ref-authority and vlpds-only, plus a three-node vlpds cluster on MinIO."
  nodes:
    - { id: v, label: vlpds, sub: "repo host · space host", at: [0, 3], size: [12, 3], tone: accent }
    - { id: r, label: Reference PDS, sub: "atproto `98ef3a6b`", at: [26, 3], size: [12, 3], tone: muted }
    - { id: s, label: Syncer, sub: "`@atproto/space` consumer", at: [13, 10], size: [12, 3], tone: blue }
  edges:
    - "v <-> r: notifyWrite · credential reads"
    - { from: s.t25, to: v.b, label: "listRepoOps · MAC", tone: blue }
    - { from: s.t75, to: r.b, label: "listRepoOps · MAC", tone: blue }
facts:
  - { value: "98ef3a6b", label: reference pin, note: "bluesky-social/atproto PR #5187, the Nov 5 alpha" }
  - { value: MAC, label: per response, note: "DHKEM(P-256) to the author's #atproto_kem key; no commit signatures", tone: accent }
  - { value: STAR, label: getRepo and importRepo, note: "one pass, bytewise path order, control bytes", tone: violet }
  - { value: OAuth, label: only, note: "the biggest divergence", tone: rust }
```

vlpds tracks the reference implementation, since the proposal leaves a lot of the wire to it.
Where the spec is silent, vlpds matches the reference's behaviour. Where vlpds differs, it's on
purpose, and `tests/REFERENCE_COVERAGE.md` lists each case.

## The pin

The pin is bluesky-social/atproto PR #5187 (branch `permissioned-data`) at `98ef3a6b`, the
November 5 alpha (`0.0.0-spaces-alpha-20261105160032` on npm) plus internal refactors with no wire
change. The lexicons are vendored unmodified in `lexicons/spaces-alpha` and the test vectors in
`testdata/spaces-alpha`, both generated from that commit by running the reference.

## What the alpha changed, and where it lands

| Upstream | vlpds | Breaking | Stored data |
|---|---|---|---|
| getSpaceCredential takes `space`, `credentialKid`, and an optional `delegationToken` and `clientAttestation` in its body; a bad token is `InvalidDelegationToken` (proposals #120) | `xrpc/space.rs`, `xrpc/authn.rs` | yes | none |
| `Atproto-Space-Credential` scheme and a `tag="atproto-space-credential"` signature; the old scheme is `InvalidToken` | `space/httpsig.rs` | yes | none |
| No `#atproto_space` key or `#atproto_space_host` entry: tokens are addressed to `<authority>#atproto_pds` and their `kid` is exactly `#atproto` (#123) | `space/token.rs`, `space/host.rs` | yes | none |
| Commits are `{ver, repo, space, rev, data}` with no signature. The repo host MACs each response for one syncer with a DHKEM(P-256) secret against the author's `#atproto_kem` key (`Atproto-Space-Want-Mac` / `Atproto-Space-Mac`); `hash` is `data` (#122) | `space/commit.rs`, `space/mac.rs`, the four read handlers | yes | none: vlpds never stored commit signatures, and the digests are unchanged |
| A `#atproto_kem` key per account: in the genesis op, backfilled once for existing accounts, in getRecommendedDidCredentials, checked by submitPlcOperation | `kem_backfill.rs`, `secrets.rs`, identity endpoints | yes | a wrapped key per account, and one PLC operation per account the backfill can publish for |
| getRepo serves a STAR archive, with control bytes and limits (#114, #131) | `space/star.rs` | yes | none |
| notifySpaceDeleted is retried until delivered or the registration expires (#124) | `space/deleted.rs` | no | `sD` rows for sends that failed |
| Space policies replace simplespace: `com.atproto.space.{create,update,get,delete}Space`, `personalspace`, `memberspace`, `managedspace`, published policy and member records (#119) | the space host methods | yes | Oct 1 configurations convert to policies when read |
| `removeWriter` and `clearRecords` (#128, #127) | the space host and repo methods | no | none |
| Account migration: `com.atproto.space.importRepo`, `exportSpaceMeta`, `importSpaceMeta` (#129) | `xrpc/space_import.rs`, `space/meta.rs` | yes (`vlpds.space.importRepo` is gone) | none |
| A taken-down or deactivated authority suspends its spaces: `RepoTakendown` / `RepoDeactivated` on getSpaceCredential and listRepos (#134) | `xrpc/space.rs` | no | none |
| An authority's own repo needs its live space (`SpaceNotFound`) | `space/repo.rs` | no | none |

Where the spec is silent and vlpds copies the reference: `updateSpace` leaves the writer set as it is
(only `removeWriter`, `removeMember` and a `putMember` without write take a writer out),
`listRepoOps` leaves out values for superseded ops, and `listSpaces` treats its
filters as the scope target, so an unfiltered listing needs a wildcard grant.

## Where vlpds differs

| | Reference PDS | vlpds |
|---|---|---|
| Auth | legacy app passwords and password sessions can read and write the account's own space records | OAuth only (final). App passwords (scoped or not) and password sessions get no space reads, writes or delegation tokens, `getServiceAuth` tokens for space methods go only to OAuth apps whose `space:` grant covers the action (the reference checks only `rpc:`), and `importRepo` is OAuth too |
| Admin token on space reads | accepted on the space read methods, a taken-down repo's included | not accepted. Operators read through the audited `vlpds.admin` space methods ([Operating](operating.md)) |
| Exports by a taken-down account | its `allowTakendown` password session may export its spaces | none: space data is OAuth-only, and OAuth signs no taken-down account in |
| Fan-out to syncers | each forward goes out as it's sequenced, unordered | one lane per (space, service), in spaceRev order, a writer's waiting forward replaced by its newer one |
| notifyWrite delivery | a retry row written only after a send fails, so an acked write's notify can be lost in a crash | the `sP` row is in the write's own log entry |
| Delegation tokens and client attestations | any lifetime (it mints 60 s) | refused past 300 s, since their `jti`s are held until `exp` |
| Request signatures | no size cap, and header values decoded as latin1 | `Signature-Input` and `Signature` over 8 KiB refused, and header values must be visible ASCII |
| did:keys | refuses hybrid (0x06/0x07) points | the same, checked explicitly, since libsecp256k1 alone would parse them |
| Token claims | `iss` and `sub` need only be truthy | they must be non-empty strings |
| Credential keys | resolves the authority's key on every request | caches a verified credential until `exp`, so a key rotation shows up within the hour |
| Account takedown | the app's session works again after a reversal (what the harness expects) | revokes the account's OAuth sessions, and they stay revoked after a reversal. The app has to sign in again |
| Credentials for taken-down members | issued | refused |
| Record takedown | none for space records: `updateSubjectStatus` refuses a space record | hidden from every space read, and every commit and MAC is over the set without it (a vlpds extension, see [Takedowns](privacy.md#takedowns)) |
| Space takedown | none | a vlpds extension: no credentials, no `listRepos` or registrations, notifies dropped |
| Oplog | keeps every op | keeps 7 days. A `since` past that gets the window's start, and the syncer falls back to `getRepo` |
| Revocations | stored for any audience the host has, unbounded, one row each | stored only when the audience account holds a repo in the space or its authority is here (else 200, dropped), capped per authority, space and account, and one past a cap blocks the space's credentials ([Revocation](reading.md#revocation)) |
| Space repo size | no cap | 100k records (`--space-repo-max-records`) |
| Space record size | 1 MiB | 1,000,000 bytes on a write, as for public records; an import takes up to STAR's 1 MiB |
| importRepo | no notify | the authority is told of the imported repo's new rev, as after any write |
| Backlinks | a like of a space URI is recorded as a backlink | public URIs only |
| `sync.getBlob` with Spaces on | serves only publicly referenced blobs | the same. Without `--spaces`, vlpds still serves an upload before any record names it |
| Writes during `clearRecords` or `importRepo` | wait for its transaction | refused with `InvalidRequest` (retry) while the clear or import holds the repo; a failed import over a repo leaves none until a retry succeeds |
| `managingApp` | must start with `did:` | the part before `#` must be a valid DID |

## Upstream gaps

```steps
- title: HTTP signatures cover two headers
  body: "A request signature covers only `authorization` and `atproto-space-audience`, with no method or URL. So a captured request can be replayed against any read of the same repo while its credential lives. vlpds requires the audience to be a DID and the target repo, checks the credential's space against the request, and checks revocation on every request. The MAC adds nothing here: it authenticates the response to the syncer, not the request to the host."
- title: Takedowns and the LtHash (Q11)
  body: "The spec has no record takedown for space data, and a hidden record still counts in the repo's hash. vlpds serves a takedown-adjusted view: every read MACs a commit over the set without the hidden records. It keeps every view verifiable, so upstream could adopt it as is."
- title: KEM keys need a PLC operation
  body: "A syncer can't read an account's repos until its `#atproto_kem` key is in its DID document. For an account whose rotation key vlpds doesn't hold (a did:web, or a did:plc that removed it), the key is stored and the owner has to publish it, and until then credential reads of its repos fail."
```
