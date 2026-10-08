---
title: Reading a space
section: Spaces
order: 201
status: draft
summary: "The credential chain: the user's PDS vouches for the user, the authority vouches for membership, and each member's PDS serves records to a credential bound to the app's own key."
---

```hero
timeline:
  caption: "An app reads two members' repos. Three hosts and three tokens, and the credential is reused for every member host until it expires. Spacing isn't to scale."
  scale: 48
  lanes:
    - { id: app, label: App, sub: "OAuth client · P-256 key", tone: ink }
    - { id: user, label: Your PDS, sub: holds your account key, tone: accent }
    - { id: auth, label: Authority's host, sub: simplespace, tone: accent }
    - { id: bob, label: bob's PDS, sub: member repo, tone: accent }
    - { id: carol, label: carol's PDS, sub: member repo, tone: accent }
  spans:
    - { lane: user, from: 0.5, to: 4.2, label: OAuth check · sign, dur: 60 s token }
    - { lane: auth, from: 4.9, to: 9.1, label: verify · claim jti · policy, dur: "~2.7 ms" }
    - { lane: bob, from: 10.1, to: 12.9, label: full verify, dur: cache miss }
    - { lane: carol, from: 13.7, to: 15.9, label: cache hit, dur: "~0.3–0.5 ms" }
  arrows:
    - { from: app, to: user, at: 0.3, label: getDelegationToken }
    - { from: user, to: app, at: 4.35, side: left, label: delegation }
    - { from: app, to: auth, at: 4.65, label: getSpaceCredential }
    - { from: auth, to: app, at: 9.4, side: left, label: credential }
    - { from: app, to: bob, at: 9.8, label: "getRecord · Audience: bob" }
    - { from: app, to: carol, at: 13.4, side: left, label: "listRepoOps · Audience: carol" }
  marks:
    - { at: 9.4, label: "credential · 10 min", tone: solid }
facts:
  - { value: "3", unit: tokens, label: from three hosts, note: "delegation · credential · a signature per request" }
  - { value: "60 s", label: delegation token, note: "single use · vlpds refuses one over 300 s", tone: amber }
  - { value: "10 min", label: space credential, note: "60 min at most · reusable on every member host", tone: violet }
  - { value: OAuth, label: only, note: "app passwords and password sessions get no space access", tone: rust }
```

A read takes three steps. The app gets a delegation token from the user's own PDS, swaps it at the
authority's host for a space credential, and then reads any member's repo with that credential. The
credential has no audience of its own, so every request names the repo it's for in a signed header.

## The three tokens

| Token | Minted by | Lifetime | Bound to | Checked by |
|---|---|---|---|---|
| Delegation (`atproto-space-delegation+jwt`) | your PDS, with your account key | 60 s, single use | `aud` = the authority's `#atproto_space_host` | the authority, which claims its `jti` once |
| Space credential (`atproto-space-credential+jwt`) | the authority, with its account key | 10 min, 60 min at most | `cnf.kid` = the app's P-256 did:key | every member host, on every request |
| Request signature (RFC 9421) | the app | per request, reusable | the `authorization` and `atproto-space-audience` headers | the host serving the request |

vlpds signs both JWTs with ES256K and the `#atproto` key. It doesn't publish a separate
`#atproto_space` key, so the reference's fallback to `#atproto` applies. The delegation token's
`jti` is claimed with `claim_replay_anywhere`, so a replay is refused even on another node after a
failover.

## OAuth only

| Session | Space reads and writes | `getDelegationToken` |
|---|---|---|
| OAuth with a matching `space:` scope | yes | only with `action=read` on the whole space |
| App password, scoped or not | refused | refused |
| Password session (`createSession`) | refused | refused |

Space data is OAuth-only on vlpds. The reference lets legacy app passwords read and write the
account's own space records, so this is a deliberate divergence
([Interop](interop.md#where-vlpds-differs)). `getServiceAuth` follows the same rule for a
`com.atproto.space.*` or `com.atproto.simplespace.*` method, with `--spaces` on or off: an app
password or password session never gets a token for one, and an OAuth app needs a `space:` grant
that covers it. `transition:generic` or `rpc:` alone isn't enough. A `notifyCredentialRevoked`
token (an authority's app revoking at member hosts) needs `manage` or the account's own spaces, a
`notifyWrite` token a write action, and any other space method some `space:` grant. Otherwise an
app could fake the account's writes to an authority or revoke credentials in spaces it runs. `vlpds.space.importRepo` is OAuth
too, so an account moving in imports after it's activated ([Moving a repo in](storage.md#moving-a-repo-in)). The consent screen names a space type by its
declaration, an authority by its handle when the handle resolves back to it (else the DID), and
says which actions a grant allows. It warns on a `space:*?authority=*` grant that reads what members
share (`read`) or writes anything. One that only reads your own space repos (`read_self`, as the
`/migrate` page asks for) gets a plain description and no warning. Space grants sit in the screen's
NSID groups by their type's authority, and opening one lists the type and each collection with its
actions ([The consent screen](../oauth-2fa.md#the-consent-screen)).

A bare grant that writes (`space:<type>` with no `collection`) gets the collections its type
declares. vlpds looks those up once, while it shows the consent screen, and the token carries
exactly that list at the code exchange and at every refresh. So if the declaration later adds a
collection, an existing session doesn't pick it up. If the lookup fails at consent, the screen says
the writes couldn't be looked up and the token request fails, as it does on the reference.

## Your spaces on the account page

With `--spaces` on, the account page (`/account`) gets a Spaces tab. The rest of the page signs in
with a password, which can't read space data, so this tab signs in again with OAuth. It's the same
first-party client `/migrate` uses (public, DPoP-bound), with its own redirect URI at
`/account/oauth/callback`. The tab is hidden when `describeServer` doesn't say `vlpds.spaces`.

| Grant | Asked for | What it covers |
|---|---|---|
| `atproto space:*?authority=*&action=read_self` | on Connect | `listSpaces`, the user's own repo in each space (`getLatestCommit`, `listRecords`), and `getSpace` and `listMembers` for the spaces they run |
| the above plus `space:*?action=read_self&manage=update&manage=delete` | when the user opens Manage on a space they run | `putMember`, `removeMember` and `deleteSpace`, only in the user's own spaces |

The owner grant leaves `authority` at its default, `self`, so the token names the user's DID and
can't touch anyone else's space. It's a second consent on top of the first, and the new token
replaces the old one, whose tokens the page revokes. The consent screen sums it up as "manage your
spaces".

The tab shows two lists. Spaces the user writes in have a record count (paged with `excludeValues`,
shown as 10,000+ past ten pages) and the last write, which is the time in the head rev's TID. The
spaces they run have their member count, how many members can write, and the read and write
policies. Who runs a space shows as a handle only when the handle resolves back to the DID
(`resolveIdentity`), else as the DID, as on the consent screen. A space's page browses the user's
own records there with their values. Nobody else's records are listed, since `read_self` can't read
them.

Adding a member takes a handle, resolved with `resolveIdentity`. A handle that doesn't resolve back
to its DID is refused, and a DID works too. Each change asks for a confirmation, and deleting a
space has the user type its key.

The tokens live in sessionStorage and the DPoP key is non-extractable in IndexedDB, as on
`/migrate` ([The page's OAuth client](../migration.md#the-page-s-oauth-client)). Disconnect, leaving
the tab and signing out of the account page all revoke the tokens and delete the key. A closed tab
leaves its key behind, and the next visit deletes it once it's a day old.

## What a member host checks

```steps
- title: The scheme and the revocations
  body: "`Authorization: Atproto-Space <credential>`, sent once. Until the node has loaded the revocations it answers 503 to every credential read."
- title: The credential
  body: "A cache lookup by sha256 of the token. On a miss vlpds checks `typ`, `iss` = the space's authority, the authority's key, `exp` (a lifetime of 3,600 s at most, 5 s of skew) and the ES256K signature, then caches it until `exp`."
- title: The request signature
  body: "`atproto-space-audience` must be a single DID. The RFC 9421 signature must cover exactly the `authorization` and `atproto-space-audience` headers, made by the key in `cnf.kid`. This runs on every request, cache hit or not."
- title: Not revoked
  body: "The (space, `jti`) pair isn't in the revocation set. This also runs on every request."
- title: The handler's checks
  body: "The audience is the repo being read (the authority, for host methods like `listRepos`), and the credential's space is the requested space. Then the repo must be available: a taken-down repo answers `RepoTakendown` and a deactivated one `RepoDeactivated`."
```

The signature covers only those two headers, with no method or URL in it, so one signed request
can be replayed against any read of the same repo while the credential lives. That's the spec as it
stands. vlpds keeps the damage to that one repo and space by checking the audience and the space on
every request, and the authority can cut it short with a revocation.

A cache hit costs a hash lookup and one P-256 verify. The trade-off is that a credential this node
already verified keeps working until it expires even if the authority rotates its key, where the
reference resolves the key on every request.

## Revocation

```diagram
caption: "An authority revokes credentials at any repo host. vlpds writes the revocation to one cluster-wide control object, nudges the live peers, then answers 200. Peers also re-read the object every 5 min and at startup."
nodes:
  - { id: auth, label: Authority, sub: notifyCredentialRevoked, at: [0, 4.6], size: [10, 3], tone: muted }
  - { id: na, label: vlpds node A, sub: any node, at: [15, 4.6], size: [9, 3], tone: accent }
  - { id: obj, label: "`spaces/revocations.json`", sub: control object, at: [29, 0], size: [12, 2.6], shape: store, tone: amber }
  - { id: nb, label: vlpds node B, sub: peer, at: [29, 4.6], size: [12, 3], tone: accent }
  - { id: nc, label: vlpds node C, sub: peer, at: [29, 9.6], size: [12, 3], tone: accent }
edges:
  - "auth -> na: 1–100 jtis"
  - { from: na.t, to: obj.l, label: CAS append }
  - { from: na.r, to: nb.l, label: nudge }
  - { from: na.b, to: nc.l, label: nudge }
  - { from: nb.t, to: obj.b, label: re-read, dash: true }
```

- The authority calls `notifyCredentialRevoked` with service auth addressed to an account this
  cluster hosts, naming 1 to 100 `jti`s of up to 128 printable ASCII characters. vlpds refuses a
  credential whose `jti` is longer, so it can revoke every credential it accepts.
- The node appends them to `spaces/revocations.json` with a CAS on its ETag. Each entry is kept
  3,610 s (the longest credential plus skew at both ends), and expired ones are pruned on the next
  write.
- The 200 goes out once the object is durable and each live peer has been asked to reload it, with
  a second for each to answer. A peer that misses the nudge is asked again in the background for
  about a minute.
- A node that hasn't read the object for 6 min (its re-reads failing) answers 503 to credential
  reads until a read succeeds. So a missed nudge can't leave a revoked credential readable for long.
- Reloading drops any cached credential the new entries revoke.

Every node reads the object whole, so anyone with a DID could grow it if nothing bounded it:

- Only a revocation with a stake here is stored: the account it's addressed to holds a repo in the
  space, or the space's authority is hosted here. Any other gets a 200 and is dropped, since no
  credential for that space reads anything here through that account. An authority should tell
  each member's host, addressed to that member.
- In a cluster, "here" is the cluster. The node that gets the revocation asks the node that holds
  the account's repo. When it can't get an answer (that node is down, or the repo is moving), it
  stores the revocation anyway: an extra entry costs little, and a dropped one would leave the
  credential readable.
- Stored ones are capped at 2,000 live entries per authority, 1,000 per space, 5,000 per account
  here, and 50,000 in all (~7 MB). Each is rate-limited per authority (`space-revoke`) and per
  account (`space-revoke-aud`). The limits count only `jti`s that aren't revoked yet, so an
  authority telling every member's host about the same credential pays once per host.
- A revocation that can't be stored gets a 503, and that space's credentials are refused on every
  node for as long as the revocation would have lasted. The block goes in the object, so it
  outlives a restart. It never fails open, and it widens only over the party that caused it:
  - Over 100 blocked spaces of one authority, the authority is blocked instead (all its spaces),
    and its space blocks fold into that one. The same happens past 10,000 blocked spaces in all.
  - Over 1,000 blocked authorities, every remote authority's credentials are refused (503) and
    `VlpdsSpaceRevocationsSaturated` fires. Spaces whose authority is hosted here keep working, and
    a local authority is always blocked on its own.
  - Every block ends 3,610 s after it was made (an authority's, after the latest one it folded
    in). A block stands for revocations of credentials that existed when it was made, and each of
    those has expired by then. A credential issued later isn't one of them.
- A revocation refused by the `space-revoke-aud` bucket (anyone can spend an account's), or one the
  store couldn't take, blocks its space the same way: nothing about a revocation fails open.
- A node runs one append at a time and refuses a ninth waiting one (blocking its space). Re-reads
  don't wait behind appends, so a flood can't make the set go stale.

On a three-node cluster a revoked credential was refused on every node within 0.5–5 ms of the
revoke's 200 (the test allows 1 s), and still after restarts, missed nudges and joins
(`tests/all/spaces_side/cluster_revocation.rs`). Details on the object: [How vlpds stores it](storage.md#revocations).
