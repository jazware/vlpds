---
title: Rate limits
section: Operations
order: 113
status: ready
summary: "Every built-in rate limit, how vlpds enforces them, how to change them on a live cluster, and what to do when someone hits a 429."
---

```hero
diagram:
  caption: "IP buckets are checked by the layer before the handler runs. DID, identifier and node buckets are checked by the handler after auth and before the expensive part. Every account mail also spends the mail budgets. Counters live in each node's memory, except `mail-cluster-day`, which is one count in the bucket. Every node re-reads `config/ratelimits.json` at least every 10 s."
  nodes:
    - { id: client, label: Client, sub: one IP or /64, at: [0, 3], size: [8, 3] }
    - { id: layer, label: rate-limit layer, sub: "IP buckets · before auth", at: [12, 3], size: [9, 3], tone: accent }
    - { id: handler, label: handler, sub: "DID · identifier + IP", at: [25, 3], size: [10, 3], tone: accent }
    - { id: mail, label: mail budgets, sub: "recipient · node · cluster", at: [39, 3], size: [10, 3], tone: violet }
    - { id: config, label: "`config/ratelimits.json`", sub: re-read every 10 s, at: [6, 9.4], size: [11, 2.6], shape: store, tone: amber }
    - { id: counters, label: node counters, sub: "in memory · fixed windows", at: [19.5, 9], size: [10, 3], tone: accent }
    - { id: budget, label: "`budget/mail.json`", sub: one count per UTC day, at: [39, 9.4], size: [10, 2.6], shape: store, tone: amber }
  edges:
    - "client -> layer: request"
    - "layer -> handler: after auth"
    - "handler -> mail: before the code"
    - "layer -> counters"
    - "handler -> counters"
    - "mail -> budget: CAS"
    - { from: config, to: layer, dash: true }
facts:
  - { value: "46", unit: buckets, label: built in, note: "keyed by IP, identifier + IP, DID, node, cluster or space credential", tone: amber }
  - { value: "3,000", unit: "/ 5 min", label: XRPC calls per IP, note: "`global-ip` · the one most clients hit first" }
  - { value: "10 s", label: for a change to reach every node, note: "peers are nudged at once · 10 s bounds a lost nudge", tone: blue }
  - { value: per node, label: counters, note: "a restart starts them over · only `mail-cluster-day` is cluster-wide", tone: muted }
```

vlpds starts from the reference PDS's buckets and values and adds a few of its own. A request over
a bucket gets 429 `RateLimitExceeded` with `RateLimit-*` headers and a `Retry-After`. The limits
can be changed on a running cluster from the console, and the change is kept in the bucket.

The buckets vlpds adds are mostly about work the reference doesn't bound. Password guessing costs
Argon2 CPU, so there's a per-IP cap on the OAuth sign-in form and a cross-IP cap per account
(`oauth-sign-in-ip`, `sign-in-account`). `reserveSigningKey` is unauthenticated and costs a KMS wrap
and a stored row per new key, so it has a per-IP and a per-node cap. Account mail has its own
budgets (`password-reset-account-*`, `mail-*`) and `requestPlcOperationSignature` has a limit
(the reference has none there). The account page's handle check (`vlpds.identity.checkHandle`) does a
DNS lookup and an HTTPS fetch of a domain the caller picks, so it's capped per account too. Passkey
registration rewrites the account's passkeys row and mails its owner, so it's capped per account
(`passkey-register-account`). The account page's passkey sign-in has its own per-IP cap
(`passkey-sign-in-ip`), since the OAuth form's bucket doesn't cover it, and it also spends the
`createSession-*` buckets (keyed by the DID and IP). Passkey sign-ins don't spend `sign-in-account`:
anyone can name any account in one, and a passkey can't be guessed, so charging the account would only
let a stranger use up its password sign-ins. Asking for the password again to change how the account
signs in (adding or removing a passkey, turning TOTP off, new recovery codes) does spend
`sign-in-account`, so a stolen session can't guess the password any faster than a sign-in could.

With `--spaces` on there are nine more. The reference only limits space writes, and those share the
repo-write buckets here too. Space reads get a budget per credential and per account
(`space-read-*`), counted on the repo's owner. Each `getSpaceCredential` claims its delegation
token durably, so it's capped per account and authority (`space-credential`). An inbound
`notifyWrite` is a durable entry on the authority's owner and a revocation is a write to a
cluster-wide object, so they're capped per writer, per authority and per account here
(`space-notify-in`, `space-revoke`, `space-revoke-aud`). Each space an account makes, and each
registration a credential makes, is fanned out to on every write, so they're capped too
(`space-create`, `space-register`). `vlpds.space.importRepo` is capped per account before its body is read
(`space-import`).

## The buckets

A bucket allows `points` per window per key. Most requests cost 1 point. Repo writes cost more
([Write points](#write-points)). Windows are fixed. A key's window starts at its first request and
resets when it ends, so a client can spend a whole window's points at the end of one and again at
the start of the next. The names are what the console, the config and the metrics use.

| Bucket | Key | Window | Points | Applies to | Over it |
|---|---|---|---|---|---|
| `global-ip` | IP | 5 min | 3,000 | every `/xrpc/` call, proxied ones too, except `sync.getRepo`, `subscribeRepos` and `_health` · OAuth sign-in and sign-up form posts | 429 |
| `com.atproto.sync.getRepo-0` | IP | 5 min | 6,000 | `sync.getRepo` (in place of `global-ip`) | 429 |
| `com.atproto.server.createSession-0` | identifier + IP | 1 day | 300 | `server.createSession` · OAuth sign-in | 429 · the sign-in page shows an error |
| `com.atproto.server.createSession-1` | identifier + IP | 5 min | 30 | `server.createSession` · OAuth sign-in | 429 · the sign-in page shows an error |
| `com.atproto.server.createAccount-0` | IP | 5 min | 100 | `server.createAccount` · OAuth sign-up form posts (`/oauth/authorize/sign-up`) | 429, or the sign-up page shows an error |
| `com.atproto.server.deleteAccount-0` | IP | 5 min | 50 | `server.deleteAccount` | 429 |
| `com.atproto.server.requestPasswordReset-0` | IP | 1 day | 50 | `server.requestPasswordReset` | 429 |
| `com.atproto.server.requestPasswordReset-1` | IP | 1 h | 15 | `server.requestPasswordReset` | 429 |
| `com.atproto.server.resetPassword-0` | IP | 5 min | 50 | `server.resetPassword` | 429 |
| `com.atproto.repo.uploadBlob-0` | IP | 1 day | 1,000 | `repo.uploadBlob`, except blobs an arriving account's repo references | 429 |
| `com.atproto.identity.updateHandle-0` | DID | 5 min | 10 | `identity.updateHandle` | 429 |
| `com.atproto.identity.updateHandle-1` | DID | 1 day | 50 | `identity.updateHandle` | 429 |
| `com.atproto.server.requestAccountDelete-0` | DID | 1 day | 15 | `server.requestAccountDelete` | 429 |
| `com.atproto.server.requestAccountDelete-1` | DID | 1 h | 5 | `server.requestAccountDelete` | 429 |
| `com.atproto.server.requestEmailConfirmation-0` | DID | 1 day | 15 | `server.requestEmailConfirmation` | 429 |
| `com.atproto.server.requestEmailConfirmation-1` | DID | 1 h | 5 | `server.requestEmailConfirmation` | 429 |
| `com.atproto.server.requestEmailUpdate-0` | DID | 1 day | 15 | `server.requestEmailUpdate` · turning off the email sign-in factor (its first step mails a code) | 429 |
| `com.atproto.server.requestEmailUpdate-1` | DID | 1 h | 5 | the same | 429 |
| `repo-write-hour` | DID | 1 h | 5,000 | `createRecord`, `putRecord`, `deleteRecord`, `applyWrites` | 429 |
| `repo-write-day` | DID | 1 day | 35,000 | the same | 429 |
| `oauth-sign-in-ip` | IP | 5 min | 100 | OAuth sign-in form posts (`/oauth/authorize/sign-in`, `/oauth/account/sign-in`) | the sign-in page shows an error (429) |
| `sign-in-account` | DID | 1 h | 100 | `server.createSession` and OAuth sign-in (both steps), from any IP · the account page's password re-checks (passkeys, TOTP off, recovery codes) | 429 · the sign-in page shows an error |
| `oauth-ip` | IP | 5 min | 3,000 | POST `/oauth/par`, `/oauth/token`, `/oauth/revoke` (in place of `global-ip`) | 429 `rate_limit_exceeded` (OAuth error JSON) |
| `com.atproto.server.reserveSigningKey-0` | IP | 1 h | 100 | `server.reserveSigningKey` | 429 |
| `reserve-signing-key-node` | node | 1 day | 5,000 | `reserveSigningKey` calls that reserve a new key (one KMS wrap each) | 429 |
| `com.atproto.identity.requestPlcOperationSignature-0` | DID | 1 day | 15 | `identity.requestPlcOperationSignature` | 429 |
| `com.atproto.identity.requestPlcOperationSignature-1` | DID | 1 h | 5 | `identity.requestPlcOperationSignature` | 429 |
| `password-reset-account-day` | DID | 1 day | 15 | password-reset mails to one account, from any IP | 200, but no mail |
| `password-reset-account-hour` | DID | 1 h | 5 | password-reset mails to one account, from any IP | 200, but no mail |
| `mail-recipient-day` | DID | 1 day | 30 | every account mail to one recipient | 429 · password reset: 200, no mail |
| `mail-recipient-hour` | DID | 1 h | 10 | every account mail to one recipient | 429 · password reset: 200, no mail |
| `mail-node-hour` | node | 1 h | 200 | every account mail this node sends | 429 · password reset: 200, no mail |
| `mail-cluster-day` | cluster | 1 day | 900 (`--mail-daily-budget`) | every account mail the cluster sends (a UTC day) | 429 · password reset: 200, no mail |
| `vlpds.identity.checkHandle-0` | DID | 5 min | 60 | `vlpds.identity.checkHandle` (the account page re-checks a new domain every 15 s) | 429 · the account page stops checking |
| `vlpds.identity.checkHandle-1` | DID | 1 day | 1,000 | the same | 429 · the account page stops checking |
| `passkey-register-account` | DID | 1 day | 10 | `vlpds.server.startPasskeyRegistration`, so passkeys added to one account (each rewrites its passkeys row and mails the owner) | 429 · the Security page shows an error |
| `passkey-sign-in-ip` | IP | 5 min | 100 | the account page's passkey sign-in (`vlpds.server.startPasskeySignIn`, `vlpds.server.createPasskeySession`) · OAuth page passkey posts count against `oauth-sign-in-ip` instead | 429 · the account page shows an error |
| `space-read-credential` | space credential | 5 min | 3,000 | `com.atproto.space` reads and the space host's `listRepos`, `registerNotify` and `unregisterNotify` made with one space credential (keyed by a hash of its issuer and `jti`, so the console doesn't show them) · with `--spaces` | 429 |
| `space-read-account` | DID | 5 min | 3,000 | `com.atproto.space` reads, `listSpaces` and `simplespace.getSpace` by an account's own OAuth session · with `--spaces` | 429 |
| `space-credential` | DID + authority | 1 h | 300 | `space.getSpaceCredential` per account and space authority, counted on the authority's owner before the delegation token is claimed, keyed by a hash of the pair so the console doesn't show them · with `--spaces` | 429 · the token stays unused |
| `space-notify-in` | DID | 5 min | 1,000 | `space.notifyWrite` arriving from another host, per writer (each is a durable entry) · with `--spaces` | 429 · the writer's outbox retries |
| `space-revoke` | DID | 1 h | 1000 | Credentials newly revoked by `space.notifyCredentialRevoked`, per space authority (one point per jti not already revoked, each a write to the cluster-wide revocations object · a call naming only revoked ones costs nothing) · with `--spaces` | 429 |
| `space-import` | DID | 1 h | 100 | `vlpds.space.importRepo` per account, spent before the body is read (an account also runs 2 at once and a node up to 8, as its import budget allows: `InvalidRequest` and 503 `Overloaded` past those) · with `--spaces` | 429 |
| `space-revoke-aud` | DID | 1 h | 2,000 | Credentials newly revoked by `space.notifyCredentialRevoked`, per account here whose stake let them in (only those are stored), so one account and many authorities can't fill the revocations object · with `--spaces` | 429 · the space's credentials are refused for 3,610 s (a revocation not stored never fails open) |
| `space-create` | DID | 1 day | 100 | `simplespace.createSpace` per account, for a space that isn't live yet (an account also governs at most 1,000 live spaces) · with `--spaces` | 429 |
| `space-register` | space credential | 1 h | 60 | `space.registerNotify` with one space credential (keyed by a hash of its issuer and `jti`) · with `--spaces` | 429 |

`npm run check-docs` fails if this table's key, window or points disagree with `src/ratelimit.rs`.

Key kinds:

- IP is the client address ([Behind a proxy](#behind-a-proxy)). An IPv6 client is keyed by its /64,
  since one subscriber can fill a /64 with fresh addresses at will. A request whose address can't be
  read shares the key `unknown`.
- Identifier + IP is `{identifier}-{ip}`. The identifier is the handle or email as typed, trimmed,
  without a leading `@` and lowercased, so case variants share a bucket. On the OAuth page's second
  step (the 2FA code) it's the account's DID instead.
- DID is the account. For the mail buckets it's the recipient's account.
- Node is one counter for the whole node, and cluster is one counter for the whole cluster.

Admin `sendEmail` is exempt from every mail bucket. `subscribeRepos` and `_health` are never rate
limited. `subscribeRepos` has its own per-IP connection cap instead
([Firehose](../firehose.md#serving-subscribers)). Proxied calls have a separate cap of 64 in flight
per account on its owner ([Proxying](../proxying.md#connection-pools-and-limits)). Neither of those
is a bucket here, so neither shows up in the console's Limits & lockouts page.

### The response

Every limited response is HTTP 429 with the reference's body:

```json
{"error": "RateLimitExceeded", "message": "Rate Limit Exceeded"}
```

A mail bucket's message is `Too many emails sent to this account; try again later` instead. The
OAuth endpoints answer `{"error": "rate_limit_exceeded", "error_description": "Rate Limit Exceeded"}`,
and the OAuth sign-in page shows "Too many sign-in attempts".

Any response that counted in a bucket carries the headers of the tightest one it counted in (an
exceeded bucket first, then the fewest points left):

| Header | Value |
|---|---|
| `RateLimit-Limit` | the bucket's points (or the override's) |
| `RateLimit-Remaining` | points left in the window |
| `RateLimit-Reset` | when the window ends, in Unix seconds |
| `RateLimit-Policy` | `{points};w={window seconds}` |
| `Retry-After` | seconds until the window ends, on a 429 only |

`requestPasswordReset` never reports its per-account or mail buckets, and answers 200 when they're
spent. The caller isn't signed in, and an account's mail budget would tell them whether an address
has an account.

## How enforcement works

```steps
- title: The layer, before the handler
  body: "For `/xrpc/` calls it counts `global-ip` (not for `sync.getRepo`), then the route's own IP buckets (`getRepo`, `createAccount`, `deleteAccount`, `requestPasswordReset`, `resetPassword`, `reserveSigningKey`), then a custom route bucket if the config has one. For `/oauth/par`, `/oauth/token` and `/oauth/revoke` it counts `oauth-ip` only. This runs before auth and before the body is read."
- title: The handler, after auth and input checks
  body: "DID buckets and the identifier + IP buckets are checked once the handler knows the DID or identifier, as the reference does, and before the expensive part. Sign-in checks `createSession-*`, looks up the account, checks `sign-in-account`, and only then hashes the password. Repo writes check `repo-write-*` before the commit. `reserveSigningKey` checks `reserve-signing-key-node` only when it's about to wrap a new key."
- title: Mail, before the code is minted
  body: "An endpoint that mails checks its own bucket first, then spends `mail-recipient-*`, `mail-node-hour` and `mail-cluster-day`. The token is minted only after all of them pass, so a refused request leaves the last mailed code working. See [Mail budgets](email-and-moderation.md#mail-budgets)."
```

Points are counted even when the request is rejected (as the reference's limiter does), in every
bucket of the check that rejected it. So a client that keeps retrying stays at its limit until the
window ends.

### Per node and cluster-wide

Counters are in each node's memory. Each node counts only the requests it serves.

- DID buckets are close to exact. A DID's requests are served by the node that owns the account
  (other nodes forward them), and `createSession` routes by its body.
- IP buckets count what one node serves. A forwarded request is counted on the node that serves it,
  under the client address the entry node resolved. So a client whose requests spread across N
  nodes can get up to N times the per-IP budget.
- Node buckets (`reserve-signing-key-node`, `mail-node-hour`) are per node by design and grow with
  the cluster.
- `mail-cluster-day` is the only cluster-wide bucket. Mail providers cap sending per account, so a
  per-node budget would grow with every node you add. It's one object in the bucket
  (`budget/mail.json`), spent with a compare-and-swap by whichever node sends the mail. Its windows
  are aligned to the epoch, so the day is the UTC day on every node. If the store can't be reached,
  mail goes out uncounted and `mail-node-hour` still bounds each node.

A restart starts a node's counters over. So does an account moving to another node, for its DID
buckets.

### Write points

| Write | Points |
|---|---|
| create (`createRecord`, or a create in `applyWrites`) | 3 (`CREATE_POINTS`) |
| update (`putRecord`, or an update in `applyWrites`) | 2 (`UPDATE_POINTS`) |
| delete (`deleteRecord`, or a delete in `applyWrites`) | 1 (`DELETE_POINTS`) |

`applyWrites` costs the sum of its writes, checked once against `repo-write-hour` and
`repo-write-day` before anything is written. These are the reference's costs, so 5,000 points an
hour is about 1,666 creates. `putRecord` costs 2 even when it creates the record. Writes made with
admin or moderation-service credentials aren't counted.

### Refunds

There's one. An account moving in uploads every blob its imported repo references. Those uploads
don't count against `uploadBlob-0`, and once the handler sees that the blob is one the repo
references, it gives back the `global-ip` point the layer took. Other blobs an arriving account
uploads count as usual. Nothing else is refunded.

### Bypasses

A request skips every bucket except the mail budgets when it carries any of these:

- the internal token (node-to-node calls)
- the bypass key in `x-ratelimit-bypass` ([Testing and load tests](#testing-and-load-tests))
- admin Basic auth

The mail budgets protect recipients and the provider's quota, so only a DID override, turning the
bucket off, the config's global switch or `--no-rate-limits` lifts them.

## Changing limits live

```facts
- { value: "10 s", label: re-read on every node, note: "plus a nudge to peers on save", tone: blue }
- { value: "50", label: changes kept, note: "who, when, from which node and IP", tone: amber }
- { value: "1,000", label: overrides at most, note: "IP, CIDR or DID", tone: violet }
- { value: "64", label: custom routes at most, note: "`route:{nsid}`, IP-keyed", tone: muted }
```

The config is `config/ratelimits.json` under the bucket prefix. It holds only the changes from the
built-in defaults, so `{}` (or no object) means the defaults. Edit it from the console's Limits &
lockouts page (`/admin/limits`), which calls `vlpds.admin.updateRateLimits`. A save checks that you
edited the version you read and writes the next version with a compare-and-swap, so two admins on
different nodes can't overwrite each other. The saving node applies it at once and nudges its
peers. Every node also re-reads it every 10 s, so a lost nudge costs at most that.

```json
{
  "enabled": true,
  "limiters": {"global-ip": {"points": 6000}, "oauth-sign-in-ip": {"enabled": false}},
  "routes": [{"nsid": "app.bsky.feed.getTimeline", "points": 600, "windowSecs": 300}],
  "overrides": [
    {"ip": "203.0.113.0/24", "limiters": ["global-ip"], "exempt": true, "note": "relay"},
    {"did": "did:plc:abc", "limiters": ["repo-write-hour", "repo-write-day"], "points": 50000}
  ]
}
```

- `enabled: false` is the global off switch. Nothing is limited, mail budgets included.
- `limiters.{name}` changes a built-in bucket's `points`, `windowSecs` or `enabled`. A new points
  value keeps each key's live window and what it has used. A new window length starts every key on
  a fresh window. `windowSecs` is 1 to 604,800 (a week), and points must be at least 1 (turn the
  bucket off instead of setting 0).
- `routes` adds an IP-keyed bucket named `route:{nsid}` for `/xrpc/{nsid}`, counted on top of
  `global-ip`. Proxied methods work too. `subscribeRepos` and `_health` can't be listed.
- `overrides` exempt a key or give it its own points in the bucket's window. Each one sets either
  `ip` (an address or CIDR block) or `did`, and either `exempt: true` or `points`. An empty
  `limiters` list means every bucket. When several match, exempt wins, and otherwise the highest
  points.

IP and DID overrides reach different buckets. An IP override matches the request's client address,
so it applies to every bucket that request counts in, DID buckets included. A DID override matches
DID-keyed buckets only (it's refused if it lists none), which makes it the way to lift
`sign-in-account`, `repo-write-*` or a mail budget for one account. IP overrides don't lift the mail
budgets.

`mail-cluster-day`'s default comes from `--mail-daily-budget` (`VLPDS_MAIL_DAILY_BUDGET`, 900). Its
`points` in the config wins over the flag, and IP or DID overrides don't apply to it.

A save with an unknown field, an unknown bucket or a bad value is refused with every problem listed.
If the stored object is invalid anyway (written by hand, say), each node keeps its last good config,
reports the error in the console and counts it in `vlpds_rate_limit_config_errors_total`. Fields a
newer feature level wrote are dropped with a warning, so a rolling upgrade doesn't break older
nodes.

What survives a restart: the config and `mail-cluster-day`'s count, since both live in the bucket.
Every other counter is in memory and starts over. The console shows the busiest keys, recent 429s
and each node's applied version ([Admin console](admin-console.md#pages)).

## Behind a proxy

```facts
- { value: right-most, label: untrusted X-Forwarded-For entry, note: "Express `trust proxy` rules", tone: accent }
- { value: "/64", label: for IPv6 clients, note: "one key per subscriber allocation", tone: blue }
```

Without `--trusted-proxies` (`VLPDS_TRUSTED_PROXIES`), the client address is the TCP peer. Behind
a TLS proxy that's the proxy, so every client shares one set of IP buckets. List the proxy's
addresses or CIDRs (comma-separated) and vlpds reads `X-Forwarded-For` when the peer is one of them.

It walks `X-Forwarded-For` from the right, skipping entries that are themselves trusted, and uses
the first one that isn't. An entry that doesn't parse stops the walk, so a garbled entry can't make
it reach the client-written entries further left. Entries may be an address, `v4:port`, `[v6]` or
`[v6]:port`. If every entry is trusted, the left-most one is used.

Don't list the vlpds nodes. A node that forwards a request passes the client address in
`x-vlpds-client-ip` next to its internal token, and the receiving node only honours that header
with a valid token. The same client address feeds the firehose's per-IP cap and the IP in the
moderation audit log. See [Deploy](deploy.md#without-ansible).

## Testing and load tests

- `--rate-limit-bypass-key` (`VLPDS_RATE_LIMIT_BYPASS_KEY`), or `--rate-limit-bypass-key-file`
  (`VLPDS_RATE_LIMIT_BYPASS_KEY_FILE`) in production, sets a value that skips every bucket but the
  mail budgets when a request sends it in `x-ratelimit-bypass`. It's compared in constant time, and
  an empty value turns it off. Use it for a trusted service or a load generator against a real
  cluster.
- `--no-rate-limits` (`VLPDS_NO_RATE_LIMITS`) doesn't install the layer at all, and turns the mail
  budgets off. The console can still edit the config, but the node counts nothing. It's meant for
  benchmarks and local development.
- To test one bucket, lower its points from the console and put them back afterwards. The change
  history keeps the old value.

## Common tasks

```steps
- title: A third-party app backend on one IP gets 429s
  body: "A confidential OAuth client calls `/oauth/par`, `/oauth/token` and `/oauth/revoke` for all its users from one address, and an AppView-style backend may make XRPC calls the same way. Add an IP override for that address on the Limits & lockouts page, with `limiters` set to `oauth-ip` (or `global-ip`) and higher points, or exempt. See [Admin console](admin-console.md#common-tasks)."
- title: A user mid-migration hits 429s
  body: "The migration page backs off on a 429 by itself ([Migration](../migration.md#what-gets-copied)). Uploads of blobs the imported repo references don't count. If they still hit `global-ip` or `uploadBlob-0`, add a temporary IP override for their address. For `repo-write-*` after the move, add a DID override. Remove it when they're done."
- title: A login flood
  body: "Look at `vlpds_logins_total{result=\"rate_limited\"}` and the Limits & lockouts page's busiest keys. One account under attack is held by `sign-in-account`, so its new sign-ins (app passwords included) are refused for up to an hour. Live sessions keep working. A DID override lifts it for the owner. A flood from many IPs that sheds Argon2 (`VlpdsPasswordHashingShed`) calls for lower `createSession-*` or `oauth-sign-in-ip` points. See [OAuth and 2FA](../oauth-2fa.md#passwords-and-argon2)."
- title: A mail flood
  body: "`vlpds_mail_suppressed_total` by `reason` says which budget is refusing. `recipient_limit` is one account being mailed too much, and a DID override lifts it if the user needs the mail. `node_limit` and `cluster_limit` mean real users aren't getting codes. Find the source on the Limits & lockouts page, then raise the budget or override the abuser down. See [Mail budgets](email-and-moderation.md#mail-budgets)."
- title: A load test
  body: "Against a test cluster, start it with `--no-rate-limits`. Against a real cluster, set `--rate-limit-bypass-key-file` and send `x-ratelimit-bypass` from the load generator. Mail budgets still apply with the bypass key, so don't load-test mailing endpoints against a real mail provider."
```

## Metrics and alerts

| Metric | What it counts |
|---|---|
| `vlpds_rate_limited_total` | requests rejected with 429 `RateLimitExceeded` by any bucket |
| `vlpds_rate_limit_rejections_total{limiter, route}` | rejections by bucket and route (the matched XRPC method or path, else `_proxy_or_unmatched`, and `mail:{purpose}` for mail) |
| `vlpds_rate_limit_config_version` | the config version in force on this node (0 means the defaults) |
| `vlpds_rate_limit_config_loads_total{result}` | config refreshes: `applied`, `unchanged`, `invalid`, `error` |
| `vlpds_rate_limit_config_errors_total` | config objects rejected by validation (the last good config stays) |
| `vlpds_logins_total{method, result="rate_limited"}` | sign-ins refused by a bucket |
| `vlpds_mail_suppressed_total{purpose, reason}` | account mails not sent: `recipient_limit`, `node_limit`, `cluster_limit`, `account_limit`, `dedup` |
| `vlpds_mail_budget_remaining{window="day"}`, `vlpds_mail_budget_limit{window="day"}` | the cluster mail budget, as this node last read it (at least once a minute) |
| `vlpds_mail_budget_errors_total` | mails sent without spending the cluster budget (store errors) |

The `vlpds internals` dashboard has a rate limits row ([Monitoring](monitoring.md#dashboards)).

The alerts are about mail: `VlpdsMailNodeBudgetExhausted`, `VlpdsMailClusterBudgetExhausted`,
`VlpdsMailClusterBudgetLow` (under 20% left) and `VlpdsMailBudgetUncounted`. There's no alert on
429s in general, on a single bucket, or on an invalid config object. Watch
`vlpds_rate_limit_rejections_total` on the dashboard, and `vlpds_rate_limit_config_version` across
nodes after a change. Related caps that aren't buckets have their own alerts:
`VlpdsProxyAccountCapSustained` and `VlpdsPasswordHashingShed`. See [Monitoring](monitoring.md#alerts).
