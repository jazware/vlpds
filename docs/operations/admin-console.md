---
title: Admin console and CLI
section: Operations
order: 111
status: ready
summary: "The operator console (on the tailnet) and the admin CLI: accounts, invites, handle domains, takedowns, rate limits, relays, firehose subscribers, cluster status and metrics."
---

```hero
diagram:
  caption: "Both are clients of admin XRPC with the admin token, on any node; calls about one account are routed to its owner. Neither is ever exposed through the public proxy: the console is reached over the tailnet or an SSH tunnel."
  nodes:
    - { id: op, label: Operator, sub: admin token, at: [0, 3.2], size: [7, 3] }
    - { id: ui, label: "/admin console", sub: "tailnet · SSH tunnel", at: [11, 0], size: [9, 3], tone: accent }
    - { id: cli, label: vlpds admin, sub: "CLI · same binary", at: [11, 6.4], size: [9, 3], tone: accent }
    - { id: api, label: admin XRPC, sub: "com.atproto.admin.* · vlpds.admin.*", at: [24, 3.2], size: [12, 3], tone: blue }
    - { id: owner, label: owning node, sub: forwarded by DID, at: [40, 3.2], size: [8, 3], tone: accent }
    - { id: caddy, label: Caddy, sub: "blocks /admin, vlpds.admin.*", at: [24, 9.4], size: [12, 2.6], tone: muted }
  edges:
    - { from: op.r, to: ui.l }
    - { from: op.r, to: cli.l }
    - "ui.r -> api.l30: Basic auth"
    - cli.r -> api.l70
    - "api -> owner: per DID"
    - { from: caddy.t, to: api.b, label: never public, dash: true, arrow: none }
facts:
  - { value: "9", unit: pages, label: in the console, note: "cluster, live metrics, accounts, moderation, invites, handle domains, rate limits, relays, firehose" }
  - { value: "2 s", label: cluster view refresh, note: "getClusterStatus polled from the node you opened", tone: blue }
  - { value: "pdsadmin", label: every command covered, note: "plus the reference's maintenance scripts and cluster ops", tone: violet }
  - { value: "0", label: direct bucket access, note: "the CLI needs only a node URL and the admin token", tone: amber }
```

vlpds has two operator tools, and both talk admin XRPC to a node. Every node serves the web console
at `/admin` from the same binary, and the `vlpds admin` CLI ships in that binary too. The console is
for looking around and for one-off account work. The CLI covers everything the reference's
`pdsadmin` and maintenance scripts do, plus cluster and key operations, and it's what you script.

## Reaching the console

```diagram
caption: "Two ways in. Caddy refuses `/admin`, `/admin/*`, `/xrpc/vlpds.admin.*`, `/metrics` and `/internal/*` from the internet, so both paths reach the node's port on the host directly."
nodes:
  - { id: lap, label: Your laptop, sub: browser, at: [0, 3.9], size: [8, 3] }
  - { id: ts, label: tailscale serve, sub: "https · tailnet only", at: [13, 0], size: [10, 2.6], tone: muted }
  - { id: ssh, label: SSH tunnel, sub: "-L 2583:127.0.0.1:2583", at: [13, 7.8], size: [10, 2.6], tone: muted }
  - { id: app, label: "vlpds :2583", sub: "/admin · admin XRPC", at: [28, 4.2], size: [9, 2.6], tone: accent }
  - { id: met, label: "vlpds :9583", sub: "/metrics", at: [28, 0], size: [9, 2.6], tone: accent }
edges:
  - { from: lap.r, to: ts.l }
  - { from: lap.r, to: ssh.l }
  - { from: ts.b, to: app.l30, via: [[18, 4.98]] }
  - { from: ts.r, to: met.l, label: "/metrics", dash: true }
  - { from: ssh.r, to: app.l70 }
```

- On the tailnet. With `vlpds_tailnet_console_port` set, the Ansible role runs `tailscale serve` on
  that port. tailscaled terminates TLS and listens on the tailnet only. `/` goes to the node and
  `/metrics` to its metrics listener. Open
  `https://<tailnet name>:<port>/admin`. Don't use port 443, because Docker's DNAT for Caddy takes it.
- Over SSH. Run `ssh -L 2583:127.0.0.1:2583 <host>` and open `http://localhost:2583/admin`.
  Every page works this way: the charts come from `getNodeMetrics`, not `/metrics`.
- Unlock it with the node's `--admin-token`. The console checks the token with a
  `getClusterStatus` call and keeps it in that browser tab only. Lock console forgets it.

Every node serves the console, and any node will do. The Cluster page is that node's view of the
cluster, and account pages are routed to each account's owner.

## Pages

```facts
- { value: Cluster, label: "/admin", note: "ownership map, nodes, firehose sources, feature level · every 2 s", tone: accent }
- { value: Metrics, label: "/admin/metrics", note: "every node's rates and latencies every 2 s, last 3 min", tone: blue }
- { value: Accounts, label: "/admin/accounts", note: "every account, search, sessions, 2FA, takedown, key rotation, rebuild, delete", tone: violet }
- { value: Limits, label: "/admin/ratelimits", note: "live 429s, top keys, buckets and overrides, cluster-wide", tone: amber }
```

| Page | What it shows | What you can do |
|---|---|---|
| Cluster | Nodes with a lease, shards owned by this node, its lease, durable log ordinal and feature level (with a finalize or mixed-builds banner) · a shard ownership map coloured by node · a node table (reachable, lease, owned, durable ordinal, firehose lag with the slowest log marked, build and level window) · the firehose's sources | Read only. Click a node to highlight its shards, or its address or build to copy it. |
| Live metrics | Commits and ops, commit to durable, segment PUT, HTTP and 5xx, 429s, firehose events, bytes and emit delay, cold repo loads, class A and B object-store requests and errors, CPU, memory, repos in memory and subscribers: the cluster's line and each node's, from `getNodeMetrics` | Read only. Two buttons download the [Grafana dashboards](monitoring.md#import-into-your-own-grafana). |
| Object store | Class A and B requests per second, bytes and objects stored, errors and timeouts, segment PUT p99 · what drives requests: the floor that grows with nodes × shards, writes and reads, and the count a month at the current rate (counts, not prices) · requests by key component and its driver (log segments, leases, SlateDB manifests and SSTs, blobs and the rest) and each one's share · objects and bytes stored by component from [storage stats](#storage-stats), exact or approximate, and the last backfill · per node rates and PUT latency · the bucket's provider, endpoint, prefix and region | Read only. Bucket listings aren't part of the console: stored sizes come from the nodes' own counters. |
| Accounts | Every account on every node's shards, most recently active first (`listAccounts`), searchable by handle prefix, email prefix or DID and filtered to those needing attention, deactivated, taken down, without a second factor or with an unconfirmed email · per row its shard and owner, records, blob bytes, last commit, second factors and state · an account opens in a side panel or full page: a "Can they sign in?" line (state, password or OAuth only, second factors, factor locks, any sign-in rate-limit key at its limit, the last good sign-in, refused attempts in the last day, email, the latest sign-in mail and what became of it), identity, placement, sign-in and second factors with recent sign-ins and refused ones, sessions, app passwords, recent ops from the firehose ring, blobs and quota, invites, spaces, cases and audit entries, its mail, the date a [scheduled deletion](email-and-moderation.md#scheduled-deletion) is due, and the dev mailbox in `--dev-mode` | Take down (with a reference) and reverse it · deactivate and reactivate · rotate the signing key · rebuild the repo (after a dry run) · check the repo · publish an `#identity` event · revoke one session, every session or an app password · clear a code lockout · change handle, email, password or blob quota · enable or disable its invites · reset its two-factor sign-in (audited and mailed to the user) · delete. Each asks for confirmation and shows the call it makes, and the destructive ones ask you to type the handle. ⌘K takes "take down @handle", "reset 2fa @handle" and the rest. |
| Moderation | Look up a subject from a bsky.app URL, at:// URI, handle, DID or DID + blob CID, and see the account, the record's JSON and its blobs (previews load on request, blurred) · active takedowns by kind · cases · the audit log · accounts over their blob quota | Take down or restore an account, record or blob with a reason, filed under a case · open and update cases (notes, status, subjects) · change an account's blob quota. See [Email and moderation](email-and-moderation.md#operator-moderation). |
| Handle domains | The primary (`--handle-domain`) and the domains added here, each with its active accounts (every 5 s), when it was added and by whom | Add a domain · remove one (refused while it has active accounts, with Remove anyway to force it). See [Handle domains](handle-domains.md). |
| Invite codes | Every code, newest first, one per row: uses left out of its total, when it was made, who made it and for whom, who used it, and whether it's active, disabled or used up | Create codes (count, uses, for an account) · copy a code, or a usable code's migrate or sign-up link · disable one code, or select several and disable them together. |
| Rate limits | Each bucket's busiest key, 429s in the last minute and 15 minutes, a 429/s chart, top keys, recent 429s by route, and each node's applied config version | Change a bucket's points, window or on/off · add routes · add IP, CIDR or DID overrides (exempt or a custom limit) · a global off switch. Changes apply to every node within seconds and are kept, with your name, in the last 50 changes. See [Rate limits](rate-limits.md#changing-limits-live). |
| Firehose & relays | Every subscribeRepos connection on every node, every 5 s: subscribers, live vs backfilling, this PDS's events/s and the bytes/s sent, emit delay · per connection its `#conn` number and node, client address with its AS, the relay it matched, user agent, how long it's been connected, start cursor, state, lag, and its events/s drawn against the PDS's · the last 50 disconnects per node with their reason · the relays asked to crawl this PDS (`--crawlers`, or a list stored from here), each one's last ask and result, whether it's subscribed now and how far behind, and the minimum interval · the merged live tail, filtered by kind, text or node | Disconnect a connection (`kickSubscriber`, type its `#conn` to confirm; it can reconnect with its cursor) · add or remove relays, reset to the flag's list, change the interval, request a crawl now. A live connection well under the PDS's events/s is falling behind. See [Relays and crawling](relays-and-crawling.md#crawl-requests). |
| Spaces (alpha) | Spaces whose authority is an account here, with members, writers, records and last write · each node's notify outbox, fan-out, revocation list and credential cache · a space's writers, members, notify registrations, taken-down records and audit entries | Take down or restore a space or one of its records, with a reason · remove a notify registration · read a writer's records after giving a reason (each page is an audited read). |
| Mail | Each node's queue, the mail budgets (`mail-cluster-day`, `mail-node-hour`, the per-recipient ones) and how much of each is spent, mail by purpose, and the recent mail log: purpose, the account it was for, the recipient's domain, node and result, filtered by purpose, domain or account | Read only. Budgets are rate-limit buckets: change them on the Limits page. |
| Config | Every flag each node runs with and where its value came from (flag, env, default, unset or a `-file` secret), with its help · secrets as set or unset with a fingerprint · settings stored in the bucket · each node's build · any setting that differs between nodes, apart from their addresses and `--node-id` | Read only. Filter by name, value or help, or show only what's set or only what differs. |

The rate-limit config lives in the bucket (`config/ratelimits.json`), so it survives restarts and
every node reads the same one. `{}` means the built-in defaults. The relay list lives next to it in
`config/crawlers.json`, and the added handle domains in `config/handle-domains.json`.

Each node serves its own firehose subscribers, so the Firehose page calls
`vlpds.admin.listFirehoseSubscribers` on the node you opened and that node asks its peers over the
peer listener. It lists up to 500 connections, oldest first, and the counts cover all of them. A peer
that doesn't answer is named at the top. The relay column is a hint. vlpds resolves the hostnames of
the configured relays every 5 minutes in the background and names a relay when the client's address
is one of them or its user agent contains the hostname. A relay that connects from other addresses
and doesn't name itself shows up unnamed, unless its reverse DNS name is under the relay's hostname
and resolves back to its address. The client cell shows the address, its AS from bgp.tools (a link to
the AS page; `--asn-lookup off` hides it) and that forward-confirmed reverse DNS name. A name that
doesn't resolve back is only in the tooltip, marked unverified, because anyone can put any name in
their reverse zone. Both are looked up in the background, so a new address shows them on a later
refresh. The `#conn` number is the `conn` label of
`vlpds_firehose_subscriber_events_total`, so a line on the dashboard and a row here can be matched
(see [Per-connection firehose series](monitoring.md#per-connection-firehose-series)).

## Console API

The console reads these `vlpds.admin.*` methods on top of the ones the pages above use. They take
the admin token like the rest, and the role's Caddy keeps them off the public listener. The UI's
typed client is `ui/src/lib/adminApi.ts`. Every time in an answer is unix milliseconds and every
seq is a string, because seqs are past 2^53.

They come in three shapes. Calls that name an account take its `did` and run on its owner, like
`getAccountInfo`. Calls about the cluster ask every live node over the peer listener and merge
the answers, naming any node that didn't answer in `unreachableNodes`. Calls about one node's own
state answer for the node they reach, and an `x-vlpds-node: <node id>` header sends them to
another one over peer mTLS.

| Method | Input | Answer |
|---|---|---|
| `listAccounts` (GET) | `q?` (handle prefix, email prefix or DID), `filter?` (`all`, `attention`, `deactivated`, `takendown`, `no2fa`, `unconfirmed`), `sort?` (`recent` or `slot`), `cursor?`, `limit?` (1-200, default 50) | `accounts`, each with its status, shard and node, email and whether it's confirmed, second factors, records, MST nodes, blobs and blob bytes from the repo's kept counts, `repoBytes` (`recordBytes` + `mstBytes`, see below), head rev and `lastCommitAt` · `counts`: `total`, `active`, `deactivated`, `takendown`, `suspended`, `unconfirmed` and `no2fa` over every account, with `approximate` while a shard's totals are loading, a node didn't answer or a shard has no owner · `cursor` while there's more · `missingShards` like `searchAccounts` |
| `getAccountSecurity` (GET) | `did` | Passkeys (name, created, last used, synced, suspect), TOTP, email codes, recovery codes left, wrong-code counts and locks, trusted browsers, app passwords, OAuth-only and app-password switches, recent sign-ins and refused ones (`failed`: `wrong_password`, `wrong_code`, `factor_locked` or `rate_limited`, with `count` and `firstAt`) |
| `getAccountKeys` (GET) | `did`, `refresh?` | The account's signing key and any pending one · the DID document's `verificationMethods` (from the resolver's cache, refetched with `refresh=true`), each with `matchesAccount` · for a did:plc, the directory's `rotationKeys`, each with its role (`server` for this PDS's current or retired key, `operator_recovery`, `other`). The rotation keys cost one request to the directory, so only an operator opening this asks |
| `createAccount` | `{handle, email, password?, reason?}` | Creates an account as `com.atproto.server.createAccount` does (the same checks, claims and DID registration) with no invite code needed. Without `password` one is generated and returned once as `password`. Audited as `account.create`, without the password |
| `recountRepo` | `{did}` | Counts the repo's records, nodes, blobs and bytes from a snapshot and replaces its kept counts, if no commit landed since (else `InvalidSwap`: run it again). Reads the whole repo, as `checkRepo` does |
| `listSessions` (GET) | `did` | `sessions`: OAuth grants (client, scope, device, signed in, last refresh) and password or app-password sessions (one per session family), each with `ip` (the client address at its latest refresh) and `signedInIp` (at sign-in), as the rate limits resolve it behind trusted proxies. Each has an `id` for `revokeSessions` |
| `revokeSessions` | `{did, ids?, reason?}` | Without `ids`, every session, OAuth grant, device sign-in and trusted browser, as a password change does. App passwords keep working. Audited as `sessions.revoke` |
| `revokeAppPassword` | `{did, name, reason?}` | The password and the sessions it signed in. Audited as `app_password.revoke` |
| `listRepoOps` (GET) | `did`, `limit?` (1-100, default 25) | The account's `#commit` (with its ops), `#sync`, `#identity` and `#account` events, newest first, from the firehose ring in memory. `reachesBackTo` says how far back it looked and `ringExhausted` that nothing older is in memory |
| `getNodeMetrics` (GET) | `since?` | Per node: commits, ops, HTTP, 5xx, 429s, firehose events and bytes, repo loads, class A and B object-store requests per second, CPU cores busy, memory, subscribers, cached repos, mail queue, and commit, segment PUT and firehose emit p50/p99. `series` holds one point per 2 s for the last 3 minutes (only those after `since`), `latest` the last 10 s · `storeComponents`: class A and B per second by key component over the kept window (`storeWindowMs`), busiest first |
| `listSegments` (GET) | `since?` (default the last 20 s) | Per node: its log, durable ordinal, watermark and its lag, and each segment's ordinal, seq range, entries against firehose events, bytes before and after compression, when it was sealed and when it was durable (null while its PUT is in flight) · the firehose's last emitted seq and min watermark |
| `listMail` (GET) | `limit?` (default 100), `did?` | Every node's recent mail, newest first, or only one account's: purpose, the account's DID, the recipient's domain only, status (`queued`, `retrying`, `sent`, `failed`, `dropped`, `suppressed`, `logged`), attempts, the provider's error with any address removed, and the budget that suppressed it · each node's queue depth |
| `listLockouts` (GET) | | Accounts whose TOTP and recovery codes (`second_factor`) or email codes (`email_code`) are locked after wrong codes, with the count and when the lock ends, from the lockout index of every node's shards |
| `clearLockout` | `{did, reason}` | Clears both locks and their counts. Audited as `lockout.clear`. The sign-in rate-limit buckets are separate: a DID override on the Rate limits page lifts those |
| `getConfig` (GET) | | This node's flags, each with its source (`flag`, `env`, `default`, `unset`, or `file` for a secret set by its `-file` flag) and value · settings stored in the bucket (handle domains, rate-limit version, shard layout, feature level) · version and build rev · `peerTls`: the peer certificate in use (`nodeId`, `subject`, `hosts`, `notBefore`, `notAfter`, the earliest CA's `caNotAfter`), null without peer TLS · `secretFiles`: each `-file` secret's `flag`, `path` and the file's `modifiedAt`, so a rotation shows as a recent change |
| `getStorageStats` (GET) | | Objects and bytes in the bucket by key component (`components`, each `exact` or not, with its count of guessed changes), `totalObjects`, `totalBytes`, `exact`, `inexactBecause`, `seeded` and `lastBackfillAt` · `backfill`: the latest run's phase, requests, keys and place · per node: what it hasn't folded yet and when it last did. See [Storage stats](#storage-stats) |
| `backfillStorageStats` | `{dryRun?, maxRequests?, pagesPerSecond?, restart?}` | Lists the bucket once in the background to seed the counts. `dryRun` answers the estimate (`estimatedObjects`, `estimatedRequests`, `estimatedSeconds`) and starts nothing. Otherwise `maxRequests` is required. Audited as `storage.backfill` |
| `kickSubscriber` | `{conn}` | Closes that firehose connection on this node with reason `kicked`. The client can reconnect with its cursor |

What these never return:

- A secret's value. `getConfig` shows a secret flag as set or unset with `sha256:` and the first 8
  hex digits of the value in use, enough to tell two nodes apart. A URL flag loses any
  `user:password@`.
- A recipient's address or a mail's body or token. The mail log keeps the purpose, the account's
  DID, the domain and the outcome, and an error loses every word with an `@` in it.

Each node keeps the last 1,024 segments it sealed, the last 200 mails and 3 minutes of metrics in
memory, so none of this reads the bucket. A restart starts them empty. Lockouts are indexed in the
shards (`L/{did}\0{factor}`, written in the same batch as the lock), so the list survives restarts
and shard moves; an entry whose lock has run out is dropped the next time the list finds it.
`listRepoOps` reads only the ring, so a quiet account's older events aren't there.
`getStorageStats` reads one control-plane object and asks each node for what it holds, and never
lists the bucket.

### Storage stats

Every PUT, copy and DELETE a node makes passes the request counter (`src/objstats.rs`), which also
keeps objects and bytes by key component (`src/store_stats.rs`). A PUT knows its size. A DELETE
doesn't, so each node remembers the size of every key it has written, read or seen in a LIST its
background jobs already run (retention lists the segments it deletes, SlateDB's GC its SSTs, the
blob sweep the blobs), up to 262,144 keys. A change it has to guess is counted as uncertain: a
DELETE of a key it never saw takes the component's mean size, and an overwrite of a control-plane
key it never saw is taken as a replace. A component with no guessed change since the last backfill
is `exact`.

Each node folds its changes into `stats/storage` every 5 minutes and when it shuts down. That's a
GET and a conditional PUT on the control-plane client, never on a request or commit path: 8,640 of
each a month per node. A node that crashes loses up to 5 minutes of changes, and its next start
marks the totals approximate until the next backfill. A node that leaves for good keeps what it
folded.

The counts start at zero, so they mean nothing until one backfill lists the bucket. It lists the
prefix once, in key order, one LIST request per 1,000 keys (Class A on R2 and S3), at
`pagesPerSecond` (default 2, at most 50), and stops after `maxRequests` requests. It saves its place
every 20 pages or 15 s in `stats/backfill`, so a capped, failed or interrupted run resumes after the
last key it listed. One run at a time: a second call while one is running answers `AlreadyRunning`,
and another node takes a run over once its runner hasn't saved for 2 minutes. While it lists, every
node keeps its changes aside with their key and time. At the end each one is checked against the
page that listed its key. A change made before that page was read is already in the listing and is
dropped, one made after is kept, and one made while the page was in flight (within 250 ms on another
node's clock) is kept as uncertain.

To run it on a live PDS:

```steps
- title: Read the estimate
  body: "`curl -su admin:$TOKEN -H 'content-type: application/json' -d '{\"dryRun\":true}' https://<pds>/xrpc/vlpds.admin.backfillStorageStats`. Before the first backfill `estimatedObjects` comes from the LISTs the background jobs ran last (`estimateBasis: \"observed LISTs\"`), which misses prefixes nothing lists, so expect the real count to be somewhat higher. `estimatedRequests` is ceil(objects / 1000)."
- title: Run it with a budget
  body: "`-d '{\"maxRequests\":<estimate × 1.5>,\"pagesPerSecond\":2}'`. The cap is the most it can spend: a bucket bigger than the estimate stops at the cap with `phase: \"capped\"` instead of listing on."
- title: Watch it
  body: "`getStorageStats` shows `backfill.phase`, `requests`, `keys` and `cursor`, and so does the Object store page. At 2 pages a second, a million objects take about 8 minutes."
- title: Resume if it stopped
  body: "Call it again with a new `maxRequests`. It goes on from `cursor`. `restart: true` starts over instead."
- title: Check the result
  body: "`seeded: true`, `lastBackfillAt` set, and `exact: true` once every node has folded. `inexactBecause` says what's in the way otherwise."
```

A bucket of N objects costs ceil(N / 1000) LIST requests, plus a GET and a PUT of `stats/backfill`
each time it saves its place. A million objects is 1,000 LISTs and 50 saves (a PUT and a GET each). Running it again later
takes the same requests, and resets any drift.

### Repo bytes and filter counts

`repoBytes` is the repo's record blocks plus its MST node blocks, leaves included: what a
`getRepo` CAR carries, less the commit and the framing. It is not what the repo's rows take in
the bucket. It rides in the repo's counts row (`S/`), which the commits that change the counts
already write, so it costs no read and no extra write. A created record adds its exact size and
a new node its own. The blocks a commit replaces aren't read, so a deleted record takes off the
repo's mean record size, a replaced node the mean node size, and an update is taken to keep the
record's size: close, not exact. `recountRepo` makes it exact again. A counts row written before
bytes were counted has none (`repoBytes` is absent); the repo's next load counts them, a read of
the whole repo once.

The filter counts ride in each slot's account totals (crate::totals), moved by the same
account changes that move the status counts: they are exact once a shard's totals have loaded.
`unconfirmed` is accounts whose email isn't confirmed, `no2fa` active accounts with no second
factor on their account row (TOTP, email codes or a passkey; the passkey count is written to the
row with each passkey change). A totals row written before they were counted is counted from the
slot's account rows when the shard opens. `attention` has no count: it depends on blob quotas and
lockouts, which the totals don't follow.

`listCases` takes `did` and `subject?` (a record's at:// URI or a blob's CID) to list the cases
about one account or one of its records. It filters every case: cases are few. Past a few
thousand, a subject index written with each case would replace the scan.

## Admin CLI

```diagram
caption: "`vlpds admin` is the same binary in client mode. Per-account calls go to any node and are routed to the owner. Per-node maintenance runs on every node `getClusterStatus` lists, and shards that moved mid-run are rerun on their new owner."
nodes:
  - { id: cli, label: vlpds admin, sub: "--url · token", at: [0, 3], size: [8, 3], tone: accent }
  - { id: any, label: any node, sub: "account · invites · layout", at: [13, 0], size: [10, 3], tone: accent }
  - { id: every, label: every node, sub: "rewrap · rotate-plc-keys", at: [13, 6], size: [10, 3], tone: accent }
  - { id: own, label: owner of the DID, sub: forwarded, at: [28, 0], size: [9, 3], tone: blue }
  - { id: cover, label: shards covered, sub: "missing → rerun", at: [28, 6], size: [9, 3], shape: note, tone: muted }
edges:
  - cli.r -> any.l
  - cli.r -> every.l
  - "any -> own: per DID"
  - every -> cover
```

```bash
export VLPDS_ADMIN_TOKEN=...                # or --admin-token-file, as the node reads it
vlpds admin --url http://127.0.0.1:2583 cluster status
docker exec vlpds vlpds admin account list  # inside the container: no token argument needed
```

`--url` (default `http://127.0.0.1:2583`, env `VLPDS_URL`), the token and `--json` can go before or
after the command. Output is a table or a short message, and `--json` prints the raw results. It
exits 1 on an XRPC error or on any failed item in a batch. `account delete` and `rebuild-repo` ask
first, and refuse to run off a terminal without `--yes`.

| Group | Commands |
|---|---|
| Accounts (`pdsadmin account …`) | `account list [--email PREFIX]`, `create EMAIL HANDLE`, `delete DID`, `takedown DID [--ref R]`, `untakedown DID`, `reset-password DID`, `info DID` |
| Invites and relays | `create-invite-code [--uses N] [--count N] [--for-account DID] [--handle-domain D]`, `request-crawl [RELAY,…]` |
| Handle domains | `handle-domain list [--recount]`, `handle-domain add DOMAIN`, `handle-domain remove DOMAIN [--force]` |
| Identity | `publish-identity [DID…] [--file F]`, `rotate-keys [DID…] [--generate]`, `rotate-plc-keys`, `ensure-recovery-key` |
| Repos | `check-repo DID`, `rebuild-repo DID [--dry-run]` |
| Secrets | `rewrap-secrets [--dry-run] [--check-versions]` |
| Cluster | `cluster status`, `cluster finalize [--level N]`, `cluster lower --level N`, `layout`, `shard-split`, `shard-merge`, `reshard-abort` |
| Peer TLS | `tls ca`, `tls issue`, `tls show` (local files only, no node involved) |

- `check-repo` reads one shard snapshot, so it works on a repo that won't load. It checks the head
  commit and its signature, every record's hash, the MST rebuilt from the records against the head,
  the persisted interior nodes and the indexes. Node or index problems heal on the next cold load,
  so they aren't an emergency.
- `rebuild-repo` re-derives the repo from its records under a new signed commit and a `#sync`. It
  refuses when the records no longer rebuild to the head, which means records were lost and you
  need a restore. If a write lands in between, it fails with `InvalidSwap`, so run it again.
- Batches (`publish-identity`, `rotate-keys`) take one DID per line from a file and run one at a
  time. The PLC directory rate-limits, so keep `rotate-keys` to a few in flight per IP.
- `pdsadmin update` has no counterpart (roll the image instead, see
  [Upgrades](upgrades.md#rolling-deploy)). Neither do the sequencer-recovery scripts, since there's
  no single sequencer database to replay.

The full mapping from each reference command is in RUNBOOK
[Admin CLI](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#admin-cli).

## Common tasks

```steps
- title: Create an account for someone
  body: "`vlpds admin account create alice@example.com alice.pds.example` prints a generated 24-character password once. If invites are required, it makes a single-use code for the account."
- title: Hand out invite codes
  body: "`vlpds admin create-invite-code --count 5` (one per line), or the console's Invite codes page. To let accounts earn their own, see [Email and moderation](email-and-moderation.md#invites)."
- title: Take an account down
  body: "Run `vlpds admin account takedown <did> --ref <ticket>`, or use the account's Takedown panel. The repo is hidden and its sessions are revoked, and `untakedown` reverses it. For a record or blob, or to keep a reason and a case with it, use the Moderation page ([Operator moderation](email-and-moderation.md#operator-moderation)). A moderation service can do the same with a service token ([Moderation service](email-and-moderation.md#moderation-service))."
- title: A user is locked out
  body: "Too many wrong codes or passwords clear up by themselves. The factor lock doubles from 5 min, and the per-account sign-in bucket clears within the hour. A DID override on the Rate limits page lifts it early. If they lost their email inbox, change the address with `updateAccountEmail`, which drops the email factor. If they lost their authenticator or a passkey, a recovery code works in its place. If they lost those too, check it's them and use the account page's \"Two-factor sign-in\" panel, which resets every strong factor (`vlpds.admin.resetSecondFactors`, audited as `second_factors.reset`). See [OAuth and 2FA](../oauth-2fa.md#second-factors)."
- title: An OAuth client app gets 429s
  body: "Its backend uses one address for all of its users, and `oauth-ip` allows 3,000 per 5 min per IP. Add an IP override for that address on the Rate limits page. See [Rate limits](rate-limits.md#common-tasks)."
- title: Check the cluster after a change
  body: "Run `vlpds admin cluster status` and look for every lease valid, no unowned shards, no stuck split or merge, and one build rev (or the one you're rolling to)."
```
