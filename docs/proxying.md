---
title: Proxying
section: vlPDS
order: 7
status: ready
summary: "How app reads reach the AppView: service auth, the per-account owner, connection pools, read-after-write merging and the limits that keep a slow upstream contained."
---

```hero
diagram:
  caption: "An app's `app.bsky.*` call can reach any node. It runs on the account's owner, which signs a cached service-auth token, calls the AppView over a pooled connection and merges in the user's own writes the AppView hasn't indexed yet."
  nodes:
    - { id: app, label: App, sub: "app.bsky.* · chat.bsky.*", at: [0, 3], size: [8, 2.6] }
    - { id: entry, label: any node, sub: route by token's DID, at: [12, 3], size: [8, 2.6], tone: accent }
    - { id: owner, label: account's owner, sub: cached key · JWT, at: [24, 3], size: [9, 2.6], tone: accent }
    - { id: av, label: AppView, sub: "`--appview`", at: [37, 3], size: [8, 2.6], tone: muted }
    - { id: rw, label: Recent writes, sub: per-repo log, at: [24, 8.5], size: [9, 2.6], tone: blue }
    - { id: svc, label: other services, sub: "`atproto-proxy` header", at: [37, 8.5], size: [8, 2.6], tone: muted }
  edges:
    - "app -> entry: HTTPS"
    - "entry -> owner: forward"
    - "owner -> av: service auth"
    - { from: rw.t, to: owner.b, label: merge own writes }
    - { from: owner.r70, to: svc.l, label: SSRF-guarded, dash: true }
facts:
  - { value: "~300k", unit: req/s, label: per 16-core node, note: "measured against a stub AppView", tone: amber }
  - { value: "~50", unit: µs, label: of CPU per request, note: "no store read and no signing in steady state" }
  - { value: "64", label: in flight per account, note: "on its owner; 429 past it", tone: violet }
  - { value: "1,024", unit: conns, label: per upstream host, note: "pooled; a burst waits instead of connecting", tone: blue }
```

Most of what a Bluesky app asks its PDS for isn't the PDS's data. Timelines, threads, profiles and
notifications come from the AppView, so the PDS signs each of those calls as the user and passes it on.
It's the busiest path a PDS serves, and at Bluesky's scale it uses more CPU than commits do.

## What is proxied

| Request | Goes to | Service id |
|---|---|---|
| `app.bsky.*`, `tools.ozone.*` without an `atproto-proxy` header | `--appview "<url>,<did>"` | `bsky_appview` |
| `com.atproto.moderation.createReport` | `--report-service "<url>,<did>"` | `atproto_labeler` |
| `chat.bsky.*` | only where the client names the service in `atproto-proxy` | |
| any method with `atproto-proxy: <did>#<service>` | that service's endpoint in the DID document | as named |
| `app.bsky.actor.{get,put}Preferences` | served locally, stored in the account's private state | |
| `app.bsky.notification.{register,unregister}Push` | the `serviceDid` in the body (its `#bsky_notif` endpoint) | |
| `app.bsky.feed.getFeed` | the AppView, with a token for the feed generator | |

The Ansible role defaults to `https://api.bsky.app` and Bluesky's moderation service. Without
`--appview`, AppView methods answer 400 "No service configured". A request that names the configured
AppView's DID in `atproto-proxy` uses the configured URL without resolving anything.

Before anything goes upstream, the owner checks:

- Scope. OAuth tokens need `rpc:<method>?aud=<did>#<service>` (403 `ScopeMissingError`
  otherwise). Non-privileged app passwords can't call the `chat.bsky.*` methods the reference
  marks privileged.
- Not a PDS method. Account and session methods (`com.atproto.server.*`, `updateHandle`, the
  PLC signing methods) are never proxied, whatever the header says.
- Account status. A taken-down or suspended account gets 401 `AccountTakedown`, except for the
  moderation inbox's appeal method.

The forwarded request carries the reference's header allow-list (`Accept-Language`,
`atproto-accept-labelers`, `x-atproto-*`, `x-bsky-topics`) and a service-auth JWT. The JWT has
`iss` = the user, `aud` = the service DID and `lxm` = the method. For `getFeed`, the token's
audience is the feed generator's DID (looked up on the AppView, cached a minute) and its `lxm` is
`getFeedSkeleton`, so the AppView can call the generator as the user.

## The owner serves

```diagram
caption: Proxied methods route by the bearer token's DID, so every request for an account runs on the node that owns it, wherever it arrived. The owner keeps the account's signing key and the recent signed tokens in memory.
nodes:
  - { id: c, label: App, at: [0, 3], size: [6, 2.6] }
  - { id: n2, label: node 2, sub: entry, at: [9, 3], size: [7, 2.6], tone: accent }
  - { id: n1, label: node 1, sub: owns the DID's shard, at: [24, 3], size: [9, 2.6], tone: accent }
  - { id: acct, label: Account cache, sub: key + status per epoch, at: [24, 7.5], size: [9, 2.6], tone: muted }
  - { id: jwt, label: Token cache, sub: reused for 30 s, at: [24, -1.5], size: [9, 2.6], tone: muted }
  - { id: av, label: AppView, at: [38, 3], size: [7, 2.6], tone: muted }
groups:
  - { label: owner, around: [n1, acct, jwt], tone: accent }
edges:
  - "c -> n2"
  - "n2 -> n1: peer mTLS · h2"
  - "n1 -> av"
  - n1.b -> acct.t
  - n1.t -> jwt.b
```

For methods outside `com.atproto.*` and `vlpds.*`, routing uses only the bearer token's `sub`,
whatever DIDs the parameters name. The entry node forwards to the owner over the peer mTLS
connection pool, the same way it does for writes (see
[Architecture](architecture.md#request-routing-and-forwarding)). Running every request for an
account on one node keeps three things in one place:

- The account. Its signing key and status are cached on the owner, and the entry is only valid in
  the shard epoch it was read in. The owner's repo worker drops the entry when an account change
  applies, so a takedown or a key rotation affects the very next request. A 60 s age limit is the
  backstop. An unchanged key never goes back to the keyring or KMS.
- Service tokens. A JWT lives 60 s and is reused for 30 s per (issuer, audience, method, key),
  so a busy user's requests don't sign anything. A rotated key is part of the cache key, so it
  mints new tokens at once.
- The per-account cap and the recent-writes log (below). These need one counter and one log per
  account, instead of one per node.

With Caddy spreading requests evenly over N nodes, about (N − 1)/N of proxied calls take this one
extra hop. That's a fraction of a millisecond on a LAN. A forwarded proxied call waits up to 30 s
for its response head (the AppView's own deadline is shorter, below).

## Connection pools and limits

```facts
- { value: "1,024", unit: conns, label: per upstream host, note: "idle + busy · a request past it waits for one", tone: blue }
- { value: "128", unit: KiB, label: read whole before replying, note: "frees the connection at once · larger bodies stream" }
- { value: "10 s / 30 s", label: head deadline / body idle, note: "10 MiB response cap", tone: violet }
- { value: "64", label: in flight per account, note: "until each body is done · 429 RateLimitExceeded", tone: amber }
```

- Pools. Every outbound client is built once and shared. A plain `http://` AppView (one on a
  private network) uses vlpds's own HTTP/1.1 pool. There's one pool per host with a slot per IO
  thread, so a request normally touches only its own thread's slot, and the pool never holds more
  than 1,024 connections (`vlpds_http_client_pool_waits_total` counts waits). An `https://` AppView
  (the default deployment) uses one h2/HTTP/1.1 client per IO thread. Pooled HTTP/1.1 measured
  faster than one multiplexed h2c connection. No client follows redirects. New connections show up
  in `vlpds_http_client_connects_total`, which should stay flat under steady load.
- Deadlines. The proxy allows 10 s for the response head and 30 s without body progress (the
  reference's defaults). It only arms those timers while the upstream keeps it waiting.
- Bodies. Responses up to 128 KiB are read whole before the client gets them, so the upstream
  connection goes back to the pool however slowly the client reads. Larger ones stream through. If
  a client takes no data for 30 s, its upstream body is dropped (`vlpds_http_stalled_bodies_total`).
  Compressed responses pass through as the upstream encoded them, since vlpds never decodes and
  re-compresses a body it isn't changing.
- Per-account cap. At most 64 proxied requests per account are in flight on its owner, counted
  until each response body is done. So one client can't hold most of the pool with responses it
  never reads (`vlpds_proxy_rejected_total{reason="account_cap"}`,
  `VlpdsProxyAccountCapSustained`).
- Errors. Upstream errors pass through with the reference's mapping (a 500 becomes 502
  `UpstreamFailure`), and an unreachable upstream is a 502. CORS preflights are answered locally.

Watch `vlpds_upstream_requests_total{service,result}` and `vlpds_upstream_request_seconds{service}`
(services: `appview`, `chat`, `moderation`, `other`).

## Read-after-write

```diagram
caption: The AppView reports the repo rev it has indexed. The owner compares it with the repo's recent-writes entry and only rewrites the response when the user has newer records.
nodes:
  - { id: resp, label: AppView response, sub: "`atproto-repo-rev`", at: [0, 4], size: [9, 2.6], tone: muted }
  - { id: log, label: Recent writes, sub: "head · base · ≤ 32 records", at: [13, 4], size: [10, 2.6], tone: blue }
  - { id: pass, label: pass through, sub: rev ≥ head (nearly all), at: [28, 0], size: [10, 2.6], tone: solid }
  - { id: mem, label: merge from memory, sub: base ≤ rev < head, at: [28, 4], size: [10, 2.6], tone: accent }
  - { id: read, label: read the store once, sub: no entry or rev < base, at: [28, 8], size: [10, 2.6], tone: amber }
edges:
  - resp -> log
  - "log.r -> pass.l"
  - "log.r -> mem.l"
  - "log.r -> read.l"
```

The AppView indexes a write a few seconds after it happens, so a user who just posted or edited
their profile wouldn't see it. Like the reference PDS, when an AppView is configured, the owner
merges the requester's own records newer than the AppView's rev into the methods the reference
rewrites:

| Method | What is merged |
|---|---|
| `actor.getProfile`, `actor.getProfiles` | the local profile record over the requester's own view |
| `feed.getActorLikes` | the profile over the requester's post authors |
| `feed.getAuthorFeed` | on the requester's own feed: the profile, then new posts |
| `feed.getTimeline` | new posts, by `indexedAt` |
| `feed.getPostThread` | new replies under their parents · a thread built locally when the AppView doesn't know the requester's new post yet |

The owner keeps a small **recent-writes log** per active repo. It holds the head rev, a base rev and
every current record above the base (up to 32 records or 64 KiB, posts and the profile with their
values). A commit's ack updates it before the client is answered, so the next read already sees it.
Nearly every response carries a rev at or past the head and streams through untouched, with no
store read and no copy. Only a response with records to merge gets buffered, decoded, rewritten and
sent with `Atproto-Upstream-Lag` (milliseconds since the oldest merged write).

Rewriting means parsing an upstream body, so it's bounded. The cap is 10 MiB on the wire and
decoded, with at most two content codings. Large or compressed bodies decode on blocking threads.
At most 32 MiB of bodies are rewritten at once, and past that a response goes out unchanged. For
these methods the client's `Accept-Encoding` is narrowed to codings vlpds can decode. The outcome
is in `vlpds_proxy_read_after_write_total{result}`. On the no-merge path the measured cost is
nothing above the noise. A laptop A/B at 64 in flight measured ~43 µs CPU per request both before
and after (a separate run from the ~50 µs throughput bench below).

## Outbound safety

```diagram
caption: Operator-configured services are trusted. A service endpoint taken from a DID document is user-controlled, so it goes through checks and a client that can't reach private addresses.
nodes:
  - { id: cfg, label: "`--appview` · `--report-service`", sub: operator-configured, at: [0, 0], size: [12, 2.6] }
  - { id: did, label: DID document endpoint, sub: "`atproto-proxy`, push service", at: [0, 5], size: [12, 2.6], tone: rust }
  - { id: check, label: check_outbound_url, sub: https · public IP literals, at: [16, 5], size: [10, 2.6], tone: accent }
  - { id: guard, label: guarded client, sub: resolver drops private IPs, at: [30, 5], size: [10, 2.6], tone: accent }
  - { id: pool, label: proxy pool, sub: trusted, at: [30, 0], size: [10, 2.6], tone: muted }
  - { id: up, label: upstream, at: [44, 2.5], size: [6, 2.6], tone: muted }
edges:
  - "cfg -> pool"
  - did -> check
  - "check -> guard"
  - pool.r -> up.l30
  - guard.r -> up.l70
```

`atproto-proxy` lets a client send the user's signed request to any service named in any DID
document, so an attacker gets to pick the endpoint. vlpds treats it that way, as the reference does:

- The URL must be `https`, and an IP-literal host must be a public unicast address (`localhost` and
  `*.localhost` are refused).
- The request goes through the guarded client (`http::guarded` in
  [vlatproto](https://github.com/jazware/vlatproto)). Its DNS resolver drops every non-public address, so
  vlpds never connects to a name that resolves to `10.x`, `169.254.x` or loopback. The same client
  fetches `did:web` documents, handle `.well-known` files, OAuth client metadata and lexicons.
- No client follows redirects, so an allowed host can't bounce a request inward.

A refused endpoint answers 502 "Upstream service unreachable" and logs the reason. `--dev-mode`
lifts these checks so local stacks work. Never run production in dev mode. The reference's SSRF
tests run against vlpds in `tests/all/ref_ssrf.rs`.

## Throughput

```facts
- { value: "~300k", unit: req/s, label: one 16-core node, note: "stub AppView, 2 KB bodies, 1M accounts", tone: amber }
- { value: "~50", unit: µs, label: CPU per proxied request, note: "HTTP stack and syscalls dominate" }
- { value: "~1", unit: core, label: "for Bluesky's proxy load", note: "assumed 20k req/s fleet-wide", tone: blue }
- { value: "~0.8", unit: Gbit/s, label: each direction at that load, note: "~5 KB per response", tone: violet }
```

On a 16-core / 32-thread desktop-class box against a stub AppView, one node proxied 334k req/s with
50k active accounts and ~300k with 1M. That's about 50 µs of server CPU each, with a p99 of 3–7 ms
at 512–1,024 in flight. Cold accounts cost more (~100 µs per request while a million accounts load)
until the account and token caches warm up. The same box also ran the load generator and the stub,
so these numbers are a floor for the server.

For sizing, that means most of a cluster's CPU goes to proxying and Argon2 logins. Bluesky's assumed
20k proxied req/s is about one core fleet-wide and ~0.8 Gbit/s each way. At 10× it's ~10 cores and
~8 Gbit/s, which is why a 3-node cluster wants 3–10 Gbit/s NICs. See
[Scaling and clustering](operations/scaling-and-clustering.md#sizing-rules).
