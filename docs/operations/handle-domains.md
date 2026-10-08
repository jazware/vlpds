---
title: Handle domains
section: Operations
order: 114
status: ready
summary: "Giving out handles under more than one domain: adding and removing domains at runtime, the DNS and certificates each one needs, and invite codes for one domain."
---

```hero
diagram:
  caption: "Every node keeps the served domains in memory: the primary from `--handle-domain` plus the ones an operator added, stored in the bucket. A change on one node nudges the others, so the whole cluster serves it within a second. Handles, `/.well-known/atproto-did` and `/tls-check` all ask the same set."
  nodes:
    - { id: op, label: Operator, sub: console · CLI, at: [0, 0], size: [8, 2.6] }
    - { id: n1, label: vlpds node, sub: addHandleDomain, at: [20, 0], size: [9, 2.6], tone: accent }
    - { id: n2, label: other nodes, sub: re-read on a nudge, at: [20, 6], size: [9, 2.6], tone: accent, stack: true }
    - { id: cfg, label: "`config/handle-domains.json`", sub: added domains, at: [35, 0], size: [13, 2.6], shape: store, tone: amber }
    - { id: users, label: Handles, sub: "alice.at.example.org", at: [0, 6], size: [9, 2.6], tone: blue }
  edges:
    - "op -> n1: add · remove"
    - "n1 -> cfg: CAS write"
    - { from: n1.b, to: n2.t, label: reload nudge }
    - { from: n2.r, to: cfg.b, label: "read (≤ 10 s)", dash: true }
    - { from: users.r, to: n2.l, label: well-known · tls-check, tone: blue }
facts:
  - { value: "1", unit: primary, label: always served, note: "`--handle-domain` · can't be removed", tone: accent }
  - { value: "100", unit: domains, label: at most, note: "primary included", tone: violet }
  - { value: "≤ 10 s", label: until every node serves a change, note: "under a second when the nudge lands", tone: blue }
  - { value: "0", unit: restarts, label: to add or remove one, tone: amber }
```

`--handle-domain` sets the domain new accounts get handles under (`alice.pds.example.com`). One
PDS can serve more than that. If you host accounts for a few groups that each bring a domain, you
can add `at.group-a.org` and `group-b.net`, and their people sign up as `alice.at.group-a.org` or
`bob.group-b.net` on the same server.

The primary stays the default. With only the primary, nothing changes: `describeServer` lists one
domain and the handle checks are the same as before.

## Adding a domain

```steps
- title: Point DNS at the PDS
  body: "Add an `A` (and `AAAA`) record for `*.<domain>` with the same addresses as the hostname. Handles are verified over HTTPS at `https://<handle>/.well-known/atproto-did`, so each handle's name has to reach a node."
- title: Get certificates
  body: "With on-demand TLS, Caddy asks `/tls-check` before issuing for any name, so there's nothing to do. With one wildcard certificate per domain, add the domain to the proxy's config first (see [Certificates](#certificates))."
- title: Add it
  body: "On the console's Domains & invites page (`/admin/domains`), or `vlpds admin handle-domain add at.group-a.org`. Every node serves it within a second."
- title: Hand out sign-up links
  body: "`describeServer` now lists every domain, primary first. The sign-up and handle pages show a domain picker, and `/account/signup?domain=at.group-a.org` preselects one."
```

A domain has to be a lowercase DNS name of two or more labels. vlpds refuses IP addresses, names
under the TLDs handles can't use (`.local`, `.onion` and the rest of the reference's list), public
suffixes such as `co.uk` or `github.io`, and a domain it already serves. A domain can sit under
another one (`at.group-a.org` next to `group-a.org`). A handle then belongs to the longest domain
it's under.

Handles under an added domain follow the primary's rules. The part before the domain is one label
of 3 to 18 letters, digits or hyphens, and the reserved names stay reserved. The domain itself is
never a handle, so `at.group-a.org` can't be claimed under `group-a.org`.

The set lives in the bucket at `{prefix}/config/handle-domains.json`, next to the rate-limit config
and the relay list. Every node loads it at startup and re-reads it every 10 s with a conditional
GET, which costs one request per node every 10 s. A change also nudges every peer to re-read at
once. If the object is unreadable, a node keeps the last set it loaded and logs a warning.

## Counting accounts

The console and `vlpds admin handle-domain list` show each domain's active accounts (no status:
not deactivated, taken down, suspended or deleted). An account counts under the longest served
domain its handle is under, and a bring-your-own handle under none of them counts nowhere.

Those counts are cheap to read, so the console page refreshes every 5 s. Each shard keeps them
in its [totals rows](../state-storage.md#key-layout), counted by the handle minus its first label
(`alice.at.group-a.org` counts under `at.group-a.org`). Every create, handle change, status change
and delete moves the count in the same write, and the counts move with their shards. A list asks
every node for its shards' counts and maps each suffix to a domain when it reads. So a domain you
add counts the handles already under it right away, and removing one needs no recount.

A shard's counts load in the background for a second or so after it opens on a node. Until then
the list says the counts are partial and names the shards that are loading. The first time a
shard opens on a build that keeps these counts, it reads its account rows once to fill them in,
then writes them back.

`vlpds admin handle-domain list --recount` (or `listHandleDomains?recount=true`) counts every
account row on every node instead. Use it to check the kept counts. It reads every account in the cluster, so don't put it on a schedule.

## Removing a domain

`vlpds admin handle-domain remove at.group-a.org` (or Remove in the console) reads the active
accounts under the domain first, across every node's shards. If there are any, it refuses with the
count. It also refuses when a node didn't answer or a shard's counts are still loading, since the
count could be low. That lasts a second or so after a shard opens. Pass `--force` (Remove anyway in
the console) to remove it regardless. The primary can't be removed. Change `--handle-domain` and
restart for that.

A forced removal doesn't touch accounts. Each one keeps its handle, its repo and its sign-in. But
the PDS stops answering for the domain:

- `/.well-known/atproto-did` on the handle's host answers 404, so other services can't verify the
  handle any more and show it as invalid.
- `/tls-check` refuses the name, so Caddy issues no new certificates for it.
- `createAccount` and `updateHandle` refuse new handles under it.

This PDS's own `resolveHandle` still finds the account, as it does for any handle a local account
holds. Each of those accounts should switch to a new handle (any served domain, or their own), or
you can rename them with `com.atproto.admin.updateAccountHandle` (the console's account page). If
you add the domain back, the handles verify again.

## Certificates

| Proxy setup | What an added domain needs |
|---|---|
| Caddy with on-demand TLS (`vlpds_caddy_wildcard_dns: ""`) | Only DNS. The role's site catches every name it doesn't otherwise serve and asks `/tls-check` before issuing, which approves the hostname and active local handles under any served domain. |
| Caddy with wildcard certificates (`vlpds_caddy_wildcard_dns: cloudflare`) | The domain in `vlpds_extra_handle_domains`, which renders a `*.<domain>` site with its own certificate. The Cloudflare token must have Zone:DNS:Edit on that zone too. |
| Your own proxy | A certificate for `*.<domain>` (or on-demand certificates asked of `/tls-check`), sending the requests to vlpds with the `Host` header kept. |

Ansible doesn't push the domain set itself. The domains are operator state in the bucket, like the
relay list. The role only gets the proxy its certificates. On-demand certificates count against
Let's Encrypt's ~50 new certificates a week per registered domain, so a group that signs up a lot
of people at once is better off with a wildcard.

## Invite codes for one domain

With `--invite-required`, a code can be limited to one served domain, so one group's codes can't
create accounts under another group's domain:

```bash
vlpds admin create-invite-code --uses 20 --handle-domain at.group-a.org
```

`createInviteCode` and `createInviteCodes` take the same limit as `handleDomain` in their input.
A limited code is refused (`InvalidInviteCode`) for a handle under any other domain, including a
bring-your-own one. Codes without a limit work for every domain.

## Admin API

| Method | Input | Answer |
|---|---|---|
| `vlpds.admin.listHandleDomains` (GET) | `recount?` (count every account row instead of the kept counts) | `primary`, `domains` (primary first, each with `accounts`, `addedAt`, `addedBy`), `recounted` · `countsPartial` with the missing nodes or shards and `loadingShards` when a count is incomplete |
| `vlpds.admin.addHandleDomain` | `{domain}` | `InvalidDomain` or `DomainExists` on a bad or served domain |
| `vlpds.admin.removeHandleDomain` | `{domain, force?}` | `{domain, accounts}` · `DomainInUse` (409) with the count · `CannotRemovePrimary` · `DomainNotFound` |

They take the admin token like the other `vlpds.admin.*` methods, and the role's Caddy keeps them
off the public listener.
