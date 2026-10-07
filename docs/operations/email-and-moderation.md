---
title: Email and moderation
section: Operations
order: 112
status: ready
summary: "Outgoing mail (SMTP or an HTTPS API, branding, disposable-address policy), the moderation service, operator takedowns and cases, blob quarantine and upload quotas, scheduled deletion, earned invites and external handles."
---

```hero
diagram:
  caption: "What a PDS operator configures around accounts. Mail leaves over SMTP or an HTTPS mail API from whichever node handled the request; a moderation service (Ozone) calls a fixed set of admin methods with its own service token; sign-up and handle changes pass the reference PDS's policies."
  nodes:
    - { id: user, label: Users, sub: "sign-up · handle · email", at: [0, 0], size: [9, 3] }
    - { id: ozone, label: Ozone, sub: "--mod-service-did", at: [0, 7], size: [9, 3], tone: muted }
    - { id: pds, label: vlpds, sub: any node, at: [14, 3.5], size: [8, 3], tone: accent }
    - { id: policy, label: Policies, sub: "handles · disposable mail · invites", at: [14, 10], size: [11, 2.6], shape: note, tone: muted }
    - { id: smtp, label: mailer, sub: "SMTP or HTTPS · queue 1,024", at: [30, 0], size: [10, 3], tone: violet }
    - { id: modmail, label: moderation mailer, sub: "admin sendEmail", at: [30, 4.6], size: [10, 3], tone: violet }
    - { id: report, label: report service, sub: "createReport", at: [30, 9.2], size: [10, 3], tone: muted }
  edges:
    - { from: user.r, to: pds.l30 }
    - { from: ozone.r, to: pds.l70, label: service JWT }
    - { from: pds.b, to: policy.t, dash: true }
    - { from: pds.r, to: smtp.l, label: mail }
    - { from: pds.r, to: modmail.l }
    - { from: pds.r, to: report.l, label: proxied }
facts:
  - { value: "2", unit: transports, label: one per mailer, note: "SMTP, or Cloudflare's HTTPS API where SMTP is blocked · unset, mail is only logged" }
  - { value: "3", unit: retries, label: per message, note: "after ~2 s, 10 s and 60 s; queued mail is lost if the node stops", tone: violet }
  - { value: "8,883", unit: domains, label: refused as disposable, note: "the reference's list, compiled in", tone: amber }
  - { value: "≤ 5", unit: codes, label: earned and unused per account, note: "one per --invite-interval-ms of account age", tone: blue }
```

These are the reference PDS's account-facing features, ported with the same behaviour and messages.
Each flag falls back to the reference's environment variable, so a reference `pds.env` works as is.
Every node of a cluster needs the same values. Sign-in second factors (email codes, TOTP, passkeys) are on
[OAuth and 2FA](../oauth-2fa.md#second-factors).

## Email

```diagram
caption: "The request path never waits on the mail provider. A node queues the message and a background task sends up to 4 at a time over a pooled connection. Tokens live in the account's state, so any node verifies a code another node mailed."
nodes:
  - { id: req, label: request, sub: "reset · confirm · PLC op", at: [0, 2], size: [9, 3] }
  - { id: queue, label: queue, sub: "1,024 · full = dropped", at: [14, 2], size: [9, 3], tone: accent }
  - { id: send, label: sender, sub: "4 at a time · 30 s", at: [28, 2], size: [9, 3], tone: accent }
  - { id: relay, label: provider, sub: SMTP or HTTPS, at: [42, 2], size: [8, 3], tone: muted }
  - { id: retry, label: retry, sub: "2 s · 10 s · 60 s", at: [28, 7.5], size: [9, 2.6], shape: note, tone: muted }
edges:
  - "req -> queue: enqueue"
  - queue -> send
  - "send -> relay: deliver"
  - { from: send.b, to: retry.t, label: transient · timeout, dash: true }
```

| Flag | Reference env | Notes |
|---|---|---|
| `--email-smtp-url` | `PDS_EMAIL_SMTP_URL` | `smtp://user:pass@host:587` (STARTTLS when offered, and `?tls=required` insists on it) or `smtps://…:465`. It holds credentials, so use `--email-smtp-url-file` |
| `--email-api-url` | | send over Cloudflare Email Sending's REST API instead of SMTP (see [Sending over HTTPS](#sending-over-https)). Set this or `--email-smtp-url` |
| `--email-api-token-file` | | the API's bearer token (`--email-api-token` takes it inline) |
| `--email-from-address` | `PDS_EMAIL_FROM_ADDRESS` | required with either URL, as `addr@host` or `Name <addr@host>` |
| `--email-smtp-ca-file` | | PEM CA certificate(s) trusted for the SMTP server(s) on top of the public roots, for a relay with a private CA or a local test server |
| `--moderation-email-smtp-url` | `PDS_MODERATION_EMAIL_SMTP_URL` | admin `sendEmail` only. Unset, moderation mail goes through the main mailer |
| `--moderation-email-api-url` | | the same over the REST API. Its token is `--moderation-email-api-token-file`, or the main one when that's unset |
| `--moderation-email-address` | `PDS_MODERATION_EMAIL_ADDRESS` | required with a moderation URL |
| `--email-brand-name` | `PDS_SERVICE_NAME` | default "{hostname} PDS" |
| `--email-home-url` | `PDS_HOME_URL` | footer link (default https://bsky.app) |
| `--email-logo-url` | `PDS_LOGO_URL` | header logo and footer mark (default the Bluesky logo). vlpds serves its own as a PNG at `/og/email-logo.png` (mail clients don't render SVG) |
| `--email-primary-color` | `PDS_PRIMARY_COLOR` | default `#067df7` |
| `--email-disable-confirmation-link` | `PDS_EMAIL_DISABLE_CONFIRMATION_LINK` | drops the bsky.app "click here" link |
| `--mail-daily-budget` | | account mails per UTC day for the whole cluster (default 900). Keep it under the provider's daily quota ([Mail budgets](#mail-budgets)) |

- A URL without its address, or the reverse, fails startup, and so do both URLs for one mailer.
  With neither, mail is logged (recipient, subject, purpose) and not sent. Sign-up still works, but
  nobody receives codes. In `--dev-mode` every mail is also kept in the node's dev mailbox, which
  the console's account page shows. The Ansible role refuses to deploy without a URL unless
  `vlpds_email_required: false`. It passes the SMTP URL and the API token as secret files
  (`VLPDS_EMAIL_SMTP_URL_FILE`, `VLPDS_EMAIL_API_TOKEN_FILE`) and never puts them in the
  container's environment.
- Admin `sendEmail` without a moderation mailer goes through the main mailer, so a single-SMTP
  deployment still delivers moderation mail. That's different from the reference, which logs the
  mail and answers `sent: true`.
- Deliverability is up to your provider. Send from a domain with SPF, DKIM and DMARC set up for
  that sender. Over SMTP each message carries a `Message-ID` on the From address's domain. Over
  the API, Cloudflare sets it.
- If mail isn't arriving, look at `vlpds_mail_messages_total{result="failed"|"dropped"}` (by
  `purpose`, where `admin` is moderation mail), `vlpds_mail_queue_depth`,
  `vlpds_mail_suppressed_total` (the budgets below), and the `mail not sent` / `mail dropped`
  warnings. The warnings name the recipient and purpose but never the token. SMTP 5xx and API 4xx
  rejections aren't retried.

### What is mailed

vlpds sends the reference's six account mails with its subjects and wording, each as plain text
plus HTML (`multipart/alternative`), its own sign-in alert in the same layout, and admin
`sendEmail` from a moderator. `purpose` is the metrics label.

| Mail | Subject | `purpose` | Sent by |
|---|---|---|---|
| Email confirmation | Email Confirmation | `confirm_email` | `requestEmailConfirmation` |
| Email update | Email Update Requested | `update_email` | `requestEmailUpdate` (confirmed address only), or `updateEmail` turning email 2FA off without a code |
| Password reset | Password Reset Requested | `reset_password` | `requestPasswordReset` |
| Sign-in code | Sign-in Confirmation | `auth_factor` | signing in to an account with email 2FA on |
| Account deletion | Account Deletion Requested | `delete_account` | `requestAccountDelete` |
| PLC operation | PLC Update Operation Requested | `plc_operation` | `requestPlcOperationSignature` |
| Sign-in alert | New Sign-in to Your Account | `sign_in_alert` | a sign-in from a new device (vlpds's own, see [Sign-in alerts](../oauth-2fa.md#sign-in-alerts-and-recent-sign-ins)) |
| Sign-in settings change | Your Account's Sign-in Settings Changed | `security_change` | a passkey added, renamed, removed or refused as a copy, new recovery codes, TOTP turned on or off, or the operator's second-factor reset (vlpds's own, see [Passkeys](../oauth-2fa.md#passkeys)) |
| Moderation | the moderator's subject | `admin` | admin `sendEmail` |

### Mail budgets

On top of each endpoint's own rate limit, every account mail spends three budgets before its code
is minted, so no path can mail around them. There's one for the recipient, one for the node and one
for the cluster. They protect recipients, the sender's reputation and the provider's quota, so the
bypass key, internal token, admin auth and IP overrides don't lift them. A DID override (console,
Rate limits) lifts a recipient's budget, and `--no-rate-limits` turns them off along with
everything else. Admin `sendEmail` is exempt from all three.

| Bucket | Default | Keyed by | Over it |
|---|---|---|---|
| `mail-recipient-hour` / `-day` | 10 / hour, 30 / day | the recipient account's DID | 429 `RateLimitExceeded` · `vlpds_mail_suppressed_total{reason="recipient_limit"}` |
| `mail-node-hour` | 200 / hour | the node | 429 · `reason="node_limit"` · alert `VlpdsMailNodeBudgetExhausted` |
| `mail-cluster-day` | `--mail-daily-budget` (900) / UTC day | the whole cluster, one count in the bucket | 429 · `reason="cluster_limit"` · alerts `VlpdsMailClusterBudgetLow` (under 20% left), `VlpdsMailClusterBudgetExhausted` |
| `password-reset-account-hour` / `-day` | 5 / hour, 15 / day | the account, from any IP | answered OK but not mailed (no account probing) · `reason="account_limit"` |
| `requestPlcOperationSignature` | 5 / hour, 15 / day | DID | 429 (the reference has no limit here) |
| sign-in code de-dup | one new code per 60 s | DID | no new mail (the live code still works) · `reason="dedup"` |
| sign-in alerts | 3 / UTC day, only for a device unseen in 180 days | the account, in its private state | not mailed, the sign-in still works. The alerts also spend the three budgets above, and a spent one drops the alert |

The other mailing endpoints keep the reference's limits. `requestEmailConfirmation`,
`requestEmailUpdate` and `requestAccountDelete` allow 5 / hour and 15 / day per DID, and
`requestPasswordReset` allows 15 / hour and 50 / day per IP.

Match the cluster budget to your provider. Mail providers cap sending per account per day, not per
server, so a per-node budget would grow with every node you add. `mail-cluster-day` is one count for
the whole cluster. It's kept in the bucket (`budget/mail.json`) and spent by whichever node sends
the mail, so it holds when nodes join, leave or restart. Set `--mail-daily-budget`
(`VLPDS_MAIL_DAILY_BUDGET`) below the provider's daily quota, and leave room for moderation mail,
which isn't counted. The console's Rate limits tab changes it live (`points`, or `windowSecs` for
another window). Windows are aligned to the epoch, so a day is the UTC day.
`vlpds_mail_budget_remaining{window="day"}` and `vlpds_mail_budget_limit{window="day"}` show where
the day stands on every node (they're read at least once a minute).

If the bucket can't be read or written, mail goes out uncounted instead of not going out at all.
`vlpds_mail_budget_errors_total` counts those (alert `VlpdsMailBudgetUncounted`). `mail-node-hour`
still bounds each node, which caps how fast one node can drain the day.

### Example: Cloudflare Email Service

Cloudflare's Email Sending relay speaks SMTP with an API token as the password. The same token
works for its REST API ([Sending over HTTPS](#sending-over-https)).

```steps
- title: Onboard the sending domain
  body: "In the dashboard (Email Service, Email Sending), add the domain you send from, e.g. `pds.example.com`. When the zone is on Cloudflare, Cloudflare publishes its records (a bounce subdomain's MX and SPF, and a DKIM key). Add a DMARC record (`_dmarc.pds.example.com`). The relay refuses mail from a domain that isn't onboarded."
- title: Create an API token
  body: "Create an account API token with the `Email Sending: Edit` permission. It's the SMTP password, and the username is the literal `api_token`."
- title: Configure vlpds
  body: "Put `smtps://api_token:<token>@smtp.mx.cloudflare.net:465` (implicit TLS) in the `--email-smtp-url-file`, and set `--email-from-address \"pds.example.com <noreply@pds.example.com>\"` and the branding flags. The relay's certificate is publicly trusted, so you don't need `--email-smtp-ca-file`."
- title: Test
  body: "Request an email confirmation for an account whose inbox you can read. In the received headers, look for `spf=pass`, `dkim=pass` and `dmarc=pass`. On the node, check `vlpds_mail_messages_total{result=\"sent\"}`."
```

vlpds stays inside the relay's limits. Those are 50 recipients per message (vlpds sends to one),
5 MiB per message, 30 s to authenticate and 300 s for DATA. There's also an account daily quota
that starts conservative on new accounts and grows with sending history (Cloudflare's
limit-increase form raises it). Set `--mail-daily-budget` below it, and raise both together. If a
recipient is on the account's suppression list (after a hard bounce or complaint), the relay
rejects the whole message unless the domain's "drop suppressed recipients" setting is on. vlpds
sees a 5xx, counts the mail as `failed` and doesn't retry.

### Sending over HTTPS

Some VPS providers block outbound SMTP (ports 25, 465 and 587 to every host). On such a host every
send times out, and the mail ends up `failed` after four attempts. HTTPS still
works, so in that case send through Cloudflare's REST API instead:

```bash
--email-api-url https://api.cloudflare.com/client/v4/accounts/<account_id>/email/sending/send
--email-api-token-file /run/secrets/email-api-token
--email-from-address "pds.example.com <noreply@pds.example.com>"
```

The token is the same kind the SMTP relay takes (an account API token with `Email Sending: Edit`),
so a deployment moving off SMTP can reuse it. The account ID is the one that owns the sending
domain. vlpds POSTs one JSON message per mail with the token as a bearer header, and the queue,
concurrency, budgets and metrics are the same as for SMTP. Each attempt gets 30 s. A 429, a 5xx
or a timeout is retried on the same 2 s, 10 s and 60 s schedule. Any other 4xx is permanent, such
as a bad token (401 or 403) or a sender domain that isn't onboarded. A 200 that lists the
recipient under `permanent_bounces` also counts as `failed`. The URL has to be `https://` and must
not carry credentials.

The API has the relay's limits (50 recipients and 5 MiB per message, the same account daily quota).
Use it only when SMTP is blocked. Otherwise SMTP needs no account ID and works with any provider.

Procedure: RUNBOOK
[Email](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#email-smtp-moderation-mail-branding).

## Moderation service

```diagram
caption: "A service JWT from `--mod-service-did` (or its `#atproto_labeler`) is accepted on the moderator methods only. Everything else that changes an account stays behind the admin token."
nodes:
  - { id: ozone, label: Ozone, sub: "service JWT · aud = our DID", at: [0, 3], size: [10, 3], tone: muted }
  - { id: check, label: verify, sub: "issuer · key · lxm · exp", at: [14, 3], size: [9, 3], tone: accent }
  - { id: mod, label: moderator methods, sub: "takedown · info · sendEmail", at: [28, 0], size: [11, 3], tone: ok }
  - { id: admin, label: admin-only methods, sub: "delete · update* · invites", at: [28, 6], size: [11, 3], tone: danger }
edges:
  - ozone -> check
  - "check.r -> mod.l: allowed"
  - { from: check.r, to: admin.l, label: "401", dash: true }
```

- A service token may call the moderator methods: `getAccountInfo(s)`,
  `get/updateSubjectStatus` (takedowns), `sendEmail`, `getInviteCodes`, `disableInviteCodes`,
  `enable/disableAccountInvites`, and reading any account's `app.bsky.actor.getPreferences?did=`.
- These need the admin token: `deleteAccount`, `updateAccountEmail/Handle/Password/SigningKey`,
  `createInviteCode(s)` and every `vlpds.admin.*` method.
- With `--mod-service-did` unset, only the admin token works for any of them.
- `tools.ozone.*` calls from users go to the AppView like other proxied calls. They don't go to the
  moderation service. User reports (`createReport`) without an `atproto-proxy` header go to
  `--report-service` (`<url>,<service did>`), and they fail if that isn't configured.

If Ozone gets a 401, the error name tells you why. `UntrustedIss` means the token's issuer isn't
`--mod-service-did` on the node that answered. `BadJwtSignature` means Ozone's DID document doesn't
list the key it signs with (vlpds re-resolves once first, so a just-rotated key works).
`BadJwtAudience` means the token wasn't addressed to this PDS's `--service-did`. Takedowns from
either path take effect on every node. See [Admin console and CLI](admin-console.md#common-tasks).

## Operator moderation

```facts
- { value: "3", unit: kinds, label: of takedown, note: "account, record, blob · each needs a reason and is audited" }
- { value: "30", unit: days, label: blob quarantine, note: "`--blob-quarantine-days` · restorable until then", tone: amber }
- { value: "25 GB", label: per-account blob quota, note: "`--blob-quota-gb` · per-account override in the console", tone: blue }
- { value: "500", unit: uploads, label: per account per day, note: "`--blob-uploads-per-day`", tone: violet }
```

Sometimes a notice reaches you directly, like a copyright (DMCA) notice, an abuse report or a
request from law enforcement. Reports users file in their apps go to the moderation service instead
(see above).

### Intake

Publish an address people can write to. `describeServer` returns `--contact-email-address`
(reference `PDS_CONTACT_EMAIL_ADDRESS`) as `contact.email`, and the landing page's footer shows it
as "Report abuse: abuse@pds.example.com". vlpds doesn't read that mailbox, so route it to a person.
With Cloudflare Email Routing, that's a rule forwarding `abuse@pds.example.com` to your inbox.
Enabling routing on the PDS's subdomain adds its MX and SPF records and leaves an Email Sending
bounce subdomain alone.

### Workflow

```steps
- title: Open a case
  body: "In the console, go to Moderation, Cases. Open one case per notice, with its source (\"DMCA notice from Example Studios, received by email\") and a first note. A case is open, actioned, restored or dismissed, and it has a notes timeline and the subjects it concerns."
- title: Look up what the notice points at
  body: "Paste what the notice names into Look up. That can be a bsky.app profile or post URL (handle or DID form), an at:// URI, a handle or DID, a CDN image or video URL, or a DID and a blob CID. Content on another PDS is refused with an explanation, since you can only take down what this PDS stores. The record's JSON and its blobs show on request. Image previews stay blurred until clicked, and video never autoplays."
- title: Act
  body: "Take down (or restore) the account, the record or a single blob. Every action needs a reason and can be filed under a case. An open case becomes actioned, and an actioned one becomes restored when you reverse it. Takedowns by a moderation service (`updateSubjectStatus`) take the same path, so they're listed and audited too."
- title: Track
  body: "Active takedowns lists everything in force, filterable by kind, with a restore button. The Audit log has every takedown, restore, purge, case and quota change, with who did it (admin, or the moderation service's DID), the client address and why. Add notes to the case as it develops. A counter-notice and the restore window (DMCA: 10 to 14 business days) belong there."
```

The audit log, cases and the list of active takedowns are objects in the bucket under
`moderation/` (one per entry). So any node shows them, and they survive restarts, failovers and the
account itself. Each action is also logged on the node (`target=vlpds::audit`).

### What a takedown does

| Kind | Effect on this PDS | What stays |
|---|---|---|
| Account | Repo, records and blobs stop being served. A `#account` event tells relays and AppViews, and sessions and OAuth tokens are revoked. Restore reverses it (sessions stay revoked) | The repo and blobs, untouched |
| Record | Hidden from this PDS's record reads (`getRecord`, `listRecords`), as in the reference PDS | The record stays in the signed repo. `sync.getRepo`, `sync.getRecord` and the firehose still carry it, so relays and AppViews keep showing it until the user deletes it |
| Blob | `getBlob` answers BlobNotFound at once. The blob can't be uploaded again or referenced by a new record, and its bytes move to `blob-quarantine/{did}/{cid}` | Only the quarantined copy, until it's purged. The operator can still preview it from the console |

With `--spaces`, Look up also takes space URIs. A space record shows its author and takedown state,
and its value only through "Read record", which asks for a reason and writes a `space.read` entry
to the audit log before it reads. A space URI at its authority can be taken down as a whole: no
credentials are issued for it, syncers can't list its writers or register, and members' notifies
are dropped. [Privacy guardrails](../spaces/privacy.md#operator-access) has the details.

A taken-down blob's bytes are deleted `--blob-quarantine-days` (30) after the takedown unless the
blob is restored first. Until then, a restore moves the bytes back and the blob is served again.
After the purge, a restore only lifts the takedown, and the user can upload the blob again. The
unreferenced-blob GC never touches quarantined bytes, and `listMissingBlobs` doesn't ask the user
to re-upload a taken-down blob. The bytes count toward the account's quota until they're purged.
`vlpds_blob_quarantine_total{event}` counts quarantined, restored and purged blobs.

### What the operator can't do

- Copies elsewhere. Relays, AppViews and their CDNs (Bluesky's image and video CDNs) fetch and
  cache content from this PDS. A takedown here stops new fetches, but cached images can stay up for
  a while, and records already indexed stay in the AppView. Report the content to Bluesky Trust &
  Safety (or the AppView's operator) so they act on their copy.
- Records in the repo. A record takedown only hides the record here. Deleting it from the signed
  repo is the user's decision. If you need to stop serving it, take down the whole account.
- Content on other servers. A bsky.app link to an account hosted elsewhere is refused. Report it to
  its PDS (its `describeServer` `contact.email`) or to Bluesky.

### Upload quotas

Each account can store `--blob-quota-gb` (25 GB, decimal) of blobs and make
`--blob-uploads-per-day` (500) uploads per UTC day. Setting either to 0 turns it off. The console's
Look up page shows an account's usage and sets a per-account override (or puts it back to the
defaults). Over a limit, `uploadBlob` answers:

| Limit | Answer | Metric |
|---|---|---|
| Stored bytes | 413 `BlobQuotaExceeded`, with the account's usage in the message. A blob the account already stores adds nothing | `vlpds_blob_quota_rejections_total{reason="bytes"}` |
| Uploads per day | 429 `RateLimitExceeded`, until 00:00 UTC | `vlpds_blob_quota_rejections_total{reason="uploads"}` |

An account migrating in uploads the blobs its imported repo references without counting toward the
daily limit, and without being refused for size. Those blobs still count toward its bytes. An
account that arrives over its quota is listed on the console's Quotas view until it's under (raise
its quota, or ask the user to delete media). Its other uploads are held to both limits.

## Scheduled deletion

`deactivateAccount` takes an optional `deleteAfter`, a date the client suggests the server delete
the deactivated account after. The reference PDS stores it and never acts on it. vlpds deletes the
account once that date has passed and the account has been deactivated for at least
`--delete-after-min-hold-days` (3), whichever is later. `--delete-after false` keeps every account
until it's deleted by hand.

The hold is there since an OAuth app with `account:status?action=manage` can deactivate an account,
but deleting one takes the password and an emailed token. With a `deleteAfter` in the past, the app
could otherwise delete the account on the next sweep. Within the hold, the user can sign in with
their password and reactivate (the account page's "Deactivate or delete"), and that clears `deleteAfter`. So does an admin reactivation, and
an admin deactivation (`updateSubjectStatus`) replaces it with none.

The deletion is the same as `deleteAccount`: the repo, blobs, a `#account` event with status
`deleted`, sessions, and the handle and email claims. Like `deleteAccount`, it doesn't touch the
PLC entry. That's what an account that moved away needs, since the DID now points at its new host.

| Account | Deleted? |
|---|---|
| Deactivated, `deleteAfter` and the hold both passed | Yes, on the next sweep |
| Deactivated, `deleteAfter` in the future | On the first sweep after it |
| Reactivated | No, `deleteAfter` is cleared |
| Taken down or suspended | No. Moderation holds it, and the sweep picks it up again only once the takedown is reversed and it's still deactivated |

Each node sweeps the shards it owns every 10 minutes and deletes at most 100 accounts a pass. It
finds them through a `D/{did}` row the account's worker writes with the account, so a pass reads
only the scheduled accounts. A shard move carries the rows along, and the new
owner's sweep takes over. The worker refuses the delete unless the account is still due, so a
reactivation that lands mid-sweep wins. A deletion that stops partway (a crash, a shard move) is
finished by the next pass. `getSession` and the console's account page show
`deletionScheduledAt`, and `vlpds_account_deletions_total{reason="delete_after"}` counts the
deletions (`user` and `admin` count the others).
To cancel a deletion that was scheduled by mistake, see `ops/RUNBOOK.md` "Cancelling a scheduled
deletion".

## Handle policy

```facts
- { value: "~1,000", unit: labels, label: reserved, note: "first label of a handle under --handle-domain: 400 HandleNotAvailable" }
- { value: "7", unit: patterns, label: refused as slurs, note: "any user-chosen handle (also with . - _ removed) and record keys", tone: rust }
- { value: "3 s", label: to prove an external handle, note: "DNS TXT and HTTPS well-known, tried at once", tone: blue }
```

The reference's reserved-handle list and slur filter are compiled in verbatim
(`src/handle_policy/`), so updating them takes a release. They apply at createAccount, OAuth sign-up
and updateHandle, with the reference's error names. An admin (`updateAccountHandle`) skips both,
but a handle under `--handle-domain` must still be one 3–18 character label. The slur filter also
checks the record key of every create and update (createRecord, putRecord, applyWrites), the same
as the reference. Deletes aren't checked.

External handles (a domain outside `--handle-domain`) need proof, the same as in the reference.
That's either a DNS TXT record `_atproto.<handle>` = `did=<the account's DID>`, or
`https://<handle>/.well-known/atproto-did` serving the DID. vlpds tries both at once with a 3 s
deadline each, through the host's own resolver. Say a user swears their handle is set up and still
gets "External handle did not resolve to DID". Usually the node can't reach the zone
(`dig TXT _atproto.<handle>` from the node) or there's more than one `did=` record. `--dev-mode`
skips the proof.

Handles under `--handle-domain` resolve over HTTPS through Caddy's certificates for each handle.
See [Deploy](deploy.md#first-deploy).

### Changing a handle on the account page

```steps
- title: A name on this server
  body: "One field with the handle domain after it. The page checks the name as it's typed (about 0.4 s after the last key) and says why one can't be used: too short or long, a character that isn't allowed, reserved, or taken. One button switches."
- title: Your own domain
  body: "A four-step wizard. The user enters the domain, adds the proof (the TXT record, recommended, or the `.well-known` file, both with copy buttons), and the page checks it every 15 s for up to 30 minutes. Once it passes, one button switches."
- title: After the switch
  body: "The page says what changed. Followers and posts stay, the old handle stops pointing to the account, and apps can take a few minutes to show the new name. After a switch to a domain it offers to switch back to a name on this server."
```

Both paths ask `vlpds.identity.checkHandle?name=<handle>`, a read-only call for the signed-in account
(the parameter isn't called `handle` because forwarding would route by it). For a name under
`--handle-domain` it answers `available`, `taken` (by another account on this server), `reserved`,
`invalid` or `current`, with a message for the user. For a domain it looks up the TXT record and fetches the file, with the same 3 s deadlines and
the same SSRF-guarded client as updateHandle (guarded in `--dev-mode` too). It reports each one
separately: found with this DID, found with another DID, several `did=` records, or nothing. The
file check says `refused` when the domain resolves to a private address, since the guarded client
won't fetch from one. It
only answers `verified` when updateHandle would accept the domain. So a TXT record naming another
DID fails the check even when the file is right, since DNS's answer is the one that counts.

That also makes it the quickest way to see what a user is stuck on. The page shows them which of
the two it found and what it points to. Each account gets 60 checks per 5 min and 1,000 a day
(`vlpds.identity.checkHandle-*` on [Rate limits](rate-limits.md#the-buckets)). In `--dev-mode` the
answer has `proofRequired: false`, and the page offers to switch without the proof.

The page turns updateHandle's errors into plain words. Its limits are 10 changes per 5 min and 50 a
day per account, and a directory that refuses the PLC update leaves the handle as it was.

## Invites

```steps
- title: Require invites
  body: "Set `--invite-required` (on in the Ansible defaults). createAccount then needs a code."
- title: Hand out codes
  body: "Use `vlpds admin create-invite-code [--count N] [--uses N]` or the console's Invite codes page. Admin-made codes don't count toward anyone's earned limit."
- title: Let accounts earn codes (optional)
  body: "With `--invite-interval-ms` (reference `PDS_INVITE_INTERVAL`), an account earns one single-use code per interval of age, up to 5 unused. The codes are created when its app asks for them (`getAccountInviteCodes`). `--invite-epoch-ms` counts only age after that time."
- title: Stop or restrict
  body: "Unset `--invite-interval-ms` (rolling restart) to stop new earning. Existing codes stay. To cut one account off, use `disableAccountInvites`. Its codes are disabled, and codes it earns later are created disabled. Setting the epoch to now restarts everyone's earning from zero."
```

Disposable email domains are refused at createAccount and updateEmail with "This email address is
not supported, please use a different email.", as in the reference. The list (8,883 domains,
`src/email_policy/disposable_email_domains.txt`) is compiled in. An admin `updateAccountEmail`
doesn't check it.

Procedure and troubleshooting: RUNBOOK
[Moderation service, earned invites, external handles](https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md#moderation-service-earned-invites-external-handles).
