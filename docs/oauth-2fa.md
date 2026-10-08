---
title: OAuth and 2FA
section: vlPDS
order: 9
status: ready
summary: "Signing in: the OAuth authorization server, DPoP, app passwords and legacy sessions, passkeys, TOTP and email second factors, recovery codes, trusted browsers, sign-in alerts, the OAuth-only switch, the account page, and how auth state stays correct under concurrency."
---

```hero
diagram:
  caption: "An OAuth sign-in. The app pushes its request, the user signs in on this server's page (with a second factor if enabled), and the app trades the code for DPoP-bound tokens. Any node serves each step: rows are routed to their owner."
  nodes:
    - { id: app, label: OAuth client, sub: an app, at: [0, 0], size: [8, 3] }
    - { id: par, label: "`/oauth/par`", sub: pushed request, at: [14, 0], size: [8, 3], tone: accent }
    - { id: page, label: sign-in page, sub: "`/oauth/authorize`", at: [28, 0], size: [9, 3], tone: accent }
    - { id: tfa, label: second factor, sub: "passkey, TOTP or email", at: [28, 6.5], size: [9, 3], tone: violet }
    - { id: token, label: "`/oauth/token`", sub: code → tokens, at: [14, 6.5], size: [8, 3], tone: accent }
    - { id: xrpc, label: XRPC, sub: access token + DPoP, at: [0, 6.5], size: [8, 3], tone: blue }
  edges:
    - "app -> par: 1 · PAR"
    - "par -> page: 2 · authorize"
    - "page.b -> tfa.t: if enabled"
    - "tfa.l -> token.r: 3 · code"
    - "token.l -> xrpc.r: 4 · tokens"
facts:
  - { value: "15 min", label: OAuth access token, note: "ES256, bound to the client's DPoP key; checked against its session on every request", tone: accent }
  - { value: "14 d", label: public-client refresh, note: "91 d idle / 730 d total for confidential clients", tone: blue }
  - { value: "5", unit: wrong codes, label: lock a second factor, note: "for 5 min, doubling up to a day; across all nodes", tone: violet }
  - { value: "~20 ms", label: Argon2id per password, note: "one permit per core (max 16); 503 after a 2 s wait", tone: amber }
```

vlpds is its own OAuth authorization server, with the same flows, tokens and error codes as the reference
PDS. It also has the legacy `createSession` login and app passwords. Every auth row (OAuth sessions, codes,
legacy sessions, second-factor state) lives in the account's private state in the bucket. So any node can
serve any step, and nothing is lost when a node dies.

## Sign-in methods

```diagram
caption: Three ways to get a session. All of them end in tokens this server checks itself; app passwords skip the second factor.
nodes:
  - { id: oauth, label: OAuth, sub: PAR · PKCE · DPoP, at: [0, 0], size: [9, 3], tone: accent }
  - { id: legacy, label: createSession, sub: password + factor, at: [0, 4.5], size: [9, 3], tone: accent }
  - { id: apppw, label: app password, sub: createSession, at: [0, 9], size: [9, 3], tone: muted }
  - { id: at, label: ES256 access JWT, sub: "15 min · DPoP-bound", at: [14, 0], size: [10, 3], tone: blue }
  - { id: hs, label: HMAC session JWT, sub: "2 h access · 90 d refresh", at: [14, 4.5], size: [10, 3], tone: blue }
  - { id: scoped, label: app-password JWT, sub: narrower scope, at: [14, 9], size: [10, 3], tone: blue }
edges:
  - oauth -> at
  - legacy -> hs
  - apppw -> scoped
```

| | OAuth | `createSession` (legacy) | App password |
|---|---|---|---|
| Used by | third-party apps | this server's account page, password-login clients, scripts | apps the user doesn't want to give a full login |
| Access token | ES256 JWT, 15 min, bound to the client's DPoP key | HMAC JWT under `jwt_secret`, 2 h | as legacy, scope `com.atproto.appPass` (or privileged) |
| Refresh | rotated each use · 14 d (public clients) or 91 d idle and 730 d total (confidential, `private_key_jwt`) | rotated each use · 90 d | as legacy |
| Second factor | on the sign-in page, unless the browser is [trusted](#trusted-browsers) · a [passkey](#passkeys) can replace the password | `authFactorToken`, unless the account page's browser is trusted · refused with `PasskeyRequired` when a passkey is the only strong factor | skipped, as in the reference |
| Revoked by | `/oauth/revoke`, the account page, any revoke-all | `deleteSession`, any revoke-all | `revokeAppPassword`, any revoke-all |

App passwords are server-generated (~80 bits) and stored as SHA-256 hashes. They can't change the account's
handle or identity, because `updateHandle` and `submitPlcOperation` refuse them. That's stricter than the
reference. Other services get short-lived **service-auth JWTs** signed with the account's repo key
(`getServiceAuth`). The one inbound use is video upload, where the video service calls `uploadBlob` with
the user's token.

### Scoped app passwords

An app password can also carry OAuth scopes, so a bot can get a password that only posts. This is a
vlpds extension: `createAppPassword` takes an optional `scopes` field (space-separated, the same syntax
an OAuth client asks for), and `listAppPasswords` returns it. Other PDSes ignore the field, so clients
that don't know about it keep working.

| Account page choice | Scopes | What the app can do |
|---|---|---|
| Full access | none | the same as any app password |
| Post only | `repo?collection=…&action=create&action=delete` for posts, likes, reposts and follows, plus `blob:*/*` | post, delete, like, repost, follow and upload |
| Read only | `rpc:*?aud=<AppView>#bsky_appview` | anything served by the AppView, so feeds and notifications, but no repo writes |
| Custom | whatever you type | what those scopes allow |

A scoped password gets what both the app password and its scopes allow. Its scopes can't add anything
an app password couldn't already do, so it still can't change the email, password or handle, and DMs
need the "privileged" flag as well as a chat scope (`transition:chat.bsky`). Every XRPC route checks the
scopes the same way it checks an OAuth token's, including proxied calls and `getServiceAuth`. The few
methods that refuse OAuth outright (`listAppPasswords`, `getTotpStatus`, `checkSignupQueue`) refuse a
scoped password too.

The scopes go into every access token as an `appPassScope` claim and are kept with the session, so a
refresh keeps them. A password's scopes never change after it's created. To change them, revoke it and
make a new one. `include:` permission sets aren't accepted, since they're resolved over the network
when an OAuth grant is made and an app password has no such step. "Read only" isn't strictly read
only. The AppView's `rpc:*` also covers its few writes (mutes, saved feeds, marking notifications seen),
because the scope syntax can't tell a query from a procedure.

## The OAuth flow

```steps
- title: Pushed authorization request
  body: "The client posts its request to `/oauth/par` (PKCE challenge, scopes, redirect URI, and a `private_key_jwt` assertion if it's confidential) and gets a `request_uri` that's valid for 5 min. Client metadata is fetched from its `client_id` URL through the SSRF-guarded client (10 s, 64 KiB, cached 10 min)."
- title: Sign in on this server
  body: "The browser opens `/oauth/authorize`. A device cookie remembers accounts that signed in on that browser within 7 days, so the user can pick one without a password unless the client sends `prompt=login`. Otherwise the user enters a handle and password, then the second factor if one is on. Sign-up (`prompt=create`) goes through the same checks as `createAccount`."
- title: Consent
  body: "Public clients always show the consent screen. It lists each requested scope in plain words with a checkbox, so the user can untick what they don't want (the page needs no script). Scopes are grouped by NSID authority, so `app.bsky.feed.post` and `app.bsky.feed.like` sit together (see [The consent screen](#the-consent-screen)). `atproto` can't be unticked, and the server refuses a post without it. The token's scope is exactly what was left ticked, and `transition:chat.bsky` goes with `transition:generic` since the spec says it doesn't work without it. A confidential client's consent is remembered per account, and the user is asked again only for scopes it hasn't been granted."
- title: Code exchange
  body: "The client posts the code, its PKCE verifier and a DPoP proof to `/oauth/token`. A code lives 5 min and works once, and reusing it revokes the session it created. A PKCE challenge seen in the last 24 h is refused."
- title: Use and refresh
  body: "Every XRPC call carries the access token and a fresh, single-use DPoP proof. The proof's `iat` has to be within 10 s of now (allowing 3 min of clock skew), and it carries a server nonce that rotates every 60 s. A refresh rotates the refresh token and replaces the access token, and the old ones stop working at once."
```

The OAuth signing key (P-256), DPoP nonces, CSRF tokens and refresh-token MACs are all derived from
`jwt_secret`, so every node can issue and check them without any shared state. Changing `jwt_secret`
invalidates every OAuth token and every legacy session.

PAR mints a request id that lands on a shard of the node that served it. Codes and refresh tokens carry
their account and session id. So `/oauth/*` calls get forwarded to the row's owner without an index. Code
exchange and refresh rotation only run on that owner. In the middle of a handoff they answer 503 and the
client retries.

DPoP proofs, client assertions and request objects are claimed once, cluster-wide, at the owner of their
routing key. Authorization-server claims are also written to the bucket before they count, so a new owner
after a failover still refuses a proof its predecessor accepted. Proofs on ordinary XRPC requests are only
claimed in memory (as in the reference). So right after a failover, a captured proof could be replayed once
within its short window, and only together with the access token it's bound to.

Users see and revoke their OAuth sessions on the account page and at `/oauth/account`. The API is
`vlpds.oauth.listSessions` and `vlpds.oauth.revokeSession`.

### The consent screen

A big grant can ask for 20 or more scopes, and a flat list of 20 checkboxes is hard to read. So the
consent screen groups every permission it lists by NSID authority, which is the NSID minus its last
segment. `app.bsky.feed.post` and `app.bsky.feed.like` both sit under `app.bsky.feed`. A
`repo:` scope groups by its collections, an `rpc:` scope by its methods, a `space:` scope by its
space type, and an `include:` permission set groups the permissions inside it. Permissions without
an NSID get groups of their own (uploads, account settings, full access, every space).

The top level is the first two segments (`app.bsky`), with one more level inside it (feed, graph,
actor). A group whose scopes all share one authority takes that authority's name instead, so a grant
that only touches `app.bsky.feed` doesn't nest under `app.bsky`. A group of one is just its row.
Each group has one summary line with a label from a small built-in map ("Bluesky posts and feeds",
"Bluesky chat", and so on) or else the prefix, plus the combined verbs and a count, like "Create and
delete in 4 collections · call 2 methods". Its warnings show in the summary too.

Opening a group shows each scope's checkbox, its plain-words description and the NSIDs it covers
with their actions. Groups are native `<details>`, so the page still runs no script under its CSP.
They start closed, except a group with a warning (full access, private messages, a read or write on
every space), which starts open. A permission set keeps one checkbox, since it's granted or refused
whole. "Show requested scopes" at the bottom shows the raw scope string.

## Second factors

```diagram
caption: After the password, the strong factors are offered. A passkey and a TOTP code (or a recovery code for either) both work when both are on. The email code is only asked for when neither is, and it's never accepted in their place.
nodes:
  - { id: pw, label: password ok, at: [0, 5], size: [8, 3], tone: accent }
  - { id: pk, label: passkey, sub: or a recovery code, at: [13, 0], size: [9, 3], tone: violet }
  - { id: totp, label: TOTP code, sub: or a recovery code, at: [13, 3.5], size: [9, 3], tone: violet }
  - { id: none, label: no factor, at: [13, 7], size: [9, 3], tone: muted }
  - { id: email, label: email code, sub: "mailed · 15 min", at: [13, 10.5], size: [9, 3], tone: violet }
  - { id: ok, label: session, at: [27, 5], size: [8, 3], tone: solid }
edges:
  - "pw.r -> pk.l: passkeys"
  - "pw.r -> totp.l: TOTP on"
  - pw.r -> none.l
  - "pw.r -> email.l: email factor only"
  - pk.r -> ok.l
  - totp.r -> ok.l
  - none.r -> ok.l
  - email.r -> ok.l
```

| | Passkey | TOTP | Email code |
|---|---|---|---|
| What it is | WebAuthn: a signature from the user's device or security key over a challenge, bound to this server's hostname | RFC 6238: SHA-1, 6 digits, 30 s steps, ±1 step | the reference's `emailAuthFactor` · what the Bluesky app offers |
| Turned on by | adding a passkey on the Security tab (see [Passkeys](#passkeys)) | `vlpds.server.setupTotp` + `confirmTotp` (account page) | `updateEmail` with `emailAuthFactor: true` and a confirmed address |
| Stored | public keys in the clear in `p/{did}\0passkeys` | secret KEK-wrapped in `p/{did}` | a keyed digest of the mailed code · newest replaces older |
| Lost it | another passkey, TOTP or a recovery code · the operator's reset | a passkey or a recovery code · the operator's reset | an admin email change (`updateAccountEmail`) drops the factor |

Passkeys and TOTP are the strong factors. When the first one goes on, the account gets 10 recovery
codes, one set shared by both and kept in the `mfa` private row. A code has 80 bits
(`xxxx-xxxx-xxxx-xxxx`) and is stored as SHA-256 salted by the DID, so checking one needs neither the
TOTP secret nor the key service. Each works once, `vlpds.server.regenerateRecoveryCodes` (with the
password) replaces the set, and the codes go when the last strong factor does.

TOTP codes and recovery codes share one guessing bound in the `mfa` row, and the email code has its own
on the same schedule. After 5 wrong codes the factor locks for 5 min, and each further lockout doubles
that, up to a day (429 `RateLimitExceeded`). No mail is sent while it's locked. The counter lives in the
account's private state, so it holds across nodes, restarts, and both the OAuth page and
`createSession`. The OAuth page also drops a pending sign-in after 3 wrong codes or refused passkeys. A
refused passkey doesn't count toward the lockout, since there's nothing to guess. An accepted code is
spent cluster-wide, and a TOTP step can't be reused inside its window. Since TOTP secrets are
KEK-wrapped, enrolling or checking TOTP needs the key service (503 during a KMS outage).

`ops/RUNBOOK.md` "A user locked out by a second factor" covers a locked-out user. Lockouts clear on their
own, and you can lift the per-account sign-in limit early with a DID override in the
[admin console](operations/admin-console.md). For a user who lost every factor and every code, the
operator can reset them ([Operator reset](#operator-reset)).

## Passkeys

```diagram
caption: "Two ways a passkey signs in on this server's pages. After the password it's the second factor, and with a PIN or biometric it replaces both. Either way the browser signs a challenge that names this server's origin, and the account's owner checks it against the account's `passkeys` row."
nodes:
  - { id: page, label: sign-in page, sub: "challenge · RP ID", at: [0, 3], size: [9, 3], tone: accent }
  - { id: dev, label: passkey, sub: device or security key, at: [17, 3], size: [9, 3], tone: violet }
  - { id: owner, label: account's owner, sub: "verify · claim once", at: [32, 3], size: [10, 3], tone: accent }
  - { id: row, label: "`passkeys` row", sub: public keys · counters, at: [32, 8], size: [10, 3], shape: store, tone: amber }
edges:
  - "page -> dev: credentials.get()"
  - "dev -> owner: assertion"
  - "owner -- row"
```

A passkey can't be phished the way a code can. The browser signs over the origin it's on, and vlpds
only accepts a `clientDataJSON.origin` equal to the `--public-url` origin. The relying-party ID is the public URL's host. So an assertion
made on a lookalike site, or framed (`crossOrigin` or `topOrigin` set), is refused. The flip side is that
passkeys only work on the public hostname, so the account page hides them on any other address it's
served from (an internal admin hostname, say), and changing the hostname invalidates every passkey on the PDS
([Configuration](operations/configuration.md#where-configuration-comes-from)).

| | |
|---|---|
| Algorithms | ES256, EdDSA and RS256 (Windows Hello), verified with `ring` · attestation isn't checked (`attestation: "none"`) |
| Per account | up to 20 passkeys, each with a name of up to 64 characters |
| Adding one | the password first (`startPasskeyRegistration`, `passkey-register-account`: 10 a day), then `finishPasskeyRegistration` · it turns the second factor on and mails the user |
| As a second factor | presence (UP) is enough · a PIN or biometric is welcome, not required |
| In place of the password | needs user verification (UV) and a discoverable passkey, whose user handle is the DID |
| Removing one | the password · ends what it signed in · "Sign out everywhere" ends everything |
| Lost | another passkey, TOTP or a recovery code ([Second factors](#second-factors)) |

### Signing in with a passkey

On the OAuth sign-in page (and `/oauth/account`) the password form is still there. Below it is a "Sign in
with a passkey" button, and the handle field has `autocomplete="username webauthn"`, so browsers offer
the passkey in autofill (conditional UI). This passwordless sign-in needs a discoverable passkey with
user verification. The browser hands back the user handle, which is the DID's bytes, so the post goes to
that account's owner with no index. Someone can send any DID as the user handle, but the signature still
has to verify against a key in that DID's own row, so a forged handle only picks which row fails. It
counts as both factors, so no second step follows.

After a password, an account with passkeys gets the factor-agnostic second step (`step=2fa`). The page
offers "Use your passkey" (listing only that account's passkeys), a TOTP code if TOTP is on, and a
recovery code. Trusted browsers still skip it, and "Trust this browser" works with a passkey too.

The account page (`/account`) signs in with `createSession`, which can't run a passkey, so it has two
calls of its own:

- `vlpds.server.startPasskeySignIn` returns options for `navigator.credentials.get`. Without a body it's
  passwordless and names no account. With `identifier` and `password` (after `createSession` answered
  `PasskeyRequired`, or next to a TOTP prompt), it checks the password and returns that account's
  passkeys, with a challenge bound to the DID and the credential epoch. So a password change voids it.
- `vlpds.server.createPasskeySession` takes `did`, the assertion and (on the second step) `trustDevice`, and returns
  the same legacy session `createSession` would. It's limited by `passkey-sign-in-ip` (100 per 5 min)
  and the `createSession-*` buckets keyed by the DID and IP. It doesn't spend `sign-in-account`, since
  anyone can name any account and a passkey can't be guessed.

`createSession` can't take a passkey, since there's no browser to vouch for the origin. So an account
with passkeys and no TOTP refuses a password `createSession` with 401 `PasskeyRequired`, and the message
points to OAuth or an app password. The email code doesn't stand in for a passkey. This server's own
account page (`Sec-Fetch-Site: same-origin`) still gets through with a recovery code, or on a trusted
browser. App passwords keep working, and with TOTP on, `createSession` takes a TOTP or recovery code as
before.

Nothing before the password says whether an account has passkeys. The passwordless options list no
credentials, `allowCredentials` only comes after a correct password, and every failed passwordless sign-in
says "Passkey not recognized". Each refusal is counted by reason in
`vlpds_passkey_failures_total{reason}`. A DID longer than 64 bytes (a long `did:web`) can't be a user
handle, so its passkeys are a second factor only, and the Security tab says so.

### Challenges, counters and removal

Challenges are stateless, like DPoP nonces and CSRF tokens. Each one is a nonce and an expiry (5 min)
MAC'd with a key derived from `jwt_secret`, bound to its purpose (sign-in, second factor, registration or
the account page) and to what it can finish. On the OAuth pages that's the browser and the flow, plus
the account for a second step. Rendering a sign-in page writes
nothing, and any node can mint or check one. After the signature verifies, the owner claims the nonce
cluster-wide (`claim_replay_anywhere`, written to the bucket before it counts), so a challenge works once
even across a failover, and junk posts never cost a write.

Synced passkeys (iCloud Keychain, Google Password Manager) report a signature counter of 0 forever, and
their copies are expected. So a counter that stays at 0 or goes up is accepted. One that goes backwards
on a passkey that can't be synced (a hardware key) means a clone or a replayed signature. That sign-in is
refused, the key is flagged until the owner removes it, and the owner is mailed. On a synced passkey it's
accepted and counted (`vlpds_passkey_counter_regressions_total{result}`). Each use updates the counter
with a compare-and-set, so a passkey removed mid-sign-in fails that sign-in.

Removing a passkey needs the password. OAuth sessions and account-page sessions record which passkey
signed them in, and those are revoked. Device sign-ins and unexchanged codes it approved are refused when
they're next used. The removal dialog's "Sign out everywhere" box runs a revoke-all. A password change or
reset doesn't remove passkeys, so someone holding the inbox can't reset the factor away. Adding or
removing a passkey always mails the owner (`security_change`, "Your Account's Sign-in Settings Changed"),
and so do renaming one, new recovery codes and turning TOTP on or off. The mail about a new passkey says
to remove it on the Security page and then change the password, since a password change alone leaves
passkeys in place. A registration's challenge only finishes with the session token that started it.

### Operator reset

A user who lost every passkey, the authenticator and the recovery codes still has their password, but
can't get past the second step. The operator can reset their second factors from the console (the
account page's "Two-factor sign-in" panel) or with `vlpds.admin.resetSecondFactors`. It removes passkeys,
TOTP, the recovery codes and trusted browsers, and ends what the passkeys signed in. The password and the
email factor stay. With "Also sign out everywhere" (`revokeSessions: true`) it runs a revoke-all too, for
when someone other than the owner may be signed in. A reason is required. The audit log gets a
`second_factors.reset` entry marked `started` before anything changes and one marked `done` (or
`failed`) after, and the user is mailed. Whoever talks the operator into a reset still needs the
password. Steps:
`ops/RUNBOOK.md` "Resetting a user's second factors".

Passkeys are bound to this PDS's hostname, so they don't move with the account
([Migration](migration.md)).

## Trusted browsers

```diagram
caption: "The password step on a browser the account trusts. Its device cookie names a `trust/` row in the account's private state, and the row counts only while the credential epoch and the account's second factors are what they were when it was written."
nodes:
  - { id: pw, label: password ok, at: [0, 3], size: [8, 3], tone: accent }
  - { id: row, label: "`trust/{hash}`", sub: "device cookie · ≤ 30 d", at: [11, 3], size: [10, 3], shape: store, tone: amber }
  - { id: skip, label: session, sub: no code asked, at: [32, 0], size: [9, 3], tone: solid }
  - { id: code, label: second factor, sub: "passkey, TOTP or email", at: [32, 6], size: [9, 3], tone: violet }
edges:
  - pw -> row
  - "row.r25 -> skip.l: unchanged"
  - "row.r75 -> code.l: missing · expired · changed"
```

The code step on the OAuth sign-in page and on the account page has a "Trust this browser" box. If the
user ticks it, that browser skips the second factor for that account for 30 days
(`--trusted-device-days`, 0 turns the box off). The password is still needed every time. Trust is
per browser and per account, keyed by the `vlpds-device` cookie the OAuth pages already set (the
account page's `createSession` sets one too when it needs to). The row's name is a hash of the
cookie, so a copy of the bucket doesn't give anyone a usable cookie.

A trust only counts while two things are unchanged since it was granted. The first is the
[credential epoch](#auth-state-under-concurrency), so a password change or reset, a takedown or any
revoke-all ends it (revoke-all also deletes the rows). The second is the account's set of second
factors. Turning TOTP or the email factor off or on, enrolling a new authenticator, or adding or
removing a passkey ends every
trust too. The trust is checked before any factor, so it covers whichever factors the account has.

On `createSession` the cookie only counts on this server's own pages (`Sec-Fetch-Site:
same-origin`), so other apps never skip the factor. The account page sends `trustDevice: true` with
its code to ask for trust. The Security tab lists trusted browsers (browser and OS from the user
agent, the address, and when the trust started, was last used and ends) and removes one or all of
them (`vlpds.server.getSignInSecurity`, `vlpds.server.revokeTrustedBrowser`). A device row the
account trusts is kept past the 7 day idle sweep until its trust ends, and the sweep deletes trusts
once they expire.

## Sign-in alerts and recent sign-ins

| | Recent sign-ins | Sign-in alert |
|---|---|---|
| Recorded or sent for | every successful sign-in · OAuth page, `createSession` with the password or an app password, a passkey on either page | a sign-in from a device the account hasn't used in 180 days |
| Kept | the last 50, at most 30 days old, in `signin/log` | at most 3 a day per account (`ALERTS_PER_DAY`) |
| Shows | when, method (app password name, OAuth client, `passkey` for one in place of the password), device, address, factor (`totp`, `email`, `passkey`, `recovery` or `trusted`) | device, method, address and time · links to change the password and to the Security tab |
| Skipped when | never | the user turned that kind off · the account has no email · the sign-in used an emailed code · it's the first sign-in vlpds records for the account |

Refused sign-ins go in a row of their own, `signin/failed`, for the operator console only. A wrong
password, a wrong or locked second factor and a sign-in rate limit each add an entry with the time,
method, address and user agent, once the account is known (a rate limit on the typed identifier
looks the account up first). A successful sign-in never touches the row. Like attempts (same method,
reason and address) within 10 minutes are one entry with a count, and the row keeps the last 20, at
most 30 days old. A flood costs at most one write a second per account and reason on each node, and
one every 10 s for rate-limited attempts. The attempts in between are added to the next entry
written, so a burst's count can come up short by its last second. The user's own Security tab
doesn't show them.

Each sign-in writes one row in the account's private state, at the account's owner, with a
conditional write. The row holds the log, the devices the account has used and today's alert count,
so the "new device", the once-per-device rule and the daily cap all hold across nodes. A browser is
its device cookie. An app has no cookie, so its user agent and address (a v6 address as its /64)
stand in for the device. That means an app on a phone that changes networks counts as new now and
then, which the daily cap keeps quiet. Each sign-in carries an id, and a write that finds its id
already there adds nothing. So a forwarded sign-in is logged once whichever node served it. A
`createSession` runs at the account's owner, and the OAuth page writes through to it.

Alerts are ordinary account mail (`purpose` `sign_in_alert`, subject "New Sign-in to Your
Account"), so they spend the [mail budgets](operations/email-and-moderation.md#mail-budgets) like any
other. The cap of 3 a day keeps them to a tenth of the recipient's 30 a day, so they can't crowd out
sign-in codes. If a budget is spent the alert is dropped (`vlpds_mail_suppressed_total`) and the
sign-in still works. The first sign-in vlpds records for an account sets the baseline without an
alert, so a new account, or an existing one the first time it signs in after an upgrade, doesn't get
one for the device it already uses. A sign-in that just used an emailed code doesn't alert either,
since the code went to the same inbox.

Users turn sign-in alerts off per kind on the Security tab. The two kinds are password sign-ins (the
OAuth sign-in page included) and app-password sign-ins. That's `vlpds.server.updateSignInSecurity`
with `alerts: {password, appPassword}`.

## OAuth only

Some apps still take a handle and password and call `createSession`. The OAuth-only switch on the
Security tab makes `createSession` refuse the account's main password with 401 `OAuthRequired`, so
the password only works on this server's own pages. App passwords keep working unless the user
also blocks them (401 `AppPasswordsBlocked`). The switch is only offered with a second factor on,
and it only applies while one is. Without a factor there's no second step to get around.
Blocking app passwords doesn't depend on a factor. It only refuses new sign-ins, so an app that's
already signed in with an app password stays signed in until the user revokes that password.

The checks run after the password is verified, so they don't tell a guesser anything, and before a
code is mailed. The error names aren't the reference's. The Bluesky app turns
`AuthFactorTokenRequired` into a code prompt, which would leave the user stuck, and it shows any
message that isn't "Authentication Required" or "Invalid identifier or password" as it is. So the
messages say what to do instead. This server's account page signs in with `createSession` too, so
same-origin requests from it still go through, and they still need the second factor (or a trusted
browser).

Passkeys and the switch don't interact. Passkeys only exist on this server's pages, which the switch
leaves alone, and a passkey counts as a second factor, so it lets the switch be turned on. An account
whose only strong factor is a passkey already refuses a password `createSession` with
`PasskeyRequired`, switch or not ([Passkeys](#passkeys)).

`ops/RUNBOOK.md` "A user locked out by OAuth only" covers a user an app refuses, and "A user lost their
passkeys" covers `PasskeyRequired`.

## The account page

| Tab | What a user can do | Details |
|---|---|---|
| Overview | see the handle, DID, status (with the date of a scheduled deletion), repo counts and the DID document | |
| Handle and email | change the handle to a name on this server or to their own domain, with a guided check · change and confirm the email | [Changing a handle](operations/email-and-moderation.md#changing-a-handle-on-the-account-page) |
| Security | passkeys · TOTP · recovery codes · recent sign-ins · trusted browsers · sign-in alerts · OAuth only · the recovery key · app passwords, scoped or not · connected OAuth apps · the password | [Passkeys](#passkeys), [Second factors](#second-factors), [Trusted browsers](#trusted-browsers), [Sign-in alerts](#sign-in-alerts-and-recent-sign-ins), [OAuth only](#oauth-only), [Scoped app passwords](#scoped-app-passwords), [Recovery keys](keys-security.md#plc-rotation-key-and-recovery-keys) |
| Repository, Media | browse records and delete one · preview blobs | |
| Spaces (only with `--spaces`) | connect with OAuth · see the spaces they write in and the ones they run · browse their own space records · add or remove a member, delete a space | [Your spaces on the account page](spaces/reading.md#your-spaces-on-the-account-page) |
| Export, Preferences | download a full backup or the repo CAR · view and edit stored app preferences | [Backups](migration.md#backups) |
| Deactivate or delete | deactivate, reactivate (which cancels a scheduled deletion) · delete with an emailed token | [Scheduled deletion](operations/email-and-moderation.md#scheduled-deletion) |

Users manage their account at `/account` on this server. The page signs in with `createSession`, so
the second factor applies there too, unless the browser is trusted. It also signs in with a passkey,
through its own two calls ([Signing in with a passkey](#signing-in-with-a-passkey)). The Spaces
tab is the one exception. Space data is OAuth-only, so that tab signs in again with OAuth and keeps
the session only while it's open.

## Auth state under concurrency

```diagram
caption: Two nodes acting on one account at once. Every auth write goes to the account's owner and is applied only if the rows are still what the caller read.
nodes:
  - { id: na, label: node A, sub: OAuth refresh, at: [0, 0], size: [8, 3], tone: accent }
  - { id: nb, label: node B, sub: password change, at: [0, 6], size: [8, 3], tone: accent }
  - { id: owner, label: account's owner, sub: per-key lock · compare, at: [14, 0], size: [10, 9], tone: accent }
  - { id: log, label: "`log/`", sub: one conditional write, at: [30, 3], size: [9, 3], shape: store, tone: amber }
edges:
  - "na -> owner: forward"
  - "nb -> owner: forward"
  - "owner -> log: if unchanged"
```

vlpds never relies on a node-local lock or on comparing clocks for correctness. Instead:

- Conditional writes. OAuth rows, legacy sessions, the credential epoch and second-factor state are only
  written with a compare-and-set at the account's owner, in one log write. If the shard moves between the
  check and the write, the write fails.
- Credential epoch. Every revoke-all (password change or reset, takedown, deletion) replaces a per-account
  random epoch in the same write that deletes the sessions. Logins and codes carry the epoch they started
  with and are written only if it hasn't changed. So a login racing a password change either landed first
  and got deleted, or it fails.
- Rotations. A refresh rewrites its session only if the row is still what it read. If a revocation deleted
  the row in the meantime, the revocation wins instead of being undone.
- Second factors. Attempts are recorded the same way, so N nodes don't get N times the guesses, and a code is
  accepted once.

Details and the reasoning: `DESIGN.md` "Auth state under concurrency".

## Passwords and Argon2

```facts
- { value: "19 MiB", label: Argon2id memory per hash, note: "2 passes, OWASP baseline · ~20 ms of one core", tone: amber }
- { value: "≤16", unit: permits, label: hashes at once per node, note: "one per core · more only adds memory" }
- { value: "2 s", label: wait for a permit, note: "then 503 Overloaded + Retry-After 1", tone: rust }
- { value: "100", unit: /h, label: sign-in attempts per account, note: "from any IP · plus per identifier + IP limits", tone: violet }
```

Password checks are the most expensive thing a node does. A login costs ~20 ms of CPU, and a commit costs
~0.1 ms. Hashing runs on a fixed pool with one permit per core (at most 16). Some requests are on a login
path (`createSession`, `createAccount`, OAuth sign-in and sign-up, `resetPassword`, `deleteAccount`,
`disableTotp`). If one of those waits 2 s without a permit, it's shed with 503 `Overloaded` instead of
queueing. Sheds are counted in `vlpds_argon2_shed_total` and alerted as `VlpdsPasswordHashingShed`. Admin
password changes still wait their turn.

Rate limits run before any hashing, so a flood from a few addresses or one account gets a 429 instead of a 503:

| Limit | Key | Default |
|---|---|---|
| `sign-in-account` | account, any IP (`createSession` and OAuth sign-in) | 100 per hour |
| `com.atproto.server.createSession-0` / `-1` | identifier + IP | 300 per day / 30 per 5 min |
| `oauth-sign-in-ip` | IP, OAuth sign-in form posts | 100 per 5 min |
| `oauth-ip` | IP, `/oauth/par`, `/oauth/token`, `/oauth/revoke` | 3,000 per 5 min |
| `passkey-sign-in-ip` | IP, the account page's passkey sign-in (`startPasskeySignIn`, `createPasskeySession`) | 100 per 5 min |
| `passkey-register-account` | account, `startPasskeyRegistration` | 10 per day |

An OAuth client whose backend calls `/oauth/token` for all its users from one address may need an IP override.
Overrides and live changes are in the [admin console](operations/admin-console.md).

## Revocation

```diagram
caption: "A revocation is a write at the account's owner. The owner enforces it at once; other nodes re-read the account's security rows within 10 s, and refuse to serve on a view older than 5 min."
nodes:
  - { id: ev, label: revoke, sub: password · takedown · logout, at: [0, 2], size: [9, 3], tone: danger }
  - { id: owner, label: account's owner, sub: "`sec/` rows · sessions", at: [14, 0], size: [10, 7], tone: accent }
  - { id: other, label: other nodes, sub: cached view · 10 s, at: [30, 0], size: [9, 2.6], tone: accent }
  - { id: oauth, label: OAuth requests, sub: session row checked, at: [30, 4.4], size: [9, 2.6], tone: blue }
edges:
  - "ev -> owner: one write"
  - "owner -> other: re-read"
  - "owner -> oauth: at once"
```

- OAuth access tokens. These are checked against their session row on every request. So `/oauth/revoke`, a
  refresh (which replaces the token) or a revoke-all takes effect immediately, despite the 15 min lifetime.
  Takedowns are checked there too.
- Legacy and app-password tokens. These are stateless JWTs. Revoking one writes a row under `sec/rvk/` (a
  session family, or "everything issued before now"). Every authenticated request reads the account's `sec/`
  rows through a per-node view. On the owner that view is cached until it changes, and elsewhere it's re-read
  every 10 s. The check fails closed. If the owner can't be read and the cached view is more than 300 s old,
  the request gets a 503 instead of a guess.
- Revoke-all. This happens on a password change or reset, takedown, account deletion, OAuth credential
  deletion and removing a passkey with "Sign out everywhere". It deletes every legacy and OAuth session and every trusted browser, and replaces the
  credential epoch, in one write. Its row
  is kept for the refresh-token lifetime (90 d), so a session that somehow survived still fails.
- Cleanup. A per-node sweep runs every 60 s. It deletes expired OAuth rows (requests, codes, sessions past
  their lifetime, devices unused for 7 d and not trusted), expired trusted browsers, and revocation rows once
  every token they cover has expired. Each
  delete only goes through if the row is unchanged.
