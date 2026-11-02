---
title: Sign-in providers
section: Operations
order: 115
status: ready
summary: "Letting people sign in with Google, Apple, Microsoft or your own identity provider: turning it on, adding a provider, per-provider recipes, adapters for non-OIDC methods, and removing or rotating one."
---

```hero
diagram:
  caption: "A provider is one config entry, not code. The browser carries the flow between a vlpds node and the provider; any node can run any step. The identity vlpds keeps is the provider's issuer plus its subject, never an email."
  nodes:
    - { id: op, label: Operator, sub: console · CLI · admin XRPC, at: [0, 0], size: [9, 2.6] }
    - { id: cfg, label: "provider config", sub: "bucket object · secrets KEK-wrapped", at: [14, 0], size: [12, 2.6], shape: store, tone: amber }
    - { id: node, label: vlpds node, sub: "/oauth/federated/*", at: [14, 6], size: [12, 2.6], tone: accent }
    - { id: user, label: Browser, at: [0, 6], size: [9, 2.6] }
    - { id: idp, label: Provider, sub: "Google · Apple · Entra · adapter", at: [32, 6], size: [12, 2.6], tone: muted }
  edges:
    - "op -> cfg: put · remove"
    - "cfg -> node: read (≤ 10 s)"
    - { from: user.r, to: node.l, label: start · callback }
    - { from: node.r, to: idp.l, label: discovery · token, dash: true }
facts:
  - { value: "off", label: by default, note: "no providers configured means no buttons and the routes 404", tone: amber }
  - { value: "2", unit: level, label: feature level needed, note: "a fresh prefix has it; an existing cluster finalizes", tone: rust }
  - { value: "1", unit: protocol, label: OpenID Connect, note: "code flow with PKCE; nothing is built in per provider", tone: blue }
  - { value: "(iss, sub)", label: the identity key, note: "never the email, never the provider's name" }
```

Sign-in providers let people use an account they hold somewhere else to get past the password
step on their vlpds account: Google, Apple, a company identity provider, or a wallet through an
adapter. vlpds has no provider built in. It speaks OpenID Connect to every one, and each
provider is an entry in a config object (`{prefix}/config/signin-providers.json` in the bucket) you edit at runtime.

It changes less than it looks. A provider sign-in replaces the password and nothing else. An account
with TOTP, a passkey or the email factor still gets that second step. Email stays required on every
account.

## Turning it on

Nothing happens until two things are true: the cluster is at **feature level 2**, and at least one
provider is configured. With no provider there are no buttons, and `/oauth/federated/start` and
`/oauth/federated/callback/{id}` answer 404. Providers can only be added or removed at level 2:
below it the admin calls answer 400 `FeatureLevelRequired`.

Level 2 exists so a mixed cluster never half-supports the feature. An old build doesn't know the
`fed:` credential references or the identity rows, so a node that did could sign someone in and
an old node could keep a session that an unlink should have ended.

```steps
- title: Check the level
  body: "`vlpds admin cluster status` prints `Feature level: L active` and, when every node could run a higher one, the finalize command. The console's Nodes & shards page shows the same."
- title: A fresh prefix
  body: "A new deployment starts at its first node's highest level, so it has level 2 already."
- title: An existing cluster
  body: "Roll every node to a build that knows level 2, then run `vlpds admin cluster finalize --level 2`. Once active, an older build exits 7 at startup. See [Upgrades](upgrades.md#rolling-upgrade-finalize-rollback) for the soak, the checks and why rollback after finalize is forward-fix only."
- title: Add a provider
  body: "Until level 2 is active, adding or removing a provider answers 400 `FeatureLevelRequired`. After it, follow [Adding a provider](#adding-a-provider)."
```

## Adding a provider

A provider is one object. These are its fields.

| Field | What it is | Notes |
|---|---|---|
| `id` | Your short name, `[a-z0-9-]`, 1 to 32 | Appears in URLs and labels only. Renaming it changes no identity |
| `name`, `icon` | Button text and an optional icon | `icon` is a `data:image/…` URI of at most 16 KiB |
| `issuer` | The OIDC issuer URL | `https`. Discovery's `issuer` must equal it byte for byte. One provider per issuer |
| `clientId` | This PDS's client id at the provider | |
| `clientAuth` | How vlpds proves itself at the token endpoint | `client_secret_basic`, `client_secret_post` or `private_key_jwt`; see below |
| `scopes` | Omitted means the default `openid email` | `openid` is always sent |
| `responseMode` | `query` (default) or `form_post` | Apple needs `form_post`; see [Apple](#apple) |
| `signup` | `off`, `invite` or `open` | See [Signup and email](#signup-and-email) |
| `signupsPerDay` | Accounts this provider may create per UTC day, cluster-wide. Default 100, 0 means no cap | On top of create-account's per-IP limit. Over it the signup form says "No more accounts can be created with {name} today" (429) |
| `trustEmail` | Use the provider's `email_verified` | Prefills and confirms the email at signup. Never finds or links an account |
| `requiredClaims` | Exact-match claim filter | `{"hd": "example.com"}` admits one Google Workspace domain |
| `idTokenAlgs` | The `alg` allowlist | Default `RS256`, `PS256`, `ES256`, `EdDSA`. `none` and HMAC are never accepted |

**Redirect URI.** The URL is per provider. Register this exact one at each provider:

```text
{public_url}/oauth/federated/callback/{id}
```

`{public_url}` is your `--public-url` and `{id}` is the provider's `id`. The console and
`vlpds admin signin-provider list` show it for each provider (the CLI column is "CALLBACK URL TO
REGISTER"), so copy it from there. It must be `https`, and the form_post return needs that too.

**Secrets never sit in the object in the clear.** A client secret or signing key is only ever
entered as a value, `"secret": {"value": "…"}` or `"key": {"value": "…"}` in `clientAuth`. The admin
call wraps it under the KEK (purpose `sign-in-provider-secret`, bound to the provider id) and stores
only the wrapped form. The list call returns `{"stored": "wrapped"}` in its place, never the value.
Leave it out of a `put` to keep the stored one. A KEK rotation rewraps these with the rest (see
[KEK and key rotation](kek-and-key-rotation.md)). There is no file form: a path accepted from the admin API could read any file the process can.
Changing a provider's `issuer` or `clientAuth` method needs the secret or key supplied again.

**Client auth.** Most providers use `client_secret_basic` or `client_secret_post` with a plain
secret. `private_key_jwt` takes a P-256 key and a `keyId`. A key always needs its `keyId`, for `private_key_jwt` and for `signedSecret` alike. Where a provider wants the client secret to
be a JWT you sign (Apple), add `signedSecret` with the JWT's `issuer` (a team id), `audience` and
`lifetimeSecs`. vlpds mints it from the key and refreshes it before it expires, so you never
paste a six-month secret again.

### Editing providers

All three ways edit the same object. `put` takes `ifVersion` (optimistic concurrency, so two operators can't overwrite
each other) and `force: true`, which skips the discovery fetch so you can save or fix a provider whose issuer is down. Without `force`, `put` fetches the issuer's discovery document first. Saves and removals are audited (`signin_provider.put`, `signin_provider.remove`). A
change reaches every node within 10 s, and an unreadable object keeps the last good set.

<!-- One place for the command names: if they change, fix this table. -->

| Where | How |
|---|---|
| Console | The sign-in providers page of the [console](admin-console.md) |
| CLI | `vlpds admin signin-provider list`, `put <file\|->` (a JSON file or stdin), `remove <id>` |
| Admin XRPC | `vlpds.admin.listSignInProviders`, `putSignInProvider` (create or replace), `removeSignInProvider` |

The admin methods take the admin token like the rest of `vlpds.admin.*`, and the role's proxy keeps
them off the public listener.

## Recipes

Each recipe shows the provider's side first, then the object to save. Provider consoles move
things around, so treat the names of their menus as a guide.

### Google

```steps
- title: Create the client
  body: "In Google Cloud Console, open APIs & Services, then Credentials, and create an OAuth client ID of type Web application. Under Authorized redirect URIs add `{public_url}/oauth/federated/callback/{id}`."
- title: Configure the consent screen
  body: "Choose Internal to admit only your Workspace, or External for any Google account. Scopes `openid` and `email` need no review."
- title: Copy the id and secret
  body: "The client id ends in `.apps.googleusercontent.com`. The secret is shown once and can be reset."
```

```json
{
  "id": "google", "name": "Google",
  "issuer": "https://accounts.google.com",
  "clientId": "1234.apps.googleusercontent.com",
  "clientAuth": { "method": "client_secret_basic", "secret": { "value": "<plaintext, wrapped on save>" } },
  "scopes": ["openid", "email"], "responseMode": "query",
  "signup": "off", "trustEmail": true
}
```

To admit only one Workspace domain, add `"requiredClaims": {"hd": "example.com"}`. Google puts `hd` in
the id_token for hosted accounts and omits it for personal ones, so a personal Gmail fails the
check. Don't rely on the email's domain for this. `requiredClaims` matches the claim exactly.

### Apple

Apple is the odd one: the client secret is a JWT you sign, the result comes back by POST, and the
user's name and email behave differently.

```steps
- title: Register an App ID and a Services ID
  body: "In the Apple Developer account, under Certificates, Identifiers & Profiles, create an App ID with Sign in with Apple enabled, then a Services ID. The Services ID is your `clientId` (for example `org.example.pds`)."
- title: Configure the web domain and return URL
  body: "On the Services ID, enable Sign in with Apple, add your PDS's domain and the return URL `{public_url}/oauth/federated/callback/{id}`. Apple takes only `https` and a real domain, not `localhost`."
- title: Create a key
  body: "Under Keys, create a key with Sign in with Apple enabled, pointed at your App ID. Download the `.p8` once and note its Key ID. Your Team ID is in the account's membership details."
- title: Keep the key text
  body: "You will paste the `.p8` file's contents into the provider as a value. vlpds wraps it under the KEK, so it never sits in the object in the clear."
```

```json
{
  "id": "apple", "name": "Apple",
  "issuer": "https://appleid.apple.com",
  "clientId": "org.example.pds",
  "clientAuth": {
    "method": "client_secret_post",
    "key": { "value": "<contents of the .p8, wrapped on save>" }, "keyId": "ABC123DEFG",
    "signedSecret": { "issuer": "TEAMID1234", "lifetimeSecs": 3600 }
  },
  "scopes": ["openid", "email"], "responseMode": "form_post",
  "signup": "off"
}
```

- **`form_post` is required** when you ask for `email`. Apple POSTs the result cross-site, which
  arrives without the browser's `SameSite=Lax` cookie, so vlpds stashes it and finishes on a
  same-origin GET. This works only over HTTPS.
- **The name comes once.** Apple sends a user's name only on the first authorization, and vlpds
  never depends on it. Don't promise users their Apple name will fill anything in.
- **Private relay.** A user can hide their address, and Apple gives vlpds a
  `@privaterelay.appleid.com` one instead. Mail to it is delivered only from senders you registered:
  in the Developer account, under Services, Sign in with Apple for Email Communication, add your
  sending domain (and the From addresses vlpds uses, `--email-from-address`). Until you do, sign-in
  mail, reset codes and notices to those users bounce. See [Email and moderation](email-and-moderation.md).

### Microsoft Entra ID

```steps
- title: Register an application
  body: "In the Entra admin center, open App registrations and create one. Choose the account types, add a Web redirect URI `{public_url}/oauth/federated/callback/{id}`."
- title: Create a client secret
  body: "Under Certificates & secrets, add a client secret. Its value is shown once, and it expires (up to 24 months), so put the expiry in a calendar."
- title: Note the ids
  body: "The Application (client) ID is the `clientId`. The Directory (tenant) ID builds the issuer."
```

```json
{
  "id": "entra", "name": "Microsoft",
  "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "clientId": "00000000-0000-0000-0000-000000000000",
  "clientAuth": { "method": "client_secret_post", "secret": { "value": "<plaintext, wrapped on save>" } },
  "scopes": ["openid", "email"], "signup": "off"
}
```

**Use a tenant issuer.** The multi-tenant endpoints (`common`, `organizations`, `consumers`) are not
one issuer. Discovery at `…/common/v2.0` reports an `issuer` with the literal `{tenantid}`, and each
id_token carries its own tenant's issuer. vlpds requires the discovered issuer to equal the
configured one byte for byte and the token's `iss` to match, so `common` can never validate and
a way to make it loose would let any tenant's users in. Pick the single tenant whose people should
sign in. To serve several tenants, add one provider per tenant. Identities are per issuer, so the
same person in two tenants is two identities.

Entra often leaves out `email_verified`. Treat the address as unconfirmed (`trustEmail` has nothing
to trust) and let vlpds confirm it itself.

### A self-hosted identity provider (Keycloak, Authentik)

This is the easiest case, since the provider is yours.

```steps
- title: Create an OIDC client
  body: "Keycloak: a client with Client authentication on, standard flow only, valid redirect URI `{public_url}/oauth/federated/callback/{id}`. Authentik: an OAuth2/OpenID provider with that redirect URI, signing key set to an RSA or ECDSA key (not the HMAC default)."
- title: Find the issuer
  body: "Keycloak: `https://idp.example.com/realms/<realm>`. Authentik: `https://idp.example.com/application/o/<slug>/`, which ends in a slash. Open `<issuer>/.well-known/openid-configuration` and copy `issuer` exactly: a trailing slash or a different host name is a mismatch."
- title: Stable subjects
  body: "Use a subject that never changes and is never reused. Keycloak's user id and Authentik's hashed user id are right. A username or an email is not."
```

```json
{
  "id": "company", "name": "Company sign-in",
  "issuer": "https://idp.example.com/realms/staff",
  "clientId": "vlpds",
  "clientAuth": { "method": "client_secret_basic", "secret": { "value": "<plaintext, wrapped on save>" } },
  "scopes": ["openid", "email"], "signup": "off", "trustEmail": false
}
```

Discovery, the key set and token requests go through the SSRF-guarded client, unless the issuer
itself is on a non-public address. A self-hosted provider on your LAN therefore works, and a public
provider can't redirect vlpds to your internal network. Plain `http` is accepted only for a
loopback issuer. Discovery and the key set are cached for an hour, with a day's grace if a refresh
fails.

## Methods that aren't OpenID Connect

Sign-In with Ethereum, GitHub, Discord and similar speak something else (a signed message, plain
OAuth 2 with no id_token). vlpds doesn't implement any of them. Put an **OIDC adapter** in front
and add it as a provider like any other.

| Method | Adapter |
|---|---|
| GitHub, Discord | A connector in [Dex](https://dexidp.io), which turns their OAuth 2 into OIDC. Keycloak and Authentik can do the same as identity brokers |
| Ethereum wallets (SIWE) | A SIWE-to-OIDC bridge: the wallet signs a SIWE message, the bridge checks it and issues an id_token whose `sub` is the address |
| Anything custom | Any server that issues a signed id_token for a stable subject |

An adapter becomes an **identity authority for your PDS**: whatever it signs in as, vlpds believes.
Before trusting one:

- **Run it yourself**, on infrastructure you control. A hosted adapter run by someone else is a
  second party who can sign in as any of your users.
- **Pin its issuer.** The issuer URL is part of every identity. Changing the adapter, its host name
  or its issuer URL strands every identity already linked, because the key is `(issuer, subject)`.
- **Protect its signing keys** like the KEK: they decide who gets in. Rotate them through the
  adapter's JWKS so old and new verify during the overlap.
- **Check the subject.** It must be stable and never reassigned: a wallet address (use one
  canonical casing), a user id, not a display name.
- **Check its claims.** The adapter must send `iss`, `aud` equal to your client id, `sub`, `iat`,
  `exp` and `nonce`, signed with `RS256`, `ES256` or `EdDSA`. vlpds reads identity from the id_token
  only, and never calls a userinfo endpoint.
- **Pick the response mode** the adapter supports (`query` unless it says `form_post`).
- **Keep email honest.** vlpds needs an email on every account. A wallet adapter has none, so such
  users must give one at signup and confirm it, and `trustEmail` should stay off.
- **Narrow who gets in** with `requiredClaims` where the adapter can express it.

## Signup and email

`signup` says what an unknown identity may do.

| Value | Behaviour |
|---|---|
| `off` | The provider signs in accounts that already linked it, and nothing else. The default |
| `invite` | A new identity may create an account with an invite code |
| `open` | A new identity may create an account freely. `--invite-required` still applies on top of either |

With `invite` or `open`, an unknown identity gets a server-rendered signup form (handle, email prefilled,
and an invite code when the policy is `invite`) that posts to `/oauth/federated/signup`. The account page
also shows "Sign in with …" buttons. Such an account has no password until an email reset sets one, and
its identity can't be unlinked while it is the only way in. Until a reset sets a password, deleting the
account, removing a passkey or reactivating a deactivated account needs an email reset first.

Keep `signupsPerDay` low for an `open` provider that hands out throwaway accounts. Its cap is cluster-wide
and counts only accounts created through that provider.

**Email is always required**, since moderation and recovery run on it. At signup the form asks
for it. With `trustEmail: true` and the provider's `email_verified` set, the address is prefilled and
marked confirmed, as long as the user leaves the address unchanged. Otherwise the user confirms it by mail like any other account. The disposable-domain
policy and uniqueness apply either way. `trustEmail` is only for that. It never lets an
identity find or take over an account.

**Account page sessions.** The account page's provider sign-in issues full-access sessions even for accounts set to
OAuth-only, as password sign-in on that page does, and only after the account's second factor.

**What users see.** A button per provider on the sign-in page and on `/oauth/account`. After the
provider says yes, the usual second factor applies: a trusted browser skips it, otherwise TOTP, a
passkey, a recovery code or the email code. Lockouts, the sign-in log and new-device alerts
are the existing ones.

**Linking and unlinking.** A user links a provider on `/oauth/account`, always through the provider's account chooser (`prompt=select_account`), after a fresh sign-in on that
browser (password plus second factor, a passkey, or an identity already linked, within the last
10 minutes). A stolen account-page token can't add a way in. The Security tab lists the identities
and sends the user to `/oauth/account` to change them. Without a fresh sign-in on that browser, that
page asks the user to confirm it's them (handle filled in), then lands on the account's sign-in
methods. Limits are 10 identities per account and one
per issuer, 10 link attempts a day. Every add and remove mails the owner. Removing an identity ends the
sessions it signed in, and is refused if it is the last way into the account (a password, a passkey or
another identity must remain).

**Why never by email.** Two providers can report the same address for different people (a
recycled corporate address, an unverified one, a tenant admin who set it). Matching on email would
let whoever controls it at *any* provider take the account. So the only link is one made by the
signed-in owner, and the email stored with an identity is just a label.

## Removing and rotating

**Removing a provider** makes its identities **dormant**: no button, no sign-in, but they stay listed
and users can still remove them. Adding a provider with the same issuer brings them back. An account
that only had that provider signs in through the email reset, which sets a password. A user who lost
both the provider account and the inbox needs you, as with a lost password and inbox.

**Rotating a client secret.**

```steps
- title: Create the new secret at the provider
  body: "Keep the old one valid if the provider allows two."
- title: Save it
  body: "Put the provider again with the new secret. Every node picks it up within 10 s. Run a test sign-in."
- title: Retire the old secret
  body: "Delete it at the provider."
```

Entra and Google secrets expire or reset on your schedule, so keep the date. **Apple's key** doesn't
expire; to rotate it, make a new key, put the provider with the new `.p8` contents and `keyId`, then
revoke the old one. vlpds re-mints the signed secret from the key, so no six-month token to track.
Changing the **signing keys of a provider you run** needs nothing here: vlpds refetches its key set on an
unknown `kid`, at most once a minute.

**Changing the issuer is not a rotation.** Identities belong to the issuer, so a new issuer starts
with none. Move the old users by having them link again, or keep the old issuer working.

**Recommend a PLC rotation key.** Third-party sign-in controls access to the account, not the
identity. A user who holds their own PLC rotation key (the account page's Security tab adds one) can
move to another PDS even if this one or their provider goes away. Say so on your sign-up page.

## Troubleshooting

A failed sign-in shows the user a plain refusal. The reason is in the node's log and the sign-in log.

| What you see | Cause and fix |
|---|---|
| `iss` mismatch | The token's `iss` isn't the configured `issuer` byte for byte. Copy it from `<issuer>/.well-known/openid-configuration`. Watch for a trailing slash, `http` vs `https`, and multi-tenant Entra (use a tenant issuer) |
| `aud` or `azp` rejected | The token was minted for another client. `clientId` must equal the provider's client id. With several audiences `azp` must be present and equal it |
| `exp`, `iat` or `nbf` rejected | Clock skew. vlpds allows 60 s and wants `iat` within the last 10 minutes. Fix NTP on the nodes (and on the provider if it's yours) |
| Unknown `kid` | vlpds refetches the key set once, at most once a minute per provider. If it persists, the provider's `jwks_uri` is unreachable from the nodes, or the token was signed with a key not in it |
| `alg` not allowed | The provider signs with something outside `idTokenAlgs` (often HS256 on a self-hosted one). Switch the provider to RS256 or ES256. `none` and HMAC are never allowed |
| Nonce mismatch | A stale or reused tab, a callback replayed, or a proxy that cached the redirect. Start again from the button. If it recurs, the provider or an adapter isn't echoing `nonce` |
| "already used" or a state error | The sign-in's 10 minutes passed, the callback was reloaded, or it finished in a different browser than it started in. Start again in one browser |
| `form_post` result never arrives | The return needs `https` and the provider must be allowed to POST to the callback. Behind a proxy, check that `/oauth/federated/callback/{id}` accepts POST and doesn't strip cookies |
| `redirect_uri_mismatch` at the provider | The registered URI isn't exactly this provider's `{public_url}/oauth/federated/callback/{id}` (copy it from `vlpds admin signin-provider list`). Check scheme, host, port, the provider id and the lack of a trailing slash. `--public-url` is what vlpds sends |
| Token endpoint 401 or `invalid_client` | Wrong secret, the secret expired, or `clientAuth.method` differs from what the provider expects. For Apple, check the team id, key id and `.p8` |
| A required claim fails | A `requiredClaims` value doesn't match the token (Google `hd` is missing for personal accounts) |
| "no account uses this identity" | Nobody linked it, and `signup` is `off`. The user signs in another way and links it on `/oauth/account` |
| 400 `FeatureLevelRequired` on put or remove | Level 2 isn't active yet. Finalize it first |
| No buttons on the sign-in page | No provider is saved, or level 2 isn't active (`vlpds admin cluster status`) |
| Provider mail to Apple users bounces | Register your sending domain with Apple's private email relay (see [Apple](#apple)) |
