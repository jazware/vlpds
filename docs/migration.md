---
title: Migration
section: vlPDS
order: 10
status: ready
summary: "Moving an existing account to this server with /migrate: what the page does in simple and advanced modes, what is copied, and how identity moves safely."
---

```hero
diagram:
  caption: "`/migrate` runs in the user's browser. It copies the repo, blobs and preferences from the old server to this one, then has the old server sign a PLC operation that this server submits. Relays and the AppView follow the DID to its new home."
  nodes:
    - { id: old, label: current PDS, sub: any atproto PDS, at: [0, 0], size: [9, 3] }
    - { id: page, label: "/migrate", sub: "in the user's browser", at: [16, 0], size: [10, 3] }
    - { id: new, label: this server, sub: vlpds, at: [32, 0], size: [9, 3], tone: accent }
    - { id: net, label: relays · AppView, sub: follow the DID, at: [34, 7], size: [9, 3], tone: blue }
    - { id: plc, label: PLC directory, sub: "DID → PDS, keys, handle", at: [16, 7], size: [10, 3], tone: muted }
  edges:
    - { from: old, to: page, label: "getRepo\ngetBlob" }
    - { from: page, to: new, label: "importRepo\nuploadBlob" }
    - "new -> net: firehose"
    - { from: old.b, to: plc.l, label: signs the op, dash: true }
    - { from: new.b5, to: plc.r, label: submits it }
facts:
  - { value: "1", unit: tab, label: does the whole move, note: "nothing to install; a reload picks up where it stopped" }
  - { value: "1 GiB", label: largest repo, note: "`--max-import-mb`; imports stream in bounded batches", tone: amber }
  - { value: "1", unit: code, label: emailed by the old server, note: "it authorises the identity move; nothing else needs one", tone: blue }
  - { value: "72 h", label: to undo a bad PLC op, note: "with a recovery key listed ahead of the server's", tone: violet }
```

An account moves to vlpds the same way it moves between any two atproto servers. You create the
account here with its existing DID, copy its data, point the DID at the new server and switch the
old one off. vlpds serves a page at `/migrate` that does all of it in the browser.

Accounts keep their DID, followers, posts and likes. Only `did:plc` accounts can move with the
page, and a `did:web` is refused.

## Before you start

| Who | Needs | Why |
|---|---|---|
| User | the account's main password, not an app password | creating the account here and signing the PLC operation need a full session, so the page refuses an app password |
| User | an email address on the old account, and access to it | the old server emails the code that authorises the identity move |
| User | an invite code, if this server requires one | `--invite-required`. A `/migrate?invite=<code>` link fills it in |
| User | the tab open for the copy | the browser does the copying, and a reload resumes |
| Operator | `vlpds admin create-invite-code` (or the console) | to hand out invites. The console's Invites page copies a code's `/migrate?invite=` link |
| Operator | `--plc-recovery-did-key` set | so migrated accounts get the operator recovery key in their rotation keys (see [Keys and security](keys-security.md#plc-rotation-key-and-recovery-keys)) |
| Operator | `--crawlers` set and the server announced | so relays pick up the account once it's active (see [Relays and crawling](operations/relays-and-crawling.md)) |

A handle under the old server's domain (`alice.bsky.social`) stops working when the account
leaves. So the page asks for a new one under this server's handle domain and checks that it's
free. A handle on the user's own domain can be kept. The DID doesn't change, so its DNS or
`.well-known` record keeps pointing at it.

## Simple and advanced modes

```diagram
caption: "One state machine, two views. Simple mode (the default) groups the nine steps into five and uses plain words; advanced mode shows each step, the DIDs, keys and counts, and the option to add your own recovery key."
nodes:
  - { id: s1, label: Find your account, sub: "find · sign in", at: [0, 0], size: [10, 3], tone: accent }
  - { id: s2, label: Get ready, sub: "checks · handle · create", at: [12, 0], size: [10, 3], tone: accent }
  - { id: s3, label: Copy, sub: "repo · blobs · preferences", at: [24, 0], size: [10, 3], tone: accent }
  - { id: s4, label: Save a copy, sub: "optional backup ZIP", at: [36, 0], size: [10, 3], tone: muted }
  - { id: s5, label: Switch over, sub: "identity · finish", at: [48, 0], size: [10, 3], tone: solid }
edges:
  - s1 -> s2
  - s2 -> s3
  - s3 -> s4
  - s4 -> s5
notes:
  - { at: [0, 5], text: "Nothing changes anywhere before \"Create\". Nothing is final before the identity step.", align: start }
```

- Simple mode is written for someone who's never heard of a PDS. It avoids protocol words (DID,
  PLC, repo, blobs, rotation keys) and shows counts people recognise, like "About 30 posts and 3
  follows, plus 6 photos & videos".
- Advanced mode (a checkbox, remembered per browser) shows the same flow with the details. You get
  the DID, the old and new signing keys, rotation keys and PDS endpoints side by side, record and
  blob counts, and raw error codes. It also offers to generate or paste the user's own recovery key.

The pre-flight checks don't change anything. They confirm that this server is open (or needs an
invite) and that the account isn't already active here (an earlier unfinished copy is reused). They
also check that the old account is readable, how big it is (over 500k records or 20k blobs gets
flagged as slow), and which email the code will go to.

Progress survives a reload. The page keeps what's been done (no secrets) in the browser's
localStorage, so a closed tab resumes at the same step. Session tokens and a signed but unsubmitted
PLC operation are kept only in sessionStorage, and passwords stay in memory.

## What gets copied

```diagram
caption: "The copy step, in order. Each part is marked done only when it checks out, and re-running any of them is safe."
nodes:
  - { id: acct, label: createAccount, sub: "service auth from old\nstarts deactivated", at: [0, 0], size: [10, 3.6], tone: accent }
  - { id: repo, label: repo, sub: "getRepo → importRepo\nrecord count checked", at: [13, 0], size: [10, 3.6], tone: accent }
  - { id: blobs, label: blobs, sub: "listMissingBlobs loop\nup to 12 at a time", at: [26, 0], size: [10, 3.6], tone: accent }
  - { id: prefs, label: preferences, sub: "get → putPreferences", at: [39, 0], size: [10, 3.6], tone: accent }
edges:
  - acct -> repo
  - repo -> blobs
  - blobs -> prefs
```

1. The account. The old server issues a service-auth token for `createAccount` here, and the
   account is created with the existing DID, the chosen handle, email, password and invite. It
   starts deactivated, so it serves nothing and emits nothing until the switch.
2. The repo. The browser downloads `com.atproto.sync.getRepo` from the old server and uploads the
   CAR to `com.atproto.repo.importRepo` here, showing progress for both. vlpds verifies the CAR as
   it streams and writes it in bounded batches under a new repo generation. Then it swaps that
   generation in with one small commit, so a large import holds a few batches in memory instead of
   the whole repo. The page then compares `checkAccountStatus.indexedRecords` on both sides and
   stops on a mismatch (advanced mode can accept it). Re-running the step replaces the copy.
3. Blobs. `listMissingBlobs` here lists what the repo references and this server lacks. The
   browser fetches each one from the old server and uploads it, up to twelve at a time, and checks
   that each upload hashes to the same CID. A 429 pauses every worker until the rate-limit window
   resets. A 429, 502–504 or dropped connection from either server halves the workers, and they
   grow back as copies succeed. These uploads don't count against this server's per-IP limits. If
   the old server answers a blob with a 5xx, the page retries it twice quickly (0.5 s, 2 s) and
   then sets it aside, because the reference PDS answers 500 every time for a blob whose bytes it
   has lost. The page makes up to five passes over the rest. It reports the blobs the old server
   can't produce, and the user can retry them (a reload or Retry tries each once more) or continue
   without them.
4. Preferences. `app.bsky.actor.getPreferences` there, then `putPreferences` here.

Sessions, app passwords and OAuth authorisations aren't copied (the user signs in again), and
neither is any two-factor setting on the old server. Passkeys don't move in either direction. A
passkey is bound to its PDS's hostname, so the old server's passkeys can't sign in here, and the
passkeys added here stay here if the account moves on. The user sets up new ones on the new PDS
([Passkeys](oauth-2fa.md#passkeys)).

See [Record storage](record-storage.md#imports) for how big imports are admitted and why they stay
cheap.

## Backups

Between the copy and the identity move, the page offers one optional step. It saves a backup of
the account, taken from the old server while it's still the live one. "Save a copy (recommended)"
and "Skip" are equal choices, and either way the step isn't offered again. The same backup is on
the welcome screen (read from this server) and on the account page under "Export → Download my
data".

| In the ZIP | From |
|---|---|
| `repo.car` | `com.atproto.sync.getRepo` |
| `blobs/<cid>` | `listBlobs` + `getBlob`, each checked against its CID's sha-256 |
| `missing-blobs.txt` | only when a blob can't be fetched or doesn't match. It lists the CID and the reason, and the backup still finishes |
| `preferences.json` | `app.bsky.actor.getPreferences` |
| `identity/did.json`, `identity/plc-audit-log.json` | `resolveDid` and `vlpds.identity.getPlcAuditLog` on this server (the directory's log, for accounts hosted here) |
| `account.json` | DID, handle, email, server, the latest commit, dates and counts |
| `README.txt` | what each file is and how to restore it on any PDS |
| `vlpds/*.json` | account page only. App password names, dates and scopes, connected OAuth apps and the PLC rotation keys (all public, no secrets) |
| `keys/recovery-key.txt` | only if the user generated a recovery key in this tab (advanced mode) and ticked "include my recovery private key" (off by default) |

Space repos aren't in the ZIP yet, and the account page's Export says so.

The backup never contains a password, app password secret or session token. The server's repo
signing key isn't exportable either, since a new server signs with its own key once the DID points
to it.

The browser builds the ZIP itself, stored without compression since blobs are already-compressed
media. Where the File System Access API exists (desktop Chrome and Edge), it streams straight into
the file the user picks, so account size doesn't matter. Elsewhere the ZIP is assembled in memory
and saved as a download. The page shows a size estimate first and warns when it looks too large for
the tab. Blob fetches run eight at a time and back off on a 429 like the copy does. A blob that
answers 5xx gets two quick retries and then goes to `missing-blobs.txt`.

To restore elsewhere, create the account with the DID, `importRepo` the CAR, upload each blob,
`putPreferences`, then point the DID at the new server. The README gives the calls.

## Moving the identity

```steps
- title: Ask this server what the DID should say
  body: "`getRecommendedDidCredentials` returns this server's PDS endpoint, the account's new signing key, its handle, and rotation keys `[operator recovery key?, server rotation key]`. In advanced mode the user's own recovery key goes first."
- title: The old server emails a code
  body: "`requestPlcOperationSignature` on the old server. The code proves the account holder agrees to the move."
- title: The old server signs the change
  body: "`signPlcOperation` with the code and the recommended values. The old server still holds a rotation key for the DID, so it's the one that can authorise handing it over. The tab keeps the signed operation, so a failed submit can be retried without a new code."
- title: This server submits it
  body: "`submitPlcOperation` here. vlpds checks that the operation lists its rotation key, names it as the PDS and carries the account's signing key. Then it sends the operation to the PLC directory and emits `#identity`."
```

This step is the switch. Once the directory accepts the operation, apps and relays resolve the DID
to this server, and only this server's keys (and any recovery key listed ahead of them) can change
it. The old server can't move it back anymore. The new list replaces any rotation keys the user had
added on the old server, which is why the page offers to add one here.

A rotation key listed ahead of the server's key can override any operation the server key signs,
for 72 hours after it. vlpds puts the operator recovery key ahead of its own, and a user's own key
ahead of both. If the user generates one in the page, it shows the private key once, never stores
it, and waits for "I saved it" before moving on. Users can also add or remove one later from their
account page. Details: [Keys and security](keys-security.md#plc-rotation-key-and-recovery-keys),
[KEK and key rotation](operations/kek-and-key-rotation.md#operator-recovery-key).

## Spaces

When both servers run Spaces, the switch-over copies the account's space repos too. Space data is
OAuth-only on vlpds (password sessions and app passwords never touch it), so this step signs in
again on each side with OAuth. It runs after `activateAccount` here and before `deactivateAccount`
there, because `com.atproto.space.importRepo` needs the account live here and the old server has to serve
the repos while the account is still active there.

```steps
- title: Check both servers
  body: "An unauthenticated `com.atproto.space.listSpaces` on each side. A server that answers it as an unknown method doesn't run Spaces, and then the step is skipped with nothing to sign in to."
- title: Sign in at the old server
  body: "OAuth with `atproto space:*?authority=*&action=read_self`, which reads the account's own space repos and nothing else. The page lists the spaces with `listSpaces` and each repo's blobs with `space.listBlobs`."
- title: Sign in here
  body: "OAuth with `atproto space:*?authority=*&collection=*&action=create&action=read_self`, what `importRepo` checks, plus `blob:*/*` only when a repo names blobs."
- title: Copy each space
  body: "`space.getRepo` there, then `com.atproto.space.importRepo` here with that STAR archive (the space comes from its metadata), then each blob with `space.getBlob` there and `repo.uploadBlob` here (checked against its CID). 429s and dropped connections are retried as in the copy step."
- title: Show what moved
  body: "Each space is listed as copied (with its record and blob counts), as having nothing of the account's in it (a space it governs but never wrote in), or as not copied with the reason. The user can retry the failures or go on without them. Then the page revokes both sessions and deactivates the old account."
```

An import over a repo that's already here replaces it with the archive's records and gives it a
new rev ([Moving a repo in](spaces/storage.md#moving-a-repo-in)). So a reload, a Retry or a lost
answer just runs the import again, and the page keeps each space's outcome (no secrets) with the rest of
its progress so it only redoes what didn't move. Only the member repos move. A space the account
governs keeps its members and policy on the old server unless its host state is carried over with
`com.atproto.space.exportSpaceMeta` and `importSpaceMeta`, which the page doesn't call. The
authority's own repo needs its space here first, so it imports after `importSpaceMeta`.

Syncers see none of the account's space data between activation and the import, so the step runs
right away. It's seconds for a few spaces. If the user skips it or a space fails, that data stays in
the deactivated account on the old server.

### The page's OAuth client

The page is its own OAuth client. vlpds serves its metadata at `/oauth/client-metadata.json` as a
public client (`token_endpoint_auth_method: none`, DPoP-bound tokens, a redirect URI at
`/migrate/oauth/callback`). The account page's Spaces tab is the same client with its own redirect
URI, `/account/oauth/callback` ([Your spaces on the account page](spaces/reading.md#your-spaces-on-the-account-page)). On plain `http://127.0.0.1` the page uses a loopback client id instead,
so a local test works against the reference PDS too.

- The page discovers the authorization server from the PDS's
  `/.well-known/oauth-protected-resource`, then uses PAR, PKCE (S256) and DPoP (ES256). The code
  comes back in the URL fragment, so it's never sent to a server or in a `Referer`.
- The DPoP key is a WebCrypto key made non-extractable and kept in IndexedDB. Script on the page
  can sign with it while the tab is open, but nothing can read the private key out, so a token
  copied out of the tab is useless anywhere else.
- Tokens and the pending sign-in live in sessionStorage, so they die with the tab. The page revokes
  the tokens and deletes the keys when the step ends. A key a closed tab left behind is deleted on
  the next visit once it's a day old.
- Discovery takes https only (plain http just for the loopback client), and the protected-resource
  metadata has to name the server it came from.
- The callback checks `state`, the `iss` the server sends (RFC 9207) and that the token's `sub` is
  the account being moved.

It names the server to sign in at instead of looking it up from the DID document on every token.
That's on purpose. The old server isn't in the DID document anymore by the time this step runs, so
a client that insists on it (like `@atproto/oauth-client-browser`) refuses exactly the session the
copy needs. It's also ~19 kB of the page's bundle instead of ~208 kB.

## Afterwards

```steps
- title: Activate here, deactivate there
  body: "`activateAccount` on this server checks that the DID now points here, then serves the account and emits `#account`, `#identity` and `#sync`. The [Spaces](#spaces) step runs next, then `deactivateAccount` on the old one. The old server keeps its copy of the data as of the move."
- title: Relays notice
  body: "vlpds asks its `--crawlers` to crawl after new activity, at most once per relay per 20 minutes. For a new server, announce it once by hand with `vlpds admin request-crawl bsky.network`."
- title: Check it
  body: "In `checkAccountStatus` here, `activated` and `validDid` should be true, `indexedRecords` should be the record count, and `importedBlobs` should equal `expectedBlobs`. `vlpds admin check-repo <did>` should come back clean. The relay's `getRepoStatus?did=` should be active with this server's rev, the profile should load in the app, and the handle should resolve."
```

The page deactivates the old account without a `deleteAfter`, so the old server keeps its copy
until someone deletes it. When this server is the old one and a client does pass `deleteAfter`,
vlpds deletes its copy once that date and a 3-day minimum hold have passed ([Scheduled
deletion](operations/email-and-moderation.md#scheduled-deletion)).

Moving back, or onward, is just another migration from this server. The account is a normal
atproto account here, so `/migrate` on any server or `goat account migrate` can take it. Posts made
here after the move aren't on the old server.

If the move stops halfway, nothing is lost. Before the identity step, the account here is a
deactivated copy and the old account is untouched, so you can reload and continue or abandon it.
After the identity step, the page only needs to finish activating here and deactivating there, and
reloading resumes that.

## Testing a migration

`just migrate-e2e` runs the whole page end to end on one machine. It starts a local PLC directory,
a reference PDS (`ghcr.io/bluesky-social/pds:0.4`) and a mail catcher in Docker, plus a local vlpds
with rate limits on. Headless Chromium drives the page for four accounts. Between them they cover
both modes, email 2FA on the old server, a dropped `createAccount` answer, a wrong PLC code, a
reload in the middle of the blob copy, a 1.5 MB-blob account, a kept custom-domain handle, and user
recovery keys (generated and pasted). Then it checks both sides. Every record CID and blob byte has
to match, the preferences have to be equal, and the PLC document has to name this server with the
right rotation keys. The account has to be active here and deactivated there, and a new post has to
be accepted. `KEEP=1` leaves the stack running, and the details are in `bench/migrate/README.md`.

`just migrate-spaces-e2e` covers the Spaces step. Two accounts with two spaces each (one record
with a blob) move here, one from the reference PDS at the Spaces alpha and one from a second vlpds,
through the real authorization pages on both sides. One import's answer is dropped, so the retry
imports the archive again. Then each space repo has to hold the same records on this server and
verify there with `@atproto/space`, the blob has to have the same bytes, and a new write has to
verify.

Before migrating real accounts to a new server, migrate one test account and check it from outside
(the last steps of [Verify](operations/deploy.md#verify)).
