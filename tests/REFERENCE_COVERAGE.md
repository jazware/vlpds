# Reference PDS test coverage

Every `it()` case in the reference TypeScript PDS's own suite (`bluesky-social/atproto` main,
`packages/pds/tests/**/*.test.ts`, 51 files) mapped to the vlpds test that covers it, or to why it doesn't apply, or to the
gap. Audited 2026-10-02. Each "covered" row was checked against what the vlpds test actually asserts, not just its name.

Status values:

- **covered**: an existing vlpds test asserts the same externally observable behavior.
- **ported**: a new test in `tests/all/ref_*.rs` (or `oauth::ref_oauth`) ports the case.
- **N/A**: the case tests something vlpds doesn't have or can't observe over the wire, such as SQLite/Kysely internals, TS unit
  internals, browser (puppeteer) UI, entryway mode, Ozone/AppView behavior behind the proxy, or `it.skip` cases.
- **divergent**: vlpds deliberately behaves differently (reason given; the notable ones are also in DESIGN.md).
- **GAP**: not covered and not fixed here (reason given).

## Summary

| | Cases |
|---|---:|
| covered | 295 |
| ported | 79 |
| N/A | 64 |
| divergent | 7 |
| GAP (left) | 0 |
| **total** | **445** |

Some rows marked `ported` or `covered` also carry a partial divergence that the row explains, for example "ported + divergent".

New test modules (`cargo test --test all ref_`): `ref_account`, `ref_auth`, `ref_handles`, `ref_invites`,
`ref_moderation`, `ref_moderator_auth`, `ref_plc`, `ref_proxy`, `ref_repo`, `ref_ssrf`, `ref_sync`, plus `oauth::ref_oauth`.

## Product fixes made by this pass

1. **Read-after-write Accept-Encoding negotiation** (`src/xrpc/proxy/read_after_write.rs`). A malformed `Accept-Encoding` is now
   400 `Invalid accept-encoding: "<part>"`, and one that rules out identity and every decodable coding is 406 NotAcceptable.
   Before, vlpds forwarded the header unchecked. Also, `*;q=0` next to an explicit coding no longer expands into a contradictory
   `gzip, gzip;q=0`.
2. **OAuth scope refusals** (`src/xrpc/authn.rs` `need_*`, used across repo/proxy/blobs/identity/server). A missing scope is now
   403 `ScopeMissingError` `Missing required scope "<scope>"`, as the reference does. It was 403 `InsufficientScope` with a generic
   message. A non-privileged app password calling a chat method through the proxy is now 400 InvalidToken "Bad token method".
3. **Deactivation over OAuth drops delegated credentials** (`src/xrpc/server.rs` `delete_delegated_credentials`). This is the
   reference's `deleteCredentials`: it drops all OAuth sessions, the remembered client authorizations, and every app password with
   its sessions. Password sessions stay.
4. **refreshSession with an access token** now fails with "Token could not be verified", the reference's jose `typ` check, instead
   of "Bad token scope".
5. **Writing into another account's repo** (create/put/delete/applyWrites) is now 401 AuthenticationRequired "Authentication
   Required". It was 403 Forbidden. A missing Authorization header says "Authentication Required".
6. **listRecords of an unknown, taken-down or deactivated repo** is now 400 InvalidRequest `Could not find repo: <repo>`, the
   reference's message. The owner and admins still read their own repos.
7. **describeServer** returns `blobUploadLimit`, `links.privacyPolicy`, `links.termsOfService` and `contact.email`. These come from
   the new `--privacy-policy-url`, `--terms-of-service-url` and `--contact-email-address` flags, which fall back to the reference's
   `PDS_*` variables.
8. **createAccount "Email already taken"** echoes the address as the user typed it.
9. **Moderation-service auth on admin methods** (`--mod-service-did`, `src/xrpc/authn.rs` `MODERATOR_METHODS`): Ozone calls
   the reference's `authVerifier.moderator` methods, and reads any account's getPreferences, with a service JWT; the
   admin-token-only methods still take Basic auth only. Errors are the reference's (`UntrustedIss` "Untrusted issuer", ...).
10. **Earned invite codes** (`--invite-interval-ms`, `--invite-epoch-ms`): getAccountInviteCodes creates codes with the
    reference's `calculateCodesToCreate`.
11. **Disposable email blocklist** (`src/email_policy.rs`, the reference's `disposable-email-domains-js` list) on createAccount
    and updateEmail.
12. **DNS TXT handle proof** (`src/handle_resolver.rs`): `_atproto.<handle>` TXT alongside `/.well-known/atproto-did`, in the
    reference HandleResolver's order and timeouts.
13. **Signing-key rotation re-signs the repo** (`src/xrpc/key_rotation.rs`, worker `KeyStep`). `admin.updateAccountSigningKey`
    (and `publishIdentity` with `syncPlc`, the rotate-keys script) writes an empty commit signed with the new key and emits
    `#identity` then `#sync`, so `getRepo` and the firehose verify against the new DID document right away. The new key is
    recorded before PLC is updated, writes wait out the rotation, and a rotation interrupted by an outage or a crash is finished
    from durable state by a retried call or the first write it fences (DESIGN.md "Signing-key rotation").
14. **Duplicate likes/reposts/follows/blocks are pruned** (`src/backlinks.rs`, a `bl/` backlink index). createRecord (unless
    `validate: false`) deletes the account's earlier record of the collection with the same subject (`subject.uri` for likes and
    reposts, the `subject` DID for follows and blocks) in the new record's commit, as the reference's `getBacklinkConflicts`
    (DESIGN.md "Backlinks").
15. **User service auth on uploadBlob** (`src/xrpc/authn.rs` `USER_SERVICE_AUTH_METHODS`, `Credentials::UserServiceAuth`). The
    reference authorizes `com.atproto.repo.uploadBlob` with `authorizationOrUserServiceAuth`: a Bearer token carrying an `lxm`
    claim is verified as a service JWT issued by the user (iss = a DID hosted here, aud = the PDS's service DID exactly,
    lxm = uploadBlob, signed with the current `#atproto` key) and the blob is that user's. The Bluesky app's video upload depends
    on it: the app gets such a token from getServiceAuth and gives it to video.bsky.app, which uploads the processed video to the
    PDS. vlpds refused it (InvalidToken), so video posts failed. **This audit missed it because no reference test exercises
    uploadBlob with service auth** (file-uploads.test.ts and the rest only upload with sessions); it was found by reading
    `auth-verifier.ts`. Tests: `user_service_auth::*` (getServiceAuth → uploadBlob → post with `app.bsky.embed.video`, listBlobs,
    getBlob; a stub video service end to end; wrong lxm / aud / expired / another user's key / a rotated-out key / a foreign or
    `did#service` issuer refused with the reference's errors; refused on every other method) and
    `ha_auth::user_service_auth_uploads_route_to_the_owner` (cluster routing by `iss`). Account status: taken-down accounts are
    refused also with service auth (divergence below). createAccount's `userServiceAuthOptional` (migration in) was already
    verified the same way (`authn::optional_service_auth`).
16. **Identity fixes** (`src/plc`, `src/xrpc/identity.rs`, claims in `src/xrpc/server.rs`; DESIGN.md "PLC identity"). Not
    reached by the reference suite, which runs against its in-process PLC server through `@did-plc/lib`'s client (it ignores
    POST bodies) and never resolves another server's handle:
    - every PLC write against a real did-method-plc directory was applied and then reported as failed (its `POST /:did`
      answers a text/plain `OK`, parsed as JSON). The mock directory now answers the same;
    - resolveHandle / resolveIdentity resolve handles and DIDs hosted elsewhere (AppView's resolveHandle, else the handle
      resolver), as the reference's resolveHandle does, so @-mentions of other servers' users resolve through the PDS;
    - createAccount with an existing DID refuses a `did#service` issuer (the reference compares the whole `iss`);
    - concurrent signups with one email can no longer both win; stale handle/email claims are taken over after a grace period;
    - concurrent PLC updates of one DID are serialized and rebuilt on `prev` races; updateHandle reconciles directory and
      account; submitPlcOperation is refused during a pending signing-key rotation; signPlcOperation consumes its token last
      (reference order); a DID with a signed op handed out or a user rotation key resolves through the directory.
    Tests: `plc::mock::tests::*`, `identity_races::*`.

## Notable divergences

- **Account deletion and firehose replay.** The reference deletes a deleted DID's earlier `repo_seq` rows, so a replay contains only
  the `#account` tombstone. vlpds's firehose is its append-only log, so a replay from before the deletion still carries that DID's
  earlier frames until retention drops the segments. Both guarantee that `#account deleted` is the DID's last event
  (`ref_sync::account_deletion_is_the_last_event_on_replay`). See DESIGN.md "Reference test divergences".
- **listRepos order** is `(slot, DID)` (per shard), not creation order.
- **getRepo `since`** returns a superset: the commit, all MST nodes and the newer records.
- **Uploaded blobs before a record references them** are served by getBlob in vlpds. The reference keeps them in a temp store and
  refuses.
- **Proxy target defaults.** vlpds needs an explicit `atproto-proxy` for `chat.bsky.*` and answers 501 for namespaces other than
  `app.bsky`/`tools.ozone`. The reference sends everything without a header to the AppView, and the listed `tools.ozone.*` methods
  to its `modService`. vlpds sends `tools.ozone.*` to the AppView: `--mod-service-did` is used for inbound auth only (no
  `modServiceUrl` routing).
- **Unresolvable proxy DIDs** (`did:foo#bar`) are 400 "could not resolve proxy did". The reference's resolver throws, which surfaces
  as a 500.
- **Stricter session requirements.** `revokeAppPassword`, `identity.updateHandle` and `identity.submitPlcOperation` need a full
  session (or OAuth with the identity scope); the reference accepts an app-password session (`ACCESS_STANDARD`; its
  `assertIdentity` applies to OAuth only). Deliberate: an app password can't move the account's identity.
- **resolveHandle of an unresolvable external handle** is 400 `HandleNotFound` (the lexicon's error); the reference throws a plain
  `InvalidRequest` "Unable to resolve handle". A dev-mode vlpds resolves external handles only through the AppView.
- **disable/enableAccountInvites** act on the account's existing codes as well as the flag. The reference only flips the flag,
  which marks interval-generated codes disabled when they are created (vlpds does that too).
- **OAuth UI** has no forgot-password step and no deactivate button. Those are the XRPC flows, and the pages are English only.
- **Legacy blob refs** are refused everywhere. The reference upgrades them on profile updates as a temporary hack.
- **uploadBlob with user service auth on a taken-down account** is 401 AccountTakedown, as with a session. The reference's
  `userServiceAuth` skips the account status check (its `checkTakedown` applies to the session path only), so a token issued
  before a takedown would still upload for up to an hour. Deactivated accounts upload either way.

## Gaps left

None.

---


## Account lifecycle, migration, recovery, entryway, account manager

### account-deactivation.test.ts

| case | status | vlpds |
|---|---|---|
| deactivates account | covered | `account_deactivation::*` (`deactivate` fixture asserts 200) |
| returns deactivated status | covered | `account_deactivation::returns_deactivated_status` |
| no longer serves repo data | covered | `account_deactivation::no_longer_serves_repo_data` (RepoDeactivated on getRepo/getLatestCommit/listBlobs/sync.getRecord/describeRepo/getBlob; listRepos active=false) |
| no longer resolves handle | covered | `account_deactivation::no_longer_resolves_handle` |
| still allows login and returns status | covered | `account_deactivation::still_allows_login_and_returns_status` |
| returns status on getSession | covered | `account_deactivation::still_allows_login_and_returns_status` |
| does not allow writes | covered | `account_deactivation::does_not_allow_writes` (401 AccountDeactivated for create/put/delete/applyWrites) |
| reactivates | covered | `account_deactivation::reactivates` |

### account-deletion.test.ts

| case | status | vlpds |
|---|---|---|
| requests account deletion | ported | token: `email_flows::account_deletion_flow`; mail to/subject/HTML: `ref_account::ref_delete_account_mail_and_taken_down_delete` |
| fails account deletion with a bad token | covered | `email_flows::account_deletion_flow`; message "Token is invalid" in `ref_account::ref_delete_account_mail_and_taken_down_delete` |
| fails account deletion with a bad password | covered | `email_flows::account_deletion_flow`; message "Invalid did or password" in `ref_account::ref_delete_account_mail_and_taken_down_delete` |
| deletes account with a valid token & password | ported | deleting an already taken-down account: `ref_account::ref_delete_account_mail_and_taken_down_delete`; plain case `email_flows::account_deletion_flow` |
| no longer lets the user log in | covered | `email_flows::account_deletion_flow`, `ref_account::ref_delete_account_mail_and_taken_down_delete` (message) |
| no longer store the user account or repo | divergent | account/repo/handle/email/tokens gone: `email_flows::account_deletion_flow`. The reference also deletes the DID's earlier `repo_seq` rows (only the `#account` tombstone stays), so a cursor replay no longer contains them; vlpds's firehose is its append-only log, so a replay from before the deletion still carries that DID's earlier `#commit`/`#identity` frames until retention drops the segments |
| deletes the users actor store | N/A | SQLite actor-store files; the vlpds equivalent (repo keys gone) is `email_flows::account_deletion_flow` (getRepo/getLatestCommit/listRecords fail) |
| deletes relevant blobs | covered | `email_flows::account_deletion_flow` (getBlob fails) |
| maintains blobs from other actors | covered | `email_flows::account_deletion_flow` (other DID's copy of the same CID still served) |
| can delete an empty user | covered | `email_flows::can_delete_an_empty_user` |
| can be performed by an administrator. | covered | `email_flows::admin_can_delete_account` |

### account-status.test.ts

| case | status | vlpds |
|---|---|---|
| takedown + activation triggers an error | covered | `account_status::takedown_plus_activation_is_an_error` |
| activating a taken down account causes an error | covered | `account_status::deactivate_takedown_untakedown_activate` (one `#account` per transition stands in for the `sequenceEvts` spy) |
| sequences an account status event when calling updateSubjectStatus without changing the status | covered | `account_status::sequences_account_event_without_status_change` |
| allows to takedown, then deactivate, an account | covered | `account_status::takedown_then_deactivate_reports_both` |
| throws when trying to activate a takedown account | covered | `account_status::cannot_activate_a_takendown_account` (AccountNotFound) |

### account.test.ts

| case | status | vlpds |
|---|---|---|
| serves the accounts system config | ported | `account::serves_the_accounts_system_config`; blobUploadLimit/links/contact: `ref_account::ref_describe_server_links_contact_and_blob_limit` (product fix) |
| fails on invalid handles | covered | `account::fails_on_invalid_handles`; message check in `ref_account::ref_create_account_error_messages` |
| email validation > succeeds on allowed emails | covered | every `create_account` fixture (`account::creates_an_account_with_plc_shaped_did_and_did_doc`) |
| email validation > fails on disallowed emails | ported | `ref_account::ref_fails_on_disallowed_emails` (the reference's `disposable-email-domains-js` list, vendored: `src/email_policy.rs`) |
| creates an account | covered | `account::creates_an_account_with_plc_shaped_did_and_did_doc` |
| generates a properly formatted PLC DID | covered | `plc::create_account_registers_the_genesis_op` (DID = hash of genesis op; handle, signing key, PDS endpoint) |
| allows a custom set recovery key | covered | `plc::server_recovery_key_is_ahead_of_the_rotation_key` ([recoveryKey, server recovery key, rotation key]), `plc::create_account_registers_the_genesis_op` |
| allows administrative email updates | covered | `account::allows_administrative_email_updates` |
| disallows duplicate email addresses and handles | covered | `ref_account::ref_create_account_error_messages` (exact messages; product fix: echo the request's email spelling) |
| disallows the email and handle of a deactivated account | covered | `account::disallows_the_email_and_handle_of_a_deactivated_account` |
| validates input through lexicon schema | covered | `account::fails_on_invalid_handles` (all nine handles) |
| disallows improperly formatted handles | covered | `ref_account::ref_create_account_error_messages` (with messages) |
| disallows reserved handles (john.bsky.io → UnsupportedDomain) | covered | `ref_account::ref_create_account_error_messages` (with message) |
| disallows reserved handles (about/atp) | covered | `ref_account::ref_create_account_error_messages` (with message) |
| handles racing signups for same handle | covered | `account::handles_racing_signups_for_same_handle` |
| fails on unauthenticated requests | covered | `account::login_and_authenticated_requests` |
| logs in | covered | `account::login_and_authenticated_requests` |
| can perform authenticated requests | covered | `account::login_and_authenticated_requests` |
| can reset account password | ported | flow: `account::can_reset_account_password`; mail to/subject/HTML (handle): `ref_account::ref_password_reset_mail_and_expired_token` |
| allows only single-use of password reset token | covered | `account::can_reset_account_password` |
| changing password invalidates past refresh tokens | covered | `account::can_reset_account_password` (lowercased token; old refresh JWT refused) |
| allows only unexpired password reset tokens | ported | `ref_account::ref_password_reset_mail_and_expired_token` (token aged 16 min → ExpiredToken; password unchanged) |
| allows an admin to update password | covered | `account::allows_an_admin_to_update_password` |

### account-migration.test.ts

| case | status | vlpds |
|---|---|---|
| migrates an account | covered | `migration::migrate_account_with_records_and_blobs` (service-auth createAccount with DID, checkAccountStatus counters, importRepo, listMissingBlobs, blob upload, activation, old PDS deactivation, writes on new PDS) + `plc::migration_out_to_another_pds` (requestPlcOperationSignature → signPlcOperation → submitPlcOperation against a PLC directory). Ported remainder: preferences copy to the not-yet-active account (`ref_account::ref_preferences_on_deactivated_account`) and the PLC mail (`ref_account::ref_plc_operation_signature_mail`) |

### recovery.test.ts

| case | status | vlpds |
|---|---|---|
| recovers repos based on the sequencer | N/A | operator script restoring SQLite actor stores from the sequencer DB. vlpds has no separate actor stores: the log is the WAL and state is rebuilt from it on restart/takeover (`cold_start::*`, `fast_failover::*`, `firehose_backfill::*`) |
| rotates keys for users | ported | `ref_account::ref_signing_key_rotation_resigns_the_repo`: `admin.updateAccountSigningKey` re-signs the head with the new key (same data, new rev) and emits `#identity` + `#sync`, as the reference's `rotate-keys`. Product fix: it used to emit `#identity` only and sign just the next commit with the new key. `tests/all/key_rotation.rs` adds writers racing the rotation, PLC refusal/outage, a deactivated account, and the owner crashing after recording the key and after the PLC update (finished by an admin retry or by the first fenced write); `go_checker::go_checker_accepts_key_rotation_resync` runs the Go checker over it |

### takedown-appeal.test.ts

| case | status | vlpds |
|---|---|---|
| actor takedown allows appeal request. | ported | PDS side: plain login 401 AccountTakedown "Account has been taken down", `allowTakendown` session, appeal `createReport` forwarded with service auth (iss/aud/lxm): `ref_account::ref_takendown_session_appeal_is_forwarded`; also `moderation::takendown_actor_cannot_report_or_write`. Ozone `queryStatuses` snapshot is N/A (moderation service) |
| allows a takendown actor to appeal an action through the PDS | covered | `proxy::takendown_session_can_appeal` (tools.ozone.inbox.appealActionedSubject proxied for the takendown scope) |
| takendown actor is not allowed to create reports. | N/A | "Report not accepted from takendown account" is Ozone's check; the reference PDS forwards every createReport from a takendown-scope token, as vlpds does (`ref_account::ref_takendown_session_appeal_is_forwarded`, `proxy::create_report_goes_to_report_service`) |
| takendown actor is not allowed to create records. | covered | `moderation::takendown_actor_cannot_report_or_write`; exact 400 InvalidToken "Bad token scope" in `ref_account::ref_takendown_session_appeal_is_forwarded` |

### entryway.test.ts

| case | status | vlpds |
|---|---|---|
| creates account. | N/A | entryway mode (PDS behind a separate entryway issuing tokens, `entrywayUrl` config); vlpds has no entryway mode |
| auths with both services. | N/A | entryway mode |
| updates handle from pds. | N/A | entryway mode (handle updates forwarded to the entryway) |
| updates handle from entryway. | N/A | entryway mode |
| resolves handle of local account via entryway. | N/A | entryway mode |
| does not resolve handle from local account store. | N/A | entryway mode |
| resolves handle of account behind entryway on another pds. | N/A | entryway mode |
| fails to resolve unknown handle on service domain. | N/A | entryway mode (non-entryway equivalent: `handles::*` resolveHandle HandleNotFound) |
| defers handle resolution over well-known to entryway. | N/A | entryway mode |
| does not allow bringing own op to account creation. | N/A | entryway mode; vlpds refuses `plcOp` outright (400 InvalidRequest, `migration::migrate_account_with_records_and_blobs`) |

### account-manager.test.ts

Puppeteer tests of the reference's browser account-manager UI (`@atproto/oauth-provider-ui`). vlpds's web UI is its own; the XRPC flows behind each step are covered as noted.

| case | status | vlpds |
|---|---|---|
| allows creating an account | N/A | browser UI; API: `account::creates_an_account_with_plc_shaped_did_and_did_doc`, `oauth::*` sign-up |
| allows switching accounts | N/A | browser UI (OAuth device sessions) |
| forgot about the ephemeral session when loading the page again | N/A | browser UI |
| allows changing the password | N/A | browser UI; API: `account::can_reset_account_password` |
| shows email 2FA as disabled until the email is verified | N/A | browser UI; API: `email_2fa::*` |
| allows verifying the email address | N/A | browser UI; API: `email_flows::email_confirmation_and_update_flow` |
| allows enabling and disabling email based 2FA | N/A | browser UI; API: `email_2fa::*` |
| allows changing the username | N/A | browser UI; API: `handles::*` |
| allows changing the email address | N/A | browser UI; API: `email_flows::email_confirmation_and_update_flow` |
| allows signing out & signing back in | N/A | browser UI |
| does not ask for a token when changing a non-verified email | N/A | browser UI; API: `email_flows::email_confirmation_and_update_flow` (tokenRequired=false) |
| rejects racial slurs when changing username | N/A | browser UI; API: `handle_validation::*` |
| rejects custom domain when not configured | N/A | browser UI |
| allows deactivating & reactivating the account | N/A | browser UI; API: `account_deactivation::*` |
| allows deleting the account | N/A | browser UI; API: `email_flows::account_deletion_flow` |

### db.test.ts

| case | status | vlpds |
|---|---|---|
| commits changes | N/A | Kysely/SQLite transaction wrapper internals |
| rolls-back changes on failure | N/A | Kysely/SQLite transaction wrapper internals |
| indicates isTransaction | N/A | Kysely/SQLite transaction wrapper internals |
| asserts transaction | N/A | Kysely/SQLite transaction wrapper internals |
| does not allow leaky transactions | N/A | Kysely/SQLite transaction wrapper internals |
| ensures all inflight queries are rolled back | N/A | Kysely/SQLite transaction wrapper internals |

### blob-transactor.test.ts

| case | status | vlpds |
|---|---|---|
| BlobTransactor > drains the MIME stream without stalling other consumers | ported | TS unit test of the upload stream tee; observable part (25 MiB upload stored whole, CID over all bytes, JPEG sniffed over a generic content type): `ref_account::ref_large_upload_is_sniffed_and_hashed_whole` |

## Auth, sessions, app passwords, email, OAuth, rate limits, SSRF

### auth.test.ts

| case | status | vlpds |
|---|---|---|
| provides valid access and refresh token on account creation. | covered | `auth::valid_tokens_on_account_creation` |
| provides valid access and refresh token on session creation. | covered | `auth::valid_tokens_on_session_creation` |
| allows session creation using email address. | covered | `auth::session_creation_using_email_address` (upper-cased email) |
| fails on session creation with a bad password. | covered | `auth::bad_password_and_unknown_identifier_are_indistinguishable` (401 AuthenticationRequired, "Invalid identifier or password") |
| returns identical error responses for unknown identifier and known-identifier-with-wrong-password. | covered | `auth::bad_password_and_unknown_identifier_are_indistinguishable` |
| returns identical error responses ... in the OAuth sign-in flow. | ported | `oauth::ref_oauth::ref_oauth_sign_in_errors_are_indistinguishable`. vlpds signs in with HTML form posts (`/oauth/authorize/sign-in`, `/oauth/account/sign-in`), not the reference's JSON `/@atproto/oauth-provider/~api/sign-in`, so the test compares those responses; the wording is "Invalid handle or password" |
| provides valid access and refresh token on session refresh. | covered | `auth::valid_tokens_on_session_refresh_and_chained_refresh` |
| handles racing refreshes | covered | `auth::handles_racing_refreshes` |
| refresh token provides new token with same id on multiple uses during grace period. | covered | `auth::refresh_reuse_within_grace_period_yields_same_token_id` |
| refresh token is revoked after grace period completes. | ported | `ref_auth::ref_refresh_token_revoked_after_grace_period` (ages the stored `sess/{jti}` state). The reference's "row was cleaned up" check is SQL-internal (N/A) |
| refresh token is revoked when session is deleted. | covered | `auth::refresh_token_revoked_when_session_deleted`; exact "Token has been revoked" in `ref_auth::ref_refresh_error_messages` |
| access token cannot be used to refresh a session. | covered | `auth::access_token_cannot_refresh_and_refresh_token_cannot_access`; "Token could not be verified" in `ref_auth::ref_refresh_error_messages` (product fix: vlpds said "Bad token scope"; src/xrpc/server.rs `refresh_claims`) |
| expired refresh token cannot be used to refresh a session. | covered | `auth::expired_refresh_token_cannot_be_used` (forged expired HS256 refresh JWT; ExpiredToken; deleteSession of it is OK) |
| actor takedown disallows fresh session. | covered | `auth::actor_takedown_disallows_fresh_session` |
| actor takedown disallows refresh session. | covered | `auth::actor_takedown_disallows_refresh_session` |
| when 2FA is enabled > challenges for a 2FA token on session creation | covered | `auth::email_2fa_challenges_and_accepts_token` (was `#[ignore]`d as "replaced by TOTP"; vlpds has the email factor now, so un-ignored and passing), `email_2fa::sign_in_with_emailed_code` |
| when 2FA is enabled > accepts a 2FA token after challenging on session creation | covered | `auth::email_2fa_challenges_and_accepts_token` (un-ignored). The mailer-spy `locale: undefined` check is TS-internal (N/A) |
| when 2FA is enabled > rejects an invalid 2FA token after challenging on session creation | covered | `auth::email_2fa_rejects_invalid_token` (un-ignored), `email_2fa::sign_in_with_emailed_code` |

### app-passwords.test.ts

| case | status | vlpds |
|---|---|---|
| creates an app-specific password | covered | `app_passwords::app_password_lifecycle` |
| creates a privileged app-specific password | covered | `app_passwords::app_password_lifecycle` |
| creates a session with an app-specific password | covered | `app_passwords::app_password_lifecycle` |
| creates a session with an app-specific password when the account has 2FA enabled | covered | `email_2fa::sign_in_with_emailed_code` ("app passwords bypass the factor"), `email_2fa::wrong_codes_lock_the_factor`, `totp::app_password_login_bypasses_totp` |
| creates an access token for an app with a restricted scope | covered | `app_passwords::app_password_lifecycle` (`com.atproto.appPass` / `com.atproto.appPassPrivileged`) |
| allows actions to be performed from app | covered | `app_passwords::app_password_lifecycle` |
| restricts full access actions | covered | `app_passwords::app_password_lifecycle`; exact 400 InvalidToken "Bad token scope" in `ref_auth::ref_app_password_error_messages` |
| restricts privileged app password actions (listConvos({})) | ported | `ref_auth::ref_app_password_error_messages` (400 InvalidToken "Bad token method"; product fix: vlpds answered 403 InsufficientScope, src/xrpc/authn.rs `need_rpc`). The call carries an explicit `atproto-proxy` header: vlpds refuses chat.bsky.* without one (`proxy::target_selection_and_rejections`), where the reference defaults it to the AppView. Group E (proxy) owns that difference |
| restricts privileged app password actions (listConvos()) | ported | same test (the reference's duplicate case) |
| restricts service auth token methods for non-privileged access tokens | covered | `app_passwords::app_password_lifecycle` (both casings); the reference's message in `ref_auth::ref_app_password_error_messages` |
| allows privileged service auth token scopes for privileged access tokens | covered | `app_passwords::app_password_lifecycle` |
| persists scope across refreshes | covered | `app_passwords::app_password_lifecycle` |
| persists privileged scope across refreshes | covered | `app_passwords::app_password_lifecycle` |
| lists available app-specific passwords | covered | `app_passwords::app_password_lifecycle` (listing from an app-password session; createdAt-descending order as the reference, not asserted) |
| revokes an app-specific password | divergent | The reference revokes with the *app-password* session (`revokeAppPassword` takes ACCESS_STANDARD). vlpds requires a full session (`full_access` in `revoke_app_password`, commented "stricter than the reference"); `app_passwords::app_password_cannot_manage_account` asserts the refusal. vlpds is likewise stricter for `identity.updateHandle` (reference: ACCESS_STANDARD) |
| no longer allows session refresh after revocation | covered | `app_passwords::app_password_lifecycle`; "Token has been revoked" in `ref_auth::ref_app_password_error_messages` |
| no longer allows session creation after revocation | covered | `app_passwords::app_password_lifecycle`; "Invalid identifier or password" in `ref_auth::ref_app_password_error_messages` |

### email-auth-factor.test.ts

| case | status | vlpds |
|---|---|---|
| enables the auth factor without a token | covered | `email_2fa::toggles_like_the_reference` (a step-by-step port of this file) |
| no-ops when the auth factor is already enabled | covered | `email_2fa::toggles_like_the_reference` |
| does not request a factor change when emailAuthFactor is omitted | covered | `email_2fa::toggles_like_the_reference` |
| rejects enabling the auth factor while changing email even if already enabled | covered | `email_2fa::toggles_like_the_reference` |
| requires a confirmation token to disable the auth factor | covered | `email_2fa::toggles_like_the_reference` |
| rejects the email auth factor change with an invalid token | covered | `email_2fa::toggles_like_the_reference` |
| disables the auth factor with a valid token | covered | `email_2fa::toggles_like_the_reference` |
| disables the auth factor with a requestEmailUpdate token | covered | `email_2fa::toggles_like_the_reference` |
| no-ops when the auth factor is already disabled | covered | `email_2fa::toggles_like_the_reference` |
| matches the account email case-insensitively | covered | `email_2fa::toggles_like_the_reference` |

### email-confirmation.test.ts

| case | status | vlpds |
|---|---|---|
| starts a user out unverified | covered | `email_flows::email_confirmation_and_update_flow` |
| allows email update without token when unverified | covered | `email_flows::email_confirmation_and_update_flow` |
| requests email confirmation | covered | `email_flows::email_confirmation_and_update_flow` (one mail to the address); subject "Email Confirmation" and HTML "Confirm your email" in `ref_auth::ref_email_confirmation_and_update_mails` |
| fails email confirmation with a bad token (InvalidToken) | covered | `email_flows::email_confirmation_and_update_flow` |
| fails email confirmation with a bad token (InvalidEmail) | covered | `email_flows::email_confirmation_and_update_flow` |
| confirms email | covered | `email_flows::email_confirmation_and_update_flow` |
| disallows email update without token when verified | covered | `email_flows::email_confirmation_and_update_flow` (TokenRequired) |
| requests email update | covered | `email_flows::email_confirmation_and_update_flow`; subject "Email Update Requested" and HTML "Update your email" in `ref_auth::ref_email_confirmation_and_update_mails` |
| fails email update with a bad token | covered | `email_flows::email_confirmation_and_update_flow` |
| fails email update with a badly formatted email | ported | `ref_auth::ref_email_confirmation_and_update_mails` (`bad-email@disposeamail.com`, and a malformed address) |
| fails email update with in-use email | covered | `email_flows::email_confirmation_and_update_flow`; exact message in `ref_auth::ref_email_confirmation_and_update_mails` |
| updates email | covered | `email_flows::email_confirmation_and_update_flow` |

### get-service-auth.test.ts

| case | status | vlpds |
|---|---|---|
| issues a token whose aud matches a bare-DID input | covered | `service_auth::issues_verifiable_token_for_bare_did_aud` |
| issues a token whose aud matches a combined did#serviceId input | covered | `service_auth::issues_token_for_did_service_id_aud` |
| rejects malformed aud with InvalidRequest | covered | `service_auth::rejects_malformed_aud` |
| rejects an aud with a non-atproto DID method | covered | `service_auth::rejects_malformed_aud` (`did:foo:bar`) |
| rejects an aud with empty fragment | covered | `service_auth::rejects_malformed_aud` (`{pds}#`) |

### moderator-auth.test.ts

| case | status | vlpds |
|---|---|---|
| allows service auth requests from the configured appview did | ported | `ref_moderator_auth::ref_allows_the_configured_mod_service` (`--mod-service-did`; also the other moderator methods, a `#atproto_labeler` issuer, and admin Basic auth still working). Extra: `mod_service_is_limited_to_moderator_methods` (wrong lxm; admin-token-only methods refuse it), `unconfigured_mod_service_is_untrusted`, `mod_service_reads_preferences` (getPreferences `?did=`) |
| does not allow requests from another did | ported | `ref_moderator_auth::ref_refuses_another_did` (401 UntrustedIss "Untrusted issuer") |
| does not allow requests with a bad signature | ported | `ref_moderator_auth::ref_refuses_a_bad_signature` ("jwt signature does not match jwt issuer") |
| does not allow requests with a bad aud | ported | `ref_moderator_auth::ref_refuses_a_bad_aud` ("jwt audience does not match service did") |

User service auth on uploadBlob (`authorizationOrUserServiceAuth`) has no reference test; see "Product fixes" 15 and
`user_service_auth::*`.

### rate-limits.test.ts

| case | status | vlpds |
|---|---|---|
| rate limits by ip | ported | `ref_auth::ref_rate_limits_by_ip` (resetPassword: 50 per 5 min per IP, then 429 RateLimitExceeded "Rate Limit Exceeded") |
| rate limits by a custom key | covered | `rate_limits::create_session_per_identifier_and_ip` (30 per identifier, another identifier unaffected), `rate_limits::create_session_identifier_variants_share_a_bucket` |

### oauth.test.ts

(The reference drives its React sign-in UI with puppeteer in French; vlpds has its own server-rendered English pages, driven with form posts in tests/all/oauth.rs.)

| case | status | vlpds |
|---|---|---|
| Allows to sign-up through OAuth (prompt=create) | covered | `oauth::prompt_create_signs_up`, `oauth::sign_up_page_with_required_invites` |
| Allows canceling the OAuth flow | covered | `oauth::account_chooser_prompts_and_denial` (deny -> `access_denied` redirect with state + iss), `oauth::response_modes_form_post_and_fragment` |
| allows resetting the password | divergent | vlpds's OAuth pages have no "forgot password" step. Password reset is the XRPC requestPasswordReset/resetPassword flow (`smtp_mail::password_reset_is_mailed_over_smtp`, `email_flows`) used by the account web UI. Locale negotiation (`locale: 'fr'`) is N/A: the pages are English only |
| restores the reset-password step after a page refresh | divergent | as above (no reset step in the OAuth UI) |
| Allows to sign-in through OAuth | covered | `oauth::full_flow_create_record_refresh_and_revoke` ("remember this account" = the device cookie) |
| remembers the session | covered | `oauth::account_chooser_prompts_and_denial` (remembered device accounts skip the password) |
| revokes OAuth sessions on deactivation & requires re-activation on sign-in | ported (partly divergent) | Revocation: `oauth::ref_oauth::ref_account_deactivation_over_oauth` (product fix: OAuth deactivation now drops OAuth sessions, authorized clients and app passwords). Divergent: vlpds's account page has no "deactivate" button (deactivation is the XRPC method), and signing in to a deactivated account is refused ("This account is deactivated or suspended", `LoginError::Inactive`) instead of offering "Yes, reactivate my account" |
| with 2FA > Allows to sign-in through OAuth | covered | `oauth::email_code_prompt_on_login` (code mailed on the password step, masked address hint, code step). `locale: 'fr'` reaching the mailer is N/A (English only) |
| with 2FA > Prevents to sign-in through OAuth with invalid OTP | covered | `oauth::email_code_prompt_on_login` ("AAAAA-AAAAA" -> "Invalid sign-in code", then the right code) |

### oauth-deactivation.test.ts

| case | status | vlpds |
|---|---|---|
| rejects deactivation when the session lacks the status scope | ported | `oauth::ref_oauth::ref_account_deactivation_over_oauth`. Product fix: OAuth scope refusals were 403 `InsufficientScope` "credentials do not grant this action"; they are now the reference's 403 `ScopeMissingError` `Missing required scope "<scope>"` (src/xrpc/authn.rs `need_*`) |
| rejects reactivation over OAuth with a message pointing at the account page | ported | same test (already implemented; message mentions the "account management page") |
| deactivates the account when the status scope is granted | ported | same test (getRepoStatus `{did, active: false, status: "deactivated"}`) |
| revokes app passwords on OAuth deactivation | ported | same test. Product fix: OAuth deactivation now deletes the app passwords (and their sessions) |
| revokes the OAuth session that performed the deactivation | ported | same test (getSession 401 for that and every other OAuth session; the password session is kept, as in the reference). Product fix: OAuth deactivation now revokes all OAuth sessions and remembered authorizations. Control: `oauth::ref_oauth::ref_password_session_deactivation_keeps_credentials` |

### oauth-lexicon.test.ts

| case | status | vlpds |
|---|---|---|
| resolves permission sets hosted on the PDS itself | covered | `oauth::include_permission_set` (permission set published in a local repo, resolved, shown on consent, granted scope narrowed to it) |
| fails to resolve lexicons that do not exist on the PDS | covered | `oauth::include_permission_set` (unresolvable `include:` -> `invalid_scope` at PAR). The reference calls the lexicon manager directly; its error text is TS-internal |

### ssrf.test.ts

| case | status | vlpds |
|---|---|---|
| with ssrf protection enabled > refuses to send registerPush to a non-unicast endpoint. | ported | `ref_ssrf::ref_with_ssrf_protection_enabled_nothing_is_sent` (vlpds's SSRF policy is on outside dev mode; service DID is a did:plc in the mock directory, endpoint `http://localhost:<port>`) |
| with ssrf protection enabled > refuses to send unregisterPush to a non-unicast endpoint. | ported | same test |
| with ssrf protection enabled > refuses to send createReport to a non-unicast endpoint. | ported | same test (atproto-proxy `did#atproto_labeler`) |
| with ssrf protection disabled > sends registerPush to the endpoint. | ported | `ref_ssrf::ref_with_ssrf_protection_disabled_calls_are_sent` (dev mode) |
| with ssrf protection disabled > sends unregisterPush to the endpoint. | ported | same test |
| with ssrf protection disabled > sends createReport to the endpoint. | ported | same test |

## Repo writes, validation, blobs, preferences, handles

### crud.test.ts

| case | status | vlpds |
|---|---|---|
| registers users | covered | `crud::registers_and_describes_repo` |
| describes repo | covered | `crud::registers_and_describes_repo` |
| creates records | covered | `crud::creates_gets_lists_and_deletes_records` |
| CRUDs records with the semantic sugars | covered | `crud::creates_gets_lists_and_deletes_records` (the sugars are client-side wrappers over the same routes) |
| attaches images to a post | ported + divergent | `ref_repo::ref_attaches_images_to_a_post` (unlisted until referenced, then listed and served; record carries the same ref). Divergent: the reference refuses `getBlob` before a record references the upload (temp store); vlpds writes uploads straight to their final key and serves them to anyone holding the CID until the GC sweep collects them |
| creates records with the correct key described by the schema | covered | `crud::profile_gets_self_rkey` |
| paginates > in forwards order | covered | `crud::paginates_list_records` |
| paginates > in reverse order | covered | `crud::paginates_list_records` |
| paginates > reverses | covered | `crud::paginates_list_records` (cursor = first/last rkey, reverse is exact reverse) |
| deleteRecord > deletes a record if it exists | covered | `crud::creates_gets_lists_and_deletes_records`, `crud::delete_of_missing_record_is_a_noop` |
| deleteRecord > no-ops if record doesn't exist | covered | `crud::delete_of_missing_record_is_a_noop` |
| deleteRecord > does not delete the underlying block if it is referenced elsewhere | covered | `crud::delete_keeps_block_referenced_elsewhere` |
| putRecord > creates a new record if it doesn't already exist | covered | `crud::put_record_creates_then_updates` |
| putRecord > updates a record if it already exists | covered | `crud::put_record_creates_then_updates` |
| putRecord > still works if repo is specified by handle | covered | `crud::put_record_by_handle` |
| putRecord > does not produce commit on no-op update | covered | `crud::put_record_noop_does_not_commit` |
| putRecord > fails on user mismatch | ported | `ref_repo::ref_writes_to_another_repo_are_auth_required` (was only `client_err` in `crud::write_requires_auth_and_matching_repo`; **fix**: 403 Forbidden -> 401 AuthenticationRequired) |
| putRecord > fails on invalid record | ported | `ref_repo::ref_put_record_invalid_update_leaves_record` (the float case's message is "floats are not allowed" without the `$.record.description` path; the integer case names the field) |
| putRecord > updates a legacy blob ref when updating profile | divergent | vlpds refuses legacy `{cid, mimeType}` blob refs on every write (`crud::rejects_legacy_blob_refs_and_bad_values`). The reference's profile-only upgrade is a `@TODO remove after migrating legacy blobs` hack; vlpds is a new PDS with no legacy-blob data to migrate |
| defaults an undefined $type on records | covered | `crud::defaults_undefined_type` |
| requires the schema to be known if explicitly validating | covered | `crud::unvalidated_writes_of_unknown_lexicons` (message names the NSID) |
| does not require the schema to be known if not explicitly validating | covered | `crud::unvalidated_writes_of_unknown_lexicons` |
| requires the $type to match the schema | covered | `crud::requires_type_to_match_collection` |
| requires valid rkey | covered | `crud::requires_valid_rkey` |
| validates the record on write | covered | `crud::validates_known_records_on_write` |
| validates datetimes rigorously | covered | `crud::validates_known_records_on_write` |
| unvalidated writes > disallows creation of unknown lexicons when validate is set to true | covered | `crud::unvalidated_writes_of_unknown_lexicons` |
| unvalidated writes > allows creation of unknown lexicons when validate is not set to true | covered | `crud::unvalidated_writes_of_unknown_lexicons` |
| unvalidated writes > allows update of unknown lexicons when validate is set to false | ported | `ref_repo::ref_updates_unknown_lexicon_records` |
| unvalidated writes > applyWrites returns results with validation status | ported | `ref_repo::ref_apply_writes_results_carry_validation_status` |
| unvalidated writes > correctly associates images with unknown record types | ported | `ref_repo::ref_images_in_unknown_record_types_are_associated` (association observed via listBlobs/getBlob and release on delete) |
| unvalidated writes > enforces record type constraint even when unvalidated | covered | `crud::requires_type_to_match_collection` |
| unvalidated writes > enforces blob ref format even when unvalidated | covered | `crud::rejects_legacy_blob_refs_and_bad_values` |
| compare-and-swap > createRecord succeeds on proper commit cas | covered | `crud::create_record_swap_commit` |
| compare-and-swap > createRecord fails on bad commit cas | covered | `crud::create_record_swap_commit` |
| compare-and-swap > deleteRecord succeeds on proper commit cas | covered | `crud::delete_record_swap_commit_and_record` |
| compare-and-swap > deleteRecord fails on bad commit cas | covered | `crud::delete_record_swap_commit_and_record` |
| compare-and-swap > deleteRecord succeeds on proper record cas | covered | `crud::delete_record_swap_commit_and_record` |
| compare-and-swap > deleteRecord fails on bad record cas | covered | `crud::delete_record_swap_commit_and_record` |
| compare-and-swap > putRecord succeeds on proper commit cas | covered | `crud::put_record_swap_commit` |
| compare-and-swap > putRecord fails on bad commit cas | covered | `crud::put_record_swap_commit` |
| compare-and-swap > putRecord succeeds on proper record cas | covered | `crud::put_record_swap_record` |
| compare-and-swap > putRecord fails on bad record cas | covered | `crud::put_record_swap_record` |
| compare-and-swap > applyWrites succeeds on proper commit cas | covered | `crud::apply_writes_swap_commit` |
| compare-and-swap > applyWrites fails on bad commit cas | covered | `crud::apply_writes_swap_commit` |
| compare-and-swap > writes fail on values that can't reliably transform between cbor to lex | covered | `crud::rejects_values_too_deep_for_cbor` |
| prevents duplicate likes | ported | `ref_repo::ref_prevents_duplicate_backlinks` (**fix**: vlpds had no backlink index. createRecord now deletes the account's earlier like with the same `subject.uri` in the new record's commit, as the reference's `getBacklinkConflicts`, unless `validate: false`; applyWrites and imports don't prune. Index `bl/` in src/backlinks.rs, DESIGN.md "Backlinks"; more cases in `backlinks::*`: the firehose commit carries the deletes, applyWrites/import duplicates, concurrent creates, replay after kill -9, reshard) |
| prevents duplicate reposts | ported | same as above (`subject.uri`) |
| prevents duplicate blocks | ported | same as above (`subject` DID) |
| prevents duplicate follows | ported | same as above (`subject` DID) |
| doesn't serve taken-down record | covered | `moderation::takes_down_and_restores_records` (getRecord + listRecords) |
| doesn't serve taken-down actor | ported | `ref_repo::ref_taken_down_actor_records_not_served` (**fix**: listRecords on an unknown/taken-down/deactivated repo was 400 RepoNotFound/RepoTakendown/RepoDeactivated; now the reference's 400 InvalidRequest "Could not find repo: {repo}". The self/admin exemption of `sync::assert_available` is kept) |

### create-post.test.ts

| case | status | vlpds |
|---|---|---|
| allows for creating posts with tags | covered | `create_post::creates_posts_with_tags` |
| handles RichText tag facets as well | covered | `create_post::creates_posts_with_tag_facets` |

### file-uploads.test.ts

| case | status | vlpds |
|---|---|---|
| handles client abort | ported | `ref_repo::ref_upload_client_abort` (body stream fails mid-upload; server stays healthy, nothing stored) |
| uploads files | covered | `file_uploads::uploads_references_and_serves_a_blob` (the reference's temp-key table rows are SQLite internals; the observable part is the returned ref/size/mime) |
| can reference the file | covered | `file_uploads::uploads_references_and_serves_a_blob` |
| after being referenced, the file is moved to permanent storage | covered | `file_uploads::uploads_references_and_serves_a_blob` (served by getBlob, listed by listBlobs) |
| can fetch the file after being referenced | covered | `file_uploads::uploads_references_and_serves_a_blob` (bytes, content-type, CSP, nosniff) |
| does not allow referencing a file that is outside blob constraints | covered | `file_uploads::rejects_blob_outside_lexicon_constraints` |
| does not make a blob permanent if referencing failed | ported | `ref_repo::ref_failed_reference_does_not_make_blob_permanent` (observed as "not referenced": unlisted, later referencable; same temp-store divergence as above for getBlob) |
| permits duplicate uploads of the same file | covered | `file_uploads::permits_duplicate_uploads` |
| supports compression during upload | covered | `file_uploads::supports_gzip_upload` |
| corrects a bad mimetype | covered | `file_uploads::mime_types` (PNG declared video/mp4 served as image/png) |
| handles pngs | covered | `file_uploads::mime_types` |
| handles unknown mimetypes | covered | `file_uploads::mime_types` |
| handles text | covered | `file_uploads::mime_types` |
| handles json | covered | `file_uploads::mime_types` |

### blob-deletes.test.ts

| case | status | vlpds |
|---|---|---|
| deletes blob when record is deleted | covered | `blob_deletes::deletes_blob_when_record_is_deleted` |
| deletes blob when blob-ref in record is updated | covered | `blob_deletes::deletes_blob_when_ref_is_updated` |
| does not delete blob when blob-ref in record is not updated | covered | `blob_deletes::keeps_blob_when_ref_is_not_updated` |
| does not delete blob when blob is reused by another record in same commit | covered | `blob_deletes::keeps_blob_reused_by_another_record_in_same_commit` |
| does delete blob from user blob store if another user is using it | covered | `blob_deletes::deletes_from_own_store_even_if_another_user_uses_it` |

Note: vlpds deletes blob bytes in a GC sweep with a grace period (`blob_deletes::gc_grace_protects_recent_uploads`), not in the write transaction; the tests run a zero-grace sweep.

### preferences.test.ts

| case | status | vlpds |
|---|---|---|
| requires auth to set or put preferences. | covered | `ref_repo::ref_preferences_error_messages` (**fix**: missing-auth message "authentication required" -> the reference's "Authentication Required". Note: the reference's error *name* for a missing Authorization header is `AuthMissing` (auth-verifier.ts `AuthRequiredError(undefined, 'AuthMissing')`); vlpds and its suite use `AuthenticationRequired`, left as is) |
| gets preferences, before any are set. | covered | `preferences::put_get_update_and_clear` |
| only gets preferences in app.bsky namespace. | N/A | seeds a `com.atproto` pref through the TS actor store directly; over XRPC vlpds (like the reference) refuses non-app.bsky prefs, so there is no external way to plant one (`ref_repo::ref_preferences_error_messages`) |
| puts preferences, all creates. | covered | `preferences::put_get_update_and_clear` (the "other namespace not clobbered" half is the same internal-store N/A) |
| puts preferences, updates and removals. | covered | `preferences::put_get_update_and_clear` |
| puts preferences, clearing them. | covered | `preferences::put_get_update_and_clear` |
| fails putting preferences outside namespace. | covered | `ref_repo::ref_preferences_error_messages` (refused with the message; prefs unchanged) |
| fails putting preferences without $type. | covered | `ref_repo::ref_preferences_error_messages` |
| does not read permissioned preferences with an app password | covered | `preferences::app_password_cannot_read_write_or_remove_personal_details` |
| does not write permissioned preferences with an app password | covered | same; message in `ref_repo::ref_preferences_error_messages` |
| does not remove permissioned preferences with an app password | covered | same |
| personalDetailsPref and declaredAgePref > declaredAgePref is computed and returned for authed user | covered | `preferences::declared_age_pref_is_computed_and_not_settable` |
| personalDetailsPref and declaredAgePref > declaredAgePref is computed and returned for app password | covered | same |
| personalDetailsPref and declaredAgePref > user cannot set declaredAgePref | covered | same |

### races.test.ts

| case | status | vlpds |
|---|---|---|
| handles races in record routes | covered | `races::concurrent_record_writes_all_land` (the reference stalls a transaction through actor-store internals; vlpds drives concurrent writes over XRPC and verifies the exported repo), plus `races::concurrent_swap_*` |

### handles.test.ts

| case | status | vlpds |
|---|---|---|
| resolves handles | covered | `handles::resolves_handles` |
| does not resolve unknown handles | covered | `handles::resolves_handles`; message in `ref_handles::ref_handle_error_messages` |
| resolves non-normalize handles | covered | `handles::resolves_handles` |
| allows a user to change their handle | covered | `handles::user_changes_handle` |
| updates their did document | covered | `handles::user_changes_handle` (alsoKnownAs) |
| allows a user to login with their new handle | covered | `handles::user_changes_handle` |
| does not allow taking a handle that already exists | covered | `handles::cannot_take_existing_handle`; exact message in `ref_handles::ref_handle_error_messages` |
| handle updates are idempotent | covered | `handles::handle_updates_are_idempotent` |
| if handle update fails, it does not update their did document | covered | `handles::cannot_take_existing_handle` |
| disallows handles that do not resolve to a DID | covered | `ref_handles::ref_unresolvable_external_handle_message` (with message; handle unchanged) |
| validates input through lexicon schema | covered | `handles::validates_input_handle_syntax` |
| applies PDS specific handle length constraints | covered | `handles::applies_pds_length_constraints` |
| disallows reserved handles | covered | `handles::disallows_reserved_handles` |
| allows updating to a dns handles | ported | `ref_handles::ref_updates_to_dns_handle_with_txt_proof` (a stub DNS TXT `_atproto` record, dev mode off, as the reference's mocked DNS), `ref_handles::ref_updates_to_external_handle` (dev mode, no proof) |
| does not allow updating to an invalid dns handle | ported | `ref_handles::ref_refuses_invalid_dns_handles` (TXT naming another DID, none, several `did=` records), `ref_handles::ref_unresolvable_external_handle_message` (real DNS, non-dev mode) |
| allows admin overrules of service domains | covered | `handles::admin_overrides_handles` |
| allows admin override of reserved domains | covered | `handles::admin_overrides_handles` |
| requires admin auth | covered | `handles::admin_update_requires_admin_auth`; error name in `ref_handles::ref_admin_update_handle_auth_message` |

### handle-validation.test.ts

| case | status | vlpds |
|---|---|---|
| validates service constraints | covered | `handle_validation::validates_service_constraints`, `handle_validation::rejects_handles_outside_service_domains` (unit test of `ensureHandleServiceConstraints`, exercised through createAccount) |
| handles bad tlds | covered | `handle_validation::rejects_bad_tlds` |
| validates handle length | covered + ported | `handle_validation::validates_handle_length`; the long-service-domain half in `ref_handles::ref_handle_length_with_long_service_domain` |

## Sync, firehose, sequencer, server, PLC, moderation, invites

### sync/sync.test.ts

| case | status | vlpds |
|---|---|---|
| creates and syncs some records | covered | `sync::creates_and_syncs_records_then_deletes` (full export: signed v3 commit, MST contents == written records) |
| syncs creates and deletes | covered | `sync::creates_and_syncs_records_then_deletes` |
| syncs repo status | covered | `sync::repo_status_and_latest_commit` |
| syncs latest repo commit | covered | `sync::repo_status_and_latest_commit` |
| syncs `since` a given rev | covered | `sync::get_repo_since_returns_diff`. The reference's `< 10 blocks` bound is divergent: vlpds returns the commit, all MST nodes and the newer records (a superset; STATUS.md) |
| sync a record proof | covered | `sync::record_inclusion_proof` |
| sync a proof of non-existence | covered | `sync::record_non_inclusion_proof` |
| repo takedown > returns takendown status | covered | `sync::repo_takedown_visibility` |
| repo takedown > lists as takendown in listRepos | covered | `sync::repo_takedown_visibility` |
| repo takedown > does not sync repo unauthed | covered | `sync::repo_takedown_visibility` (400 RepoTakendown) |
| repo takedown > syncs repo to owner or admin | covered | `sync::repo_takedown_visibility` |
| repo takedown > does not sync latest commit unauthed | covered | `sync::repo_takedown_visibility` |
| repo takedown > does not sync a record proof unauthed | covered | `sync::repo_takedown_visibility` |

### sync/list.test.ts

| case | status | vlpds |
|---|---|---|
| lists hosted repos in order of creation | divergent | `sync_list::lists_all_hosted_repos` checks completeness, head and rev. The order is `(slot, DID)`, not creation order: the listing is served per shard (DESIGN.md "Online shard split/merge", listRepos) |
| paginates listed hosted repos | covered | `sync_list::paginates_listed_repos` |

### sync/subscribe-repos.test.ts

| case | status | vlpds |
|---|---|---|
| emits sync event on account creation, matching temporary commit event. | covered | `subscribe_repos::sync_identity_account_events_on_creation` |
| sync backfilled events | covered | `subscribe_repos::backfilled_events_rebuild_repos` |
| syncs new events | covered | `subscribe_repos::cutover_from_backfill_to_live` |
| handles no backfill | covered | `subscribe_repos::live_tail_without_cursor_has_no_backfill`. The reference's listener-count check is internal |
| backfills only from provided cursor | covered | `subscribe_repos::backfills_only_from_provided_cursor` |
| syncs handle changes (identity evts) | covered | `subscribe_repos::identity_events_on_handle_change` |
| resends identity events on idempotent updates | covered | `subscribe_repos::identity_events_on_handle_change` (the third, repeated update re-sends `#identity`) |
| syncs account events | covered | `subscribe_repos::account_events_deactivate_and_takedown` |
| syncs interleaved account events | covered | `subscribe_repos::interleaved_account_events`. Divergent detail: vlpds revokes sessions on takedown, so the test logs in again before activating |
| emits sync event on account activation | covered | `subscribe_repos::sync_event_on_account_activation` |
| syncs account deletions (account evt) | covered | `subscribe_repos::account_deletion_events` |
| account deletions invalidate all seq ops | divergent + ported | `ref_sync::account_deletion_is_the_last_event_on_replay`. The reference deletes the DID's earlier `repo_seq` rows. The vlpds log is the firehose and is immutable, so earlier events stay in a replay. The test checks the shared guarantee: `#account deleted` is the DID's last event, it appears exactly once, and the repo is gone |
| sends info frame on out of date cursor | covered | `subscribe_repos::outdated_cursor_info_or_full_replay`. vlpds serves old cursors from the durable log when it can (full replay), and otherwise sends `#info OutdatedCursor` first |
| errors on future cursor | covered | `subscribe_repos::errors_on_future_cursor` |

### sync/invertible-ops.test.ts

| case | status | vlpds |
|---|---|---|
| works | covered | `invertible_ops::every_commit_inverts_to_prev_data` (also `sync11_property::*`) |

### sequencer.test.ts

| case | status | vlpds |
|---|---|---|
| sends to outbox | covered | `sequencer::sends_to_outbox_in_order` (through the WebSocket rather than the TS `Outbox` class) |
| handles cut over | covered | `sequencer::handles_cutover_while_writing` |
| only gets events after cursor | covered | `sequencer::only_gets_events_after_cursor` |
| buffers events that are not being read | covered | `sequencer::buffers_events_that_are_not_being_read` |
| errors when buffer is overloaded | covered | `firehose_fanout::stalled_subscriber_is_cut_off_without_delaying_writes_or_others` (ConsumerTooSlow, then close). The bound is in bytes (`firehose_max_lag_bytes`), not the reference's event count `maxBufferSize` |
| handles many open connections | covered | `sequencer::many_open_connections`, `subscribe_repos::many_open_connections_see_identical_streams` |
| root block must be returned in sync event | covered | `sequencer::root_block_in_sync_event` |

### server.test.ts

| case | status | vlpds |
|---|---|---|
| preserves 404s. | covered | `server_basics::preserves_404s` |
| error handler turns unknown errors into 500s. | N/A | It injects a throwing Express route into the TS app (internal). The vlpds XRPC error envelope is covered by `server_basics::malformed_json_and_missing_params_are_400` and `unknown_xrpc_method_without_appview` |
| limits size of json input. | covered | `server_basics::limits_size_of_json_input` |
| compresses large json responses | covered | `server_basics::compresses_large_json_and_car_responses_only` |
| compresses large car file responses | covered | `server_basics::compresses_large_json_and_car_responses_only` |
| does not compress small payloads | covered | `server_basics::compresses_large_json_and_car_responses_only` |
| healthcheck succeeds when database is available. | covered | `server_basics::healthcheck` |
| healthcheck fails when database is unavailable. (it.skip) | N/A | Skipped in the reference itself. It also needs a killable Postgres |

### plc-operations.test.ts

| case | status | vlpds |
|---|---|---|
| prevents submitting an operation that removes the server's rotation key | covered | `plc::sign_and_submit_plc_operations` (message asserted) |
| prevents submitting an operation that incorrectly sets the signing key | covered | `plc::sign_and_submit_plc_operations` |
| prevents submitting an operation that incorrectly sets the handle | covered | `plc::sign_and_submit_plc_operations` |
| prevents submitting an operation that incorrectly sets the pds endpoint | covered | `plc::sign_and_submit_plc_operations` |
| prevents submitting an operation that incorrectly sets the pds service type | covered | `plc::sign_and_submit_plc_operations` |
| does not allow signing plc operation without a token | ported | `ref_plc::plc_signature_request_mail_and_token_errors` (the reference's error message). `plc::sign_and_submit_plc_operations` covered only the status |
| requests a plc signature | ported | `ref_plc::plc_signature_request_mail_and_token_errors` (one mail to the account, subject "PLC Update Operation Requested", HTML contains "PLC update requested", carries a token) |
| does not sign a plc operation with a bad token | covered | `plc::sign_and_submit_plc_operations`. The "Token is invalid" message is also asserted in `ref_plc::*` |
| signs a plc operation with a valid token | covered | `plc::sign_and_submit_plc_operations` |
| submits a valid operation | covered | `plc::sign_and_submit_plc_operations` |
| emits an identity event after a valid operation | covered | `plc::sign_and_submit_plc_operations` (`#identity` on the firehose after submit) |

### plc-rotation-key-override.test.ts

| case | status | vlpds |
|---|---|---|
| uses the override for XRPC account creation | N/A | It tests the TS constructor-injection override (`plcRotationKey` over the hex config). vlpds takes one configured `RotationKey`, and `plc::create_account_registers_the_genesis_op` checks that the genesis op carries it |
| uses the override for handle updates | N/A | Same TS-internal override (it calls `accountManager.updateHandle` directly). The behavior is covered by `plc::update_handle_submits_a_plc_update_first` |
| uses the override for OAuth account creation | N/A | Same TS-internal override (`oauthProvider.accountManager.createAccount`). OAuth sign-up (`oauth::prompt_create_signs_up`) goes through the same `create_account_inner` as XRPC createAccount, so it registers with the same key |

### moderation.test.ts

| case | status | vlpds |
|---|---|---|
| takes down accounts | covered | `moderation::takes_down_and_restores_accounts` |
| restores takendown accounts | covered | `moderation::takes_down_and_restores_accounts` |
| takes down records | covered | `moderation::takes_down_and_restores_records` |
| restores takendown records | covered | `moderation::takes_down_and_restores_records` |
| blob takedown > takes down blobs | covered | `moderation::blob_takedown_lifecycle` |
| blob takedown > removes blob from the store | N/A | It reads the TS blobstore directly (internal). The observable effect (getBlob 400 BlobNotFound) is in `moderation::blob_takedown_lifecycle` |
| blob takedown > prevents blob from being referenced again. | covered | `moderation::blob_takedown_lifecycle` |
| blob takedown > prevents blob from being reuploaded | covered | `moderation::blob_takedown_lifecycle` |
| blob takedown > prevents image blob from being served. | covered | `moderation::blob_takedown_lifecycle` |
| blob takedown > restores blob when takedown is removed | covered | `moderation::blob_takedown_lifecycle` |
| blob takedown > prevents blobs of takendown accounts from being served. | ported | `ref_moderation::takendown_account_blobs_are_served_to_owner_and_admin_only` |

### invite-codes.test.ts

| case | status | vlpds |
|---|---|---|
| describes the fact that invites are required | covered | `invite_codes::describes_that_invites_are_required` |
| succeeds with a valid code | covered | `invite_codes::valid_bad_and_missing_codes` |
| fails on bad invite code | covered | `invite_codes::valid_bad_and_missing_codes` |
| fails on invite code from takendown account | covered | `invite_codes::fails_on_invite_code_from_takendown_account` |
| fails on used up invite code | covered | `invite_codes::fails_on_used_up_invite_code` |
| handles racing invite code uses | covered | `invite_codes::handles_racing_invite_code_uses` |
| allow users to get available user invites | ported | `invite_codes::ref_earns_invite_codes_on_an_interval` (a 1 h `--invite-interval-ms`, the account backdated 2.5 h as the reference backdates `actor.createdAt` in SQL); the reference's exact day/epoch arithmetic in `xrpc::server::invite_interval_tests::earns_one_code_per_interval` (lib) |
| admin gifted codes to not impact a users available codes | covered | `invite_codes::ref_earns_invite_codes_on_an_interval` (3 admin + 2 earned), `invite_codes::admin_gifted_codes_are_listed_for_the_account`, `invite_interval_tests::admin_codes_do_not_count` |
| creates invites based on epoch | ported | `xrpc::server::invite_interval_tests::counts_only_age_since_the_epoch` (lib): the reference's backdated account and SQL-inserted codes, as inputs to `codes_to_create` (its `calculateCodesToCreate`) |
| prevents use of disabled codes | covered | `invite_codes::prevents_use_of_disabled_codes` |
| does not allow disabling all admin codes | covered | `invite_codes::does_not_allow_disabling_all_admin_codes` |
| creates many invite codes | covered | `invite_codes::creates_many_invite_codes` |

### invites-admin.test.ts

These are adapted: alice's own codes are admin-gifted rather than interval-earned (the interval cases are in invite-codes above).

| case | status | vlpds |
|---|---|---|
| gets a list of invite codes by recency | ported | `ref_invites::lists_invite_codes_by_recency_and_paginates` |
| paginates by recency | ported | `ref_invites::lists_invite_codes_by_recency_and_paginates` |
| gets a list of invite codes by usage | ported | `ref_invites::lists_invite_codes_by_usage_and_paginates` |
| paginates by usage | ported | `ref_invites::lists_invite_codes_by_usage_and_paginates` |
| hydrates invites into admin.getAccountInfo | ported | `ref_invites::hydrates_invites_into_get_account_info` (also checks getAccountInfos) |
| disables an account from getting additional invite codes | ported | `ref_invites::disables_and_reenables_account_invites` (`invitesDisabled` flag; no usable codes while disabled) |
| allows setting reason when enabling and disabling invite codes | ported | `ref_invites::disables_and_reenables_account_invites` (the `note` is accepted) |
| creates codes in the background but disables them | ported | `invite_codes::ref_creates_disabled_codes_for_a_disabled_account` (interval 1 ms; the 5 codes read through admin.getInviteCodes instead of SQL) |
| re-enables an accounts invites | ported + divergent | `ref_invites::disables_and_reenables_account_invites`. vlpds re-enables the account's existing codes. The reference only clears the flag and then generates fresh codes, so codes an admin disabled by account through disableInviteCodes would stay disabled there but be re-enabled by vlpds |

## Proxying (tests/proxied)

### proxied/admin.test.ts

These drive a real Ozone through the PDS proxy (`tools.ozone.*` → mod service). What they assert is Ozone's behavior (report/event/repo views, label state). The PDS's part — forwarding `tools.ozone.*` with service auth and relaying upstream errors — is generic proxying.

| case | status | vlpds |
|---|---|---|
| creates reports of a repo. | covered | `proxy::create_report_goes_to_report_service` (createReport → configured report service, service-auth `lxm`/`aud`, body relayed) |
| takes actions and resolves reports | N/A | Ozone moderation-event semantics; the PDS only forwards (`proxy::proxies_to_default_appview_with_service_auth_and_header_rules`) |
| fetches moderation events. | N/A | Ozone view |
| fetches repo details. | N/A | Ozone view |
| fetches record details. | N/A | Ozone view |
| fetches event details. | N/A | Ozone view |
| fetches a list of events. | N/A | Ozone view |
| searches repos. | N/A | Ozone view |
| passes through errors. | covered | `proxy::maps_upstream_errors` (4xx name/message relayed, 500 → 502), `ref_proxy::ref_proxy_catchall_ok_and_error` |
| takesdown and labels repos, and reverts. | covered | the PDS side (admin `updateSubjectStatus` takedown/restore of a repo, which Ozone calls): `moderation::takes_down_and_restores_accounts`; labels are Ozone's |
| takesdown and labels records, and reverts. | covered | `moderation::takes_down_and_restores_records`; labels are Ozone's |

### proxied/decompression-bound.test.ts

| case | status | vlpds |
|---|---|---|
| stops parsing an oversized decoded error body. | ported | `ref_proxy::ref_proxy_oversized_error_body_is_not_parsed` (gzip bomb and an uncompressed >10 MiB body; the status is relayed, the error name is not). vlpds never decodes a compressed error body (the reference decodes up to the cap), so the bomb is never inflated |
| rejects an oversized decoded read-after-write body. | ported | `ref_proxy::ref_proxy_oversized_read_after_write_body` (502 `upstream response too large`) |
| rejects an oversized body that is not compressed. | ported | `ref_proxy::ref_proxy_oversized_read_after_write_body` (wire cap, 502). vlpds's cap is the reference default (10 MiB, not configurable) |

### proxied/feedgen.test.ts

| case | status | vlpds |
|---|---|---|
| performs basic proxy of getFeed | covered | `read_after_write::get_feed_service_auth_names_the_generator` (generator record lookup, token `aud` = feed generator DID, `lxm` = getFeedSkeleton, UnknownFeed) |

### proxied/notif.test.ts

| case | status | vlpds |
|---|---|---|
| proxies registerPush to notif service. | covered | `push::other_service_did_resolves_its_bsky_notif_endpoint`, `push::appview_service_did_goes_to_the_configured_appview` |
| proxies unregisterPush to notif service. | covered | same tests (both methods) |

### proxied/procedures.test.ts

The muting state lives in the AppView; the PDS part is proxying a JSON procedure with service auth.

| case | status | vlpds |
|---|---|---|
| maintains muted actors. | covered | generic POST proxy: `proxy::streams_post_bodies` (body, content-type, method relayed); mute state is AppView behavior (N/A) |
| maintains muted actor lists. | covered | as above |
| maintains notification last seen state. | covered | as above |

### proxied/proxy-catchall.test.ts

| case | status | vlpds |
|---|---|---|
| rejects when upstream unavailable | ported | `ref_proxy::ref_proxy_upstream_unavailable` (502 UpstreamFailure "Upstream service unreachable"); also `proxy::unreachable_upstream_is_502` |
| successfully proxies requests | ported | `ref_proxy::ref_proxy_catchall_ok_and_error`; `proxy::target_selection_and_rejections` |
| handles cancelled upstream requests | ported | `ref_proxy::ref_proxy_cancelled_upstream` (the broken body is not delivered as complete) |
| handles failing upstream requests | covered | `proxy::maps_upstream_errors`; `ref_proxy::ref_proxy_catchall_ok_and_error` (500 → 502 FooBar / My message) |
| handles cancelled downstream requests | ported | `ref_proxy::ref_proxy_cancelled_downstream` |

### proxied/proxy-header.test.ts

| case | status | vlpds |
|---|---|---|
| parses proxy header | ported | `ref_proxy::ref_proxy_header_errors` (every message over the wire). divergent (minor): `did:foo#bar`, `did:foo:bar#baz`, `foo#bar` — the reference's resolver throws PoorlyFormattedDid/UnsupportedDidMethod, which surfaces as a 500; vlpds answers 400 "could not resolve proxy did" |
| proxies requests based on header | covered | `proxy::target_selection_and_rejections` (did:web target, path, service JWT verified: `iss`, bare-DID `aud`, `lxm`) |
| fails on a non-existant did | ported | `ref_proxy::ref_proxy_header_errors`; `proxy::target_selection_and_rejections` |
| fails when a service is not specified | ported | `ref_proxy::ref_proxy_header_errors` |
| fails on a non-existant service | ported | `ref_proxy::ref_proxy_header_errors`; `proxy::target_selection_and_rejections` |
| handles failing manual pipethroughs | ported | `ref_proxy::ref_proxy_header_errors` (getPreferences for another service → upstream 501 relayed) |

### proxied/proxy-oauth-aud.test.ts

The reference stubs the auth verifier and calls `proxyHandler` directly; it checks that the scope check sees `did#serviceId`.

| case | status | vlpds |
|---|---|---|
| matches an OAuth rpc scope granted with combined did#serviceId aud | covered | `oauth::scopes::tests::rpc` (lib unit test) + the proxy checks `creds.allows_rpc(lxm, Target::scope_aud())` = `did#service_id` (src/xrpc/proxy.rs) |
| rejects an OAuth rpc scope granted for a different service id | covered | `oauth::scopes::tests::rpc` (assertion added: same DID, other service id, and the bare DID don't match) |

### proxied/read-after-write.test.ts

| case | status | vlpds |
|---|---|---|
| handles read after write on profiles | covered | `read_after_write::profile_overlay_and_images` |
| handles image formatting | covered | `read_after_write::profile_overlay_and_images` (avatar/banner CDN URLs) |
| handles read after write on getAuthorFeed | covered | `read_after_write::feeds_get_new_posts` |
| handles read after write on threads | covered | `read_after_write::threads_get_new_replies` |
| handles read after write on a thread that is not found on appview | covered | `read_after_write::threads_get_new_replies` (NotFound → built locally, parents from the AppView) |
| handles read after write on threads with record embeds (images/external) | covered | `read_after_write::threads_get_new_replies` (images#view, external#view CDN URLs) |
| handles read after write on threads with record embeds (embed.record) | covered | `read_after_write::threads_get_new_replies` (record#view via getPosts) |
| handles read after write on getTimeline | covered | `read_after_write::feeds_get_new_posts` |
| passes the appview cursors through the timeline munge | ported | `ref_proxy::ref_read_after_write_timeline_cursors_and_since` (`cursor` and `startCursor`); `cursor` also in `feeds_get_new_posts` |
| forwards since to the appview through the timeline munge | ported | `ref_proxy::ref_read_after_write_timeline_cursors_and_since` |
| returns lag headers | covered | `read_after_write::feeds_get_new_posts`, `profile_overlay_and_images` |
| negotiates encoding | ported | `ref_proxy::ref_read_after_write_encoding_negotiation` |
| defaults to identity encoding | ported | same |
| falls back to identity encoding | ported | same |
| errors when failing to negotiate encoding | ported | same (406). **fixed**: vlpds did not negotiate; see product fixes |
| errors on invalid content-encoding format | ported | same (400 `Invalid accept-encoding: ";q=1"`). **fixed** |

### proxied/views.test.ts

All 20 cases snapshot AppView views fetched through the PDS (`app.bsky.*` GETs). Their content is the AppView's; the PDS behavior (default AppView target, service auth, header allow-lists, error relay) is covered by `proxy::proxies_to_default_appview_with_service_auth_and_header_rules`, `proxy::maps_upstream_errors` and the read-after-write tests.

| case | status | vlpds |
|---|---|---|
| actor.getProfile | covered | generic GET proxy (above) + `read_after_write::profile_overlay_and_images` |
| actor.getProfiles | covered | generic GET proxy + read-after-write `Kind::Profiles` |
| actor.getSuggestions | N/A | AppView view (generic proxy covered) |
| actor.searchActor | N/A | AppView view |
| actor.searchActorTypeahead | N/A | AppView view |
| feed.getAuthorFeed | covered | `read_after_write::feeds_get_new_posts` |
| feed.getListFeed | N/A | AppView view |
| feed.getLikes | N/A | AppView view (`read_after_write::compressed_upstream_is_munged` proxies it) |
| feed.getRepostedBy | N/A | AppView view |
| feed.getPosts | N/A | AppView view |
| feed.getTimeline | covered | `read_after_write::feeds_get_new_posts` |
| unspecced.getPopularFeedGenerators | N/A | AppView view |
| feed.getFeedGenerator | N/A | AppView view |
| feed.getFeedGenerators | N/A | AppView view |
| graph.getBlocks | N/A | AppView view |
| graph.getFollows | N/A | AppView view |
| graph.getFollowers | N/A | AppView view |
| graph.getList | N/A | AppView view |
| graph.getLists | N/A | AppView view |
| graph.getListBlocks | N/A | AppView view |

## Spaces (permissioned data)

The reference's space suites at `bluesky-social/atproto` 5b95b2f2 (PR #5187, permissioned-data; `policy.test.ts` and the clearRecords and writer-set cases at 98ef3a6b), mapped case by case to
`tests/all/spaces_side/ref_*.rs`. The harness is `spaces_side::ref_net`, the reference's `tests/_space.ts` over XRPC: a `Net` of
`--spaces` PDSes on one in-process PLC directory, OAuth accounts, signed credential reads, a did:web `MockService` (managing app,
syncer, remote space host, or a party whose key a test holds) and a `MockClientApp` serving client metadata and a JWKS. Run them
with `cargo test --test all spaces_side::ref_`. Each test names its reference case in a doc comment, and the `(Cn)` on a row
is the core slice that made it pass.

Two things change how a case is ported, so they aren't repeated on every row:

- The reference adds members to most spaces even where a test never reads with a credential. A member's PDS never consults the
  member list on a write (only the authority does, on notifyWrite), so the ports add members only where a credential is minted.
- The reference reads its stores directly (`repoState`, `writerDids`, `blobExists`, revocation rows). The ports read the same
  facts over XRPC (the owner's getLatestCommit and listRecords, space.getBlob), except `writerDids`, which reads the authority's
  `sW` rows as the reference does. A credential for listRepos would have to clear an allowList space's app check, and the
  reference's own read never does.

Divergences, also in DESIGN.md's Spaces section:

- **OAuth-only.** Space data needs an OAuth `space:` grant. App passwords (privileged or not) and password sessions get no space
  read, write or delegation token, nor a `getServiceAuth` token for a `com.atproto.space.*` or policy (`com.atproto.memberspace.*`)
  method. The reference lets both write and read the account's own repo.
- **The durable `sP` outbox replaces the lease-elected retry worker.** A notify's row is written in the write's own log entry,
  sent single-flight per repo and space, retried in memory, and rescanned by whichever node opens the shard. So the reference's
  lease-election and "persists failures before the request" cases become outbox cases (a restart or takeover resends the
  newest rev), and the cases about its retry table, backoff timing and deadline are left to the outbox's own tests.
- **Record takedowns are pushed.** A space record takedown or its reversal changes the hash the author's repo serves at the
  same rev, and its host notifies the authority with it. So the authority sequences the same repoRev with another hash again
  and forwards it, once the writer's PDS serves a commit with that hash at that rev (at most 3 per writer and space in
  10 min). The same repoRev with the same hash is a no-op, as in the reference, which ignores every repoRev at or below the
  last.
- **300 s single-use token cap.** Delegation tokens and client attestations live at most 300 s. The reference takes any lifetime.
- **sync.getBlob needs a public reference, with `--spaces` on.** That's the reference's rule. With the flag off vlpds keeps
  serving an uploaded blob before anything references it, except one that only space records name.
- **Oplog retention.** vlpds keeps 7 days of oplog. A `since` older than that gets ops from the window start, the replay doesn't
  match the commit, and the syncer falls back to getRepo or listRecords (the spec treats the oplog as droppable). The
  reference never prunes.
- **Bounded revocations and registrations.** Revocations are one cluster-wide object every node reads, so `jti`s are capped at
  128 characters (a longer credential is refused), live entries per authority and in all are capped, and one that can't be
  stored blocks its space's credentials. A space holds at most 256 notify registrations. The reference bounds neither.
- **Account takedowns revoke OAuth sessions for good.** As for every vlpds account, a takedown revokes the account's OAuth
  sessions and a reversal doesn't bring them back, so an app signs in again. The reference's sessions work again.
- **Takedowns reach space data.** A taken-down account mints no delegation token, and getSpaceCredential refuses a taken-down
  member (`AccountTakedown`) or authority (`RepoTakendown`). Record takedowns (a takedown-adjusted, consistently MACed view)
  and space takedowns are vlpds extensions. The reference has neither, so its suites have no cases for them. They're tested in
  `spaces_admin`, `spaces_sync::record_takedown_serves_a_consistent_view` and `spaces_blobs`.
- **vlpds-only methods.** The audited operator reads (`vlpds.admin.getSpaceRepo`, `listSpaceRecords`, `getSpaceRecord`,
  `checkSpace`) have no upstream counterpart (`spaces_admin`).
- **importRepo.** `com.atproto.space.importRepo` takes the getRepo STAR archive as the reference does (no MAC, the commit
  naming the account, the records folding to its `data`, `create` granted per collection). It's OAuth-only like every space
  method, the new rev follows the archive's as well as the one held, an archive whose rev is past the FutureRev window is
  refused, and the authority's own repo needs its live space. The whole archive is checked before the repo here is touched
  (kept in memory up to 8 MiB, then in a temporary file), so a refused import leaves the repo as it was, as the reference's
  one transaction does (`spaces_side::import_repo`). These cases are vlpds's own, not a reference suite's.
- **1,000,000-byte space records.** A space record's encoding is capped at 1,000,000 bytes, as a public repo record's is.
  The reference caps it at 1 MiB, its STAR value limit, which an import still allows.

The notification retry rows and the registration expiry row run through test hooks: `Outbox::set_retry_base` shortens the
1 min retry pause, and `xrpc::space::set_registration_expiry` expires a registration through the authority's worker (the
tests no longer age `sN` rows with a direct `db.put`, which the worker's cached expiry would hide). The rows that still need
minutes-to-hours timing or a mocked clock stay N/A and are covered by the outbox's own unit tests.

| | Cases |
|---|---:|
| ported | 245 |
| ported + divergent | 7 |
| divergent | 1 |
| covered | 1 |
| N/A | 8 |
| GAP | 2 |
| **total** | **264** |

Counted per `it()` case, with each `it.each` row counted once per value. Three more rows (marked "(vlpds)") are vlpds-only
tests (the 300 s cap, the old credential scheme) and aren't counted. The sync, records and auth rows follow the reference at
98ef3a6b (the October 22 wire: MACs, STAR, credentials in the request body).

### space/records.test.ts

| case | status | vlpds |
|---|---|---|
| writes a record as a co-located member | ported | `ref_space_records::writes_a_record_as_a_co_located_member` (C1) |
| writes a record from a remote PDS | ported | `..::writes_a_record_from_a_remote_pds` (C2, listSpaces) |
| refuses a write to another account repo | ported | `..::refuses_a_write_to_another_account_repo` (C1) |
| deletes a record | ported | `..::deletes_a_record` (C1) |
| deleteRecord is idempotent | ported | `..::delete_record_is_idempotent` (C1) |
| putRecord creates a record that does not yet exist | ported | `..::put_record_creates_a_record_that_does_not_yet_exist` (C1) |
| putRecord overwrites an existing record, and the oplog names what it replaced | ported | `..::put_record_overwrites_and_the_oplog_names_what_it_replaced` (C1) |
| applies a batch as one rev | ported | `..::apply_writes_applies_a_batch_as_one_rev` (C1) |
| rejects a duplicate create within one batch | ported | `..::apply_writes_rejects_a_duplicate_create_within_one_batch` (C1) |
| applies dependent writes within one batch | ported | `..::apply_writes_applies_dependent_writes_within_one_batch` (C1) |
| treats an empty batch as a no-op | ported | `..::apply_writes_treats_an_empty_batch_as_a_no_op` (C1) |
| reports each result against the write it came from | ported | `..::apply_writes_reports_each_result_against_its_write` (C1) |
| refuses a batch over the write limit | ported | `..::apply_writes_refuses_a_batch_over_the_write_limit` (C1) |
| refuses an unrecognized write type at the schema | ported | `..::apply_writes_refuses_an_unrecognized_write_type` (C1, 400 InvalidRequest; the message isn't pinned) |
| rejects a record whose $type disagrees with its collection | ported | `..::rejects_a_record_whose_type_disagrees_with_its_collection` (C1) |
| reports unknown for a collection with no resolvable schema | ported | `..::reports_unknown_for_a_collection_with_no_resolvable_schema` (C1) |
| refuses an unvalidatable record when validation is demanded | ported | `..::refuses_an_unvalidatable_record_when_validation_is_demanded` (C1) |
| refuses a record over the size limit | ported + divergent | `..::refuses_a_record_over_the_size_limit`: vlpds caps the encoding at 1,000,000 bytes (1 MiB in the reference). As in the reference the request body limit comes first (413), so the port writes one just under the cap and one at it, where the reference calls `prepareCreate` |
| listRecords paginates across collections | ported | `..::list_records_paginates_across_collections` (C2) |
| listRecords filters to one collection | ported | `..::list_records_filters_to_one_collection` (C2) |
| listRecords reverses the listing order | ported | `..::list_records_reverses_the_listing_order` (C2) |
| listRecords scopes a listing to one space | ported | `..::list_records_scopes_a_listing_to_one_space` (C1) |
| getRecord returns the record and its current cid | ported | `..::get_record_returns_the_record_and_its_current_cid` (C1) |
| getRecord reports RecordNotFound for a record that never existed | ported | `..::get_record_reports_record_not_found` (C1) |
| tracks a blob on a space record and serves it to a member | ported | `..::blobs_tracks_a_blob_and_serves_it_to_a_member` (C5). The "untethered until referenced" store read isn't observable |
| does not serve a space-only blob through public sync | ported + divergent | `..::blobs_does_not_serve_a_space_only_blob_through_public_sync` (C5, flag on). Flag off: `..::flag_off_serves_an_unreferenced_upload` (runs now) |
| keeps a blob shared with a public record | ported | `..::blobs_keeps_a_blob_shared_with_a_public_record` (C5). Bytes held = space.getBlob serves them |
| filters listBlobs by revision | ported | `..::blobs_filters_list_blobs_by_revision` (C5) |
| scopes listBlobs to one space | ported | `..::blobs_scopes_list_blobs_to_one_space` (C5) |
| refuses a blob to a credential for another space | ported | `..::blobs_refuses_a_blob_to_a_credential_for_another_space` (C5) |
| refuses a blob that the authorized space does not reference | ported | `..::blobs_refuses_a_blob_the_authorized_space_does_not_reference` (C5) |
| serves a blob the authorized space does reference | ported | `..::blobs_serves_a_blob_the_authorized_space_does_reference` (C5) |
| clearRecords: deletes every record, leaving the repo empty at a new rev | ported | `..::clear_deletes_every_record_at_a_new_rev` |
| clearRecords: clears the oplog rather than logging a delete per record | ported | `..::clear_empties_the_oplog` |
| clearRecords: is a no-op on an empty or unwritten repo | ported | `..::clear_is_a_noop_on_an_empty_repo` |
| clearRecords: recreates the repo on a later write | ported | `..::clear_then_a_write_repopulates` |
| clearRecords: leaves the account's repos in other spaces alone | ported | `..::clear_leaves_other_spaces_alone` |
| clearRecords: refuses to clear another account repo | ported | `..::clear_refuses_another_accounts_repo` |
| blobs: drops the blobs of cleared records | ported | `..::clear_drops_the_blobs_of_cleared_records`. Blob gone = listBlobs and space.getBlob no longer have it |

### space/auth.test.ts

| case | status | vlpds |
|---|---|---|
| refuses a co-located non-member reading a member repo | ported | `ref_space_auth::refuses_a_co_located_non_member_reading_a_member_repo` (C3, getRepo) |
| refuses to mint a delegation token on an app password (privileged: false) | ported + divergent | `..::refuses_space_access_to_app_passwords_and_password_sessions` (C1): the app password's write is refused too, OAuth-only |
| refuses to mint a delegation token on an app password (privileged: true) | ported + divergent | same |
| reads another member repo across PDSes | ported | `..::reads_another_member_repo_across_pdses` (C3) |
| refuses a credential presented as a bearer token | ported | `..::refuses_a_credential_presented_as_a_bearer_token` (C3) |
| refuses a credential without a signature | ported | `..::refuses_a_credential_without_a_signature` (C1, the authority's own credential) |
| recognizes the credential scheme regardless of case | ported | `..::recognizes_the_credential_scheme_regardless_of_case`, plus a signature over another casing than the one sent refused (the base is byte-exact) |
| (vlpds) refuses the old `Atproto-Space` scheme | ported | `..::refuses_the_old_credential_scheme`: 400 InvalidToken "Unsupported authorization type", the migration note's section 2 (no reference case) |
| responds 401 to repeated atproto-space-audience fields | ported | `..::responds_to_repeated_signature_fields` (C1, over listRecords as the reference now reads; a repeated authorization, no longer a reference row, is still refused) |
| responds 200 to repeated signature-input fields | ported | same |
| responds 200 to repeated signature fields | ported | same |
| refuses a credential presented with a key of the holder own | ported | `..::refuses_a_credential_presented_with_another_key` (C3) |
| refuses a signature addressed to another repo owner (remote) | ported | `..::refuses_a_signature_addressed_to_another_repo_owner` (C3) |
| refuses a signature addressed to another repo owner (co-located) | ported | same |
| requires the space authority as audience for space-host requests | ported | `..::requires_the_authority_as_audience_for_space_host_requests` (C3) |
| reuses a signature for the same audience across requests | ported | `..::reuses_a_signature_for_the_same_audience_across_requests` (C3) |
| reuses one credential across many hosts, each with its own audience signature | ported | `..::reuses_one_credential_across_many_hosts` (C3) |
| is scoped to one space | ported | `..::credential_is_scoped_to_one_space` (C3) |
| refuses one the space authority did not issue | ported | `..::refuses_a_credential_the_authority_did_not_issue` (C3). The forger is a did:web, not a member's account key |
| refuses one for a revoked member | ported | `..::refuses_a_credential_for_a_removed_member` (C3) |
| revokes a batch idempotently on a remote repo host | ported | `..::revokes_a_batch_idempotently_on_a_remote_repo_host` (C3). The row count is the refusals |
| requires service auth from the authority addressed to a local repo and method | ported | `..::revocation_requires_service_auth_from_the_authority` (C3) |
| scopes revocations to the space | ported | `..::scopes_revocations_to_the_space` (C3) |
| persists revocations for an hour including clock skew, and prunes expired entries | N/A | mocks `Date.now` over the account DB. vlpds keeps `until = now + 3610 s` in `spaces/revocations` (core unit tests) |
| keeps the revocation when background cleanup fails | N/A | the reference's background queue. vlpds prunes in the CAS write |
| delegation tokens are useless at a host that does not govern the space | ported | `..::delegation_tokens_are_useless_at_a_host_that_does_not_govern_the_space` (C3) |
| binds the credential to the requested key | ported | `..::binds_the_credential_to_the_requested_key` (`credentialKid` in the body) |
| refuses to bind the credential to a key that is not P-256 | ported | `..::refuses_to_bind_the_credential_to_a_key_that_is_not_p256` |
| are refused when the audience names another authority | ported | `..::delegation_tokens_are_refused_when_the_audience_names_another_authority` (C1). The user is a did:web |
| are single-use — a replayed jti is refused | ported | `..::delegation_tokens_are_single_use` (C3) |
| are refused for a space other than their subject | ported | `..::delegation_tokens_are_refused_for_a_space_other_than_their_subject` (C1) |
| (vlpds) 300 s single-use token cap | divergent | `..::delegation_tokens_live_at_most_300_seconds` (C1) |
| stops serving permissioned records for a taken-down account | ported | `..::stops_serving_space_records_of_a_taken_down_account` (C3) |
| stops accepting permissioned writes from a taken-down account | ported | `..::stops_accepting_space_writes_from_a_taken_down_account` (C1) |
| OAuth: enforces the collection a grant names on a write | ported | `..::oauth_enforces_the_collection_a_grant_names` (C1). Real grants, not a stubbed verifier |
| OAuth: enforces the action a grant names | ported | `..::oauth_enforces_the_action_a_grant_names` (C1) |
| OAuth: resolves putRecord to update rather than demanding create too | ported | `..::oauth_resolves_put_record_to_update` (C2) |
| OAuth: refuses a space of a type the grant does not name | ported | `..::oauth_refuses_a_space_of_a_type_the_grant_does_not_name` (C1) |
| OAuth: refuses a space under an authority the grant does not name | ported | `..::oauth_refuses_a_space_under_an_authority_the_grant_does_not_name` (C1) |
| OAuth: reads own repo on read_self, and refuses whole-space read | ported | `..::oauth_read_self_reads_own_repo_but_mints_no_delegation` (C1) |
| OAuth: exchanges a whole-space read grant for a delegation token | ported | `..::oauth_whole_space_read_mints_a_delegation_token` (C1) |
| OAuth: requires a wildcard grant to list spaces unfiltered | ported | `..::oauth_requires_a_wildcard_grant_to_list_spaces_unfiltered` (C2) |
| OAuth: materializes the space type declared collections into a bare grant | ported | `..::oauth_materializes_declared_collections_into_a_bare_grant` (C6). The declaration is published in the account's repo with a pinned NSID authority |
| OAuth: requires delete on every collection a clear removes | ported | `..::oauth_requires_delete_on_every_collection_a_clear_removes` |

### space/policy.test.ts

Was `simplespace.test.ts`.

| case | status | vlpds |
|---|---|---|
| creates a space anchored on the caller own DID | ported | `ref_space_policy::creates_a_space_anchored_on_the_caller` |
| refuses a duplicate space | ported | `..::refuses_a_duplicate_space` |
| refuses a space key that is not a valid record key | ported | `..::refuses_a_space_key_that_is_not_a_record_key` |
| filters spaces by spaceType | ported | `..::filters_spaces_by_space_type` |
| refuses an owner write until createSpace | ported | `..::refuses_an_owner_write_until_create_space` |
| memberspace members: adds and removes members, and the owner is not one of them | ported | `..::adds_and_removes_members` |
| memberspace members: refuses membership changes from a non-owner member | ported | `..::refuses_membership_changes_from_a_non_owner` |
| memberspace members: refuses listMembers to a space credential and to a non-owner member | ported | `..::refuses_list_members_to_a_credential_and_a_non_owner` |
| memberspace members: putMember replaces both access values | ported | `..::put_member_replaces_both_access_values` |
| memberspace members: refuses member methods on a space under another policy | ported | `..::refuses_member_methods_under_another_policy` |
| memberspace members: removeMember drops the member from the writer set | ported | `..::remove_member_drops_the_writer` |
| memberspace members: putMember drops the member from the writer set when it revokes write | ported | `..::put_member_without_write_drops_the_writer` |
| policy: persists what createSpace was given | ported | `..::persists_what_create_space_was_given` |
| policy: fills in the defaults of an omitted configuration | ported | `..::fills_in_the_defaults` |
| policy: replaces the policy wholesale on update | ported | `..::replaces_the_policy_wholesale` |
| policy: keeps the member list across a configuration change | ported | `..::keeps_the_member_list_across_a_configuration_change` |
| policy: refuses an update from a non-owner | ported | `..::refuses_an_update_from_a_non_owner` |
| policy: refuses an unrecognized policy | ported | `..::refuses_an_unrecognized_policy` |
| policy: refuses a managingApp that does not name a service | ported | `..::refuses_a_managing_app_that_is_not_a_did` |
| policy: refuses the policy to a member with a space credential | ported | `..::refuses_the_policy_to_a_member_credential` |
| policy: refuses the policy to another account on an account credential | ported | `..::refuses_the_policy_to_another_account` |
| policy: refuses to answer for a space this host does not govern | ported | `..::refuses_to_answer_for_a_space_this_host_does_not_govern` |
| policy migration: discards the member list, and migrating back does not restore it | ported | `..::migration_discards_the_member_list` |
| publishing: publishes the policy to readers | ported | `..::publishes_the_policy_to_readers` |
| publishing: keeps the published policy in sync, and withdraws it when unpublished | ported | `..::keeps_the_published_policy_in_sync` |
| publishing: publishes the member list, keyed by member DID | ported | `..::publishes_the_member_list` |
| publishing: leaves the port of a localhost did:web unencoded in its record key | ported | `..::leaves_a_did_web_port_unencoded_in_its_record_key` |
| publishing: publishes or withdraws the whole member list when publishMembers changes | ported | `..::publishes_or_withdraws_the_whole_member_list` |
| publishing: withdraws the published member list on migration | ported | `..::withdraws_the_published_member_list_on_migration` |
| publishing: keeps the published records when the authority clears its repo | ported | `..::keeps_the_published_records_when_the_authority_clears` |
| publishing: notifies the space of what it publishes | ported | `..::notifies_the_space_of_what_it_publishes` |
| publishing: refuses direct writes of published records | ported | `..::refuses_direct_writes_of_published_records` |
| personalspace: authorizes only the authority to read | ported | `..::personalspace_authorizes_only_the_authority` |
| personalspace: tracks no writer but the authority | ported | `..::personalspace_tracks_no_writer_but_the_authority` |
| mints for a non-member when read access is public | ported | `..::mints_for_a_non_member_when_read_is_public` |
| mints without a delegation token when read access is public | ported | `..::mints_without_a_delegation_token_when_read_is_public` |
| hides a memberspace space from a request without a delegation token | ported | `..::hides_a_space_from_a_request_without_a_delegation_token` (one test, all three policies) |
| hides a personalspace space from a request without a delegation token | ported | `..::hides_a_space_from_a_request_without_a_delegation_token` |
| hides a managedspace space from a request without a delegation token | ported | `..::hides_a_space_from_a_request_without_a_delegation_token` |
| hides a space from a request without a delegation token before checking the app | ported | `..::hides_a_space_without_a_token_before_checking_the_app` |
| refuses a request without a delegation token or attestation when apps are restricted | ported | `..::refuses_a_tokenless_request_without_an_attestation_when_apps_are_restricted` |
| hides the space from a non-member when read access is not public | ported | `..::hides_the_space_from_a_non_member` |
| hides the space from a non-member before checking the app | ported | `..::hides_the_space_from_a_non_member_before_checking_the_app` |
| hides the space from a member without read access | ported | `..::hides_the_space_from_a_member_without_read_access` |
| always admits the authority, whatever the policy | ported | `..::always_admits_the_authority` |
| refuses when apps are restricted and no attestation is presented | ported | `..::refuses_restricted_apps_without_an_attestation` |
| client attestation: mints for an allow-listed app that signs with its published key | ported | `ref_client_attestation::accepts_an_attestation_when_the_client_publishes_a_jwks_uri` |
| client attestation: refuses an attestation signed by a key the app does not publish | ported | `ref_client_attestation::refuses_an_attestation_signed_by_an_unpublished_key` |
| client attestation: refuses an attestation addressed to another authority | ported | `ref_client_attestation::refuses_an_attestation_addressed_to_another_space_host` |
| client attestation: refuses an attestation from an app that is not allow-listed | ported | `ref_client_attestation::refuses_an_attestation_from_an_app_that_is_not_allow_listed` |
| client attestation: mints for an allow-listed app without a delegation token | ported | `ref_client_attestation::mints_for_an_allow_listed_app_without_a_delegation_token` |
| client attestation: refuses an expired attestation | ported | `ref_client_attestation::refuses_an_expired_attestation` |
| managedspace: admits a user the managing app authorizes | ported | `ref_space_policy::managing_app_admits_a_user_it_authorizes` |
| managedspace: refuses a user the managing app declines | ported | `..::managing_app_refuses_a_user_it_declines` |
| managedspace: denies when the managing app errors | ported | `..::managing_app_denies_when_it_errors` |
| managedspace: denies when the managing app cannot be resolved | ported | `..::managing_app_denies_when_unresolvable` |
| managedspace: records a writer the managing app admits | ported | `..::managing_app_admits_a_writer`, which also checks the write check carries no `clientId` |
| registers, forwards writes, and stops once withdrawn | ported | `..::registers_forwards_writes_and_stops_once_withdrawn` |
| stops delivering to a registration past its expiry, and resumes on renewal | ported | `..::stops_past_expiry_and_resumes_on_renewal`. The row is expired through the authority's worker (`xrpc::space::set_registration_expiry`), and vlpds prunes it where the reference withholds it, so the renewal registers it again |
| refuses a service that cannot be resolved | ported | `..::refuses_a_service_that_cannot_be_resolved` |
| purges the authority own repo and keeps a tombstone | ported | `..::delete_purges_the_authority_repo_and_keeps_a_tombstone`. Blob gone = space.getBlob refuses it |
| answers SpaceDeleted on credential renewal | ported | `..::answers_space_deleted_on_credential_renewal` |
| answers SpaceDeleted to a request without a delegation token | ported | `..::answers_space_deleted_without_a_delegation_token` |
| notifies registered syncers | ported | `..::delete_notifies_registered_syncers` |
| leaves a member repo untouched | ported | `..::delete_leaves_a_member_repo_untouched` |
| allows re-creating a deleted space, with a fresh policy | ported | `..::allows_re_creating_a_deleted_space_with_a_fresh_policy` |

### space-scope.test.ts

A unit test of `assertSpaceRead`, ported over XRPC with real grants.

| case | status | vlpds |
|---|---|---|
| reads the caller's own repo with only read_self | ported | `ref_space_scope::reads_own_repo_with_only_read_self` (C1) |
| refuses another repo with only read_self | ported | `..::refuses_another_repo_with_only_read_self` (C1) |
| refuses another repo even with whole-space read | ported | `..::refuses_another_repo_even_with_whole_space_read` (C1) |
| refuses another repo on a legacy access token | ported + divergent | `..::refuses_every_repo_to_a_legacy_access_token` (C1): the account's own repo is refused too, OAuth-only |
| read_self is not narrowed by collection | ported | `..::read_self_is_not_narrowed_by_collection` (C1) |
| a space credential reads any repo in its own space | ported | `..::a_space_credential_reads_any_repo_in_its_own_space` (C3) |

### client-attestation.test.ts

A unit test of the verifier against an injected fetch. vlpds verifies inside getSpaceCredential, so each case mints a
credential for an allow-listed `MockClientApp` served over loopback HTTP.

| case | status | vlpds |
|---|---|---|
| accepts an attestation signed by a key in the client jwks | ported | `ref_client_attestation::accepts_an_attestation_signed_by_a_key_in_the_client_jwks` (C3) |
| accepts an attestation when the client publishes a jwks_uri | ported | `..::accepts_an_attestation_when_the_client_publishes_a_jwks_uri` (C3) |
| refuses a replayed attestation, but not a second fresh one | ported | `..::refuses_a_replayed_attestation_but_not_a_fresh_one` (C3) |
| refuses an attestation with no jti to consume | ported | `..::refuses_an_attestation_with_no_jti` (C3) |
| refuses an attestation signed by a key the client does not publish | ported | `..::refuses_an_attestation_signed_by_an_unpublished_key` (C3) |
| refuses an attestation addressed to another space host | ported | `..::refuses_an_attestation_addressed_to_another_space_host` (C3) |
| refuses an expired attestation | ported | `..::refuses_an_expired_attestation` (C3) |
| (vlpds) 300 s single-use token cap | divergent | `..::refuses_an_attestation_living_past_300_seconds` (C3) |
| refuses an attestation whose iss and sub disagree | ported | `..::refuses_an_attestation_whose_iss_and_sub_disagree` (C3) |
| refuses when the client publishes no keys | ported | `..::refuses_when_the_client_publishes_no_keys` (C3) |
| refuses when the client metadata cannot be resolved | ported | `..::refuses_when_the_client_metadata_cannot_be_resolved` (C3) |
| refuses when the jwks_uri cannot be resolved | ported | `..::refuses_when_the_jwks_uri_cannot_be_resolved` (C3) |

### space/sync.test.ts

The oplog cases have the authority write and read with its own credential (a co-located member in the reference).

| case | status | vlpds |
|---|---|---|
| pages through a single rev without dropping ops | ported | `ref_space_sync::pages_through_a_single_rev_without_dropping_ops` (C1) |
| withholds the commit until the oplog is drained to head | ported | `..::withholds_the_commit_until_drained_to_head` (C1) |
| pages with since and cursor together | ported | `..::pages_with_since_and_cursor_together` (C1) |
| inlines only a record current value | ported | `..::inlines_only_a_record_current_value` (C1) |
| omits values entirely with excludeValues | ported | `..::omits_values_with_exclude_values` (C1) |
| rejects a malformed cursor | ported | `..::rejects_a_malformed_cursor` (C1) |
| replays the oplog to the repo commit | ported | `..::replays_the_oplog_to_the_repo_commit` (C1, the commit's MAC verified as it's served) |
| detects divergence when an op is missed | ported | `..::detects_divergence_when_an_op_is_missed` (C1) |
| (todo) prunes the oplog on its own, past a retention window | divergent | `it.todo` upstream. vlpds prunes past 7 days (C4, oplog retention) |
| recovers from a pruned oplog via listRecords | ported + divergent | `..::recovers_full_state_via_list_records` (C3): the recovery half. Nothing over XRPC prunes early, so the forced-prune mismatch isn't ported (oplog retention) |
| serves a verifiable STAR archive for full-state recovery | ported | `..::get_repo_serves_a_verifiable_star_archive` (the MAC, then `verifyRepoStarFull`'s archive checks) |
| refuses a repo without a credential for that space | ported | `..::get_repo_refuses_a_credential_for_another_space` (C3) |
| reports RepoNotFound for an unwritten repo | ported | `..::reports_repo_not_found_for_an_unwritten_repo` (C3) |
| MACs: publishes a KEM key for each account | ported | `..::publishes_a_kem_key_for_each_account` (the held key, the DID document's `#atproto_kem` and getRecommendedDidCredentials agree) |
| MACs: macs a record served to a syncer | ported | `..::macs_a_record_served_to_a_syncer` |
| MACs: omits the MAC from an oplog page without a commit | ported | `..::omits_the_mac_from_an_oplog_page_without_a_commit`, and that page still needs the request header |
| MACs: requires a MAC request with a space credential | ported | `..::requires_a_mac_request_with_a_space_credential` |
| MACs: macs an account its own data only when asked | ported | `..::macs_an_account_its_own_data_only_when_asked` (Vary, Access-Control-Expose-Headers) |
| records a co-located writer without resolving its public PDS endpoint | ported | `..::records_a_co_located_writer_without_resolving_it` (C3). The PLC directory is down during the write instead of a mocked resolver |
| records a writer from notifyWrite, and it is not the member list | ported | `..::records_a_writer_from_notify_write` (C3) |
| records a writer admitted by public write policy, who was never a member | ported | `..::records_a_public_policy_writer_who_was_never_a_member` (C3) |
| records a writer into an allowList space, whose PDS presents no attestation | ported | `..::records_a_writer_into_an_allow_list_space` (C3) |
| migrates existing writer state | N/A | a SQLite migration. vlpds is unshipped and has no migrations |
| recovers missed notifications with a space checkpoint | ported | `..::recovers_missed_notifications_with_a_space_checkpoint` (C3) |
| resumes after an empty page using the last processed repo revision | ported | `..::resumes_after_an_empty_page` (C3) |
| accepts arbitrary string listRepos cursors | ported | `..::accepts_arbitrary_string_list_repos_cursors` (C3) |
| chains forwarded notifications across local and remote writers | ported | `..::chains_forwarded_notifications` (C4). vlpds also sends them in spaceRev order per registration |
| resolves a space host through the authority's #atproto_pds entry | ported | `..::notify_resolves_the_space_host_through_atproto_pds`, observed at the hosts instead of calling the resolver: the notify's audience is `#atproto_pds`, and an authority naming only `#atproto_space_host` hears nothing. The syncer-entry half is the resolver's unit, with no wire effect |
| retries the latest state after delivery failure and worker restart | ported | `..::retries_the_latest_state_after_failure_and_restart` (C1): the outbox row is resent at the newest rev after a restart |
| ignores duplicate and older revisions without forwarding them | ported (partly divergent) | `..::notify_write_ignores_duplicate_and_older_revisions` (C3). Divergent: a duplicate is the same repoRev with the same hash. The same repoRev with another hash is sequenced and forwarded again, since a record takedown or its reversal changes the hash a vlpds repo serves at the same rev (`spaces_side::takedowns`). The reference ignores any repoRev at or below the last |
| keeps the newest repo revision when notifications race | ported | `..::notify_write_keeps_the_newest_revision_when_racing` (C3) |
| rejects future revisions while allowing a small clock skew | ported | `..::notify_write_rejects_future_revisions` (C3) |
| rejects one that spoofs the writer | ported | `..::notify_write_rejects_a_spoofed_writer` (C3) |
| rejects one addressed to another authority | ported | `..::notify_write_rejects_one_addressed_to_another_authority` (C3) |
| rejects one from a non-member | ported | `..::notify_write_rejects_a_non_member` (C3) |
| rejects a member without write access | ported | `..::notify_write_rejects_a_member_without_write_access` (C3) |
| rejects a repoRev that is not a TID before any auth check | ported | `..::notify_write_rejects_a_rev_that_is_not_a_tid` (C3) |
| writer set: drops a writer on removeWriter, and tracks it again once it writes | ported | `..::remove_writer_drops_it_until_it_writes_again` |
| writer set: refuses removeWriter from anyone but the authority | ported | `..::remove_writer_is_the_authoritys_alone` |
| writer set: keeps a cleared repo in the writer set, at the empty digest | ported | `..::a_cleared_repo_stays_a_writer_at_the_empty_digest` |

### space/notifications.test.ts

The reference tests its `SpaceNotifications` retry worker and `space_notification_retry` table. vlpds's equivalent is the `sP`
outbox, so these are outbox cases against a remote space host in `ref_space_sync` (the durable outbox divergence above).

| case | status | vlpds |
|---|---|---|
| sends immediately without queueing a successful notification | ported | `ref_space_sync::outbox_sends_immediately` (C1) |
| clears an older queued notification when a new write succeeds immediately | ported | `..::outbox_a_newer_write_sends_at_once_after_a_refusal` (C1) |
| persists an HTTP 408/425/429/500/502/503/504/522/524 response for retry (9) | ported | `..::outbox_keeps_retryable_refusals_and_drops_permanent_ones` (C1): resent after a restart |
| uses the HTTP status even when the XRPC error name suggests a rejection | ported | same (503 Forbidden is retried) |
| stops retrying HTTP 400/401/403/404/422/501 with an unfamiliar XRPC error name (6) | ported | same (not resent) |
| retries local HTTP 429/503 failures (2) | N/A | mocks the actor store's reads. A local authority write is a worker op on the same node |
| Forbidden/SpaceNotFound: does not queue a rejected notification (2) | ported | `..::outbox_keeps_retryable_refusals_and_drops_permanent_ones` |
| Forbidden/SpaceNotFound: clears queued work when notify/retry is rejected (4) | ported | `..::outbox_clears_queued_work_when_a_send_is_refused`. The retry pause is shortened with `Outbox::set_retry_base` |
| Forbidden/SpaceNotFound: stops on local authority rejections too (2) | ported | `..::outbox_stops_on_local_authority_rejections` (C3) |
| persists failures before the HTTP request | ported | `..::outbox_persists_a_send_that_never_reached_the_host` (C1): the row is in the write's entry, so a restart sends it |
| surfaces an error if the failed delivery cannot be queued | N/A | the row is part of the write. If its log PUT fails the write fails (`spaces_side::durability`) |
| starts a fresh retry flow for a newer revision and ignores older or equal revisions | ported | `..::outbox_a_newer_write_sends_at_once_after_a_refusal` (the in-memory attempt counts aren't observable) |
| keeps newer queued work when an older delivery finishes with 200/403/400 (3) | ported | `..::outbox_keeps_newer_work_when_an_older_send_finishes` (C1) |
| backs off failed retries, caps the delay, and only reads due work | N/A | minutes-to-hours timing. The outbox's own unit tests |
| preserves a fresh retry flow when an older retry finishes with 200/503/403/400 (4) | ported | `..::outbox_keeps_a_fresh_flow_when_an_older_retry_finishes`. The retry pause is shortened with `Outbox::set_retry_base` and the retry stalled at the mock host |
| stops at the deadline and allows a later write to start a new retry window | N/A | the 24 h deadline. The outbox's own unit tests |
| elects one retry worker and allows takeover after its lease expires | ported + divergent | no lease worker: the shard owner sends, and a takeover rescans `sP` (`spaces_side::durability`, and the restart cases above) |
| defers retries for inactive accounts and resumes after activation | ported | `..::outbox_defers_inactive_accounts_and_resumes_on_activation` (C2) |
| **space deleted** | | |
| sends immediately without queueing a successful notification | ported | `spaces_side::space_deleted::deliveries_and_retries` |
| retries a transient failure until delivered | ported | same, the retry run through `space::deleted::retry_due` with a clock past the backoff |
| does not retry a permanent failure | ported | same |
| stops retrying once the registration expires | ported | `..::retries_end_with_the_registration_or_a_new_space` |
| drops retries once the authority account is gone | covered | account deletion sweeps every space family, `sD` included (`xrpc::space::delete_account_rows`) |
| defers retries while the authority is inactive | GAP | the code defers (`space::deleted::retry_one`); no test |
| drops retries once the space is recreated | ported | `..::retries_end_with_the_registration_or_a_new_space` |
| keeps a newer deletion retry when an older delivery finishes | GAP | a retry clears its row only if it's still the one it read (`clear_if_same`); no test races two deletions |

### space/migration.test.ts

| case | status | vlpds |
|---|---|---|
| moves the spaces an account is the authority of, and its repos | ported | `spaces_side::ref_space_migration::the_space_meta_archive_round_trips` (one host), `spaces_side::import_repo` (the repo), and the harness's migrate e2e (reference to vlpds, both hosts) |
| requires the space before the authority's own repo in it | ported | `spaces_side::import_repo` (SpaceNotFound before the space) |
| replaces what the new host holds when imported again | ported | `..::the_space_meta_archive_round_trips` (a second import over a changed list), `spaces_side::import_repo` (replace and retry) |
| keeps the percent-encoded port of a did:web member's DID | ported | `xrpc::space_meta::tests::did_web_ports_round_trip` |
| rejects a repo with a record that is not canonical DRISL | ported | `spaces_side::import_repo`, `xrpc::space_import::tests::records_must_be_canonical` |
| imports only the account's own spaces and repos | ported | `..::rejects_an_archive` (NotSpaceOwner), `spaces_side::import_repo` (the commit must name the account) |
| rejects an archive: with a policy the host does not implement | ported | `..::rejects_an_archive` |
| rejects an archive: with policy state the policy does not define | ported | same |
| rejects an archive: with a member list for a policy that keeps none | ported | same |
| rejects an archive: that does not parse | ported | same |

### space/kem-key-backfill.test.ts

Ported in `kem_keys` (a new account publishes its key and keeps it through rotation and handle updates; a migration carries
the new host's key; the backfill publishes or stores and logs, retries while PLC is down, runs once, and looks again after a
restart without Spaces; rewrap moves KEM keys). The backfill's per-shard completion record and node-local passes stand in for
the reference's lease (ported + divergent).
