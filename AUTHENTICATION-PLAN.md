# Pluggable owner authentication for vlpds

## Goal and delivery contract

Implement Google, Apple, and Sign-In with Ethereum (SIWE) as owner authentication mechanisms behind shared backend and frontend interfaces. Password and passkey authentication must use the same coordinator. Support first-party account sign-in, AT Protocol OAuth sign-in, provider-backed signup, credential linking/unlinking, and reauthentication for sensitive account operations.

This is an implementation handoff, not a description of completed functionality. Work in this vlpds checkout. `../tranquil-pds` is read-only protocol prior art; do not modify it. Streamplace clients continue using AT Protocol OAuth and encounter these methods on the PDS's hosted authorization page. Native Streamplace UI changes are not part of this handoff.

Complete the behavior, not an interface-only scaffold. Preserve public AT Protocol contracts and existing MFA/revocation guarantees. Migrate every first-party caller and affected test; do not leave the old and new owner-auth implementations as separate policy paths.

### Proposed product defaults

- Compile providers and browser adapters into the application; enable/configure them at startup. No dynamic libraries, arbitrary remote JavaScript, or user-supplied OIDC issuers.
- New external methods are off unless configured. Password/passkey availability retains existing account policy and RP-host restrictions.
- External identity is a login credential for a normal AT Protocol DID. Wallet keys do not become repo-signing or PLC-rotation keys.
- Provider-backed signup does not require a local password. Keep a real contact email required: Google/Apple can supply an eligible email claim; SIWE signup explicitly collects and verifies an address. An email-free account/recovery system is not part of this plan.
- Existing identity: sign in to its account. Unknown identity: offer explicit signup or sign in to an existing account to link it. Never silently merge accounts by matching email, username, or wallet display name.
- Support multiple credentials, including multiple wallet addresses, on one account. One configured external identity belongs to at most one DID.
- SIWE scope is EOA wallets using EIP-191 `personal_sign`, matching the inspected prior art. Smart-contract signature verification (EIP-1271), undeployed smart wallets, and WalletConnect/mobile wallet transport are not included in this proposed scope. State that limitation in UI/docs; never advertise generic smart-wallet support. The provider/UI boundaries must allow later additions without changing account policy. Revisit this scope before implementation if the product requires those wallets at launch.
- Google/Apple/SIWE do not automatically satisfy local MFA. Preserve UV-passkey passwordless behavior, strong-factor precedence over email, recovery-code consumption, and trusted-browser rules.
- Losing a credential is handled by another enrolled credential, existing recovery/email policy, or the existing operator workflow. Do not add a wallet-rooted DID or a new recovery bypass.

## Prior art: inspect, do not blindly port

Paths below are relative to `../tranquil-pds`:

| Area | Files / symbols | What to learn |
| --- | --- | --- |
| Provider interface and Google | `crates/tranquil-pds/src/sso/providers.rs`: `SsoProvider`, `SsoManager`, `OidcProvider` | Authorization-code flow, PKCE, nonce, issuer/audience validation and JWKS handling |
| Apple | Same file: `AppleProvider`, `generate_client_secret`, `validate_id_token`; `crates/tranquil-pds/src/sso/config.rs` | ES256 client-secret JWT, Apple token validation and configuration |
| HTTP lifecycle | `crates/tranquil-oauth-server/src/sso_endpoints.rs` | GET/POST callbacks, login/link/register actions, pending signup |
| Identity/state model | `crates/tranquil-db-traits/src/sso.rs`; `crates/tranquil-db/src/postgres/sso.rs` | Stable provider subjects, uniqueness, atomic single-use auth state |
| SIWE | `crates/tranquil-pds/src/siwe/message.rs`, `verify.rs`, `mod.rs`; `crates/tranquil-oauth-server/src/siwe_endpoints.rs` | Server-generated exact message, origin/chain/time validation, signer recovery |
| SIWE state | `crates/tranquil-db-traits/src/siwe.rs`; `crates/tranquil-db/src/postgres/siwe.rs`; `migrations/20260401_siwe_login.sql` | Purpose/account/OAuth binding, atomic consume-and-read |
| Browser UX | `frontend/src/routes/OAuthLogin.svelte`, `RegisterSso.svelte`, `SsoRegisterComplete.svelte`; `frontend/src/components/dashboard/SecurityContent.svelte`; `frontend/src/lib/api.ts` | Redirect buttons, pending signup, injected-wallet login/link interaction |
| Test examples | `crates/tranquil-pds/tests/it/sso.rs`, `siwe.rs`, `apple_sso_unit.rs` | Behavioral test cases; use independently created fixtures |

### Licensing boundary

vlpds declares MIT. tranquil-pds's root `LICENSE` says its code is AGPLv3-or-later unless otherwise specified. Do not copy implementation, UI, or test source into vlpds without a documented compatible permission/licensing decision. Use public protocol specifications and appropriately licensed dependencies for the new implementation, with prior art as a behavioral reference. Reading prior art is not evidence that copying or a purported clean-room implementation has legal approval; request a provenance review if reuse is desired.

### Verified prior-art gaps to avoid

- `OidcProvider::get_user_info` falls through to userinfo after ID-token validation fails (`providers.rs:723-755`). For Google and Apple here, a missing/invalid required ID token, issuer, audience, signature, or nonce is terminal. Do not use userinfo to rescue a failed proof.
- `handle_siwe_login` proceeds to OAuth consent without the local MFA check (`siwe_endpoints.rs:291-366`). All providers here go through the same policy coordinator.
- SIWE `Register` and dedicated `Recover` are rejected by the inspected endpoints. Implement vlpds's provider-backed signup; do not mistake this prior art for a complete signup/recovery system.
- Apple first-authorization `user` data is discarded in the prior-art callback; refresh tokens and provider token revocation are not implemented there. Address first-login profile persistence, relay-email delivery, and Apple authorization revocation deliberately.
- Link/unlink prior art does not provide the fresh-owner authorization and dependent-session revocation required here.
- The SIWE unit test named `recovers_known_signer` contains an illustrative signature and does not prove successful recovery. Generate genuine signatures independently and include a positive interoperability case.
- The prior-art wallet UI uses only `window.ethereum`: no multi-provider discovery or account/chain-change handling. Implement those browser boundaries explicitly rather than copying the interaction unchanged.
- The SIWE cleanup repository method exists, but the inspected scheduler does not invoke it. In vlpds, wire expiry cleanup into the running GC; a repository method alone is not a complete lifecycle.

Public specifications: [Google token verification](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token), [Apple web authorization](https://developer.apple.com/documentation/signinwithapple/configuring-your-webpage-for-sign-in-with-apple), [SIWE / EIP-4361](https://eips.ethereum.org/EIPS/eip-4361), [EIP-191](https://eips.ethereum.org/EIPS/eip-191).

## Existing vlpds integration map

Read relevant sections before editing. Use language-server references for exported symbols when available.

| Boundary | Existing files |
| --- | --- |
| App/config/route mounting | `src/main.rs`, `src/server.rs`, `src/xrpc/mod.rs`, `src/lib.rs` |
| OAuth owner login, consent, code/refresh flow | `src/xrpc/oauth.rs`, `src/oauth/store.rs`, `src/oauth/gc.rs` |
| Password/account creation, sessions, epoch/revocation, email/deletion/TOTP | `src/xrpc/server.rs` |
| Passkey verifier, enrollment, credential liveness | `src/xrpc/passkeys.rs`, `src/webauthn.rs` |
| Factors, recovery, trust, sign-in history | `src/xrpc/mfa.rs`, `src/xrpc/email2fa.rs`, `src/xrpc/signin.rs`, `src/totp.rs` |
| Conditional owner-routed writes | `src/xrpc/cas.rs`, `src/xrpc/internal.rs`, `src/forward.rs` |
| Account persistence and deletion retries | `src/state.rs`, `src/xrpc/server.rs`, `src/xrpc/scheduled_deletion.rs` |
| Sessions/credential display, private-row fixtures | `src/xrpc/console.rs`, `src/xrpc/private_rows.rs` |
| React first-party auth/session transport | `ui/src/pages/account/AccountApp.tsx`, `SignUp.tsx`, `ui/src/lib/xrpc.ts` |
| React security/lifecycle | `ui/src/pages/account/Security.tsx`, `Passkeys.tsx`, `SignIns.tsx`, `Danger.tsx`, `Identity.tsx` |
| Server-rendered authorization UI/CSP | `src/oauth/ui.rs`, `src/xrpc/webui.rs` |
| Tests and browser harness | `tests/all/common/`, `tests/all/oauth.rs`, `passkeys.rs`, `totp.rs`, `sign_in_security.rs`, `ha_auth.rs`, `oauth_replay_durable.rs`, `delete_account_retry.rs`; `bench/passkeys/`, `bench/migrate/lib/oauth.mjs` |

Important constraints:

- `Account.password_hash` exists today; an empty value is already representable, but public signup explicitly requires password and email. Internal external-signup authorization must not relax anonymous `com.atproto.server.createAccount` into a bypass.
- Device accounts, pending codes, OAuth sessions and legacy refresh rows carry passkey-specific `auth_cred`. Several displays equate any such reference with a passkey. Generalize validation and display together.
- `private_cas` is atomic only within one routing key. Subject-index and DID-row changes are not one distributed transaction.
- The current account SPA stores ordinary first-party sessions in sessionStorage; OAuth pages have a separate browser-device context. Do not accidentally transfer a session between those contexts through a query-string token.
- A pre-existing local release binary returned `501 MethodNotImplemented` for a source-present passkey route during baseline investigation. Build current source for acceptance; do not use an arbitrary old binary as proof of this checkout.

## Shared contracts to freeze first

### Provider boundary

Create a small `src/auth/` module with coordinator, provider registry, transaction/credential persistence and provider implementations. Suggested files: `mod.rs`, `provider.rs`, `flow.rs`, `store.rs`, `policy.rs`, `providers/{password,passkey,google,apple,siwe}.rs`. Keep provider-specific parsing/signature/token verification outside the coordinator; keep account creation, linking, MFA and token issuance outside providers.

`AuthProvider` supplies:

1. Static descriptor: provider ID, display/presentation ID, supported intents.
2. `begin`: create a public challenge plus private verification state.
3. `verify`: consume a typed/bounded provider proof and return verified identity/evidence.

Use native Rust async traits with compile-time or enum dispatch; avoid per-request boxed-future allocation when static dispatch suffices. A registry selected at startup is enough; no generalized plugin ABI.

`VerifiedIdentity` contains a namespaced stable subject, optional existing credential reference, verification time, actual assurance evidence (e.g. WebAuthn UV), and optional profile/contact claims with provenance. It is not a client-writable structure and does not contain tokens or a policy instruction such as `skip_mfa`.

Google/Apple keys are configured-provider namespace + validated issuer + `sub`. SIWE EOA keys use a fixed Ethereum-EOA namespace + normalized address; configured chain ID is a signed challenge constraint, not an arbitrary client-selectable identity namespace. Passkeys/passwords retain existing DID/credential bindings. No ENS or profile lookup is needed for authentication.

### Coordinator boundary

Intents: `sign_in`, `sign_up`, `link`, `reauthenticate`. Account-management routes select exact reauth actions server-side; the caller cannot mint an arbitrary privileged intent by naming an action string.

Server states: awaiting primary proof -> verified identity -> resolve account or collect signup -> required local factors -> ready -> completed/cancelled/expired. Store completed outcome only as needed for safe, browser-bound continuation; no provider owns its own parallel MFA/session state machine.

Continuations are typed and server-owned: AT Protocol authorization request, account-page completion, credential-link action, or sensitive-operation grant. Return locations are relative allowlisted paths or already validated OAuth request metadata, never raw callback-supplied URLs.

### Frontend boundary

Create a shared flow client and a local adapter registry under `ui/src/lib/auth/`. Adapters expose support/cancellation and browser ceremony helpers, with React presentation components for interactive input where needed. Presentation kinds: credentials, redirect, WebAuthn, SIWE, code. Google/Apple share redirect mechanics but retain branded local button assets/text.

Use the same wire contract from React and server-rendered authorization pages. Preserve password/code no-JavaScript forms; use same-origin self-hosted ceremony code for passkeys/wallets. Do not replace the entire OAuth UI with the SPA or weaken CSP globally. Factor selection, signup collection and final success come from the server, not provider UI components.

Suggested transport:

- `GET /auth/methods`: configured methods/capabilities; no identifier-based account enumeration.
- `POST /auth/start`: create a browser-bound intent/continuation transaction.
- `POST /auth/continue`: bounded proof/factor/signup submission.
- `GET|POST /auth/callback/:provider`: provider transport normalization only.
- `GET /auth/transaction/:id`: browser-bound resumption/status.
- `POST /auth/complete`: single-use, same-origin account-session redemption.
- First-party credential-management XRPCs: `vlpds.auth.listCredentials`, `unlinkCredential`, and a passwordless-capable deletion procedure backed by the existing deletion routine. Linking uses the shared transaction intent rather than a second provider-specific API.

Before coding, define exact JSON types/errors, CSRF/browser binding, TTL and completion semantics. Unknown providers/presentation kinds fail explicitly. Provider callbacks redirect only with an opaque transaction locator; never put PDS/provider bearer tokens in URLs.

## Ordered implementation work

### Phase 0 — baseline and licensing/config decisions

1. Read the integration map and prior-art caveats. Record provider registration prerequisites and scope defaults above.
2. Build current UI/server and smoke existing password, passkey, MFA, OAuth consent, revocation and `.stream.place` signup/resolution.
3. Freeze the shared Rust/TypeScript contract and persistence migration approach before provider/UI work fans out.
4. Follow existing secret `-file`/environment configuration and console redaction conventions. Add only Google, Apple and SIWE configuration needed for this feature; validate enabled providers at startup, including canonical public URL and missing keys/credentials.

Acceptance: known current-source baseline; no hidden protocol/license assumptions; API/types agreed; existing routes remain operational.

### Phase 1 — durable transactions, credentials and coordinator

1. Implement owner-routed transaction rows with random locators, browser binding, selected provider, intent, continuation, target DID/action, expiry, provider state and proof-consumption state. Sensitive provider state is private, bounded and KEK-wrapped where required.
2. Implement CAS single-use claims for callback state, SIWE nonces, reauth grants and completion. A local mutex/in-memory replay cache is insufficient. Survive restart, owner handoff, callback on another node, and concurrent submissions.
3. Implement DID-local credential records (opaque local ID, provider/subject, version, display label, active/revoked state) and the global external-subject claim/index.
4. Specify and implement staged linking: reserve subject -> conditional DID credential write -> activate index. Login requires matching active index and active DID record. An interrupted stage never authenticates. Resume/cleanup orphan reservations safely; age alone cannot steal a claim with a live credential. Unlink revokes the DID record before releasing the external claim.
5. Carry all persistent credentials used by a completed authentication in its device/code/session provenance. Use the account epoch and credential versions at commit, so unlink/revoke races cannot resurrect authentication. Do not treat a consumed recovery code as a still-live persistent credential.
6. Integrate expiry GC with existing owner/conditional-delete patterns. Extend account deletion and retry tombstones so external claims and provider authorization artifacts are removed even after the main account row disappears.
7. Decide schema migration and feature gating through the existing cluster upgrade mechanism (`src/cluster.rs`, `docs/operations/upgrades.md`; levels live in the pinned vlsync dependency). Any semantics old nodes must honor are gated. Coordinate a vlsync feature-level/dependency change if necessary; do not invent a second upgrade mechanism. Migrate old passkey provenance explicitly and preserve existing sessions or explicitly document a required sign-out. New external flows must not activate on incompatible owners.

Acceptance: one external identity cannot bind two DIDs under concurrency; incomplete links fail closed; replay stays rejected after failover; deletion/expiry are retry-safe; old account and session data have a tested upgrade path.

### Phase 2 — cut over password/passkey policy and sensitive operations

1. Adapt existing password and passkey verifiers into the shared service, preserving rate limits, Argon2 shedding, RP/origin binding, UV requirements, factor lockouts, trusted browsers, sign-in history, alerts and inactive/takendown behavior.
2. Keep TOTP/email/recovery as factor verification under the coordinator. New providers cannot skip these checks. Passwordless UV passkeys retain their established assurance policy; app passwords remain delegated credentials, not owner-auth plugins.
3. Route account-page and OAuth-page owner authentication through this service. Keep PAR, PKCE, DPoP, consent and OAuth session issuance in their existing authorization-server layer.
4. Replace first-party `check_password` authorization with short-lived action-bound fresh-owner grants for adding/removing credentials, regenerating recovery codes, disabling MFA, setting/changing a local password, and deleting an account. Bind grant to DID, browser/session, exact operation/target, epoch/credential versions and expiry; consume once with the mutation where possible.
5. Reauth means a new bound proof ceremony for the same account, not reuse of an old PDS access token. Use upstream authentication-time/reauth controls when supported; distinguish locally completed verification time from upstream user-presence claims. Do not infer MFA or user presence merely from a new ID token's `iat`.
6. Preserve public AT Protocol password-oriented contracts. Standard createSession/createAccount/deleteAccount inputs remain valid. First-party passwordless deletion uses a vlpds procedure and the same retry-safe deletion implementation, retaining the existing deletion-code requirement. Migrate vlpds extension APIs/UI/tests together rather than retaining obsolete first-party aliases.
7. Granted deletion remains retryable after its credential/account rows are gone; retain a bounded authorization/tombstone sufficient for the already approved deletion, rather than requiring the now-deleted provider credential again.

Acceptance: password/passkey regression behavior remains intact; a provider-only account can manage its security and delete itself without inventing a password; a stolen ordinary session alone cannot add a new login credential; last usable primary credential removal is refused. Recovery codes alone do not count as a replacement primary sign-in method.

### Phase 3 — Google and Apple

1. Implement Google authorization-code flow with S256 PKCE, server-generated state/nonce, trusted fixed endpoints/issuer, validated ID token and bounded cached JWKS. Restrict algorithms; validate issuer/audience/expiry/nonce and authorized-party semantics where applicable. Refresh JWKS on appropriate key rotation with bounded network behavior. Invalid proof is terminal, not a userinfo fallback.
2. Implement Apple independently where it differs: Service ID/client ID, Team ID, Key ID, mounted signing key, ES256 client-secret JWT, Apple issuer/JWKS/ID-token verification, authorization code exchange and GET/POST callback support as required by the chosen flow. Do not assume Apple supports Google's PKCE behavior; apply its documented protocol.
3. Persist allowed first-authorization `user` profile data after identity verification. It is optional on subsequent login and is not independently trusted proof of identity/email ownership. Handle cancellation and malformed POST bodies cleanly.
4. Apple `form_post` must work when normal SameSite cookies are absent: consume server-side state, stage the verified result, then resume through a same-origin landing request that checks original browser binding. State alone does not authorize attaching a credential or issuing a session to another browser.
5. Configure and document outbound mail for Apple relay addresses. Do not mark an arbitrary matched email authoritative. For conservative recovery semantics, confirm the contact email through vlpds before using it for recovery unless a provider claim is explicitly established as authoritative by policy.
6. Retain and encrypt only provider token material actually needed for Apple authorization revocation/lifecycle. Integrate the provider-documented disconnect/account-deletion revocation behavior with deletion/link-removal cleanup; do not retain Google access/refresh tokens merely for login. Separate local credential revocation from external-network success so a provider outage cannot leave a locally removed credential usable.
7. For unknown subjects, use shared pending signup. Require explicit handle/invite and contact-email completion; avoid generating a hidden password. For an email already claimed by another account, require owner-authenticated linking instead of automatic merge. Completed signup resumes the original OAuth request or first-party login.

Acceptance: first and repeat Google/Apple login/signup/link work; Apple POST returns to the initiating browser; invalid token/state/nonce cannot authenticate; existing local MFA still applies; Apple relay contact and cleanup behavior are documented and exercised where test credentials are available.

### Phase 4 — SIWE EOA provider

1. Build a strict EIP-4361 message with canonical public origin (including non-default port), URI, configured chain ID, cryptographic alphanumeric nonce, issued-at/expiry, and human-readable intent. Never derive origin from an untrusted Host header.
2. Persist the exact message plus browser/transaction/purpose/DID/continuation binding before returning it. Verify exact-message equality, grammar, all expected fields and expiry before authentication; consume once with durable CAS.
3. Verify EIP-191 digest with Ethereum Keccak-256, not SHA-256 or SHA3-256, and recover/compare the signer using a maintained appropriately licensed library or the existing secp256k1 dependency's suitable recovery support. Hash prefix and bytes without avoidable message copies; normalize accepted signature recovery IDs and reject malformed/unexpected encodings.
4. Normalize addresses for identity lookup; display checksum addresses. Changing selected wallet, signature, chain, nonce, message, purpose or transaction cannot authenticate a different identity or authorize another action.
5. Connect the result to the shared coordinator for login/signup/link/reauth and local MFA. Unlinked wallets can complete explicit `.stream.place` signup with real contact email; no `not implemented` registration path.
6. Implement injected EIP-1193 wallet interaction, provider selection where multiple injected wallets exist, explicit account access and `personal_sign`, account/chain-change handling, and cancellation. Do not fabricate a wallet when none is installed. Provide actionable unsupported-wallet messages and preserve other login methods.

Acceptance: real independently generated EOA signatures succeed; wrong signer/origin/URI/chain/time/message fail; one challenge cannot be reused across nodes or purposes; wallet login cannot bypass local MFA; linked and new-wallet signup work without local passwords. Contract-wallet and mobile-transport exclusions are explicit, not fake fallbacks.

### Phase 5 — frontend surfaces and account lifecycle

1. Implement shared frontend protocol types, flow controller, local ceremony adapters and reusable React components. Provider modules never set sessions or decide MFA completion themselves.
2. Replace the React account page's separate password/passkey state logic with this contract while retaining conditional WebAuthn autofill, Enter-key behavior, cancellation and error semantics. Abort conditional WebAuthn when another method is selected.
3. Add configured method selection to React signup/sign-in and server-rendered OAuth login/signup. Preserve OAuth `prompt=login/create`, account selection, consent and redirect semantics. SSR form posts and SPA JSON normalize into the same coordinator.
4. Add `Ways to sign in` to Security: list credentials, link through a shared fresh-owner flow, unlink safely, and show provider/address/passkey labels. Keep app passwords and connected OAuth apps visibly distinct from owner credentials.
5. Replace password-only confirmation widgets in Passkeys, recovery-code/MFA controls, password setup and Danger with the shared reauth component. Provider-only accounts can add a local password or passkey; ordinary legacy login still requires a local password or app password.
6. Preserve the current account session transport through safe same-origin completion. No PDS or provider token in URLs, localStorage, browser history, logs or frontend provider metadata. Use browser-bound single-use redemption; clear transient URL/state after completion.
7. Keep opaque transactions resumable across provider redirects/reloads within expiry. Surface cancelled/expired/disabled-provider flows without selecting a fallback credential automatically. Show no disabled provider button.
8. Update first-party migration interactions only where they call changed local extension APIs; do not assume remote/source PDSes implement the new contract.

Acceptance: actual account and OAuth browser surfaces support all enabled methods; keyboard/passkey flows do not regress; linked credential lifecycle and passwordless sensitive actions work; no CSP violations or leaked tokens; provider configuration controls available UI.

## Verification and completion gates

Use existing harness conventions. New permanent tests must assert consumer-visible behavior/security boundaries, not copied defaults, source strings, registry wiring or mock echoes.

### Required integration coverage

Add focused modules such as `tests/all/auth_methods.rs`, `auth_providers.rs`, `auth_credentials.rs`, and `auth_methods_ha.rs` to `tests/all/main.rs`. Reuse `common::TestServer`, software WebAuthn, cluster helpers and CAS pause hooks. Locally hosted OIDC test servers must actually sign ID tokens, exchange one-use codes and rotate keys; do not return pre-approved evidence in place of provider verification.

Cover:

- Password/passkey success/failure and factor precedence across old public protocol and new first-party paths.
- Google/Apple signed-token success; wrong issuer/audience/nonce/signature, expiry, unknown/rotated key, absent token, cancellation, mismatched callback provider, Apple first/repeat profile and POST browser binding.
- SIWE real-signature success, wrong signer, origin/URI/chain/expiry/message, replay, cross-intent and cross-browser substitution.
- Google/Apple/SIWE with local TOTP/passkey/email/recovery policy; no provider-specific bypass; trusted browser remains correctly bound.
- Existing-account linking versus unknown-identity signup; duplicate email never merges; concurrent subject claims have exactly one winner; lost signup response does not create a second account or steal a live claim.
- Reauth wrong account/browser/action/target, expiry and replay; ordinary access token alone insufficient; concurrent last-credential removals cannot lock out the account.
- Credential removal versus pending browser login, OAuth code exchange, first-party session issuance and refresh. Revoked credentials never produce usable sessions; unrelated credentials/sessions survive selective removal under existing policy.
- Cross-node callback/nonce/grant consumption, owner handoff/restart, cleanup, account deletion retries, scheduled deletion and explicit old-row/cluster-version upgrade behavior.

### Browser smoke proof

Extend the existing `bench/passkeys` approach or add a focused `bench/auth-methods` harness following its conventions. Use an actual current-source vlpds, real authorization pages, a locally hosted signed-token OIDC fixture, CDP software authenticator and a deterministic EIP-1193 wallet signer. Exercise account login/signup, OAuth consent/code exchange, credentials UI, reauth, unlink, expiry/cancel/reload and logout. Include Apple cross-site POST with production-like HTTPS/site boundaries; localhost form submission alone is insufficient. Inspect screenshots and fail on page errors/CSP violations. Browser fixtures are test devices/providers, not production fallback implementations.

Also exercise real Google and Apple provider accounts using supplied registrations/HTTPS callbacks when credentials are available. If unavailable, report that exact production-integration limit while completing the deterministic local protocol/browser proof; do not claim live-provider verification.

### Commands and existing suites

Run checks after integrated edits, not repeatedly mid-flight in sibling agents:

```sh
cargo fmt --check
cargo test
cargo test --features test-level --test level_gating
cargo clippy --all-targets -- -D warnings
npm --prefix ui run build
npm --prefix ui run check-docs
cargo build --profile dev-release --bin vlpds
```

Run the existing `bench/passkeys/run.sh` against that freshly built binary using `VLPDS_BIN` (its default path is `target/dev-release/vlpds`, or respect `CARGO_TARGET_DIR`), then the new authentication browser smoke harness. Targeted modules may be run once during final verification to diagnose a failure; permanent success requires the affected/full suite, not only a narrowed passing filter. Record exact exercised scenarios/results. Source inspection is not runtime proof.

### Documentation and deployment

After smoke proof, update `docs/oauth-2fa.md`, `docs/operations/configuration.md`, `docs/operations/upgrades.md`, relevant email/key-security/operator docs and `DESIGN.md` concurrency/schema notes. Follow `docs/_style.md`. Document provider console setup/callback URLs, secrets/rotation, Apple relay delivery/revocation, optional local passwords, MFA/reauth/recovery, SIWE wallet scope and the `.stream.place` DNS/TLS setup (`--handle-domain stream.place`, wildcard DNS/certificate preserving Host). Update console provenance displays and existing deployment secret/config plumbing that exposes the new settings; no unrelated dashboard/telemetry project.

Provide upgrade/finalize/rollback steps, configuration parity across nodes, and incompatibility behavior. Remove throwaway scripts and obsolete first-party auth paths after verified cutover; keep intentional public AT Protocol endpoints as real contracts. Deliver no TODO verifiers, mocked production providers, hidden generated passwords, silent degraded validation or misleading placeholders.

## Suggested execution ownership

One integration owner owns coordinator/store/types, migration, route mounting, policy cutover and final checks. Once contracts are frozen, independent slices may run concurrently: Google/Apple verification; SIWE verification; frontend adapters/surfaces. Give each slice the full shared contract, explicit file ownership and acceptance cases. Provider slices do not edit coordinator/session policy; frontend does not invent different backend transitions. Keep tests for provider boundaries with their owning slices and cluster/lifecycle integration with the integration owner. No sibling builds/lint/formatters until integrated verification.

## Definition of done

All configured methods complete owner login, AT Protocol OAuth login, explicit signup, link/unlink and fresh-owner security operations through the shared contracts. `.stream.place` accounts resolve correctly. Existing public clients/password/passkey/MFA behavior remains covered. Authentication/revocation is durable and owner-routed, survives failover, and has no weaker provider-specific policy path. UI is verified on both surfaces; docs and upgrade path match exercised behavior. State explicitly which live-provider/HTTPS checks were and were not exercised.
