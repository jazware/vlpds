//! Pluggable owner authentication (src/xrpc/owner_auth): Sign-In with
//! Ethereum end to end — a real secp256k1 signature over the exact EIP-4361
//! challenge — plus provider-backed signup (no local password), credential
//! linking and unlinking with a fresh proof, and the refusals that matter:
//! replay, another key's signature, a tampered challenge, an unknown wallet,
//! removing the last way in, and a provider login trying to skip the
//! account's own second factor.
//!
//! The signature is produced here with an independent secp256k1
//! implementation (`k256`) and recovered by the server's own code.

use crate::common::webauthn::*;
use crate::common::*;
use k256::ecdsa::SigningKey;
use vlpds::xrpc::owner_auth::providers::siwe;

fn hexl(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn siwe_cfg() -> vlpds::xrpc::owner_auth::Config {
    vlpds::xrpc::owner_auth::Config {
        siwe: Some(vlpds::xrpc::owner_auth::SiweConfig { chain_id: 1, domain: None, uri: None }),
        ..Default::default()
    }
}

/// A deterministic wallet, so a failure is reproducible.
fn wallet(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).expect("a valid secp256k1 scalar")
}

fn address(sk: &SigningKey) -> String {
    let point = sk.verifying_key().to_sec1_point(false);
    let hash = siwe::keccak256(&point.as_bytes()[1..]);
    format!("0x{}", hexl(&hash[12..]))
}

/// EIP-191 `personal_sign` over `message`, as a wallet would produce.
fn sign(sk: &SigningKey, message: &str) -> String {
    let digest = siwe::personal_sign_digest(message);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest);
    let mut out = sig.to_bytes().to_vec();
    out.push(recid.to_byte());
    format!("0x{}", hexl(&out))
}

/// A browser: keeps the device cookie the server sets, as a real client does.
struct Browser {
    http: reqwest::Client,
    base: String,
    cookie: Option<String>,
}

impl Browser {
    fn new(base: &str) -> Browser {
        Browser { http: reqwest::Client::new(), base: base.to_string(), cookie: None }
    }

    fn absorb(&mut self, r: &reqwest::Response) {
        for v in r.headers().get_all(reqwest::header::SET_COOKIE) {
            if let Ok(s) = v.to_str() {
                if let Some(c) = s.split(';').next() {
                    if c.starts_with("vlpds-device=") {
                        self.cookie = Some(c.to_string());
                    }
                }
            }
        }
    }

    async fn post(&mut self, path: &str, body: J) -> (reqwest::StatusCode, J) {
        self.post_maybe_bearer(path, body, None).await
    }

    async fn post_maybe_bearer(&mut self, path: &str, body: J, bearer: Option<&str>) -> (reqwest::StatusCode, J) {
        let mut rb = self.http.post(format!("{}{}", self.base, path)).json(&body);
        if let Some(c) = &self.cookie {
            rb = rb.header("cookie", c.as_str());
        }
        if let Some(t) = bearer {
            rb = rb.bearer_auth(t);
        }
        let r = rb.send().await.expect("request");
        self.absorb(&r);
        let status = r.status();
        let v = r.json().await.unwrap_or(J::Null);
        (status, v)
    }
}

/// Start a SIWE step and return (txn, message).
async fn start_siwe(b: &mut Browser, intent: &str, addr: &str) -> (String, String) {
    let (st, v) = b.post("/auth/start", json!({"provider": "siwe", "intent": intent, "address": addr})).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["challenge"]["kind"], "siwe", "{v}");
    (v["txnId"].as_str().unwrap().to_string(), v["challenge"]["message"].as_str().unwrap().to_string())
}

/// Sign a challenge and answer it. Returns the response.
async fn answer(b: &mut Browser, txn: &str, msg: &str, sk: &SigningKey) -> (reqwest::StatusCode, J) {
    let signature = sign(sk, msg);
    b.post("/auth/continue", json!({"txn": txn, "step": "siwe", "message": msg, "signature": signature})).await
}

/// Create an account from a wallet, returning (did, session token).
async fn signup_with(b: &mut Browser, sk: &SigningKey, name: &str) -> (String, String) {
    let addr = address(sk);
    let (txn, msg) = start_siwe(b, "sign_up", &addr).await;
    let (st, v) = answer(b, &txn, &msg, sk).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "signup", "an unknown wallet must be asked to create an account: {v}");
    let (st, v) = b
        .post(
            "/auth/continue",
            json!({"txn": txn, "step": "signup", "handle": name, "email": format!("{name}@example.com")}),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "done", "{v}");
    let did = v["did"].as_str().unwrap().to_string();
    let (st, v) = b.post("/auth/complete", json!({})).await;
    assert_eq!(st, 200, "{v}");
    (did, v["accessJwt"].as_str().unwrap().to_string())
}

/// Link a wallet to an already-signed-in account, confirming the change.
async fn link_wallet(b: &mut Browser, sk: &SigningKey, access: &str, password: Option<&str>) -> J {
    let addr = address(sk);
    let mut body = json!({"provider": "siwe", "address": addr});
    if let Some(p) = password {
        body["password"] = json!(p);
    }
    let (st, v) = b.post_maybe_bearer("/auth/link", body, Some(access)).await;
    assert_eq!(st, 200, "{v}");
    let txn = v["txnId"].as_str().unwrap().to_string();
    let msg = v["challenge"]["message"].as_str().unwrap().to_string();
    let (st, v) = answer(b, &txn, &msg, sk).await;
    assert_eq!(st, 200, "{v}");
    v
}

/// Prove the wallet again for one operation, returning the grant.
async fn confirm_with_wallet(
    b: &mut Browser,
    sk: &SigningKey,
    action: &str,
    target: Option<&str>,
    access: &str,
) -> String {
    let (st, v) = b
        .post_maybe_bearer(
            "/auth/reauth",
            json!({"provider": "siwe", "action": action, "target": target, "address": address(sk)}),
            Some(access),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let txn = v["txnId"].as_str().unwrap().to_string();
    let msg = v["challenge"]["message"].as_str().unwrap().to_string();
    let signature = sign(sk, &msg);
    let (st, v) = b
        .post_maybe_bearer(
            "/auth/continue",
            json!({"txn": txn, "step": "reauth", "message": msg, "signature": signature}),
            Some(access),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "confirmed", "{v}");
    v["grant"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_provider_only_account_can_add_mfa_and_delete_itself() {
    let s = TestServer::spawn_with(|c| c.owner_auth = siwe_cfg()).await;
    let sk = wallet(51);
    let mut b = Browser::new(&s.url);
    // Signed up with a wallet: no local password exists anywhere.
    let (did, token) = signup_with(&mut b, &sk, "walletonly").await;
    let email = "walletonly@example.com";

    // The password gate cannot be passed at all.
    let refused = s
        .xrpc
        .post("vlpds.server.startPasskeyRegistration", &json!({"password": ""}), &Auth::Bearer(token.clone()))
        .await;
    refused.err(401, "AuthenticationRequired");

    // A fresh proof of the wallet it does have can add a passkey.
    let grant = confirm_with_wallet(&mut b, &sk, "add_passkey", None, &token).await;
    let opts = s
        .xrpc
        .post("vlpds.server.startPasskeyRegistration", &json!({"grant": grant}), &Auth::Bearer(token.clone()))
        .await
        .ok();
    let mut key = SoftKey::new(&s.url);
    let cred = key.register(&opts, &Lie::default());
    let done = s
        .xrpc
        .post(
            "vlpds.server.finishPasskeyRegistration",
            &json!({"name": "Wallet laptop", "credential": cred}),
            &Auth::Bearer(token.clone()),
        )
        .await
        .ok();
    assert_eq!(done["name"], "Wallet laptop", "{done}");

    // The first strong factor brings the shared recovery codes with it.
    let list = s.xrpc.get("vlpds.server.listPasskeys", &[], &Auth::Bearer(token.clone())).await.ok();
    assert_eq!(list["passkeys"].as_array().map(|a| a.len()), Some(1), "{list}");
    assert!(list["recoveryCodesRemaining"].as_u64().unwrap_or(0) > 0, "{list}");

    // And it can delete itself: the mailed deletion code plus a fresh proof,
    // with no password anywhere in the flow.
    s.xrpc.post("com.atproto.server.requestAccountDelete", &json!({}), &Auth::Bearer(token.clone())).await.ok();
    let code = s.mail_token(email).await.expect("the mailed deletion code");
    let grant = confirm_with_wallet(&mut b, &sk, "delete_account", None, &token).await;
    s.xrpc
        .post("vlpds.auth.deleteAccount", &json!({"did": did, "token": code, "grant": grant}), &Auth::None)
        .await
        .ok();

    // The session is dead, and the wallet is free to start over.
    s.xrpc.get("com.atproto.server.getSession", &[], &Auth::Bearer(token)).await.err(400, "ExpiredToken");
    let addr = address(&sk);
    let (txn, msg) = start_siwe(&mut b, "sign_in", &addr).await;
    let (st, v) = answer(&mut b, &txn, &msg, &sk).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "signup", "a deleted account's wallet is unlinked again: {v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn siwe_signup_signin_replay_and_impersonation() {
    let s = TestServer::spawn_with(|c| c.owner_auth = siwe_cfg()).await;
    let sk = wallet(7);
    let addr = address(&sk);
    let mut b = Browser::new(&s.url);

    // An unlinked wallet: sign up, with no local password.
    let (did, token) = signup_with(&mut b, &sk, "wallet").await;

    // No local password was invented: the public password login cannot work.
    s.xrpc
        .post(
            "com.atproto.server.createSession",
            &json!({"identifier": "wallet.vlpds.test", "password": ""}),
            &Auth::None,
        )
        .await
        .err_status(401);

    // The credential is listed for the owner.
    let list = s.xrpc.get("vlpds.auth.listCredentials", &[], &Auth::Bearer(token)).await.ok();
    assert_eq!(list["hasPassword"], false, "{list}");
    let creds = list["credentials"].as_array().cloned().unwrap_or_default();
    assert_eq!(creds.len(), 1, "{list}");
    assert_eq!(creds[0]["provider"], "siwe");

    // Signing in again with the same wallet resolves to the same account.
    let (txn2, msg2) = start_siwe(&mut b, "sign_in", &addr).await;
    let (st, v) = answer(&mut b, &txn2, &msg2, &sk).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "done", "{v}");
    assert_eq!(v["did"], did);

    // The same transaction cannot be used twice.
    let (st, _) = answer(&mut b, &txn2, &msg2, &sk).await;
    assert_eq!(st, 400, "a consumed transaction must be refused");

    // A different key's signature cannot authenticate as the wallet.
    let (txn3, msg3) = start_siwe(&mut b, "sign_in", &addr).await;
    let (st, _) = answer(&mut b, &txn3, &msg3, &wallet(9)).await;
    assert_eq!(st, 400, "a signature from another key must not authenticate");

    // A tampered challenge is refused even when correctly signed.
    let (txn4, msg4) = start_siwe(&mut b, "sign_in", &addr).await;
    let tampered = msg4.replace("Chain ID: 1", "Chain ID: 8453");
    let sig4 = sign(&sk, &tampered);
    let (st, _) =
        b.post("/auth/continue", json!({"txn": txn4, "step": "siwe", "message": tampered, "signature": sig4})).await;
    assert_eq!(st, 400, "a modified message must not be accepted");

    // An unknown wallet gets no account of someone else's.
    let stranger = wallet(11);
    let saddr = address(&stranger);
    let (txn5, msg5) = start_siwe(&mut b, "sign_in", &saddr).await;
    let (st, v) = answer(&mut b, &txn5, &msg5, &stranger).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "signup", "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlink_needs_a_fresh_proof_and_releases_the_identity() {
    let s = TestServer::spawn_with(|c| c.owner_auth = siwe_cfg()).await;
    let a = s.create_account("unlinker").await;
    let sk = wallet(21);
    let addr = address(&sk);
    let mut b = Browser::new(&s.url);

    // Link the wallet, confirming with the account's password.
    let v = link_wallet(&mut b, &sk, &a.access, Some(&a.password)).await;
    assert_eq!(v["status"], "linked", "{v}");

    let list = s.xrpc.get("vlpds.auth.listCredentials", &[], &a.auth()).await.ok();
    assert_eq!(list["hasPassword"], true, "{list}");
    let cred_id = list["credentials"][0]["id"].as_str().unwrap().to_string();

    // A session token alone cannot remove a way to sign in.
    s.xrpc
        .post("vlpds.auth.unlinkCredential", &json!({"id": cred_id, "grant": "made-up"}), &a.auth())
        .await
        .err_status(400);

    // Prove the wallet again; the grant is bound to the action and object.
    let grant = confirm_with_wallet(&mut b, &sk, "unlink", Some(&cred_id), &a.access).await;
    s.xrpc
        .post("vlpds.auth.unlinkCredential", &json!({"id": "some-other-cred", "grant": grant.clone()}), &a.auth())
        .await
        .err_status(400);
    let ok = s.xrpc.post("vlpds.auth.unlinkCredential", &json!({"id": cred_id, "grant": grant}), &a.auth()).await.ok();
    assert_eq!(ok["removed"], true, "{ok}");

    // The identity is free again: the wallet is unknown, not someone's login.
    let (txn, msg) = start_siwe(&mut b, "sign_in", &addr).await;
    let (st, v) = answer(&mut b, &txn, &msg, &sk).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "signup", "an unlinked wallet must not resolve to the old account: {v}");
    assert_ne!(v.get("did").and_then(J::as_str), Some(a.did.as_str()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_last_way_in_cannot_be_removed() {
    let s = TestServer::spawn_with(|c| c.owner_auth = siwe_cfg()).await;
    let sk = wallet(41);
    let mut b = Browser::new(&s.url);
    let (did, token) = signup_with(&mut b, &sk, "onlyway").await;

    let list = s.xrpc.get("vlpds.auth.listCredentials", &[], &Auth::Bearer(token.clone())).await.ok();
    let cred_id = list["credentials"][0]["id"].as_str().unwrap().to_string();

    // The owner's own fresh proof is not enough to leave the account
    // unreachable.
    let grant = confirm_with_wallet(&mut b, &sk, "unlink", Some(&cred_id), &token).await;
    let refused = s
        .xrpc
        .post("vlpds.auth.unlinkCredential", &json!({"id": cred_id, "grant": grant}), &Auth::Bearer(token.clone()))
        .await;
    refused.err_status(400);
    let list = s.xrpc.get("vlpds.auth.listCredentials", &[], &Auth::Bearer(token)).await.ok();
    assert_eq!(list["credentials"].as_array().map(|a| a.len()), Some(1), "the credential must survive: {list}");

    // And the account still signs in.
    let addr = address(&sk);
    let (txn, msg) = start_siwe(&mut b, "sign_in", &addr).await;
    let (st, v) = answer(&mut b, &txn, &msg, &sk).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "done", "{v}");
    assert_eq!(v["did"], did);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_login_still_needs_the_accounts_second_factor() {
    // An account with a password and a passkey (a strong second factor), with
    // the wallet linked. A provider login must not skip the factor.
    let s = TestServer::spawn_with(|c| c.owner_auth = siwe_cfg()).await;
    let a = s.create_account("mfa").await;
    let sk = wallet(31);
    let addr = address(&sk);
    let mut b = Browser::new(&s.url);

    let v = link_wallet(&mut b, &sk, &a.access, Some(&a.password)).await;
    assert_eq!(v["status"], "linked", "{v}");

    // Enroll a passkey, which turns on the strong second factor.
    let opts =
        s.xrpc.post("vlpds.server.startPasskeyRegistration", &json!({"password": a.password}), &a.auth()).await.ok();
    let mut key = SoftKey::new(&s.url);
    let cred = key.register(&opts, &Lie::default());
    s.xrpc
        .post("vlpds.server.finishPasskeyRegistration", &json!({"name": "Laptop", "credential": cred}), &a.auth())
        .await
        .ok();

    // A passwordless wallet login must now stop at the factor, not sign in.
    let (txn, msg) = start_siwe(&mut b, "sign_in", &addr).await;
    let (st, v) = answer(&mut b, &txn, &msg, &sk).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "factor", "a provider login must not skip the account's second factor: {v}");

    // Nothing signed in yet: no session can be redeemed.
    let (st, _) = b.post("/auth/complete", json!({})).await;
    assert_ne!(st, 200, "no session may exist before the factor is passed");
}
