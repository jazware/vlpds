//! Ported from the reference's `tests/space/auth.test.ts` (1f510f8e): who
//! may read what, and on whose authority. Each test names its reference
//! case.
//!
//! Adaptations:
//! - Space data is OAuth-only: a password session gets no space access at
//!   all, where the reference lets it write and read the account's own
//!   repo. App passwords are refused by both ("Bad token scope").
//! - Tokens the reference forges with an account's own key (which vlpds
//!   never hands out) are signed by a [`MockService`] DID standing in for
//!   that party: a member forging a credential, a user misaddressing a
//!   delegation token.
//! - The OAuth scope suite gets real grants (`regrant`) where the reference
//!   stubs the verifier.
//! - Revocation storage internals (row counts, the hour of retention, a
//!   failing cleanup) aren't observable over XRPC: the refusals are.

use super::ref_net::*;
use crate::common::spaces::{Holder, SpaceClient};
use crate::common::*;
use vlpds::space::token::{space_host_aud, Mint, TokenType};

const NOTIFY_REVOKED: &str = "com.atproto.space.notifyCredentialsRevoked";

async fn own_reads(dan: &SpaceClient, space: &str, repo: &str) -> Vec<Resp> {
    let base = [("space", space), ("repo", repo)];
    let rec = [("space", space), ("repo", repo), ("collection", TEST_COLLECTION), ("rkey", "private")];
    vec![
        dan.get("com.atproto.space.getRecord", &rec).await,
        dan.get("com.atproto.space.listRecords", &base).await,
        dan.get("com.atproto.space.listRepoOps", &base).await,
        dan.get("com.atproto.space.getLatestCommit", &base).await,
        dan.get("com.atproto.space.getRepo", &base).await,
    ]
}

/// account tokens: "read only the account's own repo": even a member
/// reading another account's repo with an account token gets what an absent
/// repo gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_co_located_non_member_reading_a_member_repo() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    write(&alice, &space, W::new().rkey("private").text("members only")).await.ok();
    for r in own_reads(&dan, &space, &alice.did).await {
        r.err(400, "RepoNotFound");
    }
    let own = alice.get("com.atproto.space.listRecords", &[("space", &space), ("repo", &alice.did)]).await.ok();
    assert_eq!(own["records"].as_array().unwrap().len(), 1);
}

/// account tokens: "are refused for an app password, even a privileged
/// one": every space and policy method answers an app password (privileged
/// or not) 400 InvalidToken "Bad token scope". Divergent: a password
/// session is refused too (403, OAuth-only), where the reference takes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_space_access_to_app_passwords_and_password_sessions() {
    let net = Net::new(0).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 0).await);
    let s = &net.pds[0];
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&alice, &space, W::new()).await.ok();
    let session = Auth::Bearer(alice.session_jwt.clone());
    let mut auths = vec![("password session", session.clone())];
    for privileged in [false, true] {
        let ap = s
            .xrpc
            .post(
                "com.atproto.server.createAppPassword",
                &json!({"name": format!("space-pass-{privileged}"), "privileged": privileged}),
                &session,
            )
            .await
            .ok();
        let sess = s.create_session(&alice.did, ap["password"].as_str().unwrap()).await.ok();
        auths.push(("app password", Auth::Bearer(sess["accessJwt"].as_str().unwrap().into())));
    }
    let q = [("space", space.as_str())];
    for (what, auth) in &auths {
        let calls = [
            s.xrpc
                .post(
                    "com.atproto.space.createSpace",
                    &json!({"spaceType": TEST_SPACE_TYPE, "policy": {"$type": "com.atproto.memberspace.policy"}}),
                    auth,
                )
                .await,
            s.xrpc.get("com.atproto.space.getSpace", &q, auth).await,
            s.xrpc
                .post(
                    "com.atproto.memberspace.putMembers",
                    &json!({"space": space, "members": [{"did": carol.did, "read": true, "write": true}]}),
                    auth,
                )
                .await,
            s.xrpc
                .post(
                    "com.atproto.space.createRecord",
                    &json!({"space": space, "repo": alice.did, "collection": TEST_COLLECTION, "record": record(TEST_COLLECTION, "from an app password")}),
                    auth,
                )
                .await,
            s.xrpc.get("com.atproto.space.listRecords", &[("space", &space), ("repo", &alice.did)], auth).await,
            s.xrpc.get("com.atproto.space.getDelegationToken", &q, auth).await,
        ];
        for r in calls {
            match *what {
                "app password" => {
                    r.err(400, "InvalidToken");
                    assert_eq!(r.json["message"], "Bad token scope", "{what}: {}", r.text());
                }
                _ => r.err(403, "InsufficientScope"),
            }
        }
    }
}

/// space credentials: "reads another member repo across PDSes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_another_member_repo_across_pdses() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    write(&bob, &space, W::new().text("for the record")).await.ok();

    // Minted on pds1, read on pds2: neither is the reader's own PDS.
    let cred = net.credential_for(&carol, &space).await;
    let c = cred.claims();
    assert_eq!(c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap(), 600);
    let pds2 = &net.pds[1].url;
    let q = [("space", space.as_str()), ("repo", bob.did.as_str()), ("collection", TEST_COLLECTION)];
    let list = cred.get(pds2, "com.atproto.space.listRecords", &q).await.ok();
    let recs = list["records"].as_array().unwrap();
    assert_eq!(recs.len(), 1);
    let rkey = recs[0]["rkey"].as_str().unwrap();
    let q = [("space", space.as_str()), ("repo", bob.did.as_str()), ("collection", TEST_COLLECTION), ("rkey", rkey)];
    let got = cred.get(pds2, "com.atproto.space.getRecord", &q).await.ok();
    assert_eq!(got["value"]["text"], json!("for the record"));
}

/// HTTP message signature binding: "refuses a credential presented as a
/// bearer token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_credential_presented_as_a_bearer_token() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    write(&alice, &space, W::new().text("bound")).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let bearer = vec![("authorization".to_string(), format!("Bearer {}", cred.credential))];
    raw_get(&net.pds[0].url, "com.atproto.space.getLatestCommit", &q, &bearer).await.err(400, "InvalidToken");
    cred.get(&net.pds[0].url, "com.atproto.space.getLatestCommit", &q).await.ok();
}

/// HTTP message signature binding: "refuses a credential without a
/// signature"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_credential_without_a_signature() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let cred = net.credential_for(&alice, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let unsigned = vec![("authorization".to_string(), format!("Atproto-Space-Credential {}", cred.credential))];
    raw_get(&net.pds[0].url, "com.atproto.space.getLatestCommit", &q, &unsigned).await.err(401, "BadSpaceSignature");
}

/// HTTP message signature binding: "recognizes the credential scheme
/// regardless of case", the signature over the Authorization value as sent
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recognizes_the_credential_scheme_regardless_of_case() {
    let net = Net::new(0).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    write(&alice, &space, W::new()).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let h = cred.holder.headers(&format!("atproto-space-credential {}", cred.credential), &alice.did);
    raw_get(&net.pds[0].url, "com.atproto.space.listRecords", &q, &h).await.ok();
    // signed over one casing, sent with another: the base is byte-exact
    let mut h = cred.holder.headers(&format!("Atproto-Space-Credential {}", cred.credential), &alice.did);
    h[0].1 = format!("ATPROTO-SPACE-CREDENTIAL {}", cred.credential);
    raw_get(&net.pds[0].url, "com.atproto.space.listRecords", &q, &h).await.err(401, "BadSpaceSignature");
}

/// The October 1 scheme (`Atproto-Space`, label `atproto-space`) is gone:
/// 400 InvalidToken "Unsupported authorization type", not a signature
/// error (the reference's migration note, section 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_the_old_credential_scheme() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&alice, &space, W::new()).await.ok();
    let cred = net.credential_for(&alice, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let mut h = cred.headers(&alice.did);
    h[0].1 = format!("Atproto-Space {}", cred.credential);
    for (k, v) in h.iter_mut() {
        if k == "signature-input" || k == "signature" {
            *v = v.replacen("atproto-space-credential=", "atproto-space=", 1);
        }
    }
    let r = raw_get(&net.pds[0].url, "com.atproto.space.listRecords", &q, &h).await;
    r.err(400, "InvalidToken");
    assert!(r.json["message"].as_str().unwrap().contains("Unsupported authorization type"), "{}", r.text());
}

/// HTTP message signature binding: "responds $expectedStatus to repeated
/// $name fields": a repeated audience is refused, an extra signature label
/// is ignored (and a repeated authorization, which the reference no longer
/// lists, is refused too).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responds_to_repeated_signature_fields() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&alice, &space, W::new()).await.ok();
    let cred = net.credential_for(&alice, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    for (name, extra, status) in [
        ("authorization", None, 401),
        ("atproto-space-audience", None, 401),
        ("signature-input", Some("other=(\"authorization\");keyid=\"other\""), 200),
        ("signature", Some("other=:YWJj:"), 200),
    ] {
        let mut h = cred.headers(&alice.did);
        let same = h.iter().find(|(k, _)| k == name).unwrap().1.clone();
        h.push((name.to_string(), extra.map(String::from).unwrap_or(same)));
        let r = raw_get(&net.pds[0].url, "com.atproto.space.listRecords", &q, &h).await;
        assert_eq!(r.status, status, "repeated {name}: {}", r.text());
        if name == "atproto-space-audience" {
            r.err(401, "BadSpaceSignature");
        }
    }
}

/// HTTP message signature binding: "refuses a credential presented with a
/// key of the holder own"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_credential_presented_with_another_key() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    write(&alice, &space, W::new().text("not yours to read")).await.ok();
    let rebound = net.credential_for(&carol, &space).await.rebound(Holder::new());
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let r = rebound.get(&net.pds[0].url, "com.atproto.space.getLatestCommit", &q).await;
    r.err(401, "BadSpaceSignature");
}

/// HTTP message signature binding: "refuses a signature addressed to
/// another account (remote|co-located)"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_signature_addressed_to_another_repo_owner() {
    let net = Net::new(2).await;
    let (alice, bob, dan) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("dan", 0).await);
    let carol = net.actor("carol", 2).await;
    for other in [&bob, &dan] {
        let space = net.create_space(&alice, SpaceOpts { members: &[other, &carol], ..Default::default() }).await;
        write(&alice, &space, W::new()).await.ok();
        let cred = net.credential_for(&carol, &space).await;
        let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
        let r = cred.get_for(&net.pds[0].url, "com.atproto.space.getLatestCommit", &q, &other.did).await;
        r.err(401, "BadSpaceAudience");
    }
}

/// HTTP message signature binding: "requires the space authority as
/// audience for space-host requests"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requires_the_authority_as_audience_for_space_host_requests() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let cred = net.credential_for(&bob, &space).await;
    let q = [("space", space.as_str())];
    cred.get_for(&net.pds[0].url, "com.atproto.space.listWriters", &q, &bob.did).await.err(401, "BadSpaceAudience");
}

/// HTTP message signature binding: "reuses a signature for the same
/// audience across requests"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuses_a_signature_for_the_same_audience_across_requests() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    write(&alice, &space, W::new()).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    let h = cred.headers(&alice.did);
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let base = &net.pds[0].url;
    for _ in 0..2 {
        raw_get(base, "com.atproto.space.listRecords", &q, &h).await.ok();
    }
    raw_get(base, "com.atproto.space.listBlobs", &q, &h).await.ok();
    raw_get(base, "com.atproto.space.listWriters", &[("space", space.as_str())], &h).await.ok();
}

/// HTTP message signature binding: "reuses one credential across many
/// hosts, each with its own audience signature"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuses_one_credential_across_many_hosts() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    write(&alice, &space, W::new().text("on the authority")).await.ok();
    write(&bob, &space, W::new().text("on pds2")).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    for host in [&alice, &bob] {
        let q = [("space", space.as_str()), ("repo", host.did.as_str())];
        let r = cred.get(&net.host_of(&host.did), "com.atproto.space.listRecords", &q).await.ok();
        assert_eq!(r["records"].as_array().unwrap().len(), 1);
    }
}

/// space credentials: "is scoped to one space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_is_scoped_to_one_space() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let target = net
        .create_space(&alice, SpaceOpts { skey: Some("cred-target"), members: &[&carol], ..Default::default() })
        .await;
    let other = net.create_space(&alice, SpaceOpts { skey: Some("cred-other"), ..Default::default() }).await;
    write(&alice, &target, W::new().text("scoped")).await.ok();
    let cred = net.credential_for(&carol, &target).await;
    let base = &net.pds[0].url;
    let ok =
        cred.get(base, "com.atproto.space.getLatestCommit", &[("space", &target), ("repo", &alice.did)]).await.ok();
    assert!(ok["commit"].is_object());
    cred.get(base, "com.atproto.space.listRepoOps", &[("space", &other), ("repo", &alice.did)])
        .await
        .err(400, "InvalidCredential");
}

/// space credentials: "refuses one the space authority did not issue".
/// The forger is a did:web whose key the test holds (the reference uses a
/// member's account key).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_credential_the_authority_did_not_issue() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    write(&alice, &space, W::new().text("forgery target")).await.ok();
    let base = &net.pds[0].url;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    net.credential_for(&carol, &space).await.get(base, "com.atproto.space.getLatestCommit", &q).await.ok();

    let forger = MockService::spawn(&[]).await;
    let holder = Holder::new();
    let forged = forger.token(
        TokenType::Credential,
        Mint { iss: &forger.did, sub: &space, key_id: Some(&holder.did), ..Default::default() },
    );
    let forged = Cred { credential: forged, holder, http: reqwest::Client::new() };
    forged.get(base, "com.atproto.space.getLatestCommit", &q).await.err(401, "BadJwtIss");
    // listWriters authorizes off the credential too, on a separate path.
    forged.get(base, "com.atproto.space.listWriters", &[("space", &space)]).await.err(401, "BadJwtIss");
}

/// space credentials: "are refused unless signed by the issuer's key": the
/// forger claims alice as issuer but signs with its own key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_credential_not_signed_by_the_issuers_key() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    write(&alice, &space, W::new().text("forgery target")).await.ok();
    let forger = MockService::spawn(&[]).await;
    let holder = Holder::new();
    let forged = forger.token(
        TokenType::Credential,
        Mint { iss: &alice.did, sub: &space, key_id: Some(&holder.did), ..Default::default() },
    );
    let forged = Cred { credential: forged, holder, http: reqwest::Client::new() };
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    forged.get(&net.pds[0].url, "com.atproto.space.listRecords", &q).await.err(401, "BadJwtSignature");
}

/// space credentials: "refuses one for a revoked member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_credential_for_a_removed_member() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let token = delegation_token(&carol, &space).await;
    remove_member(&alice, &space, &carol).await.ok();
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

// ---------------------------------------------------------------------------
// credential revocation
// ---------------------------------------------------------------------------

/// `revoke(signer, space, credentials, {aud, lxm})`: notifyCredentialsRevoked
/// at bob's PDS with service auth from `signer`.
async fn revoke(net: &Net, signer: &SpaceClient, aud: &str, lxm: &str, space: &str, jtis: &[String]) -> Resp {
    let jwt = service_jwt(signer, aud, lxm).await;
    post_service(&net.pds[1].url, NOTIFY_REVOKED, &jwt, json!({"space": space, "credentials": jtis})).await
}

/// credential revocation: "revokes a batch idempotently on a remote repo
/// host"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revokes_a_batch_idempotently_on_a_remote_repo_host() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    write(&alice, &space, W::new()).await.ok();
    write(&bob, &space, W::new()).await.ok();
    let first = net.credential_for(&carol, &space).await;
    let second = net.credential_for(&carol, &space).await;
    let untouched = net.credential_for(&carol, &space).await;
    let jtis = vec![first.jti(), second.jti()];
    let (pds1, pds2) = (&net.pds[0].url, &net.pds[1].url);
    let at_bob = [("space", space.as_str()), ("repo", bob.did.as_str())];
    let r = first.get(pds2, "com.atproto.space.listRecords", &at_bob).await.ok();
    assert_eq!(r["records"].as_array().unwrap().len(), 1);

    revoke(&net, &alice, &bob.did, NOTIFY_REVOKED, &space, &jtis).await.ok();
    let again = vec![jtis[0].clone(), jtis[0].clone(), jtis[1].clone()];
    revoke(&net, &alice, &bob.did, NOTIFY_REVOKED, &space, &again).await.ok();

    for cred in [&first, &second] {
        cred.get(pds2, "com.atproto.space.listRecords", &at_bob).await.err(401, "CredentialRevoked");
    }
    untouched.get(pds2, "com.atproto.space.listRecords", &at_bob).await.ok();
    // Revoked at bob's host only.
    let at_alice = [("space", space.as_str()), ("repo", alice.did.as_str())];
    first.get(pds1, "com.atproto.space.listRecords", &at_alice).await.ok();
    bob.get("com.atproto.space.listRecords", &at_bob).await.ok();
}

/// credential revocation: "requires service auth from the authority
/// addressed to a local repo and method"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_requires_service_auth_from_the_authority() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new()).await.ok();
    let cred = net.credential_for(&bob, &space).await;
    let jtis = vec![cred.jti()];

    let forbidden = |r: Resp, message: &str| {
        r.err(403, "Forbidden");
        assert_eq!(r.json["message"], message, "{}", r.text());
    };
    forbidden(
        revoke(&net, &bob, &bob.did, NOTIFY_REVOKED, &space, &jtis).await,
        "Revocation issuer is not the space authority",
    );
    let wrong_aud = "Revocation audience does not match a repo hosted here";
    forbidden(revoke(&net, &alice, &alice.did, NOTIFY_REVOKED, &space, &jtis).await, wrong_aud);
    let pds2_did = net.pds[1].pds_did().await;
    forbidden(revoke(&net, &alice, &pds2_did, NOTIFY_REVOKED, &space, &jtis).await, wrong_aud);
    revoke(&net, &alice, &bob.did, "com.atproto.space.notifyRepoUpdate", &space, &jtis).await.client_err();
    let not_service_auth = Auth::Bearer(alice.session_jwt.clone());
    Xrpc::new(&net.pds[1].url)
        .post(NOTIFY_REVOKED, &json!({"space": space, "credentials": jtis}), &not_service_auth)
        .await
        .client_err();
    cred.get(&net.pds[1].url, "com.atproto.space.listRecords", &[("space", &space), ("repo", &bob.did)]).await.ok();
}

/// credential revocation: "scopes revocations to the space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scopes_revocations_to_the_space() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let other =
        net.create_space(&alice, SpaceOpts { skey: Some("other-revocation-space"), ..Default::default() }).await;
    write(&bob, &space, W::new()).await.ok();
    let cred = net.credential_for(&bob, &space).await;
    revoke(&net, &alice, &bob.did, NOTIFY_REVOKED, &other, &[cred.jti()]).await.ok();
    cred.get(&net.pds[1].url, "com.atproto.space.listRecords", &[("space", &space), ("repo", &bob.did)]).await.ok();
}

// ---------------------------------------------------------------------------
// delegation tokens
// ---------------------------------------------------------------------------

/// delegation tokens: "are useless at a host that does not govern the space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegation_tokens_are_useless_at_a_host_that_does_not_govern_the_space() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let token = delegation_token(&carol, &space).await;
    let r = exchange(&reqwest::Client::new(), &Holder::new(), &net.pds[1].url, &space, &token, None).await;
    r.err(400, "SpaceNotFound");
}

/// delegation tokens: "binds the credential to the requested key"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binds_the_credential_to_the_requested_key() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let token = delegation_token(&carol, &space).await;
    let (r, holder) = net.mint_credential(&space, &token, None).await;
    let cred = r.ok()["credential"].as_str().unwrap().to_string();
    assert_eq!(jwt_claims(&cred)["cnf"], json!({"kid": holder.did}));
}

/// delegation tokens: "refuses to bind the credential to a key that is not
/// P-256"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_to_bind_the_credential_to_a_key_that_is_not_p256() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let token = delegation_token(&carol, &space).await;
    let k256 = vlatproto::crypto::Keypair::generate().did_key();
    let body = json!({"space": space, "credentialKey": k256, "delegationToken": token});
    let r = raw_post(&net.pds[0].url, "com.atproto.space.authorizeSpaceSync", body, &[]).await;
    r.err(400, "InvalidRequest");
    assert!(r.json["message"].as_str().unwrap().contains("P-256"), "{r:?}");
}

/// delegation tokens: "are single-use — a replayed jti is refused"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegation_tokens_are_single_use() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.ok();
    let r = net.mint_credential(&space, &token, None).await.0;
    r.err(400, "InvalidDelegationToken");
    assert!(r.json["message"].as_str().unwrap().contains("already been used"), "{r:?}");
}

/// delegation tokens: "are refused when the audience names another
/// authority". The user is a did:web whose key the test holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegation_tokens_are_refused_when_the_audience_names_another_authority() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let user = MockService::spawn(&[]).await;
    let aud = space_host_aud(&bob.did);
    let misaddressed =
        user.token(TokenType::Delegation, Mint { iss: &user.did, sub: &space, aud: Some(&aud), ..Default::default() });
    let r = net.mint_credential(&space, &misaddressed, None).await.0;
    r.err(400, "InvalidDelegationToken");
    assert!(r.json["message"].as_str().unwrap().contains("audience does not match the space authority"), "{r:?}");
}

/// delegation tokens: "are refused for a space other than their subject"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegation_tokens_are_refused_for_a_space_other_than_their_subject() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { skey: Some("deleg-sub"), ..Default::default() }).await;
    let other = net.create_space(&alice, SpaceOpts { skey: Some("deleg-sub-other"), ..Default::default() }).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&other, &token, None).await.0.err(400, "InvalidDelegationToken");
}

/// Divergence: the 300 s cap on single-use tokens. getDelegationToken's
/// own tokens live within it, and a longer one is refused at the exchange
/// (the reference accepts any lifetime).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegation_tokens_live_at_most_300_seconds() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net
        .create_space(
            &alice,
            SpaceOpts { policy: Some(memberspace(json!({"publicRead": true}))), ..Default::default() },
        )
        .await;
    let c = jwt_claims(&delegation_token(&alice, &space).await);
    assert!(c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap() <= 300, "{c}");
    let user = MockService::spawn(&[]).await;
    let aud = space_host_aud(&alice.did);
    let long = user.token(
        TokenType::Delegation,
        Mint { iss: &user.did, sub: &space, aud: Some(&aud), expires_in_secs: Some(600), ..Default::default() },
    );
    net.mint_credential(&space, &long, None).await.0.client_err();
}

// ---------------------------------------------------------------------------
// takedowns
// ---------------------------------------------------------------------------

/// takedowns: "stops serving permissioned records for a taken-down account"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stops_serving_space_records_of_a_taken_down_account() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan, &carol], ..Default::default() }).await;
    write(&dan, &space, W::new().text("before takedown")).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    let q = [("space", space.as_str()), ("repo", dan.did.as_str())];
    let ops = || cred.get(&net.pds[0].url, "com.atproto.space.listRepoOps", &q);
    assert_eq!(ops().await.ok()["ops"].as_array().unwrap().len(), 1);
    set_repo_takedown(&net.pds[0], &dan.did, true).await;
    ops().await.err(400, "RepoTakendown");
    set_repo_takedown(&net.pds[0], &dan.did, false).await;
    // Gated, not deleted.
    assert_eq!(ops().await.ok()["ops"].as_array().unwrap().len(), 1);
}

/// takedowns: "stops accepting permissioned writes from a taken-down account"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stops_accepting_space_writes_from_a_taken_down_account() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    set_repo_takedown(&net.pds[0], &dan.did, true).await;
    write(&dan, &space, W::new().text("during takedown")).await.err(401, "AccountTakedown");
    dan.delegation_token(&space).await.err(401, "AccountTakedown");
    set_repo_takedown(&net.pds[0], &dan.did, false).await;
    // A takedown revokes the account's OAuth sessions, so sign in again.
    let dan = regrant(&dan, FULL_SCOPE).await;
    write(&dan, &space, W::new().text("after")).await.ok();
}

/// The reference's `STATUSES`: an account status, the error a repo in that
/// status gets and the one its account gets.
const STATUSES: [(&str, &str, &str); 2] =
    [("takendown", "RepoTakendown", "AccountTakedown"), ("deactivated", "RepoDeactivated", "AccountDeactivated")];

/// `sc.withStatus(actor, status)`, left on for the rest of the test.
async fn set_status(s: &TestServer, actor: &SpaceClient, status: &str) {
    match status {
        "takendown" => set_repo_takedown(s, &actor.did, true).await,
        _ => {
            let session = Auth::Bearer(actor.session_jwt.clone());
            s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &session).await.ok();
        }
    }
}

/// account status: "stops minting credentials and listing writers for a
/// $status authority"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stops_minting_credentials_and_listing_writers_for_an_inactive_authority() {
    let net = Net::new(0).await;
    let dan = net.actor("dan", 0).await;
    for (status, repo_error, _) in STATUSES {
        let authority = net.actor(&format!("host-{}", &status[..5]), 0).await;
        let space = net.create_space(&authority, SpaceOpts { members: &[&dan], ..Default::default() }).await;
        let cred = net.credential_for(&dan, &space).await;
        set_status(&net.pds[0], &authority, status).await;
        let token = delegation_token(&dan, &space).await;
        net.mint_credential(&space, &token, None).await.0.err(400, repo_error);
        net.public_credential(&space, None).await.0.err(400, repo_error);
        cred.get(&net.pds[0].url, "com.atproto.space.listWriters", &[("space", &space)]).await.err(400, repo_error);
    }
}

/// account status: "stops a $status authority managing its spaces"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stops_an_inactive_authority_managing_its_spaces() {
    let net = Net::new(0).await;
    let (dan, bob) = (net.actor("dan", 0).await, net.actor("bob", 0).await);
    for (status, _, account_error) in STATUSES {
        let authority = net.actor(&format!("mgr-{}", &status[..5]), 0).await;
        let space = net.create_space(&authority, SpaceOpts { members: &[&dan], ..Default::default() }).await;
        set_status(&net.pds[0], &authority, status).await;
        let calls = [
            authority
                .post(
                    "com.atproto.space.createSpace",
                    json!({"spaceType": TEST_SPACE_TYPE, "policy": memberspace(json!({}))}),
                )
                .await,
            authority
                .post("com.atproto.space.updateSpace", json!({"space": space, "policy": memberspace(json!({}))}))
                .await,
            authority.post("com.atproto.space.deleteSpace", json!({"space": space})).await,
            remove_writer(&authority, &space, &dan).await,
            put_member(&authority, &space, &bob, true, true).await,
            remove_member(&authority, &space, &dan).await,
        ];
        for r in calls {
            r.err(401, account_error);
        }
    }
}

/// account status: "lets a taken-down account export its spaces". Divergent:
/// the takendown-scope session the reference lets export gets nothing on
/// space routes here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taken_down_account_exports_nothing() {
    let net = Net::new(0).await;
    let josie = net.actor("josie", 0).await;
    let space = net.create_space(&josie, SpaceOpts::default()).await;
    let blob = upload_blob(&josie, b"\x89PNG taken down").await;
    write(&josie, &space, W::new().record(json!({"$type": TEST_COLLECTION, "text": "hi", "image": blob}))).await.ok();
    set_repo_takedown(&net.pds[0], &josie.did, true).await;
    let r = net.pds[0]
        .xrpc
        .post(
            "com.atproto.server.createSession",
            &json!({"identifier": josie.did, "password": crate::oauth::PASSWORD, "allowTakendown": true}),
            &Auth::None,
        )
        .await
        .ok();
    let auth = Auth::Bearer(r["accessJwt"].as_str().unwrap().into());
    let x = &net.pds[0].xrpc;
    let params = [("space", space.as_str()), ("repo", josie.did.as_str())];
    let calls = [
        x.get("com.atproto.space.listSpaces", &[], &auth).await,
        x.get("com.atproto.space.exportSpaceMeta", &[("space", &space)], &auth).await,
        x.get("com.atproto.space.getRepo", &params, &auth).await,
        x.get("com.atproto.space.listBlobs", &params, &auth).await,
        x.get("com.atproto.space.listRecords", &params, &auth).await,
        x.post(
            "com.atproto.space.createRecord",
            &json!({"space": space, "repo": josie.did, "collection": TEST_COLLECTION, "record": record(TEST_COLLECTION, "no")}),
            &auth,
        )
        .await,
    ];
    for r in calls {
        r.err(400, "InvalidToken");
        assert_eq!(r.json["message"], "Bad token scope", "{}", r.text());
    }
}

// ---------------------------------------------------------------------------
// OAuth scopes, end to end, with real grants. A refusal names the space:
// scope it lacks (ScopeMissingError).
// ---------------------------------------------------------------------------

fn grant(alice: &SpaceClient, params: &str) -> String {
    format!("space:{TEST_SPACE_TYPE}?authority={}&{params}", alice.did)
}

#[track_caller]
fn scope_missing(r: &Resp) {
    r.err(403, "ScopeMissingError");
    assert!(r.json["message"].as_str().unwrap_or("").contains("space:"), "{}", r.text());
}

/// OAuth scopes: "enforces the collection a grant names on a write"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_enforces_the_collection_a_grant_names() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let [allowed, forbidden] = SPACE_TYPE_COLLECTIONS;
    let app = regrant(&alice, &grant(&alice, &format!("collection={allowed}&action=create"))).await;
    write(&app, &space, W::new().collection(allowed).rkey("ok")).await.ok();
    scope_missing(&write(&app, &space, W::new().collection(forbidden).rkey("no")).await);
}

/// OAuth scopes: "enforces the action a grant names"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_enforces_the_action_a_grant_names() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let coll = SPACE_TYPE_COLLECTIONS[0];
    write(&alice, &space, W::new().collection(coll).rkey("seeded")).await.ok();
    let app = regrant(&alice, &grant(&alice, &format!("collection={coll}&action=create"))).await;
    scope_missing(&del(&app, &space, Some(coll), "seeded").await);
}

/// OAuth scopes: "resolves putRecord to update rather than demanding create
/// too"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_resolves_put_record_to_update() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let coll = SPACE_TYPE_COLLECTIONS[0];
    write(&alice, &space, W::new().collection(coll).rkey("self").text("first")).await.ok();
    let app = regrant(&alice, &grant(&alice, &format!("collection={coll}&action=update"))).await;
    put(&app, &space, W::new().collection(coll).rkey("self").text("second")).await.ok();
    scope_missing(&put(&app, &space, W::new().collection(coll).rkey("fresh")).await);
}

/// OAuth scopes: "refuses a space of a type the grant does not name"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_refuses_a_space_of_a_type_the_grant_does_not_name() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts { space_type: Some(OTHER_SPACE_TYPE), ..Default::default() }).await;
    let app = regrant(&alice, &grant(&alice, "collection=*&action=create")).await;
    scope_missing(&write(&app, &space, W::new().rkey("wrong-type")).await);
}

/// OAuth scopes: "refuses a space under an authority the grant does not name"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_refuses_a_space_under_an_authority_the_grant_does_not_name() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let dan_space = net.create_space(&dan, SpaceOpts { skey: Some("dan-governed"), ..Default::default() }).await;
    let app = regrant(&dan, &grant(&alice, "collection=*&action=create")).await;
    scope_missing(&write(&app, &dan_space, W::new().rkey("other-authority")).await);
}

/// OAuth scopes: "reads own repo on read_self, and refuses whole-space read"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_read_self_reads_own_repo_but_mints_no_delegation() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&alice, &space, W::new().rkey("mine")).await.ok();
    let app = regrant(&alice, &grant(&alice, "action=read_self")).await;
    let own = app.get("com.atproto.space.listRecords", &[("space", &space), ("repo", &alice.did)]).await.ok();
    assert_eq!(own["records"].as_array().unwrap().len(), 1);
    scope_missing(&app.delegation_token(&space).await);
}

/// OAuth scopes: "exchanges a whole-space read grant for a delegation token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_whole_space_read_mints_a_delegation_token() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let app = regrant(&alice, &grant(&alice, "action=read")).await;
    assert!(app.delegation_token(&space).await.ok()["token"].is_string());
}

/// OAuth scopes: "requires a wildcard grant to list spaces unfiltered"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_requires_a_wildcard_grant_to_list_spaces_unfiltered() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let app = regrant(&alice, &grant(&alice, "action=read_self")).await;
    scope_missing(&app.get("com.atproto.space.listSpaces", &[]).await);
    let listed =
        app.get("com.atproto.space.listSpaces", &[("spaceType", TEST_SPACE_TYPE), ("spaceDid", &alice.did)]).await.ok();
    let uris: Vec<&str> = listed["spaces"].as_array().unwrap().iter().filter_map(|s| s["space"].as_str()).collect();
    assert!(uris.contains(&space.as_str()), "{listed}");
    scope_missing(
        &app.get("com.atproto.space.listSpaces", &[("spaceType", OTHER_SPACE_TYPE), ("spaceDid", &alice.did)]).await,
    );
}

/// OAuth scopes: "materializes the space type declared collections into a
/// bare grant". The space type's lexicon is published in alice's repo
/// (`com.atproto.lexicon.schema`) under an NSID authority pinned to her.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_materializes_declared_collections_into_a_bare_grant() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let t = unique_name("");
    let space_type = format!("com.decl{t}.group");
    let colls = [format!("com.decl{t}.groupNote"), format!("com.decl{t}.groupPost")];
    let lex = json!({"lexicon": 1, "id": space_type, "defs": {"main": {"type": "space", "name": "Group", "key": "any", "collections": colls}}});
    let body = json!({"repo": alice.did, "collection": "com.atproto.lexicon.schema", "rkey": space_type, "record": lex, "validate": false});
    net.pds[0].xrpc.post("com.atproto.repo.createRecord", &body, &Auth::Bearer(alice.session_jwt.clone())).await.ok();
    vlpds::oauth::lexicon::override_authority(&vlpds::oauth::lexicon::nsid_authority(&space_type), &alice.did);

    let app = regrant(&alice, &format!("space:{space_type}")).await;
    for c in &colls {
        assert!(app.scope.contains(&format!("collection={c}")), "{}", app.scope);
    }
    assert!(app.scope.contains(&format!("authority={}", alice.did)), "{}", app.scope);
    let space = net.create_space(&alice, SpaceOpts { space_type: Some(&space_type), ..Default::default() }).await;
    for c in &colls {
        write(&app, &space, W::new().collection(c).rkey(&format!("decl-{}", last_segment(&c.replace('.', "/")))))
            .await
            .ok();
    }
    scope_missing(&write(&app, &space, W::new().collection(TEST_COLLECTION).rkey("undeclared")).await);
}

/// OAuth scopes: "requires delete on every collection a clear removes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_requires_delete_on_every_collection_a_clear_removes() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let [first, second] = SPACE_TYPE_COLLECTIONS;
    write(&alice, &space, W::new().collection(first).rkey("first")).await.ok();
    write(&alice, &space, W::new().collection(second).rkey("second")).await.ok();
    let app = regrant(&alice, &grant(&alice, &format!("collection={first}&action=delete"))).await;
    scope_missing(&clear(&app, &space).await);
    assert_eq!(all_records(&alice, &space).await.len(), 2);
    let app = regrant(&alice, &grant(&alice, &format!("collection={first}&collection={second}&action=delete"))).await;
    assert_eq!(clear(&app, &space).await.ok(), json!({}));
    assert!(all_records(&alice, &space).await.is_empty());
}

/// OAuth scopes: "enforces the manage operations a grant names"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_enforces_the_manage_operations_a_grant_names() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let update = |c: SpaceClient| {
        let space = space.clone();
        async move {
            c.post("com.atproto.space.updateSpace", json!({"space": space, "policy": memberspace(json!({}))})).await
        }
    };
    // collection=* keeps the grant from needing the space type's lexicon at approval
    scope_missing(&update(regrant(&alice, &grant(&alice, "collection=*")).await).await);
    update(regrant(&alice, &grant(&alice, "collection=*&manage=update")).await).await.ok();
}
