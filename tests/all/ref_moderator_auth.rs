//! Port of the reference PDS's moderator-auth.test.ts: with
//! `--mod-service-did`, the moderation service (Ozone) calls the moderator
//! admin methods with a service JWT (aud = the PDS's DID, lxm = the method)
//! signed by the `#atproto` key of its DID document. Extended with the
//! reference's permission split (admin-token-only methods refuse it), the
//! `#atproto_labeler` issuer, getPreferences for any account, and the
//! unconfigured case.

use crate::common::*;
use vlpds::plc::mock::MockPlc;
use vlsync_atproto::crypto::Keypair;

/// Registers a did:plc with `key` as its `#atproto` and `#atproto_label` key.
async fn register(plc: &MockPlc, handle: &str, key: &Keypair) -> String {
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [key.did_key()],
        "verificationMethods": {"atproto": key.did_key(), "atproto_label": key.did_key()},
        "alsoKnownAs": [format!("at://{handle}")],
        "services": {},
        "prev": null,
    });
    let op = vlpds::plc::sign(op, key).unwrap();
    let did = vlpds::plc::did_for_genesis(&op).unwrap();
    let r = reqwest::Client::new().post(format!("{}/{did}", plc.url)).json(&op).send().await.unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    did
}

fn jwt(key: &Keypair, iss: &str, aud: &str, lxm: &str) -> Auth {
    Auth::Bearer(vlpds::auth::service_auth_jwt(key, iss, aud, Some(lxm), 60).unwrap())
}

struct Ctx {
    s: TestServer,
    _plc: MockPlc,
    key: Keypair,
    mod_did: String,
    alt_did: String,
    pds_did: String,
    alice: TestAccount,
    bob: TestAccount,
}

async fn setup(configured: bool) -> Ctx {
    let plc = MockPlc::start().await;
    let key = Keypair::generate();
    let mod_did = register(&plc, "mod.test", &key).await;
    let alt_did = register(&plc, "alt-mod.test", &key).await;
    let (url, m) = (plc.url.clone(), mod_did.clone());
    let s = TestServer::spawn_with(move |c| {
        c.plc_url = url;
        c.mod_service_did = configured.then_some(m);
    })
    .await;
    let pds_did = s.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok()["did"]
        .as_str()
        .unwrap()
        .to_string();
    let alice = s.create_account("alice").await;
    let bob = s.create_account("bob").await;
    Ctx { s, _plc: plc, key, mod_did, alt_did, pds_did, alice, bob }
}

const UPDATE: &str = "com.atproto.admin.updateSubjectStatus";
const GET: &str = "com.atproto.admin.getSubjectStatus";

impl Ctx {
    fn takedown(&self) -> J {
        json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": self.bob.did},
            "takedown": {"applied": true, "ref": "test-repo"},
        })
    }

    async fn update_as(&self, auth: &Auth) -> Resp {
        self.s.xrpc.post(UPDATE, &self.takedown(), auth).await
    }
}

fn expect_401(r: &Resp, name: &str, msg: &str) {
    r.err(401, name);
    assert!(r.text().contains(msg), "{}", r.text());
}

/// "allows service auth requests from the configured appview did"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_allows_the_configured_mod_service() {
    let c = setup(true).await;
    c.update_as(&jwt(&c.key, &c.mod_did, &c.pds_did, UPDATE)).await.ok();
    let r = c.s.xrpc.get(GET, &[("did", &c.bob.did)], &jwt(&c.key, &c.mod_did, &c.pds_did, GET)).await;
    let v = r.ok();
    assert_eq!(v["subject"]["did"], json!(c.bob.did));
    assert_eq!(v["takedown"]["applied"], json!(true));

    // the other moderator methods too
    let info = "com.atproto.admin.getAccountInfo";
    let r = c.s.xrpc.get(info, &[("did", &c.alice.did)], &jwt(&c.key, &c.mod_did, &c.pds_did, info)).await;
    assert_eq!(r.ok()["did"], json!(c.alice.did));
    let codes = "com.atproto.admin.getInviteCodes";
    c.s.xrpc.get(codes, &[], &jwt(&c.key, &c.mod_did, &c.pds_did, codes)).await.ok();
    let dis = "com.atproto.admin.disableAccountInvites";
    c.s.xrpc.post(dis, &json!({"account": c.alice.did}), &jwt(&c.key, &c.mod_did, &c.pds_did, dis)).await.ok();
    let mail = "com.atproto.admin.sendEmail";
    let body = json!({"recipientDid": c.alice.did, "content": "hello", "senderDid": c.mod_did});
    assert_eq!(c.s.xrpc.post(mail, &body, &jwt(&c.key, &c.mod_did, &c.pds_did, mail)).await.ok()["sent"], json!(true));

    // a labeler-service issuer (`#atproto_labeler`, the `#atproto_label` key)
    let iss = format!("{}#atproto_labeler", c.mod_did);
    c.s.xrpc.get(GET, &[("did", &c.bob.did)], &jwt(&c.key, &iss, &c.pds_did, GET)).await.ok();

    // admin Basic auth still works
    c.s.xrpc.get(GET, &[("did", &c.bob.did)], &Auth::Admin).await.ok();
}

/// "does not allow requests from another did"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_refuses_another_did() {
    let c = setup(true).await;
    let r = c.update_as(&jwt(&c.key, &c.alt_did, &c.pds_did, UPDATE)).await;
    expect_401(&r, "UntrustedIss", "Untrusted issuer");
    // nor a user's own service token
    let r = c.update_as(&jwt(&Keypair::generate(), &c.alice.did, &c.pds_did, UPDATE)).await;
    expect_401(&r, "UntrustedIss", "Untrusted issuer");
    // nothing applied
    let st = c.s.xrpc.get(GET, &[("did", &c.bob.did)], &Auth::Admin).await.ok();
    assert_ne!(st["takedown"]["applied"], json!(true), "{st}");
}

/// "does not allow requests with a bad signature"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_refuses_a_bad_signature() {
    let c = setup(true).await;
    let r = c.update_as(&jwt(&Keypair::generate(), &c.mod_did, &c.pds_did, UPDATE)).await;
    expect_401(&r, "BadJwtSignature", "jwt signature does not match jwt issuer");
}

/// "does not allow requests with a bad aud"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_refuses_a_bad_aud() {
    let c = setup(true).await;
    // the subject is bob; alice is the audience
    let r = c.update_as(&jwt(&c.key, &c.mod_did, &c.alice.did, UPDATE)).await;
    expect_401(&r, "BadJwtAudience", "jwt audience does not match service did");
}

/// A token for another method (lxm), and the admin-token-only methods
/// (reference `authVerifier.adminToken`), refuse the moderation service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mod_service_is_limited_to_moderator_methods() {
    let c = setup(true).await;
    let r = c.update_as(&jwt(&c.key, &c.mod_did, &c.pds_did, GET)).await;
    r.err(401, "BadJwtLexiconMethod");
    for (nsid, body) in [
        ("com.atproto.admin.deleteAccount", json!({"did": c.bob.did})),
        ("com.atproto.admin.updateAccountPassword", json!({"did": c.bob.did, "password": "x-new-password"})),
        ("com.atproto.admin.updateAccountEmail", json!({"account": c.bob.did, "email": "x@example.com"})),
        ("com.atproto.server.createInviteCode", json!({"useCount": 1})),
    ] {
        let r = c.s.xrpc.post(nsid, &body, &jwt(&c.key, &c.mod_did, &c.pds_did, nsid)).await;
        // not user auth either: vlpds's InvalidToken (400), the reference's 401
        assert!(matches!(r.status, 400 | 401), "{nsid}: {}", r.text());
    }
    // bob still exists and can sign in
    c.s.create_session(&c.bob.handle, &c.bob.password).await.ok();
}

/// Without `--mod-service-did` every service JWT on a moderator method is
/// "Untrusted issuer" (reference: `dids.modService` unset), and a user
/// session token is refused too (a Bearer token there is never user auth).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unconfigured_mod_service_is_untrusted() {
    let c = setup(false).await;
    let r = c.update_as(&jwt(&c.key, &c.mod_did, &c.pds_did, UPDATE)).await;
    expect_401(&r, "UntrustedIss", "Untrusted issuer");
    let r = c.update_as(&c.alice.auth()).await;
    assert_eq!(r.status, 401, "{}", r.text());
    c.update_as(&Auth::Admin).await.ok();
}

/// app.bsky.actor.getPreferences (reference `authorizationOrModService`):
/// the moderation service reads any account's preferences with `?did=`,
/// personalDetailsPref included; users still read their own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mod_service_reads_preferences() {
    let c = setup(true).await;
    let prefs = json!({"preferences": [
        {"$type": "app.bsky.actor.defs#adultContentPref", "enabled": true},
        {"$type": "app.bsky.actor.defs#personalDetailsPref", "birthDate": "1990-01-01T00:00:00.000Z"},
    ]});
    c.s.xrpc.post("app.bsky.actor.putPreferences", &prefs, &c.alice.auth()).await.ok();
    let nsid = "app.bsky.actor.getPreferences";
    let auth = jwt(&c.key, &c.mod_did, &c.pds_did, nsid);
    let got = c.s.xrpc.get(nsid, &[("did", &c.alice.did)], &auth).await.ok();
    let types: Vec<&str> = got["preferences"].as_array().unwrap().iter().filter_map(|p| p["$type"].as_str()).collect();
    assert!(types.contains(&"app.bsky.actor.defs#adultContentPref"), "{got}");
    assert!(types.contains(&"app.bsky.actor.defs#personalDetailsPref"), "{got}");
    // the did parameter is required
    c.s.xrpc.get(nsid, &[], &auth).await.err(400, "InvalidRequest");
    // another issuer is not the moderation service: user auth, which fails
    let other = jwt(&c.key, &c.alt_did, &c.pds_did, nsid);
    let r = c.s.xrpc.get(nsid, &[("did", &c.alice.did)], &other).await;
    assert!(matches!(r.status, 400 | 401), "{}", r.text());
    // users are unaffected
    let mine = c.s.xrpc.get(nsid, &[], &c.alice.auth()).await.ok();
    assert_eq!(mine["preferences"].as_array().unwrap().len(), got["preferences"].as_array().unwrap().len());
}
