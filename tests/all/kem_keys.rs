//! `#atproto_kem` keys (Spaces MACs) against the mock PLC directory: the key
//! in the genesis op of a new account and in the DID document, kept by
//! signing-key rotation and rotate-keys, carried by getRecommendedDidCredentials
//! into a migration and checked by submitPlcOperation, rewrapped with the
//! other secrets, and the one-time backfill of accounts made without one
//! (published where this PDS may, stored and logged where it may not, once,
//! failures retried).

use crate::common::*;
use std::sync::Arc;
use vlatproto::crypto::Keypair;
use vlpds::plc::mock::MockPlc;

fn new_key() -> Arc<Keypair> {
    Arc::new(Keypair::generate())
}

async fn node(
    id: &str,
    store: &Arc<dyn object_store::ObjectStore>,
    plc: &MockPlc,
    rot: &Arc<Keypair>,
    spaces: bool,
) -> TestServer {
    let (url, rot) = (plc.url.clone(), rot.clone());
    cluster_node(id, store.clone(), 4, move |c| {
        use_plc(c, url, rot);
        c.spaces = spaces;
    })
    .await
}

async fn spaces_pds(plc: &MockPlc, rot: &Arc<Keypair>, service_did: &str) -> TestServer {
    let (url, rot, sd) = (plc.url.clone(), rot.clone(), service_did.to_string());
    TestServer::spawn_with(move |c| {
        use_plc(c, url, rot);
        c.service_did = sd;
        c.spaces = true;
    })
    .await
}

async fn kem_did_key(s: &TestServer, did: &str) -> Option<String> {
    s.app.account(did).await.ok().unwrap().kem_pubkey.map(|k| format!("did:key:{k}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_accounts_publish_a_kem_key() {
    let plc = MockPlc::start().await;
    let rot = new_key();
    let s = spaces_pds(&plc, &rot, "did:web:pds.test").await;
    let a = s.create_account("kem").await;
    let acct = s.app.account(&a.did).await.ok().unwrap();
    let kem = kem_did_key(&s, &a.did).await.expect("a KEM key");
    assert!(kem.starts_with("did:key:zDn"), "P-256: {kem}");
    assert_ne!(acct.kem_pubkey.as_deref(), Some(acct.signing_pubkey.as_str()));
    let key = s.app.secrets.account_kem_key(&acct).await.unwrap().expect("unwraps");
    assert_eq!(format!("did:key:{}", vlpds::secrets::kem_multibase(&key.public_key())), kem);

    let ops = plc.ops(&a.did);
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0]["verificationMethods"],
        json!({"atproto": format!("did:key:{}", acct.signing_pubkey), "atproto_kem": kem})
    );
    // the local document is the directory's
    let local =
        s.xrpc.get("com.atproto.identity.resolveDid", &[("did", &a.did)], &Auth::None).await.ok()["didDoc"].clone();
    let served = vlpds::plc::format_did_doc(&plc.data(&a.did).unwrap());
    for k in ["id", "alsoKnownAs", "verificationMethod", "service"] {
        assert_eq!(served[k], local[k], "{k}");
    }
    assert!(local["verificationMethod"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["id"] == format!("{}#atproto_kem", a.did) && m["type"] == "Multikey"));
    let rec = s.xrpc.get("com.atproto.identity.getRecommendedDidCredentials", &[], &a.auth()).await.ok();
    assert_eq!(rec["verificationMethods"]["atproto_kem"], json!(kem));

    // signing-key rotation and rotate-keys keep it
    s.xrpc.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": a.did}), &Auth::Admin).await.ok();
    let data = plc.data(&a.did).unwrap();
    assert_ne!(data["verificationMethods"]["atproto"], ops[0]["verificationMethods"]["atproto"], "rotated");
    assert_eq!(data["verificationMethods"]["atproto_kem"], json!(kem));
    s.xrpc
        .post(
            "com.atproto.identity.updateHandle",
            &json!({"handle": format!("{}.{HANDLE_DOMAIN}", unique_name("kem2"))}),
            &a.auth(),
        )
        .await
        .ok();
    assert_eq!(plc.data(&a.did).unwrap()["verificationMethods"]["atproto_kem"], json!(kem));
    // rotate-keys republishes a KEM key the directory lost
    let p = vlpds::plc::Plc::new(&plc.url, rot.clone(), None);
    let last = plc.last_op(&a.did).unwrap();
    let op = p
        .update_op(&last, |m| {
            m["verificationMethods"].as_object_mut().unwrap().remove("atproto_kem");
            Ok(())
        })
        .unwrap();
    p.client.send(&a.did, &op, "submit").await.unwrap();
    let r =
        s.xrpc.post("vlpds.admin.publishIdentity", &json!({"did": a.did, "syncPlc": true}), &Auth::Admin).await.ok();
    assert_eq!(r["plcUpdated"], json!(true), "{r}");
    assert_eq!(plc.data(&a.did).unwrap()["verificationMethods"]["atproto_kem"], json!(kem));

    // a node without Spaces makes none
    let plain = TestServer::spawn_plc(&plc.url, new_key()).await;
    let b = plain.create_account("nokem").await;
    assert!(kem_did_key(&plain, &b.did).await.is_none());
    assert!(plc.ops(&b.did)[0]["verificationMethods"].get("atproto_kem").is_none());
    let rec = plain.xrpc.get("com.atproto.identity.getRecommendedDidCredentials", &[], &b.auth()).await.ok();
    assert!(rec["verificationMethods"].get("atproto_kem").is_none(), "{rec}");
}

/// Migration in: the new PDS makes its own KEM key at createAccount, its
/// recommended credentials carry it into the PLC op, and submitPlcOperation
/// refuses an op that drops it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_carries_the_new_hosts_kem_key() {
    let plc = MockPlc::start().await;
    let old = spaces_pds(&plc, &new_key(), "did:web:old-pds.test").await;
    let new = spaces_pds(&plc, &new_key(), "did:web:new-pds.test").await;
    let alice = old.create_account("kemout").await;
    let did = alice.did.clone();
    let old_kem = kem_did_key(&old, &did).await.unwrap();
    let token = old
        .xrpc
        .get(
            "com.atproto.server.getServiceAuth",
            &[("aud", "did:web:new-pds.test"), ("lxm", "com.atproto.server.createAccount")],
            &alice.auth(),
        )
        .await
        .ok()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("kemin"));
    let email = format!("{}@example.com", unique_name("kemin"));
    let created = new
        .xrpc
        .post(
            "com.atproto.server.createAccount",
            &json!({"handle": handle, "email": email, "password": PASSWORD, "did": did}),
            &Auth::Bearer(token),
        )
        .await
        .ok();
    let auth = Auth::Bearer(created["accessJwt"].as_str().unwrap().into());
    let new_kem = kem_did_key(&new, &did).await.expect("made at createAccount");
    assert_ne!(new_kem, old_kem);
    let rec = new.xrpc.get("com.atproto.identity.getRecommendedDidCredentials", &[], &auth).await.ok();
    assert_eq!(rec["verificationMethods"]["atproto_kem"], json!(new_kem));

    let sign = |body: J| {
        let (old, alice) = (&old, &alice);
        async move {
            old.xrpc.post_empty("com.atproto.identity.requestPlcOperationSignature", &alice.auth()).await.ok();
            let mut body = body;
            body["token"] = json!(old.mail_token(&alice.email).await.unwrap());
            old.xrpc.post("com.atproto.identity.signPlcOperation", &body, &alice.auth()).await.ok()["operation"].clone()
        }
    };
    // an op with only `atproto` (a tool that drops the rest) is refused
    let mut only_signing = rec.clone();
    only_signing["verificationMethods"] = json!({"atproto": rec["verificationMethods"]["atproto"]});
    let op = sign(only_signing).await;
    let r = new.xrpc.post("com.atproto.identity.submitPlcOperation", &json!({"operation": op}), &auth).await;
    r.err(400, "InvalidRequest");
    assert!(r.text().contains("Incorrect KEM key"), "{}", r.text());
    let mut wrong = rec.clone();
    wrong["verificationMethods"]["atproto_kem"] = json!(old_kem);
    let op = sign(wrong).await;
    let r = new.xrpc.post("com.atproto.identity.submitPlcOperation", &json!({"operation": op}), &auth).await;
    assert!(r.text().contains("Incorrect KEM key"), "{}", r.text());
    let op = sign(rec.clone()).await;
    new.xrpc.post("com.atproto.identity.submitPlcOperation", &json!({"operation": op}), &auth).await.ok();
    assert_eq!(plc.data(&did).unwrap()["verificationMethods"]["atproto_kem"], json!(new_kem));
}

/// Pre-existing accounts: published where this PDS may change the DID,
/// stored and left to the owner where it may not, none while the directory
/// is down (retried), and never again once each shard is recorded done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backfill_publishes_once_and_retries_failures() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let plc = MockPlc::start().await;
    let rot = new_key();
    // accounts made by a node without Spaces have no key
    let s = node("kem", &store, &plc, &rot, false).await;
    let ours = s.create_account("bfours").await;
    let unkeyed = s.create_account("bfnokey").await;
    let moved = s.create_account("bfmoved").await;
    assert!(kem_did_key(&s, &ours.did).await.is_none());
    // one removed the server's rotation key, one moved to another PDS
    let p = vlpds::plc::Plc::new(&plc.url, rot.clone(), None);
    let other = Keypair::generate().did_key();
    for (did, edit) in [(&unkeyed.did, 0), (&moved.did, 1)] {
        let op = p
            .update_op(&plc.last_op(did).unwrap(), |m| {
                match edit {
                    0 => m.insert("rotationKeys".into(), json!([other])),
                    _ => m.insert(
                        "services".into(),
                        json!({"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://elsewhere.test"}}),
                    ),
                };
                Ok(())
            })
            .unwrap();
        p.client.send(did, &op, "submit").await.unwrap();
    }

    let mut done = Default::default();
    plc.set_down(true);
    let pass = vlpds::kem_backfill::pass(&s.app, &mut done).await;
    assert_eq!((pass.published, pass.unpublished, pass.failed), (0, 0, 3), "{pass:?}");
    assert!(done.len() < 4, "a shard with a failure isn't recorded");
    plc.set_down(false);
    for a in [&ours, &unkeyed, &moved] {
        assert!(kem_did_key(&s, &a.did).await.is_none(), "nothing stored before it's published");
    }

    let mut sub = s.subscribe_from_now().await;
    let pass = vlpds::kem_backfill::pass(&s.app, &mut done).await;
    assert_eq!((pass.published, pass.unpublished, pass.failed), (1, 2, 0), "{pass:?}");
    assert_eq!(done.len(), 4, "every owned shard recorded");
    let kem = kem_did_key(&s, &ours.did).await.unwrap();
    assert_eq!(plc.data(&ours.did).unwrap()["verificationMethods"]["atproto_kem"], json!(kem));
    for a in [&unkeyed, &moved] {
        let k = kem_did_key(&s, &a.did).await.expect("stored for the owner to publish");
        assert!(plc.data(&a.did).unwrap()["verificationMethods"].get("atproto_kem").is_none());
        let rec = s.xrpc.get("com.atproto.identity.getRecommendedDidCredentials", &[], &a.auth()).await.ok();
        assert_eq!(rec["verificationMethods"]["atproto_kem"], json!(k));
    }
    let frames = sub
        .until(FH_TIMEOUT, |fs| fs.iter().any(|f| f.kind() == "#identity" && f.did() == Some(ours.did.as_str())))
        .await;
    let mut seen = frames;
    while let Some(f) = sub.next(std::time::Duration::from_millis(300)).await {
        seen.push(f);
    }
    assert!(
        !seen.iter().any(|f| f.kind() == "#identity" && f.did() != Some(ours.did.as_str())),
        "no #identity for keys left unpublished"
    );

    // runs once: another process finds every shard recorded
    let posts = plc.posts();
    let pass = vlpds::kem_backfill::pass(&s.app, &mut Default::default()).await;
    assert_eq!(pass, Default::default());
    assert_eq!(plc.posts(), posts);
    // an account without a key on a recorded shard stays so
    s.app
        .mutate_account(&ours.did, false, false, false, |a| {
            a.kem_pubkey = None;
            a.wrapped_kem_key = None;
            Ok(true)
        })
        .await
        .map_err(|e| e.message)
        .unwrap();
    assert_eq!(vlpds::kem_backfill::pass(&s.app, &mut Default::default()).await, Default::default());

    // rewrapSecrets covers KEM keys
    let r = s
        .xrpc
        .post("vlpds.admin.rewrapSecrets", &json!({"dryRun": true, "checkVersions": true}), &Auth::Admin)
        .await
        .ok();
    assert_eq!((r["kemKeys"].clone(), r["failed"].clone()), (json!(0), json!(0)), "{r}");

    // a node without Spaces clears the records, so a later Spaces start looks again
    s.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&s.app).await;
    let s = node("kem", &store, &plc, &rot, false).await;
    let records = || async {
        use futures::StreamExt;
        let prefix = object_store::path::Path::from(format!("{}/kem-backfill", s.app.store.prefix));
        s.app.store.raw.list(Some(&prefix)).collect::<Vec<_>>().await.len()
    };
    for _ in 0..100 {
        if records().await == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(records().await, 0);
    let pass = vlpds::kem_backfill::pass(&s.app, &mut Default::default()).await;
    // (unpublished: the restarted node has another URL, so the DID names another PDS)
    assert_eq!((pass.published + pass.unpublished, pass.failed, pass.shards_done), (1, 0, 4), "{pass:?}");
    s.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&s.app).await;
}

/// rewrapSecrets moves KEM keys to a new KEK, like signing keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rewrap_moves_kem_keys_to_the_new_kek() {
    use vlpds::secrets::{KekBytes, KekConfig};
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let (k1, k2) = (KekBytes::random(), KekBytes::random());
    let kek = |k: &KekBytes, old: &[&KekBytes]| KekConfig {
        local: Some(k.clone()),
        local_old: old.iter().map(|k| (*k).clone()).collect(),
        ..Default::default()
    };
    let (c1, c2, c3) = (kek(&k1, &[]), kek(&k2, &[&k1]), kek(&k2, &[]));
    let a = cluster_node("kemrw", store.clone(), 4, move |c| {
        c.kek = c1;
        c.spaces = true;
    })
    .await;
    let t = a.create_account("kemrw").await;
    let before = a.app.secrets.account_kem_key(&a.app.account(&t.did).await.ok().unwrap()).await.unwrap().unwrap();
    a.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&a.app).await;

    let b = cluster_node("kemrw", store.clone(), 4, move |c| {
        c.kek = c2;
        c.spaces = true;
    })
    .await;
    let dry = b.xrpc.post("vlpds.admin.rewrapSecrets", &json!({"dryRun": true}), &Auth::Admin).await.ok();
    assert_eq!((dry["kemKeys"].clone(), dry["signingKeys"].clone()), (json!(1), json!(1)), "{dry}");
    let done = b.xrpc.post("vlpds.admin.rewrapSecrets", &json!({}), &Auth::Admin).await.ok();
    assert_eq!((done["kemKeys"].clone(), done["failed"].clone()), (json!(1), json!(0)), "{done}");
    let row = b.app.account(&t.did).await.ok().unwrap();
    assert!(row.wrapped_kem_key.as_deref().unwrap().starts_with(&format!("vw1.{}.", k2.kid())));
    b.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&b.app).await;

    let c = cluster_node("kemrw", store.clone(), 4, move |c| {
        c.kek = c3;
        c.spaces = true;
    })
    .await;
    let after = c.app.secrets.account_kem_key(&c.app.account(&t.did).await.ok().unwrap()).await.unwrap().unwrap();
    assert_eq!(after.to_bytes(), before.to_bytes(), "rewrapped, not rotated");
    c.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&c.app).await;
}
