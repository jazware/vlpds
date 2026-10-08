//! OAuth single-use claims at the authorization server (token endpoint / PAR
//! DPoP proofs, client assertion and request object `jti`s) survive a change
//! of owner: they are persisted in the routing key's partition, so the node
//! that takes it over (with an empty in-memory set) still refuses a proof
//! its predecessor accepted. Resource-request proofs are memory-only claims
//! (tests/all/oauth.rs `resource_dpop_checks`; HA notes in src/oauth/mod.rs).
use crate::common::*;
use crate::oauth::DpopKey;
use std::sync::Arc;

const SHARDS: u32 = 8;
const PUBLIC: &str = "http://pds.replay.test";

async fn node(id: &str, store: &Arc<object_store::memory::InMemory>) -> TestServer {
    cluster_node(id, store.clone(), SHARDS, |c| c.public_url = PUBLIC.into()).await
}

/// A token request that fails after the proof check (unknown refresh
/// token): its `error` and the nonce the server sent, if any.
async fn token_request(node: &TestServer, proof: &str) -> (String, Option<String>) {
    let r = reqwest::Client::new()
        .post(format!("{}/oauth/token", node.url))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("dpop", proof)
        .body("grant_type=refresh_token&client_id=http%3A%2F%2Flocalhost&refresh_token=ref-bogus")
        .send()
        .await
        .unwrap();
    let nonce = r.headers().get("dpop-nonce").map(|v| v.to_str().unwrap().to_string());
    let j: J = r.json().await.unwrap_or(J::Null);
    (j["error"].as_str().unwrap_or("").to_string(), nonce)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dpop_proof_replay_refused_after_owner_change() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("rep-a", &store).await;
    let b = node("rep-b", &store).await;
    balanced(&[&a, &b]).await;
    let htu = format!("{PUBLIC}/oauth/token");

    // a key whose proofs are claimed on a; requests go through b
    let key = loop {
        let k = DpopKey::new();
        let p = vlsync_store::slots::shard_of(&format!("oauth:jkt:{}", k.jkt()), SHARDS);
        if a.app.partitions.get(p).is_some() {
            break k;
        }
    };
    let (e, nonce) = token_request(&b, &key.proof("POST", &htu, None)).await;
    if e == "use_dpop_nonce" {
        *key.nonce.lock() = nonce;
    }
    let proof = key.proof("POST", &htu, None);
    let (e, _) = token_request(&b, &proof).await;
    assert_ne!(e, "invalid_dpop_proof", "first use");
    assert_ne!(e, "use_dpop_nonce");
    assert_eq!(token_request(&b, &proof).await.0, "invalid_dpop_proof", "replay");

    // a hands its shards to b, whose in-memory set never saw the proof
    vlpds::server::shutdown(&a.app).await;
    balanced(&[&b]).await;
    assert_eq!(token_request(&b, &proof).await.0, "invalid_dpop_proof", "replay after the handoff");
    // a node restarted from scratch agrees too
    vlpds::oauth::util::forget_replays(&b.app);
    assert_eq!(token_request(&b, &proof).await.0, "invalid_dpop_proof", "replay with an empty set");
    // and fresh proofs of the key still work
    let (e, _) = token_request(&b, &key.proof("POST", &htu, None)).await;
    assert!(e != "invalid_dpop_proof" && e != "use_dpop_nonce", "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claims_are_persisted_and_expired_ones_collected() {
    use vlpds::xrpc::internal::{claim_replay_anywhere, claim_transient_anywhere, release_replay_anywhere};
    let s = TestServer::spawn().await;
    let app = &s.app;
    let now = chrono::Utc::now().timestamp();
    let routing = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(claim_replay_anywhere(app, routing, "dpop:k:1", now + 300).await.map_err(|e| e.message).unwrap());
    assert!(!claim_replay_anywhere(app, routing, "dpop:k:1", now + 300).await.map_err(|e| e.message).unwrap());
    vlpds::oauth::util::forget_replays(app);
    assert!(
        !claim_replay_anywhere(app, routing, "dpop:k:1", now + 300).await.map_err(|e| e.message).unwrap(),
        "persisted"
    );
    assert!(claim_replay_anywhere(app, routing, "dpop:k:2", now + 300).await.map_err(|e| e.message).unwrap());
    // a transient guard is memory only
    assert!(claim_transient_anywhere(app, routing, "cc:x", now + 60).await.map_err(|e| e.message).unwrap());
    release_replay_anywhere(app, routing, "cc:x").await.map_err(|e| e.message).unwrap();
    assert!(claim_transient_anywhere(app, routing, "cc:x", now + 60).await.map_err(|e| e.message).unwrap());

    let rows = |app: Arc<vlpds::xrpc::App>| async move {
        let p = app.partition(routing).ok().unwrap();
        let prefix = vlpds::state::private_key(routing, vlpds::oauth::util::REPLAY_ROW);
        let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
        let mut n = 0;
        while it.next().await.unwrap().is_some() {
            n += 1;
        }
        n
    };
    assert_eq!(rows(app.clone()).await, 2);
    let mut sw = vlpds::oauth::gc::Sweeper::new();
    let st = sw.tick(app, now, 10_000, 10_000).await.unwrap();
    assert_eq!(st.claims_removed, 0, "{st:?}");
    let st = sw.tick(app, now + 301, 10_000, 10_000).await.unwrap();
    assert_eq!(st.claims_removed, 2, "{st:?}");
    assert_eq!(rows(app.clone()).await, 0);
}
