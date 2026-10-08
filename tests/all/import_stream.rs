//! importRepo of a CAR in the streamable block order (src/car_order.rs)
//! takes the one-pass parse; any other order is parsed buffered. Both give
//! the same repo, and bodies that break off or run over the cap are refused.
//! The per-CAR cases (wrong CIDs, missing blocks, refusals matching the
//! buffered errors) are unit tests in src/xrpc/import_stream.rs.
use crate::common::*;
use std::collections::HashMap;

const CAR: &str = "application/vnd.ipld.car";

fn parses(path: &str) -> u64 {
    vlpds::metrics::IMPORT_REPO_PARSES.with_label_values(&[path]).get()
}

/// The repo's records and MST root, as served by getRepo.
async fn contents(s: &TestServer, did: &str) -> (Cid, Vec<(String, Cid)>, HashMap<Cid, Vec<u8>>) {
    let repo = s.get_repo(did).await;
    let entries = repo.entries();
    let records = entries.iter().map(|(_, c)| (*c, repo.blocks[c].clone())).collect();
    (repo.commit().data, entries, records)
}

fn stream_order(car: &[u8]) -> Vec<u8> {
    let repo = Repo::from_car(car).unwrap();
    let commit = &repo.blocks[&repo.root];
    vlsync_atproto::car_order::write_car((repo.root, commit), repo.commit().data, &repo.blocks).unwrap()
}

fn shuffled(car: &[u8]) -> Vec<u8> {
    let repo = Repo::from_car(car).unwrap();
    let mut order = repo.order.clone();
    // deterministic, and far from either order
    order.sort_by_key(|c| c.to_bytes().iter().rev().copied().collect::<Vec<u8>>());
    let mut out = Vec::new();
    vlsync_atproto::car::write_header(&mut out, &repo.root);
    for c in order {
        vlsync_atproto::car::write_block(&mut out, &c, &repo.blocks[&c]);
    }
    out
}

async fn import(s: &TestServer, a: &TestAccount, car: Vec<u8>) -> Resp {
    s.xrpc.post_bytes("com.atproto.repo.importRepo", car, CAR, &a.auth()).await
}

/// Migration: a repo exported from one server imports into another in its
/// export order (the streamable order, records sharing a block repeated by
/// each entry: the one-pass parse), in the reference writer's order and
/// shuffled, with the same records and tree each time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streamed_and_buffered_imports_agree() {
    let old = TestServer::spawn().await;
    let new = TestServer::spawn().await;
    let a = old.create_account("src").await;
    for i in 0..150 {
        old.post(&a, &format!("post {i}")).await;
    }
    for i in 0..30 {
        let rec = json!({"$type": "app.bsky.graph.follow", "subject": format!("did:plc:{:024}", i), "createdAt": "2026-01-01T00:00:00Z"});
        old.xrpc
            .post(
                "com.atproto.repo.createRecord",
                &json!({"repo": a.did, "collection": "app.bsky.graph.follow", "record": rec}),
                &a.auth(),
            )
            .await
            .ok();
    }
    for _ in 0..2 {
        old.create_record(&a, "com.example.same", json!({"$type": "com.example.same", "same": true})).await;
    }
    let want = contents(&old, &a.did).await;
    assert_eq!(want.1.len(), 182);
    let exported = old.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await;
    assert_eq!(exported.status, 200);
    let exported = exported.body.to_vec();
    assert!(exported == stream_order(&exported), "getRepo writes the streamable order");

    let cases: [(&str, Vec<u8>); 3] =
        [("export", exported.clone()), ("stream", stream_order(&exported)), ("shuffled", shuffled(&exported))];
    for (name, car) in cases {
        let b = new.create_account("dst").await;
        let streamed = parses("stream");
        import(&new, &b, car).await.ok();
        if name != "shuffled" {
            assert!(parses("stream") > streamed, "{name}: the streamable order takes the one-pass parse");
        }
        let got = contents(&new, &b.did).await;
        assert_eq!(got.0, want.0, "{name}: MST root");
        assert_eq!(got.1, want.1, "{name}: entries");
        assert_eq!(got.2, want.2, "{name}: record bytes");
        let repo = new.get_repo(&b.did).await;
        assert_eq!(repo.commit().did, b.did);
        repo.commit().verify(&new.signing_key(&b.did).await).unwrap();
    }
}

/// Identical records share one CID under several keys: an import takes
/// each, and deleting one leaves the others (and their block) in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imported_records_sharing_a_cid_delete_independently() {
    let old = TestServer::spawn().await;
    let new = TestServer::spawn().await;
    let a = old.create_account("shared").await;
    let rec = json!({"$type": "com.example.same", "same": true});
    let mut refs = Vec::new();
    for _ in 0..3 {
        refs.push(old.create_record(&a, "com.example.same", rec.clone()).await);
    }
    assert!(refs.iter().all(|r| r.cid == refs[0].cid));
    old.post(&a, "other").await;
    let exported = old.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await.body.to_vec();
    for car in [exported.clone(), shuffled(&exported)] {
        let b = new.create_account("sharedst").await;
        import(&new, &b, car).await.ok();
        for r in &refs {
            assert_eq!(new.get_record(&b.did, "com.example.same", r.rkey()).await.ok()["cid"], r.cid.as_str());
        }
        new.delete_record(&b, "com.example.same", refs[0].rkey()).await.ok();
        new.get_record(&b.did, "com.example.same", refs[0].rkey()).await.err(400, "RecordNotFound");
        let repo = new.get_repo(&b.did).await;
        for r in &refs[1..] {
            assert_eq!(new.get_record(&b.did, "com.example.same", r.rkey()).await.ok()["value"], rec);
            assert_eq!(repo.record(&format!("com.example.same/{}", r.rkey())), Some(rec.clone()));
        }
        for r in &refs[1..] {
            new.delete_record(&b, "com.example.same", r.rkey()).await.ok();
        }
        let repo = new.get_repo(&b.did).await;
        assert!(!repo.blocks.contains_key(&Cid::parse(&refs[0].cid).unwrap()), "the last reference's block is gone");
    }
}

/// A body that breaks off mid-stream imports nothing; a complete body
/// holding a truncated CAR gets the buffered parse's error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_imports_are_refused() {
    let s = TestServer::spawn().await;
    let a = s.create_account("trunc").await;
    for i in 0..40 {
        s.post(&a, &format!("post {i}")).await;
    }
    let car = stream_order(&s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await.body);
    let b = s.create_account("trunc").await;
    let before = contents(&s, &b.did).await;

    let half = car[..car.len() / 2].to_vec();
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![Ok(half), Err(std::io::Error::other("client went away"))];
    let r = s
        .xrpc
        .http
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", s.xrpc.base))
        .header("content-type", CAR)
        .header("authorization", format!("Bearer {}", b.access))
        .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks)))
        .send()
        .await;
    if let Ok(r) = r {
        assert_ne!(r.status(), 200);
    }
    assert_eq!(contents(&s, &b.did).await, before);

    let r = import(&s, &b, car[..car.len() - 5].to_vec()).await;
    r.err(400, "InvalidRequest");
    assert!(r.text().contains("invalid CAR: short block"), "{}", r.text());
    assert_eq!(contents(&s, &b.did).await, before);
    import(&s, &b, car).await.ok();
    assert_eq!(contents(&s, &b.did).await.1.len(), 40);
}

/// The cap holds for a body without a length, streamed past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_bodies_over_the_cap_are_refused() {
    let s = TestServer::spawn_with(|c| c.max_import_bytes = 64 << 10).await;
    let a = s.create_account("cap").await;
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> = (0..100).map(|_| Ok(vec![0u8; 4096])).collect();
    let r = s
        .xrpc
        .http
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", s.xrpc.base))
        .header("content-type", CAR)
        .header("authorization", format!("Bearer {}", a.access))
        .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks)))
        .send()
        .await;
    // the server may answer before reading the rest of the body
    if let Ok(r) = r {
        assert_eq!(r.status(), 413);
    }
    let r = import(&s, &a, vec![0u8; (64 << 10) + 1]).await;
    r.err(413, "PayloadTooLarge");
}
