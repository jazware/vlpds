//! importRepo of CARs built here: legacy blob refs are indexed (as the
//! reference's `enumBlobRefs(allowLegacy)`), record blocks and whole CARs
//! are capped, and integers outside JS's safe range are refused on write.
use crate::common::*;
use std::time::Duration;
use vlatproto::cbor::key_cmp;

/// A CAR of an (unsigned: importRepo doesn't check) commit over `records`.
fn import_car(did: &str, records: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut tree = vlatproto::mst::Tree::new();
    let mut blocks: Vec<(Cid, Vec<u8>)> = Vec::new();
    for (path, rec) in records {
        let c = Cid::dag_cbor(rec);
        tree.insert_no_proof(path.as_bytes(), c).unwrap();
        blocks.push((c, rec.clone()));
    }
    let data = tree.write_diff_blocks(&mut blocks).unwrap();
    let mut fields = vec![
        ("did".to_string(), Value::Text(did.to_string())),
        ("rev".to_string(), Value::Text("3l3qo2vuowo2b".to_string())),
        ("data".to_string(), Value::Link(data)),
        ("prev".to_string(), Value::Null),
        ("version".to_string(), Value::Int(3)),
        ("sig".to_string(), Value::Bytes(vec![0; 64])),
    ];
    fields.sort_by(|a, b| key_cmp(&a.0, &b.0));
    let commit = Value::Map(fields).to_cbor();
    let root = Cid::dag_cbor(&commit);
    let mut car = Vec::new();
    vlatproto::car::write_header(&mut car, &root);
    vlatproto::car::write_block(&mut car, &root, &commit);
    for (c, b) in &blocks {
        vlatproto::car::write_block(&mut car, c, b);
    }
    car
}

fn cbor(j: J) -> Vec<u8> {
    Value::from_json(&j).unwrap().to_cbor()
}

/// An old repo's legacy blob refs (`{cid, mimeType}`) are indexed on
/// import: listBlobs lists them, listMissingBlobs reports the missing ones,
/// and the blob GC keeps the uploaded one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_blob_refs_are_indexed_on_import() {
    let s = TestServer::spawn().await;
    let a = s.create_account("legacy").await;
    let have = s.upload_blob(&a, &random_png(1), "image/png").await["ref"]["$link"].as_str().unwrap().to_string();
    let missing = Cid::raw(b"never uploaded").to_string();
    let post = |cid: &str| {
        cbor(json!({"$type": "app.bsky.feed.post", "text": "old", "createdAt": "2023-01-01T00:00:00Z",
            "embed": {"$type": "app.bsky.embed.images", "images": [{"alt": "", "image": {"cid": cid, "mimeType": "image/png"}}]}}))
    };
    // not a legacy ref: an extra field
    let other = cbor(json!({"$type": "app.bsky.feed.post", "text": "x", "createdAt": "2023-01-01T00:00:00Z",
        "x": {"cid": Cid::raw(b"other").to_string(), "mimeType": "image/png", "size": 1}}));
    let car = import_car(
        &a.did,
        &[
            ("app.bsky.feed.post/3jzfcijpj2z2a", post(&have)),
            ("app.bsky.feed.post/3jzfcijpj2z2b", post(&missing)),
            ("app.bsky.feed.post/3jzfcijpj2z2c", other),
        ],
    );
    s.import_repo(&a.auth(), car).await.ok();
    let mut cids = s.list_blobs(&a.did).await;
    cids.sort();
    let mut want = vec![have.clone(), missing.clone()];
    want.sort();
    assert_eq!(cids, want);
    let m = s.xrpc.get("com.atproto.repo.listMissingBlobs", &[], &a.auth()).await.ok();
    assert_eq!(
        m["blobs"].as_array().unwrap().iter().map(|b| b["cid"].as_str().unwrap()).collect::<Vec<_>>(),
        vec![missing.as_str()]
    );
    // the GC sees the reference
    vlpds::xrpc::blobs::sweep_blobs_settle(&s.app, Duration::ZERO, Duration::ZERO).await.unwrap();
    assert_eq!(s.get_blob(&a.did, &have).await.status, 200);
}

/// A record block over 2 MiB is refused; one under it imports.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_import_records_are_refused() {
    let s = TestServer::spawn().await;
    let a = s.create_account("bigrec").await;
    let rec = |n: usize| {
        let mut m = vec![
            ("$type".to_string(), Value::Text("com.example.big".into())),
            ("b".to_string(), Value::Bytes(vec![7; n])),
        ];
        m.sort_by(|a, b| key_cmp(&a.0, &b.0));
        Value::Map(m).to_cbor()
    };
    let r = s.import_repo(&a.auth(), import_car(&a.did, &[("com.example.big/a", rec((2 << 20) + 1))])).await;
    r.err(400, "InvalidRequest");
    assert!(r.text().contains("too large"), "{}", r.text());
    s.import_repo(&a.auth(), import_car(&a.did, &[("com.example.big/a", rec(1 << 20))])).await.ok();
}

/// `Config::max_import_bytes` bounds the CAR.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_size_is_configurable() {
    let s = TestServer::spawn_with(|c| c.max_import_bytes = 4096).await;
    let a = s.create_account("capped").await;
    let small = import_car(&a.did, &[("com.example.x/a", cbor(json!({"$type": "com.example.x", "v": 1})))]);
    s.import_repo(&a.auth(), small).await.ok();
    let big =
        import_car(&a.did, &[("com.example.x/a", cbor(json!({"$type": "com.example.x", "v": "y".repeat(5000)})))]);
    assert_eq!(s.import_repo(&a.auth(), big).await.status, 413);
}

/// Integers past 2^53 - 1 are refused like integral floats there (the
/// reference encoder: `Number.isSafeInteger`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsafe_integers_are_refused_on_write() {
    let s = TestServer::spawn().await;
    let a = s.create_account("bigint").await;
    for (n, ok) in [("9007199254740991", true), ("9007199254740992", false), ("-9223372036854775808", false)] {
        let body = format!(
            r#"{{"repo": "{}", "collection": "com.example.n", "record": {{"$type": "com.example.n", "n": {n}}}}}"#,
            a.did
        );
        let j: J = serde_json::from_str(&body).unwrap();
        let r = s.xrpc.post("com.atproto.repo.createRecord", &j, &a.auth()).await;
        assert_eq!(r.is_ok(), ok, "{n}: {}", r.text());
    }
}

/// A body that sends part of a CAR and then nothing fails once it's been
/// idle too long, giving back its import slot and reservation, as one that
/// takes too long in all does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_import_body_fails() {
    use futures::StreamExt;
    for (idle, total) in
        [(Duration::from_millis(500), Duration::from_secs(60)), (Duration::from_secs(60), Duration::from_secs(1))]
    {
        let s = TestServer::spawn_with(move |c| {
            c.import_body_idle = idle;
            c.import_body_deadline = total;
        })
        .await;
        let a = s.create_account("stall").await;
        let car = bytes::Bytes::from(import_car(&a.did, &[]));
        let head = car.slice(..car.len() / 2);
        // trickles a byte a quarter second, never ending
        let trickle = futures::stream::unfold((), |_| async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            Some((Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"\x00")), ()))
        });
        let stalled = futures::stream::once(async move { Ok::<_, std::io::Error>(head) });
        let body = match total < Duration::from_secs(5) {
            true => reqwest::Body::wrap_stream(stalled.chain(trickle)),
            false => reqwest::Body::wrap_stream(stalled.chain(futures::stream::pending())),
        };
        let rb = s
            .xrpc
            .http
            .post(format!("{}/xrpc/com.atproto.repo.importRepo", s.url))
            .header("content-type", "application/vnd.ipld.car")
            .header("authorization", format!("Bearer {}", a.access))
            .body(body);
        let t = std::time::Instant::now();
        let r =
            tokio::time::timeout(Duration::from_secs(20), s.xrpc.send(rb)).await.expect("the import waited forever");
        assert_eq!(r.status, 400, "{}", r.text());
        assert!(r.text().contains("stalled"), "{}", r.text());
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        assert_eq!(s.app.imports.reserved(), 0);
    }
}
