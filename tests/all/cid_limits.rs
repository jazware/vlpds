//! CIDs from untrusted input are the one atproto form: CIDv1, dag-cbor or
//! raw, sha2-256 with a 32-byte digest (59 characters as a string, 36 bytes
//! binary). An oversized "CID" (a 64 KB multihash) or any other form is
//! refused at every entry point: XRPC params, swap CIDs, `$link`s and blob
//! refs in record JSON, tag-42 links in imported records, and CAR blocks.
use crate::common::*;
use vlatproto::cbor;
use vlatproto::cid::base32_encode;

/// A CIDv1 string ("b" + base32) of `version`, `codec`, a multihash of
/// `code` and `digest_len` declared bytes.
fn cid_str(version: u8, codec: u8, code: u8, digest_len: usize) -> String {
    let mut b = vec![version, codec, code];
    vlatproto::car::write_varint(&mut b, digest_len as u64);
    b.extend(std::iter::repeat_n(7u8, digest_len));
    format!("b{}", base32_encode(&b))
}

/// Every refused form: oversized, other versions/codecs/hashes, other
/// multibases, non-canonical base32.
fn odd_cids() -> Vec<(&'static str, String)> {
    let good = Cid::dag_cbor(b"x").to_string();
    vec![
        ("64 KB multihash", cid_str(1, 0x71, 0x12, 64 << 10)),
        ("4 KB multihash", cid_str(1, 0x71, 0x12, 4 << 10)),
        ("33-byte digest", cid_str(1, 0x71, 0x12, 33)),
        ("31-byte digest", cid_str(1, 0x71, 0x12, 31)),
        ("sha2-512", cid_str(1, 0x71, 0x13, 64)),
        ("identity hash", cid_str(1, 0x71, 0x00, 32)),
        ("dag-pb", cid_str(1, 0x70, 0x12, 32)),
        ("version 2", cid_str(2, 0x71, 0x12, 32)),
        ("CIDv0", "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".into()),
        ("base58btc", "zdj7WhuEjrB52m1BisYCtmjH1hSKa7yZ3jEZ9JcXaFRD51wVz".into()),
        ("upper-case base32", good.to_uppercase()),
        ("trailing character", format!("{good}a")),
    ]
}

#[test]
fn odd_cids_never_parse() {
    for (name, s) in odd_cids() {
        assert!(Cid::parse(&s).is_err(), "{name}");
    }
    assert!(Cid::parse("").is_err());
    // parsing stops at the length: a 1 MB string is no work
    let huge = cid_str(1, 0x71, 0x12, 1 << 20);
    let t = std::time::Instant::now();
    for _ in 0..1000 {
        assert!(Cid::parse(&huge).is_err());
    }
    assert!(t.elapsed() < std::time::Duration::from_secs(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn odd_cids_refused_at_xrpc_entry_points() {
    let s = TestServer::spawn().await;
    let a = s.create_account("cids").await;
    let rec = s.post(&a, "hello").await;
    let blob = s.upload_blob(&a, b"blob bytes", "text/plain").await;
    let blob_cid = blob["ref"]["$link"].as_str().unwrap().to_string();
    let head = s.xrpc.get("com.atproto.sync.getLatestCommit", &[("did", &a.did)], &Auth::None).await.ok();
    let head = head["cid"].as_str().unwrap().to_string();
    for (name, bad) in odd_cids() {
        // a 64 KB string doesn't fit a request line; the 4 KB one does
        let in_url = bad.len() < 8 << 10;
        if in_url {
            let r = s
                .xrpc
                .get(
                    "com.atproto.repo.getRecord",
                    &[("repo", &a.did), ("collection", "app.bsky.feed.post"), ("rkey", rec.rkey()), ("cid", &bad)],
                    &Auth::None,
                )
                .await;
            r.client_err();
            assert!(r.json.get("value").is_none(), "{name}: getRecord answered");
            s.xrpc.get("com.atproto.sync.getBlob", &[("did", &a.did), ("cid", &bad)], &Auth::None).await.client_err();
            s.xrpc
                .get_multi("com.atproto.sync.getBlocks", &[("did", a.did.clone()), ("cids", bad.clone())], &Auth::None)
                .await
                .client_err();
        }
        let post = json!({"$type": "app.bsky.feed.post", "text": "x", "createdAt": now_iso()});
        let writes: [(&str, J); 6] = [
            (
                "com.atproto.repo.createRecord",
                json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post, "swapCommit": bad}),
            ),
            (
                "com.atproto.repo.putRecord",
                json!({"repo": a.did, "collection": "app.bsky.feed.post", "rkey": rec.rkey(), "record": post, "swapRecord": bad}),
            ),
            (
                "com.atproto.repo.deleteRecord",
                json!({"repo": a.did, "collection": "app.bsky.feed.post", "rkey": rec.rkey(), "swapRecord": bad}),
            ),
            (
                "com.atproto.repo.applyWrites",
                json!({"repo": a.did, "writes": [{"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": post}], "swapCommit": bad}),
            ),
            // a link in record data, and a blob ref
            (
                "com.atproto.repo.createRecord",
                json!({"repo": a.did, "collection": "com.example.links", "record": {"$type": "com.example.links", "l": {"$link": bad}}}),
            ),
            (
                "com.atproto.repo.createRecord",
                json!({"repo": a.did, "collection": "com.example.links", "record": {"$type": "com.example.links", "b": {"$type": "blob", "ref": {"$link": bad}, "mimeType": "text/plain", "size": 10}}}),
            ),
        ];
        for (nsid, body) in writes {
            let r = s.xrpc.post(nsid, &body, &a.auth()).await;
            r.client_err();
            assert!(!r.text().contains("\"uri\""), "{name}: {nsid} wrote: {}", r.text());
        }
    }
    // the record is untouched, and the well-formed forms still work
    s.xrpc
        .get(
            "com.atproto.repo.getRecord",
            &[("repo", &a.did), ("collection", "app.bsky.feed.post"), ("rkey", rec.rkey()), ("cid", &rec.cid)],
            &Auth::None,
        )
        .await
        .ok();
    s.xrpc.get("com.atproto.sync.getBlob", &[("did", &a.did), ("cid", &blob_cid)], &Auth::None).await.ok();
    s.xrpc.get_multi("com.atproto.sync.getBlocks", &[("did", a.did.clone()), ("cids", head)], &Auth::None).await.ok();
    // a blob ref must be raw: the record's dag-cbor CID is refused there
    let r = s
        .xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": a.did, "collection": "com.example.links", "record": {"$type": "com.example.links", "b": {"$type": "blob", "ref": {"$link": rec.cid}, "mimeType": "text/plain", "size": 10}}}),
            &a.auth(),
        )
        .await;
    r.client_err();
}

/// A CAR of an otherwise valid one-record repo whose record carries `link`
/// (a tag-42 byte string) and, if given, one extra raw block.
fn car_with(did: &str, link: &[u8], extra: Option<&[u8]>) -> Vec<u8> {
    let mut rec = Vec::new();
    cbor::write_map_head(&mut rec, 2);
    cbor::write_text(&mut rec, "l");
    rec.extend_from_slice(&[0xd8, 0x2a]);
    cbor::write_bytes(&mut rec, link);
    cbor::write_text(&mut rec, "$type");
    cbor::write_text(&mut rec, "com.example.links");
    let rc = Cid::dag_cbor(&rec);
    let mut tree = vlatproto::mst::Tree::new();
    tree.insert_no_proof(b"com.example.links/x", rc).unwrap();
    let mut blocks = vec![(rc, rec)];
    let data = tree.write_diff_blocks(&mut blocks).unwrap();
    let mut fields = vec![
        ("data".to_string(), Value::Link(data)),
        ("did".to_string(), Value::Text(did.into())),
        ("rev".to_string(), Value::Text("3l3qo2vuowo2b".into())),
        ("sig".to_string(), Value::Bytes(vec![0; 64])),
        ("prev".to_string(), Value::Null),
        ("version".to_string(), Value::Int(3)),
    ];
    fields.sort_by(|a, b| cbor::key_cmp(&a.0, &b.0));
    let commit = Value::Map(fields).to_cbor();
    let root = Cid::dag_cbor(&commit);
    let mut car = Vec::new();
    vlatproto::car::write_header(&mut car, &root);
    vlatproto::car::write_block(&mut car, &root, &commit);
    for (c, b) in &blocks {
        vlatproto::car::write_block(&mut car, c, b);
    }
    if let Some(prefix) = extra {
        // a block whose CID prefix is `prefix` (say, a 64 KB multihash)
        vlatproto::car::write_varint(&mut car, prefix.len() as u64 + 4);
        car.extend_from_slice(prefix);
        car.extend_from_slice(b"data");
    }
    car
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn odd_cids_refused_in_imported_cars() {
    let s = TestServer::spawn().await;
    let a = s.create_account("cidimp").await;
    let auth = a.auth();
    let import =
        |car: Vec<u8>| s.xrpc.post_bytes("com.atproto.repo.importRepo", car, "application/vnd.ipld.car", &auth);
    let car_with = |link: &[u8], extra: Option<&[u8]>| car_with(&a.did, link, extra);
    let good = {
        let mut b = vec![0u8];
        b.extend_from_slice(&Cid::dag_cbor(b"x").to_bytes());
        b
    };
    let huge_mh = {
        let mut b = vec![0x01, 0x71, 0x12];
        vlatproto::car::write_varint(&mut b, 64 << 10);
        b.extend(std::iter::repeat_n(0u8, 64 << 10));
        b
    };
    let link_of = |cid: &[u8]| {
        let mut b = vec![0u8];
        b.extend_from_slice(cid);
        b
    };
    // control: the same repo with a well-formed link imports (again and again)
    import(car_with(&good, None)).await.ok();
    let sha512 = {
        let mut c = vec![0x01, 0x71, 0x13, 0x40];
        c.extend([0u8; 64]);
        c
    };
    let cidv0 = {
        let mut c = vec![0x12, 0x20];
        c.extend([0u8; 32]);
        c
    };
    for (name, car) in [
        ("tag-42 link with a 64 KB multihash", car_with(&link_of(&huge_mh), None)),
        ("tag-42 link with a sha2-512 multihash", car_with(&link_of(&sha512), None)),
        ("tag-42 CIDv0 link", car_with(&link_of(&cidv0), None)),
        ("tag-42 link without the identity prefix", car_with(&Cid::dag_cbor(b"x").to_bytes(), None)),
        ("block CID with a 64 KB multihash", car_with(&good, Some(&huge_mh))),
        ("block CID with a sha2-512 multihash", car_with(&good, Some(&sha512))),
        ("CIDv0 block", car_with(&good, Some(&cidv0))),
    ] {
        let r = import(car).await;
        assert_eq!(r.status, 400, "{name}: {}", r.text());
    }
}
