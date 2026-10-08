//! Blobs in spaces (`--spaces`; src/xrpc/space.rs getBlob/listBlobs, the
//! `sb`/`sc` refs of src/space/repo.rs, src/xrpc/blobs.rs): a blob a space
//! record names is served only through that space, to a credential for it
//! or its owner; sync.getBlob serves only blobs a public record names; the
//! GC keeps a blob while any space record names it. Without the flag a
//! fresh upload is still served before any record names it.

use crate::common::spaces::SpaceClient;
use crate::common::*;
use object_store::ObjectStoreExt;
use std::sync::Arc;
use std::time::Duration;

const TYPE: &str = "com.example.group";
const COLL: &str = "com.example.post";
const OWNER: &str =
    "space:com.example.group?collection=com.example.post&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete";
const ANY: &str = "space:com.example.group?authority=*&collection=com.example.post&action=read";

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

/// The client's password session as a [`TestAccount`], for the public
/// repo and uploads.
fn legacy(c: &SpaceClient) -> TestAccount {
    TestAccount {
        did: c.did.clone(),
        handle: c.handle.clone(),
        password: String::new(),
        email: String::new(),
        access: c.session_jwt.clone(),
        refresh: String::new(),
    }
}

fn rec(text: &str, blobs: &[&J]) -> J {
    json!({"$type": COLL, "text": text, "images": blobs, "createdAt": "2026-10-01T00:00:00.000Z"})
}

fn cid(blob: &J) -> String {
    blob["ref"]["$link"].as_str().unwrap().to_string()
}

async fn upload(s: &TestServer, c: &SpaceClient, tag: u8) -> (J, Vec<u8>) {
    let bytes = random_png(tag);
    (s.upload_blob(&legacy(c), &bytes, "image/png").await, bytes)
}

async fn object_exists(s: &TestServer, did: &str, cid: &str) -> bool {
    let p = |root: &str| object_store::path::Path::from(format!("{}/{root}/{did}/{cid}", s.app.store.prefix));
    s.app.store.raw.head(&p("blob")).await.is_ok() || s.app.store.raw.head(&p("blob-gc")).await.is_ok()
}

/// Two passes: the first quarantines what nothing names, the second purges it.
async fn sweep(s: &TestServer) {
    for _ in 0..2 {
        vlpds::xrpc::blobs::sweep_blobs_settle(&s.app, Duration::ZERO, Duration::ZERO).await.expect("sweep");
    }
}

/// `sb`/`sc` rows of `did`.
async fn blob_rows(s: &TestServer, did: &str) -> usize {
    let p = s.app.partition(did).ok().expect("local partition");
    let mut n = 0;
    for fam in [vlpds::state::SPACE_BLOB_FAMILY, vlpds::state::SPACE_BLOB_CID_FAMILY] {
        let prefix = vlpds::state::space_did_prefix(fam, did);
        let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
        while it.next().await.unwrap().is_some() {
            n += 1;
        }
    }
    n
}

/// space.getBlob of `repo`'s blob with `cred`, signed by `who`.
async fn get(s: &TestServer, who: &SpaceClient, cred: &str, space: &str, repo: &str, c: &J) -> Resp {
    let q = [("space", space), ("repo", repo), ("cid", &cid(c))];
    who.signed_get(&s.url, "com.atproto.space.getBlob", &q, cred, repo).await
}

async fn list(s: &TestServer, who: &SpaceClient, cred: &str, space: &str, repo: &str, extra: &[(&str, &str)]) -> Resp {
    let mut q = vec![("space", space), ("repo", repo)];
    q.extend_from_slice(extra);
    who.signed_get(&s.url, "com.atproto.space.listBlobs", &q, cred, repo).await
}

fn cids(j: &J) -> Vec<String> {
    j["cids"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_blobs_are_served_only_through_their_space() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "sbo", OWNER).await;
    let member = SpaceClient::new(&s, "sbm", ANY).await;
    let space = owner.create_space(TYPE, "main").await;
    let other = owner.create_space(TYPE, "other").await;
    let r = owner
        .post(
            "com.atproto.simplespace.putMember",
            json!({"space": space, "did": member.did, "read": true, "write": false}),
        )
        .await;
    r.ok();
    let (only, only_bytes) = upload(&s, &owner, 1).await;
    let (shared, _) = upload(&s, &owner, 2).await;
    let (stray, _) = upload(&s, &owner, 3).await;
    let (elsewhere, _) = upload(&s, &owner, 4).await;
    owner.create_record(&space, COLL, Some("a"), rec("a", &[&only])).await.ok();
    owner.create_record(&space, COLL, Some("b"), rec("b", &[&shared])).await.ok();
    owner.create_record(&other, COLL, Some("c"), rec("c", &[&elsewhere])).await.ok();
    s.create_record(&legacy(&owner), "app.bsky.feed.post", image_post("public", &shared)).await;

    // public sync: only what a public record names
    s.get_blob(&owner.did, &cid(&only)).await.err(400, "BlobNotFound");
    s.get_blob(&owner.did, &cid(&elsewhere)).await.err(400, "BlobNotFound");
    s.get_blob(&owner.did, &cid(&stray)).await.err(400, "BlobNotFound");
    assert_eq!(s.get_blob(&owner.did, &cid(&shared)).await.status, 200);
    assert_eq!(s.list_blobs(&owner.did).await, vec![cid(&shared)]);

    // a member's credential for the space reads its blobs
    let cred = member.credential(&space).await;
    let o = owner.did.as_str();
    let r = get(&s, &member, &cred, &space, o, &only).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(&r.body[..], &only_bytes[..]);
    assert_eq!(r.headers["content-type"], "image/png");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    assert_eq!(get(&s, &member, &cred, &space, o, &shared).await.status, 200);
    // not one the space names: another space's, or an upload nothing names
    get(&s, &member, &cred, &space, o, &elsewhere).await.err(400, "BlobNotFound");
    get(&s, &member, &cred, &space, o, &stray).await.err(400, "BlobNotFound");
    // a credential for another space
    let other_cred = owner.credential(&other).await;
    let r = get(&s, &owner, &other_cred, &space, o, &only).await;
    assert_eq!((r.status, r.error_name()), (400, Some("InvalidCredential")), "{r:?}");
    get(&s, &owner, &other_cred, &other, o, &only).await.err(400, "BlobNotFound");
    assert_eq!(get(&s, &owner, &other_cred, &other, o, &elsewhere).await.status, 200);

    // the owner over OAuth (read_self); anyone else's OAuth gets nothing
    let only_cid = cid(&only);
    let oq = [("space", space.as_str()), ("repo", o), ("cid", only_cid.as_str())];
    let (status, ctype, body) = owner.get_raw("com.atproto.space.getBlob", &oq).await;
    assert_eq!((status, ctype.as_str(), &body[..]), (200, "image/png", &only_bytes[..]));
    member.get("com.atproto.space.getBlob", &oq).await.err(400, "RepoNotFound");
    // unauthenticated
    let r = s.xrpc.get("com.atproto.space.getBlob", &oq, &Auth::None).await;
    assert_eq!(r.status, 401, "{r:?}");

    // listBlobs: one space's, in CID order, paged; `since` a rev
    let mut both = vec![cid(&only), cid(&shared)];
    both.sort();
    let r = list(&s, &member, &cred, &space, o, &[]).await.ok();
    assert_eq!(cids(&r), both);
    assert!(r.get("cursor").is_none(), "a short page has no cursor: {r}");
    let p1 = list(&s, &member, &cred, &space, o, &[("limit", "1")]).await.ok();
    assert_eq!(cids(&p1), both[..1]);
    let c = p1["cursor"].as_str().unwrap().to_string();
    let p2 = list(&s, &member, &cred, &space, o, &[("limit", "1"), ("cursor", &c)]).await.ok();
    assert_eq!(cids(&p2), both[1..]);
    let c = p2["cursor"].as_str().unwrap().to_string();
    let p3 = list(&s, &member, &cred, &space, o, &[("limit", "1"), ("cursor", &c)]).await.ok();
    assert_eq!((cids(&p3), p3.get("cursor")), (vec![], None));
    let r = owner.get("com.atproto.space.listBlobs", &[("space", &other), ("repo", &owner.did)]).await.ok();
    assert_eq!(cids(&r), vec![cid(&elsewhere)]);
    let rev = owner.get("com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &owner.did)]).await.ok()
        ["commit"]["rev"]
        .as_str()
        .unwrap()
        .to_string();
    let (later, _) = upload(&s, &owner, 5).await;
    // `a` now names `later` instead of `only`
    owner.put_record(&space, COLL, "a", rec("a2", &[&later])).await.ok();
    let r = list(&s, &member, &cred, &space, o, &[("since", &rev)]).await.ok();
    assert_eq!(cids(&r), vec![cid(&later)]);
    list(&s, &member, &cred, &space, o, &[("since", "nope")]).await.err(400, "InvalidRequest");
    get(&s, &member, &cred, &space, o, &only).await.err(400, "BlobNotFound");
    assert_eq!(get(&s, &member, &cred, &space, o, &later).await.status, 200);
    s.get_blob(&owner.did, &cid(&later)).await.err(400, "BlobNotFound");

    // a blob a public record names too outlives the space record
    owner.delete_record(&space, COLL, "b").await.ok();
    get(&s, &member, &cred, &space, o, &shared).await.err(400, "BlobNotFound");
    assert_eq!(s.get_blob(&owner.did, &cid(&shared)).await.status, 200);
    sweep(&s).await;
    assert_eq!(s.get_blob(&owner.did, &cid(&shared)).await.status, 200);
    assert_eq!(get(&s, &member, &cred, &space, o, &later).await.status, 200, "the GC kept a space-referenced blob");
}

/// A space write checks its blobs as a repo write does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_writes_check_their_blobs() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "sbc", OWNER).await;
    let space = owner.create_space(TYPE, "main").await;
    let (blob, _) = upload(&s, &owner, 1).await;
    let missing = json!({"$type": "blob", "ref": {"$link": Cid::raw(b"never uploaded").to_string()}, "mimeType": "image/png", "size": 3});
    owner.create_record(&space, COLL, Some("a"), rec("a", &[&missing])).await.err(400, "BlobNotFound");
    let mut wrong = blob.clone();
    wrong["mimeType"] = json!("image/jpeg");
    owner.create_record(&space, COLL, Some("a"), rec("a", &[&wrong])).await.err(400, "InvalidMimeType");
    let w = |rkey: &str, b: &J| json!({"$type": "com.atproto.space.applyWrites#create", "collection": COLL, "rkey": rkey, "value": rec(rkey, &[b])});
    owner.apply_writes(&space, json!([w("x", &blob), w("y", &missing)])).await.err(400, "BlobNotFound");
    // another account's upload isn't this account's blob
    let stranger = SpaceClient::new(&s, "sbx", OWNER).await;
    let (theirs, _) = upload(&s, &stranger, 2).await;
    owner.create_record(&space, COLL, Some("t"), rec("t", &[&theirs])).await.err(400, "BlobNotFound");
    assert_eq!(blob_rows(&s, &owner.did).await, 0, "a refused write left refs");
    owner.apply_writes(&space, json!([w("x", &blob)])).await.ok();
    assert_eq!(blob_rows(&s, &owner.did).await, 2);
}

/// The GC keeps a blob while a space record names it, and collects it once
/// the last one is gone: a delete, or the whole space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gc_counts_space_refs() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "sbg", OWNER).await;
    let space = owner.create_space(TYPE, "main").await;
    let doomed = owner.create_space(TYPE, "doomed").await;
    let (a, _) = upload(&s, &owner, 1).await;
    let (b, _) = upload(&s, &owner, 2).await;
    owner.create_record(&space, COLL, Some("one"), rec("one", &[&a])).await.ok();
    owner.create_record(&space, COLL, Some("two"), rec("two", &[&a])).await.ok();
    owner.create_record(&doomed, COLL, Some("x"), rec("x", &[&b])).await.ok();
    sweep(&s).await;
    assert!(object_exists(&s, &owner.did, &cid(&a)).await);
    assert!(object_exists(&s, &owner.did, &cid(&b)).await);
    // one of two refs gone: kept
    owner.delete_record(&space, COLL, "one").await.ok();
    sweep(&s).await;
    assert!(object_exists(&s, &owner.did, &cid(&a)).await);
    owner.delete_record(&space, COLL, "two").await.ok();
    sweep(&s).await;
    assert!(!object_exists(&s, &owner.did, &cid(&a)).await, "collected after the last space ref");
    // deleteSpace drops the space's refs
    assert_eq!(blob_rows(&s, &owner.did).await, 2);
    owner.post("com.atproto.simplespace.deleteSpace", json!({"space": doomed})).await.ok();
    assert_eq!(blob_rows(&s, &owner.did).await, 0);
    sweep(&s).await;
    assert!(!object_exists(&s, &owner.did, &cid(&b)).await);
}

/// Without `--spaces` an upload is served before any record names it, as
/// tests/all/blobs.rs pins; with it, only once a public record does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_get_blob_rule_follows_the_flag() {
    for spaces in [false, true] {
        let s = TestServer::spawn_with(|c| c.spaces = spaces).await;
        let a = s.create_account("sbf").await;
        let blob = s.upload_blob(&a, &random_png(1), "image/png").await;
        let r = s.get_blob(&a.did, &cid(&blob)).await;
        match spaces {
            false => assert_eq!(r.status, 200, "{r:?}"),
            true => r.err(400, "BlobNotFound"),
        }
        s.create_record(&a, "app.bsky.feed.post", image_post("x", &blob)).await;
        assert_eq!(s.get_blob(&a.did, &cid(&blob)).await.status, 200);
    }
}

/// A blob only space records name stays private when a node comes back
/// without `--spaces` (its space refs, which keep it from the GC, outlive
/// the flag); one a public record names, or an upload nothing names, is as
/// it was without the flag. An account with no space blob ref is held as
/// such, so its getBlobs read no ref at all, as before Spaces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_only_blob_stays_private_with_the_flag_off() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let on = cluster_node("sbx", store.clone(), 8, |c| c.spaces = true).await;
    let owner = SpaceClient::new(&on, "sbx", OWNER).await;
    let space = owner.create_space(TYPE, "main").await;
    let (private, _) = upload(&on, &owner, 1).await;
    let (shared, _) = upload(&on, &owner, 2).await;
    let (stray, _) = upload(&on, &owner, 3).await;
    owner.create_record(&space, COLL, Some("a"), rec("a", &[&private, &shared])).await.ok();
    on.create_record(&legacy(&owner), "app.bsky.feed.post", image_post("public", &shared)).await;
    on.get_blob(&owner.did, &cid(&private)).await.err(400, "BlobNotFound");
    // an account no space record names a blob of
    let plain = SpaceClient::new(&on, "sby", OWNER).await;
    let (plain_stray, _) = upload(&on, &plain, 4).await;
    let (plain_public, _) = upload(&on, &plain, 5).await;
    on.create_record(&legacy(&plain), "app.bsky.feed.post", image_post("public", &plain_public)).await;
    vlpds::server::shutdown(&on.app).await;

    let off = cluster_node("sbx", store.clone(), 8, |c| c.spaces = false).await;
    let held = |did: &str| off.app.space_blob_accounts.peek(did);
    assert_eq!((held(&owner.did), held(&plain.did)), (None, None), "worked out on first use");
    off.get_blob(&owner.did, &cid(&private)).await.err(400, "BlobNotFound");
    assert_eq!(held(&owner.did), Some(true));
    for b in [&plain_stray, &plain_public] {
        assert_eq!(off.get_blob(&plain.did, &cid(b)).await.status, 200);
    }
    assert_eq!(held(&plain.did), Some(false), "no sc/ row: no ref is read");
    off.get_blob(&owner.did, &cid(&private)).await.err(400, "BlobNotFound");
    assert_eq!(off.get_blob(&owner.did, &cid(&shared)).await.status, 200);
    assert_eq!(off.get_blob(&owner.did, &cid(&stray)).await.status, 200, "serve-before-reference, as without spaces");
    let session = off.create_session(&owner.handle, crate::oauth::PASSWORD).await.ok();
    let acct = TestAccount { access: session["accessJwt"].as_str().unwrap().into(), ..legacy(&owner) };
    off.create_record(&acct, "app.bsky.feed.post", image_post("now public", &private)).await;
    assert_eq!(off.get_blob(&owner.did, &cid(&private)).await.status, 200);
}

/// listMissingBlobs counts blobs space records name, merged in CID order
/// with the public ones, each with one record naming it: a move has to
/// bring those over too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_space_blobs_are_listed() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "sbmiss", OWNER).await;
    let space = owner.create_space(TYPE, "main").await;
    let (in_space, _) = upload(&s, &owner, 11).await;
    let (in_public, _) = upload(&s, &owner, 12).await;
    let (in_both, _) = upload(&s, &owner, 13).await;
    let (kept, _) = upload(&s, &owner, 14).await;
    owner.create_record(&space, COLL, Some("a"), rec("a", &[&in_space, &kept])).await.ok();
    owner.create_record(&space, COLL, Some("b"), rec("b", &[&in_both])).await.ok();
    let acct = legacy(&owner);
    let public = s.create_record(&acct, "app.bsky.feed.post", image_post("p", &in_public)).await;
    s.create_record(&acct, "app.bsky.feed.post", image_post("q", &in_both)).await;
    for b in [&in_space, &in_public, &in_both] {
        let path = object_store::path::Path::from(format!("{}/blob/{}/{}", s.app.store.prefix, owner.did, cid(b)));
        s.app.store.raw.delete(&path).await.unwrap();
    }

    let mut want = [
        (cid(&in_space), format!("{space}/{}/{COLL}/a", owner.did)),
        (cid(&in_public), public.uri.clone()),
        (cid(&in_both), String::new()),
    ];
    want.sort();
    let got = s.xrpc.get("com.atproto.repo.listMissingBlobs", &[], &acct.auth()).await.ok();
    let got: Vec<(String, String)> = got["blobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| (b["cid"].as_str().unwrap().to_string(), b["recordUri"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(got.len(), 3, "{got:?}");
    for ((wc, wu), (gc, gu)) in want.iter().zip(&got) {
        assert_eq!(wc, gc, "{got:?}");
        if *wc == cid(&in_both) {
            // a public record names it too: that's the one shown
            assert!(gu.starts_with(&format!("at://{}/app.bsky.feed.post/", owner.did)), "{gu}");
        } else {
            assert_eq!(wu, gu);
        }
    }

    // paged one at a time, the cursor walks both lists
    let mut paged = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut q = vec![("limit", "1".to_string())];
        if let Some(c) = &cursor {
            q.push(("cursor", c.clone()));
        }
        let q: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = s.xrpc.get("com.atproto.repo.listMissingBlobs", &q, &acct.auth()).await.ok();
        let blobs = r["blobs"].as_array().unwrap();
        if blobs.is_empty() {
            break;
        }
        paged.push(blobs[0]["cid"].as_str().unwrap().to_string());
        cursor = r["cursor"].as_str().map(String::from);
    }
    assert_eq!(paged, got.iter().map(|(c, _)| c.clone()).collect::<Vec<_>>());
}

/// sync.getBlob's cost with `--spaces` off for an account no space record
/// names a blob of: a blob a public record names and a fresh upload, timed
/// over HTTP. `cargo test --profile dev-release --test all
/// spaces_blobs::get_blob_flag_off_cost -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "bench"]
async fn get_blob_flag_off_cost() {
    let s = TestServer::spawn_with(|c| c.spaces = false).await;
    let a = s.create_account("gbc").await;
    let public = s.upload_blob(&a, &random_png(1), "image/png").await;
    s.create_record(&a, "app.bsky.feed.post", image_post("p", &public)).await;
    let fresh = s.upload_blob(&a, &random_png(2), "image/png").await;
    let http = reqwest::Client::new();
    for (what, blob) in [("public", &public), ("unreferenced", &fresh)] {
        let url = format!("{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}", s.url, a.did, cid(blob));
        let mut us = Vec::with_capacity(5000);
        for i in 0..5200 {
            let t = std::time::Instant::now();
            let r = http.get(&url).send().await.unwrap();
            assert_eq!(r.status(), 200);
            r.bytes().await.unwrap();
            if i >= 200 {
                us.push(t.elapsed().as_micros() as u64);
            }
        }
        us.sort();
        let p = |q: f64| us[((us.len() - 1) as f64 * q) as usize];
        eprintln!(
            "getBlob {what}: p50 {} us, p99 {} us, mean {} us",
            p(0.5),
            p(0.99),
            us.iter().sum::<u64>() / us.len() as u64
        );
    }
}
