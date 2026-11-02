//! Operator moderation (src/xrpc/moderation.rs, blob_quota.rs): console
//! takedowns with reasons, cases and the audit log, blob quarantine and its
//! expiry, subject lookup, and per-account upload quotas.
use crate::common::*;
use object_store::ObjectStoreExt;
use std::time::Duration;

async fn moderate(s: &TestServer, body: J) -> Resp {
    s.xrpc.post("vlpds.admin.moderate", &body, &Auth::Admin).await
}

async fn object_exists(s: &TestServer, root: &str, did: &str, cid: &str) -> bool {
    let p = object_store::path::Path::from(format!("{}/{root}/{did}/{cid}", s.app.store.prefix));
    s.app.store.raw.head(&p).await.is_ok()
}

fn cid_of(blob: &J) -> String {
    blob["ref"]["$link"].as_str().unwrap().to_string()
}

async fn audit(s: &TestServer, did: &str) -> Vec<J> {
    s.xrpc.get("vlpds.admin.getAuditLog", &[("did", did)], &Auth::Admin).await.ok()["entries"]
        .as_array()
        .unwrap()
        .clone()
}

async fn takedowns(s: &TestServer, kind: &str) -> Vec<J> {
    s.xrpc.get("vlpds.admin.listTakedowns", &[("kind", kind)], &Auth::Admin).await.ok()["takedowns"]
        .as_array()
        .unwrap()
        .clone()
}

async fn quota(s: &TestServer, did: &str) -> J {
    s.xrpc.get("vlpds.admin.getSubject", &[("did", did)], &Auth::Admin).await.ok()["quota"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_takedown_with_a_case_and_audit() {
    let s = TestServer::spawn().await;
    let a = s.create_account("modrec").await;
    let p = s.post(&a, "infringing text").await;
    let keep = s.post(&a, "fine").await;

    let case = s
        .xrpc
        .post(
            "vlpds.admin.createCase",
            &json!({"source": "DMCA notice from Example Studios (email)", "note": "received 2026-10-03"}),
            &Auth::Admin,
        )
        .await
        .ok();
    let id = case["id"].as_str().unwrap().to_string();
    assert_eq!(case["status"], json!("open"));
    assert_eq!(case["notes"].as_array().unwrap().len(), 1);

    // a reason is required
    moderate(&s, json!({"did": a.did, "kind": "record", "uri": p.uri, "action": "takedown", "reason": "  "}))
        .await
        .err(400, "InvalidRequest");
    // an unknown case is refused before anything changes
    moderate(
        &s,
        json!({"did": a.did, "kind": "record", "uri": p.uri, "action": "takedown", "reason": "x", "caseId": "nope"}),
    )
    .await
    .err(400, "CaseNotFound");
    s.get_record(&a.did, p.collection(), p.rkey()).await.ok();

    let r = moderate(&s, json!({"did": a.did, "kind": "record", "uri": p.uri, "action": "takedown", "reason": "copyright: notice 42", "caseId": id})).await.ok();
    assert_eq!(r["applied"], json!(true));
    s.get_record(&a.did, p.collection(), p.rkey()).await.err(400, "RecordNotFound");
    let lr = s.list_records(&a.did, "app.bsky.feed.post", &[]).await.ok();
    let uris: Vec<&str> = lr["records"].as_array().unwrap().iter().map(|r| r["uri"].as_str().unwrap()).collect();
    assert_eq!(uris, vec![keep.uri.as_str()]);
    // the reference status view agrees, with the case as its ref
    let st = s.xrpc.get("com.atproto.admin.getSubjectStatus", &[("uri", &p.uri)], &Auth::Admin).await.ok();
    assert_eq!(st["takedown"]["applied"], json!(true));
    assert_eq!(st["takedown"]["ref"], json!(format!("case:{id}")));

    let td = takedowns(&s, "record").await;
    assert_eq!(td.len(), 1, "{td:?}");
    assert_eq!(td[0]["subject"]["uri"], json!(p.uri));
    assert_eq!(td[0]["reason"], json!("copyright: notice 42"));
    assert_eq!(td[0]["caseId"], json!(id));

    let c = s.xrpc.get("vlpds.admin.getCase", &[("id", &id)], &Auth::Admin).await.ok();
    assert_eq!(c["status"], json!("actioned"));
    assert_eq!(c["subjects"][0]["uri"], json!(p.uri));
    assert_eq!(c["actions"][0]["action"], json!("takedown"));

    // admin details still show the record (and that it is taken down)
    let subj = s.xrpc.get("vlpds.admin.getSubject", &[("did", &a.did), ("uri", &p.uri)], &Auth::Admin).await.ok();
    assert_eq!(subj["record"]["takendown"], json!(true));
    assert_eq!(subj["record"]["value"]["text"], json!("infringing text"));

    moderate(&s, json!({"did": a.did, "kind": "record", "uri": p.uri, "action": "restore", "reason": "counter-notice accepted", "caseId": id})).await.ok();
    s.get_record(&a.did, p.collection(), p.rkey()).await.ok();
    assert!(takedowns(&s, "record").await.is_empty());
    let c = s.xrpc.get("vlpds.admin.getCase", &[("id", &id)], &Auth::Admin).await.ok();
    assert_eq!(c["status"], json!("restored"));
    assert_eq!(c["actions"].as_array().unwrap().len(), 2);

    let log = audit(&s, &a.did).await;
    assert_eq!(log.len(), 2, "{log:?}");
    assert_eq!(log[0]["action"], json!("restore"), "newest first");
    assert_eq!(log[1]["action"], json!("takedown"));
    assert_eq!(log[1]["actor"], json!("admin"));
    assert_eq!(log[1]["ip"], json!("127.0.0.1"));
    assert_eq!(log[1]["reason"], json!("copyright: notice 42"));
    assert_eq!(log[1]["caseId"], json!(id));

    // case edits: notes, status, subjects; bad status refused
    let c = s.xrpc.post("vlpds.admin.updateCase", &json!({"id": id, "note": "closed", "status": "dismissed", "addSubject": {"kind": "account", "did": a.did}}), &Auth::Admin).await.ok();
    assert_eq!(
        (c["status"].clone(), c["notes"].as_array().unwrap().len(), c["subjects"].as_array().unwrap().len()),
        (json!("dismissed"), 2, 2)
    );
    s.xrpc
        .post("vlpds.admin.updateCase", &json!({"id": id, "status": "bogus"}), &Auth::Admin)
        .await
        .err(400, "InvalidRequest");
    let open = s.xrpc.get("vlpds.admin.listCases", &[("status", "open")], &Auth::Admin).await.ok();
    assert!(open["cases"].as_array().unwrap().is_empty());
    let all = s.xrpc.get("vlpds.admin.listCases", &[], &Auth::Admin).await.ok();
    assert_eq!(all["cases"].as_array().unwrap().len(), 1);

    // admin only
    s.xrpc.get("vlpds.admin.listCases", &[], &a.auth()).await.client_err();
    let body = json!({"did": a.did, "kind": "account", "action": "takedown", "reason": "x"});
    s.xrpc.post("vlpds.admin.moderate", &body, &a.auth()).await.client_err();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blob_takedown_quarantines_and_restores() {
    let s = TestServer::spawn().await;
    let a = s.create_account("modblob").await;
    let bytes = random_png(41);
    let blob = s.upload_blob(&a, &bytes, "image/png").await;
    let cid = cid_of(&blob);
    s.create_record(&a, "app.bsky.feed.post", image_post("pic", &blob)).await;
    let before = quota(&s, &a.did).await["bytes"].as_u64().unwrap();

    moderate(&s, json!({"did": a.did, "kind": "blob", "cid": cid, "action": "takedown", "reason": "CSAM report (hash withheld)"})).await.ok();
    assert!(!object_exists(&s, "blob", &a.did, &cid).await, "moved out of blob/");
    assert!(object_exists(&s, "blob-quarantine", &a.did, &cid).await, "kept in quarantine");
    s.get_blob(&a.did, &cid).await.err(400, "BlobNotFound");
    // the operator can still review it
    let r = s.xrpc.get("com.atproto.sync.getBlob", &[("did", &a.did), ("cid", &cid)], &Auth::Admin).await;
    assert_eq!(r.status, 200);
    assert_eq!(&r.body[..], &bytes[..]);

    // re-uploading refuses and leaves blob/ empty
    let r = s.xrpc.post_bytes("com.atproto.repo.uploadBlob", bytes.clone(), "image/png", &a.auth()).await;
    r.err(400, "InvalidRequest");
    assert!(!object_exists(&s, "blob", &a.did, &cid).await);
    // not "missing" for the user to fix
    let missing = s.xrpc.get("com.atproto.repo.listMissingBlobs", &[], &a.auth()).await.ok();
    assert!(missing["blobs"].as_array().unwrap().is_empty(), "{missing}");
    // the blob GC leaves it alone, and it still counts toward the quota
    vlpds::xrpc::blobs::sweep_blobs_settle(&s.app, Duration::ZERO, Duration::ZERO).await.unwrap();
    assert!(object_exists(&s, "blob-quarantine", &a.did, &cid).await);
    assert_eq!(quota(&s, &a.did).await["bytes"].as_u64().unwrap(), before);

    let subj = s.xrpc.get("vlpds.admin.getSubject", &[("did", &a.did), ("cid", &cid)], &Auth::Admin).await.ok();
    assert_eq!(
        (subj["blob"]["takendown"].clone(), subj["blob"]["quarantined"].clone(), subj["blob"]["stored"].clone()),
        (json!(true), json!(true), json!(false))
    );
    assert_eq!(subj["blob"]["mimeType"], json!("image/png"));
    assert!(subj["blob"]["purgeAfterMs"].as_u64().unwrap() > 0);
    let td = takedowns(&s, "blob").await;
    assert_eq!(td[0]["quarantined"], json!(true));

    moderate(&s, json!({"did": a.did, "kind": "blob", "cid": cid, "action": "restore", "reason": "false report"}))
        .await
        .ok();
    assert!(object_exists(&s, "blob", &a.did, &cid).await);
    assert!(!object_exists(&s, "blob-quarantine", &a.did, &cid).await);
    let r = s.get_blob(&a.did, &cid).await;
    assert_eq!(&r.body[..], &bytes[..]);
    s.create_record(&a, "app.bsky.feed.post", image_post("again", &blob)).await;
    assert!(takedowns(&s, "blob").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quarantine_expires() {
    let s = TestServer::spawn().await;
    let a = s.create_account("modexp").await;
    let bytes = random_png(42);
    let blob = s.upload_blob(&a, &bytes, "image/png").await;
    let cid = cid_of(&blob);
    s.create_record(&a, "app.bsky.feed.post", image_post("pic", &blob)).await;
    let before = quota(&s, &a.did).await["bytes"].as_u64().unwrap();
    // takedowns through the reference endpoint quarantine too (and are audited)
    let subject = json!({"$type": "com.atproto.admin.defs#repoBlobRef", "did": a.did, "cid": cid});
    s.xrpc
        .post(
            "com.atproto.admin.updateSubjectStatus",
            &json!({"subject": subject, "takedown": {"applied": true, "ref": "ozone-1"}}),
            &Auth::Admin,
        )
        .await
        .ok();
    assert!(object_exists(&s, "blob-quarantine", &a.did, &cid).await);
    assert_eq!(audit(&s, &a.did).await[0]["action"], json!("takedown"));

    assert_eq!(
        vlpds::xrpc::moderation::sweep_quarantine(&s.app, Duration::from_secs(3600)).await.unwrap(),
        0,
        "not old enough"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(vlpds::xrpc::moderation::sweep_quarantine(&s.app, Duration::from_millis(10)).await.unwrap(), 1);
    assert!(!object_exists(&s, "blob-quarantine", &a.did, &cid).await, "purged");
    assert!(!object_exists(&s, "blob", &a.did, &cid).await);
    assert_eq!(quota(&s, &a.did).await["bytes"].as_u64().unwrap(), before - bytes.len() as u64);
    // still taken down: no re-upload
    s.xrpc
        .post_bytes("com.atproto.repo.uploadBlob", bytes.clone(), "image/png", &a.auth())
        .await
        .err(400, "InvalidRequest");
    let log = audit(&s, &a.did).await;
    assert_eq!(log[0]["action"], json!("blob.purge"));
    assert_eq!(log[0]["actor"], json!("system"));

    // a restore after the purge only lifts the takedown; the user may upload again
    let r = moderate(&s, json!({"did": a.did, "kind": "blob", "cid": cid, "action": "restore", "reason": "appeal"}))
        .await
        .ok();
    assert_eq!(r["result"]["bytesRestored"], json!(false));
    s.upload_blob(&a, &bytes, "image/png").await;
    assert_eq!(s.get_blob(&a.did, &cid).await.status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_takedown_and_lookup() {
    let s = TestServer::spawn().await;
    let a = s.create_account("modacct").await;
    let p = s.post(&a, "hello").await;
    let blob = s.upload_blob(&a, &random_png(43), "image/png").await;
    let cid = cid_of(&blob);
    let resolve = |q: String| {
        let s = &s;
        async move { s.xrpc.get("vlpds.admin.resolveSubject", &[("q", &q)], &Auth::Admin).await }
    };

    let r = resolve(format!("https://bsky.app/profile/{}", a.handle)).await.ok();
    assert_eq!((r["kind"].clone(), r["did"].clone()), (json!("account"), json!(a.did)));
    let r = resolve(format!("https://bsky.app/profile/{}/post/{}", a.handle, p.rkey())).await.ok();
    assert_eq!((r["kind"].clone(), r["uri"].clone()), (json!("record"), json!(p.uri)));
    let r = resolve(format!("https://bsky.app/profile/{}/post/{}", a.did, p.rkey())).await.ok();
    assert_eq!(r["uri"], json!(p.uri));
    let r = resolve(p.uri.clone()).await.ok();
    assert_eq!(r["kind"], json!("record"));
    let r = resolve(format!("@{}", a.handle.to_uppercase())).await.ok();
    assert_eq!(r["did"], json!(a.did));
    let r = resolve(format!("{} {cid}", a.did)).await.ok();
    assert_eq!((r["kind"].clone(), r["cid"].clone()), (json!("blob"), json!(cid)));
    resolve("https://bsky.app/profile/someone.bsky.social/post/3k".into()).await.err(400, "NotHostedHere");
    resolve("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into()).await.err(400, "NotHostedHere");
    resolve("not a thing".into()).await.err(400, "InvalidRequest");

    moderate(
        &s,
        json!({"did": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "kind": "account", "action": "takedown", "reason": "x"}),
    )
    .await
    .err(400, "NotHostedHere");
    moderate(&s, json!({"did": a.did, "kind": "account", "action": "takedown", "reason": "spam network"})).await.ok();
    s.create_session(&a.handle, PASSWORD).await.err(401, "AccountTakedown");
    let subj = s.xrpc.get("vlpds.admin.getSubject", &[("did", &a.did)], &Auth::Admin).await.ok();
    assert_eq!(subj["account"]["takedown"]["applied"], json!(true));
    assert_eq!(subj["account"]["status"], json!("takendown"));
    assert_eq!(takedowns(&s, "account").await.len(), 1);
    moderate(&s, json!({"did": a.did, "kind": "account", "action": "restore", "reason": "mistake"})).await.ok();
    s.create_session(&a.handle, PASSWORD).await.ok();
    assert!(takedowns(&s, "account").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_quotas() {
    let s = TestServer::spawn_with(|c| c.blob_uploads_per_day = 3).await;
    let a = s.create_account("quota").await;
    let pngs: Vec<Vec<u8>> = (0..5).map(|i| random_png(60 + i)).collect();
    for p in &pngs[..3] {
        s.upload_blob(&a, p, "image/png").await;
    }
    let r = s.xrpc.post_bytes("com.atproto.repo.uploadBlob", pngs[3].clone(), "image/png", &a.auth()).await;
    r.err(429, "RateLimitExceeded");
    let q = quota(&s, &a.did).await;
    let used: u64 = pngs[..3].iter().map(|p| p.len() as u64).sum();
    assert_eq!(
        (q["bytes"].as_u64(), q["uploadsToday"].as_u64(), q["limitUploadsPerDay"].as_u64()),
        (Some(used), Some(3), Some(3))
    );

    // per-account override: unlimited uploads, a byte quota just above usage
    // (one byte of room: a quota exactly full refuses before reading the body)
    let limit = used + pngs[3].len() as u64 + 1;
    let q = s
        .xrpc
        .post(
            "vlpds.admin.setBlobQuota",
            &json!({"did": a.did, "bytes": limit, "uploadsPerDay": 0, "reason": "trial"}),
            &Auth::Admin,
        )
        .await
        .ok();
    assert_eq!(q["limitBytes"].as_u64(), Some(limit));
    s.upload_blob(&a, &pngs[3], "image/png").await;
    let r = s.xrpc.post_bytes("com.atproto.repo.uploadBlob", pngs[4].clone(), "image/png", &a.auth()).await;
    r.err(413, "BlobQuotaExceeded");
    assert!(r.json["message"].as_str().unwrap().contains("quota"), "{}", r.text());
    // bytes already stored add nothing, though a Content-Length past what's
    // left is refused before the body is read
    let r = s.xrpc.post_bytes("com.atproto.repo.uploadBlob", pngs[0].clone(), "image/png", &a.auth()).await;
    r.err(413, "BlobQuotaExceeded");
    upload_streamed_bytes(&s, &a, pngs[0].clone()).await.expect("streamed").ok();
    assert_eq!(quota(&s, &a.did).await["bytes"].as_u64(), Some(limit - 1));
    assert_eq!(audit(&s, &a.did).await[0]["action"], json!("quota.set"));

    // the GC frees what nothing references
    vlpds::xrpc::blobs::sweep_blobs_settle(&s.app, Duration::ZERO, Duration::ZERO).await.unwrap();
    assert_eq!(quota(&s, &a.did).await["bytes"].as_u64(), Some(0));
    s.upload_blob(&a, &pngs[4], "image/png").await;

    // back to the defaults
    let q = s.xrpc.post("vlpds.admin.setBlobQuota", &json!({"did": a.did}), &Auth::Admin).await.ok();
    assert_eq!(q["limitUploadsPerDay"].as_u64(), Some(3));
    assert_eq!(q["override"], json!({}));
}

async fn upload_sized(s: &TestServer, a: &TestAccount, n: usize) -> Resp {
    s.xrpc.post_bytes("com.atproto.repo.uploadBlob", random_bytes(n), "image/jpeg", &a.auth()).await
}

/// Streamed in 1 KB chunks with no Content-Length. None: the server answered
/// before taking the whole body and closed (as it may for one over the limit).
async fn upload_streamed(s: &TestServer, a: &TestAccount, n: usize) -> Option<Resp> {
    upload_streamed_bytes(s, a, random_bytes(n)).await
}

async fn upload_streamed_bytes(s: &TestServer, a: &TestAccount, body: Vec<u8>) -> Option<Resp> {
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> = body.chunks(1000).map(|c| Ok(c.to_vec())).collect();
    let rb = s
        .xrpc
        .http
        .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", s.xrpc.base))
        .header("content-type", "image/jpeg")
        .header("authorization", format!("Bearer {}", a.access))
        .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks)));
    s.xrpc.try_send(rb).await.ok()
}

/// The largest blob an account may upload, `maxBlobBytes` or the default,
/// both declared and streamed. Refusals store nothing, so the account's
/// stored bytes show what got in.
async fn assert_max_blob(s: &TestServer, a: &TestAccount, max: usize) {
    let before = quota(s, &a.did).await["bytes"].as_u64().unwrap();
    let r = upload_sized(s, a, max + 1).await;
    r.err(413, "PayloadTooLarge");
    assert!(r.json["message"].as_str().unwrap().contains(&format!("max {max} bytes")), "{}", r.text());
    if let Some(r) = upload_streamed(s, a, max + 1).await {
        r.err(413, "PayloadTooLarge");
    }
    assert_eq!(quota(s, &a.did).await["bytes"].as_u64().unwrap(), before, "a refused upload stored bytes");
    upload_sized(s, a, max).await.ok();
    upload_streamed(s, a, max).await.expect("streamed upload at the limit").ok();
    let q = quota(s, &a.did).await;
    assert_eq!(
        (q["bytes"].as_u64(), q["limitMaxBlobBytes"].as_u64()),
        (Some(before + 2 * max as u64), Some(max as u64))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_account_max_blob_size() {
    let s = TestServer::spawn_with(|c| {
        c.max_blob_size = 10_000;
        c.max_blob_override = 60_000;
    })
    .await;
    let a = s.create_account("bigblobs").await;
    let b = s.create_account("smallblobs").await;
    let set = |body: J| s.xrpc.post_owned("vlpds.admin.setBlobQuota", body, Auth::Admin);

    let q = quota(&s, &a.did).await;
    assert_eq!((q["defaults"]["maxBlobBytes"].as_u64(), q["maxBlobCeiling"].as_u64()), (Some(10_000), Some(60_000)));
    assert_max_blob(&s, &a, 10_000).await;

    // raised for one account (a paid plan); the other keeps the default
    let q = set(json!({"did": a.did, "maxBlobBytes": 50_000, "reason": "paid plan"})).await.ok();
    assert_eq!(
        (q["limitMaxBlobBytes"].as_u64(), q["override"].clone()),
        (Some(50_000), json!({"maxBlobBytes": 50_000}))
    );
    let e = &audit(&s, &a.did).await[0];
    assert_eq!(
        (&e["action"], &e["reason"], &e["detail"]),
        (&json!("quota.set"), &json!("paid plan"), &json!({"maxBlobBytes": 50_000}))
    );
    assert_max_blob(&s, &a, 50_000).await;
    assert_max_blob(&s, &b, 10_000).await;

    // lowered
    set(json!({"did": a.did, "maxBlobBytes": 5_000})).await.ok();
    assert_max_blob(&s, &a, 5_000).await;

    // no 0 (unlimited) and nothing past --max-blob-override-mb; a refusal
    // changes nothing
    set(json!({"did": a.did, "maxBlobBytes": 0})).await.err(400, "InvalidRequest");
    let r = set(json!({"did": a.did, "maxBlobBytes": 60_001})).await;
    r.err(400, "InvalidRequest");
    assert!(r.json["message"].as_str().unwrap().contains("--max-blob-override-mb"), "{}", r.text());
    assert_eq!(quota(&s, &a.did).await["limitMaxBlobBytes"].as_u64(), Some(5_000));
    let q = set(json!({"did": a.did, "maxBlobBytes": 60_000})).await.ok();
    assert_eq!(q["limitMaxBlobBytes"].as_u64(), Some(60_000));

    // an override that leaves it out, or none at all, is back to the default
    let q = set(json!({"did": a.did, "uploadsPerDay": 100})).await.ok();
    assert_eq!((q["limitMaxBlobBytes"].as_u64(), q["override"].clone()), (Some(10_000), json!({"uploadsPerDay": 100})));
    set(json!({"did": a.did, "maxBlobBytes": 50_000})).await.ok();
    let q = set(json!({"did": a.did})).await.ok();
    assert_eq!((q["limitMaxBlobBytes"].as_u64(), q["override"].clone()), (Some(10_000), json!({})));
    assert_max_blob(&s, &a, 10_000).await;

    // an override stored above the cap (set before the operator lowered
    // --max-blob-override-mb) is held to the cap
    let row = json!({"maxBlobBytes": 90_000});
    s.app
        .put_private(
            &a.did,
            vec![vlsync_store::segment::Mutation {
                key: vlpds::state::private_key(&a.did, "bq/limit").into(),
                val: Some(serde_json::to_vec(&row).unwrap().into()),
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("put_private: {}", e.message));
    assert_max_blob(&s, &a, 60_000).await;
}

/// Without --max-blob-override-mb the cap is --max-blob-mb: an override can
/// lower an account's largest blob but not raise it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raising_the_largest_blob_is_opt_in() {
    let s = TestServer::spawn_with(|c| {
        c.max_blob_size = 10_000;
        c.max_blob_override = 10_000;
    })
    .await;
    let a = s.create_account("nooptin").await;
    let set = |body: J| s.xrpc.post_owned("vlpds.admin.setBlobQuota", body, Auth::Admin);
    assert_eq!(quota(&s, &a.did).await["maxBlobCeiling"].as_u64(), Some(10_000));
    set(json!({"did": a.did, "maxBlobBytes": 10_001})).await.err(400, "InvalidRequest");
    set(json!({"did": a.did, "maxBlobBytes": 4_000})).await.ok();
    assert_max_blob(&s, &a, 4_000).await;
}

/// A Content-Length past the account's remaining byte quota is refused
/// before the body is read, with the quota's error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_size_past_the_quota_is_refused_early() {
    let s = TestServer::spawn().await;
    let a = s.create_account("quotaearly").await;
    let first = upload_sized(&s, &a, 3_000).await.ok();
    assert_eq!(first["blob"]["size"], json!(3_000));
    s.xrpc.post("vlpds.admin.setBlobQuota", &json!({"did": a.did, "bytes": 5_000}), &Auth::Admin).await.ok();
    let r = upload_sized(&s, &a, 2_001).await;
    r.err(413, "BlobQuotaExceeded");
    assert!(r.json["message"].as_str().unwrap().contains("this blob is 2001 bytes"), "{}", r.text());
    assert_eq!(quota(&s, &a.did).await["bytes"].as_u64(), Some(3_000));
    upload_sized(&s, &a, 2_000).await.ok();
    assert_eq!(quota(&s, &a.did).await["bytes"].as_u64(), Some(5_000));
}

/// An account moving in uploads the blobs its imported repo references past
/// the daily count and the byte quota (flagged, not refused); anything else
/// it uploads is held to them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migrating_accounts_are_not_blocked() {
    let s = TestServer::spawn_with(|c| c.blob_uploads_per_day = 1).await;
    let a = s.create_account("quotamig").await;
    let pngs: Vec<Vec<u8>> = (0..3).map(|i| random_png(70 + i)).collect();
    let blob = s.upload_blob(&a, &pngs[0], "image/png").await;
    s.create_record(&a, "app.bsky.feed.post", image_post("pic", &blob)).await;
    let car = s.get_repo_car(&a.did).await;
    // the account "arrives" without its blob
    let p = object_store::path::Path::from(format!("{}/blob/{}/{}", s.app.store.prefix, a.did, cid_of(&blob)));
    s.app.store.raw.delete(&p).await.unwrap();
    vlpds::xrpc::blobs::sweep_blobs_settle(&s.app, Duration::ZERO, Duration::ZERO).await.unwrap();
    s.xrpc.post("vlpds.admin.setBlobQuota", &json!({"did": a.did, "bytes": 10}), &Auth::Admin).await.ok();
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &a.auth()).await.ok();
    s.import_repo(&a.auth(), car).await.ok();
    let missing = s.xrpc.get("com.atproto.repo.listMissingBlobs", &[], &a.auth()).await.ok();
    assert_eq!(missing["blobs"].as_array().unwrap().len(), 1, "{missing}");

    // over the daily count (1 used) and the 10-byte quota: still accepted
    s.upload_blob(&a, &pngs[0], "image/png").await;
    let q = quota(&s, &a.did).await;
    assert_eq!(q["over"], json!(true), "{q}");
    let over = s.xrpc.get("vlpds.admin.listOverQuota", &[], &Auth::Admin).await.ok();
    assert_eq!(over["accounts"][0]["did"], json!(a.did));
    // an unreferenced blob is held to the quota (daily count lifted to see the byte check)
    s.xrpc
        .post("vlpds.admin.setBlobQuota", &json!({"did": a.did, "bytes": 10, "uploadsPerDay": 0}), &Auth::Admin)
        .await
        .ok();
    let r = s.xrpc.post_bytes("com.atproto.repo.uploadBlob", pngs[1].clone(), "image/png", &a.auth()).await;
    r.err(413, "BlobQuotaExceeded");
    // raising the quota clears the flag
    s.xrpc.post("vlpds.admin.setBlobQuota", &json!({"did": a.did, "bytes": 0}), &Auth::Admin).await.ok();
    let over = s.xrpc.get("vlpds.admin.listOverQuota", &[], &Auth::Admin).await.ok();
    assert!(over["accounts"].as_array().unwrap().is_empty());
}
