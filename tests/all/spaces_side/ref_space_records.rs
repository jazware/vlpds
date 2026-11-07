//! Ported from the reference's `tests/space/records.test.ts` (5b95b2f2):
//! reading and writing records in a space. Each test names its reference
//! case.
//!
//! The reference adds members to most spaces here. A member's PDS never
//! consults the member list on a write (only the authority does, on
//! notifyWrite), so membership is added only where a test reads with a
//! credential, which keeps the write and read cases runnable from C1.
//! Accounts are OAuth clients (space data is OAuth-only in vlpds).

use super::ref_net::*;
use crate::common::*;

/// "writes a record as a co-located member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_a_record_as_a_co_located_member() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let before = repo_state(&dan, &space).await;

    let created = write(&dan, &space, W::new().text("hello from dan")).await.ok();
    assert!(created["uri"].as_str().unwrap().contains(&dan.did));
    let rkey = last_segment(created["uri"].as_str().unwrap()).to_string();
    let got = dan
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &dan.did), ("collection", TEST_COLLECTION), ("rkey", &rkey)],
        )
        .await
        .ok();
    assert_eq!(got["value"]["text"], json!("hello from dan"));

    let after = repo_state(&dan, &space).await.expect("written");
    assert_ne!(Some(&after.0), before.as_ref().map(|b| &b.0), "a new rev");
    assert_ne!(Some(&after.1), before.as_ref().map(|b| &b.1), "a new set hash");
    expect_set_hash_matches_store(&dan, &space).await;
}

/// "writes a record from a remote PDS"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_a_record_from_a_remote_pds() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;

    let created = write(&bob, &space, W::new().text("hello from bob")).await.ok();
    assert!(created["uri"].as_str().unwrap().contains(&bob.did));
    let ops = bob.get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &bob.did)]).await.ok();
    let last = ops["ops"].as_array().unwrap().last().unwrap().clone();
    // A create names a cid and no prev; the wire op carries no action.
    assert_eq!(last["cid"], created["cid"]);
    assert!(last["prev"].is_null(), "{last}");
    assert!(last.get("action").is_none(), "{last}");

    // listSpaces on a member's PDS lists spaces written to, not joined.
    let listed = bob.get("com.atproto.space.listSpaces", &[]).await.ok();
    let uris: Vec<&str> = listed["spaces"].as_array().unwrap().iter().filter_map(|s| s["uri"].as_str()).collect();
    assert!(uris.contains(&space.as_str()), "{listed}");
}

/// "refuses a write to another account repo"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_write_to_another_account_repo() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let r = dan
        .post(
            "com.atproto.space.createRecord",
            json!({"space": space, "repo": alice.did, "collection": TEST_COLLECTION, "record": record(TEST_COLLECTION, "x")}),
        )
        .await;
    r.err(403, "Forbidden");
}

/// "deletes a record"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deletes_a_record() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let created = write(&dan, &space, W::new().text("to be deleted")).await.ok();
    let rkey = last_segment(created["uri"].as_str().unwrap()).to_string();
    del(&dan, &space, None, &rkey).await.ok();

    let ops = dan.get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &dan.did)]).await.ok();
    let deleted = ops["ops"].as_array().unwrap().iter().find(|o| o["cid"].is_null()).expect("a delete op").clone();
    assert_eq!(deleted["rkey"], json!(rkey));
    // The delete names what it replaced, so a syncer can subtract it.
    assert_eq!(deleted["prev"], created["cid"]);
    expect_set_hash_matches_store(&dan, &space).await;
}

/// "deleteRecord is idempotent"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_record_is_idempotent() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    del(&alice, &space, None, "gone").await.ok();
    write(&alice, &space, W::new().rkey("gone").text("here")).await.ok();
    del(&alice, &space, None, "gone").await.ok();
    del(&alice, &space, None, "gone").await.ok();
}

/// putRecord: "creates a record that does not yet exist"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_record_creates_a_record_that_does_not_yet_exist() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let p = put(&dan, &space, W::new().rkey("put-new").text("first")).await.ok();
    assert_eq!(p["uri"], json!(format!("{space}/{}/{TEST_COLLECTION}/put-new", dan.did)));
    let got = dan
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &dan.did), ("collection", TEST_COLLECTION), ("rkey", "put-new")],
        )
        .await
        .ok();
    assert_eq!(got["value"]["text"], json!("first"));
}

/// putRecord: "overwrites an existing record, and the oplog names what it
/// replaced"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_record_overwrites_and_the_oplog_names_what_it_replaced() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let created = put(&dan, &space, W::new().rkey("put-over").text("first")).await.ok();
    let updated = put(&dan, &space, W::new().rkey("put-over").text("second")).await.ok();
    assert_ne!(updated["cid"], created["cid"]);

    let got = dan
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &dan.did), ("collection", TEST_COLLECTION), ("rkey", "put-over")],
        )
        .await
        .ok();
    assert_eq!(got["value"]["text"], json!("second"));

    // An update is a remove-then-add against the set hash.
    let ops = dan.get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &dan.did)]).await.ok();
    let last = ops["ops"].as_array().unwrap().last().unwrap().clone();
    assert_eq!((&last["cid"], &last["prev"]), (&updated["cid"], &created["cid"]));
    expect_set_hash_matches_store(&dan, &space).await;

    let listed = dan
        .get("com.atproto.space.listRecords", &[("space", &space), ("repo", &dan.did), ("collection", TEST_COLLECTION)])
        .await
        .ok();
    assert_eq!(listed["records"].as_array().unwrap().len(), 1);
}

/// applyWrites: "applies a batch as one rev"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_writes_applies_a_batch_as_one_rev() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let writes: Vec<J> = (0..3).map(|i| create_op(&format!("batch-{i}"), &format!("batch {i}"))).collect();
    dan.apply_writes(&space, json!(writes)).await.ok();

    let ops = dan.get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &dan.did)]).await.ok();
    let ops = ops["ops"].as_array().unwrap();
    let revs: std::collections::BTreeSet<&str> = ops.iter().map(|o| o["rev"].as_str().unwrap()).collect();
    assert_eq!(revs.len(), 1, "one batch, one rev");
    let rkeys: Vec<&str> = ops.iter().map(|o| o["rkey"].as_str().unwrap()).collect();
    assert_eq!(rkeys, ["batch-0", "batch-1", "batch-2"]);
}

/// applyWrites: "rejects a duplicate create within one batch"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_writes_rejects_a_duplicate_create_within_one_batch() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let r = dan.apply_writes(&space, json!([create_op("dupe", "one"), create_op("dupe", "two")])).await;
    r.err(400, "RecordAlreadyExists");
    expect_set_hash_matches_store(&dan, &space).await;
}

/// applyWrites: "applies dependent writes within one batch"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_writes_applies_dependent_writes_within_one_batch() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let writes = json!([
        create_op("dependent", "first"),
        {"$type": "com.atproto.space.applyWrites#update", "collection": TEST_COLLECTION, "rkey": "dependent", "value": record(TEST_COLLECTION, "second")},
        create_op("survivor", "survivor"),
        {"$type": "com.atproto.space.applyWrites#delete", "collection": TEST_COLLECTION, "rkey": "dependent"},
    ]);
    dan.apply_writes(&space, writes).await.ok();
    let rkeys: Vec<String> =
        all_records(&dan, &space).await.iter().map(|r| r["rkey"].as_str().unwrap().to_string()).collect();
    assert_eq!(rkeys, ["survivor"]);
    expect_set_hash_matches_store(&dan, &space).await;
}

/// applyWrites: "treats an empty batch as a no-op"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_writes_treats_an_empty_batch_as_a_no_op() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let r = dan.apply_writes(&space, json!([])).await.ok();
    assert_eq!(r["results"], json!([]));
    // No head: a rev with no op behind it would read as state a syncer
    // never received.
    assert_eq!(repo_state(&dan, &space).await, None);
    dan.get("com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &dan.did)])
        .await
        .err(400, "RepoNotFound");
}

/// applyWrites: "reports each result against the write it came from"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_writes_reports_each_result_against_its_write() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&dan, &space, W::new().rkey("doomed").text("doomed")).await.ok();
    let res = dan
        .apply_writes(
            &space,
            json!([
                create_op("first", "first"),
                {"$type": "com.atproto.space.applyWrites#delete", "collection": TEST_COLLECTION, "rkey": "doomed"},
                create_op("last", "last"),
            ]),
        )
        .await
        .ok();
    let results = res["results"].as_array().unwrap();
    assert_eq!(results[1]["$type"], json!("com.atproto.space.applyWrites#deleteResult"));
    assert_eq!(results[0]["uri"], json!(format!("{space}/{}/{TEST_COLLECTION}/first", dan.did)));
    assert_eq!(results[2]["uri"], json!(format!("{space}/{}/{TEST_COLLECTION}/last", dan.did)));
    // A third-party collection: both creates report unknown, on themselves.
    assert_eq!(results[0]["validationStatus"], json!("unknown"));
    assert_eq!(results[2]["validationStatus"], json!("unknown"));
}

/// applyWrites: "refuses a batch over the write limit"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_writes_refuses_a_batch_over_the_write_limit() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let writes: Vec<J> = (0..201).map(|i| create_op(&format!("over-{i}"), &format!("over {i}"))).collect();
    let r = dan.apply_writes(&space, json!(writes)).await;
    refused_mentioning(&r, &["Too many writes"]);
}

/// applyWrites: "refuses an unrecognized write type at the schema"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_writes_refuses_an_unrecognized_write_type() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let r = dan.apply_writes(&space, json!([{"$type": "com.example.somethingElse"}])).await;
    r.err(400, "InvalidRequest");
}

/// validation: "rejects a record whose $type disagrees with its collection"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_a_record_whose_type_disagrees_with_its_collection() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let r = write(&alice, &space, W::new().record(record(TEST_COLLECTION_ALT, "mismatched"))).await;
    r.err(400, "InvalidRequest");
}

/// validation: "reports unknown for a collection with no resolvable schema"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_unknown_for_a_collection_with_no_resolvable_schema() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let created = write(&alice, &space, W::new().text("unvalidatable")).await.ok();
    assert_eq!(created["validationStatus"], json!("unknown"));
}

/// validation: "refuses an unvalidatable record when validation is demanded"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_unvalidatable_record_when_validation_is_demanded() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&alice, &space, W::new().text("strict").validate(true)).await.client_err();
}

/// validation: "refuses a record over the size limit". Divergent: vlpds
/// caps a space record's encoding at 1,000,000 bytes, as its public repo
/// writes are capped, where the reference allows 1 MiB (1,048,576). As in
/// the reference, a request body that large is refused before the record
/// is encoded (413 here), so the port checks a record just under the cap
/// goes in and one at it doesn't.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_record_over_the_size_limit() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let r = write(&alice, &space, W::new().text(&"x".repeat(1_000_000))).await;
    assert!(r.status == 413 || r.text().contains("record too large"), "{}", r.text());
    write(&alice, &space, W::new().text(&"x".repeat(990_000))).await.ok();
}

/// listRecords: "paginates across collections"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_records_paginates_across_collections() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&dan, &space, W::new().collection(TEST_COLLECTION).rkey("a").text("post")).await.ok();
    write(&dan, &space, W::new().collection(TEST_COLLECTION_ALT).rkey("b").text("note")).await.ok();

    let page = |cursor: Option<String>| {
        let (dan, space) = (&dan, &space);
        async move {
            let mut q = vec![("space", space.as_str()), ("repo", dan.did.as_str()), ("limit", "1")];
            if let Some(c) = &cursor {
                q.push(("cursor", c.as_str()));
            }
            dan.get("com.atproto.space.listRecords", &q).await.ok()
        }
    };
    let first = page(None).await;
    assert_eq!(first["records"].as_array().unwrap().len(), 1);
    let c1 = first["cursor"].as_str().expect("a cursor").to_string();
    let second = page(Some(c1)).await;
    assert_eq!(second["records"].as_array().unwrap().len(), 1);
    assert_ne!(second["records"][0]["collection"], first["records"][0]["collection"], "the cursor spans collections");
    let third = page(second["cursor"].as_str().map(String::from)).await;
    assert_eq!(third["records"], json!([]));
}

/// listRecords: "filters to one collection"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_records_filters_to_one_collection() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&dan, &space, W::new().collection(TEST_COLLECTION).rkey("a")).await.ok();
    write(&dan, &space, W::new().collection(TEST_COLLECTION_ALT).rkey("b")).await.ok();
    let listed = dan
        .get(
            "com.atproto.space.listRecords",
            &[("space", &space), ("repo", &dan.did), ("collection", TEST_COLLECTION_ALT)],
        )
        .await
        .ok();
    let recs = listed["records"].as_array().unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["collection"], json!(TEST_COLLECTION_ALT));
}

/// listRecords: "reverses the listing order"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_records_reverses_the_listing_order() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    for k in ["aaa", "bbb", "ccc"] {
        write(&dan, &space, W::new().rkey(k)).await.ok();
    }
    let list = |reverse: bool| {
        let (dan, space) = (&dan, &space);
        async move {
            let mut q = vec![("space", space.as_str()), ("repo", dan.did.as_str()), ("collection", TEST_COLLECTION)];
            if reverse {
                q.push(("reverse", "true"));
            }
            let r = dan.get("com.atproto.space.listRecords", &q).await.ok();
            r["records"].as_array().unwrap().iter().map(|x| x["rkey"].as_str().unwrap().to_string()).collect::<Vec<_>>()
        }
    };
    let mut forward = list(false).await;
    assert_eq!(forward.len(), 3);
    forward.reverse();
    assert_eq!(list(true).await, forward);
}

/// listRecords: "scopes a listing to one space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_records_scopes_a_listing_to_one_space() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts { skey: Some("scope-a"), ..Default::default() }).await;
    let other = net.create_space(&alice, SpaceOpts { skey: Some("scope-b"), ..Default::default() }).await;
    write(&alice, &space, W::new().rkey("here")).await.ok();
    let listed = alice.get("com.atproto.space.listRecords", &[("space", &other), ("repo", &alice.did)]).await.ok();
    assert_eq!(listed["records"], json!([]));
}

/// getRecord: "returns the record and its current cid"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_record_returns_the_record_and_its_current_cid() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let created = write(&alice, &space, W::new().rkey("by-cid")).await.ok();
    let got = alice
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &alice.did), ("collection", TEST_COLLECTION), ("rkey", "by-cid")],
        )
        .await
        .ok();
    assert_eq!(got["cid"], created["cid"]);
    assert_eq!(got["uri"], json!(format!("{space}/{}/{TEST_COLLECTION}/by-cid", alice.did)));
}

/// getRecord: "reports RecordNotFound for a record that never existed"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_record_reports_record_not_found() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    write(&alice, &space, W::new().rkey("present")).await.ok();
    alice
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &alice.did), ("collection", TEST_COLLECTION), ("rkey", "absent")],
        )
        .await
        .err(400, "RecordNotFound");
}

// ---------------------------------------------------------------------------
// blobs (C5). The reference reads its blob store directly to see bytes
// held or dropped. Here a blob is "held" while space.getBlob serves it to
// a member and gone once it doesn't (GC timing is blobs.rs's own tests').
// ---------------------------------------------------------------------------

fn image_record(text: &str, blob: &J) -> J {
    json!({"$type": TEST_COLLECTION, "text": text, "image": blob})
}

async fn space_get_blob(net: &Net, cred: &Cred, space: &str, repo: &str, cid: &str) -> Resp {
    cred.get(&net.host_of(repo), "com.atproto.space.getBlob", &[("space", space), ("repo", repo), ("cid", cid)]).await
}

/// blobs: "tracks a blob on a space record and serves it to a member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_tracks_a_blob_and_serves_it_to_a_member() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let bytes = [1u8, 2, 3, 4, 5];
    let blob = upload_blob(&alice, &bytes).await;
    let cid = blob_cid(&blob);
    write(&alice, &space, W::new().rkey("with-blob").record(image_record("has a blob", &blob))).await.ok();

    let cred = net.credential_for(&carol, &space).await;
    let listed =
        cred.get(&net.pds[0].url, "com.atproto.space.listBlobs", &[("space", &space), ("repo", &alice.did)]).await;
    assert_eq!(listed.ok()["cids"], json!([cid]));
    let r = space_get_blob(&net, &cred, &space, &alice.did, &cid).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(&r.body[..], &bytes);
}

/// blobs: "does not serve a space-only blob through public sync"
/// (vlpds: the reference's rule applies with --spaces on; see
/// [`flag_off_serves_an_unreferenced_upload`])
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_does_not_serve_a_space_only_blob_through_public_sync() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let blob = upload_blob(&alice, &[5, 4, 3, 2, 1]).await;
    let cid = blob_cid(&blob);
    write(&alice, &space, W::new().rkey("private-blob").record(image_record("private", &blob))).await.ok();
    assert!(!net.pds[0].list_blobs(&alice.did).await.contains(&cid));
    public_get_blob(&net.pds[0].url, &alice.did, &cid).await.err(400, "BlobNotFound");
}

/// With --spaces off, an uploaded blob nothing references yet is still
/// served by sync.getBlob (vlpds's serve-before-reference, unchanged).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flag_off_serves_an_unreferenced_upload() {
    let s = TestServer::spawn().await;
    let a = s.create_account("fo").await;
    let blob = s.upload_blob(&a, &[9, 8, 7, 6], "image/png").await;
    let cid = blob_cid(&blob);
    let r = public_get_blob(&s.url, &a.did, &cid).await;
    assert_eq!((r.status, &r.body[..]), (200, &[9u8, 8, 7, 6][..]), "{}", r.text());
}

/// blobs: "keeps a blob shared with a public record"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_keeps_a_blob_shared_with_a_public_record() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    let blob = upload_blob(&alice, &[7, 7, 7]).await;
    let cid = blob_cid(&blob);
    let pds = &net.pds[0];
    let session = Auth::Bearer(alice.session_jwt.clone());
    let profile = json!({"repo": alice.did, "collection": "app.bsky.actor.profile", "rkey": "self", "record": {"$type": "app.bsky.actor.profile", "avatar": blob}});
    pds.xrpc.post("com.atproto.repo.createRecord", &profile, &session).await.ok();
    write(&alice, &space, W::new().rkey("shared").record(image_record("shared", &blob))).await.ok();
    assert_eq!(public_get_blob(&pds.url, &alice.did, &cid).await.status, 200);

    // Deleting the public record must not strand the space record's bytes.
    let drop_profile = json!({"repo": alice.did, "collection": "app.bsky.actor.profile", "rkey": "self"});
    pds.xrpc.post("com.atproto.repo.deleteRecord", &drop_profile, &session).await.ok();
    let cred = net.credential_for(&dan, &space).await;
    assert_eq!(space_get_blob(&net, &cred, &space, &alice.did, &cid).await.status, 200, "space ref keeps the bytes");
    public_get_blob(&pds.url, &alice.did, &cid).await.err(400, "BlobNotFound");

    // And the reverse: dropping the space record leaves nothing behind.
    del(&alice, &space, None, "shared").await.ok();
    space_get_blob(&net, &cred, &space, &alice.did, &cid).await.err(400, "BlobNotFound");
}

/// blobs: "filters listBlobs by revision"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_filters_list_blobs_by_revision() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let first = upload_blob(&alice, &[1]).await;
    write(&alice, &space, W::new().rkey("first").record(image_record("first", &first))).await.ok();
    let (mid_rev, _) = repo_state(&alice, &space).await.unwrap();
    let second = upload_blob(&alice, &[2]).await;
    write(&alice, &space, W::new().rkey("second").record(image_record("second", &second))).await.ok();

    let cred = net.credential_for(&carol, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let all = cred.get(&net.pds[0].url, "com.atproto.space.listBlobs", &q).await.ok();
    let mut got: Vec<&str> = all["cids"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    got.sort();
    let mut want = vec![blob_cid(&first), blob_cid(&second)];
    want.sort();
    assert_eq!(got, want);
    let q = [("space", space.as_str()), ("repo", alice.did.as_str()), ("since", mid_rev.as_str())];
    let since = cred.get(&net.pds[0].url, "com.atproto.space.listBlobs", &q).await.ok();
    assert_eq!(since["cids"], json!([blob_cid(&second)]));
}

/// blobs: "scopes listBlobs to one space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_scopes_list_blobs_to_one_space() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net
        .create_space(&alice, SpaceOpts { skey: Some("blobs-scoped"), members: &[&carol], ..Default::default() })
        .await;
    let other = net
        .create_space(&alice, SpaceOpts { skey: Some("blobs-scoped-other"), members: &[&carol], ..Default::default() })
        .await;
    let blob = upload_blob(&alice, &[9, 9, 9]).await;
    write(&alice, &space, W::new().rkey("scoped-blob").record(image_record("blob", &blob))).await.ok();
    let cred = net.credential_for(&carol, &other).await;
    let listed =
        cred.get(&net.pds[0].url, "com.atproto.space.listBlobs", &[("space", &other), ("repo", &alice.did)]).await;
    assert_eq!(listed.ok()["cids"], json!([]));
}

/// blobs: "refuses a blob to a credential for another space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_refuses_a_blob_to_a_credential_for_another_space() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space =
        net.create_space(&alice, SpaceOpts { skey: Some("blob-auth"), members: &[&carol], ..Default::default() }).await;
    let other = net
        .create_space(&alice, SpaceOpts { skey: Some("blob-auth-other"), members: &[&carol], ..Default::default() })
        .await;
    let blob = upload_blob(&alice, &[4, 2]).await;
    write(&alice, &space, W::new().rkey("guarded").record(image_record("guarded", &blob))).await.ok();
    let wrong = net.credential_for(&carol, &other).await;
    let r = space_get_blob(&net, &wrong, &space, &alice.did, &blob_cid(&blob)).await;
    assert!(r.status >= 400, "{}", r.text());
}

/// blobs: "refuses a blob that the authorized space does not reference"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_refuses_a_blob_the_authorized_space_does_not_reference() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net
        .create_space(&alice, SpaceOpts { skey: Some("blob-unrelated"), members: &[&carol], ..Default::default() })
        .await;
    let other = net
        .create_space(
            &alice,
            SpaceOpts { skey: Some("blob-unrelated-other"), members: &[&carol], ..Default::default() },
        )
        .await;
    let blob = upload_blob(&alice, &[7, 7, 7]).await;
    write(&alice, &space, W::new().rkey("elsewhere").record(image_record("elsewhere", &blob))).await.ok();
    let cred = net.credential_for(&carol, &other).await;
    space_get_blob(&net, &cred, &other, &alice.did, &blob_cid(&blob)).await.err(400, "BlobNotFound");
}

/// blobs: "serves a blob the authorized space does reference"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_serves_a_blob_the_authorized_space_does_reference() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net
        .create_space(&alice, SpaceOpts { skey: Some("blob-referenced"), members: &[&carol], ..Default::default() })
        .await;
    let blob = upload_blob(&alice, &[1, 2, 3]).await;
    write(&alice, &space, W::new().rkey("referenced").record(image_record("referenced", &blob))).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    let r = space_get_blob(&net, &cred, &space, &alice.did, &blob_cid(&blob)).await;
    assert_eq!((r.status, &r.body[..]), (200, &[1u8, 2, 3][..]), "{}", r.text());
}

// ---------------------------------------------------------------------------
// clearRecords
// ---------------------------------------------------------------------------

const EMPTY_REPO_DATA: &str = "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad";

/// clearRecords: "deletes every record, leaving the repo empty at a new rev"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_deletes_every_record_at_a_new_rev() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    write(&dan, &space, W::new().rkey("one").text("one")).await.ok();
    write(&dan, &space, W::new().collection(TEST_COLLECTION_ALT).rkey("two").text("two")).await.ok();
    let before = repo_state(&dan, &space).await.unwrap();
    assert_eq!(clear(&dan, &space).await.ok(), json!({}));
    assert!(all_records(&dan, &space).await.is_empty());
    let (rev, data) = repo_state(&dan, &space).await.unwrap();
    assert!(rev > before.0, "{rev} after {}", before.0);
    assert_eq!(hex::encode(data), EMPTY_REPO_DATA);
    expect_set_hash_matches_store(&dan, &space).await;
}

/// clearRecords: "clears the oplog rather than logging a delete per record"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_empties_the_oplog() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    write(&dan, &space, W::new().rkey("one")).await.ok();
    write(&dan, &space, W::new().rkey("two")).await.ok();
    clear(&dan, &space).await.ok();
    let r = dan.get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &dan.did)]).await.ok();
    assert_eq!(r["ops"], json!([]), "{r}");
    assert_eq!(hex::encode(bytes_field(&r["commit"]["data"])), EMPTY_REPO_DATA);
}

/// clearRecords: "is a no-op on an empty or unwritten repo"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_is_a_noop_on_an_empty_repo() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    clear(&dan, &space).await.ok();
    assert_eq!(repo_state(&dan, &space).await, None);
    write(&dan, &space, W::new().rkey("gone")).await.ok();
    del(&dan, &space, None, "gone").await.ok();
    let emptied = repo_state(&dan, &space).await;
    clear(&dan, &space).await.ok();
    assert_eq!(repo_state(&dan, &space).await, emptied);
}

/// clearRecords: "recreates the repo on a later write"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_then_a_write_repopulates() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    write(&dan, &space, W::new().rkey("before")).await.ok();
    clear(&dan, &space).await.ok();
    let cleared = repo_state(&dan, &space).await.unwrap();
    let created = write(&dan, &space, W::new().rkey("after")).await.ok();
    let after = repo_state(&dan, &space).await.unwrap();
    assert!(after.0 > cleared.0);
    let ops = dan.get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &dan.did)]).await.ok();
    let ops = ops["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 1, "{ops:?}");
    assert_eq!((&ops[0]["rkey"], &ops[0]["cid"], &ops[0]["prev"]), (&json!("after"), &created["cid"], &J::Null));
    expect_set_hash_matches_store(&dan, &space).await;
}

/// clearRecords: "leaves the account's repos in other spaces alone"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_leaves_other_spaces_alone() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    let other = net
        .create_space(&alice, SpaceOpts { skey: Some("clear-records-other"), members: &[&dan], ..Default::default() })
        .await;
    write(&dan, &space, W::new().rkey("cleared")).await.ok();
    write(&dan, &other, W::new().rkey("kept")).await.ok();
    clear(&dan, &space).await.ok();
    let kept: Vec<J> = all_records(&dan, &other).await.iter().map(|r| r["rkey"].clone()).collect();
    assert_eq!(kept, [json!("kept")]);
    expect_set_hash_matches_store(&dan, &other).await;
}

/// clearRecords: "refuses to clear another account repo"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_refuses_another_accounts_repo() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    let r = dan.post("com.atproto.space.clearRecords", json!({"space": space, "repo": alice.did})).await;
    r.err(403, "Forbidden");
}

/// blobs: "drops the blobs of cleared records" (gone once space.getBlob no
/// longer serves it)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_drops_the_blobs_of_cleared_records() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let blob = upload_blob(&alice, &[3, 1, 3]).await;
    let cid = blob_cid(&blob);
    let rec = json!({"$type": TEST_COLLECTION, "text": "cleared", "image": blob});
    write(&alice, &space, W::new().rkey("cleared-blob").record(rec)).await.ok();
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let listed = alice.get("com.atproto.space.listBlobs", &q).await.ok();
    assert_eq!(listed["cids"], json!([cid]), "{listed}");
    clear(&alice, &space).await.ok();
    let listed = alice.get("com.atproto.space.listBlobs", &q).await.ok();
    assert_eq!(listed["cids"], json!([]), "{listed}");
    let q = [("space", space.as_str()), ("repo", alice.did.as_str()), ("cid", cid.as_str())];
    alice.get("com.atproto.space.getBlob", &q).await.client_err();
}
