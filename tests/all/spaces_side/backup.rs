//! Space repos and backups. The browser backup on the account page stays
//! public-repo only (brief, FINAL decision 2): it signs in with a password
//! session, space data is OAuth-only, and the page and the ZIP's README say
//! space repos aren't included yet. `backup_space_step_needs_oauth` pins
//! why. The rest holds what an OAuth-backed space backup, once the account
//! page moves to OAuth, gets from the server: [`space_backup`] models it
//! (`spaces/<sid>/space.txt`, `spaces/<sid>/repo.star` per space listSpaces
//! names, its space blobs in `blobs/<cid>`), with every space repo of the
//! account and nothing of any other member's, and a restore through
//! importRepo on a new host.

use super::import_repo::*;
use super::leak::Sentinels;
use super::phase3::*;
use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::collections::BTreeMap;

/// The space part of the account's backup ZIP, as path -> bytes.
pub(super) async fn space_backup(sc: &SpaceClient) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut cursor = None::<String>;
    let mut spaces = Vec::new();
    for _ in 0..100 {
        let mut q = vec![("limit", "100")];
        if let Some(c) = &cursor {
            q.push(("cursor", c));
        }
        let r = sc.get("com.atproto.space.listSpaces", &q).await.ok();
        let page = r["spaces"].as_array().cloned().unwrap_or_default();
        spaces.extend(page.iter().map(|s| s["uri"].as_str().unwrap().to_string()));
        cursor = r["cursor"].as_str().map(String::from);
        if page.is_empty() || cursor.is_none() {
            break;
        }
    }
    let base = sc.srv.base.clone();
    for space in spaces {
        let dir = format!("spaces/{}", sid_hex(&space));
        files.insert(format!("{dir}/space.txt"), format!("{space}\n").into_bytes());
        let r = get_repo_self(sc, &space).await;
        if r.status == 400 && r.error_name() == Some("RepoNotFound") {
            // governed, never written in: no repo
            continue;
        }
        assert_eq!(r.status, 200, "getRepo {space}: {}", r.text());
        files.insert(format!("{dir}/repo.star"), r.body.to_vec());
        let lb =
            sc.get("com.atproto.space.listBlobs", &[("space", &space), ("repo", &sc.did), ("limit", "1000")]).await;
        for cid in lb.ok()["cids"].as_array().cloned().unwrap_or_default() {
            let cid = cid.as_str().unwrap();
            let q = [("space", space.as_str()), ("repo", sc.did.as_str()), ("cid", cid)];
            let b = dpop_raw(sc, &base, reqwest::Method::GET, "com.atproto.space.getBlob", &q, None).await;
            assert_eq!(b.status, 200, "getBlob {cid}: {}", b.text());
            assert_eq!(Cid::raw(&b.body).to_string(), cid, "a blob that doesn't match its CID");
            files.insert(format!("blobs/{cid}"), b.body.to_vec());
        }
    }
    files
}

/// bob is a member of alice's space and governs his own, where alice is a
/// member; all three write, with blobs, in both. Everyone's sentinels but
/// bob's are collected.
struct Mixed {
    /// Holds the hosts up.
    _net: Net,
    bob: SpaceClient,
    spaces: [String; 2],
    others: Sentinels,
}

async fn tagged_write(sc: &SpaceClient, space: &str, rkey: &str, tag: &str, others: Option<&mut Sentinels>) -> J {
    let bytes = format!("\u{89}PNG {tag} {}", unique_name("b")).into_bytes();
    let blob = upload_blob(sc, &bytes).await;
    let rec = json!({"$type": TEST_COLLECTION, "text": tag, "image": blob});
    let r = write(sc, space, W::new().rkey(rkey).record(rec)).await.ok();
    if let Some(s) = others {
        s.push(format!("{tag} text"), tag);
        s.push_cid(&format!("{tag} record"), r["cid"].as_str().unwrap());
        s.push_cid(&format!("{tag} blob"), &blob_cid(&blob));
        s.push(format!("{tag} blob bytes"), &bytes);
    }
    r
}

async fn mixed() -> Mixed {
    let net = Net::new(1).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 0).await, net.actor("carol", 1).await);
    let alices = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    let bobs = net.create_space(&bob, SpaceOpts { members: &[&alice, &carol], ..Default::default() }).await;
    let mut others = Sentinels::default();
    for (i, space) in [&alices, &bobs].into_iter().enumerate() {
        tagged_write(&alice, space, "a", &format!("zqalice{i}text"), Some(&mut others)).await;
        tagged_write(&carol, space, "c", &format!("zqcarol{i}text"), Some(&mut others)).await;
        tagged_write(&bob, space, "b", &format!("zqbob{i}text"), None).await;
        write(&bob, space, W::new().rkey("plain").text(&format!("zqbob{i}plain"))).await.ok();
    }
    Mixed { _net: net, bob, spaces: [alices, bobs], others }
}

/// The backup holds a verifying repo per space the account is in (the one
/// it governs too), exactly its own records, and its own blobs, and not a
/// byte of any other member's records or blobs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_holds_each_space_repo_and_no_other_members_data() {
    let m = mixed().await;
    let files = space_backup(&m.bob).await;
    let mut want_files = vec![];
    let mut blobs = std::collections::BTreeSet::new();
    for space in &m.spaces {
        let dir = format!("spaces/{}", sid_hex(space));
        assert_eq!(files[&format!("{dir}/space.txt")], format!("{space}\n").into_bytes());
        let v = verify_repo_star(&files[&format!("{dir}/repo.star")], space, &m.bob.did)
            .unwrap_or_else(|e| panic!("{space}: the backup's repo doesn't verify: {e}"));
        let own: BTreeMap<String, String> = all_records(&m.bob, space)
            .await
            .iter()
            .map(|r| {
                (
                    format!("{}/{}", r["collection"].as_str().unwrap(), r["rkey"].as_str().unwrap()),
                    r["cid"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(v.set(), own, "{space}: exactly bob's records");
        assert_eq!(v.set().len(), 2);
        want_files.push(format!("{dir}/space.txt"));
        want_files.push(format!("{dir}/repo.star"));
        let lb = m.bob.get("com.atproto.space.listBlobs", &[("space", space), ("repo", &m.bob.did)]).await.ok();
        blobs.extend(lb["cids"].as_array().unwrap().iter().map(|c| format!("blobs/{}", c.as_str().unwrap())));
    }
    assert_eq!(blobs.len(), 2, "bob's two space blobs");
    want_files.extend(blobs);
    want_files.sort();
    assert_eq!(files.keys().cloned().collect::<Vec<_>>(), want_files);
    for (path, bytes) in &files {
        m.others.assert_clean(&format!("backup file {path}"), bytes);
    }
}

/// What the backup step asks for is the account's own repo; asked for
/// another member's (by DID, on its own grant), every space read refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_reads_only_the_accounts_own_repos() {
    let net = Net::new(0).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let blob = upload_blob(&alice, b"\x89PNG alice's").await;
    let r = write(
        &alice,
        &space,
        W::new().rkey("a").record(json!({"$type": TEST_COLLECTION, "text": "zqalicesown", "image": blob})),
    )
    .await
    .ok();
    assert!(r["cid"].is_string());
    let bc = blob_cid(&blob);
    let (sp, did) = (space.as_str(), alice.did.as_str());
    let base = bob.srv.base.clone();
    for (nsid, q) in [
        ("com.atproto.space.getRepo", vec![("space", sp), ("repo", did)]),
        ("com.atproto.space.listRecords", vec![("space", sp), ("repo", did)]),
        (
            "com.atproto.space.getRecord",
            vec![("space", sp), ("repo", did), ("collection", TEST_COLLECTION), ("rkey", "a")],
        ),
        ("com.atproto.space.listRepoOps", vec![("space", sp), ("repo", did)]),
        ("com.atproto.space.getLatestCommit", vec![("space", sp), ("repo", did)]),
        ("com.atproto.space.listBlobs", vec![("space", sp), ("repo", did)]),
        ("com.atproto.space.getBlob", vec![("space", sp), ("repo", did), ("cid", bc.as_str())]),
    ] {
        let r = dpop_raw(&bob, &base, reqwest::Method::GET, nsid, &q, None).await;
        assert!((400..500).contains(&r.status), "{nsid} of alice's repo on bob's grant: {}", r.text());
        assert!(!r.text().contains("zqalicesown"));
    }
}

/// The account page's backup signs in with a password session; space data
/// is OAuth-only, so that session reads no space data, which is why the
/// backup has no space step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_space_step_needs_oauth() {
    let net = Net::new(0).await;
    let bob = net.actor("bob", 0).await;
    let space = net.create_space(&bob, SpaceOpts::default()).await;
    write(&bob, &space, W::new().rkey("b").text("zqbobsown")).await.ok();
    let s = &net.pds[0];
    let session = Auth::Bearer(bob.session_jwt.clone());
    let r = s.xrpc.get("com.atproto.space.listSpaces", &[], &session).await;
    assert_eq!(r.status, 403, "listSpaces on a password session: {}", r.text());
    let r = s.xrpc.get("com.atproto.space.getRepo", &[("space", &space), ("repo", &bob.did)], &session).await;
    assert_eq!(r.status, 403, "getRepo on a password session: {}", r.text());
    assert!(!r.text().contains("zqbobsown"));
}

/// The backup restores on a new host: bob's account arrives there, each
/// `spaces/<sid>/repo.star` imports into the space its `space.txt` names,
/// the `blobs/` go up as listMissingBlobs asks, and every space repo is back
/// as it was (data, records, blobs; at a new rev), check-space clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_restores_on_a_new_host() {
    let h = two_hosts().await;
    fill_bob(&h).await;
    // bob's own space too, alice writing in it
    let own = format!("at://{}/space/{TEST_SPACE_TYPE}/{}", h.bob.did, unique_name("own"));
    h.bob
        .post(
            "com.atproto.space.createSpace",
            json!({"spaceType": TEST_SPACE_TYPE, "skey": last_segment(&own), "policy": memberspace(json!({}))}),
        )
        .await
        .ok();
    put_member(&h.bob, &own, &h.alice, true, true).await.ok();
    write(&h.alice, &own, W::new().rkey("alices").text("not bob's")).await.ok();
    write(&h.bob, &own, W::new().rkey("bobs").text("bob's own space")).await.ok();
    let heads = [repo_state(&h.bob, &h.space).await.unwrap(), repo_state(&h.bob, &own).await.unwrap()];
    let files = space_backup(&h.bob).await;

    let b_did = h.b.pds_did().await;
    let sa = service_jwt(&h.bob, &b_did, "com.atproto.server.createAccount").await;
    let arrived = arrive(&h.b, &h.bob.did, sa).await;
    complete_move(&h.docs, &h.b, &arrived).await;
    let moved = arrived.oauth(&h.b).await;
    // bob's own space comes first: its repo there is the authority's
    assert_eq!(moved.create_space(TEST_SPACE_TYPE, last_segment(&own)).await, own);
    for (path, bytes) in &files {
        let Some(dir) = path.strip_suffix("/repo.star") else { continue };
        let space = String::from_utf8(files[&format!("{dir}/space.txt")].clone()).unwrap().trim().to_string();
        assert_eq!(
            verify_repo_star(bytes, &space, &h.bob.did).unwrap().commit.space,
            space,
            "the archive names its space"
        );
        import_repo(&moved, bytes).await.ok();
    }
    // the blobs listMissingBlobs asks for, which the backup holds
    let missing = h.b.xrpc.get("com.atproto.repo.listMissingBlobs", &[], &arrived.session).await.ok();
    let missing: Vec<String> =
        missing["blobs"].as_array().unwrap().iter().map(|b| b["cid"].as_str().unwrap().to_string()).collect();
    assert!(!missing.is_empty(), "the imported repos name blobs");
    for cid in &missing {
        let bytes = files[&format!("blobs/{cid}")].clone();
        h.b.xrpc.post_bytes("com.atproto.repo.uploadBlob", bytes, "image/png", &arrived.session).await.ok();
    }
    let missing = h.b.xrpc.get("com.atproto.repo.listMissingBlobs", &[], &arrived.session).await.ok();
    assert_eq!(missing["blobs"], json!([]));
    for (space, head) in [&h.space, &own].into_iter().zip(heads) {
        let (rev, data) = repo_state(&moved, space).await.unwrap();
        assert!(rev > head.0, "{space}: at a new rev");
        assert_eq!(data, head.1, "{space}");
        expect_set_hash_matches_store(&moved, space).await;
        let (r, out) = admin_cli(&h.b.url, &["--json", "check-space", &h.bob.did, space]).await;
        assert!(r.is_ok(), "{out}");
    }
    let restored = space_backup(&moved).await;
    assert_eq!(
        restored.keys().collect::<Vec<_>>(),
        files.keys().collect::<Vec<_>>(),
        "the same backup from the new host"
    );
}
