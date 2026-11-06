//! Takedowns on every space read path (plan §2.8, brief "option (e)" and
//! the docs-draft decisions):
//!
//! - a record takedown hides the record from getRecord, listRecords and
//!   listRepoOps values; its blobs (when no live record names them) from
//!   getBlob and listBlobs; and getRepo, listRepoOps and getLatestCommit
//!   serve a view without it that is signed afresh and verifies, so a syncer
//!   that held the record converges, and converges back on a reversal;
//! - an account takedown refuses every read of the account's repos
//!   (RepoTakendown), and credential issuance stops for a taken-down member
//!   (AccountTakedown) or authority (RepoTakendown), and getDelegationToken
//!   for a taken-down account;
//! - a space takedown (a vlpds extension) closes the space at its host.
//!
//! The network: alice governs the space on pds0, where dave is a member;
//! bob and carol are members on pds1. Takedowns are applied on the host of
//! the account they name.

use super::phase3::*;
use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::collections::BTreeMap;
use std::time::Duration;

struct Td {
    net: Net,
    alice: SpaceClient,
    bob: SpaceClient,
    carol: SpaceClient,
    dave: SpaceClient,
    space: String,
}

async fn td() -> Td {
    let net = Net::new(1).await;
    let alice = net.actor("alice", 0).await;
    let (bob, carol, dave) = (net.actor("bob", 1).await, net.actor("carol", 1).await, net.actor("dave", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol, &dave], ..Default::default() }).await;
    Td { net, alice, bob, carol, dave, space }
}

impl Td {
    /// bob writes `rkey` with `text`; the record's (uri, cid).
    async fn bob_writes(&self, rkey: &str, text: &str) -> (String, String) {
        let r = write(&self.bob, &self.space, W::new().rkey(rkey).text(text)).await.ok();
        (r["uri"].as_str().unwrap().to_string(), r["cid"].as_str().unwrap().to_string())
    }

    fn uri(&self, rkey: &str) -> String {
        record_uri(&self.space, &self.bob.did, TEST_COLLECTION, rkey)
    }

    async fn takedown_bobs(&self, rkey: &str, cid: &str, applied: bool) {
        takedown_record(&self.net.pds[1], &self.uri(rkey), cid, applied).await;
    }
}

fn path(rkey: &str) -> String {
    format!("{TEST_COLLECTION}/{rkey}")
}

/// getRecord answers RecordNotFound, listRecords leaves it out and no
/// listRepoOps op carries its value, for a credential reader; a reversal
/// brings it back. The taken-down record's text never appears in a response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_takedown_hides_it_from_records_and_op_values() {
    let t = td().await;
    let (uri, cid) = t.bob_writes("gone", "zqtakendowntext").await;
    assert_eq!(uri, t.uri("gone"), "a space record's URI");
    t.bob_writes("kept", "still here").await;
    let cred = t.net.credential_for(&t.carol, &t.space).await;
    let base = t.net.pds[1].url.clone();
    let q =
        [("space", t.space.as_str()), ("repo", t.bob.did.as_str()), ("collection", TEST_COLLECTION), ("rkey", "gone")];
    cred.get(&base, "com.atproto.space.getRecord", &q).await.ok();

    t.takedown_bobs("gone", &cid, true).await;
    let r = cred.get(&base, "com.atproto.space.getRecord", &q).await;
    r.err(400, "RecordNotFound");
    assert!(!r.text().contains("zqtakendowntext"));
    let l = listed(&base, &cred, &t.space, &t.bob.did).await;
    assert_eq!(l.keys().cloned().collect::<Vec<_>>(), vec![path("kept")]);
    let ops = cred.get(&base, "com.atproto.space.listRepoOps", &[("space", &t.space), ("repo", &t.bob.did)]).await;
    assert!(!ops.ok().to_string().contains("zqtakendowntext"), "listRepoOps carried the value: {}", ops.text());

    t.takedown_bobs("gone", &cid, false).await;
    assert_eq!(cred.get(&base, "com.atproto.space.getRecord", &q).await.ok()["cid"], json!(cid));
    assert_eq!(listed(&base, &cred, &t.space, &t.bob.did).await.len(), 2);
}

/// A blob is served while a record that isn't taken down names it:
/// getBlob answers BlobNotFound and listBlobs leaves it out once every
/// record of the repo in this space naming it is taken down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_takedown_hides_blobs_only_it_names() {
    let t = td().await;
    let only = upload_blob(&t.bob, format!("\u{89}PNG only {}", unique_name("x")).as_bytes()).await;
    let shared = upload_blob(&t.bob, format!("\u{89}PNG shared {}", unique_name("y")).as_bytes()).await;
    let (only_cid, shared_cid) = (blob_cid(&only), blob_cid(&shared));
    let mut cids = BTreeMap::new();
    for (rkey, blob) in [("a", &only), ("b", &shared), ("c", &shared)] {
        let rec = json!({"$type": TEST_COLLECTION, "text": rkey, "image": blob});
        let r = write(&t.bob, &t.space, W::new().rkey(rkey).record(rec)).await.ok();
        cids.insert(rkey, r["cid"].as_str().unwrap().to_string());
    }
    let cred = t.net.credential_for(&t.carol, &t.space).await;
    let base = t.net.pds[1].url.clone();
    let get = |cid: String| {
        let (cred, base, space, did) = (&cred, base.clone(), t.space.clone(), t.bob.did.clone());
        async move {
            cred.get(&base, "com.atproto.space.getBlob", &[("space", &space), ("repo", &did), ("cid", &cid)]).await
        }
    };
    let list = || async {
        let r = cred.get(&base, "com.atproto.space.listBlobs", &[("space", &t.space), ("repo", &t.bob.did)]).await;
        let mut v: Vec<String> =
            r.ok()["cids"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().into()).collect();
        v.sort();
        v
    };
    let mut both = vec![only_cid.clone(), shared_cid.clone()];
    both.sort();
    assert_eq!(list().await, both);

    t.takedown_bobs("a", &cids["a"], true).await;
    t.takedown_bobs("b", &cids["b"], true).await;
    get(only_cid.clone()).await.err(400, "BlobNotFound");
    assert_eq!(get(shared_cid.clone()).await.status, 200, "c still names the shared blob");
    assert_eq!(list().await, vec![shared_cid.clone()]);

    t.takedown_bobs("c", &cids["c"], true).await;
    get(shared_cid.clone()).await.err(400, "BlobNotFound");
    assert_eq!(list().await, Vec::<String>::new());

    for rkey in ["a", "b", "c"] {
        t.takedown_bobs(rkey, &cids[rkey], false).await;
    }
    assert_eq!(get(only_cid).await.status, 200);
    assert_eq!(get(shared_cid).await.status, 200);
    assert_eq!(list().await, both);
}

/// Option (e): during a record takedown, getLatestCommit's hash is the
/// LtHash of the remaining records (at the same rev, signed afresh);
/// getRepo verifies as `verifyRepoCarFull` does with the record in neither
/// the index nor the blocks; listRepoOps replays to the same commit. A
/// syncer that held the record converges through getRepo, follows later
/// writes incrementally, and converges back when the takedown is reversed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_takedown_serves_a_consistent_view() {
    let t = td().await;
    let base = t.net.pds[1].url.clone();
    let (_, gone) = t.bob_writes("gone", "zqoptiontext").await;
    t.bob_writes("kept", "kept").await;
    put(&t.bob, &t.space, W::new().rkey("kept").text("kept, revised")).await.ok();
    let mut syncer = Syncer::new(&base, &t.space, &t.bob.did, t.net.credential_for(&t.carol, &t.space).await);
    syncer.full().await;
    let all = listed(&base, &syncer.cred, &t.space, &t.bob.did).await;
    assert_eq!(all.len(), 2);
    let head_rev = repo_state(&t.bob, &t.space).await.unwrap().0;

    t.takedown_bobs("gone", &gone, true).await;
    let mut visible = all.clone();
    visible.remove(&path("gone"));
    let cred = t.net.credential_for(&t.carol, &t.space).await;
    let q = [("space", t.space.as_str()), ("repo", t.bob.did.as_str())];

    let latest = cred.get(&base, "com.atproto.space.getLatestCommit", &q).await.ok();
    let c = super::fuzz::signed_commit(&latest["commit"]);
    assert_eq!(c.rev, head_rev, "the takedown moves no rev");
    assert_eq!(c.data, set_hash(&visible), "getLatestCommit's hash is the remaining records' LtHash");

    let r = cred.get(&base, "com.atproto.space.getRepo", &q).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = verify_repo_star(&r.body, &t.space, &t.bob.did)
        .unwrap_or_else(|e| panic!("getRepo during a takedown doesn't verify: {e}"));
    assert_eq!(v.set(), visible, "getRepo's index");
    assert_eq!(v.records.len(), 1);
    let gone_bytes = Cid::parse(&gone).unwrap().to_bytes();
    assert!(!r.body.windows(gone_bytes.len()).any(|w| w == gone_bytes), "the record's CID is in the archive");
    assert!(!String::from_utf8_lossy(&r.body).contains("zqoptiontext"), "the record's value is in the archive");

    let ops = cred.get(&base, "com.atproto.space.listRepoOps", &[q[0], q[1], ("limit", "100")]).await.ok();
    assert!(
        commit_matches(&replay(ops["ops"].as_array().unwrap()), &ops["commit"]),
        "listRepoOps from the start: {ops}"
    );
    assert!(!ops.to_string().contains("zqoptiontext"));
    let noop = cred.get(&base, "com.atproto.space.listRepoOps", &[q[0], q[1], ("since", &head_rev)]).await.ok();
    assert_eq!(noop["ops"], json!([]));
    assert_eq!(super::fuzz::signed_commit(&noop["commit"]).data, set_hash(&visible));
    assert_eq!(listed(&base, &cred, &t.space, &t.bob.did).await, visible);

    let pulls = syncer.full_pulls;
    converge(&mut syncer, &visible, "after the takedown").await;
    assert_eq!(syncer.full_pulls, pulls + 1, "the digest mismatch sends the syncer to getRepo once");

    // later writes follow incrementally from the adjusted view
    let (_, more) = t.bob_writes("more", "written during the takedown").await;
    visible.insert(path("more"), more.clone());
    converge(&mut syncer, &visible, "a write during the takedown").await;
    assert_eq!(syncer.full_pulls, pulls + 1, "no further getRepo for an ordinary write");

    t.takedown_bobs("gone", &gone, false).await;
    let mut restored = all.clone();
    restored.insert(path("more"), more);
    let latest = cred.get(&base, "com.atproto.space.getLatestCommit", &q).await.ok();
    assert_eq!(super::fuzz::signed_commit(&latest["commit"]).data, set_hash(&restored));
    let r = cred.get(&base, "com.atproto.space.getRepo", &q).await;
    assert_eq!(verify_repo_star(&r.body, &t.space, &t.bob.did).unwrap().set(), restored);
    let ops = cred.get(&base, "com.atproto.space.listRepoOps", &[q[0], q[1], ("limit", "100")]).await.ok();
    assert!(commit_matches(&replay(ops["ops"].as_array().unwrap()), &ops["commit"]));
    converge(&mut syncer, &restored, "after the reversal").await;
}

/// Every read of a taken-down account's repo in the space is refused with
/// RepoTakendown, to a credential minted before the takedown; a reversal
/// restores them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_takedown_refuses_every_read_path() {
    let t = td().await;
    let blob = upload_blob(&t.bob, b"\x89PNG account takedown").await;
    let (cid, bc) = (
        write(
            &t.bob,
            &t.space,
            W::new().rkey("r").record(json!({"$type": TEST_COLLECTION, "text": "x", "image": blob})),
        )
        .await
        .ok()["cid"]
            .clone(),
        blob_cid(&blob),
    );
    assert!(cid.is_string());
    let cred = t.net.credential_for(&t.carol, &t.space).await;
    let base = t.net.pds[1].url.clone();
    let (sp, did) = (t.space.as_str(), t.bob.did.as_str());
    let reads: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            "com.atproto.space.getRecord",
            vec![("space", sp), ("repo", did), ("collection", TEST_COLLECTION), ("rkey", "r")],
        ),
        ("com.atproto.space.listRecords", vec![("space", sp), ("repo", did)]),
        ("com.atproto.space.listRepoOps", vec![("space", sp), ("repo", did)]),
        ("com.atproto.space.getLatestCommit", vec![("space", sp), ("repo", did)]),
        ("com.atproto.space.getRepo", vec![("space", sp), ("repo", did)]),
        ("com.atproto.space.getBlob", vec![("space", sp), ("repo", did), ("cid", bc.as_str())]),
        ("com.atproto.space.listBlobs", vec![("space", sp), ("repo", did)]),
    ];
    for (nsid, q) in &reads {
        assert_eq!(cred.get(&base, nsid, q).await.status, 200, "{nsid} before the takedown");
    }
    takedown_account(&t.net.pds[1], &t.bob.did, true).await;
    for (nsid, q) in &reads {
        cred.get(&base, nsid, q).await.err(400, "RepoTakendown");
    }
    takedown_account(&t.net.pds[1], &t.bob.did, false).await;
    for (nsid, q) in &reads {
        let r = cred.get(&base, nsid, q).await;
        assert_eq!(r.status, 200, "{nsid} after the reversal: {}", r.text());
    }
}

/// getDelegationToken for a taken-down account is refused as the
/// reference's checkTakedown refuses it (AccountTakedown), on the grant it
/// held before the takedown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taken_down_account_gets_no_delegation_token() {
    let t = td().await;
    t.bob.delegation_token(&t.space).await.ok();
    takedown_account(&t.net.pds[1], &t.bob.did, true).await;
    let r = t.bob.delegation_token(&t.space).await;
    assert!(r.json["token"].is_null(), "{}", r.text());
    r.err(401, "AccountTakedown");
}

/// A delegation token minted before its account was taken down is refused
/// at the authority (AccountTakedown) when the member is hosted with the
/// authority; restored, the member gets credentials again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taken_down_member_gets_no_credential() {
    let t = td().await;
    let token = delegation_token(&t.dave, &t.space).await;
    takedown_account(&t.net.pds[0], &t.dave.did, true).await;
    let (r, _) = t.net.mint_credential(&t.space, &token, None).await;
    assert!(r.json["credential"].is_null(), "{}", r.text());
    assert_eq!(r.error_name(), Some("AccountTakedown"), "{}", r.text());
    takedown_account(&t.net.pds[0], &t.dave.did, false).await;
    // the takedown revoked dave's OAuth sessions for good: a fresh grant
    let dave = regrant(&t.dave, FULL_SCOPE).await;
    let token = delegation_token(&dave, &t.space).await;
    t.net.mint_credential(&t.space, &token, None).await.0.ok();
}

/// A taken-down authority issues no credentials (RepoTakendown), even for
/// members hosted elsewhere, and its host methods refuse credentials it
/// issued before; restored, it issues again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taken_down_authority_issues_no_credentials() {
    let t = td().await;
    let before = t.net.credential_for(&t.carol, &t.space).await;
    let token = delegation_token(&t.carol, &t.space).await;
    takedown_account(&t.net.pds[0], &t.alice.did, true).await;
    let (r, _) = t.net.mint_credential(&t.space, &token, None).await;
    assert!(r.json["credential"].is_null(), "{}", r.text());
    assert_eq!(r.error_name(), Some("RepoTakendown"), "{}", r.text());
    let lr = before.get(&t.net.pds[0].url, "com.atproto.space.listRepos", &[("space", &t.space)]).await;
    assert!((400..500).contains(&lr.status), "listRepos at a taken-down authority: {}", lr.text());
    takedown_account(&t.net.pds[0], &t.alice.did, false).await;
    let token = delegation_token(&t.carol, &t.space).await;
    t.net.mint_credential(&t.space, &token, None).await.0.ok();
}

/// A space takedown (vlpds extension, plan §2.8) at the authority's host:
/// getSpaceCredential answers NotAuthorized, listRepos SpaceNotFound, and
/// reads of member repos on that host are refused; restored, all of it
/// works again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_takedown_closes_the_space_at_its_host() {
    let t = td().await;
    write(&t.dave, &t.space, W::new().rkey("d").text("dave's")).await.ok();
    let before = t.net.credential_for(&t.carol, &t.space).await;
    let pds0 = t.net.pds[0].url.clone();
    let q = [("space", t.space.as_str()), ("repo", t.dave.did.as_str())];
    before.get(&pds0, "com.atproto.space.listRecords", &q).await.ok();

    let eve = t.net.actor("eve", 1).await;
    takedown_space(&t.net.pds[0], &t.space, true).await.ok();
    let token = delegation_token(&t.carol, &t.space).await;
    let (r, _) = t.net.mint_credential(&t.space, &token, None).await;
    assert_eq!(r.error_name(), Some("NotAuthorized"), "{}", r.text());
    // a non-member is told what it's always told, not that it's taken down
    let token = delegation_token(&eve, &t.space).await;
    let (r, _) = t.net.mint_credential(&t.space, &token, None).await;
    assert_eq!(r.error_name(), Some("SpaceNotFound"), "{}", r.text());
    assert!(!r.text().contains("taken down"), "{}", r.text());
    before.get(&pds0, "com.atproto.space.listRepos", &[("space", &t.space)]).await.err(400, "SpaceNotFound");
    let r = before.get(&pds0, "com.atproto.space.listRecords", &q).await;
    assert!((400..500).contains(&r.status) && !r.text().contains("dave's"), "{}", r.text());

    takedown_space(&t.net.pds[0], &t.space, false).await.ok();
    let token = delegation_token(&t.carol, &t.space).await;
    t.net.mint_credential(&t.space, &token, None).await.0.ok();
    before.get(&pds0, "com.atproto.space.listRecords", &q).await.ok();
}

/// The authority's listRepos row for `repo`: (repoRev, hash).
async fn row_at_authority(t: &Td, cred: &Cred, repo: &str) -> Option<(String, Vec<u8>)> {
    let r = cred.get(&t.net.pds[0].url, "com.atproto.space.listRepos", &[("space", &t.space)]).await.ok();
    let row = r["repos"].as_array()?.iter().find(|r| r["did"] == json!(repo))?.clone();
    Some((row["repoRev"].as_str()?.to_string(), super::fuzz::bytes_field(&row["data"])))
}

/// Waits (5 s at most) for the authority to list `repo` at `rev` with `hash`.
async fn authority_lists(t: &Td, cred: &Cred, repo: &str, rev: &str, hash: &[u8], what: &str) -> Duration {
    let t0 = std::time::Instant::now();
    let want = Some((rev.to_string(), hash.to_vec()));
    for _ in 0..500 {
        if row_at_authority(t, cred, repo).await == want {
            return t0.elapsed();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what}: the authority lists {:?}, wants {want:?}", row_at_authority(t, cred, repo).await);
}

/// Waits for a forward of `repo` at `rev` with `hash` at `syncer`.
async fn forwarded(syncer: &super::hooks::StubDid, repo: &str, rev: &str, hash: &[u8], what: &str) {
    let hit = || {
        syncer.seen().iter().any(|n| {
            n.body["repo"] == json!(repo)
                && n.body["repoRev"] == json!(rev)
                && super::fuzz::bytes_field(&n.body["data"]) == hash
        })
    };
    for _ in 0..500 {
        if hit() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what}: no forward of {repo} at {rev} with that hash: {:?}", syncer.seen());
}

/// A record takedown and its reversal are pushed, not left to polls: the
/// author's host notifies the authority with the hash it now serves at the
/// same rev, listRepos shows it within milliseconds, and a registered
/// syncer gets a forward, sees the same rev with another hash and
/// converges with getRepo. Through all of it, no prevSpaceRev forks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_takedown_and_reversal_are_pushed_to_the_authority_and_its_syncers() {
    let t = td().await;
    let base = t.net.pds[1].url.clone();
    let (_, gone) = t.bob_writes("gone", "pushed away").await;
    t.bob_writes("kept", "kept").await;
    let rev = repo_state(&t.bob, &t.space).await.unwrap().0;
    let stub = super::hooks::StubDid::spawn().await;
    let acred = t.net.credential_for(&t.alice, &t.space).await;
    let reg = json!({"space": t.space, "service": format!("{}#atproto_space_syncer", stub.did)});
    acred.post(&t.net.pds[0].url, "com.atproto.space.registerNotify", reg).await.ok();
    let mut syncer = Syncer::new(&base, &t.space, &t.bob.did, t.net.credential_for(&t.carol, &t.space).await);
    syncer.full().await;
    let all = syncer.set.clone();
    authority_lists(&t, &acred, &t.bob.did, &rev, &set_hash(&all), "before").await;

    t.takedown_bobs("gone", &gone, true).await;
    let mut visible = all.clone();
    visible.remove(&path("gone"));
    let took = authority_lists(&t, &acred, &t.bob.did, &rev, &set_hash(&visible), "the takedown").await;
    eprintln!("the takedown reached listRepos in {took:?}");
    forwarded(&stub, &t.bob.did, &rev, &set_hash(&visible), "the takedown").await;
    // the spec's signal: the same rev with another hash, so a full pull
    let pulls = syncer.full_pulls;
    syncer.full().await;
    assert_eq!((syncer.rev.as_deref(), &syncer.set), (Some(rev.as_str()), &visible));
    assert_eq!(syncer.full_pulls, pulls + 1);

    t.takedown_bobs("gone", &gone, false).await;
    let took = authority_lists(&t, &acred, &t.bob.did, &rev, &set_hash(&all), "the reversal").await;
    eprintln!("the reversal reached listRepos in {took:?}");
    forwarded(&stub, &t.bob.did, &rev, &set_hash(&all), "the reversal").await;
    syncer.full().await;
    assert_eq!(syncer.set, all);

    // a write after it is an ordinary forward again
    let (_, more) = t.bob_writes("more", "after the reversal").await;
    let mut now = all.clone();
    now.insert(path("more"), more);
    let rev2 = repo_state(&t.bob, &t.space).await.unwrap().0;
    authority_lists(&t, &acred, &t.bob.did, &rev2, &set_hash(&now), "a later write").await;
    forwarded(&stub, &t.bob.did, &rev2, &set_hash(&now), "a later write").await;
    stub.assert_no_fork("the syncer");
}

/// The authority's own records: a takedown re-sequences its own row with
/// the adjusted hash, and so does its next write while it lasts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_authoritys_own_record_takedown_moves_its_listed_hash() {
    let t = td().await;
    let pds0 = t.net.pds[0].url.clone();
    let w = |rkey: &'static str, text: &'static str| W::new().rkey(rkey).text(text);
    let gone = write(&t.alice, &t.space, w("gone", "alice's")).await.ok()["cid"].as_str().unwrap().to_string();
    write(&t.alice, &t.space, w("kept", "kept")).await.ok();
    let acred = t.net.credential_for(&t.alice, &t.space).await;
    let all = listed(&pds0, &acred, &t.space, &t.alice.did).await;
    let rev = repo_state(&t.alice, &t.space).await.unwrap().0;
    authority_lists(&t, &acred, &t.alice.did, &rev, &set_hash(&all), "before").await;
    let uri = record_uri(&t.space, &t.alice.did, TEST_COLLECTION, "gone");
    takedown_record(&t.net.pds[0], &uri, &gone, true).await;
    let mut visible = all.clone();
    visible.remove(&path("gone"));
    authority_lists(&t, &acred, &t.alice.did, &rev, &set_hash(&visible), "the takedown").await;
    let more = write(&t.alice, &t.space, w("more", "during")).await.ok()["cid"].as_str().unwrap().to_string();
    visible.insert(path("more"), more.clone());
    let rev2 = repo_state(&t.alice, &t.space).await.unwrap().0;
    authority_lists(&t, &acred, &t.alice.did, &rev2, &set_hash(&visible), "a write during it").await;
    takedown_record(&t.net.pds[0], &uri, &gone, false).await;
    let mut restored = all.clone();
    restored.insert(path("more"), more);
    authority_lists(&t, &acred, &t.alice.did, &rev2, &set_hash(&restored), "the reversal").await;
}

/// `vlpds_space_notify_total{hop="in",result}` in this process.
fn notifies_in(result: &str) -> f64 {
    let want = format!(r#"vlpds_space_notify_total{{hop="in",result="{result}"}} "#);
    vlpds::metrics::render().lines().find_map(|l| l.strip_prefix(&want)?.trim().parse().ok()).unwrap_or(0.0)
}

/// A writer's host can sign notifyWrites for its own accounts, so it could
/// repeat its current repoRev with made-up hashes, each one sending every
/// syncer to a full getRepo. The authority asks the writer's host for the
/// hash it serves first: the fakes are dropped unforwarded, the first few as
/// unconfirmed, the rest over the per-(writer, space) cap without a check.
/// Another writer's real takedown still goes through, and nothing forks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_rev_notifies_with_made_up_hashes_are_dropped() {
    let t = td().await;
    let stub = super::hooks::StubDid::spawn().await;
    let acred = t.net.credential_for(&t.alice, &t.space).await;
    let reg = json!({"space": t.space, "service": format!("{}#atproto_space_syncer", stub.did)});
    acred.post(&t.net.pds[0].url, "com.atproto.space.registerNotify", reg).await.ok();
    t.bob_writes("one", "one").await;
    let rev = repo_state(&t.bob, &t.space).await.unwrap().0;
    let held = listed(&t.net.pds[1].url, &acred, &t.space, &t.bob.did).await;
    authority_lists(&t, &acred, &t.bob.did, &rev, &set_hash(&held), "bob's write").await;
    // the real write's forward leaves after listRepos shows it: counted
    // before the fakes, so a late one can't pass for a fake's
    forwarded(&stub, &t.bob.did, &rev, &set_hash(&held), "bob's write").await;
    let forwards = stub.seen().len();
    let (unverified, capped) = (notifies_in("same_rev_unverified"), notifies_in("same_rev_capped"));

    let aud = vlpds::space::token::space_host_aud(&t.alice.did);
    let jwt = service_jwt(&t.bob, &aud, "com.atproto.space.notifyWrite").await;
    let spam = 10;
    for _ in 0..spam {
        let body = json!({"space": t.space, "repo": t.bob.did, "repoRev": rev, "data": json_bytes(&rand::random::<[u8; 32]>())});
        post_service(&t.net.pds[0].url, "com.atproto.space.notifyWrite", &jwt, body).await.ok();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(row_at_authority(&t, &acred, &t.bob.did).await, Some((rev.clone(), set_hash(&held))));
    assert_eq!(stub.seen().len(), forwards, "no forward for a made-up hash: {:?}", stub.seen());
    let per = vlpds::space::SAME_REV_PER_WINDOW as f64;
    assert!(notifies_in("same_rev_unverified") - unverified >= per, "checked and refused");
    assert!(notifies_in("same_rev_capped") - capped >= spam as f64 - per, "over the cap, not checked");

    // carol's host has its own budget: her record's takedown is pushed
    let r = write(&t.carol, &t.space, W::new().rkey("gone").text("carol's")).await.ok();
    let cid = r["cid"].as_str().unwrap().to_string();
    write(&t.carol, &t.space, W::new().rkey("kept").text("kept")).await.ok();
    let crev = repo_state(&t.carol, &t.space).await.unwrap().0;
    let all = listed(&t.net.pds[1].url, &acred, &t.space, &t.carol.did).await;
    authority_lists(&t, &acred, &t.carol.did, &crev, &set_hash(&all), "carol's writes").await;
    let uri = record_uri(&t.space, &t.carol.did, TEST_COLLECTION, "gone");
    takedown_record(&t.net.pds[1], &uri, &cid, true).await;
    let mut visible = all.clone();
    visible.remove(&path("gone"));
    authority_lists(&t, &acred, &t.carol.did, &crev, &set_hash(&visible), "carol's takedown").await;
    forwarded(&stub, &t.carol.did, &crev, &set_hash(&visible), "carol's takedown").await;
    stub.assert_no_fork("the syncer");
}
