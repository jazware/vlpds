//! Operator read access to space records (brief Q6): moderators and admins
//! can read a space record for ToS work, and every read is audited.
//!
//! The contract (the Mac harness probes the same name and shape):
//! `GET vlpds.admin.getSpaceRecord?space&repo&collection&rkey` with admin
//! Basic auth, or the moderation service's service JWT, answers
//! `{uri, cid, value}`, and writes a `vlpds.admin.getAuditLog` entry for the
//! record's author naming who read it, what (the space or rkey) and when.
//! Nobody else gets it: no auth, the account's own password session, app
//! password or OAuth grant, a space credential. A refused call writes no
//! audit entry. What an operator reads never shows up on a public surface
//! (the phase 1 leak collector's checks).

use super::leak::*;
use super::phase3::*;
use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;

const GET_SPACE_RECORD: &str = "vlpds.admin.getSpaceRecord";

async fn audit_for(s: &TestServer, did: &str) -> Vec<J> {
    let r = s.xrpc.get("vlpds.admin.getAuditLog", &[("did", did), ("limit", "100")], &Auth::Admin).await;
    r.ok()["entries"].as_array().cloned().unwrap_or_default()
}

/// The audit entries for `did` naming `space` or `rkey`.
async fn reads_audited(s: &TestServer, did: &str, space: &str, rkey: &str) -> Vec<J> {
    audit_for(s, did)
        .await
        .into_iter()
        .filter(|e| {
            let t = e.to_string();
            t.contains(space) || t.contains(rkey)
        })
        .collect()
}

fn q<'a>(space: &'a str, repo: &'a str, rkey: &'a str) -> [(&'a str, &'a str); 4] {
    [("space", space), ("repo", repo), ("collection", TEST_COLLECTION), ("rkey", rkey)]
}

/// The moderation service's DID and key, registered on `net`'s directory
/// (its genesis op computed up front, so the hosts can be configured with
/// the DID before the directory has it).
fn mod_service() -> (vlsync_atproto::crypto::Keypair, J, String) {
    let key = vlsync_atproto::crypto::Keypair::generate();
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [key.did_key()],
        "verificationMethods": {"atproto": key.did_key()},
        "alsoKnownAs": ["at://mod.test"],
        "services": {},
        "prev": null,
    });
    let op = vlpds::plc::sign(op, &key).unwrap();
    let did = vlpds::plc::did_for_genesis(&op).unwrap();
    (key, op, did)
}

struct Ops {
    net: Net,
    alice: SpaceClient,
    bob: SpaceClient,
    space: String,
    rkey: String,
    cid: String,
    mod_key: vlsync_atproto::crypto::Keypair,
    mod_did: String,
    pds_did: String,
}

async fn ops() -> Ops {
    let (mod_key, op, mod_did) = mod_service();
    let m = mod_did.clone();
    let net = Net::new_with(0, move |_, c| c.mod_service_did = Some(m.clone())).await;
    let r = reqwest::Client::new().post(format!("{}/{mod_did}", net.plc.url)).json(&op).send().await.unwrap();
    assert!(r.status().is_success());
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let w = write(&bob, &space, W::new().rkey("reported").text("zqreportedtext")).await.ok();
    let pds_did = net.pds[0].pds_did().await;
    Ops {
        alice,
        bob,
        space,
        rkey: "reported".into(),
        cid: w["cid"].as_str().unwrap().into(),
        mod_key,
        mod_did,
        pds_did,
        net,
    }
}

impl Ops {
    fn s(&self) -> &TestServer {
        &self.net.pds[0]
    }

    fn moderator(&self) -> Auth {
        Auth::Bearer(
            vlpds::auth::service_auth_jwt(&self.mod_key, &self.mod_did, &self.pds_did, Some(GET_SPACE_RECORD), 60)
                .unwrap(),
        )
    }
}

/// Admin and moderator reads answer `{uri, cid, value}` and are each
/// audited for the author: who, what and when.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admins_and_moderators_read_space_records_audited() {
    let o = ops().await;
    let (s, did) = (o.s(), o.bob.did.as_str());
    assert!(reads_audited(s, did, &o.space, &o.rkey).await.is_empty());

    let r = s.xrpc.get(GET_SPACE_RECORD, &q(&o.space, did, &o.rkey), &Auth::Admin).await.ok();
    assert_eq!(r["uri"], json!(record_uri(&o.space, did, TEST_COLLECTION, &o.rkey)), "{r}");
    assert_eq!(r["cid"], json!(o.cid));
    assert_eq!(r["value"]["text"], json!("zqreportedtext"));
    let after_admin = reads_audited(s, did, &o.space, &o.rkey).await;
    assert_eq!(after_admin.len(), 1, "one audit entry per read: {after_admin:?}");
    let e = &after_admin[0];
    assert_eq!(e["actor"], json!("admin"), "{e}");
    assert!(e["at"].as_str().is_some_and(|t| t.starts_with("20")), "{e}");

    let r = s.xrpc.get(GET_SPACE_RECORD, &q(&o.space, did, &o.rkey), &o.moderator()).await.ok();
    assert_eq!(r["cid"], json!(o.cid));
    let after_mod = reads_audited(s, did, &o.space, &o.rkey).await;
    assert_eq!(after_mod.len(), 2, "{after_mod:?}");
    assert!(after_mod.iter().any(|e| e["actor"] == json!(o.mod_did)), "the moderator is named: {after_mod:?}");

    // a missing record
    let r = s.xrpc.get(GET_SPACE_RECORD, &q(&o.space, did, "nope"), &Auth::Admin).await;
    r.err(400, "RecordNotFound");
}

/// A taken-down record stays readable to operators (that's when they need
/// it), audited the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operators_read_taken_down_records() {
    let o = ops().await;
    let (s, did) = (o.s(), o.bob.did.as_str());
    takedown_record(s, &record_uri(&o.space, did, TEST_COLLECTION, &o.rkey), &o.cid, true).await;
    let r = s.xrpc.get(GET_SPACE_RECORD, &q(&o.space, did, &o.rkey), &Auth::Admin).await.ok();
    assert_eq!(r["value"]["text"], json!("zqreportedtext"));
    assert!(!reads_audited(s, did, &o.space, &o.rkey).await.is_empty());
}

/// Nobody but an operator: no auth, the author's or another member's
/// password session, app password, OAuth grant or space credential, and a
/// service JWT from someone other than the moderation service. Nothing
/// refused is audited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_operators_are_refused_and_unaudited() {
    let o = ops().await;
    let (s, did) = (o.s(), o.bob.did.as_str());
    let session = Auth::Bearer(o.bob.session_jwt.clone());
    let ap = s
        .xrpc
        .post("com.atproto.server.createAppPassword", &json!({"name": "ops", "privileged": true}), &session)
        .await
        .ok();
    let app_pw =
        s.create_session(did, ap["password"].as_str().unwrap()).await.ok()["accessJwt"].as_str().unwrap().to_string();
    let other = vlsync_atproto::crypto::Keypair::generate();
    let not_mod = Auth::Bearer(
        vlpds::auth::service_auth_jwt(&other, &o.alice.did, &o.pds_did, Some(GET_SPACE_RECORD), 60).unwrap(),
    );
    let wrong_admin = Auth::Basic("admin".into(), "not-the-token".into());
    let cases: Vec<(&str, Auth)> = vec![
        ("no auth", Auth::None),
        ("a wrong admin password", wrong_admin),
        ("the author's password session", session),
        ("another member's password session", Auth::Bearer(o.alice.session_jwt.clone())),
        ("an app password", Auth::Bearer(app_pw)),
        ("a service JWT not from the moderation service", not_mod),
    ];
    for (what, auth) in &cases {
        let r = s.xrpc.get(GET_SPACE_RECORD, &q(&o.space, did, &o.rkey), auth).await;
        assert!(r.status == 401 || r.status == 403, "{what}: {}", r.text());
        assert!(!r.text().contains("zqreportedtext"), "{what}");
    }
    let r = o.bob.get(GET_SPACE_RECORD, &q(&o.space, did, &o.rkey)).await;
    assert!(r.status == 401 || r.status == 403, "the author's OAuth grant: {}", r.text());
    let cred = o.net.credential_for(&o.alice, &o.space).await;
    let r = cred.get(&s.url, GET_SPACE_RECORD, &q(&o.space, did, &o.rkey)).await;
    assert!(r.status == 401 || r.status == 403, "a space credential: {}", r.text());
    assert!(reads_audited(s, did, &o.space, &o.rkey).await.is_empty(), "a refused read was audited");
    // the audit log itself is operator-only
    let r = s.xrpc.get("vlpds.admin.getAuditLog", &[("did", did)], &Auth::Bearer(o.bob.session_jwt.clone())).await;
    assert!(r.status == 401 || r.status == 403, "{}", r.text());
}

/// Operator reads of every planted record leave no sentinel on the
/// firehose (live and replayed from cursor 0), the S3 backfill, or the
/// author's public sync and repo surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_reads_never_reach_public_surfaces() {
    let s = TestServer::spawn_with(|c| {
        c.spaces = true;
        c.firehose_ring_bytes = 2048;
    })
    .await;
    let public = s.create_account("opp").await;
    let mut p = Planted::new(&s).await;
    let a = p.author.clone();
    p.fill(&s, &public, 4).await;
    let mut live = s.subscribe(None).await;
    s.sync_subs(&public, std::slice::from_mut(&mut live)).await;

    let mut read = 0;
    for coll in p.sc.get("com.atproto.space.listRecords", &[("space", &p.space), ("repo", &a.did)]).await.ok()
        ["records"]
        .as_array()
        .unwrap()
    {
        let (c, k) = (coll["collection"].as_str().unwrap(), coll["rkey"].as_str().unwrap());
        let q = [("space", p.space.as_str()), ("repo", a.did.as_str()), ("collection", c), ("rkey", k)];
        let r = s.xrpc.get(GET_SPACE_RECORD, &q, &Auth::Admin).await.ok();
        assert_eq!(r["cid"], coll["cid"]);
        read += 1;
    }
    assert!(read >= 4, "{read} records read");

    let marker =
        Cid::parse(s.post(&a, "public after the operator reads").await.commit_cid.as_deref().unwrap()).unwrap();
    p.sentinels.assert_frames_clean("live subscribeRepos", &read_to_commit(&mut live, &marker).await);
    let mut replay = s.subscribe(Some(0)).await;
    p.sentinels.assert_frames_clean("cursor-0 backfill", &read_to_commit(&mut replay, &marker).await);
    for (seq, raw) in s3_backfill(&s).await {
        p.sentinels.assert_clean(&format!("S3 backfill seq {seq}"), &raw);
    }
    check_public_surface(&s, &a.did, &p).await;
    let (private, _) = scan_log(&s, &p).await;
    assert!(private > 0);
}
