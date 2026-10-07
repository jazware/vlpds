//! Golden format fixtures (DESIGN.md "Rolling upgrades and format
//! versioning", "Tests and CI"): `testdata/formats/L{n}/` holds what a build
//! at feature level n writes, for every persisted or wire format a reader
//! must keep understanding.
//!
//! - `writers_reproduce_the_max_level_fixtures`: this build's writers, at
//!   the active level, emit `L{MAX_LEVEL}` byte for byte (a writer change
//!   without a new level fails here).
//! - `fixtures_decode_and_reencode`: every level in the build's window
//!   decodes, and re-encodes to the same bytes.
//! - `manifest_freezes_released_levels`: a released level's files match
//!   `testdata/formats/MANIFEST` (sha256), so its fixtures never change.
//!
//! `VLPDS_BLESS=1 cargo test --test all formats:: -- --test-threads=1`
//! rewrites the `MAX_LEVEL` fixtures from the current writers and records
//! the manifest entries of a level that has none yet (or isn't released).
//! The wrapped secret is random (its nonce): blessing writes it only when missing.
//!
//! Built with the `test-level` feature (tests/level_gating.rs includes this
//! module), `MAX_LEVEL` is the test-only level and its fixtures live in
//! `testdata/formats/Ltest` (never released, so never in the MANIFEST):
//! `VLPDS_BLESS=1 cargo test --features test-level --test level_gating formats::`.

use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use vlpds::cid::Cid;
use vlpds::segment::{self, LogObject, Mutation, SegmentBuilder};
use vlpds::slots::ShardId;
use vlpds::version;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/formats")
}

/// `L{n}`; the test-only level's are `Ltest` (they move up with it).
fn level_dir(level: u32) -> PathBuf {
    if level == version::TEST_LEVEL {
        return root().join("Ltest");
    }
    root().join(format!("L{level}"))
}

fn bless() -> bool {
    std::env::var("VLPDS_BLESS").is_ok_and(|v| v == "1")
}

const DID: &str = "did:plc:fixture0000000000000000";
const LOG: &str = "node-a.1790000000000000";
const TIME: &str = "2026-10-01T00:00:00.000Z";
const KEK: [u8; 32] = [7; 32];
const SECRET: &[u8] = b"level-1 wrapped secret fixture";

/// A commit over one record block: (record cid, commit cid, commit block,
/// the CAR of both).
fn commit_car(rec_block: &[u8]) -> (Cid, Cid, Vec<u8>, Vec<u8>) {
    let rec = Cid::dag_cbor(rec_block);
    let mut commit_block = Vec::new();
    vlpds::cbor::Value::Map(vec![
        ("did".into(), vlpds::cbor::Value::Text(DID.into())),
        ("data".into(), vlpds::cbor::Value::Link(rec)),
    ])
    .encode(&mut commit_block);
    let commit = Cid::dag_cbor(&commit_block);
    let mut car = Vec::new();
    vlpds::car::write_header(&mut car, &commit);
    vlpds::car::write_block(&mut car, &commit, &commit_block);
    vlpds::car::write_block(&mut car, &rec, rec_block);
    (rec, commit, commit_block, car)
}

/// A finished #commit frame of `ops` at `seq`.
fn finish_commit(rev: &str, commit: Cid, car: &[u8], ops: &[vlpds::events::RepoOp], seq: i64) -> Vec<u8> {
    let frame = vlpds::events::commit_frame(&vlpds::events::CommitFrame {
        repo: DID,
        rev,
        since: None,
        commit,
        prev_data: None,
        blocks: car,
        ops,
        time: TIME,
    });
    let mut bytes = Vec::new();
    frame.finish(seq, &mut bytes);
    bytes
}

/// A #commit frame (one update) and the record/commit blocks it carries.
fn commit_frame() -> (Vec<u8>, Cid, Vec<u8>, vlpds::tid::Tid) {
    let (rec, commit, commit_block, car) = commit_car(b"\xa1aa\x01");
    let rev = vlpds::tid::Tid::parse("3l3qo2vutsw2b").unwrap();
    let ops =
        [vlpds::events::RepoOp { action: "update", path: "app.bsky.feed.post/1", cid: Some(rec), prev: Some(commit) }];
    (finish_commit(&rev.to_string(), commit, &car, &ops, 1000 << 8), commit, commit_block, rev)
}

fn segment_plain() -> Vec<u8> {
    let (frame, ..) = commit_frame();
    let derived = segment::derive_commit_muts(&frame, 2).unwrap();
    let mut muts = derived.clone();
    muts.push(Mutation {
        key: Bytes::from(vlpds::state::collection_key("app.bsky.feed.post", DID)),
        val: Some(Bytes::new()),
    });
    let m = |k: &str, v: Option<&str>| Mutation {
        key: Bytes::from(k.to_string()),
        val: v.map(|v| Bytes::from(v.to_string())),
    };
    let mut b = SegmentBuilder::for_log(LOG);
    b.push_derived(1000 << 8, ShardId(3), 7, |o| o.extend_from_slice(&frame), &muts, derived.len(), 2);
    b.push(
        1001 << 8,
        ShardId(70_000),
        1,
        |o| o.extend_from_slice(b"not a frame"),
        &[m("k-put", Some("v")), m("k-del", None)],
    );
    b.push(1002 << 8, ShardId(3), 7, |_| {}, &[]);
    b.seal(LOG, 5, 4)
}

/// A like record (it has a backlink: src/backlinks.rs).
fn like_record() -> Vec<u8> {
    let v = serde_json::json!({"$type": "app.bsky.feed.like", "subject": {"uri": "at://did:plc:subject000000000000000000/app.bsky.feed.post/3l3qo2vutsw2a", "cid": Cid::dag_cbor(b"\xa0").to_string()}, "createdAt": TIME});
    vlpds::cbor::Value::from_json(&v).unwrap().to_cbor()
}

/// A segment of one #commit creating a like: its derived muts include the
/// backlink put (`bl/`, `segment::derive_commit_muts`).
fn segment_like() -> Vec<u8> {
    let (rec, commit, _, car) = commit_car(&like_record());
    let ops = [vlpds::events::RepoOp {
        action: "create",
        path: "app.bsky.feed.like/3l3qo2vutsw2b",
        cid: Some(rec),
        prev: None,
    }];
    let bytes = finish_commit("3l3qo2vutsw2c", commit, &car, &ops, 1010 << 8);
    let derived = segment::derive_commit_muts(&bytes, 0).unwrap();
    let mut b = SegmentBuilder::for_log(LOG);
    b.push_derived(1010 << 8, ShardId(3), 7, |o| o.extend_from_slice(&bytes), &derived, derived.len(), 0);
    b.seal(LOG, 6, 6)
}

/// The backlink index: a like's link, its `bl/` key, and a value of two rkeys.
fn backlinks() -> Vec<u8> {
    let rec = like_record();
    let link = vlpds::backlinks::link("app.bsky.feed.like", &rec).unwrap();
    let rkeys: vlpds::backlinks::Rkeys = vec!["3l3qo2vutsw2b".into(), "3l3qo2vutsw2d".into()];
    let k: BTreeMap<&str, String> = [
        ("record", hex::encode(&rec)),
        ("link", hex::encode(&link)),
        ("key bl/", hex::encode(vlpds::state::backlink_key(DID, 0, &link))),
        ("value", hex::encode(vlpds::backlinks::encode(&rkeys))),
    ]
    .into_iter()
    .collect();
    pretty(&k)
}

/// A repo's counts (`S/`, checkAccountStatus): its key and value. With
/// `bytes`, the row the console's repo bytes ride in; without, a row from
/// before they were counted (still read: the repo's next load counts them).
fn repo_stats(bytes: Option<vlpds::state::RepoBytes>) -> Vec<u8> {
    let st = vlpds::state::RepoStats { records: 1_000_003, nodes: 270_001, blobs: 4_096, bytes };
    let k: BTreeMap<&str, String> =
        [("key S/", hex::encode(vlpds::state::repo_stats_key(DID))), ("value", hex::encode(st.encode()))]
            .into_iter()
            .collect();
    pretty(&k)
}

const REPO_BYTES: vlpds::state::RepoBytes = vlpds::state::RepoBytes { records: 412_345_678, nodes: 61_234_567 };

/// A factor lockout's index entry (`L/`, listLockouts): its key and value.
fn lockout_index() -> Vec<u8> {
    let k: BTreeMap<&str, String> = [
        ("key L/", hex::encode(vlpds::state::lockout_key(DID, vlpds::xrpc::mfa::FACTOR_LOCK))),
        ("value", hex::encode(1_790_000_300u64.to_be_bytes())),
    ]
    .into_iter()
    .collect();
    pretty(&k)
}

fn head() -> vlpds::state::Head {
    let (_, commit, commit_block, rev) = commit_frame();
    vlpds::state::Head { commit, data: Cid::dag_cbor(b"\xa1aa\x01"), rev, commit_block: Bytes::from(commit_block) }
}

fn account() -> vlpds::state::Account {
    let mut a = vlpds::state::Account {
        did: DID.into(),
        handle: "fixture.test".into(),
        wrapped_signing_key: "vw1.kid.AAAA".into(),
        signing_pubkey: "zQ3shfixture".into(),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
        created_at: TIME.into(),
        status: Some("deactivated".into()),
        email: Some("fixture@example.com".into()),
        email_confirmed: true,
        repo_gen: 2,
        pending_signing_key: None,
        extra: Default::default(),
    };
    a.extra.insert(
        "preferences".into(),
        serde_json::json!([{"$type": "app.bsky.actor.defs#adultContentPref", "enabled": false}]),
    );
    a
}

fn recent() -> Vec<u8> {
    let r = vlpds::partition::RecentRepos::new(8);
    for d in ["did:plc:c", "did:plc:b", "did:plc:a"] {
        r.touch(&Arc::from(d));
    }
    r.take_dirty().unwrap().to_vec()
}

fn keys() -> Vec<u8> {
    use vlpds::state;
    let cid = Cid::dag_cbor(b"\xa1aa\x01");
    let k: BTreeMap<&str, String> = [
        ("head h/", state::head_key(DID)),
        ("account a/", state::account_key(DID)),
        ("handle", state::handle_key(DID, "fixture.test")),
        ("record R/", state::record_key(DID, 300, "app.bsky.feed.post/1")),
        ("record cid c/", state::record_cid_key(DID, 300, &cid, "app.bsky.feed.post/1")),
        ("collection C/", state::collection_key("app.bsky.feed.post", DID)),
        ("blob ref b/", state::blob_ref_key(DID, 300, &cid, "app.bsky.feed.post/1")),
        ("import G/", state::import_key(DID)),
        ("private p/", state::private_key(DID, "session/abc")),
        ("mst node M/", state::mst_node_key(DID, 300, &cid)),
    ]
    .into_iter()
    .map(|(n, k)| (n, hex::encode(k)))
    .collect();
    pretty(&k)
}

const SPACE: &str = "at://did:plc:fixture0000000000000000/space/com.example.group/main";

/// Spaces (`--spaces`): the `s*` key layout and row values.
fn space_keys() -> Vec<u8> {
    use vlpds::state;
    let sid = state::space_id(SPACE);
    let k: BTreeMap<&str, String> = [
        ("space head sH/", state::space_head_key(DID, &sid)),
        ("space record sR/", state::space_record_key(DID, &sid, "com.example.post/1")),
        ("space oplog sO/", state::space_oplog_key(DID, &sid, 0x1234_5678_9abc, 3)),
        ("space outbox sP/", state::space_outbox_key(DID, &sid)),
        ("space sS/", state::space_key(DID, &sid)),
        ("space member sM/", state::space_member_key(DID, &sid, "did:plc:member")),
        ("space writer sW/", state::space_writer_key(DID, &sid, "did:plc:writer")),
        ("space seq sQ/", state::space_seq_key(DID, &sid, 0x1234_5678_9abc)),
    ]
    .into_iter()
    .map(|(n, k)| (n, hex::encode(k)))
    .collect();
    pretty(&k)
}

fn space_head() -> vlpds::space::rows::HeadRow {
    let mut hash = vlpds::space::lthash::LtHash::default();
    hash.add(&vlpds::space::commit::element("com.example.post", "1", &Cid::dag_cbor(b"\xa1aa\x01").to_string()));
    vlpds::space::rows::HeadRow {
        uri: SPACE.into(),
        rev: vlpds::tid::Tid(0x1234_5678_9abc),
        hash,
        records: 1,
        created: 1_790_000_000_000_000,
    }
}

fn space_ops() -> Vec<u8> {
    use vlpds::space::rows::{OpAction, OpRow};
    let (a, b) = (Cid::dag_cbor(b"\xa1aa\x01"), Cid::dag_cbor(b"\xa1aa\x02"));
    let ops = [
        OpRow {
            action: OpAction::Create,
            collection: "com.example.post".into(),
            rkey: "1".into(),
            cid: Some(a),
            prev: None,
        },
        OpRow {
            action: OpAction::Update,
            collection: "com.example.post".into(),
            rkey: "1".into(),
            cid: Some(b),
            prev: Some(a),
        },
        OpRow {
            action: OpAction::Delete,
            collection: "com.example.post".into(),
            rkey: "1".into(),
            cid: None,
            prev: Some(b),
        },
    ];
    let mut out = Vec::new();
    for op in ops {
        let v = op.encode();
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(&v);
    }
    out
}

fn space_ops_decode(b: &[u8]) -> Vec<vlpds::space::rows::OpRow> {
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        out.push(vlpds::space::rows::OpRow::decode(&rest[4..4 + n]).unwrap());
        rest = &rest[4 + n..];
    }
    out
}

fn space_outbox() -> vlpds::space::rows::OutboxRow {
    vlpds::space::rows::OutboxRow { uri: SPACE.into(), repo_rev: vlpds::tid::Tid(0x1234_5678_9abc), hash: [7; 32] }
}

fn space_writer() -> vlpds::space::rows::WriterRow {
    vlpds::space::rows::WriterRow {
        repo_rev: vlpds::tid::Tid(0x1234_5678_9abc),
        hash: [7; 32],
        space_rev: vlpds::tid::Tid(0x1234_5678_9abd),
    }
}

/// A notify registration (`sN`): its key and row.
fn space_notify() -> Vec<u8> {
    let sid = vlpds::state::space_id(SPACE);
    let key = vlpds::state::space_notify_key(DID, &sid, "did:web:syncer.example#atproto_space_syncer");
    let row =
        vlpds::space::rows::NotifyRow { endpoint: "https://syncer.example".into(), expires: 1_790_000_000_000_000 };
    let k: BTreeMap<&str, String> =
        [("space notify sN/", hex::encode(key)), ("row", hex::encode(row.encode()))].into_iter().collect();
    pretty(&k)
}

/// A space blob ref (`sb`, its rev) and its CID-major twin (`sc`).
fn space_blob_refs() -> Vec<u8> {
    let sid = vlpds::state::space_id(SPACE);
    let blob = Cid::raw(b"space blob fixture");
    let path = "com.example.post/1";
    let k: BTreeMap<&str, String> = [
        ("space blob sb/", hex::encode(vlpds::state::space_blob_key(DID, &sid, &blob, path))),
        ("space blob by cid sc/", hex::encode(vlpds::state::space_blob_cid_key(DID, &blob, &sid, path))),
        ("sb row", hex::encode(0x1234_5678_9abc_u64.to_be_bytes())),
    ]
    .into_iter()
    .collect();
    pretty(&k)
}

/// listSpaces's index rows (`sL`): held and governed, both empty.
fn space_list() -> Vec<u8> {
    use vlpds::state::SpaceListed;
    let k: BTreeMap<&str, String> = [
        ("space list sL/ repo", hex::encode(vlpds::state::space_list_key(DID, SPACE, SpaceListed::Repo))),
        ("space list sL/ governs", hex::encode(vlpds::state::space_list_key(DID, SPACE, SpaceListed::Governs))),
    ]
    .into_iter()
    .collect();
    pretty(&k)
}

fn space_space() -> vlpds::space::rows::SpaceRow {
    vlpds::space::rows::SpaceRow::defaults(SPACE, TIME)
}

fn pretty<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let mut b = serde_json::to_vec_pretty(v).unwrap();
    b.push(b'\n');
    b
}

fn compact<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn lease() -> vlpds::cluster::NodeLease {
    vlpds::cluster::NodeLease {
        node_id: "node-a".into(),
        log_id: LOG.into(),
        addr: "http://10.0.0.1:2583".into(),
        writer: 17,
        expires_ms: 1_790_000_010_000,
        renewals: 42,
        next_ordinal: 6,
        draining: false,
        joined: true,
        follows: [("node-b.1790000000000001".to_string(), 255_000i64)].into(),
        wm_cap: 458_240_002_560_000_000,
        rev: "0123abc".into(),
        min_level: 1,
        max_level: 1,
        seen_level: 1,
        pending_age_ms: None,
    }
}

fn assignment() -> vlpds::cluster::Assignment {
    use vlpds::nodelog::Span;
    vlpds::cluster::Assignment {
        owner: Some("node-a".into()),
        log_id: Some(LOG.into()),
        addr: Some("http://10.0.0.1:2583".into()),
        epoch: 3,
        seq_floor: 256_000,
        history: vec![
            Span { log_id: "node-b.1".into(), epoch: 2, start: 0, end: Some(9) },
            Span { log_id: LOG.into(), epoch: 3, start: 6, end: None },
        ],
        frozen: None,
        applied_epoch: 0,
        extra: Default::default(),
    }
}

fn layout() -> vlpds::slots::Layout {
    let l = vlpds::slots::Layout::uniform(4);
    let op = l.plan_split(ShardId(1), None, "node-a").unwrap();
    l.with_op(op)
}

fn report() -> vlpds::retention::Report {
    vlpds::retention::Report::new([(ShardId(3), 7), (ShardId(70_000), 1)].into(), 255_000, 1)
}

fn ratelimits() -> Vec<u8> {
    let d = vlpds::ratelimit::config::parse(
        br#"{"version": 7, "enabled": true, "limiters": {"global-ip": {"points": 6000}}, "routes": [{"nsid": "app.bsky.feed.getTimeline", "points": 600, "windowSecs": 300}], "overrides": [{"ip": "203.0.113.0/24", "limiters": ["global-ip"], "exempt": true, "note": "relay"}], "updatedAt": "2026-10-01T00:00:00.000Z", "updatedBy": "jaz", "history": [{"version": 7, "at": "2026-10-01T00:00:00.000Z", "by": "jaz", "node": "node-a", "changes": ["routes: + app.bsky.feed.getTimeline"]}]}"#,
    )
    .unwrap();
    compact(&d)
}

fn space_revocations() -> vlpds::space::revocations::Doc {
    use vlpds::space::revocations::{Doc, Entry};
    let space = "at://did:plc:fixture0000000000000000/space/com.example.group/main".to_string();
    Doc {
        revoked: vec![
            Entry { space: space.clone(), jti: "3k2a7bq5zzc2a".into(), until: 1_790_003_610, aud: String::new() },
            Entry { space, jti: "3k2a7bq5zzc2b".into(), until: 1_790_003_611, aud: String::new() },
        ],
        ..Default::default()
    }
}

fn cluster_version() -> version::ClusterVersion {
    version::ClusterVersion {
        active: 1,
        target: None,
        history: vec![version::Change { level: 1, at: TIME.into(), by: "node-a".into(), extra: Default::default() }],
        extra: Default::default(),
    }
}

/// The writer claim `Cluster::join` writes (a JSON literal there).
fn writer_claim() -> Vec<u8> {
    compact(&serde_json::json!({"node_id": "node-a", "log_id": LOG, "confirmed": true}))
}

fn frames() -> Vec<(&'static str, Vec<u8>)> {
    use vlpds::events;
    let fin = |f: events::Frame, seq: i64| {
        let mut b = Vec::new();
        f.finish(seq, &mut b);
        b
    };
    let mut car = Vec::new();
    let c = Cid::dag_cbor(b"\xa0");
    vlpds::car::write_header(&mut car, &c);
    vlpds::car::write_block(&mut car, &c, b"\xa0");
    vec![
        ("firehose/commit.frame", commit_frame().0),
        ("firehose/identity.frame", fin(events::identity_frame(DID, "fixture.test", TIME), 1003 << 8)),
        ("firehose/account.frame", fin(events::account_frame(DID, false, Some("deactivated"), TIME), 1004 << 8)),
        ("firehose/sync.frame", fin(events::sync_frame(DID, "3l3qo2vutsw2b", &car, TIME), 1005 << 8)),
        ("firehose/error.frame", events::error_frame("FutureCursor", "Cursor in the future.")),
    ]
}

/// Every fixture this build writes at the active level (path -> bytes),
/// except the wrapped secret (random nonce).
fn written() -> Vec<(&'static str, Vec<u8>)> {
    let plain = segment_plain();
    let zstd = segment::compress(&plain, 1).unwrap().expect("compressible");
    let batch = vlpds::nodelog::LogBatch {
        log_id: LOG.into(),
        ordinal: 5,
        events: vec![(1000 << 8, Bytes::from(commit_frame().0)), (1003 << 8, Bytes::from_static(b"frame"))],
    };
    let h = head();
    let mut v = vec![
        ("segment/plain.seg", plain),
        ("segment/zstd.seg", zstd),
        ("segment/fence.bin", segment::fence_object("node-b").to_vec()),
        ("segment/like.seg", segment_like()),
        ("state/backlinks.json", backlinks()),
        ("state/repo_stats.json", repo_stats(None)),
        ("state/repo_stats_bytes.json", repo_stats(Some(REPO_BYTES))),
        ("state/lockout_index.json", lockout_index()),
        ("state/head.bin", h.encode().to_vec()),
        ("state/record.bin", vlpds::state::record_value(&h.data, h.rev.0, b"\xa1aa\x01").to_vec()),
        ("state/account.json", compact(&account())),
        ("state/applied2.bin", vlpds::nodelog::encode_marker(LOG, 5)),
        ("state/recent.bin", recent()),
        ("state/keys.json", keys()),
        ("state/space_keys.json", space_keys()),
        ("state/space_head.bin", space_head().encode().to_vec()),
        ("state/space_oplog.bin", space_ops()),
        ("state/space_outbox.bin", space_outbox().encode().to_vec()),
        ("state/space_writer.bin", space_writer().encode().to_vec()),
        ("state/space_space.json", space_space().encode().to_vec()),
        ("state/space_notify.json", space_notify()),
        ("state/space_blob_refs.json", space_blob_refs()),
        ("state/space_list.json", space_list()),
        ("control/node_lease.json", compact(&lease())),
        ("control/assignment.json", compact(&assignment())),
        ("control/layout.json", compact(&layout())),
        ("control/writer_claim.json", writer_claim()),
        ("control/retain_report.json", compact(&report())),
        ("control/ratelimits.json", ratelimits()),
        ("control/cluster_version.json", compact(&cluster_version())),
        ("control/space_revocations.json", space_revocations().encode()),
        ("stream/batch.bin", vlpds::remote::encode_batch(&batch).to_vec()),
        ("stream/watermark.bin", vlpds::remote::encode_watermark(1003 << 8).to_vec()),
        ("private/rows.json", private_rows()),
        ("private/blob_quota.json", blob_quota_rows()),
        ("private/app_password_scopes.json", app_password_scope_rows()),
        ("private/sign_in.json", rows_json(vlpds::xrpc::private_rows::sign_in_row_fixtures(DID))),
        ("private/passkeys.json", rows_json(vlpds::xrpc::private_rows::passkey_row_fixtures(DID))),
    ];
    v.extend(frames());
    v
}

const SECRET_FIXTURE: &str = "secrets/vw1.txt";

fn secrets() -> vlpds::secrets::Secrets {
    let k = vlpds::secrets::KekBytes::new(KEK);
    vlpds::secrets::Secrets::new(vec![Arc::new(vlpds::secrets::LocalKek::new(&k))], 1).unwrap()
}

/// Every private (`p/`) row kind, from the lib's fixed-value builders
/// (`vlpds::xrpc::private_rows`): `[{routing, name, value}]`, values UTF-8.
fn private_rows() -> Vec<u8> {
    rows_json(vlpds::xrpc::private_rows::private_row_fixtures(DID))
}

/// Blob quota rows (`private_rows::blob_quota_row_fixtures`), added after
/// level 1's `private/rows.json` was frozen.
fn blob_quota_rows() -> Vec<u8> {
    rows_json(vlpds::xrpc::private_rows::blob_quota_row_fixtures(DID))
}

/// Scoped app password rows, added after level 1's `private/rows.json` was
/// frozen.
fn app_password_scope_rows() -> Vec<u8> {
    rows_json(vlpds::xrpc::private_rows::app_password_scope_row_fixtures(DID))
}

fn rows_json(rows: Vec<vlpds::xrpc::private_rows::PrivateRow>) -> Vec<u8> {
    let rows: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(routing, name, v)| serde_json::json!({"routing": routing, "name": name, "value": String::from_utf8(v).expect("private row values are UTF-8")}))
        .collect();
    pretty(&rows)
}

/// Session JWTs (access, refresh; one per line): random (their iat/exp), so
/// recorded once.
const JWT_FIXTURE: &str = "auth/session.jwt";
const JWT_SECRET: &str = "fixture-jwt-secret";
const JWT_AUD: &str = "did:web:fixture.test";
const JWT_FAMILY: &str = "0006439b2a1c0000aabbccddeeff0011";
const JWT_REFRESH_ID: &str = "00112233445566778899aabbccddeeff0011223344556600";

fn jwts() -> String {
    let j = vlpds::auth::Jwt::new(JWT_SECRET, JWT_AUD);
    let access = j.issue_with_jti(DID, "com.atproto.access", 2 * 3600, "at+jwt", Some(JWT_FAMILY));
    let refresh = j.issue_with_jti(DID, "com.atproto.refresh", 90 * 86400, "refresh+jwt", Some(JWT_REFRESH_ID));
    format!("{access}\n{refresh}\n")
}

/// A shard's SlateDB directory written by the pinned slatedb rev
/// (`slatedb/` + paths under the DB root): random (ULIDs, timestamps), so
/// recorded once.
const SLATEDB_DIR: &str = "slatedb/";

/// The keys the SlateDB fixture holds after its writes (two flushes: two L0
/// SSTs, the second deleting a key of the first).
fn slatedb_rows() -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let h = head();
    vec![
        (vlpds::state::head_key(DID), Some(h.encode().to_vec())),
        (
            vlpds::state::record_key(DID, 0, "app.bsky.feed.post/1"),
            Some(vlpds::state::record_value(&h.data, h.rev.0, b"\xa1aa\x01").to_vec()),
        ),
        (vlpds::state::collection_key("app.bsky.feed.post", DID), Some(Vec::new())),
        (vlpds::state::record_key(DID, 0, "app.bsky.feed.post/2"), None),
    ]
}

fn slatedb_store(prefix: &str) -> (vlpds::store::Store, Arc<object_store::memory::InMemory>) {
    let mem = Arc::new(object_store::memory::InMemory::new());
    (vlpds::store::Store { raw: mem.clone(), prefix: prefix.into(), latency: None }, mem)
}

/// Writes a tiny shard DB the way a node opens one (`partition::open_db`)
/// and snapshots its objects into `dir/slatedb/`.
async fn record_slatedb(dir: &std::path::Path) {
    use futures::StreamExt;
    use object_store::{ObjectStore, ObjectStoreExt};
    let (store, mem) = slatedb_store("fx");
    let db = vlpds::partition::open_db(&store, ShardId(0), None).await.unwrap();
    let rows = slatedb_rows();
    db.put(&rows[3].0, b"deleted later").await.unwrap();
    db.put(&rows[0].0, rows[0].1.as_ref().unwrap()).await.unwrap();
    db.flush().await.unwrap();
    for (k, v) in &rows[1..] {
        match v {
            Some(v) => db.put(k, v).await.unwrap(),
            None => db.delete(k).await.unwrap(),
        };
    }
    db.flush().await.unwrap();
    db.close().await.unwrap();
    let root = vlpds::partition::db_path(&store, ShardId(0));
    let objs: Vec<_> =
        mem.list(Some(&object_store::path::Path::from(root.as_str()))).map(|m| m.unwrap().location).collect().await;
    for p in objs {
        let rel = p.as_ref().strip_prefix(&format!("{root}/")).unwrap().to_string();
        let b = mem.get(&p).await.unwrap().bytes().await.unwrap();
        let f = dir.join(SLATEDB_DIR).join(&rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, &b).unwrap();
    }
}

/// Opens the SlateDB fixture with this build: the keys read back, and a new
/// write over the old manifest and SSTs reopens.
async fn check_slatedb(level: u32) {
    use object_store::ObjectStoreExt;
    let dir = level_dir(level);
    let names: Vec<String> = files(&dir).into_iter().filter(|f| f.starts_with(SLATEDB_DIR)).collect();
    assert!(names.iter().any(|f| f.ends_with(".manifest")), "L{level}: SlateDB fixture has no manifest: {names:?}");
    let (store, mem) = slatedb_store("fx2");
    let root = vlpds::partition::db_path(&store, ShardId(0));
    for n in &names {
        let rel = n.strip_prefix(SLATEDB_DIR).unwrap();
        let b = std::fs::read(dir.join(n)).unwrap();
        mem.put(&object_store::path::Path::from(format!("{root}/{rel}")), b.into()).await.unwrap();
    }
    let db = vlpds::partition::open_db(&store, ShardId(0), None)
        .await
        .unwrap_or_else(|e| panic!("L{level}: SlateDB fixture doesn't open: {e:#}"));
    for (k, v) in slatedb_rows() {
        assert_eq!(
            db.get(&k).await.unwrap().map(|b| b.to_vec()),
            v,
            "L{level}: SlateDB fixture key {}",
            hex::encode(&k)
        );
    }
    db.put(b"new", b"write").await.unwrap();
    db.flush().await.unwrap();
    db.close().await.unwrap();
    let db = vlpds::partition::open_db(&store, ShardId(0), None).await.unwrap();
    assert_eq!(db.get(b"new").await.unwrap().as_deref(), Some(&b"write"[..]));
    assert_eq!(db.get(vlpds::state::head_key(DID)).await.unwrap().map(|b| b.to_vec()), slatedb_rows()[0].1);
    db.close().await.unwrap();
}

/// Records the fixtures that are random by construction (wrapped secret,
/// JWTs, SlateDB directory) where missing.
async fn record_once(dir: &std::path::Path) {
    let p = dir.join(SECRET_FIXTURE);
    if !p.exists() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let blob = secrets().wrap(vlpds::secrets::Purpose::SigningKey, DID, SECRET).await.unwrap();
        std::fs::write(&p, format!("{blob}\n")).unwrap();
    }
    let p = dir.join(JWT_FIXTURE);
    if !p.exists() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, jwts()).unwrap();
    }
    if !dir.join(SLATEDB_DIR).exists() {
        record_slatedb(dir).await;
    }
}

fn check_jwts(name: &str, b: &[u8]) {
    use base64::Engine;
    let j = vlpds::auth::Jwt::new(JWT_SECRET, JWT_AUD);
    let text = std::str::from_utf8(b).unwrap();
    let toks: Vec<&str> = text.lines().collect();
    assert_eq!(toks.len(), 2, "{name}: access and refresh");
    for (tok, (typ, scope, jti)) in toks
        .iter()
        .zip([("at+jwt", "com.atproto.access", JWT_FAMILY), ("refresh+jwt", "com.atproto.refresh", JWT_REFRESH_ID)])
    {
        let c = j.verify_signature(tok).unwrap_or_else(|| panic!("{name}: {typ} doesn't verify"));
        assert_eq!(
            (c.scope.as_str(), c.sub.as_str(), c.aud.as_str(), c.jti.as_deref()),
            (scope, DID, JWT_AUD, Some(jti)),
            "{name}"
        );
        assert!(c.exp > c.iat, "{name}");
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut parts = tok.split('.');
        let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts.next().unwrap()).unwrap()).unwrap();
        assert_eq!((header["alg"].as_str(), header["typ"].as_str()), (Some("HS256"), Some(typ)), "{name}");
        // the claims re-encode to the signed payload (no field dropped)
        assert_eq!(b64.encode(serde_json::to_vec(&c).unwrap()), parts.next().unwrap(), "{name}: claims re-encode");
    }
}

fn files(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(base: &std::path::Path, d: &std::path::Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.push(p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    if dir.exists() {
        walk(dir, dir, &mut out);
    }
    out.sort();
    out
}

#[tokio::test]
async fn writers_reproduce_the_max_level_fixtures() {
    // writers emit the active level (process-wide): the build's max here
    let _level = crate::common::ACTIVE_LEVEL.lock().await;
    version::set_active(version::MAX_LEVEL);
    let dir = level_dir(version::MAX_LEVEL);
    let written = written();
    if bless() {
        for (name, bytes) in &written {
            let p = dir.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            if std::fs::read(&p).ok().as_deref() != Some(bytes.as_slice()) {
                std::fs::write(&p, bytes).unwrap();
                eprintln!("blessed {}", p.display());
            }
        }
        record_once(&dir).await;
    }
    for (name, bytes) in &written {
        let got = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e} (VLPDS_BLESS=1 to record)"));
        assert!(
            got == *bytes,
            "{name}: this build writes different bytes than L{} records: a format change needs a new level",
            version::MAX_LEVEL
        );
    }
    // plus the fixtures recorded once (random by construction)
    let mut expected: Vec<String> = written
        .iter()
        .map(|(n, _)| n.to_string())
        .chain([SECRET_FIXTURE.to_string(), JWT_FIXTURE.to_string()])
        .collect();
    expected.sort();
    let got: Vec<String> = files(&dir).into_iter().filter(|f| !f.starts_with(SLATEDB_DIR)).collect();
    assert_eq!(got, expected, "fixture files of L{}", version::MAX_LEVEL);
    assert!(
        files(&dir).iter().any(|f| f.starts_with(SLATEDB_DIR)),
        "L{}: no SlateDB fixture (VLPDS_BLESS=1 to record)",
        version::MAX_LEVEL
    );
}

fn cbor_reencode(name: &str, b: &[u8]) {
    use vlpds::cbor::Value;
    let (h, n) = Value::decode_prefix(b).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let body = Value::decode(&b[n..]).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let mut out = Vec::new();
    h.encode(&mut out);
    body.encode(&mut out);
    assert!(out == b, "{name}: dag-cbor re-encode differs");
}

/// A parsed segment re-sealed by this build at `level`.
fn reseal(h: &segment::SegHeader, entries: &[segment::SegEntry], level: u32) -> Vec<u8> {
    let mut sb = SegmentBuilder::for_log_at(&h.log_id, level);
    for e in entries {
        let frame = e.frame.clone();
        sb.push_derived(e.seq, e.shard, e.epoch, |o| o.extend_from_slice(&frame), &e.muts, e.derived, e.gen);
    }
    sb.seal(&h.log_id, h.ordinal, h.prefix_end)
}

fn json_reencode<T: serde::Serialize + serde::de::DeserializeOwned>(name: &str, b: &[u8]) -> T {
    let v: T = serde_json::from_slice(b).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(compact(&v) == b, "{name}: JSON re-encode differs");
    v
}

/// Decodes one fixture with this build's readers and re-encodes it.
async fn check(level: u32, name: &str, b: &[u8]) {
    let dir = level_dir(level);
    match name {
        "segment/plain.seg" => {
            let (h, _) = segment::parse_header(b).unwrap().unwrap();
            assert_eq!((h.level, h.codec, h.ordinal, h.prefix_end, h.count), (level, segment::CODEC_NONE, 5, 4, 3));
            assert_eq!(
                h.checksum.is_some(),
                level == version::TEST_LEVEL,
                "only the test level's header has a checksum"
            );
            let LogObject::Segment(h, entries) = segment::parse(Bytes::copy_from_slice(b), true, None).unwrap() else {
                panic!("{name}")
            };
            assert_eq!(entries[0].derived, 4, "#commit muts are derived, not stored");
            assert!(reseal(&h, &entries, level) == b, "{name}: re-encode differs");
        }
        "segment/zstd.seg" => {
            let (h, _) = segment::parse_header(b).unwrap().unwrap();
            assert_eq!((h.level, h.codec), (level, segment::CODEC_ZSTD));
            // zstd's output may change with the library; only decoding is a format
            let plain = std::fs::read(dir.join("segment/plain.seg")).unwrap();
            assert!(segment::decode(Bytes::copy_from_slice(b)).unwrap() == plain, "{name}: decodes to plain.seg");
        }
        "segment/like.seg" => {
            let LogObject::Segment(h, entries) = segment::parse(Bytes::copy_from_slice(b), true, None).unwrap() else {
                panic!("{name}")
            };
            assert_eq!(h.level, level, "{name}: segment level");
            let e = &entries[0];
            // c/ put, R/ put, the backlink put, h/
            assert_eq!(e.derived, 4, "{name}: #commit muts derived");
            let bl = &e.muts[2];
            assert_eq!(vlpds::state::key_body(&bl.key)[..3], *b"bl/", "{name}: the like's backlink put");
            assert_eq!(bl.val.as_deref(), Some(&b"3l3qo2vutsw2b"[..]));
            assert!(reseal(&h, &entries, level) == b, "{name}: re-encode differs");
        }
        "state/backlinks.json" => {
            let k: BTreeMap<String, String> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&k) == b);
            let hx = |n: &str| hex::decode(&k[n]).unwrap();
            let link = vlpds::backlinks::link("app.bsky.feed.like", &hx("record")).unwrap();
            assert_eq!(link, hx("link"));
            assert_eq!(vlpds::state::backlink_key(DID, 0, &link), hx("key bl/"));
            assert_eq!(vlpds::state::key_slot(&hx("key bl/")), Some(vlpds::slots::slot_of(DID)));
            let v = vlpds::backlinks::decode(&hx("value"));
            assert_eq!(v.len(), 2);
            assert!(vlpds::backlinks::encode(&v) == hx("value"));
        }
        "state/repo_stats.json" | "state/repo_stats_bytes.json" => {
            let k: BTreeMap<String, String> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&k) == b);
            let key = hex::decode(&k["key S/"]).unwrap();
            assert_eq!(key, vlpds::state::repo_stats_key(DID));
            assert_eq!(vlpds::state::key_slot(&key), Some(vlpds::slots::slot_of(DID)));
            let v = hex::decode(&k["value"]).unwrap();
            let st = vlpds::state::RepoStats::decode(&v).unwrap();
            assert_eq!((st.records, st.nodes, st.blobs), (1_000_003, 270_001, 4_096));
            let want = (name.ends_with("_bytes.json")).then_some(REPO_BYTES);
            assert_eq!(st.bytes, want);
            assert!(st.encode() == v);
        }
        "state/lockout_index.json" => {
            let k: BTreeMap<String, String> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&k) == b);
            let key = hex::decode(&k["key L/"]).unwrap();
            assert_eq!(key, vlpds::state::lockout_key(DID, vlpds::xrpc::mfa::FACTOR_LOCK));
            assert_eq!(vlpds::state::key_slot(&key), Some(vlpds::slots::slot_of(DID)));
            assert_eq!(hex::decode(&k["value"]).unwrap(), 1_790_000_300u64.to_be_bytes());
        }

        "segment/fence.bin" => {
            let LogObject::Fence { by } = segment::parse(Bytes::copy_from_slice(b), true, None).unwrap() else {
                panic!("{name}")
            };
            assert!(segment::fence_object(&by) == b);
        }
        "state/head.bin" => {
            let h = vlpds::state::Head::decode(&Bytes::copy_from_slice(b)).unwrap();
            assert!(h.encode() == b);
        }
        "state/record.bin" => {
            let v = Bytes::copy_from_slice(b);
            let (cid, rec) = vlpds::state::decode_record_value(&v).unwrap();
            assert!(vlpds::state::record_value(&cid, vlpds::state::record_value_rev(b), &rec) == b);
        }
        "state/account.json" => {
            let a: vlpds::state::Account = json_reencode(name, b);
            assert!(a.extra.contains_key("preferences"), "extension fields round-trip");
        }
        "state/applied2.bin" => {
            let (log, ord) = vlpds::nodelog::decode_marker(b).unwrap();
            assert!(vlpds::nodelog::encode_marker(&log, ord) == b);
        }
        "state/recent.bin" => {
            let dids = vlpds::partition::RecentRepos::decode(b);
            let r = vlpds::partition::RecentRepos::new(8);
            for d in dids.iter().rev() {
                r.touch(d);
            }
            assert!(r.take_dirty().unwrap() == b);
        }
        "state/keys.json" => {
            let k: BTreeMap<String, String> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&k) == b);
            for (n, hexkey) in &k {
                let key = hex::decode(hexkey).unwrap();
                assert_eq!(
                    vlpds::state::key_slot(&key),
                    Some(vlpds::slots::slot_of(DID)),
                    "{n}: slot-prefixed by the DID's slot"
                );
            }
        }
        "state/space_keys.json" => {
            let k: BTreeMap<String, String> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&k) == b);
            for (n, hexkey) in &k {
                let key = hex::decode(hexkey).unwrap();
                assert_eq!(vlpds::state::key_slot(&key), Some(vlpds::slots::slot_of(DID)), "{n}");
                assert!(vlpds::state::is_space_key(&key), "{n}");
            }
        }
        "state/space_head.bin" => {
            let h = vlpds::space::rows::HeadRow::decode(b).unwrap();
            assert_eq!((h.uri.as_str(), h.records), (SPACE, 1));
            assert!(h.encode() == b);
        }
        "state/space_oplog.bin" => {
            let ops = space_ops_decode(b);
            assert_eq!(ops.len(), 3);
            let mut again = Vec::new();
            for op in ops {
                let v = op.encode();
                again.extend_from_slice(&(v.len() as u32).to_be_bytes());
                again.extend_from_slice(&v);
            }
            assert!(again == b);
        }
        "state/space_outbox.bin" => {
            let o = vlpds::space::rows::OutboxRow::decode(b).unwrap();
            assert!(o.encode() == b);
        }
        "state/space_writer.bin" => {
            let w = vlpds::space::rows::WriterRow::decode(b).unwrap();
            assert!(w.encode() == b);
        }
        "state/space_notify.json" => {
            let k: BTreeMap<String, String> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&k) == b);
            let key = hex::decode(&k["space notify sN/"]).unwrap();
            assert_eq!(vlpds::state::key_slot(&key), Some(vlpds::slots::slot_of(DID)));
            assert!(vlpds::state::is_space_key(&key));
            let row = hex::decode(&k["row"]).unwrap();
            let r = vlpds::space::rows::NotifyRow::decode(&row).unwrap();
            assert!(r.encode() == row);
        }
        "state/space_blob_refs.json" => {
            let k: BTreeMap<String, String> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&k) == b);
            let sid = vlpds::state::space_id(SPACE);
            let sb = hex::decode(&k["space blob sb/"]).unwrap();
            let sc = hex::decode(&k["space blob by cid sc/"]).unwrap();
            for key in [&sb, &sc] {
                assert_eq!(vlpds::state::key_slot(key), Some(vlpds::slots::slot_of(DID)));
                assert!(vlpds::state::is_space_key(key));
            }
            let prefix = vlpds::state::space_prefix(vlpds::state::SPACE_BLOB_FAMILY, DID, &sid);
            let (cid, path) = vlpds::space::rows::blob_ref_parts(&sb[prefix.len()..]).unwrap();
            let blob = Cid::parse(cid).unwrap();
            assert!(vlpds::state::space_blob_key(DID, &sid, &blob, path) == sb);
            assert!(vlpds::state::space_blob_cid_key(DID, &blob, &sid, path) == sc);
            let rev = vlpds::space::rows::blob_ref_rev(&hex::decode(&k["sb row"]).unwrap());
            assert_eq!(rev.0, 0x1234_5678_9abc);
        }
        "state/space_list.json" => {
            use vlpds::state::SpaceListed;
            let k: BTreeMap<String, String> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&k) == b);
            let base = vlpds::state::space_did_prefix(vlpds::state::SPACE_LIST_FAMILY, DID);
            for (name, why) in
                [("space list sL/ repo", SpaceListed::Repo), ("space list sL/ governs", SpaceListed::Governs)]
            {
                let key = hex::decode(&k[name]).unwrap();
                assert_eq!(vlpds::state::key_slot(&key), Some(vlpds::slots::slot_of(DID)));
                assert!(vlpds::state::is_space_key(&key));
                assert_eq!(vlpds::state::space_list_uri(&key, &base), Some(SPACE));
                assert!(vlpds::state::space_list_key(DID, SPACE, why) == key);
            }
        }
        "state/space_space.json" => {
            let r = vlpds::space::rows::SpaceRow::decode(b).unwrap();
            assert!(r.live() && r.encode() == b);
        }
        "control/node_lease.json" => {
            json_reencode::<vlpds::cluster::NodeLease>(name, b);
        }
        "control/assignment.json" => {
            json_reencode::<vlpds::cluster::Assignment>(name, b);
        }
        "control/layout.json" => json_reencode::<vlpds::slots::Layout>(name, b).validate().unwrap(),
        "control/writer_claim.json" => {
            json_reencode::<serde_json::Value>(name, b);
        }
        "control/retain_report.json" => {
            let r = json_reencode::<vlpds::retention::Report>(name, b);
            assert_eq!(
                r.min_seg_format.is_some(),
                level == version::TEST_LEVEL,
                "min_seg_format is the test level's field"
            );
        }
        "control/ratelimits.json" => {
            let d = vlpds::ratelimit::config::parse(b).unwrap();
            assert!(compact(&d) == b);
            vlpds::ratelimit::config::compile(Some(&d)).unwrap();
        }
        "control/cluster_version.json" => {
            json_reencode::<version::ClusterVersion>(name, b);
        }
        "control/space_revocations.json" => {
            let d = vlpds::space::revocations::Doc::decode(b).unwrap();
            assert!(d.encode() == b, "{name}");
        }
        "stream/batch.bin" => {
            let vlpds::remote::StreamMsg::Batch(batch) =
                vlpds::remote::decode(&Arc::from(LOG), Bytes::copy_from_slice(b)).unwrap()
            else {
                panic!("{name}")
            };
            assert!(vlpds::remote::encode_batch(&batch) == b);
        }
        "stream/watermark.bin" => {
            let vlpds::remote::StreamMsg::Watermark(w) =
                vlpds::remote::decode(&Arc::from(LOG), Bytes::copy_from_slice(b)).unwrap()
            else {
                panic!("{name}")
            };
            assert!(vlpds::remote::encode_watermark(w) == b);
        }
        SECRET_FIXTURE => {
            let blob = std::str::from_utf8(b).unwrap().trim_end();
            let plain = secrets().unwrap(vlpds::secrets::Purpose::SigningKey, DID, blob).await.unwrap();
            assert_eq!(&plain.plaintext[..], SECRET);
            let parts: Vec<&str> = blob.splitn(3, '.').collect();
            assert_eq!((parts[0], parts[1]), ("vw1", vlpds::secrets::KekBytes::new(KEK).kid().as_str()));
            assert_eq!(format!("{}.{}.{}\n", parts[0], parts[1], parts[2]).as_bytes(), b);
        }
        n if n.starts_with("firehose/") => cbor_reencode(n, b),
        "private/rows.json" => {
            let rows: Vec<serde_json::Value> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&rows) == b, "{name}: re-encode differs");
            let mut kinds = std::collections::BTreeSet::new();
            for r in &rows {
                let (routing, n, v) =
                    (r["routing"].as_str().unwrap(), r["name"].as_str().unwrap(), r["value"].as_str().unwrap());
                let kind = vlpds::xrpc::private_rows::check_private_row(routing, n, v.as_bytes())
                    .unwrap_or_else(|e| panic!("L{level}/{name}: {routing} {n}: {e:#}"));
                kinds.insert(kind);
            }
            assert!(kinds.len() >= 20, "L{level}/{name}: only {} row kinds: {kinds:?}", kinds.len());
        }
        "private/blob_quota.json"
        | "private/app_password_scopes.json"
        | "private/sign_in.json"
        | "private/passkeys.json" => {
            let rows: Vec<serde_json::Value> = serde_json::from_slice(b).unwrap();
            assert!(pretty(&rows) == b, "{name}: re-encode differs");
            for r in &rows {
                let (routing, n, v) =
                    (r["routing"].as_str().unwrap(), r["name"].as_str().unwrap(), r["value"].as_str().unwrap());
                vlpds::xrpc::private_rows::check_private_row(routing, n, v.as_bytes())
                    .unwrap_or_else(|e| panic!("L{level}/{name}: {routing} {n}: {e:#}"));
            }
        }
        JWT_FIXTURE => check_jwts(name, b),
        // checked as a whole: check_slatedb
        n if n.starts_with(SLATEDB_DIR) => {}
        n => panic!("L{level}/{n}: no reader check for this fixture"),
    }
}

#[tokio::test]
async fn fixtures_decode_and_reencode() {
    for level in version::MIN_LEVEL..=version::MAX_LEVEL {
        let dir = level_dir(level);
        let names = files(&dir);
        assert!(!names.is_empty(), "no fixtures for level {level}");
        for name in names {
            let b = std::fs::read(dir.join(&name)).unwrap();
            check(level, &name, &b).await;
        }
        check_slatedb(level).await;
    }
}

/// `MANIFEST`: `sha256  L{n}/path` per fixture file of every recorded level.
fn manifest() -> BTreeMap<String, String> {
    std::fs::read_to_string(root().join("MANIFEST"))
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (h, p) = l.split_once("  ").expect("`sha256  path`");
            (p.to_string(), h.to_string())
        })
        .collect()
}

fn hashes(level: u32) -> BTreeMap<String, String> {
    let dir = level_dir(level);
    files(&dir)
        .into_iter()
        .map(|f| (format!("L{level}/{f}"), hex::encode(Sha256::digest(std::fs::read(dir.join(&f)).unwrap()))))
        .collect()
}

#[test]
fn manifest_freezes_released_levels() {
    let mut m = manifest();
    if bless() {
        // the test-only level is never recorded
        for level in (1..=version::MAX_LEVEL).filter(|l| *l != version::TEST_LEVEL) {
            let recorded = m.keys().any(|k| k.starts_with(&format!("L{level}/")));
            if level > version::RELEASED || !recorded {
                m.retain(|k, _| !k.starts_with(&format!("L{level}/")));
                m.extend(hashes(level));
            } else {
                // a released level: fixtures recorded later (formats it
                // already had) are added; existing entries never change
                for (k, h) in hashes(level) {
                    m.entry(k).or_insert(h);
                }
            }
        }
        let mut out = String::from("# sha256 of every fixture of a recorded feature level (tests/all/formats.rs).\n# A released level's entries never change: a format change is a new level.\n");
        for (p, h) in &m {
            out.push_str(&format!("{h}  {p}\n"));
        }
        std::fs::write(root().join("MANIFEST"), out).unwrap();
    }
    for level in 1..=version::RELEASED {
        let prefix = format!("L{level}/");
        let recorded: BTreeMap<String, String> =
            m.iter().filter(|(k, _)| k.starts_with(&prefix)).map(|(k, v)| (k.clone(), v.clone())).collect();
        assert!(!recorded.is_empty(), "released level {level} has no manifest entries");
        assert_eq!(
            hashes(level),
            recorded,
            "level {level} is released: its fixtures are frozen (testdata/formats/MANIFEST)"
        );
    }
}
