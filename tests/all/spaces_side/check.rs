//! check-space (`vlpds.admin.checkSpace`, `vlpds admin check-space`): a
//! healthy space repo checks clean, and damaged rows (a lost record, a lost
//! op, a head that disagrees) are each reported. With --spaces off the
//! method is answered as any unknown admin method is.

use crate::common::spaces::SpaceClient;
use crate::common::*;
use sha2::Digest;

fn ok((r, out): (anyhow::Result<()>, String)) -> String {
    if let Err(e) = r {
        panic!("command failed: {e:#}\n{out}");
    }
    out
}

/// `{fam}{did}\0{sid}{rest}` in the DID's slot.
fn space_key(fam: &[u8], did: &str, space: &str, rest: &[u8]) -> Vec<u8> {
    let mut k = vlsync_store::keys::slot_family(vlsync_store::slots::slot_of(did), fam);
    k.extend_from_slice(did.as_bytes());
    k.push(0);
    k.extend_from_slice(&sha2::Sha256::digest(space.as_bytes())[..16]);
    k.extend_from_slice(rest);
    k
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_space_takes_a_space_uri() {
    let (r, _) = admin_cli("http://127.0.0.1:9", &["check-space", "did:plc:abc", "com.example.x"]).await;
    assert!(r.unwrap_err().to_string().contains("space URI"));
    let (r, _) = admin_cli("http://127.0.0.1:9", &["check-space", "abc", "at://did:plc:abc/space/a.b.c/x"]).await;
    assert!(r.unwrap_err().to_string().contains("must start with \"did:\""));
}

/// Flag off: the same answer as a method that doesn't exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_space_is_unknown_with_spaces_off() {
    let s = TestServer::spawn().await;
    let q = [("did", "did:plc:abc"), ("space", "at://did:plc:abc/space/a.b.c/x")];
    let got = s.xrpc.get("vlpds.admin.checkSpace", &q, &Auth::Admin).await;
    let unknown = s.xrpc.get("vlpds.admin.checkSpaceZz", &q, &Auth::Admin).await;
    assert_eq!((got.status, &got.json), (unknown.status, &unknown.json), "{}", got.text());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_space_finds_damaged_rows() {
    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let (st, coll) = ("com.example.chk.space", "com.example.chk.note");
    let scope =
        format!("space:{st}?collection={coll}&action=read&action=create&action=update&action=delete&manage=create");
    let sc = SpaceClient::new(&s, &unique_name("chk"), &scope).await;
    let space = sc.create_space(st, "chk").await;
    let u = s.url.as_str();
    let did = sc.did.clone();

    // never written: no repo here
    let (r, _) = admin_cli(u, &["check-space", &did, "at://did:plc:nobody/space/a.b.c/x"]).await;
    assert!(r.is_err(), "a space with no rows");

    for i in 0..6 {
        let rec = json!({"$type": coll, "text": format!("n{i}")});
        sc.create_record(&space, coll, Some(&format!("r{i}")), rec).await.ok();
    }
    sc.put_record(&space, coll, "r1", json!({"$type": coll, "text": "again"})).await.ok();
    sc.delete_record(&space, coll, "r2").await.ok();

    let out = ok(admin_cli(u, &["check-space", &did, &space]).await);
    assert!(out.contains("(ok)") && out.contains("Records      : 5 (0 bad)"), "{out}");
    assert!(out.contains("8 op(s) in 8 rev(s)") && out.contains("(complete)"), "{out}");
    let a = ["--json", "check-space", did.as_str(), space.as_str()];
    let j: J = serde_json::from_str(&ok(admin_cli(u, &a).await)).unwrap();
    assert_eq!(j["ok"], json!(true), "{j}");
    assert_eq!(j["records"]["matchesHead"], json!(true));
    // the account governs the space: its own writes are sequenced there
    assert_eq!(j["host"]["writers"], json!(1), "{j}");
    assert!(j["outbox"].is_null(), "{j}");

    // a record row gone: the set hash, the count and the oplog all disagree
    let p = s.app.partition(&did).unwrap_or_else(|_| panic!("not owned"));
    let rkey = space_key(b"sR/", &did, &space, format!("{coll}/r3").as_bytes());
    let saved = p.db.get(rkey.clone()).await.unwrap().expect("sR row");
    p.db.delete(rkey.clone()).await.unwrap();
    let (r, out) = admin_cli(u, &["check-space", &did, &space]).await;
    assert!(r.unwrap_err().to_string().contains("problem(s)"), "{out}");
    for want in ["records hash to", "the head counts 5 record(s), sR holds 4", "oplog replays to something sR"] {
        assert!(out.contains(want), "{want:?} not in {out}");
    }
    p.db.put(rkey, saved).await.unwrap();
    ok(admin_cli(u, &["check-space", &did, &space]).await);

    // the newest op gone
    let oprefix = space_key(b"sO/", &did, &space, b"");
    let last = {
        let mut it = p.db.scan(oprefix.clone()..vlsync_store::keys::prefix_end(&oprefix)).await.unwrap();
        let mut last = None;
        while let Some(kv) = it.next().await.unwrap() {
            last = Some(kv.key);
        }
        last.expect("sO rows")
    };
    p.db.delete(last).await.unwrap();
    let (r, out) = admin_cli(u, &a).await;
    assert!(r.is_err(), "{out}");
    let j: J = serde_json::from_str(&out).unwrap();
    let problems = j["problems"].to_string();
    assert!(problems.contains("the newest op is at rev"), "{j}");
    assert!(problems.contains("oplog replays to something sR doesn't hold"), "{j}");
}
