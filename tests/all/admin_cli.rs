//! `vlpds admin ...` (src/cli/admin.rs): the pdsadmin and PDS-script
//! equivalents, driven through the CLI's library entry (`cli::admin::run`,
//! argv parsed by clap as the binary does) against in-process nodes, and
//! once through the built binary. Also the admin endpoints they added
//! (src/xrpc/admin_tools.rs): publishIdentity, checkRepo, rebuildRepo,
//! requestCrawl.

use crate::common::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

#[track_caller]
fn ok((r, out): (anyhow::Result<()>, String)) -> String {
    if let Err(e) = r {
        panic!("command failed: {e:#}\n{out}");
    }
    out
}

async fn admin_json(url: &str, args: &[&str]) -> J {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    let out = ok(admin_cli(url, &a).await);
    serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_commands_match_pdsadmin() {
    let s = TestServer::spawn_with(|c| c.invite_required = true).await;
    let u = s.url.as_str();

    // create: an invite is minted (the PDS requires one), the password generated
    let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("cli"));
    let email = format!("{}@example.com", unique_name("cli"));
    let out = ok(admin_cli(u, &["account", "create", &email, &handle]).await);
    assert!(out.contains("Account created successfully!"), "{out}");
    let did = out.lines().find_map(|l| l.strip_prefix("DID      : ")).unwrap().to_string();
    let password = out.lines().find_map(|l| l.strip_prefix("Password : ")).unwrap().to_string();
    assert_eq!(password.len(), 24);
    s.create_session(&handle, &password).await.ok();
    let info = s.account_info(&did).await.ok();
    assert!(info["invitedBy"]["code"].is_string(), "used a fresh invite: {info}");
    // --json, a given password
    let h2 = format!("{}.{HANDLE_DOMAIN}", unique_name("cli"));
    let j = admin_json(
        u,
        &["account", "create", &format!("{}@example.com", unique_name("cli")), &h2, "--password", "a-given-password-1"],
    )
    .await;
    let did2 = j["did"].as_str().unwrap().to_string();
    assert_eq!(j["handle"], json!(h2));
    s.create_session(&h2, "a-given-password-1").await.ok();
    // a bad handle is the server's error
    let (r, _) = admin_cli(u, &["account", "create", "x@example.com", "no spaces allowed"]).await;
    assert!(format!("{:#}", r.unwrap_err()).contains("createAccount"));

    // list: table and JSON
    let out = ok(admin_cli(u, &["account", "list"]).await);
    let header = out.lines().next().unwrap();
    assert!(header.starts_with("Handle") && header.contains("Email") && header.contains("DID"), "{out}");
    assert!(out.lines().any(|l| l.starts_with(&handle) && l.contains(&did) && l.contains(&email)), "{out}");
    let j = admin_json(u, &["account", "list"]).await;
    let dids: HashSet<&str> = j.as_array().unwrap().iter().map(|a| a["did"].as_str().unwrap()).collect();
    assert!(dids.contains(did.as_str()) && dids.contains(did2.as_str()), "{j}");
    let j = admin_json(u, &["account", "list", "--email", &email]).await;
    assert_eq!(j.as_array().unwrap().len(), 1, "{j}");
    let out = ok(admin_cli(u, &["account", "info", &did]).await);
    assert!(out.contains(&handle) && out.contains("takedown:"), "{out}");

    // takedown / untakedown
    let out = ok(admin_cli(u, &["account", "takedown", &did, "--ref", "ticket-42"]).await);
    assert_eq!(out.trim(), format!("{did} taken down (ref ticket-42)"));
    let st = s.xrpc.get("com.atproto.admin.getSubjectStatus", &[("did", &did)], &Auth::Admin).await.ok();
    assert_eq!(st["takedown"], json!({"applied": true, "ref": "ticket-42"}), "{st}");
    s.create_session(&handle, &password).await.err(401, "AccountTakedown");
    let j = admin_json(u, &["account", "info", &did]).await;
    assert_eq!(j["status"]["takedown"]["applied"], json!(true), "{j}");
    ok(admin_cli(u, &["account", "untakedown", &did]).await);
    s.create_session(&handle, &password).await.ok();

    // reset-password: the new one works, the old one doesn't
    let out = ok(admin_cli(u, &["account", "reset-password", &did]).await);
    let new_pw = out.lines().find_map(|l| l.strip_prefix("New password: ")).unwrap().to_string();
    assert_eq!(new_pw.len(), 24);
    assert_ne!(new_pw, password);
    s.create_session(&handle, &password).await.client_err();
    s.create_session(&handle, &new_pw).await.ok();

    // invite codes
    let j = admin_json(u, &["create-invite-code", "--count", "2", "--uses", "3"]).await;
    let codes: Vec<&str> = j["codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    assert_eq!(codes.len(), 2);
    let listed = s.xrpc.get("com.atproto.admin.getInviteCodes", &[("limit", "500")], &Auth::Admin).await.ok();
    for code in &codes {
        let c = listed["codes"].as_array().unwrap().iter().find(|c| c["code"] == json!(code)).expect("listed");
        assert_eq!(c["available"], json!(3), "{c}");
    }
    let out = ok(admin_cli(u, &["create-invite-code"]).await);
    assert_eq!(out.lines().count(), 1, "{out}");

    // delete: refused without --yes off a terminal, then permanent
    let (r, _) = admin_cli(u, &["account", "delete", &did2]).await;
    assert!(r.unwrap_err().to_string().contains("--yes"));
    s.account_info(&did2).await.ok();
    let out = ok(admin_cli(u, &["account", "delete", &did2, "--yes"]).await);
    assert_eq!(out.trim(), format!("{did2} deleted"));
    s.account_info(&did2).await.client_err();

    // DIDs are checked before anything is sent
    let (r, _) = admin_cli(u, &["account", "takedown", "alice.test"]).await;
    assert!(r.unwrap_err().to_string().contains("did:"));
    // a wrong token is an error, not output
    assert!(admin_cli_as(u, "wrong", &["account", "list"]).await.0.is_err());
}

/// A relay stand-in: answers requestCrawl with `status`, recording bodies.
async fn relay(status: u16) -> (String, Arc<parking_lot::Mutex<Vec<J>>>) {
    use axum::routing::post;
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let app = axum::Router::new().route(
        "/xrpc/com.atproto.sync.requestCrawl",
        post(move |axum::Json(b): axum::Json<J>| {
            let seen = s2.clone();
            async move {
                seen.lock().push(b);
                (axum::http::StatusCode::from_u16(status).unwrap(), axum::Json(json!({})))
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_crawl_reports_each_relay() {
    let (good, seen) = relay(200).await;
    let (bad, bad_seen) = relay(500).await;
    let s = TestServer::spawn().await;
    let host = s.url.strip_prefix("http://").unwrap().to_string();

    let out = ok(admin_cli(&s.url, &["request-crawl", &good]).await);
    assert!(out.contains(&format!("Requesting crawl of {host} from {good}: ok")), "{out}");
    assert_eq!(seen.lock().last().unwrap(), &json!({"hostname": host}));

    // comma-separated; one failing relay fails the command, the other is still asked
    let n = seen.lock().len();
    let (r, out) = admin_cli(&s.url, &["request-crawl", &format!("{good},{bad}")]).await;
    assert!(r.unwrap_err().to_string().contains("1 of 2 relays failed"), "{out}");
    assert!(out.contains(": ok") && out.contains("FAILED 500"), "{out}");
    assert_eq!(seen.lock().len(), n + 1);
    assert_eq!(bad_seen.lock().len(), 1);

    // nothing given, nothing configured
    let (r, _) = admin_cli(&s.url, &["request-crawl"]).await;
    assert!(r.unwrap_err().to_string().contains("none configured"));
    // default: the node's --crawlers
    let g = good.clone();
    let s2 = TestServer::spawn_with(move |c| c.crawlers = vec![g]).await;
    let j = admin_json(&s2.url, &["request-crawl"]).await;
    assert_eq!(j["results"][0]["relay"], json!(good), "{j}");
    assert_eq!(j["results"][0]["ok"], json!(true), "{j}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_identity_and_key_rotation() {
    use vlpds::plc::mock::MockPlc;
    let plc = MockPlc::start().await;
    let rot = Arc::new(vlsync_atproto::crypto::Keypair::generate());
    let s = TestServer::spawn_plc(&plc.url, rot.clone()).await;
    let a = s.create_account("pid").await;
    let b = s.create_account("pid").await;
    let local_key = |did: String| {
        let s = &s;
        async move { format!("did:key:{}", s.app.account(&did).await.ok().unwrap().signing_pubkey) }
    };

    // publish-identity: one #identity per DID (args and a file), in order
    let mut sub = s.subscribe_from_now().await;
    let file = std::env::temp_dir().join(format!("vlpds-cli-dids-{}", unique_name("f")));
    std::fs::write(&file, format!("# accounts\n{}\n", b.did)).unwrap();
    let out = ok(admin_cli(&s.url, &["publish-identity", &a.did, "--file", file.to_str().unwrap()]).await);
    let _ = std::fs::remove_file(&file);
    assert!(out.contains(&format!("published identity evt for {} ({})", a.did, a.handle)), "{out}");
    let frames =
        sub.until(Duration::from_secs(10), |f| f.iter().filter(|f| f.kind() == "#identity").count() >= 2).await;
    let ids: Vec<(&str, Option<&str>)> =
        frames.iter().filter(|f| f.kind() == "#identity").map(|f| (f.did().unwrap(), f.str("handle"))).collect();
    assert_eq!(ids, vec![(a.did.as_str(), Some(a.handle.as_str())), (b.did.as_str(), Some(b.handle.as_str()))]);
    // an unknown DID fails the batch, the others still go out
    let (r, out) = admin_cli(&s.url, &["publish-identity", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", &a.did]).await;
    assert!(r.unwrap_err().to_string().contains("1 of 2 DIDs failed"), "{out}");
    assert!(out.contains("FAILED") && out.contains(&format!("published identity evt for {}", a.did)), "{out}");

    // rotate-keys: the PLC document's atproto key back to the one held here
    let other = vlsync_atproto::crypto::Keypair::generate().did_key();
    let direct = vlpds::plc::Plc::new(&plc.url, rot.clone(), None);
    assert!(direct.update_signing_key(&a.did, &other).await.unwrap(), "diverged");
    let out = ok(admin_cli(&s.url, &["rotate-keys", &a.did]).await);
    assert!(out.contains("PLC signing key updated"), "{out}");
    assert_eq!(plc.last_op(&a.did).unwrap()["verificationMethods"]["atproto"], json!(local_key(a.did.clone()).await));
    let out = ok(admin_cli(&s.url, &["rotate-keys", &a.did]).await);
    assert!(out.contains("already current"), "{out}");
    // --generate: a fresh signing key, in PLC too
    let before = local_key(b.did.clone()).await;
    let j = admin_json(&s.url, &["rotate-keys", "--generate", &b.did]).await;
    let new_key = j[0]["result"]["signingKey"].as_str().unwrap().to_string();
    assert_ne!(new_key, before);
    assert_eq!(local_key(b.did.clone()).await, new_key);
    assert_eq!(plc.last_op(&b.did).unwrap()["verificationMethods"]["atproto"], json!(new_key));
    s.post(&b, "signed with the new key").await;

    // per-node maintenance: one node, dry runs
    let j = admin_json(&s.url, &["rotate-plc-keys", "--dry-run"]).await;
    assert_eq!(j.as_array().unwrap().len(), 1, "{j}");
    let r = &j[0]["result"];
    assert_eq!(
        (r["accounts"].as_u64(), r["current"].as_u64(), r["rotated"].as_u64()),
        (Some(2), Some(2), Some(0)),
        "{j}"
    );
    let (r, out) = admin_cli(&s.url, &["ensure-recovery-key", "--dry-run", "--per-second", "20"]).await;
    assert!(r.is_err() && out.contains("no operator recovery key configured"), "{out}");
    let out = ok(admin_cli(&s.url, &["rewrap-secrets", "--dry-run"]).await);
    assert!(out.starts_with("node") && out.contains("(dry run: nothing changed)"), "{out}");
    let j = admin_json(&s.url, &["rewrap-secrets", "--dry-run", "--node-only"]).await;
    assert_eq!((j[0]["result"]["accounts"].as_u64(), j[0]["result"]["stale"].as_u64()), (Some(2), Some(0)), "{j}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_plc_keys_needs_plc() {
    let s = TestServer::spawn().await;
    let (r, out) = admin_cli(&s.url, &["rotate-plc-keys", "--dry-run"]).await;
    assert!(r.is_err() && out.contains("PLC registration is off"), "{out}");
    let (r, out) = admin_cli(&s.url, &["ensure-recovery-key", "--dry-run"]).await;
    assert!(r.is_err() && out.contains("PLC registration is off"), "{out}");
    // publish-identity of a non-PLC setup still works; rotate-keys refuses
    // to sync PLC without it
    let a = s.create_account("np").await;
    ok(admin_cli(&s.url, &["publish-identity", &a.did]).await);
    let (r, out) = admin_cli(&s.url, &["rotate-keys", &a.did]).await;
    assert!(r.is_err() && out.contains("PLC registration is off"), "{out}");
}

async fn many_records(s: &TestServer, a: &TestAccount, n: usize) {
    for chunk in 0..n.div_ceil(50) {
        let writes: Vec<J> = (0..50.min(n - chunk * 50))
            .map(
                |i| json!({"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": post_record(&format!("p{chunk}-{i}"))}),
            )
            .collect();
        s.apply_writes(a, json!(writes)).await.ok();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_and_rebuild_repo() {
    let s = TestServer::spawn().await;
    let a = s.create_account("rb").await;
    many_records(&s, &a, 120).await;
    let u = s.url.as_str();

    // a healthy repo
    let out = ok(admin_cli(u, &["check-repo", &a.did]).await);
    assert!(out.contains("(ok)") && out.contains("Records      : 120 (0 bad)"), "{out}");
    let j = admin_json(u, &["check-repo", &a.did]).await;
    assert_eq!(j["ok"], json!(true), "{j}");
    assert_eq!(j["commit"], json!({"cidOk": true, "dataOk": true, "didOk": true, "signatureOk": true}));
    let expected = j["nodes"]["expected"].as_u64().unwrap();
    assert!(expected >= 2, "interior nodes: {j}");
    assert_eq!(j["nodes"]["stored"].as_u64(), Some(expected));

    // break M/: one node gone, one stray; c/ loses an entry
    let Ok(p) = s.app.partition(&a.did) else { panic!("not owned") };
    let prefix = vlpds::state::mst_node_prefix(&a.did, 0);
    let first = {
        let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
        it.next().await.unwrap().unwrap().key
    };
    p.db.delete(first).await.unwrap();
    let stray = Cid::dag_cbor(b"\xa0");
    p.db.put(vlpds::state::mst_node_key(&a.did, 0, &stray), b"\xa0".to_vec()).await.unwrap();
    let (r, out) = admin_cli(u, &["check-repo", &a.did]).await;
    assert!(r.unwrap_err().to_string().contains("2 problem(s)"), "{out}");
    assert!(
        out.contains("1 persisted MST node(s) missing") && out.contains("1 persisted MST node(s) not in the tree"),
        "{out}"
    );

    // rebuild: dry run changes nothing; then a new commit, #sync, clean state
    let (head0, rev0) = s.latest_commit(&a.did).await;
    let out = ok(admin_cli(u, &["rebuild-repo", &a.did, "--dry-run"]).await);
    assert!(out.contains("would write 120 records"), "{out}");
    assert_eq!(s.latest_commit(&a.did).await.0, head0);
    let (r, _) = admin_cli(u, &["rebuild-repo", &a.did]).await;
    assert!(r.unwrap_err().to_string().contains("--yes"), "asks first");
    let mut sub = s.subscribe_from_now().await;
    let out = ok(admin_cli(u, &["rebuild-repo", &a.did, "--yes"]).await);
    assert!(out.contains("Record count : 120") && out.contains("After        : ok"), "{out}");
    let (head1, rev1) = s.latest_commit(&a.did).await;
    assert_ne!(head1, head0);
    assert!(rev1 > rev0);
    let frames = sub.until(Duration::from_secs(10), |f| f.iter().any(|f| f.kind() == "#sync")).await;
    let sync = frames.iter().find(|f| f.kind() == "#sync").unwrap();
    assert_eq!((sync.did(), sync.str("rev")), (Some(a.did.as_str()), Some(rev1.as_str())));
    let j = admin_json(u, &["check-repo", &a.did]).await;
    assert_eq!(j["ok"], json!(true), "{j}");
    assert_eq!(j["records"]["count"], json!(120));
    // the same tree, re-signed
    assert_eq!(j["mst"]["rebuiltRoot"], json!(j["head"]["data"]));
    assert_eq!(
        s.list_records(&a.did, "app.bsky.feed.post", &[("limit", "100")]).await.ok()["records"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    s.post(&a, "still writable").await;
    let repo = s.get_repo(&a.did).await;
    assert!(repo.blocks.len() > 120);

    // the replace is guarded by the head the records were read at
    let stale = Some(Cid::from_bytes(&head0.to_bytes()).unwrap());
    let r = s
        .app
        .account_op(
            &a.did,
            vlpds::worker::AccountOp::ReplaceRepo {
                records: Vec::new(),
                swap_commit: stale,
                stale_keys: Vec::new(),
                tree: None,
            },
        )
        .await;
    assert_eq!(r.err().map(|e| e.error), Some("InvalidSwap".to_string()));
    assert_eq!(
        s.list_records(&a.did, "app.bsky.feed.post", &[("limit", "5")]).await.ok()["records"].as_array().unwrap().len(),
        5
    );

    // a lost record: the check says so, and rebuild refuses
    let rprefix = vlpds::state::record_prefix(&a.did, 0);
    let rec = {
        let mut it = p.db.scan(rprefix.clone()..vlsync_store::keys::prefix_end(&rprefix)).await.unwrap();
        it.next().await.unwrap().unwrap().key
    };
    p.db.delete(rec).await.unwrap();
    let j: J = serde_json::from_str(&admin_cli(u, &["--json", "check-repo", &a.did]).await.1).unwrap();
    assert_eq!(j["mst"]["matchesHead"], json!(false), "{j}");
    let (r, _) = admin_cli(u, &["rebuild-repo", &a.did, "--yes"]).await;
    assert!(r.unwrap_err().to_string().contains("RepoUnrecoverable"));

    // unknown repos
    let (r, _) = admin_cli(u, &["check-repo", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"]).await;
    assert!(r.unwrap_err().to_string().contains("RepoNotFound"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_node_commands_cover_the_cluster() {
    const SHARDS: u32 = 8;
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = cluster_node("cli-a", store.clone(), SHARDS, |_| {}).await;
    let b = cluster_node("cli-b", store.clone(), SHARDS, |_| {}).await;
    balanced(&[&a, &b]).await;

    let accts = [
        a.create_account("pn").await,
        a.create_account("pn").await,
        b.create_account("pn").await,
        b.create_account("pn").await,
    ];
    let on_b = accts.iter().find(|t| b.app.partition(&t.did).is_ok()).expect("an account on b");

    // every node, totals summed
    let j = admin_json(&a.url, &["rewrap-secrets", "--dry-run"]).await;
    let nodes: HashSet<&str> = j.as_array().unwrap().iter().map(|r| r["node"].as_str().unwrap()).collect();
    assert_eq!(nodes, HashSet::from(["cli-a", "cli-b"]), "{j}");
    let total: u64 = j.as_array().unwrap().iter().map(|r| r["result"]["accounts"].as_u64().unwrap()).sum();
    assert_eq!(total, 4, "{j}");
    let out = ok(admin_cli(&a.url, &["rewrap-secrets", "--dry-run"]).await);
    assert!(out.lines().any(|l| l.starts_with("total") && l.split_whitespace().nth(1) == Some("4")), "{out}");

    // cluster status lists both
    let out = ok(admin_cli(&b.url, &["cluster", "status"]).await);
    assert!(out.contains("cli-a") && out.contains("cli-b*") && out.contains("0 unowned"), "{out}");

    // DID-keyed calls through the other node reach the owner
    let mut sub = b.subscribe_from_now().await;
    ok(admin_cli(&a.url, &["publish-identity", &on_b.did]).await);
    sub.until(Duration::from_secs(10), |f| {
        f.iter().any(|f| f.kind() == "#identity" && f.did() == Some(on_b.did.as_str()))
    })
    .await;
    let j = admin_json(&a.url, &["check-repo", &on_b.did]).await;
    assert_eq!(j["ok"], json!(true), "{j}");
    let j = admin_json(&a.url, &["account", "list"]).await;
    assert_eq!(j.as_array().unwrap().len(), 4, "{j}");
}

/// The `vlpds` binary's own argv handling (`vlpds admin ...` -> cli::admin).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_binary_runs_admin_commands() {
    let s = TestServer::spawn().await;
    let a = s.create_account("bin").await;
    let bin = env!("CARGO_BIN_EXE_vlpds");
    let run_bin = |args: Vec<String>| async move {
        tokio::process::Command::new(bin)
            .args(args)
            .env("VLPDS_ADMIN_TOKEN", vlpds::server::DEV_ADMIN_TOKEN)
            .output()
            .await
            .unwrap()
    };
    let o =
        run_bin(vec!["admin".into(), "--url".into(), s.url.clone(), "account".into(), "list".into(), "--json".into()])
            .await;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let j: J = serde_json::from_slice(&o.stdout).unwrap();
    assert!(j.as_array().unwrap().iter().any(|x| x["did"] == json!(a.did)), "{j}");
    let o = run_bin(vec!["admin".into(), "--url".into(), s.url.clone(), "check-repo".into(), a.did.clone()]).await;
    assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains("(ok)"));
    let o = run_bin(vec![
        "admin".into(),
        "--url".into(),
        s.url.clone(),
        "account".into(),
        "takedown".into(),
        "nope".into(),
    ])
    .await;
    assert!(!o.status.success());
}

fn secret_file(name: &str, contents: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("vlpds-cli-{name}-{}-{}", std::process::id(), rand::random::<u64>()));
    std::fs::write(&p, contents).unwrap();
    p
}

const SECRET_ENV: &[&str] = &[
    "VLPDS_JWT_SECRET",
    "VLPDS_JWT_SECRET_FILE",
    "VLPDS_ADMIN_TOKEN",
    "VLPDS_ADMIN_TOKEN_FILE",
    "VLPDS_INTERNAL_TOKEN",
    "VLPDS_INTERNAL_TOKEN_FILE",
    "VLPDS_S3_ACCESS_KEY",
    "VLPDS_S3_ACCESS_KEY_FILE",
    "VLPDS_S3_SECRET_KEY",
    "VLPDS_S3_SECRET_KEY_FILE",
    "VLPDS_DEV_MODE",
];

/// `vlpds admin` reads the token from VLPDS_ADMIN_TOKEN_FILE (as the node's
/// container provides it); VLPDS_ADMIN_TOKEN wins over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_binary_reads_the_admin_token_file() {
    let s = TestServer::spawn().await;
    let bin = env!("CARGO_BIN_EXE_vlpds");
    let good = secret_file("admin-good", &format!("{}\n", vlpds::server::DEV_ADMIN_TOKEN));
    let bad = secret_file("admin-bad", "not-the-admin-token\n");
    let run_bin = |env: Vec<(&'static str, String)>| {
        let url = s.url.clone();
        async move {
            let mut c = tokio::process::Command::new(bin);
            c.args(["admin", "--url", &url, "account", "list", "--json"]);
            for k in SECRET_ENV {
                c.env_remove(k);
            }
            c.envs(env).output().await.unwrap()
        }
    };
    let file = |p: &std::path::Path| ("VLPDS_ADMIN_TOKEN_FILE", p.display().to_string());
    let o = run_bin(vec![file(&good)]).await;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = run_bin(vec![file(&bad)]).await;
    assert!(!o.status.success(), "a wrong token from the file is used");
    let o = run_bin(vec![file(&bad), ("VLPDS_ADMIN_TOKEN", vlpds::server::DEV_ADMIN_TOKEN.into())]).await;
    assert!(o.status.success(), "VLPDS_ADMIN_TOKEN wins: {}", String::from_utf8_lossy(&o.stderr));
    let missing = std::env::temp_dir().join("vlpds-cli-admin-missing");
    let o = run_bin(vec![file(&missing)]).await;
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("--admin-token-file"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    for p in [good, bad] {
        std::fs::remove_file(p).unwrap();
    }
}

/// The node's `--<secret>-file` options: read at startup (one trailing
/// newline dropped), refused when empty or together with the plain form
/// (flag or env), and never echoed.
#[tokio::test]
async fn the_node_reads_secret_files() {
    let bin = env!("CARGO_BIN_EXE_vlpds");
    let run = |args: Vec<String>, env: Vec<(&'static str, String)>| async move {
        let mut c = tokio::process::Command::new(bin);
        c.arg("--memory").args(args);
        for k in SECRET_ENV {
            c.env_remove(k);
        }
        let o = c.envs(env).output().await.unwrap();
        (o.status.code(), String::from_utf8_lossy(&o.stderr).into_owned())
    };
    let long = "a-jwt-secret-of-well-over-32-bytes-0123456789";
    let jwt = secret_file("jwt", &format!("{long}\n"));
    let short = secret_file("short", "shhh-short\n");
    let empty = secret_file("empty", "\n");
    let path = |p: &std::path::Path| p.display().to_string();

    // A short secret from the file is refused for its length, not as unset.
    let (code, err) = run(vec!["--jwt-secret-file".into(), path(&short)], vec![]).await;
    assert_ne!(code, Some(0));
    assert!(err.contains("VLPDS_JWT_SECRET must be at least"), "{err}");
    assert!(!err.contains("shhh-short"), "secret echoed: {err}");
    let (_, err) =
        run(vec!["--jwt-secret-file".into(), path(&jwt), "--admin-token-file".into(), path(&short)], vec![]).await;
    assert!(err.contains("VLPDS_ADMIN_TOKEN must be at least"), "{err}");
    let env = vec![
        ("VLPDS_JWT_SECRET_FILE", path(&jwt)),
        ("VLPDS_ADMIN_TOKEN_FILE", path(&jwt)),
        ("VLPDS_INTERNAL_TOKEN_FILE", path(&short)),
    ];
    let (_, err) = run(vec![], env).await;
    assert!(err.contains("VLPDS_INTERNAL_TOKEN must be at least"), "{err}");

    let (code, err) = run(vec!["--rate-limit-bypass-key-file".into(), path(&empty)], vec![]).await;
    assert_ne!(code, Some(0));
    assert!(err.contains("--rate-limit-bypass-key-file") && err.contains("is empty"), "{err}");

    // Flag + file and env + file conflict; the S3 defaults don't count.
    for (args, env) in [
        (vec!["--jwt-secret".to_string(), long.into(), "--jwt-secret-file".into(), path(&jwt)], vec![]),
        (vec!["--internal-token-file".into(), path(&jwt)], vec![("VLPDS_INTERNAL_TOKEN", long.to_string())]),
        (vec![], vec![("VLPDS_S3_SECRET_KEY", long.to_string()), ("VLPDS_S3_SECRET_KEY_FILE", path(&jwt))]),
        (vec!["--email-smtp-url".into(), "smtp://x".into(), "--email-smtp-url-file".into(), path(&jwt)], vec![]),
        (vec!["--email-api-token-file".into(), path(&jwt)], vec![("VLPDS_EMAIL_API_TOKEN", long.to_string())]),
    ] {
        let (code, err) = run(args, env).await;
        assert_eq!(code, Some(2), "{err}");
        assert!(err.contains("cannot be used with"), "{err}");
        assert!(!err.contains(long), "secret echoed: {err}");
    }
    let (_, err) = run(vec!["--s3-access-key-file".into(), path(&short)], vec![]).await;
    assert!(!err.contains("cannot be used with"), "{err}");
    for p in [jwt, short, empty] {
        std::fs::remove_file(p).unwrap();
    }
}
