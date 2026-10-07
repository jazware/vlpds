//! The operator console's API (src/xrpc/console.rs): admin only, account
//! rows with repo stats and search, an account's security, sessions and
//! recent events, per-node metrics, segments, mail and lockouts, the
//! effective config, and kicking a subscriber, on one node and across two.

use crate::common::*;
use std::sync::Arc;
use std::time::Duration;

const READS: [&str; 9] = [
    "vlpds.admin.listAccounts",
    "vlpds.admin.getAccountSecurity",
    "vlpds.admin.listSessions",
    "vlpds.admin.listRepoOps",
    "vlpds.admin.getNodeMetrics",
    "vlpds.admin.listSegments",
    "vlpds.admin.listMail",
    "vlpds.admin.listLockouts",
    "vlpds.admin.getConfig",
];

async fn admin_get(s: &TestServer, nsid: &str, q: &[(&str, &str)]) -> J {
    s.xrpc.get(nsid, q, &Auth::Admin).await.ok()
}

fn dids(r: &J) -> Vec<String> {
    r["accounts"].as_array().unwrap().iter().map(|a| a["did"].as_str().unwrap().to_string()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_only() {
    let s = TestServer::spawn().await;
    let a = s.create_account("cauth").await;
    for nsid in READS {
        s.xrpc.get(nsid, &[("did", &a.did)], &Auth::None).await.err(401, "AuthenticationRequired");
        s.xrpc.get(nsid, &[("did", &a.did)], &a.auth()).await.err(401, "AuthenticationRequired");
    }
    for nsid in ["vlpds.admin.revokeSessions", "vlpds.admin.kickSubscriber", "vlpds.admin.clearLockout"] {
        let body = json!({"did": a.did, "conn": "1", "reason": "x"});
        s.xrpc.post(nsid, &body, &a.auth()).await.err(401, "AuthenticationRequired");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accounts_with_repo_stats_search_and_paging() {
    let s = TestServer::spawn().await;
    let older = s.create_account("cacct").await;
    let newer = s.create_account("cacct").await;
    for i in 0..3 {
        s.post(&older, &format!("old {i}")).await;
    }
    s.post(&newer, "new").await;

    // most recently committed first
    let r = admin_get(&s, "vlpds.admin.listAccounts", &[("limit", "200")]).await;
    assert_eq!(r["sort"], "recent", "{r}");
    let order = dids(&r);
    let (i_new, i_old) = (
        order.iter().position(|d| *d == newer.did).expect("newer listed"),
        order.iter().position(|d| *d == older.did).expect("older listed"),
    );
    assert!(i_new < i_old, "{order:?}");
    let row = r["accounts"].as_array().unwrap().iter().find(|a| a["did"] == older.did.as_str()).unwrap().clone();
    assert_eq!(row["handle"], older.handle.as_str());
    assert_eq!(row["records"], 3, "{row}");
    assert_eq!(row["status"], "active");
    assert!(row["lastCommitAt"].as_u64().unwrap() > 1_700_000_000_000, "{row}");
    assert_eq!(row["secondFactors"]["totp"], false);
    assert_eq!(row["node"], "single");

    // recent paging: limit 1 walks newest to oldest without repeats
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..50 {
        let mut q = vec![("limit", "1".to_string()), ("sort", "recent".to_string())];
        if let Some(c) = &cursor {
            q.push(("cursor", c.clone()));
        }
        let r = s.xrpc.get_multi("vlpds.admin.listAccounts", &q, &Auth::Admin).await.ok();
        seen.extend(dids(&r));
        match r["cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    let (p_new, p_old) =
        (seen.iter().position(|d| *d == newer.did).unwrap(), seen.iter().position(|d| *d == older.did).unwrap());
    assert!(p_new < p_old, "{seen:?}");
    let mut dedup = seen.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), seen.len(), "no account twice: {seen:?}");

    // handle prefix, email prefix and a whole DID
    let prefix = &older.handle[..older.handle.find('.').unwrap()];
    let r = admin_get(&s, "vlpds.admin.listAccounts", &[("q", &format!("@{prefix}"))]).await;
    assert_eq!(dids(&r), vec![older.did.clone()], "{r}");
    assert_eq!(r["sort"], "slot");
    let r = admin_get(&s, "vlpds.admin.listAccounts", &[("q", &newer.email[..8])]).await;
    assert!(dids(&r).contains(&newer.did), "{r}");
    let r = admin_get(&s, "vlpds.admin.listAccounts", &[("q", &older.did)]).await;
    assert_eq!((dids(&r), &r["exact"]), (vec![older.did.clone()], &json!(true)), "{r}");

    // slot paging finds every account once
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..500 {
        let mut q = vec![("limit", "2".to_string()), ("sort", "slot".to_string())];
        if let Some(c) = &cursor {
            q.push(("cursor", c.clone()));
        }
        let r = s.xrpc.get_multi("vlpds.admin.listAccounts", &q, &Auth::Admin).await.ok();
        all.extend(dids(&r));
        match r["cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert!(all.contains(&older.did) && all.contains(&newer.did));
    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), n);

    // filters
    s.xrpc
        .post("com.atproto.admin.updateSubjectStatus", &json!({"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": older.did}, "takedown": {"applied": true}}), &Auth::Admin)
        .await
        .ok();
    let r =
        admin_get(&s, "vlpds.admin.listAccounts", &[("filter", "takendown"), ("sort", "slot"), ("limit", "200")]).await;
    assert!(dids(&r).contains(&older.did) && !dids(&r).contains(&newer.did), "{r}");
    let r =
        admin_get(&s, "vlpds.admin.listAccounts", &[("filter", "no2fa"), ("q", &newer.did[..12]), ("limit", "200")])
            .await;
    assert!(dids(&r).contains(&newer.did), "{r}");
    s.xrpc.get("vlpds.admin.listAccounts", &[("filter", "nope")], &Auth::Admin).await.err(400, "InvalidRequest");
    s.xrpc.get("vlpds.admin.listAccounts", &[("cursor", "x")], &Auth::Admin).await.err(400, "InvalidRequest");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn security_sessions_and_revocation() {
    let s = TestServer::spawn().await;
    let a = s.create_account("csec").await;
    s.xrpc.post("com.atproto.server.createAppPassword", &json!({"name": "feeds"}), &a.auth()).await.ok();
    let ap = s.xrpc.post("com.atproto.server.createAppPassword", &json!({"name": "bot"}), &a.auth()).await.ok();
    let ap_session = s.login(&a.handle, ap["password"].as_str().unwrap(), None).await.ok();
    s.login(&a.handle, "not the password", None).await.err(401, "AuthenticationRequired");

    let sec = admin_get(&s, "vlpds.admin.getAccountSecurity", &[("did", &a.did)]).await;
    assert_eq!(sec["passwordSet"], true);
    let signins = sec["recentSignIns"].as_array().unwrap();
    let bad = signins.iter().find(|e| e["failed"].is_string()).unwrap_or_else(|| panic!("a refusal listed: {sec}"));
    assert_eq!(
        (bad["failed"].as_str(), bad["method"].as_str(), bad["count"].as_u64()),
        (Some("wrong_password"), Some("password"), Some(1))
    );
    assert!(signins.iter().any(|e| e["method"] == "app_password" && e["failed"].is_null()), "{sec}");
    assert_eq!(sec["totp"]["enabled"], false);
    assert_eq!(sec["recoveryCodes"]["remaining"], 0);
    let mut names: Vec<&str> =
        sec["appPasswords"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["bot", "feeds"]);
    assert!(!sec.to_string().contains("hash"), "no app password hash: {sec}");

    // the account's own session and the app password's
    let list = admin_get(&s, "vlpds.admin.listSessions", &[("did", &a.did)]).await;
    let sessions = list["sessions"].as_array().unwrap().clone();
    assert_eq!(sessions.len(), 2, "{list}");
    let ap_row = sessions.iter().find(|x| x["kind"] == "appPassword").expect("app password session");
    assert_eq!(ap_row["appPassword"], "bot");
    assert!(sessions.iter().any(|x| x["kind"] == "legacy"));
    assert!(!list.to_string().contains(&a.refresh), "no tokens");

    // one session: only that one stops working
    let id = ap_row["id"].as_str().unwrap();
    s.xrpc
        .post("vlpds.admin.revokeSessions", &json!({"did": a.did, "ids": [id], "reason": "test"}), &Auth::Admin)
        .await
        .ok();
    let ap_auth = Auth::Bearer(ap_session["accessJwt"].as_str().unwrap().to_string());
    s.get_session(&ap_auth).await.client_err();
    s.get_session(&a.auth()).await.ok();
    s.xrpc
        .post("vlpds.admin.revokeSessions", &json!({"did": a.did, "ids": ["nope"]}), &Auth::Admin)
        .await
        .err(400, "InvalidRequest");

    // everything
    let r = s.xrpc.post("vlpds.admin.revokeSessions", &json!({"did": a.did}), &Auth::Admin).await.ok();
    assert_eq!(r["revoked"]["all"], true);
    assert!(r["auditId"].as_str().is_some());
    s.get_session(&a.auth()).await.client_err();
    let list = admin_get(&s, "vlpds.admin.listSessions", &[("did", &a.did)]).await;
    assert_eq!(list["sessions"].as_array().unwrap().len(), 0, "{list}");

    // an app password, by name
    s.xrpc.post("vlpds.admin.revokeAppPassword", &json!({"did": a.did, "name": "feeds"}), &Auth::Admin).await.ok();
    s.xrpc
        .post("vlpds.admin.revokeAppPassword", &json!({"did": a.did, "name": "feeds"}), &Auth::Admin)
        .await
        .err(400, "NotFound");
    let sec = admin_get(&s, "vlpds.admin.getAccountSecurity", &[("did", &a.did)]).await;
    assert_eq!(sec["appPasswords"].as_array().unwrap().len(), 1, "{sec}");
    s.xrpc
        .get("vlpds.admin.getAccountSecurity", &[("did", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")], &Auth::Admin)
        .await
        .err(400, "NotFound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lockouts_are_listed_and_cleared() {
    let s = TestServer::spawn().await;
    let a = s.create_account("clock").await;
    let (secret, step) = s.enable_totp(&a).await;
    let wrong = vlpds::totp::code_for_step(&secret, step + 1000);
    for _ in 1..vlpds::totp::MAX_FAILURES {
        s.login(&a.handle, &a.password, Some(&wrong)).await.client_err();
    }
    s.login(&a.handle, &a.password, Some(&wrong)).await.err(429, "RateLimitExceeded");

    let r = admin_get(&s, "vlpds.admin.listLockouts", &[]).await;
    let l = r["lockouts"].as_array().unwrap().iter().find(|l| l["did"] == a.did.as_str()).expect("listed").clone();
    assert_eq!((l["factor"].as_str(), l["handle"].as_str()), (Some("second_factor"), Some(a.handle.as_str())));
    assert!(l["lockedUntil"].as_u64().unwrap() > 1_700_000_000_000);
    let sec = admin_get(&s, "vlpds.admin.getAccountSecurity", &[("did", &a.did)]).await;
    assert_eq!(sec["lockouts"][0]["failures"], vlpds::totp::MAX_FAILURES, "{sec}");
    assert_eq!(sec["totp"]["enabled"], true);
    // the refusals, newest first, next to the successes
    let failed: Vec<&str> =
        sec["recentSignIns"].as_array().unwrap().iter().filter_map(|e| e["failed"].as_str()).collect();
    assert_eq!(failed.first(), Some(&"factor_locked"), "{sec}");
    assert!(failed.contains(&"wrong_code"), "{sec}");
    let row = admin_get(&s, "vlpds.admin.listAccounts", &[("q", &a.did)]).await;
    assert_eq!(row["accounts"][0]["secondFactors"]["totp"], true);

    s.xrpc.post("vlpds.admin.clearLockout", &json!({"did": a.did}), &Auth::Admin).await.client_err();
    s.xrpc
        .post("vlpds.admin.clearLockout", &json!({"did": a.did, "reason": "verified by email"}), &Auth::Admin)
        .await
        .ok();
    let r = admin_get(&s, "vlpds.admin.listLockouts", &[]).await;
    assert!(!r["lockouts"].as_array().unwrap().iter().any(|l| l["did"] == a.did.as_str()), "{r}");
    let code = vlpds::totp::code_for_step(&secret, vlpds::totp::step_at(vlpds::totp::now_secs()) + 1);
    s.login(&a.handle, &a.password, Some(&code)).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repo_ops_metrics_segments_and_mail() {
    let s = TestServer::spawn().await;
    let a = s.create_account("cops").await;
    let p = s.post(&a, "first").await;
    s.delete_record(&a, p.collection(), p.rkey()).await.ok();

    // the account's events, newest first, from the ring
    let r = eventually(Duration::from_secs(10), || async {
        let r = admin_get(&s, "vlpds.admin.listRepoOps", &[("did", &a.did)]).await;
        let first = r["events"].as_array()?.iter().find(|e| e["kind"] == "commit")?.clone();
        (first["ops"][0]["action"] == "delete").then_some(r)
    })
    .await
    .expect("commits listed");
    let commits: Vec<&J> = r["events"].as_array().unwrap().iter().filter(|e| e["kind"] == "commit").collect();
    assert_eq!(commits[0]["ops"][0]["action"], "delete", "{r}");
    assert_eq!(commits[1]["ops"][0]["action"], "create");
    assert_eq!(commits[1]["ops"][0]["path"].as_str().unwrap(), format!("{}/{}", p.collection(), p.rkey()));
    assert!(
        commits[0]["seq"].as_str().unwrap().parse::<i64>().unwrap()
            > commits[1]["seq"].as_str().unwrap().parse::<i64>().unwrap()
    );
    let r = admin_get(&s, "vlpds.admin.listRepoOps", &[("did", &a.did), ("limit", "1")]).await;
    assert_eq!(r["events"].as_array().unwrap().len(), 1);

    // this node's rates, once two samples exist
    let r = admin_get(&s, "vlpds.admin.getNodeMetrics", &[]).await;
    let n = &r["nodes"][0];
    assert_eq!((n["node"].as_str(), n["self"].as_bool()), (Some("single"), Some(true)), "{r}");
    assert!(n["cpuLimitCores"].as_f64().unwrap() > 0.0);
    let r = eventually(Duration::from_secs(10), || async {
        let r = admin_get(&s, "vlpds.admin.getNodeMetrics", &[]).await;
        r["nodes"][0]["latest"].is_object().then_some(r)
    })
    .await
    .expect("a point");
    let latest = &r["nodes"][0]["latest"];
    assert!(latest["t"].as_u64().unwrap() > 0 && latest["rssBytes"].as_i64().unwrap() > 0, "{latest}");
    let last_t = r["nodes"][0]["series"].as_array().unwrap().last().unwrap()["t"].as_u64().unwrap();
    let r = admin_get(&s, "vlpds.admin.getNodeMetrics", &[("since", &last_t.to_string())]).await;
    assert!(r["nodes"][0]["series"].as_array().unwrap().iter().all(|p| p["t"].as_u64().unwrap() > last_t));

    // the segments those commits went out in
    let r = admin_get(&s, "vlpds.admin.listSegments", &[("since", "0")]).await;
    let n = &r["nodes"][0];
    let segs = n["segments"].as_array().unwrap();
    assert!(!segs.is_empty(), "{r}");
    let durable: Vec<&J> = segs.iter().filter(|g| g["durableAt"].is_u64()).collect();
    assert!(!durable.is_empty(), "{r}");
    for g in &durable {
        assert!(g["entries"].as_u64().unwrap() >= g["events"].as_u64().unwrap());
        assert!(g["putMs"].as_f64().is_some() && g["storedBytes"].as_u64().unwrap() > 0, "{g}");
        assert!(
            g["firstSeq"].as_str().unwrap().parse::<i64>().unwrap()
                <= g["lastSeq"].as_str().unwrap().parse::<i64>().unwrap()
        );
    }
    assert!(n["watermark"].as_str().is_some() && r["lastEmitted"].as_str().is_some());

    // mail shows the recipient's domain only
    s.xrpc.post_empty("com.atproto.server.requestEmailConfirmation", &a.auth()).await.ok();
    let r = admin_get(&s, "vlpds.admin.listMail", &[("limit", "200")]).await;
    let m = r["mail"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["purpose"] == "confirm_email" && m["toDomain"] == "example.com")
        .unwrap_or_else(|| panic!("mail listed: {r}"))
        .clone();
    assert_eq!(m["node"], "single");
    assert_eq!(m["did"], a.did.as_str(), "the account it was for: {m}");
    assert!(["logged", "queued", "sent"].contains(&m["status"].as_str().unwrap()), "{m}");
    assert!(!r.to_string().contains(&a.email), "no address: {r}");

    // filtered to one account
    let b = s.create_account("cops").await;
    s.xrpc.post_empty("com.atproto.server.requestEmailConfirmation", &b.auth()).await.ok();
    let r = admin_get(&s, "vlpds.admin.listMail", &[("did", &b.did)]).await;
    let mail = r["mail"].as_array().unwrap();
    assert!(!mail.is_empty() && mail.iter().all(|m| m["did"] == b.did.as_str()), "{r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_and_kick() {
    let s = TestServer::spawn().await;
    let r = admin_get(&s, "vlpds.admin.getConfig", &[]).await;
    assert_eq!(r["node"], "single");
    assert_eq!(r["recorded"], false, "an in-process node has no command line");
    assert!(r["stored"]["handleDomains"].as_array().is_some_and(|d| !d.is_empty()), "{r}");
    assert!(!r.to_string().contains(ADMIN_TOKEN));

    let _sub = s.subscribe(None).await;
    let conn = eventually(Duration::from_secs(10), || async {
        let r = admin_get(&s, "vlpds.admin.listFirehoseSubscribers", &[]).await;
        r["subscribers"][0]["conn"].as_str().map(String::from)
    })
    .await
    .expect("subscriber listed");
    s.xrpc.post("vlpds.admin.kickSubscriber", &json!({"conn": "999999999"}), &Auth::Admin).await.err(400, "NotFound");
    s.xrpc.post("vlpds.admin.kickSubscriber", &json!({"conn": "x"}), &Auth::Admin).await.err(400, "InvalidRequest");
    s.xrpc.post("vlpds.admin.kickSubscriber", &json!({"conn": conn}), &Auth::Admin).await.ok();
    let gone = eventually(Duration::from_secs(10), || async {
        let r = admin_get(&s, "vlpds.admin.listFirehoseSubscribers", &[]).await;
        r["recentDisconnects"].as_array()?.iter().find(|g| g["conn"] == conn.as_str()).cloned()
    })
    .await
    .expect("disconnected");
    assert_eq!(gone["reason"], "kicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gathers_every_node() {
    let store: Arc<object_store::memory::InMemory> = Arc::new(object_store::memory::InMemory::new());
    let a = cluster_node("cons-a", store.clone(), 4, |_| {}).await;
    let b = cluster_node("cons-b", store.clone(), 4, |_| {}).await;
    eventually(Duration::from_secs(20), || async {
        [&a, &b]
            .iter()
            .all(|s| {
                let c = s.app.cluster.as_ref().unwrap();
                c.peers().iter().any(|l| l.node_id != c.cfg.node_id)
            })
            .then_some(())
    })
    .await
    .expect("two-node cluster formed");
    let mut accts = Vec::new();
    for _ in 0..4 {
        let acct = a.create_account("cgat").await;
        a.post(&acct, "x").await;
        accts.push(acct);
    }
    for nsid in
        ["vlpds.admin.getNodeMetrics", "vlpds.admin.listSegments", "vlpds.admin.listMail", "vlpds.admin.listLockouts"]
    {
        let r = admin_get(&a, nsid, &[]).await;
        assert!(r.get("unreachableNodes").is_none(), "{nsid}: {r}");
        if let Some(nodes) = r["nodes"].as_array() {
            let mut ids: Vec<&str> = nodes.iter().map(|n| n["node"].as_str().unwrap()).collect();
            ids.sort();
            assert_eq!(ids, ["cons-a", "cons-b"], "{nsid}: {r}");
        }
    }
    // every account, whichever node owns it, from either node
    for from in [&a, &b] {
        let r = admin_get(from, "vlpds.admin.listAccounts", &[("limit", "200"), ("sort", "slot")]).await;
        for acct in &accts {
            assert!(dids(&r).contains(&acct.did), "{r}");
        }
        let r = admin_get(from, "vlpds.admin.listAccounts", &[("limit", "200")]).await;
        for acct in &accts {
            assert!(dids(&r).contains(&acct.did), "recent: {r}");
        }
        // an account's security answers wherever it's asked
        let sec = admin_get(from, "vlpds.admin.getAccountSecurity", &[("did", &accts[0].did)]).await;
        assert_eq!(sec["did"], accts[0].did.as_str());
    }
    // a node's own config through the other
    let r = a
        .xrpc
        .send(
            a.xrpc
                .http
                .get(format!("{}/xrpc/vlpds.admin.getConfig", a.url))
                .header("x-vlpds-node", "cons-b")
                .basic_auth("admin", Some(ADMIN_TOKEN)),
        )
        .await
        .ok();
    assert_eq!(r["node"], "cons-b");
}
