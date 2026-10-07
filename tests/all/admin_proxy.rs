//! Operator sign-in through a proxy (src/admin_proxy.rs): the identity
//! header counts on the admin listener only, from a trusted peer only, for
//! an allowlisted login only, never on a cross-site write, and it names the
//! operator in the audit log (also at an account's owner on another node).
//! The admin token works as before on both listeners.

use crate::common::*;
use std::sync::Arc;
use std::time::Duration;

const HEADER: &str = "tailscale-user-login";
const ALICE: &str = "alice@example.com";

fn proxy(from: &str) -> impl FnOnce(&mut vlpds::server::Config) {
    let from = from.to_string();
    move |c| {
        c.admin_proxy = Some(Arc::new(
            vlpds::admin_proxy::Settings::parse("Tailscale-User-Login", &[from], &[ALICE.into()]).unwrap(),
        ))
    }
}

/// The node's admin listener, as a base URL.
async fn admin_listener(s: &TestServer) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    vlpds::server::spawn_admin_listener(&s.app, l);
    url
}

fn get(s: &TestServer, base: &str, nsid: &str) -> reqwest::RequestBuilder {
    s.xrpc.http.get(format!("{base}/xrpc/{nsid}"))
}

fn post(s: &TestServer, base: &str, nsid: &str, body: &J) -> reqwest::RequestBuilder {
    s.xrpc.http.post(format!("{base}/xrpc/{nsid}")).json(body)
}

async fn audit_actors(s: &TestServer, did: &str, action: &str) -> Vec<String> {
    let log = s.xrpc.get("vlpds.admin.getAuditLog", &[("did", did)], &Auth::Admin).await.ok();
    log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == action)
        .map(|e| e["actor"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn header_counts_on_the_admin_listener_only() {
    let s = TestServer::spawn_with(proxy("127.0.0.0/8")).await;
    let admin = admin_listener(&s).await;
    let session = "vlpds.admin.getSession";

    let r = s.xrpc.send(get(&s, &admin, session).header(HEADER, ALICE)).await.ok();
    assert_eq!(r, json!({"auth": "proxy", "operator": ALICE}));
    // the public listener never reads it, even from a trusted address
    s.xrpc.send(get(&s, &s.url, session).header(HEADER, ALICE)).await.err(401, "AuthenticationRequired");
    // nor the peer-only header a forward carries, on either listener
    for base in [&s.url, &admin] {
        let rb = get(&s, base, session).header(vlpds::admin_proxy::OPERATOR_HEADER, ALICE);
        s.xrpc.send(rb).await.err(401, "AuthenticationRequired");
    }
    s.xrpc.send(get(&s, &admin, session)).await.err(401, "AuthenticationRequired");

    // a login off the allowlist is refused, and two headers are too
    let r = s.xrpc.send(get(&s, &admin, session).header(HEADER, "mallory@example.com")).await;
    r.err(403, "OperatorRefused");
    let rb = get(&s, &admin, session).header(HEADER, ALICE).header(HEADER, "mallory@example.com");
    s.xrpc.send(rb).await.err(403, "OperatorRefused");
    // a public read stays anonymous for a refused login
    s.xrpc.send(get(&s, &admin, "com.atproto.server.describeServer").header(HEADER, "mallory@example.com")).await.ok();

    // token auth is unchanged, on both listeners, and wins over the header
    for base in [&s.url, &admin] {
        let r = s.xrpc.send(get(&s, base, session).basic_auth("admin", Some(ADMIN_TOKEN))).await.ok();
        assert_eq!(r, json!({"auth": "token"}));
        let rb = get(&s, base, session).basic_auth("admin", Some(ADMIN_TOKEN)).header(HEADER, "mallory@example.com");
        assert_eq!(s.xrpc.send(rb).await.ok(), json!({"auth": "token"}));
        let rb = get(&s, base, session).basic_auth("admin", Some("wrong")).header(HEADER, ALICE);
        s.xrpc.send(rb).await.err(401, "AuthenticationRequired");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn header_from_an_untrusted_peer_is_ignored() {
    let s = TestServer::spawn_with(proxy("10.0.0.0/8")).await;
    let admin = admin_listener(&s).await;
    let rb = get(&s, &admin, "vlpds.admin.getSession").header(HEADER, ALICE);
    s.xrpc.send(rb).await.err(401, "AuthenticationRequired");
    let rb = get(&s, &admin, "vlpds.admin.getSession").basic_auth("admin", Some(ADMIN_TOKEN));
    s.xrpc.send(rb).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_listener_without_proxy_settings_is_token_only() {
    let s = TestServer::spawn().await;
    let admin = admin_listener(&s).await;
    let rb = get(&s, &admin, "vlpds.admin.getSession").header(HEADER, ALICE);
    s.xrpc.send(rb).await.err(401, "AuthenticationRequired");
    let rb = get(&s, &admin, "vlpds.admin.getSession").basic_auth("admin", Some(ADMIN_TOKEN));
    s.xrpc.send(rb).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_site_writes_are_refused_and_the_audit_log_names_the_operator() {
    let s = TestServer::spawn_with(proxy("127.0.0.1")).await;
    let admin = admin_listener(&s).await;
    let a = s.create_account("prx").await;
    let revoke = "vlpds.admin.revokeSessions";
    // the body's actor is the console's name for a token user; a proxy's login overrides it
    let body = json!({"did": a.did, "reason": "test", "actor": "someone-else"});

    let refused: [&[(&str, &str)]; 5] = [
        &[],
        &[("sec-fetch-site", "cross-site")],
        &[("sec-fetch-site", "same-site")],
        &[("sec-fetch-site", "none")],
        &[("origin", "https://evil.example.net")],
    ];
    for extra in refused {
        let mut rb = post(&s, &admin, revoke, &body).header(HEADER, ALICE);
        for (k, v) in extra {
            rb = rb.header(*k, *v);
        }
        s.xrpc.send(rb).await.err(403, "OperatorRefused");
    }
    // a read the browser marks cross-site, too
    let rb = get(&s, &admin, "vlpds.admin.getSession").header(HEADER, ALICE).header("sec-fetch-site", "cross-site");
    s.xrpc.send(rb).await.err(403, "OperatorRefused");
    assert!(audit_actors(&s, &a.did, "sessions.revoke").await.is_empty());

    let rb = post(&s, &admin, revoke, &body).header(HEADER, ALICE).header("sec-fetch-site", "same-origin");
    s.xrpc.send(rb).await.ok();
    let rb = post(&s, &admin, revoke, &body).header(HEADER, ALICE).header("origin", admin.as_str());
    s.xrpc.send(rb).await.ok();
    assert_eq!(audit_actors(&s, &a.did, "sessions.revoke").await, [ALICE, ALICE]);

    // the token keeps the console's name, with no origin checks
    let rb = post(&s, &admin, revoke, &body).basic_auth("admin", Some(ADMIN_TOKEN));
    s.xrpc.send(rb).await.ok();
    assert_eq!(audit_actors(&s, &a.did, "sessions.revoke").await, ["someone-else", ALICE, ALICE]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forward_to_the_owner_keeps_the_operator() {
    let store: Arc<object_store::memory::InMemory> = Arc::new(object_store::memory::InMemory::new());
    let a = cluster_node("prx-a", store.clone(), 4, proxy("127.0.0.1")).await;
    let b = cluster_node("prx-b", store.clone(), 4, |_| {}).await;
    balanced(&[&a, &b]).await;
    let admin = admin_listener(&a).await;
    // a node mints DIDs in its own shards
    let acct = b.create_account("prxf").await;
    assert!(a.app.remote_owner(&acct.did).is_some(), "b owns it");
    let body = json!({"did": acct.did, "reason": "test"});
    let rb = post(&a, &admin, "vlpds.admin.revokeSessions", &body)
        .header(HEADER, ALICE)
        .header("sec-fetch-site", "same-origin");
    a.xrpc.send(rb).await.ok();
    let actors = eventually(Duration::from_secs(10), || async {
        let v = audit_actors(&a, &acct.did, "sessions.revoke").await;
        (!v.is_empty()).then_some(v)
    })
    .await
    .expect("audited");
    assert_eq!(actors, [ALICE]);
}
