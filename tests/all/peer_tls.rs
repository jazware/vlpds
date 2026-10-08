//! Peer mTLS (src/peer_tls.rs; DESIGN.md "Exposure"), the only
//! node-to-node transport: an in-process cluster whose nodes talk h2 over
//! TLS 1.3 with client certificates on their peer listeners, while clients
//! use the public listener (every `TestServer` is such a node; this file
//! checks the transport itself).
//!
//! - forwards, internal private put/get, the OAuth replay claim and log
//!   streams (the merged firehose) all work over mTLS;
//! - the public listener 404s `/internal/*` and serves a request carrying a
//!   forwarded marker as a client request (routed to the owner);
//! - the peer listener refuses cleartext, a client without a certificate,
//!   or with one from another CA, at the handshake; a client refuses a
//!   server whose certificate names another node than the lease at that
//!   address;
//! - a lone node has no peer listener and no `/internal/*`.

use crate::common::*;
use std::sync::Arc;
use std::time::Duration;
use vlpds::peer_tls::{self, PeerTls};

const SHARDS: u32 = 8;
const PUBLIC: &str = "http://pds.mtls.test";

/// A cluster node (public listener `url`, mTLS peer listener `peer_url`).
async fn tls_node(id: &str, store: &Arc<object_store::memory::InMemory>) -> TestServer {
    let (id, store) = (id.to_string(), store.clone());
    TestServer::spawn_with(move |c| {
        c.memory_store = Some(store);
        c.shards = SHARDS;
        c.cluster = Some(vlpds::cluster::ClusterConfig {
            node_id: id,
            addr: peer_url(c),
            shards: SHARDS,
            ttl: Duration::from_millis(1500),
            renew_every: Duration::from_millis(100),
            skew: Duration::from_millis(200),
            ..Default::default()
        });
        // one issuer for every node (OAuth)
        c.public_url = PUBLIC.into();
    })
    .await
}

fn forwards() -> u64 {
    vlpds::metrics::FORWARDED.get()
}

async fn cluster_status(c: &reqwest::Client, base: &str) -> reqwest::Result<reqwest::Response> {
    c.get(format!("{base}/internal/v1/cluster"))
        .header("x-vlpds-internal", vlpds::server::DEV_INTERNAL_TOKEN)
        .send()
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mtls_cluster_end_to_end() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = tls_node("tls-a", &store).await;
    let b = tls_node("tls-b", &store).await;
    let c = tls_node("tls-c", &store).await;
    let a_peer = a.peer_url.clone();
    let nodes = [&a, &b, &c];
    balanced(&nodes).await;
    for n in nodes {
        for p in n.app.cluster.as_ref().unwrap().peers() {
            assert!(p.addr.starts_with("https://"), "{}", p.addr);
        }
    }

    // accounts until each node owns one
    let mut owned: Vec<Option<TestAccount>> = vec![None, None, None];
    for k in 0..90 {
        let acct = nodes[k % 3].create_account("mtls").await;
        let o = owner_of(&nodes, &acct.did);
        let i = nodes.iter().position(|n| std::ptr::eq(*n, o)).unwrap();
        owned[i].get_or_insert(acct);
        if owned.iter().all(Option::is_some) {
            break;
        }
    }
    let owned: Vec<TestAccount> = owned
        .into_iter()
        .enumerate()
        .map(|(i, o)| {
            o.unwrap_or_else(|| {
                panic!(
                    "no account on node {i}: owned {:?}",
                    nodes.iter().map(|n| n.app.partitions.owned().len()).collect::<Vec<_>>()
                )
            })
        })
        .collect();

    // a firehose on a: b's and c's commits reach it through their log streams
    let mut sub = a.subscribe_from_now().await;
    let before = forwards();
    for (i, acct) in owned.iter().enumerate() {
        // through a node that doesn't own the account: forwarded over mTLS
        let via = nodes[(i + 1) % 3];
        let r = via.post(acct, &format!("over mtls {i}")).await;
        let got = nodes[(i + 2) % 3].get_record(acct.did.as_str(), r.collection(), r.rkey()).await;
        assert_eq!(got.status, 200, "{}", got.text());
        sub.wait_for(FH_TIMEOUT, &acct.did, "#commit").await;
    }
    assert!(forwards() >= before + 6, "writes and reads were forwarded");

    // internal private put/get, from c, for an account a owns
    let did = &owned[0].did;
    let m = vlsync_store::segment::Mutation {
        key: vlpds::state::private_key(did, "mtls").into(),
        val: Some(bytes::Bytes::from_static(b"v")),
    };
    c.app.put_private(did, vec![m]).await.unwrap_or_else(|e| panic!("private put: {}", e.message));
    assert_eq!(
        c.app.get_private(did, "mtls").await.unwrap_or_else(|e| panic!("{}", e.message)).as_deref(),
        Some(&b"v"[..])
    );

    // the OAuth replay claim at the routing key's owner (a), from c
    let until = chrono::Utc::now().timestamp() + 60;
    let key = format!("mtls-jti-{}", rand::random::<u64>());
    assert!(
        vlpds::xrpc::internal::claim_replay_anywhere(&c.app, did, &key, until)
            .await
            .unwrap_or_else(|e| panic!("{}", e.message)),
        "first claim"
    );
    assert!(
        !vlpds::xrpc::internal::claim_replay_anywhere(&b.app, did, &key, until)
            .await
            .unwrap_or_else(|e| panic!("{}", e.message)),
        "replay refused"
    );

    // the public listener: no /internal/*, even with the token
    let plain = reqwest::Client::new();
    assert_eq!(cluster_status(&plain, &a.url).await.unwrap().status(), 404);
    assert_eq!(plain.get(format!("{}/internal/v1/ratelimits", a.url)).send().await.unwrap().status(), 404);
    // ... and a client's forwarded marker is a client request: a write for
    // b's account sent to a with the marker is routed to b, not served here
    let acct = &owned[1];
    let r = a
        .xrpc
        .send(
            a.xrpc
                .http
                .post(format!("{}/xrpc/com.atproto.repo.createRecord", a.url))
                .header("authorization", format!("Bearer {}", acct.access))
                .header("x-vlpds-forwarded", vlpds::server::DEV_INTERNAL_TOKEN)
                .json(&json!({"repo": acct.did, "collection": "app.bsky.feed.post", "record": post_record("marker")})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    // the peer listener: TLS only
    assert!(cluster_status(&plain, &a_peer.replace("https://", "http://")).await.is_err());
    // a peer client of this cluster gets in (and the token still applies)
    let peer = peer_client();
    let r = peer
        .get(format!("{a_peer}/internal/v1/cluster"))
        .header("x-vlpds-internal", vlpds::server::DEV_INTERNAL_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.version(), reqwest::Version::HTTP_2);
    let r = peer.get(format!("{a_peer}/internal/v1/cluster")).header("x-vlpds-internal", "nope").send().await.unwrap();
    assert_eq!(r.status(), 401, "the internal token is a second factor");

    // operators reach a given node through any node's public listener: an
    // admin call naming it (x-vlpds-node) is relayed over mTLS
    for (id, n) in [("tls-a", &a), ("tls-b", &b), ("tls-c", &c)] {
        let r = a
            .xrpc
            .send(
                a.xrpc
                    .http
                    .get(format!("{}/xrpc/vlpds.admin.getClusterStatus", a.url))
                    .header("x-vlpds-node", id)
                    .basic_auth("admin", Some(ADMIN_TOKEN)),
            )
            .await
            .ok();
        assert_eq!(r["node"], id, "{r}");
        assert_eq!(n.app.cluster.as_ref().unwrap().cfg.node_id, id);
    }
    let rb = a.xrpc.http.get(format!("{}/xrpc/vlpds.admin.getClusterStatus", a.url)).header("x-vlpds-node", "tls-b");
    assert_eq!(a.xrpc.send(rb).await.status, 401, "relayed with the caller's (missing) credentials");
    let r = a
        .xrpc
        .send(
            a.xrpc
                .http
                .get(format!("{}/xrpc/vlpds.admin.getClusterStatus", a.url))
                .header("x-vlpds-node", "nope")
                .basic_auth("admin", Some(ADMIN_TOKEN)),
        )
        .await;
    r.err(404, "NodeNotFound");
}

/// TLS 1.3 client config with the test CA as root and no client certificate.
fn no_client_cert() -> reqwest::Client {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::CertificateDer::pem_slice_iter(test_ca().cert_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(vlatproto::http::tls_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    reqwest::Client::builder().tls_backend_preconfigured(cfg).http2_prior_knowledge().build().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_listener_refuses_foreign_and_missing_certs() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = tls_node("tls-solo", &store).await;
    let url = format!("{}/internal/v1/cluster", a.peer_url);
    let token = vlpds::server::DEV_INTERNAL_TOKEN;
    // the server counts each refusal (other tests may add their own)
    let failures = || {
        vlpds::metrics::render()
            .lines()
            .find_map(|l| l.strip_prefix("vlpds_peer_tls_handshake_failures_total{side=\"server\"} "))
            .map_or(0.0, |v| v.parse::<f64>().unwrap())
    };
    let refused = |before: f64| async move {
        let t = std::time::Instant::now();
        while failures() <= before {
            assert!(t.elapsed() < Duration::from_secs(5), "refusal not counted");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };

    // a node of this cluster: in
    let ok = vlpds::http::PeerClient::new(1, node_tls("tls-member"));
    assert_eq!(ok.get(&url).header("x-vlpds-internal", token).send().await.unwrap().status(), 200);

    // no client certificate: refused at the handshake
    let before = failures();
    let e = no_client_cert().get(&url).header("x-vlpds-internal", token).send().await;
    assert!(e.is_err(), "{e:?}");
    refused(before).await;

    // a certificate from another CA (whose CA trusts ours, so only the
    // server's check fails)
    let other = peer_tls::create_ca("another CA", 30).unwrap();
    let n = peer_tls::issue_node(&other.cert_pem, &other.key_pem, "tls-intruder", &["127.0.0.1".into()], 30).unwrap();
    let bundle = format!("{}{}", other.cert_pem, test_ca().cert_pem);
    let intruder = vlpds::http::PeerClient::new(1, PeerTls::from_pem(&bundle, &n.cert_pem, &n.key_pem).unwrap());
    let before = failures();
    let e = intruder.get(&url).header("x-vlpds-internal", token).send().await;
    assert!(e.is_err(), "{e:?}");
    refused(before).await;

    // a client of another CA doesn't trust our server either
    let s = peer_tls::issue_node(&other.cert_pem, &other.key_pem, "tls-stranger", &["127.0.0.1".into()], 30).unwrap();
    let stranger =
        vlpds::http::PeerClient::new(1, PeerTls::from_pem(&other.cert_pem, &s.cert_pem, &s.key_pem).unwrap());
    assert!(stranger.get(&url).send().await.is_err());

    // no cleartext either way: the peer client refuses http:// before
    // connecting, and the peer listener answers no plain HTTP
    assert!(ok.get(url.replace("https://", "http://")).send().await.is_err());
    let plain =
        reqwest::Client::new().get(url.replace("https://", "http://")).header("x-vlpds-internal", token).send().await;
    assert!(plain.is_err(), "{plain:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_identity_must_match_the_lease() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = tls_node("tls-x", &store).await;
    let a_peer = a.peer_url.clone();
    let url = format!("{a_peer}/internal/v1/cluster");
    let origin = vlpds::http::split_origin(&a_peer).0.to_string();

    // the registry says another node lives at this address: tls-x's
    // certificate (valid, same CA, right host) is refused
    let wrong = vlpds::http::PeerClient::new(1, node_tls("tls-y"));
    let o = origin.clone();
    wrong.set_registry(Arc::new(move |q: &str| if q == o { vec!["tls-y".to_string()] } else { Vec::new() }));
    let e = wrong.get(&url).header("x-vlpds-internal", vlpds::server::DEV_INTERNAL_TOKEN).send().await;
    assert!(e.is_err(), "{e:?}");

    // the right node: in
    let right = vlpds::http::PeerClient::new(1, node_tls("tls-y"));
    let o = origin.clone();
    right.set_registry(Arc::new(move |q: &str| if q == o { vec!["tls-x".to_string()] } else { Vec::new() }));
    let r = right.get(&url).header("x-vlpds-internal", vlpds::server::DEV_INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(r.status(), 200);

    // the log stream connector checks the node too
    let ws = format!("{}/internal/v1/log/stream", a_peer.replace("https://", "wss://"));
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(ws.as_str()).unwrap();
    req.headers_mut().insert("x-vlpds-internal", vlpds::server::DEV_INTERNAL_TOKEN.parse().unwrap());
    let bad =
        tokio_tungstenite::connect_async_tls_with_config(req.clone(), None, false, right.ws_connector("tls-y")).await;
    assert!(bad.is_err());
    let good = tokio_tungstenite::connect_async_tls_with_config(req, None, false, right.ws_connector("tls-x")).await;
    assert!(good.is_ok(), "{:?}", good.err());
}

/// A lone node (the binary without `--peer-listen`): no peer listener, no
/// `/internal/*`, and its peer client reaches no one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lone_node_has_no_peer_side() {
    let s = TestServer::spawn_lone(|_| {}).await;
    assert!(s.peer_url.is_empty());
    let r = reqwest::Client::new()
        .get(format!("{}/internal/v1/cluster", s.url))
        .header("x-vlpds-internal", vlpds::server::DEV_INTERNAL_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let a = s.create_account("lone").await;
    s.post(&a, "still serves").await;
    // (a peer's address, were one to show up: refused without connecting)
    let other = TestServer::spawn().await;
    assert!(s.app.http.get(format!("{}/internal/v1/cluster", other.peer_url)).send().await.is_err());
}
