//! AT Protocol Spaces, phase 0 (src/space): `--spaces` keeps the Spaces
//! NSIDs local (501, never proxied), and a public record pointing into a
//! space validates whatever the flag.

use crate::common::*;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use parking_lot::Mutex;
use std::sync::Arc;

const METHODS: &[(&str, bool)] = &[
    ("com.atproto.space.getRecord?repo=did:plc:x", false),
    ("com.atproto.space.getDelegationToken?space=at://did:plc:x/space/com.example.group/default", false),
    ("com.atproto.space.createRecord", true),
    ("com.atproto.space.notifyWrite", true),
    ("com.atproto.space.createSpace", true),
    ("com.atproto.space.getSpace", false),
    // NSID authorities are case-insensitive
    ("COM.ATPROTO.Space.getRecord", false),
];

/// Spaces methods without a handler yet: with the flag they answer 501
/// locally.
const UNIMPLEMENTED: &[(&str, bool)] = &[
    ("com.atproto.space.notifySpaceDeleted", true),
    ("com.atproto.managedspace.checkUserAccess", false),
    // NSID authorities are case-insensitive
    ("COM.ATPROTO.Space.getRecord", false),
];

/// A did:web service on loopback that records what reaches it.
async fn upstream() -> (String, Arc<Mutex<Vec<String>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (base, did) = (format!("http://{addr}"), format!("did:web:127.0.0.1%3A{}", addr.port()));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (s, d, b) = (seen.clone(), did.clone(), base.clone());
    let router = axum::Router::new().fallback(move |req: Request| {
        let (s, d, b) = (s.clone(), d.clone(), b.clone());
        async move {
            if req.uri().path() == "/.well-known/did.json" {
                let doc = json!({"id": d, "service": [{"id": "#atproto_test", "type": "Test", "serviceEndpoint": b}]});
                return Response::builder()
                    .header("content-type", "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap();
            }
            s.lock().push(req.uri().to_string());
            Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(r#"{"upstream":true}"#))
                .unwrap()
        }
    });
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    (format!("{did}#atproto_test"), seen)
}

async fn call(s: &TestServer, a: &TestAccount, nsid: &str, post: bool, proxy: Option<&str>) -> Resp {
    let url = format!("{}/xrpc/{nsid}", s.url);
    let mut rb = match post {
        true => s.xrpc.http.post(url).json(&json!({})),
        false => s.xrpc.http.get(url),
    };
    rb = rb.header("authorization", format!("Bearer {}", a.access));
    if let Some(p) = proxy {
        rb = rb.header("atproto-proxy", p);
    }
    s.xrpc.send(rb).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_methods_answer_501_locally_with_the_flag() {
    let (proxy, seen) = upstream().await;
    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let a = s.create_account("spc").await;
    for &(nsid, post) in UNIMPLEMENTED {
        for p in [None, Some(proxy.as_str())] {
            let r = call(&s, &a, nsid, post, p).await;
            assert_eq!(
                (r.status, r.error_name(), r.json["message"].as_str()),
                (501, Some("MethodNotImplemented"), Some("Method Not Implemented")),
                "{nsid} proxy={p:?}: {r:?}"
            );
        }
        // without credentials too
        let r = s.xrpc.send(s.xrpc.http.get(format!("{}/xrpc/{nsid}", s.url)).header("atproto-proxy", &proxy)).await;
        assert_eq!(r.status, 501, "{nsid}: {r:?}");
    }
    assert!(seen.lock().is_empty(), "reached the upstream: {:?}", seen.lock());
    // other methods are still proxied
    let r = call(&s, &a, "com.example.ok", false, Some(&proxy)).await;
    assert_eq!(r.ok(), json!({"upstream": true}));
    assert_eq!(seen.lock().len(), 1);
}

/// Without the flag a Spaces NSID still answers 501 here and is never
/// proxied: the proxy would mint service auth for it (a notifyWrite as the
/// account) and send it wherever the header names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_methods_without_the_flag_are_never_proxied() {
    let (proxy, seen) = upstream().await;
    let s = TestServer::spawn().await;
    let a = s.create_account("spo").await;
    for &(nsid, post) in METHODS {
        for p in [None, Some(proxy.as_str())] {
            let r = call(&s, &a, nsid, post, p).await;
            assert_eq!((r.status, r.error_name()), (501, Some("MethodNotImplemented")), "{nsid} proxy={p:?}: {r:?}");
        }
    }
    assert!(seen.lock().is_empty(), "reached the upstream: {:?}", seen.lock());
    let r = call(&s, &a, "com.example.ok", false, Some(&proxy)).await;
    assert_eq!(r.ok(), json!({"upstream": true}));
}

/// A public record whose `at-uri` field names a record in a space (or the
/// space itself) validates, with Spaces on or off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_records_may_reference_spaces() {
    for spaces in [false, true] {
        let s = TestServer::spawn_with(|c| c.spaces = spaces).await;
        let a = s.create_account("spr").await;
        for uri in [
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/app.bsky.feed.post/3jui7kd54zh2y",
            "at://did:plc:asdf123/space/com.example.group/default",
        ] {
            let like = json!({
                "$type": "app.bsky.feed.like",
                "createdAt": "2026-10-01T00:00:00.000Z",
                "subject": {"uri": uri, "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},
            });
            let body = json!({"repo": a.did, "collection": "app.bsky.feed.like", "record": like, "validate": true});
            let r = s.xrpc.post("com.atproto.repo.createRecord", &body, &a.auth()).await;
            assert_eq!(r.ok()["validationStatus"], "valid", "spaces={spaces} {uri}");
        }
        // a malformed space URI still isn't an at-uri
        let like = json!({
            "$type": "app.bsky.feed.like",
            "createdAt": "2026-10-01T00:00:00.000Z",
            "subject": {"uri": "at://user.test/space/com.example.group/default", "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},
        });
        let body = json!({"repo": a.did, "collection": "app.bsky.feed.like", "record": like});
        let r = s.xrpc.post("com.atproto.repo.createRecord", &body, &a.auth()).await;
        assert_eq!((r.status, r.error_name()), (400, Some("InvalidRequest")), "{r:?}");
    }
}
