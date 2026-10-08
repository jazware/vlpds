//! Port of the reference PDS's ssrf.test.ts: registerPush, unregisterPush
//! and an atproto-proxy'd createReport go to endpoints taken from a DID
//! document. Outside dev mode (vlpds's SSRF policy) a loopback endpoint is
//! refused before anything is sent; in dev mode (the differential control:
//! same DID, same calls) the stub receives them. The service DID is a
//! did:plc in the mock directory, which both modes resolve (the operator's
//! PLC URL is trusted), so the refusal can only come from the endpoint.

use crate::common::*;
use axum::extract::{Request, State};
use axum::response::IntoResponse;
use parking_lot::Mutex;
use std::sync::Arc;
use vlpds::plc::mock::MockPlc;

#[derive(Clone, Default)]
struct Upstream {
    seen: Arc<Mutex<Vec<String>>>,
}

async fn upstream_handler(State(u): State<Upstream>, req: Request) -> axum::response::Response {
    let path = req.uri().path().to_string();
    u.seen.lock().push(format!("{} {path}", req.method()));
    let body = if path.ends_with("createReport") {
        json!({
            "id": 1,
            "reasonType": "com.atproto.moderation.defs#reasonSpam",
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:abcdefghijklmnopqrstuvwx"},
            "reportedBy": "did:plc:abcdefghijklmnopqrstuvwx",
            "createdAt": now_iso(),
        })
    } else {
        json!({})
    };
    axum::Json(body).into_response()
}

async fn spawn_upstream() -> (Upstream, String) {
    let u = Upstream::default();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://localhost:{}", l.local_addr().unwrap().port());
    let router = axum::Router::new().fallback(upstream_handler).with_state(u.clone());
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    (u, endpoint)
}

/// Registers a did:plc whose `#bsky_notif` and `#atproto_labeler` services
/// point at `endpoint`.
async fn service_did(plc: &MockPlc, endpoint: &str) -> String {
    let key = vlatproto::crypto::Keypair::generate();
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [key.did_key()],
        "verificationMethods": {"atproto": key.did_key(), "atproto_label": key.did_key()},
        "alsoKnownAs": ["at://notifsvc.example.com"],
        "services": {
            "bsky_notif": {"type": "BskyNotificationService", "endpoint": endpoint},
            "atproto_labeler": {"type": "AtprotoLabeler", "endpoint": endpoint},
        },
        "prev": null,
    });
    let op = vlpds::plc::sign(op, &key).unwrap();
    let did = vlpds::plc::did_for_genesis(&op).unwrap();
    let r = reqwest::Client::new().post(format!("{}/{did}", plc.url)).json(&op).send().await.unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    did
}

struct Ctx {
    s: TestServer,
    reporter: TestAccount,
    service: String,
}

async fn setup(ssrf_protection: bool, endpoint: &str) -> Ctx {
    let plc = MockPlc::start().await;
    let service = service_did(&plc, endpoint).await;
    let url = plc.url.clone();
    let s = TestServer::spawn_with(move |c| {
        // vlpds ties its SSRF policy to dev mode
        c.dev_mode = !ssrf_protection;
        c.plc_url = url;
        // push needs an AppView configured (unused here: never contacted)
        c.appview = Some(("http://127.0.0.1:1".into(), "did:web:appview.test".into()));
    })
    .await;
    let reporter = s.create_account("reporter").await;
    Ctx { s, reporter, service }
}

impl Ctx {
    async fn push(&self, nsid: &str) -> Resp {
        let body = json!({"serviceDid": self.service, "token": "tok1", "platform": "web", "appId": "app1"});
        self.s.xrpc.post(nsid, &body, &self.reporter.auth()).await
    }

    async fn create_report(&self) -> Resp {
        let body = json!({
            "reasonType": "com.atproto.moderation.defs#reasonSpam",
            "reason": "ssrf probe",
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": self.reporter.did},
        });
        let rb = self
            .s
            .xrpc
            .http
            .post(format!("{}/xrpc/com.atproto.moderation.createReport", self.s.url))
            .bearer_auth(&self.reporter.access)
            .header("atproto-proxy", format!("{}#atproto_labeler", self.service))
            .json(&body);
        self.s.xrpc.send(rb).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_with_ssrf_protection_enabled_nothing_is_sent() {
    let (up, endpoint) = spawn_upstream().await;
    let ctx = setup(true, &endpoint).await;
    // refuses to send registerPush to a non-unicast endpoint
    let r = ctx.push("app.bsky.notification.registerPush").await;
    assert!(!r.is_ok(), "{}", r.text());
    // refuses to send unregisterPush to a non-unicast endpoint
    let r = ctx.push("app.bsky.notification.unregisterPush").await;
    assert!(!r.is_ok(), "{}", r.text());
    // refuses to send createReport to a non-unicast endpoint
    let r = ctx.create_report().await;
    assert!(!r.is_ok(), "{}", r.text());
    assert_eq!(*up.seen.lock(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_with_ssrf_protection_disabled_calls_are_sent() {
    let (up, endpoint) = spawn_upstream().await;
    let ctx = setup(false, &endpoint).await;
    // sends registerPush to the endpoint
    ctx.push("app.bsky.notification.registerPush").await.ok();
    assert_eq!(std::mem::take(&mut *up.seen.lock()), ["POST /xrpc/app.bsky.notification.registerPush"]);
    // sends unregisterPush to the endpoint
    ctx.push("app.bsky.notification.unregisterPush").await.ok();
    assert_eq!(std::mem::take(&mut *up.seen.lock()), ["POST /xrpc/app.bsky.notification.unregisterPush"]);
    // sends createReport to the endpoint
    let r = ctx.create_report().await;
    assert!(r.is_ok(), "{}", r.text());
    assert_eq!(std::mem::take(&mut *up.seen.lock()), ["POST /xrpc/com.atproto.moderation.createReport"]);
}

/// Registers a did:plc with these `(service id, endpoint)` services.
async fn did_with_services(plc: &MockPlc, services: &[(String, String)]) -> String {
    let key = vlatproto::crypto::Keypair::generate();
    let services: serde_json::Map<String, J> =
        services.iter().map(|(id, ep)| (id.clone(), json!({"type": "SomeService", "endpoint": ep}))).collect();
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [key.did_key()],
        "verificationMethods": {"atproto": key.did_key()},
        "alsoKnownAs": [],
        "services": services,
        "prev": null,
    });
    let op = vlpds::plc::sign(op, &key).unwrap();
    let did = vlpds::plc::did_for_genesis(&op).unwrap();
    let r = reqwest::Client::new().post(format!("{}/{did}", plc.url)).json(&op).send().await.unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    did
}

/// atproto-proxy to a service whose endpoint is internal, in the forms an
/// attacker's DID document can spell it: refused with 502 before anything
/// connects (the loopback listener counts connections), so the service JWT
/// minted for the call never leaves the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_to_internal_endpoints_is_refused() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = hits.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(s);
        }
    });
    let endpoints: Vec<String> = [
        "http://127.0.0.1:{port}",
        "https://127.0.0.1:{port}",
        "https://localhost:{port}",
        "https://localhost.:{port}",
        "https://2130706433:{port}",
        "https://0x7f.1:{port}",
        "https://[::1]:{port}",
        "https://[::ffff:127.0.0.1]:{port}",
        "https://[::ffff:7f00:1]:{port}",
        "https://169.254.169.254",
        "https://[fd00:ec2::254]",
        "https://10.0.0.1:2583",
        "https://100.100.100.200",
        "https://[fe80::1]",
        "https://0.0.0.0:{port}",
    ]
    .iter()
    .map(|e| e.replace("{port}", &port.to_string()))
    .collect();
    let plc = MockPlc::start().await;
    let mut targets = Vec::new();
    for chunk in endpoints.chunks(8) {
        let svcs: Vec<(String, String)> =
            chunk.iter().enumerate().map(|(i, e)| (format!("svc{i}"), e.clone())).collect();
        let did = did_with_services(&plc, &svcs).await;
        targets.extend(svcs.into_iter().map(|(id, e)| (format!("{did}#{id}"), e)));
    }
    let url = plc.url.clone();
    let s = TestServer::spawn_with(move |c| {
        c.dev_mode = false;
        c.plc_url = url;
        c.appview = Some(("http://127.0.0.1:1".into(), "did:web:appview.test".into()));
    })
    .await;
    let u = s.create_account("prober").await;
    for (target, endpoint) in &targets {
        for nsid in ["app.bsky.feed.getTimeline", "com.atproto.moderation.createReport"] {
            let url = format!("{}/xrpc/{nsid}", s.url);
            let rb = match nsid.ends_with("Report") {
                true => s.xrpc.http.post(url).json(&json!({
                    "reasonType": "com.atproto.moderation.defs#reasonSpam",
                    "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": u.did},
                })),
                false => s.xrpc.http.get(url),
            };
            let r = s.xrpc.send(rb.bearer_auth(&u.access).header("atproto-proxy", target)).await;
            assert_eq!((r.status, r.error_name()), (502, Some("UpstreamFailure")), "{endpoint} ({nsid}): {}", r.text());
        }
    }
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "an internal endpoint was contacted");
}
