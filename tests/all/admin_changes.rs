//! `vlpds.admin.subscribeChanges` (src/xrpc/changes.rs): admin only, a
//! hello and then one message per change, and on a cluster a change made on
//! a peer reaches a console connected to another node.

use crate::common::*;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;

struct Feed {
    body: futures::stream::BoxStream<'static, reqwest::Result<bytes::Bytes>>,
    buf: String,
}

impl Feed {
    async fn open(s: &TestServer) -> Feed {
        let r = s
            .xrpc
            .http
            .get(format!("{}/xrpc/vlpds.admin.subscribeChanges", s.url))
            .header("authorization", admin_basic())
            .timeout(Duration::from_secs(600))
            .send()
            .await
            .expect("subscribeChanges");
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "text/event-stream");
        Feed { body: r.bytes_stream().boxed(), buf: String::new() }
    }

    /// The next SSE message: (event name, data).
    async fn next(&mut self) -> (String, J) {
        loop {
            if let Some(i) = self.buf.find("\n\n") {
                let msg: String = self.buf.drain(..i + 2).collect();
                let mut event = "message".to_string();
                let mut data = String::new();
                for line in msg.lines() {
                    if let Some(e) = line.strip_prefix("event: ") {
                        event = e.into();
                    } else if let Some(d) = line.strip_prefix("data: ") {
                        data = d.into();
                    }
                }
                if data.is_empty() {
                    continue;
                }
                return (event, serde_json::from_str(&data).expect("JSON data"));
            }
            let chunk = tokio::time::timeout(Duration::from_secs(20), self.body.next())
                .await
                .expect("a message within 20 s")
                .expect("stream open")
                .expect("chunk");
            self.buf.push_str(std::str::from_utf8(&chunk).unwrap());
        }
    }

    /// Reads until a change of `kind` for `id` arrives.
    async fn until(&mut self, kind: &str, id: &str) -> J {
        loop {
            let (ev, d) = self.next().await;
            if ev == "message" && d["kind"] == kind && d["id"] == id {
                return d;
            }
        }
    }
}

fn admin_basic() -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("admin:{ADMIN_TOKEN}")))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn names_what_changed() {
    let s = TestServer::spawn().await;
    s.xrpc.get("vlpds.admin.subscribeChanges", &[], &Auth::None).await.err(401, "AuthenticationRequired");
    let a = s.create_account("chg").await;
    s.xrpc.get("vlpds.admin.subscribeChanges", &[], &a.auth()).await.err(401, "AuthenticationRequired");

    let mut f = Feed::open(&s).await;
    let (ev, hello) = f.next().await;
    assert_eq!(ev, "hello");
    assert_eq!(hello["node"], "single");
    assert!(hello["kinds"].as_array().unwrap().iter().any(|k| k == "account"), "{hello}");

    // an operator write: its audit entry and its subject
    let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("chgh"));
    s.xrpc
        .post("com.atproto.admin.updateAccountHandle", &json!({"did": a.did, "handle": handle}), &Auth::Admin)
        .await
        .ok();
    let c = f.until("account", &a.did).await;
    assert_eq!(c["node"], "single");
    assert!(c["version"].as_u64().unwrap() > 1_700_000_000_000, "{c}");

    // a case, and an account made by someone signing up
    let case = s.xrpc.post("vlpds.admin.createCase", &json!({"source": "report"}), &Auth::Admin).await.ok();
    f.until("case", case["id"].as_str().unwrap()).await;
    let b = s.create_account("chg2").await;
    f.until("account", &b.did).await;

    // the user's own sign-in
    s.create_session(&b.handle, PASSWORD).await.ok();
    f.until("account", &b.did).await;

    // a firehose connection coming and going
    let sub = s.subscribe(None).await;
    let conn = eventually(Duration::from_secs(10), || async {
        let r = s.xrpc.get("vlpds.admin.listFirehoseSubscribers", &[], &Auth::Admin).await.ok();
        r["subscribers"][0]["conn"].as_str().map(String::from)
    })
    .await
    .expect("listed");
    f.until("subscriber", &format!("single/{conn}")).await;
    drop(sub);
    f.until("subscriber", &format!("single/{conn}")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_a_peers_changes() {
    let store: Arc<object_store::memory::InMemory> = Arc::new(object_store::memory::InMemory::new());
    let a = cluster_node("chg-a", store.clone(), 4, |_| {}).await;
    let b = cluster_node("chg-b", store.clone(), 4, |_| {}).await;
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
    let mut f = Feed::open(&a).await;
    assert_eq!(f.next().await.1["node"], "chg-a");
    // the relay follows b within a tick: a case made on b, until a sees one
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let seen = loop {
        assert!(std::time::Instant::now() < deadline, "b's change never reached a's watcher");
        let case = b.xrpc.post("vlpds.admin.createCase", &json!({"source": "on b"}), &Auth::Admin).await.ok();
        let id = case["id"].as_str().unwrap().to_string();
        if let Ok(c) = tokio::time::timeout(Duration::from_secs(3), f.until("case", &id)).await {
            break c;
        }
    };
    assert_eq!(seen["node"], "chg-b", "{seen}");
}
