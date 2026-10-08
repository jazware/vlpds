//! Read-after-write on proxied AppView reads (src/xrpc/proxy/read_after_write.rs),
//! after the reference's tests/proxied/read-after-write.test.ts, against a
//! stub AppView that answers with a fixed `atproto-repo-rev` and canned
//! bodies. Also getFeed's feed-generator service auth (reference getFeed.ts).

use crate::common::*;
use axum::extract::Request;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const APPVIEW_DID: &str = "did:web:appview.test";
const CDN: &str = "https://cdn.test/img/%s/plain/%s/%s@jpeg";
const OLD: &str = "2020-01-01T00:00:00.000Z";

#[derive(Debug, Clone)]
struct Seen {
    nsid: String,
    query: String,
    authorization: String,
    accept_encoding: String,
}

#[derive(Default)]
struct Stub {
    rev: Mutex<String>,
    /// nsid (or "nsid uri" for getPostThread) -> (status, body)
    bodies: Mutex<HashMap<String, (u16, J)>>,
    /// served as is with Content-Encoding: gzip, instead of `bodies`
    raw_gzip: Mutex<Option<Vec<u8>>>,
    /// gzip JSON bodies when the request accepts gzip
    gzip: AtomicBool,
    /// brotli JSON bodies when the request accepts br
    br: AtomicBool,
    seen: Mutex<Vec<Seen>>,
}

impl Stub {
    fn set(&self, key: &str, body: J) {
        self.bodies.lock().insert(key.into(), (200, body));
    }
    fn set_status(&self, key: &str, status: u16, body: J) {
        self.bodies.lock().insert(key.into(), (status, body));
    }
    fn set_rev(&self, rev: &str) {
        *self.rev.lock() = rev.into();
    }
    fn last(&self, nsid: &str) -> Seen {
        self.seen.lock().iter().rev().find(|s| s.nsid == nsid).cloned().unwrap_or_else(|| panic!("no {nsid} request"))
    }
}

async fn spawn_stub() -> (Arc<Stub>, String) {
    let stub = Arc::new(Stub::default());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let st = stub.clone();
    let router = axum::Router::new().fallback(move |req: Request| {
        let st = st.clone();
        async move {
            let nsid = req.uri().path().trim_start_matches("/xrpc/").to_string();
            let query = req.uri().query().unwrap_or("").to_string();
            let h = |n: &str| req.headers().get(n).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
            let seen = Seen {
                nsid: nsid.clone(),
                query: query.clone(),
                authorization: h("authorization"),
                accept_encoding: h("accept-encoding"),
            };
            st.seen.lock().push(seen.clone());
            let mut b = axum::http::Response::builder().header("content-type", "application/json");
            let rev = st.rev.lock().clone();
            if !rev.is_empty() {
                b = b.header("atproto-repo-rev", rev);
            }
            if let Some(raw) = st.raw_gzip.lock().clone() {
                return b.header("content-encoding", "gzip").body(axum::body::Body::from(raw)).unwrap();
            }
            let uri = qmap(&query).remove("uri");
            let bodies = st.bodies.lock();
            let (status, body) = uri
                .and_then(|u| bodies.get(&format!("{nsid} {u}")))
                .or_else(|| bodies.get(&nsid))
                .cloned()
                .unwrap_or((200, json!({})));
            drop(bodies);
            let bytes = serde_json::to_vec(&body).unwrap();
            if st.br.load(Ordering::Relaxed) && seen.accept_encoding.contains("br") {
                let mut out = Vec::new();
                brotli::BrotliCompress(&mut &bytes[..], &mut out, &Default::default()).unwrap();
                b = b.header("content-encoding", "br");
                return b.status(status).body(axum::body::Body::from(out)).unwrap();
            }
            if st.gzip.load(Ordering::Relaxed) && seen.accept_encoding.contains("gzip") {
                let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(&bytes).unwrap();
                b = b.header("content-encoding", "gzip");
                return b.status(status).body(axum::body::Body::from(e.finish().unwrap())).unwrap();
            }
            b.status(status).body(axum::body::Body::from(bytes)).unwrap()
        }
    });
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    (stub, url)
}

async fn setup() -> (Arc<Stub>, TestServer) {
    let (stub, url) = spawn_stub().await;
    let s = TestServer::spawn_with(|c| {
        c.appview = Some((url, APPVIEW_DID.into()));
        c.appview_cdn_url_pattern = Some(CDN.into());
    })
    .await;
    (stub, s)
}

fn cdn(preset: &str, did: &str, cid: &str) -> String {
    CDN.replacen("%s", preset, 1).replacen("%s", did, 1).replacen("%s", cid, 1)
}

fn qmap(query: &str) -> HashMap<String, String> {
    reqwest::Url::parse(&format!("http://x/?{query}")).unwrap().query_pairs().into_owned().collect()
}

/// JWT payload of a `Bearer` header.
fn claims(authorization: &str) -> J {
    let tok = authorization.strip_prefix("Bearer ").expect("bearer");
    serde_json::from_slice(&B64.decode(tok.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

async fn rev(s: &TestServer, did: &str) -> String {
    s.latest_commit(did).await.1
}

async fn put_profile(s: &TestServer, a: &TestAccount, record: J) {
    let r = s
        .xrpc
        .post(
            "com.atproto.repo.putRecord",
            &json!({"repo": a.did, "collection": "app.bsky.actor.profile", "rkey": "self", "record": record}),
            &a.auth(),
        )
        .await;
    assert_eq!(r.status, 200, "{r:?}");
}

async fn upload_png(s: &TestServer, a: &TestAccount) -> J {
    s.xrpc.post_bytes("com.atproto.repo.uploadBlob", PNG_1X1.to_vec(), "image/png", &a.auth()).await.ok()["blob"]
        .clone()
}

fn author(a: &TestAccount, name: &str) -> J {
    json!({"did": a.did, "handle": a.handle, "displayName": name})
}

fn post_view(r: &RecordRef, author: J, text: &str, indexed_at: &str) -> J {
    json!({"uri": r.uri, "cid": r.cid, "author": author, "record": {"$type": "app.bsky.feed.post", "text": text, "createdAt": indexed_at},
        "likeCount": 3, "indexedAt": indexed_at})
}

fn strong(r: &RecordRef) -> J {
    json!({"uri": r.uri, "cid": r.cid})
}

fn lag(r: &Resp) -> Option<i64> {
    r.header("atproto-upstream-lag").map(|v| v.parse().expect("lag is an integer"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_overlay_and_images() {
    let (stub, s) = setup().await;
    let a = s.create_account("rawprof").await;
    let b = s.create_account("rawother").await;
    s.post(&a, "before the appview rev").await;
    stub.set_rev(&rev(&s, &a.did).await);
    let upstream = json!({"did": a.did, "handle": a.handle, "displayName": "old", "description": "old desc", "banner": "https://x/b", "followersCount": 7});
    stub.set("app.bsky.actor.getProfile", upstream.clone());
    stub.set(
        "app.bsky.actor.getProfiles",
        json!({"profiles": [upstream.clone(), {"did": b.did, "handle": b.handle, "displayName": "b"}]}),
    );

    // nothing written since the rev: the upstream's answer
    let r = s.xrpc.get("app.bsky.actor.getProfile", &[("actor", &a.did)], &a.auth()).await;
    assert_eq!(r.ok(), upstream);
    assert_eq!(lag(&r), None);

    put_profile(&s, &a, json!({"$type": "app.bsky.actor.profile", "displayName": "blah"})).await;
    let r = s.xrpc.get("app.bsky.actor.getProfile", &[("actor", &a.did)], &a.auth()).await;
    let j = r.ok();
    assert_eq!(j["displayName"], "blah");
    assert!(j.get("description").is_none(), "the record has none: {j}");
    assert!(j.get("banner").is_none(), "{j}");
    assert_eq!(j["followersCount"], 7, "AppView fields are kept");
    assert!(lag(&r).unwrap() >= 0);
    assert_eq!(r.header("content-type").as_deref(), Some("application/json; charset=utf-8"));

    // image formatting: the CDN pattern (reference util.format)
    let blob = upload_png(&s, &a).await;
    let cid = blob["ref"]["$link"].as_str().unwrap().to_string();
    put_profile(&s, &a, json!({"$type": "app.bsky.actor.profile", "displayName": "blah", "description": "new", "avatar": blob, "banner": blob})).await;
    let j = s.xrpc.get("app.bsky.actor.getProfile", &[("actor", &a.did)], &a.auth()).await.ok();
    assert_eq!(j["avatar"], cdn("avatar", &a.did, &cid));
    assert_eq!(j["banner"], cdn("banner", &a.did, &cid));
    assert_eq!(j["description"], "new");

    // getProfiles: only the requester's entry
    let j = s.xrpc.get("app.bsky.actor.getProfiles", &[("actors", &a.did), ("actors", &b.did)], &a.auth()).await.ok();
    assert_eq!(j["profiles"][0]["displayName"], "blah");
    assert_eq!(j["profiles"][0]["avatar"], cdn("avatar", &a.did, &cid));
    assert_eq!(j["profiles"][1], json!({"did": b.did, "handle": b.handle, "displayName": "b"}));

    // someone else's profile is not touched, even when the requester has writes
    stub.set("app.bsky.actor.getProfile", json!({"did": b.did, "handle": b.handle, "displayName": "b"}));
    let j = s.xrpc.get("app.bsky.actor.getProfile", &[("actor", &b.did)], &a.auth()).await.ok();
    assert_eq!(j, json!({"did": b.did, "handle": b.handle, "displayName": "b"}));

    // unauthenticated: not proxied as anyone (and so never munged)
    let r = s.xrpc.get("app.bsky.actor.getProfile", &[("actor", &a.did)], &Auth::None).await;
    assert_eq!(r.status, 401, "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn feeds_get_new_posts() {
    let (stub, s) = setup().await;
    let a = s.create_account("rawfeed").await;
    let b = s.create_account("rawfeedb").await;
    let p0 = s.post(&a, "indexed").await;
    let bp = s.post(&b, "someone else").await;
    stub.set_rev(&rev(&s, &a.did).await);
    stub.set(
        "app.bsky.feed.getAuthorFeed",
        json!({"feed": [{"post": post_view(&p0, author(&a, "old"), "indexed", OLD)}], "cursor": "c1"}),
    );
    stub.set(
        "app.bsky.feed.getTimeline",
        json!({"feed": [{"post": post_view(&bp, author(&b, "b"), "someone else", OLD)}], "cursor": "t1"}),
    );
    stub.set(
        "app.bsky.feed.getActorLikes",
        json!({"feed": [{"post": post_view(&p0, author(&a, "old"), "indexed", OLD)}, {"post": post_view(&bp, author(&b, "b"), "x", OLD)}]}),
    );

    put_profile(&s, &a, json!({"$type": "app.bsky.actor.profile", "displayName": "New Name"})).await;
    let p1 = s.post(&a, "fresh").await;

    // getAuthorFeed: the new post first, the profile on every own post
    let r = s.xrpc.get("app.bsky.feed.getAuthorFeed", &[("actor", &a.did)], &a.auth()).await;
    assert!(lag(&r).is_some());
    let j = r.ok();
    let feed = j["feed"].as_array().unwrap();
    assert_eq!(feed.len(), 2, "{j}");
    let post = &feed[0]["post"];
    assert_eq!(post["uri"], p1.uri);
    assert_eq!(post["cid"], p1.cid);
    for k in ["likeCount", "replyCount", "repostCount", "quoteCount"] {
        assert_eq!(post[k], 0, "{k}");
    }
    assert_eq!(post["author"], json!({"did": a.did, "handle": a.handle, "displayName": "New Name"}));
    assert_eq!(post["record"]["text"], "fresh");
    assert_eq!(post["record"]["$type"], "app.bsky.feed.post");
    let at = post["indexedAt"].as_str().unwrap();
    assert!(chrono::DateTime::parse_from_rfc3339(at).is_ok() && at.ends_with('Z') && at.len() == 24, "{at}");
    assert!(post.get("embed").is_none());
    assert_eq!(feed[1]["post"]["uri"], p0.uri);
    assert_eq!(feed[1]["post"]["author"]["displayName"], "New Name");
    assert_eq!(feed[1]["post"]["likeCount"], 3);
    assert_eq!(j["cursor"], "c1", "cursors pass through");

    // getTimeline: the new post spliced in by time; others' posts untouched
    let j = s.xrpc.get("app.bsky.feed.getTimeline", &[("limit", "2")], &a.auth()).await.ok();
    let feed = j["feed"].as_array().unwrap();
    assert_eq!(feed[0]["post"]["uri"], p1.uri);
    assert_eq!(feed[1]["post"], post_view(&bp, author(&b, "b"), "someone else", OLD));
    assert_eq!(j["cursor"], "t1");

    // getActorLikes: profile overlay only (the reference inserts nothing)
    let j = s.xrpc.get("app.bsky.feed.getActorLikes", &[("actor", &a.did)], &a.auth()).await.ok();
    let feed = j["feed"].as_array().unwrap();
    assert_eq!(feed.len(), 2);
    assert_eq!(feed[0]["post"]["author"]["displayName"], "New Name");
    assert_eq!(feed[1]["post"]["author"]["displayName"], "b");

    // someone else's author feed: no insertion
    stub.set(
        "app.bsky.feed.getAuthorFeed",
        json!({"feed": [{"post": post_view(&bp, author(&b, "b"), "someone else", OLD)}]}),
    );
    let j = s.xrpc.get("app.bsky.feed.getAuthorFeed", &[("actor", &b.did)], &a.auth()).await.ok();
    assert_eq!(j["feed"].as_array().unwrap().len(), 1);

    // the log forgot the repo (eviction, restart): read from the store
    vlpds::recent_writes::invalidate(&a.did);
    let j = s.xrpc.get("app.bsky.feed.getTimeline", &[], &a.auth()).await.ok();
    assert_eq!(j["feed"][0]["post"]["uri"], p1.uri);
    // and once the AppView catches up, nothing is merged
    stub.set_rev(&rev(&s, &a.did).await);
    let r = s.xrpc.get("app.bsky.feed.getTimeline", &[], &a.auth()).await;
    assert_eq!(r.ok()["feed"].as_array().unwrap().len(), 1);
    assert_eq!(lag(&r), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn threads_get_new_replies() {
    let (stub, s) = setup().await;
    let a = s.create_account("rawthread").await;
    let b = s.create_account("rawthreadb").await;
    let root = s.post(&a, "root").await;
    stub.set_rev(&rev(&s, &a.did).await);
    let root_thread = json!({"thread": {"$type": "app.bsky.feed.defs#threadViewPost", "post": post_view(&root, author(&a, "a"), "root", OLD), "replies": []}});
    stub.set("app.bsky.feed.getPostThread", root_thread.clone());

    let blob = upload_png(&s, &a).await;
    let cid = blob["ref"]["$link"].as_str().unwrap().to_string();
    let reply = |parent: &RecordRef, text: &str, embed: J| {
        let mut r = json!({"$type": "app.bsky.feed.post", "text": text, "createdAt": now_iso(),
            "reply": {"root": strong(&root), "parent": strong(parent)}});
        if !embed.is_null() {
            r["embed"] = embed;
        }
        r
    };
    let r1 = s
        .create_record(
            &a,
            "app.bsky.feed.post",
            reply(
                &root,
                "images",
                json!({"$type": "app.bsky.embed.images",
            "images": [{"image": blob, "alt": "alt text", "aspectRatio": {"height": 2, "width": 1}}]}),
            ),
        )
        .await;
    let r2 = s
        .create_record(&a, "app.bsky.feed.post", reply(&r1, "external", json!({"$type": "app.bsky.embed.external",
            "external": {"uri": "https://example.com", "title": "TestImage", "description": "testLink", "thumb": blob}})))
        .await;

    let r = s.xrpc.get("app.bsky.feed.getPostThread", &[("uri", &root.uri)], &a.auth()).await;
    let j = r.ok();
    let replies = j["thread"]["replies"].as_array().unwrap();
    assert_eq!(replies.len(), 1, "{j}");
    assert_eq!(replies[0]["$type"], "app.bsky.feed.defs#threadViewPost");
    assert_eq!(replies[0]["post"]["uri"], r1.uri);
    let embed = &replies[0]["post"]["embed"];
    assert_eq!(embed["$type"], "app.bsky.embed.images#view");
    assert_eq!(embed["images"][0]["fullsize"], cdn("feed_fullsize", &a.did, &cid));
    assert_eq!(embed["images"][0]["thumb"], cdn("feed_thumbnail", &a.did, &cid));
    assert_eq!(embed["images"][0]["aspectRatio"], json!({"height": 2, "width": 1}));
    assert_eq!(embed["images"][0]["alt"], "alt text");
    let nested = &replies[0]["replies"][0];
    assert_eq!(nested["post"]["uri"], r2.uri);
    let ext = &nested["post"]["embed"];
    assert_eq!(ext["$type"], "app.bsky.embed.external#view");
    assert_eq!(
        ext["external"],
        json!({"uri": "https://example.com", "title": "TestImage", "description": "testLink",
        "thumb": cdn("feed_thumbnail", &a.did, &cid)})
    );

    // a handle-form URI gets the same thread
    let by_handle = root.uri.replace(&a.did, &a.handle);
    let j2 = s.xrpc.get("app.bsky.feed.getPostThread", &[("uri", &by_handle)], &a.auth()).await.ok();
    assert_eq!(j2["thread"], j["thread"]);

    // a reply the AppView hasn't indexed: built locally, parents from the AppView
    stub.set_status(
        &format!("app.bsky.feed.getPostThread {}", r1.uri),
        400,
        json!({"error": "NotFound", "message": "Post not found"}),
    );
    let j = s.xrpc.get("app.bsky.feed.getPostThread", &[("uri", &r1.uri), ("parentHeight", "5")], &a.auth()).await.ok();
    assert_eq!(j["thread"]["post"]["uri"], r1.uri);
    assert_eq!(j["thread"]["parent"]["post"]["uri"], root.uri);
    assert_eq!(j["thread"]["replies"][0]["post"]["uri"], r2.uri);
    let parents = stub.last("app.bsky.feed.getPostThread");
    let q = qmap(&parents.query);
    assert_eq!(q["uri"], root.uri);
    assert_eq!(q["depth"], "0");
    assert_eq!(q["parentHeight"], "5");
    assert_eq!(claims(&parents.authorization)["lxm"], "app.bsky.feed.getPostThread");
    let r1_handle = r1.uri.replace(&a.did, &a.handle);
    stub.set_status(
        &format!("app.bsky.feed.getPostThread {r1_handle}"),
        400,
        json!({"error": "NotFound", "message": "Post not found"}),
    );
    let j2 = s.xrpc.get("app.bsky.feed.getPostThread", &[("uri", &r1_handle)], &a.auth()).await.ok();
    assert_eq!(j2["thread"]["post"]["uri"], r1.uri);

    // someone else's unindexed post: the AppView's NotFound
    stub.set_status(
        &format!("app.bsky.feed.getPostThread {}", r1.uri),
        400,
        json!({"error": "NotFound", "message": "Post not found"}),
    );
    let r = s.xrpc.get("app.bsky.feed.getPostThread", &[("uri", &r1.uri)], &b.auth()).await;
    r.err(400, "NotFound");

    // a record embed: viewed through the AppView's getPosts
    stub.set("app.bsky.feed.getPosts", json!({"posts": [post_view(&root, author(&a, "a"), "root", OLD)]}));
    let q = s
        .create_record(
            &a,
            "app.bsky.feed.post",
            reply(&root, "quote", json!({"$type": "app.bsky.embed.record", "record": strong(&root)})),
        )
        .await;
    let j = s.xrpc.get("app.bsky.feed.getPostThread", &[("uri", &root.uri)], &a.auth()).await.ok();
    let quote = j["thread"]["replies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["post"]["uri"] == q.uri)
        .expect("quote reply")
        .clone();
    let rec = &quote["post"]["embed"];
    assert_eq!(rec["$type"], "app.bsky.embed.record#view");
    assert_eq!(rec["record"]["$type"], "app.bsky.embed.record#viewRecord");
    assert_eq!(rec["record"]["uri"], root.uri);
    assert_eq!(rec["record"]["value"]["text"], "root");
    let gp = stub.last("app.bsky.feed.getPosts");
    let c = claims(&gp.authorization);
    assert_eq!(
        (c["lxm"].as_str(), c["aud"].as_str(), c["iss"].as_str()),
        (Some("app.bsky.feed.getPosts"), Some(APPVIEW_DID), Some(a.did.as_str()))
    );
}

/// No records since the AppView's rev: the response streams through as the
/// AppView sent it (not valid gzip on purpose: the PDS must not look inside).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_local_records_passes_through() {
    let (stub, s) = setup().await;
    let a = s.create_account("rawpass").await;
    s.post(&a, "indexed").await;
    stub.set_rev(&rev(&s, &a.did).await);
    let payload: Vec<u8> = (0..5000u32).map(|i| (i * 7 + 3) as u8).collect();
    *stub.raw_gzip.lock() = Some(payload.clone());
    let get = |nsid: &'static str| {
        let (url, tok) = (s.url.clone(), a.access.clone());
        async move {
            reqwest::Client::new()
                .get(format!("{url}/xrpc/{nsid}?actor=x&uri=at://x/y/z"))
                .header("authorization", format!("Bearer {tok}"))
                .header("accept-encoding", "gzip")
                .send()
                .await
                .unwrap()
        }
    };
    for nsid in [
        "app.bsky.feed.getTimeline",
        "app.bsky.actor.getProfile",
        "app.bsky.feed.getPostThread",
        "app.bsky.feed.getAuthorFeed",
    ] {
        let r = get(nsid).await;
        assert_eq!(r.status(), 200, "{nsid}");
        assert_eq!(r.headers().get("content-encoding").unwrap(), "gzip");
        assert_eq!(r.headers().get("content-length").unwrap(), "5000");
        assert!(r.headers().get("atproto-upstream-lag").is_none());
        assert_eq!(r.headers().get("atproto-repo-rev").unwrap().to_str().unwrap(), &*stub.rev.lock());
        assert_eq!(r.bytes().await.unwrap().as_ref(), payload.as_slice(), "{nsid}");
    }
    // local records but no rev header: also untouched
    s.post(&a, "new").await;
    stub.set_rev("");
    let r = get("app.bsky.feed.getTimeline").await;
    assert_eq!(r.bytes().await.unwrap().as_ref(), payload.as_slice());
}

/// The AppView's gzip response is decoded to merge into; Accept-Encoding
/// asks only for codings the PDS can decode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compressed_upstream_is_munged() {
    let (stub, s) = setup().await;
    let a = s.create_account("rawgzip").await;
    s.post(&a, "indexed").await;
    stub.set_rev(&rev(&s, &a.did).await);
    stub.gzip.store(true, Ordering::Relaxed);
    let pad = "x".repeat(4000);
    stub.set("app.bsky.feed.getTimeline", json!({"feed": [], "cursor": pad}));
    let p = s.post(&a, "fresh").await;
    let r = reqwest::Client::new()
        .get(format!("{}/xrpc/app.bsky.feed.getTimeline", s.url))
        .header("authorization", format!("Bearer {}", a.access))
        .header("accept-encoding", "gzip, compress")
        .send()
        .await
        .unwrap();
    assert_eq!(stub.last("app.bsky.feed.getTimeline").accept_encoding, "gzip");
    assert!(r.headers().get("atproto-upstream-lag").is_some());
    let gz = r.headers().get("content-encoding").map(|v| v.to_str().unwrap().to_string());
    let body = r.bytes().await.unwrap();
    let body = match gz.as_deref() {
        Some("gzip") => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(&body[..]).read_to_end(&mut out).unwrap();
            out
        }
        None => body.to_vec(),
        Some(other) => panic!("{other}"),
    };
    let j: J = serde_json::from_slice(&body).unwrap();
    assert_eq!(j["feed"][0]["post"]["uri"], p.uri);
    assert_eq!(j["cursor"], pad);
    // methods without read-after-write forward the client's Accept-Encoding as is
    s.xrpc
        .send(
            s.xrpc
                .http
                .get(format!("{}/xrpc/app.bsky.feed.getLikes?uri=x", s.url))
                .header("authorization", format!("Bearer {}", a.access))
                .header("accept-encoding", "gzip, compress"),
        )
        .await;
    assert_eq!(stub.last("app.bsky.feed.getLikes").accept_encoding, "gzip, compress");
}

/// Brotli is decodable (the reference's set is gzip, deflate, br): a
/// client's `br` reaches the AppView as is and its brotli body is merged into.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brotli_upstream_is_munged() {
    let (stub, s) = setup().await;
    let a = s.create_account("rawbrotli").await;
    s.post(&a, "indexed").await;
    stub.set_rev(&rev(&s, &a.did).await);
    stub.br.store(true, Ordering::Relaxed);
    let pad = "y".repeat(4000);
    stub.set("app.bsky.feed.getTimeline", json!({"feed": [], "cursor": pad}));
    let p = s.post(&a, "fresh").await;
    let r = reqwest::Client::new()
        .get(format!("{}/xrpc/app.bsky.feed.getTimeline", s.url))
        .header("authorization", format!("Bearer {}", a.access))
        .header("accept-encoding", "br")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(stub.last("app.bsky.feed.getTimeline").accept_encoding, "br");
    assert!(r.headers().get("atproto-upstream-lag").is_some());
    let enc = r.headers().get("content-encoding").map(|v| v.to_str().unwrap().to_string());
    let body = r.bytes().await.unwrap();
    // the munged body is re-encoded by the PDS's own compression layer (or not)
    let body = match enc.as_deref() {
        Some("br") => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut &body[..], &mut out).unwrap();
            out
        }
        None => body.to_vec(),
        Some(other) => panic!("{other}"),
    };
    let j: J = serde_json::from_slice(&body).unwrap();
    assert_eq!(j["feed"][0]["post"]["uri"], p.uri);
    assert_eq!(j["cursor"], pad);
}

/// An AppView lagging more than the log keeps (32 records) behind a repo:
/// the store read keeps only the oldest records above its rev (the
/// reference's oldest 10), and that answer is kept until the repo changes,
/// so polls with the same rev don't scan the repo again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lagging_appview_is_answered_from_one_bounded_scan() {
    use vlpds::recent_writes::{lookup, Since};
    let (stub, s) = setup().await;
    let a = s.create_account("rawlag").await;
    s.post(&a, "indexed").await;
    stub.set_rev(&rev(&s, &a.did).await);
    stub.set("app.bsky.feed.getTimeline", json!({"feed": []}));
    let mut posts = Vec::new();
    for i in 0..40 {
        posts.push(s.post(&a, &format!("lagging {i}")).await.uri);
    }
    let since = vlsync_atproto::tid::Tid::parse(&stub.rev.lock()).unwrap().0;
    let p = s.app.partition(&a.did).ok().unwrap();
    let part = (p.id, p.epoch);
    vlpds::recent_writes::invalidate(&a.did);
    assert!(matches!(lookup(&a.did, part, since), Since::Unknown));
    let oldest: std::collections::HashSet<String> = posts[..10].iter().cloned().collect();
    for _ in 0..2 {
        let j = s.xrpc.get("app.bsky.feed.getTimeline", &[], &a.auth()).await.ok();
        let got: std::collections::HashSet<String> =
            j["feed"].as_array().unwrap().iter().map(|i| i["post"]["uri"].as_str().unwrap().to_string()).collect();
        assert_eq!(got, oldest, "the oldest 10 records above the AppView's rev");
        // kept: the next poll needs no store read
        match lookup(&a.did, part, since) {
            Since::Records(r) => assert_eq!(r.len(), 10),
            other => panic!("not kept: {other:?}"),
        }
    }
    // a new commit drops it
    s.post(&a, "one more").await;
    assert!(matches!(lookup(&a.did, part, since), Since::Unknown));
}

/// A repo with no records at or below the AppView's rev (a new account's
/// first posts) gets nothing merged: the reference's sanity check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rev_older_than_every_record_is_ignored() {
    let (stub, s) = setup().await;
    let a = s.create_account("rawnew").await;
    stub.set_rev(&rev(&s, &a.did).await);
    stub.set("app.bsky.feed.getTimeline", json!({"feed": []}));
    s.post(&a, "first").await;
    let r = s.xrpc.get("app.bsky.feed.getTimeline", &[], &a.auth()).await;
    assert_eq!(r.ok()["feed"], json!([]));
    assert_eq!(lag(&r), None);
    vlpds::recent_writes::invalidate(&a.did);
    assert_eq!(s.xrpc.get("app.bsky.feed.getTimeline", &[], &a.auth()).await.ok()["feed"], json!([]));
}

/// getFeed's token is for the feed generator (reference getFeed.ts): aud =
/// the generator's DID from its record, lxm = getFeedSkeleton.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_feed_service_auth_names_the_generator() {
    let (stub, s) = setup().await;
    let a = s.create_account("rawgetfeed").await;
    stub.set(
        "com.atproto.repo.getRecord",
        json!({"uri": "at://did:plc:fg/app.bsky.feed.generator/hot", "value": {"did": "did:web:feedgen.test"}}),
    );
    stub.set("app.bsky.feed.getFeed", json!({"feed": []}));
    let feed = "at://did:plc:fg/app.bsky.feed.generator/hot";
    let r = s.xrpc.get("app.bsky.feed.getFeed", &[("feed", feed)], &a.auth()).await;
    assert_eq!(r.ok(), json!({"feed": []}));
    let gr = stub.last("com.atproto.repo.getRecord");
    assert!(gr.authorization.is_empty(), "getRecord is unauthenticated");
    let q = qmap(&gr.query);
    assert_eq!(
        (q["repo"].as_str(), q["collection"].as_str(), q["rkey"].as_str()),
        ("did:plc:fg", "app.bsky.feed.generator", "hot")
    );
    let c = claims(&stub.last("app.bsky.feed.getFeed").authorization);
    assert_eq!(c["aud"], "did:web:feedgen.test");
    assert_eq!(c["lxm"], "app.bsky.feed.getFeedSkeleton");
    assert_eq!(c["iss"], a.did);
    // an unknown generator
    stub.set("com.atproto.repo.getRecord", json!({"value": {}}));
    let r = s
        .xrpc
        .get("app.bsky.feed.getFeed", &[("feed", "at://did:plc:fg/app.bsky.feed.generator/other")], &a.auth())
        .await;
    r.err(400, "UnknownFeed");
}
