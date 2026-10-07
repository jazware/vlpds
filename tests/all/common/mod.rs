//! Shared harness for the vlpds conformance suite.
//!
//! - `TestServer::spawn()` boots an in-process PDS (in-memory object store,
//!   dev mode) on 127.0.0.1:0, with an mTLS peer listener (`peer_url`) and
//!   a node certificate from the suite's CA ([`test_ca`]): in-process nodes
//!   sharing a store form a cluster over peer mTLS, as processes do. A
//!   cluster test advertises [`peer_url`] (`ClusterConfig::addr`) and calls
//!   `/internal/*` with [`peer_client`]. `TestServer::spawn_lone` has no
//!   peer listener (a lone node).
//! - `Xrpc` is a small typed client: `get`/`post` return a `Resp` with status,
//!   decoded JSON and helpers to assert success or a specific XRPC error.
//! - `TestAccount` + `TestServer::create_account` for account fixtures.
//! - `Sub` is a firehose subscriber that decodes frames into `Frame`s.
//! - Repo helpers: CAR parsing, commit signature checks, MST loading and
//!   sync 1.1 commit inversion.
#![allow(dead_code)]

pub use serde_json::{json, Value as J};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
pub use vlpds::cbor::Value;
pub use vlpds::cid::Cid;
use vlpds::mst::Tree;

mod cluster;
#[allow(unused_imports)]
pub use cluster::*;
suite_only! {
    pub mod spaces;
}
pub mod webauthn;

pub const ADMIN_TOKEN: &str = "dev-admin-token";
pub const HANDLE_DOMAIN: &str = "vlpds.test";
pub const PASSWORD: &str = "hunter2-password";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Held by tests that set or depend on the process-wide active feature
/// level (`vlpds::version::active`, what writers emit).
pub static ACTIVE_LEVEL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Unique, valid handle label (lowercase alnum), e.g. "alice3k9x".
/// A unique name that still fits one 18-character handle label: the
/// counter and random suffix are base-36, and a long prefix is cut so the
/// whole name never exceeds 18 characters however many names a run makes.
pub fn unique_name(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let r: u32 = rand::random::<u32>() % 46656;
    let suffix = format!("{}x{}", radix36(n), radix36(r as u64));
    let keep = 18usize.saturating_sub(suffix.len()).min(prefix.len());
    format!("{}{suffix}", &prefix[..keep])
}

fn radix36(mut n: u64) -> String {
    const A: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut s = Vec::new();
    loop {
        s.push(A[(n % 36) as usize]);
        n /= 36;
        if n == 0 {
            break;
        }
    }
    s.reverse();
    String::from_utf8(s).unwrap()
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("VLPDS_TEST_LOG").unwrap_or_else(|_| "off".into()))
        .with_test_writer()
        .try_init();
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

pub struct TestServer {
    pub app: Arc<vlpds::xrpc::App>,
    pub addr: SocketAddr,
    pub url: String,
    /// The mTLS peer listener (`https://`; empty on a lone node).
    pub peer_url: String,
    pub xrpc: Xrpc,
}

/// The suite's cluster CA (one per test binary): every [`TestServer`]'s
/// node certificate comes from it.
pub fn test_ca() -> &'static vlpds::peer_tls::Issued {
    static CA: std::sync::LazyLock<vlpds::peer_tls::Issued> =
        std::sync::LazyLock::new(|| vlpds::peer_tls::create_ca("vlpds test cluster CA", 30).unwrap());
    &CA
}

/// Peer TLS material for node `id`, from [`test_ca`].
pub fn node_tls(id: &str) -> Arc<vlpds::peer_tls::PeerTls> {
    let ca = test_ca();
    let n = vlpds::peer_tls::issue_node(&ca.cert_pem, &ca.key_pem, id, &["127.0.0.1".into(), "localhost".into()], 30)
        .unwrap();
    vlpds::peer_tls::PeerTls::from_pem(&ca.cert_pem, &n.cert_pem, &n.key_pem).unwrap()
}

/// A peer client of the test cluster (mTLS as node "test-peer", any node
/// accepted): `/internal/*` calls at `TestServer::peer_url`.
pub fn peer_client() -> &'static vlpds::http::PeerClient {
    static C: std::sync::LazyLock<vlpds::http::PeerClient> =
        std::sync::LazyLock::new(|| vlpds::http::PeerClient::new(1, node_tls("test-peer")));
    &C
}

/// Config of a PDS (`did:web:pds.test`) registering DIDs with the PLC
/// directory at `plc_url` under `rotation`.
pub fn use_plc(c: &mut vlpds::server::Config, plc_url: String, rotation: Arc<vlpds::crypto::Keypair>) {
    c.plc_url = plc_url;
    c.service_did = "did:web:pds.test".into();
    c.plc = vlpds::plc::PlcConfig { rotation_key: Some(vlpds::plc::RotationKey::Key(rotation)), ..Default::default() };
}

/// In a `TestServer::spawn_with` closure: this node's peer listener URL,
/// what a cluster test advertises (`ClusterConfig::addr`).
pub fn peer_url(c: &vlpds::server::Config) -> String {
    c.cluster.as_ref().expect("the harness presets cluster.addr").addr.clone()
}

impl TestServer {
    pub async fn spawn() -> TestServer {
        Self::spawn_with(|_| {}).await
    }

    /// A node with an mTLS peer listener; its node certificate names
    /// `cluster.node_id` as `f` leaves it ("single" by default).
    pub async fn spawn_with(f: impl FnOnce(&mut vlpds::server::Config)) -> TestServer {
        let peer = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let peer_url = format!("https://{}", peer.local_addr().unwrap());
        Self::spawn_inner(Some((peer, peer_url)), f).await
    }

    /// A PDS (`did:web:pds.test`) registering DIDs with the PLC directory at
    /// `plc_url` under `rotation`.
    pub async fn spawn_plc(plc_url: &str, rotation: Arc<vlpds::crypto::Keypair>) -> TestServer {
        let plc_url = plc_url.to_string();
        Self::spawn_with(move |c| use_plc(c, plc_url, rotation)).await
    }

    /// A lone node: no peer listener, no peer TLS, no `/internal/*`.
    pub async fn spawn_lone(f: impl FnOnce(&mut vlpds::server::Config)) -> TestServer {
        Self::spawn_inner(None, f).await
    }

    async fn spawn_inner(
        peer: Option<(tokio::net::TcpListener, String)>,
        f: impl FnOnce(&mut vlpds::server::Config),
    ) -> TestServer {
        init_tracing();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let peer_url = peer.as_ref().map(|(_, u)| u.clone()).unwrap_or_default();
        let mut cfg = vlpds::server::Config {
            dev_mode: true,
            public_url: url.clone(),
            // Off by default, as in the reference's dev-env test network: the
            // suite drives thousands of writes from one IP and DID.
            rate_limits_enabled: false,
            cluster: peer.is_some().then(|| vlpds::cluster::ClusterConfig {
                node_id: "single".into(),
                addr: peer_url.clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        f(&mut cfg);
        if peer.is_some() && cfg.peer_tls.is_none() {
            let id = cfg.cluster.as_ref().map_or("single".to_string(), |c| c.node_id.clone());
            cfg.peer_tls = Some(node_tls(&id));
        }
        let (app, addr) = vlpds::server::spawn(cfg, listener, peer.map(|(l, _)| l)).await.expect("spawn server");
        TestServer { app, addr, url: url.clone(), peer_url, xrpc: Xrpc::new(&url) }
    }

    pub fn ws_url(&self, cursor: Option<i64>) -> String {
        match cursor {
            Some(c) => format!("ws://{}/xrpc/com.atproto.sync.subscribeRepos?cursor={c}", self.addr),
            None => format!("ws://{}/xrpc/com.atproto.sync.subscribeRepos", self.addr),
        }
    }

    /// Creates an account with a unique handle `{prefix}N.vlpds.test` and an
    /// email `{handle}@example.com`; panics unless it succeeds.
    pub async fn create_account(&self, prefix: &str) -> TestAccount {
        let handle = format!("{}.{HANDLE_DOMAIN}", unique_name(prefix));
        self.create_account_with(&handle, PASSWORD).await
    }

    /// Retries while password hashing sheds load (503: the Argon2 permits
    /// are process-wide, shared with every test running at the time).
    pub async fn create_account_with(&self, handle: &str, password: &str) -> TestAccount {
        let email = format!("{}@example.com", handle.replace('.', "-"));
        let body = json!({"handle": handle, "password": password, "email": email});
        let t = std::time::Instant::now();
        let r = loop {
            let r = self.xrpc.post("com.atproto.server.createAccount", &body, &Auth::None).await;
            if r.status != 503 || t.elapsed() > Duration::from_secs(60) {
                break r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let j = r.ok();
        TestAccount {
            did: j["did"].as_str().unwrap_or_else(|| panic!("createAccount failed: {j}")).to_string(),
            handle: j["handle"].as_str().unwrap_or(handle).to_string(),
            password: password.to_string(),
            email,
            access: j["accessJwt"].as_str().expect("accessJwt").to_string(),
            refresh: j["refreshJwt"].as_str().unwrap_or_default().to_string(),
        }
    }

    pub async fn create_session(&self, identifier: &str, password: &str) -> Resp {
        self.xrpc
            .post(
                "com.atproto.server.createSession",
                &json!({"identifier": identifier, "password": password}),
                &Auth::None,
            )
            .await
    }

    // ---- record helpers ----

    pub async fn create_record(&self, a: &TestAccount, collection: &str, record: J) -> RecordRef {
        let r = self
            .xrpc
            .post(
                "com.atproto.repo.createRecord",
                &json!({"repo": a.did, "collection": collection, "record": record}),
                &a.auth(),
            )
            .await
            .ok();
        RecordRef::from_json(&r)
    }

    pub async fn post(&self, a: &TestAccount, text: &str) -> RecordRef {
        self.create_record(a, "app.bsky.feed.post", post_record(text)).await
    }

    pub async fn get_record(&self, did: &str, collection: &str, rkey: &str) -> Resp {
        self.xrpc
            .get(
                "com.atproto.repo.getRecord",
                &[("repo", did), ("collection", collection), ("rkey", rkey)],
                &Auth::None,
            )
            .await
    }

    pub async fn list_records(&self, did: &str, collection: &str, extra: &[(&str, &str)]) -> Resp {
        let mut q = vec![("repo", did), ("collection", collection)];
        q.extend_from_slice(extra);
        self.xrpc.get("com.atproto.repo.listRecords", &q, &Auth::None).await
    }

    pub async fn latest_commit(&self, did: &str) -> (Cid, String) {
        let j = self.xrpc.get("com.atproto.sync.getLatestCommit", &[("did", did)], &Auth::None).await.ok();
        (Cid::parse(j["cid"].as_str().unwrap()).unwrap(), j["rev"].as_str().unwrap().to_string())
    }

    /// `sync.getRepo`'s CAR, raw.
    pub async fn get_repo_car(&self, did: &str) -> Vec<u8> {
        let r = self.xrpc.get("com.atproto.sync.getRepo", &[("did", did)], &Auth::None).await;
        assert_eq!(r.status, 200, "getRepo failed: {}", r.text());
        r.body.to_vec()
    }

    pub async fn import_repo(&self, auth: &Auth, car: Vec<u8>) -> Resp {
        self.xrpc.post_bytes("com.atproto.repo.importRepo", car, "application/vnd.ipld.car", auth).await
    }

    /// Downloads and parses `sync.getRepo`.
    pub async fn get_repo(&self, did: &str) -> Repo {
        let r = self.xrpc.get("com.atproto.sync.getRepo", &[("did", did)], &Auth::None).await;
        assert_eq!(r.status, 200, "getRepo failed: {}", r.text());
        Repo::from_car(&r.body).expect("parse getRepo CAR")
    }

    /// Signing key from the account's DID document (via describeRepo).
    pub async fn signing_key(&self, did: &str) -> k256::ecdsa::VerifyingKey {
        let j = self.xrpc.get("com.atproto.repo.describeRepo", &[("repo", did)], &Auth::None).await.ok();
        let vms = j["didDoc"]["verificationMethod"].as_array().expect("verificationMethod");
        let vm =
            vms.iter().find(|v| v["id"].as_str().map(|s| s.ends_with("#atproto")).unwrap_or(false)).unwrap_or(&vms[0]);
        decode_k256_multibase(vm["publicKeyMultibase"].as_str().unwrap()).expect("k256 multikey")
    }

    // ---- admin / dev helpers ----

    /// Messages "sent" to `email` in dev mode (vlpds.admin.getDevMail).
    pub async fn dev_mail(&self, email: &str) -> Resp {
        self.xrpc.get("vlpds.admin.getDevMail", &[("email", email)], &Auth::Admin).await
    }

    /// Latest emailed token for `email` (searches the dev-mail JSON for a
    /// "token" field, else for an XXXXX-XXXXX code in any string).
    pub async fn mail_token(&self, email: &str) -> Option<String> {
        let r = self.dev_mail(email).await;
        if r.status != 200 {
            return None;
        }
        find_token(&r.json)
    }

    pub async fn subscribe(&self, cursor: Option<i64>) -> Sub {
        Sub::connect(&self.ws_url(cursor)).await
    }

    /// Subscribes with a cursor at the current head, so only events sequenced
    /// after this call are delivered. (A cursor-less live subscription may
    /// still receive events for writes acked just before it connected: the
    /// broadcast waits for every partition's watermark, which can trail acks.)
    ///
    /// The cursor is a seq, not an event: every event acked before this call
    /// is at or below this node log's durable watermark (or the clock, for
    /// other nodes' logs), and the call returns once the firehose has settled
    /// past it. (The highest seq seen on a replay goes wrong under load: a
    /// slow backfill start reads as idle, and the cursor falls back to 0.)
    pub async fn subscribe_from_now(&self) -> Sub {
        let head = self.settled_now().await;
        self.subscribe(Some(head)).await
    }

    /// A firehose cursor after every event acked before this call, once the
    /// firehose has settled up to it (events at or below it are never sent
    /// to a subscriber with this cursor; everything above it is).
    pub async fn settled_now(&self) -> i64 {
        let clock = vlpds::nodelog::seq_floor(vlpds::tid::now_micros()) - 1;
        let target = self.app.log.wm.get().max(clock);
        let deadline = tokio::time::Instant::now() + FH_TIMEOUT;
        while self.app.firehose.position() < target {
            assert!(tokio::time::Instant::now() < deadline, "firehose never settled past {target}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        target
    }

    /// Waits until every subscription in `subs` is live, without a fixed sleep:
    /// a cursor-less subscription only sees events broadcast after the server
    /// registered it, which can trail the websocket handshake. Writes probe
    /// posts as `a` until each sub has received one, then consumes each stream
    /// up to the last probe's commit. Returns that commit's seq; everything
    /// read afterwards was sequenced after it.
    pub async fn sync_subs(&self, a: &TestAccount, subs: &mut [Sub]) -> i64 {
        let deadline = tokio::time::Instant::now() + FH_TIMEOUT;
        let is_probe = |f: &Frame| f.kind() == "#commit" && f.did() == Some(a.did.as_str());
        let mut seen: Vec<Vec<Frame>> = subs.iter().map(|_| Vec::new()).collect();
        let mut live = vec![false; subs.len()];
        let last_rev = loop {
            assert!(tokio::time::Instant::now() < deadline, "subscriptions never went live");
            let rev = self.post(a, "probe").await.rev.expect("probe rev");
            for (i, sub) in subs.iter_mut().enumerate() {
                if !live[i] {
                    let (fs, ok) = sub.try_until(Duration::from_millis(250), |fs| fs.iter().any(is_probe)).await;
                    seen[i].extend(fs);
                    live[i] = ok;
                }
            }
            if live.iter().all(|l| *l) {
                break rev;
            }
        };
        let is_last = |f: &Frame| is_probe(f) && f.str("rev") == Some(last_rev.as_str());
        let mut seq = 0;
        for (i, sub) in subs.iter_mut().enumerate() {
            if !seen[i].iter().any(is_last) {
                let fs = sub.until(FH_TIMEOUT, |fs| fs.last().map(is_last).unwrap_or(false)).await;
                seen[i].extend(fs);
            }
            let last = seen[i].iter().rev().find(|f| is_last(f)).expect("last probe");
            seq = last.seq().expect("probe seq");
        }
        seq
    }

    /// Highest seq currently on the firehose (replays from 0 and stops when idle).
    pub async fn current_seq(&self) -> i64 {
        let mut sub = self.subscribe(Some(0)).await;
        let frames = sub.drain(Duration::from_millis(400)).await;
        frames.iter().filter_map(|f| f.seq()).max().unwrap_or(0)
    }

    pub async fn put_record(&self, a: &TestAccount, collection: &str, rkey: &str, record: J) -> Resp {
        let body = json!({"repo": a.did, "collection": collection, "rkey": rkey, "record": record});
        self.xrpc.post("com.atproto.repo.putRecord", &body, &a.auth()).await
    }

    pub async fn delete_record(&self, a: &TestAccount, collection: &str, rkey: &str) -> Resp {
        let body = json!({"repo": a.did, "collection": collection, "rkey": rkey});
        self.xrpc.post("com.atproto.repo.deleteRecord", &body, &a.auth()).await
    }

    pub async fn apply_writes(&self, a: &TestAccount, writes: J) -> Resp {
        self.xrpc.post("com.atproto.repo.applyWrites", &json!({"repo": a.did, "writes": writes}), &a.auth()).await
    }

    pub async fn repo_status(&self, did: &str) -> Resp {
        self.xrpc.get("com.atproto.sync.getRepoStatus", &[("did", did)], &Auth::None).await
    }

    /// admin.getAccountInfo.
    pub async fn account_info(&self, did: &str) -> Resp {
        self.xrpc.get("com.atproto.admin.getAccountInfo", &[("did", did)], &Auth::Admin).await
    }

    pub async fn describe_repo(&self, repo: &str) -> Resp {
        self.xrpc.get("com.atproto.repo.describeRepo", &[("repo", repo)], &Auth::None).await
    }

    pub async fn resolve_handle(&self, handle: &str) -> Resp {
        self.xrpc.get("com.atproto.identity.resolveHandle", &[("handle", handle)], &Auth::None).await
    }

    /// setupTotp + confirmTotp as `a`: (the raw secret, the step confirmed).
    pub async fn enable_totp(&self, a: &TestAccount) -> (Vec<u8>, u64) {
        let j = self.xrpc.post_empty("vlpds.server.setupTotp", &a.auth()).await.ok();
        let secret = vlpds::totp::base32_decode(j["secret"].as_str().unwrap()).unwrap();
        let step = vlpds::totp::step_at(vlpds::totp::now_secs());
        let body = json!({"code": vlpds::totp::code_for_step(&secret, step)});
        self.xrpc.post("vlpds.server.confirmTotp", &body, &a.auth()).await.ok();
        (secret, step)
    }

    /// uploadBlob as `a`; returns the blob ref.
    pub async fn upload_blob(&self, a: &TestAccount, bytes: &[u8], mime: &str) -> J {
        self.xrpc.post_bytes("com.atproto.repo.uploadBlob", bytes.to_vec(), mime, &a.auth()).await.ok()["blob"].clone()
    }

    pub async fn get_blob(&self, did: &str, cid: &str) -> Resp {
        self.xrpc.get("com.atproto.sync.getBlob", &[("did", did), ("cid", cid)], &Auth::None).await
    }

    pub async fn list_blobs(&self, did: &str) -> Vec<String> {
        let j = self.xrpc.get("com.atproto.sync.listBlobs", &[("did", did)], &Auth::None).await.ok();
        j["cids"].as_array().expect("cids").iter().map(|c| c.as_str().unwrap().to_string()).collect()
    }

    pub async fn get_blocks(&self, did: &str, cids: &[Cid]) -> Resp {
        let mut q = vec![("did", did.to_string())];
        q.extend(cids.iter().map(|c| ("cids", c.to_string())));
        self.xrpc.get_multi("com.atproto.sync.getBlocks", &q, &Auth::None).await
    }

    pub async fn get_session(&self, auth: &Auth) -> Resp {
        self.xrpc.get("com.atproto.server.getSession", &[], auth).await
    }

    /// createSession with an optional `authFactorToken`.
    pub async fn login(&self, identifier: &str, password: &str, code: Option<&str>) -> Resp {
        let mut body = json!({"identifier": identifier, "password": password});
        if let Some(c) = code {
            body["authFactorToken"] = json!(c);
        }
        self.xrpc.post("com.atproto.server.createSession", &body, &Auth::None).await
    }

    /// The server's own DID (describeServer).
    pub async fn pds_did(&self) -> String {
        self.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok()["did"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

pub fn post_record(text: &str) -> J {
    json!({"$type": "app.bsky.feed.post", "text": text, "createdAt": now_iso()})
}

/// A post embedding `blob` as an image.
pub fn image_post(text: &str, blob: &J) -> J {
    json!({"$type": "app.bsky.feed.post", "text": text, "createdAt": now_iso(),
           "embed": {"$type": "app.bsky.embed.images", "images": [{"image": blob, "alt": ""}]}})
}

pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn find_token(j: &J) -> Option<String> {
    fn by_key(j: &J) -> Option<String> {
        match j {
            J::Object(o) => {
                for k in ["token", "code"] {
                    if let Some(J::String(s)) = o.get(k) {
                        return Some(s.clone());
                    }
                }
                o.values().rev().find_map(by_key)
            }
            J::Array(a) => a.iter().rev().find_map(by_key),
            _ => None,
        }
    }
    fn by_pattern(j: &J) -> Option<String> {
        match j {
            J::String(s) => {
                let b = s.as_bytes();
                (0..b.len().saturating_sub(10)).rev().find_map(|i| {
                    let w = &b[i..i + 11];
                    let ok = w[5] == b'-'
                        && w[..5]
                            .iter()
                            .chain(&w[6..])
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c.is_ascii_lowercase());
                    ok.then(|| String::from_utf8_lossy(w).to_string())
                })
            }
            J::Object(o) => o.values().rev().find_map(by_pattern),
            J::Array(a) => a.iter().rev().find_map(by_pattern),
            _ => None,
        }
    }
    by_key(j).or_else(|| by_pattern(j))
}

// ---------------------------------------------------------------------------
// accounts / records
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TestAccount {
    pub did: String,
    pub handle: String,
    pub password: String,
    pub email: String,
    pub access: String,
    pub refresh: String,
}

impl TestAccount {
    pub fn auth(&self) -> Auth {
        Auth::Bearer(self.access.clone())
    }
    pub fn refresh_auth(&self) -> Auth {
        Auth::Bearer(self.refresh.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordRef {
    pub uri: String,
    pub cid: String,
    pub commit_cid: Option<String>,
    pub rev: Option<String>,
}

impl RecordRef {
    pub fn from_json(j: &J) -> RecordRef {
        RecordRef {
            uri: j["uri"].as_str().expect("uri").to_string(),
            cid: j["cid"].as_str().expect("cid").to_string(),
            commit_cid: j["commit"]["cid"].as_str().map(String::from),
            rev: j["commit"]["rev"].as_str().map(String::from),
        }
    }
    pub fn rkey(&self) -> &str {
        self.uri.rsplit('/').next().unwrap()
    }
    pub fn collection(&self) -> &str {
        let mut it = self.uri.rsplit('/');
        it.next();
        it.next().unwrap()
    }
    pub fn did(&self) -> &str {
        self.uri.trim_start_matches("at://").split('/').next().unwrap()
    }
}

// ---------------------------------------------------------------------------
// XRPC client
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Auth {
    None,
    Bearer(String),
    Admin,
    Basic(String, String),
    Raw(String),
}

#[derive(Clone)]
pub struct Xrpc {
    pub http: reqwest::Client,
    pub base: String,
}

pub struct Resp {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: bytes::Bytes,
    /// Parsed JSON body (Null if not JSON).
    pub json: J,
}

impl std::fmt::Debug for Resp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.status, self.text())
    }
}

impl Resp {
    pub fn text(&self) -> String {
        let s = String::from_utf8_lossy(&self.body);
        if s.len() > 2000 {
            let mut end = 2000;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…", &s[..end])
        } else {
            s.to_string()
        }
    }

    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Asserts 2xx and returns the JSON body.
    #[track_caller]
    pub fn ok(&self) -> J {
        assert!(self.is_ok(), "expected success, got {} {}", self.status, self.text());
        self.json.clone()
    }

    pub fn error_name(&self) -> Option<&str> {
        self.json.get("error").and_then(|e| e.as_str())
    }

    /// Asserts an XRPC error with this HTTP status and error name.
    #[track_caller]
    pub fn err(&self, status: u16, name: &str) {
        assert_eq!((self.status, self.error_name()), (status, Some(name)), "unexpected response: {}", self.text());
    }

    /// Asserts an XRPC error with this status (any error name).
    #[track_caller]
    pub fn err_status(&self, status: u16) {
        assert_eq!(self.status, status, "unexpected response: {}", self.text());
    }

    /// Asserts a 4xx failure (any).
    #[track_caller]
    pub fn client_err(&self) {
        assert!((400..500).contains(&self.status), "expected 4xx, got {} {}", self.status, self.text());
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(String::from)
    }
}

impl Xrpc {
    pub fn new(base: &str) -> Xrpc {
        Xrpc {
            http: reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap(),
            base: base.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{nsid}", self.base)
    }

    fn apply(rb: reqwest::RequestBuilder, auth: &Auth) -> reqwest::RequestBuilder {
        use base64::Engine;
        match auth {
            Auth::None => rb,
            Auth::Bearer(t) => rb.header("authorization", format!("Bearer {t}")),
            Auth::Admin => rb.header(
                "authorization",
                format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("admin:{ADMIN_TOKEN}"))),
            ),
            Auth::Basic(u, p) => rb.header(
                "authorization",
                format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))),
            ),
            Auth::Raw(h) => rb.header("authorization", h.clone()),
        }
    }

    pub async fn send(&self, rb: reqwest::RequestBuilder) -> Resp {
        self.try_send(rb).await.expect("http request")
    }

    /// Like `send`, but a transport error (e.g. the server answered and closed
    /// before the request body was fully written) comes back as `Err`.
    pub async fn try_send(&self, rb: reqwest::RequestBuilder) -> reqwest::Result<Resp> {
        let r = rb.send().await?;
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let body = r.bytes().await.unwrap_or_default();
        let json = serde_json::from_slice(&body).unwrap_or(J::Null);
        Ok(Resp { status, headers, body, json })
    }

    pub async fn get(&self, nsid: &str, query: &[(&str, &str)], auth: &Auth) -> Resp {
        let rb = self.http.get(self.url(nsid)).query(query);
        self.send(Self::apply(rb, auth)).await
    }

    /// GET with repeated params (e.g. cids=a&cids=b).
    pub async fn get_multi(&self, nsid: &str, query: &[(&str, String)], auth: &Auth) -> Resp {
        let rb = self.http.get(self.url(nsid)).query(query);
        self.send(Self::apply(rb, auth)).await
    }

    pub async fn post(&self, nsid: &str, body: &J, auth: &Auth) -> Resp {
        let rb = self.http.post(self.url(nsid)).json(body);
        self.send(Self::apply(rb, auth)).await
    }

    /// `post` owning its arguments, so a closure can build a request and
    /// return its future.
    pub fn post_owned(&self, nsid: &str, body: J, auth: Auth) -> impl std::future::Future<Output = Resp> + 'static {
        let (x, nsid) = (self.clone(), nsid.to_string());
        async move { x.post(&nsid, &body, &auth).await }
    }

    /// POST with no body (procedures without input).
    pub async fn post_empty(&self, nsid: &str, auth: &Auth) -> Resp {
        let rb = self.http.post(self.url(nsid));
        self.send(Self::apply(rb, auth)).await
    }

    pub async fn post_bytes(&self, nsid: &str, body: Vec<u8>, content_type: &str, auth: &Auth) -> Resp {
        let rb = self.http.post(self.url(nsid)).header("content-type", content_type).body(body);
        self.send(Self::apply(rb, auth)).await
    }

    /// `post_bytes` that tolerates the server closing early (see `try_send`).
    pub async fn try_post_bytes(
        &self,
        nsid: &str,
        body: Vec<u8>,
        content_type: &str,
        auth: &Auth,
    ) -> reqwest::Result<Resp> {
        let rb = self.http.post(self.url(nsid)).header("content-type", content_type).body(body);
        self.try_send(Self::apply(rb, auth)).await
    }
}

// ---------------------------------------------------------------------------
// firehose
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Frame {
    /// 1 = message, -1 = error
    pub op: i64,
    /// "#commit", "#sync", "#identity", "#account", "#info", ...
    pub t: Option<String>,
    pub body: Value,
    pub raw: Vec<u8>,
}

impl Frame {
    pub fn decode(raw: &[u8]) -> anyhow::Result<Frame> {
        let (header, n) = Value::decode_prefix(raw)?;
        let body = Value::decode(&raw[n..])?;
        let op = match header.get("op") {
            Some(Value::Int(i)) => *i,
            _ => anyhow::bail!("frame header without op"),
        };
        let t = header.get("t").and_then(|v| v.as_str()).map(String::from);
        Ok(Frame { op, t, body, raw: raw.to_vec() })
    }

    pub fn kind(&self) -> &str {
        self.t.as_deref().unwrap_or("")
    }

    pub fn seq(&self) -> Option<i64> {
        match self.body.get("seq") {
            Some(Value::Int(i)) => Some(*i),
            _ => None,
        }
    }

    /// `repo` for #commit, `did` for everything else.
    pub fn did(&self) -> Option<&str> {
        self.body.get("repo").or_else(|| self.body.get("did")).and_then(|v| v.as_str())
    }

    pub fn str(&self, k: &str) -> Option<&str> {
        self.body.get(k).and_then(|v| v.as_str())
    }

    pub fn bool(&self, k: &str) -> Option<bool> {
        match self.body.get(k) {
            Some(Value::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    pub fn commit(&self) -> Option<CommitEvt> {
        (self.kind() == "#commit").then(|| CommitEvt::from_body(&self.body).expect("decode #commit"))
    }

    pub fn sync(&self) -> Option<SyncEvt> {
        (self.kind() == "#sync").then(|| SyncEvt::from_body(&self.body).expect("decode #sync"))
    }
}

pub struct Sub {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    pub closed: bool,
}

impl Sub {
    pub async fn connect(url: &str) -> Sub {
        let (ws, _) = tokio_tungstenite::connect_async(url).await.expect("ws connect");
        Sub { ws, closed: false }
    }

    pub async fn connect_as(url: &str, user_agent: &str) -> Sub {
        Sub::connect_with(url, &[("user-agent", user_agent)]).await
    }

    pub async fn connect_with(url: &str, headers: &[(&'static str, &str)]) -> Sub {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = url.into_client_request().expect("ws request");
        for (k, v) in headers {
            req.headers_mut().insert(*k, v.parse().expect("header value"));
        }
        let (ws, _) = tokio_tungstenite::connect_async(req).await.expect("ws connect");
        Sub { ws, closed: false }
    }

    /// Next decoded frame, or None on timeout / close.
    pub async fn next(&mut self, timeout: Duration) -> Option<Frame> {
        use futures::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        if self.closed {
            return None;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let m = match tokio::time::timeout_at(deadline, self.ws.next()).await {
                Err(_) => return None,
                Ok(None) => {
                    self.closed = true;
                    return None;
                }
                Ok(Some(Err(_))) => {
                    self.closed = true;
                    return None;
                }
                Ok(Some(Ok(m))) => m,
            };
            match m {
                Message::Binary(b) => return Some(Frame::decode(&b).expect("decode frame")),
                Message::Close(_) => {
                    self.closed = true;
                    return None;
                }
                _ => continue,
            }
        }
    }

    /// Collects frames until `pred` holds for the collected list (checked after
    /// each frame). Panics with what it has on timeout.
    #[track_caller]
    pub fn until<'a>(
        &'a mut self,
        timeout: Duration,
        mut pred: impl FnMut(&[Frame]) -> bool + 'a,
    ) -> impl std::future::Future<Output = Vec<Frame>> + 'a {
        let loc = std::panic::Location::caller();
        async move {
            let deadline = tokio::time::Instant::now() + timeout;
            let mut out = Vec::new();
            loop {
                if pred(&out) {
                    return out;
                }
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                match self.next(left).await {
                    Some(f) => out.push(f),
                    None => panic!(
                        "{loc}: firehose condition not met within {timeout:?} (closed={}); got {} frames: {:?}",
                        self.closed,
                        out.len(),
                        out.iter()
                            .map(|f| (f.kind().to_string(), f.seq(), f.did().map(String::from)))
                            .collect::<Vec<_>>()
                    ),
                }
            }
        }
    }

    /// Like `until` but returns whatever arrived instead of panicking.
    pub async fn try_until(&mut self, timeout: Duration, mut pred: impl FnMut(&[Frame]) -> bool) -> (Vec<Frame>, bool) {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut out = Vec::new();
        loop {
            if pred(&out) {
                return (out, true);
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next(left).await {
                Some(f) => out.push(f),
                None => return (out, false),
            }
        }
    }

    /// Reads frames until none arrive for `idle`.
    pub async fn drain(&mut self, idle: Duration) -> Vec<Frame> {
        let mut out = Vec::new();
        while let Some(f) = self.next(idle).await {
            out.push(f);
        }
        out
    }

    /// Collects frames until one for `did` of kind `kind` matching `pred` arrives.
    pub async fn wait_for(&mut self, timeout: Duration, did: &str, kind: &str) -> Vec<Frame> {
        let did = did.to_string();
        let kind = kind.to_string();
        self.until(timeout, move |fs| {
            fs.last().map(|f| f.did() == Some(did.as_str()) && f.kind() == kind).unwrap_or(false)
        })
        .await
    }
}

#[derive(Clone, Debug)]
pub struct RepoOp {
    pub action: String,
    pub path: String,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
}

#[derive(Clone, Debug)]
pub struct CommitEvt {
    pub seq: i64,
    pub repo: String,
    pub rev: String,
    pub since: Option<String>,
    pub commit: Cid,
    pub prev_data: Option<Cid>,
    pub blocks: HashMap<Cid, Vec<u8>>,
    pub blocks_roots: Vec<Cid>,
    pub ops: Vec<RepoOp>,
    pub blobs: Vec<Cid>,
    pub too_big: bool,
    pub rebase: bool,
    pub time: String,
}

fn link(v: Option<&Value>) -> Option<Cid> {
    match v {
        Some(Value::Link(c)) => Some(*c),
        _ => None,
    }
}

impl CommitEvt {
    pub fn from_body(b: &Value) -> anyhow::Result<CommitEvt> {
        let blocks_raw = match b.get("blocks") {
            Some(Value::Bytes(x)) => x.clone(),
            _ => anyhow::bail!("#commit without blocks"),
        };
        let (roots, blocks) = vlpds::car::read_car(&blocks_raw)?;
        let ops = match b.get("ops") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|o| RepoOp {
                    action: o.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    path: o.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    cid: link(o.get("cid")),
                    prev: link(o.get("prev")),
                })
                .collect(),
            _ => vec![],
        };
        let blobs = match b.get("blobs") {
            Some(Value::Array(a)) => a.iter().filter_map(|v| link(Some(v))).collect(),
            _ => vec![],
        };
        Ok(CommitEvt {
            seq: match b.get("seq") {
                Some(Value::Int(i)) => *i,
                _ => anyhow::bail!("no seq"),
            },
            repo: b.get("repo").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            rev: b.get("rev").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            since: b.get("since").and_then(|v| v.as_str()).map(String::from),
            commit: link(b.get("commit")).ok_or_else(|| anyhow::anyhow!("no commit"))?,
            prev_data: link(b.get("prevData")),
            blocks: blocks.into_iter().map(|(c, d)| (c, d.to_vec())).collect(),
            blocks_roots: roots,
            ops,
            blobs,
            too_big: matches!(b.get("tooBig"), Some(Value::Bool(true))),
            rebase: matches!(b.get("rebase"), Some(Value::Bool(true))),
            time: b.get("time").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
    }

    pub fn commit_obj(&self) -> CommitObj {
        CommitObj::decode(self.blocks.get(&self.commit).expect("commit block missing from #commit blocks"))
            .expect("decode commit")
    }

    /// sync 1.1 inversion: undo `ops` on the partial tree from `blocks` and
    /// return the resulting root (must equal prevData).
    pub fn invert(&self) -> anyhow::Result<Cid> {
        let c = self.commit_obj();
        let mut tree =
            Tree::load_from_blocks(&self.blocks, c.data).map_err(|e| anyhow::anyhow!("load partial tree: {e}"))?;
        for op in &self.ops {
            let got = tree.get(op.path.as_bytes()).map_err(|e| anyhow::anyhow!("get {}: {e}", op.path))?;
            let want = if op.action == "delete" { None } else { op.cid };
            anyhow::ensure!(got == want, "op {} {}: tree has {:?}, op says {:?}", op.action, op.path, got, want);
        }
        for op in &self.ops {
            match op.action.as_str() {
                "create" => {
                    anyhow::ensure!(op.prev.is_none(), "create {} has prev", op.path);
                    tree.remove(op.path.as_bytes()).map_err(|e| anyhow::anyhow!("invert create {}: {e}", op.path))?;
                }
                "update" | "delete" => {
                    let p = op.prev.ok_or_else(|| anyhow::anyhow!("{} {} without prev", op.action, op.path))?;
                    tree.insert(op.path.as_bytes(), p)
                        .map_err(|e| anyhow::anyhow!("invert {} {}: {e}", op.action, op.path))?;
                }
                a => anyhow::bail!("unknown action {a}"),
            }
        }
        tree.root_cid().map_err(|e| anyhow::anyhow!("root after inversion: {e}"))
    }
}

#[derive(Clone, Debug)]
pub struct SyncEvt {
    pub seq: i64,
    pub did: String,
    pub rev: String,
    pub commit: Cid,
    pub blocks: HashMap<Cid, Vec<u8>>,
}

impl SyncEvt {
    pub fn from_body(b: &Value) -> anyhow::Result<SyncEvt> {
        let raw = match b.get("blocks") {
            Some(Value::Bytes(x)) => x.clone(),
            _ => anyhow::bail!("#sync without blocks"),
        };
        let (roots, blocks) = vlpds::car::read_car(&raw)?;
        Ok(SyncEvt {
            seq: match b.get("seq") {
                Some(Value::Int(i)) => *i,
                _ => anyhow::bail!("no seq"),
            },
            did: b.get("did").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            rev: b.get("rev").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            commit: *roots.first().ok_or_else(|| anyhow::anyhow!("#sync blocks without root"))?,
            blocks: blocks.into_iter().map(|(c, d)| (c, d.to_vec())).collect(),
        })
    }

    pub fn commit_obj(&self) -> CommitObj {
        CommitObj::decode(self.blocks.get(&self.commit).expect("#sync commit block")).expect("decode commit")
    }
}

// ---------------------------------------------------------------------------
// repo / commit helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CommitObj {
    pub did: String,
    pub rev: String,
    pub data: Cid,
    pub version: i64,
    pub prev: Option<Cid>,
    pub sig: Vec<u8>,
    pub value: Value,
}

impl CommitObj {
    pub fn decode(b: &[u8]) -> anyhow::Result<CommitObj> {
        let v = Value::decode(b)?;
        Ok(CommitObj {
            did: v.get("did").and_then(|x| x.as_str()).unwrap_or("").into(),
            rev: v.get("rev").and_then(|x| x.as_str()).unwrap_or("").into(),
            data: link(v.get("data")).ok_or_else(|| anyhow::anyhow!("commit without data"))?,
            version: match v.get("version") {
                Some(Value::Int(i)) => *i,
                _ => 0,
            },
            prev: link(v.get("prev")),
            sig: match v.get("sig") {
                Some(Value::Bytes(s)) => s.clone(),
                _ => vec![],
            },
            value: v,
        })
    }

    /// The unsigned commit bytes (commit object minus `sig`).
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        match &self.value {
            Value::Map(m) => Value::Map(m.iter().filter(|(k, _)| k != "sig").cloned().collect()).to_cbor(),
            _ => panic!("commit is not a map"),
        }
    }

    /// Verifies the signature (low-S ES256K over sha256(unsigned bytes)).
    pub fn verify(&self, key: &k256::ecdsa::VerifyingKey) -> anyhow::Result<()> {
        use k256::ecdsa::signature::Verifier;
        let sig = k256::ecdsa::Signature::from_slice(&self.sig)?;
        anyhow::ensure!(sig.normalize_s() == sig, "signature is not low-S");
        key.verify(&self.unsigned_bytes(), &sig)?;
        Ok(())
    }
}

pub fn decode_k256_multibase(s: &str) -> anyhow::Result<k256::ecdsa::VerifyingKey> {
    let b = bs58::decode(s.strip_prefix('z').ok_or_else(|| anyhow::anyhow!("not base58btc"))?).into_vec()?;
    anyhow::ensure!(b.len() == 35 && b[0] == 0xe7 && b[1] == 0x01, "not a secp256k1 multikey");
    Ok(k256::ecdsa::VerifyingKey::from_sec1_bytes(&b[2..])?)
}

pub fn decode_did_key_k256(did: &str) -> anyhow::Result<k256::ecdsa::VerifyingKey> {
    decode_k256_multibase(did.strip_prefix("did:key:").ok_or_else(|| anyhow::anyhow!("not did:key"))?)
}

/// A parsed repo CAR (getRepo / getRecord / getBlocks / firehose blocks).
pub struct Repo {
    pub root: Cid,
    pub blocks: HashMap<Cid, Vec<u8>>,
    pub order: Vec<Cid>,
}

impl Repo {
    pub fn from_car(b: &[u8]) -> anyhow::Result<Repo> {
        let (roots, blocks) = vlpds::car::read_car(b)?;
        let order = blocks.iter().map(|(c, _)| *c).collect();
        Ok(Repo {
            root: *roots.first().ok_or_else(|| anyhow::anyhow!("CAR without root"))?,
            blocks: blocks.into_iter().map(|(c, d)| (c, d.to_vec())).collect(),
            order,
        })
    }

    pub fn commit(&self) -> CommitObj {
        CommitObj::decode(self.blocks.get(&self.root).expect("root block")).expect("decode commit")
    }

    pub fn tree(&self) -> Tree {
        Tree::load_from_blocks(&self.blocks, self.commit().data).expect("load MST")
    }

    /// All (path, cid) entries of a complete repo.
    pub fn entries(&self) -> Vec<(String, Cid)> {
        let mut out = Vec::new();
        self.tree().walk(&mut |k, v| out.push((String::from_utf8_lossy(k).to_string(), v)));
        out
    }

    pub fn record(&self, path: &str) -> Option<J> {
        let c = self.tree().get(path.as_bytes()).ok()??;
        self.blocks.get(&c).map(|b| Value::decode(b).unwrap().to_json())
    }

    /// Every block's CID matches its content hash.
    pub fn check_block_hashes(&self) -> anyhow::Result<()> {
        for (c, b) in &self.blocks {
            let want = if c.codec == vlpds::cid::CODEC_RAW { Cid::raw(b) } else { Cid::dag_cbor(b) };
            anyhow::ensure!(*c == want, "block {c} hashes to {want}");
        }
        Ok(())
    }
}

/// Checks that `path` maps to `cid` (or is absent when None) in the proof CAR
/// returned by sync.getRecord, and that the commit is signed by `key`.
pub fn verify_record_proof(
    car: &[u8],
    did: &str,
    path: &str,
    key: Option<&k256::ecdsa::VerifyingKey>,
) -> anyhow::Result<Option<Cid>> {
    let repo = Repo::from_car(car)?;
    repo.check_block_hashes()?;
    let c = repo.commit();
    anyhow::ensure!(c.did == did, "commit did {} != {did}", c.did);
    if let Some(k) = key {
        c.verify(k)?;
    }
    let tree = Tree::load_from_blocks(&repo.blocks, c.data).map_err(|e| anyhow::anyhow!("{e}"))?;
    let got = tree.get(path.as_bytes()).map_err(|e| anyhow::anyhow!("proof incomplete for {path}: {e}"))?;
    if let Some(cid) = got {
        anyhow::ensure!(repo.blocks.contains_key(&cid), "record block {cid} missing from proof CAR");
    }
    Ok(got)
}

pub fn is_tid(s: &str) -> bool {
    s.len() == 13
        && s.bytes().enumerate().all(|(i, b)| {
            let ok = matches!(b, b'2'..=b'7' | b'a'..=b'z');
            ok && (i != 0 || matches!(b, b'2'..=b'7' | b'a'..=b'j'))
        })
}

/// Polls `f` every 20 ms until it holds; panics after `deadline`. Returns
/// how long it took.
pub async fn wait_until(what: &str, deadline: Duration, f: impl Fn() -> bool) -> Duration {
    let t = std::time::Instant::now();
    while !f() {
        assert!(t.elapsed() < deadline, "{what}: not within {deadline:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    t.elapsed()
}

/// Retries `f` every 50 ms until it returns Some; panics after 10 s.
pub async fn retry<T, F: std::future::Future<Output = Option<T>>>(what: &str, f: impl FnMut() -> F) -> T {
    eventually(Duration::from_secs(10), f).await.unwrap_or_else(|| panic!("never: {what}"))
}

/// Waits until `f` returns Some or the timeout passes.
pub async fn eventually<T, F: std::future::Future<Output = Option<T>>>(
    timeout: Duration,
    mut f: impl FnMut() -> F,
) -> Option<T> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(v) = f().await {
            return Some(v);
        }
        if tokio::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// listHandleDomains (admin) once its counts are complete: no shard's
/// totals loading and none uncounted, as after a shard moves between nodes.
pub async fn complete_domain_counts(s: &TestServer) -> J {
    let l = eventually(Duration::from_secs(30), || async {
        let l = s.xrpc.get("vlpds.admin.listHandleDomains", &[], &Auth::Admin).await.ok();
        let loading = l["loadingShards"].as_array().is_some_and(|a| !a.is_empty());
        (l["countsPartial"].is_null() && !loading).then_some(l)
    })
    .await;
    l.expect("handle domain counts never complete")
}

/// An unforced removeHandleDomain, refused (DomainInUse, "there may be
/// more") while the counts are partial: sent once they are complete, and
/// again if a shard started loading in between.
pub async fn remove_handle_domain_unforced(s: &TestServer, domain: &str) -> Resp {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        complete_domain_counts(s).await;
        let body = json!({"domain": domain, "force": false});
        let r = s.xrpc.post("vlpds.admin.removeHandleDomain", &body, &Auth::Admin).await;
        if r.status != 409 || !r.text().contains("may be more") || tokio::time::Instant::now() > deadline {
            return r;
        }
        eprintln!("removeHandleDomain {domain}: counts partial again: {}", r.text());
    }
}

pub const FH_TIMEOUT: Duration = Duration::from_secs(10);

pub fn fixture_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata").join(rel)
}

pub fn read_fixture(rel: &str) -> String {
    std::fs::read_to_string(fixture_path(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// An interop data-model fixture: a record's JSON, DAG-CBOR and CID.
pub struct DataModelFixture {
    pub json: J,
    pub cbor: Vec<u8>,
    pub cid: String,
}

pub fn data_model_fixtures() -> Vec<DataModelFixture> {
    #[derive(serde::Deserialize)]
    struct F {
        json: J,
        cbor_base64: String,
        cid: String,
    }
    let fs: Vec<F> = serde_json::from_str(&read_fixture("interop/data-model/data-model-fixtures.json")).unwrap();
    assert!(!fs.is_empty());
    fs.into_iter().map(|f| DataModelFixture { json: f.json, cbor: b64_decode(&f.cbor_base64), cid: f.cid }).collect()
}

/// Non-comment, non-empty lines of an interop syntax fixture.
pub fn fixture_lines(rel: &str) -> Vec<String> {
    read_fixture(rel).lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).map(String::from).collect()
}

/// A minimal 1x1 PNG.
pub const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49,
    0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

// ---------------------------------------------------------------------------
// mail, moderation, encodings, generators, stubs
// ---------------------------------------------------------------------------

/// The newest dev-mode mail sent to `email` (vlpds.admin.getDevMail):
/// `{to, subject, body, html, purpose, token, sentAt}`.
pub async fn latest_mail(s: &TestServer, email: &str) -> J {
    let j = s.dev_mail(email).await.ok();
    j["messages"].as_array().and_then(|m| m.last().cloned()).unwrap_or_else(|| panic!("no mail to {email}: {j}"))
}

/// Dev-mode mail sent to `email`, oldest first.
pub async fn mails(s: &TestServer, email: &str) -> Vec<J> {
    s.dev_mail(email).await.ok()["messages"].as_array().cloned().unwrap_or_default()
}

/// Runs `f`, asserting it mailed exactly `n` messages to `email`; returns
/// its response and the newest message (if any).
pub async fn mailed_n<F: std::future::Future<Output = Resp>>(
    s: &TestServer,
    email: &str,
    n: usize,
    f: F,
) -> (Resp, Option<J>) {
    let before = mails(s, email).await.len();
    let r = f.await;
    let after = mails(s, email).await;
    assert_eq!(after.len(), before + n, "mails to {email} (response {})", r.text());
    (r, (n > 0).then(|| after.last().unwrap().clone()))
}

/// Runs `f`, asserts it sent exactly one mail to `email`, and returns that
/// mail's token, `f`'s response and the mail.
pub async fn mailed<F: std::future::Future<Output = Resp>>(s: &TestServer, email: &str, f: F) -> (String, Resp, J) {
    let (r, m) = mailed_n(s, email, 1, f).await;
    let m = m.unwrap();
    let tok = m["token"]
        .as_str()
        .map(String::from)
        .or_else(|| find_token(&m["body"]))
        .unwrap_or_else(|| panic!("mail without token: {m}"));
    (tok, r, m)
}

/// Moves the stored email token for `purpose` `ms` milliseconds into the
/// past (the reference tests rewrite `email_token.requestedAt`).
pub async fn age_email_token(s: &TestServer, did: &str, purpose: &str, ms: u64) {
    let name = format!("etok/{purpose}");
    let raw = s.app.get_private(did, &name).await.ok().flatten().unwrap_or_else(|| panic!("no stored {name} token"));
    let mut rec: J = serde_json::from_slice(&raw).unwrap();
    rec["requested_at"] = json!(rec["requested_at"].as_u64().unwrap() - ms);
    s.app
        .put_private(
            did,
            vec![vlpds::segment::Mutation {
                key: vlpds::state::private_key(did, &name).into(),
                val: Some(serde_json::to_vec(&rec).unwrap().into()),
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("put_private: {}", e.message));
}

/// admin.updateSubjectStatus on a repoRef with `takedown: {applied}`.
pub async fn set_repo_takedown(s: &TestServer, did: &str, applied: bool) {
    s.xrpc
        .post(
            "com.atproto.admin.updateSubjectStatus",
            &json!({"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": did}, "takedown": {"applied": applied}}),
            &Auth::Admin,
        )
        .await
        .ok();
}

/// Collects mismatches and fails once with all of them.
pub struct Diffs {
    what: String,
    list: Vec<String>,
}

impl Diffs {
    pub fn new(what: &str) -> Diffs {
        Diffs { what: what.to_string(), list: Vec::new() }
    }

    pub fn push(&mut self, s: impl Into<String>) {
        let s = s.into();
        if !self.list.contains(&s) {
            self.list.push(s);
        }
    }

    #[track_caller]
    pub fn assert_none(self) {
        assert!(
            self.list.is_empty(),
            "{}: {} mismatches:\n  {}",
            self.what,
            self.list.len(),
            self.list.iter().take(400).cloned().collect::<Vec<_>>().join("\n  ")
        );
    }
}

/// `s` quoted, cut at 80 bytes.
pub fn short(s: &str) -> String {
    if s.len() > 80 {
        format!("{:?}…({} bytes)", &s[..s.floor_char_boundary(80)], s.len())
    } else {
        format!("{s:?}")
    }
}

pub fn repo_ref(did: &str) -> J {
    json!({"$type": "com.atproto.admin.defs#repoRef", "did": did})
}

pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// base64url without padding (JWT/JWK/DPoP encoding).
pub fn b64url(b: impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A JWT's claims (payload), unverified.
pub fn jwt_claims(tok: &str) -> J {
    serde_json::from_slice(&b64url_decode(tok.split('.').nth(1).expect("jwt payload"))).expect("jwt json")
}

pub fn b64url_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

/// `n` random bytes, base64url (nonces, jtis, PKCE verifiers).
pub fn rand_b64url(n: usize) -> String {
    b64url(random_bytes(n))
}

/// The `csrf` hidden field of an OAuth page.
pub fn csrf_of(html: &str) -> String {
    let i = html.find("name=\"csrf\" value=\"").expect("csrf field") + "name=\"csrf\" value=\"".len();
    html[i..i + html[i..].find('"').unwrap()].to_string()
}

/// An `application/x-www-form-urlencoded` body.
pub fn form_body(pairs: &[(&str, &str)]) -> String {
    let enc = vlpds::oauth::util::form_encode_component;
    pairs.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

/// Standard base64, padded or not.
pub fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')).unwrap()
}

/// Short random text from pieces that stress escaping, UTF-8 and map key
/// order ("$"-keys, prefixes of each other).
pub fn rand_text(rng: &mut impl rand::Rng) -> String {
    const PIECES: &[&str] = &[
        "a", "b", "z", "aa", "ab", "$type", "$link", "$bytes", "text", "\"", "\\", "\n", "\t", "\u{0}", "\u{1f}",
        "\u{7f}", "é", "日本", "😀", "\u{2028}", "/", "<", " ",
    ];
    (0..rng.gen_range(0..6)).map(|_| PIECES[rng.gen_range(0..PIECES.len())]).collect()
}

/// A random DAG-CBOR value tree (canonical key order), at most 5 deep, with
/// integers around the encoding's width boundaries.
pub fn rand_cbor(rng: &mut impl rand::Rng, depth: usize) -> Value {
    let leaf = depth >= 5 || rng.gen_bool(0.4);
    match rng.gen_range(0..if leaf { 6 } else { 8 }) {
        0 => Value::Null,
        1 => Value::Bool(rng.gen()),
        2 => Value::Int(match rng.gen_range(0..4) {
            0 => rng.gen_range(-30..30),
            1 => rng.gen_range(-70_000..70_000),
            2 => rng.gen(),
            _ => [i64::MIN, i64::MAX, i64::MIN + 1, -1 - u32::MAX as i64, u32::MAX as i64, 23, 24, -24, -25, 255, 256]
                [rng.gen_range(0..11)],
        }),
        3 => Value::Bytes((0..rng.gen_range(0..40)).map(|_| rng.gen()).collect()),
        4 => Value::Text(rand_text(rng)),
        5 => {
            Value::Link(if rng.gen() { Cid::dag_cbor(&rng.gen::<[u8; 8]>()) } else { Cid::raw(&rng.gen::<[u8; 8]>()) })
        }
        6 => Value::Array((0..rng.gen_range(0..5)).map(|_| rand_cbor(rng, depth + 1)).collect()),
        _ => {
            let mut m: Vec<(String, Value)> = Vec::new();
            for _ in 0..rng.gen_range(0..6) {
                let k = rand_text(rng);
                if !m.iter().any(|(x, _)| *x == k) {
                    m.push((k, rand_cbor(rng, depth + 1)));
                }
            }
            m.sort_by(|a, b| vlpds::cbor::key_cmp(&a.0, &b.0));
            Value::Map(m)
        }
    }
}

/// Env var `k` parsed, else `d` (measurement knobs).
pub fn env_or<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

/// An in-memory store adding `ms` to every request (S3-like latency).
pub fn throttled_store(ms: u64) -> object_store::throttle::ThrottledStore<object_store::memory::InMemory> {
    let d = Duration::from_millis(ms);
    let cfg = object_store::throttle::ThrottleConfig {
        wait_get_per_call: d,
        wait_put_per_call: d,
        wait_list_per_call: d,
        wait_delete_per_call: d,
        ..Default::default()
    };
    object_store::throttle::ThrottledStore::new(object_store::memory::InMemory::new(), cfg)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

/// A unique ~2 KB blob that sniffs as PNG.
pub fn random_png(tag: u8) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend(random_bytes(2000));
    v.push(tag);
    v
}

#[derive(clap::Parser)]
struct AdminCli {
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    cmd: vlpds::cli::admin::Cmd,
}

/// Runs `vlpds admin --url <url> <args...>` through the CLI's library entry
/// (argv parsed by clap as the binary does): (result, stdout).
pub async fn admin_cli(url: &str, args: &[&str]) -> (anyhow::Result<()>, String) {
    admin_cli_as(url, vlpds::server::DEV_ADMIN_TOKEN, args).await
}

pub async fn admin_cli_as(url: &str, token: &str, args: &[&str]) -> (anyhow::Result<()>, String) {
    use clap::Parser;
    let cli =
        AdminCli::try_parse_from(std::iter::once("vlpds-admin").chain(args.iter().copied())).expect("argv parses");
    let opts = vlpds::cli::admin::Opts { url: url.to_string(), token: token.to_string(), json: cli.json };
    let mut out = Vec::new();
    let r = vlpds::cli::admin::run(cli.cmd, &opts, &mut out).await;
    (r, String::from_utf8(out).unwrap())
}

/// A fake AppView answering `{"feed": []}` to everything; records each
/// request's Authorization header. Returns (headers, url).
pub async fn spawn_auth_recorder() -> (Arc<parking_lot::Mutex<Vec<String>>>, String) {
    use axum::extract::{Request, State};
    let seen: Arc<parking_lot::Mutex<Vec<String>>> = Default::default();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let router = axum::Router::new()
        .fallback(|State(seen): State<Arc<parking_lot::Mutex<Vec<String>>>>, req: Request| async move {
            let auth = req.headers().get("authorization").map(|v| v.to_str().unwrap().to_string());
            seen.lock().push(auth.unwrap_or_default());
            axum::Json(json!({"feed": []}))
        })
        .with_state(seen.clone());
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    (seen, url)
}
