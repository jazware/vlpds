//! An in-process PLC directory for tests, with the directory's own checks
//! on incoming ops. Serves only what the PDS reads: `GET /{did}`,
//! `/{did}/data`, `/{did}/log/last` and `/{did}/log/audit`. Failures can be injected.

use super::{assert_valid_incoming, format_did_doc, PlcLog};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use parking_lot::Mutex;
use serde_json::{json, Value as J};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct Inner {
    logs: Mutex<HashMap<String, PlcLog>>,
    /// POSTs answered with this status (count, status) before validation.
    fail_posts: Mutex<(u32, u16)>,
    down: AtomicBool,
    /// Ops applied just before the next POST of their DID is handled, as if
    /// another writer had landed between that client's read and its submit.
    race: Mutex<HashMap<String, Vec<J>>>,
    posts: AtomicU64,
}

/// Served until the process exits.
#[derive(Clone)]
pub struct MockPlc {
    pub url: String,
    inner: Arc<Inner>,
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({"message": message.into()}))).into_response()
}

impl MockPlc {
    pub async fn start() -> MockPlc {
        let inner = Arc::new(Inner::default());
        let app = axum::Router::new()
            .route("/{did}", get(doc).post(post_op))
            .route("/{did}/data", get(data))
            .route("/{did}/log/last", get(last))
            .route("/{did}/log/audit", get(audit))
            .with_state(inner.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock PLC");
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        MockPlc { url, inner }
    }

    pub fn fail_posts(&self, n: u32, status: u16) {
        *self.inner.fail_posts.lock() = (n, status);
    }

    /// A concurrent writer winning the race for `prev`.
    pub fn race_next_post(&self, did: &str, op: J) {
        self.inner.race.lock().entry(did.to_string()).or_default().push(op);
    }

    /// While set, every request is answered 503.
    pub fn set_down(&self, down: bool) {
        self.inner.down.store(down, Ordering::SeqCst);
    }

    pub fn posts(&self) -> u64 {
        self.inner.posts.load(Ordering::SeqCst)
    }

    /// Oldest first, nullified ones included.
    pub fn ops(&self, did: &str) -> Vec<J> {
        self.inner.logs.lock().get(did).map(|l| l.entries.iter().map(|e| e.op.clone()).collect()).unwrap_or_default()
    }

    pub fn last_op(&self, did: &str) -> Option<J> {
        self.inner.logs.lock().get(did).and_then(|l| l.last().map(|e| e.op.clone()))
    }

    pub fn data(&self, did: &str) -> Option<J> {
        self.inner.logs.lock().get(did).and_then(PlcLog::data)
    }

    pub fn dids(&self) -> Vec<String> {
        self.inner.logs.lock().keys().cloned().collect()
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[allow(clippy::result_large_err)]
fn known(s: &Inner, did: &str) -> Result<PlcLog, Response> {
    if s.down.load(Ordering::SeqCst) {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "mock PLC down"));
    }
    match s.logs.lock().get(did) {
        Some(l) if !l.entries.is_empty() => Ok(l.clone()),
        _ => Err(err(StatusCode::NOT_FOUND, format!("DID not registered: {did}"))),
    }
}

async fn doc(State(s): State<Arc<Inner>>, Path(did): Path<String>) -> Response {
    match known(&s, &did) {
        Ok(l) => match l.data() {
            Some(d) => {
                ([(axum::http::header::CONTENT_TYPE, "application/did+ld+json")], format_did_doc(&d).to_string())
                    .into_response()
            }
            None => err(StatusCode::NOT_FOUND, format!("DID not available: {did}")),
        },
        Err(r) => r,
    }
}

async fn data(State(s): State<Arc<Inner>>, Path(did): Path<String>) -> Response {
    match known(&s, &did) {
        Ok(l) => match l.data() {
            Some(d) => Json(d).into_response(),
            None => err(StatusCode::NOT_FOUND, format!("DID not available: {did}")),
        },
        Err(r) => r,
    }
}

async fn last(State(s): State<Arc<Inner>>, Path(did): Path<String>) -> Response {
    match known(&s, &did) {
        Ok(l) => Json(l.last().map(|e| e.op.clone()).unwrap_or(J::Null)).into_response(),
        Err(r) => r,
    }
}

async fn audit(State(s): State<Arc<Inner>>, Path(did): Path<String>) -> Response {
    match known(&s, &did) {
        Ok(l) => {
            let at = |ms: i64| {
                chrono::DateTime::from_timestamp_millis(ms)
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            };
            let log: Vec<J> = l
                .entries
                .iter()
                .map(|e| json!({"did": did, "operation": e.op, "cid": e.cid, "nullified": e.nullified, "createdAt": at(e.created_at_ms)}))
                .collect();
            Json(log).into_response()
        }
        Err(r) => r,
    }
}

async fn post_op(State(s): State<Arc<Inner>>, Path(did): Path<String>, body: axum::body::Bytes) -> Response {
    s.posts.fetch_add(1, Ordering::SeqCst);
    if s.down.load(Ordering::SeqCst) {
        return err(StatusCode::SERVICE_UNAVAILABLE, "mock PLC down");
    }
    {
        let mut f = s.fail_posts.lock();
        if f.0 > 0 {
            f.0 -= 1;
            return err(StatusCode::from_u16(f.1).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), "injected failure");
        }
    }
    if !super::valid_plc_did(&did) {
        return err(StatusCode::BAD_REQUEST, format!("Invalid DID: {did}"));
    }
    let op: J = match serde_json::from_slice(&body) {
        Ok(o) => o,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad JSON: {e}")),
    };
    if let Err(e) = assert_valid_incoming(&op) {
        return err(StatusCode::BAD_REQUEST, e.to_string());
    }
    let mut logs = s.logs.lock();
    let mut l = logs.get(&did).cloned().unwrap_or_else(|| PlcLog::new(&did));
    for raced in s.race.lock().remove(&did).unwrap_or_default() {
        let at = now_ms().max(l.entries.last().map_or(0, |e| e.created_at_ms + 1));
        if l.apply(raced, at).is_ok() {
            logs.insert(did.clone(), l.clone());
        }
    }
    // strictly increasing timestamps, as the directory's clock would give
    let at = now_ms().max(l.entries.last().map_or(0, |e| e.created_at_ms + 1));
    match l.apply(op, at) {
        Ok(()) => {
            logs.insert(did, l);
            // the directory answers `res.sendStatus(200)`: text/plain "OK"
            ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], "OK").into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plc::Plc;
    use vlsync_atproto::crypto::Keypair;

    #[tokio::test]
    async fn mock_directory_round_trip() {
        let m = MockPlc::start().await;
        let plc = Plc::new(&m.url, Arc::new(Keypair::generate()), None);
        let signing = Keypair::generate().did_key();
        let (did, op) = plc.genesis(&signing, "alice.test", "https://pds.example", None).unwrap();
        // a genesis op posted under another DID is refused
        let other = vlsync_atproto::crypto::random_plc_did();
        assert!(matches!(
            plc.client.send(&other, &op, "create").await,
            Err(crate::plc::PlcError::Rejected { status: 400, .. })
        ));
        plc.create(&did, &op).await.unwrap();
        assert_eq!(m.last_op(&did).unwrap(), op);
        assert!(plc.update_handle(&did, "bob.test").await.unwrap());
        assert!(!plc.update_handle(&did, "bob.test").await.unwrap(), "unchanged: nothing submitted");
        let new_key = Keypair::generate().did_key();
        assert!(plc.update_signing_key(&did, &new_key).await.unwrap());
        let d = plc.client.document_data(&did).await.unwrap();
        assert_eq!(d["alsoKnownAs"], json!(["at://bob.test"]));
        assert_eq!(d["verificationMethods"]["atproto"], json!(new_key));
        assert_eq!(m.ops(&did).len(), 3);
        // injected failures and outages
        m.fail_posts(1, 500);
        assert!(matches!(plc.update_handle(&did, "carol.test").await, Err(crate::plc::PlcError::Unavailable(_))));
        m.set_down(true);
        assert!(matches!(plc.client.last_op(&did).await, Err(crate::plc::PlcError::Unavailable(_))));
        m.set_down(false);
        assert!(matches!(plc.client.last_op(&other).await, Err(crate::plc::PlcError::NotFound(_))));
        plc.tombstone(&did).await.unwrap();
        assert!(m.data(&did).is_none());
        assert!(matches!(plc.update_handle(&did, "dave.test").await, Err(crate::plc::PlcError::Tombstoned)));
        // a doc served like the directory's
        let doc: J = reqwest::get(format!("{}/{did}", m.url)).await.unwrap().json().await.unwrap();
        assert_eq!(doc["message"], json!(format!("DID not available: {did}")));
    }

    /// An op landing between an update's read and its submit (another node,
    /// or a key rotation racing a handle change) forks `prev`; the directory
    /// refuses the second one and the update is rebuilt on the new last op:
    /// both changes land.
    #[tokio::test]
    async fn prev_race_is_rebuilt_not_lost() {
        let m = MockPlc::start().await;
        let plc = Plc::new(&m.url, Arc::new(Keypair::generate()), None);
        let (did, op) = plc.genesis(&Keypair::generate().did_key(), "alice.test", "https://pds.example", None).unwrap();
        plc.create(&did, &op).await.unwrap();
        let new_key = Keypair::generate().did_key();
        let raced = plc
            .update_op(&op, |m| {
                m.insert("verificationMethods".into(), json!({"atproto": new_key}));
                Ok(())
            })
            .unwrap();
        m.race_next_post(&did, raced);
        assert!(plc.update_handle(&did, "bob.test").await.unwrap());
        let d = m.data(&did).unwrap();
        assert_eq!(d["alsoKnownAs"], json!(["at://bob.test"]));
        assert_eq!(d["verificationMethods"]["atproto"], json!(new_key), "the racing op stays");
        assert_eq!(m.ops(&did).len(), 3);
        assert_eq!(m.posts(), 3, "genesis, the refused fork, the rebuilt update");
        // a refusal with the log unchanged is final
        m.fail_posts(1, 400);
        assert!(matches!(plc.update_handle(&did, "carol.test").await, Err(crate::plc::PlcError::Rejected { .. })));
    }
}
