//! The reference's `tests/_space.ts` for the ported space suites
//! (`ref_space_*`, `ref_simplespace`, `ref_client_attestation`), over XRPC:
//!
//! - [`Net`]: the reference's `TestNetworkNoAppView` with `extraPdses`, as
//!   `--spaces` PDSes registering DIDs with one in-process PLC directory, so
//!   each resolves the others' accounts. `pds[0]` is the authority's host.
//! - Accounts are [`SpaceClient`]s granted [`FULL_SCOPE`] over OAuth.
//!   Space data is OAuth-only in vlpds, where the reference's actors use
//!   password sessions (`SeedClient.getHeaders`).
//! - [`Cred`]: the reference's `SpaceCredential`, signing each request for
//!   the audience it derives (`repo`, else the space's authority).
//! - [`MockService`]: the reference's `MockService` (a managing app, a
//!   syncer, a remote space host) as a did:web on loopback that records
//!   every call. It holds an `#atproto` key, so it can also stand in for a
//!   remote authority or writer whose tokens a test signs by hand.
//! - [`MockClientApp`]: the reference's `MockClientApp`, publishing client
//!   metadata and a JWKS over HTTP and signing client attestations.

use crate::common::spaces::{resp, signed_get_as, xrpc_url, Holder, SpaceClient};
use crate::common::*;
use crate::oauth;
use base64::Engine;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vlpds::space::commit::{self, SignedCommit};
use vlpds::space::lthash::LtHash;
use vlpds::space::token::{self, Mint, TokenType};

pub const TEST_COLLECTION: &str = "com.example.spaceRecord";
pub const TEST_COLLECTION_ALT: &str = "com.example.spaceNote";
pub const TEST_SPACE_TYPE: &str = "com.example.group";
pub const OTHER_SPACE_TYPE: &str = "com.example.otherGroup";
pub const SPACE_TYPE_COLLECTIONS: [&str; 2] = ["com.example.groupNote", "com.example.groupPost"];

/// Everything a reference actor's legacy session could do in a space, plus
/// public repo writes and blob uploads.
pub const FULL_SCOPE: &str = "transition:generic space:*?authority=*&collection=*&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete";

pub const MEMBER_LIST: &str = "com.atproto.simplespace.defs#memberListPolicy";
pub const PUBLIC: &str = "com.atproto.simplespace.defs#publicPolicy";
pub const MANAGING_APP: &str = "com.atproto.simplespace.defs#managingAppPolicy";
pub const OPEN: &str = "com.atproto.simplespace.defs#open";
pub const ALLOW_LIST: &str = "com.atproto.simplespace.defs#allowList";

pub fn member_list() -> J {
    json!({"$type": MEMBER_LIST})
}

pub fn public() -> J {
    json!({"$type": PUBLIC})
}

pub fn managing_app(app: &str) -> J {
    json!({"$type": MANAGING_APP, "managingApp": app})
}

pub fn open() -> J {
    json!({"$type": OPEN})
}

pub fn allow_list(allowed: &[&str]) -> J {
    json!({"$type": ALLOW_LIST, "allowed": allowed})
}

/// `record()`: a minimal record body for a test collection.
pub fn record(collection: &str, text: &str) -> J {
    json!({"$type": collection, "text": text, "createdAt": now_iso()})
}

/// The authority DID of a space URI.
pub fn authority_of(space: &str) -> &str {
    space.trim_start_matches("at://").split('/').next().unwrap()
}

pub fn last_segment(uri: &str) -> &str {
    uri.rsplit('/').next().unwrap()
}

pub fn b64url(b: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// `{"$bytes": ...}`, the JSON form of a bytes field.
pub fn json_bytes(b: &[u8]) -> J {
    json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)})
}

pub(super) use super::fuzz::{bytes_field, fold, signed_commit};

pub fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// A TID `offset` from now (`TID.fromTime`), with a random clock id.
pub fn tid_at(offset_us: i64) -> String {
    let micros = (vlatproto::tid::now_micros() as i64 + offset_us) as u64;
    vlatproto::tid::Tid::from_parts(micros, rand::random::<u64>() % 1024).to_string()
}

/// `TID.nextStr()`: a fresh TID, later than `after` if given.
pub fn next_tid(after: Option<&str>) -> String {
    let t = tid_at(0);
    match after {
        Some(a) if t.as_str() <= a => {
            let p = vlatproto::tid::Tid::parse(a).unwrap();
            vlatproto::tid::Tid::from_parts(p.micros() + 1, 0).to_string()
        }
        _ => t,
    }
}

/// Asserts a 4xx whose error name or message mentions one of `needles`
/// (case-insensitive): the reference pins some refusals by message only.
#[track_caller]
pub fn refused_mentioning(r: &Resp, needles: &[&str]) {
    assert!((400..500).contains(&r.status), "expected a refusal, got {} {}", r.status, r.text());
    let hay = format!("{} {}", r.error_name().unwrap_or(""), r.json["message"].as_str().unwrap_or("")).to_lowercase();
    assert!(
        needles.iter().any(|n| hay.contains(&n.to_lowercase())),
        "refusal doesn't mention {needles:?}: {}",
        r.text()
    );
}

// ---------------------------------------------------------------------------
// the network
// ---------------------------------------------------------------------------

pub struct Net {
    pub plc: vlpds::plc::mock::MockPlc,
    pub pds: Vec<TestServer>,
    hosts: Mutex<HashMap<String, usize>>,
}

impl Net {
    /// `1 + extra` `--spaces` PDSes on one PLC directory.
    pub async fn new(extra: usize) -> Net {
        Self::new_with(extra, |_, _| {}).await
    }

    pub async fn new_with(extra: usize, f: impl Fn(usize, &mut vlpds::server::Config)) -> Net {
        let plc = vlpds::plc::mock::MockPlc::start().await;
        let mut pds = Vec::new();
        for i in 0..=extra {
            let url = plc.url.clone();
            let rot = Arc::new(vlatproto::crypto::Keypair::generate());
            pds.push(
                TestServer::spawn_with(|c| {
                    use_plc(c, url, rot);
                    c.service_did = format!("did:web:pds{i}.test");
                    c.spaces = true;
                    f(i, c);
                })
                .await,
            );
        }
        Net { plc, pds, hosts: Mutex::new(HashMap::new()) }
    }

    /// `createActor(name, pds)`, signed in over OAuth with [`FULL_SCOPE`].
    pub async fn actor(&self, name: &str, pds: usize) -> SpaceClient {
        // unique_name adds up to 7 characters and createAccount 5 digits, under an 18-character limit
        let a = SpaceClient::new(&self.pds[pds], &unique_name(&name[..name.len().min(6)]), FULL_SCOPE).await;
        self.hosts.lock().insert(a.did.clone(), pds);
        a
    }

    /// The base URL of the PDS hosting `did`.
    pub fn host_of(&self, did: &str) -> String {
        let i = *self.hosts.lock().get(did).unwrap_or_else(|| panic!("{did} isn't a Net account"));
        self.pds[i].url.clone()
    }

    /// `sc.createSpace(owner, opts)`: the space's URI.
    pub async fn create_space(&self, owner: &SpaceClient, o: SpaceOpts<'_>) -> String {
        let space_type = o.space_type.unwrap_or(TEST_SPACE_TYPE);
        let skey = o.skey.map(String::from).unwrap_or_else(|| format!("s{}", unique_name("")));
        let uri = format!("at://{}/space/{space_type}/{skey}", owner.did);
        if !o.ungoverned {
            let r = owner
                .post(
                    "com.atproto.simplespace.createSpace",
                    json!({
                        "spaceType": space_type,
                        "skey": skey,
                        "readPolicy": o.read_policy.unwrap_or_else(member_list),
                        "writePolicy": o.write_policy.unwrap_or_else(member_list),
                        "appAccess": o.app_access.unwrap_or_else(open),
                    }),
                )
                .await;
            assert_eq!(r.ok()["uri"], json!(uri), "createSpace anchors on the caller");
        }
        for m in o.members {
            put_member(owner, &uri, m, true, true).await.ok();
        }
        uri
    }

    /// `sc.credentialFor(actor, space)`: a delegation token from the actor's
    /// PDS, exchanged at the authority's for a credential bound to a fresh
    /// holder key.
    pub async fn credential_for(&self, actor: &SpaceClient, space: &str) -> Cred {
        let token = delegation_token(actor, space).await;
        let r = self.mint_credential(space, &token, None).await;
        let credential = r.0.ok()["credential"].as_str().unwrap().to_string();
        Cred { credential, holder: r.1, http: actor.srv.http.clone() }
    }

    /// `sc.mintCredential(space, token, {clientAttestation})` at the
    /// authority's PDS: the response and the holder key that signed it.
    pub async fn mint_credential(&self, space: &str, token: &str, attestation: Option<&str>) -> (Resp, Holder) {
        let holder = Holder::new();
        let host = self.host_of(authority_of(space));
        (exchange(&reqwest::Client::new(), &holder, &host, space, token, attestation).await, holder)
    }

    /// The authority's writer set as its storage holds it (`sW`), as the
    /// reference's `writerDids` reads it: no credential, so an allowList
    /// space's app perimeter doesn't stand in the way. `owner` is the
    /// authority's account.
    pub async fn writer_dids(&self, owner: &SpaceClient, space: &str) -> Vec<String> {
        use vlpds::state;
        let i = *self.hosts.lock().get(&owner.did).expect("a Net account");
        let p = self.pds[i].app.partitions.for_key(&owner.did).expect("the authority's shard");
        let prefix = state::space_prefix(state::SPACE_WRITER_FAMILY, &owner.did, &state::space_id(space));
        let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
        let mut dids = Vec::new();
        while let Some(kv) = it.next().await.unwrap() {
            dids.push(String::from_utf8_lossy(&kv.key[prefix.len()..]).into_owned());
        }
        dids.sort();
        dids
    }

    /// `awaitNotify` over [`Self::writer_dids`]: the set once it holds
    /// `did`, or what it was when the wait ran out.
    pub async fn await_writer(&self, owner: &SpaceClient, space: &str, did: &str) -> Vec<String> {
        let mut last = Vec::new();
        for _ in 0..100 {
            last = self.writer_dids(owner, space).await;
            if last.iter().any(|d| d == did) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        last
    }
}

#[derive(Default)]
pub struct SpaceOpts<'a> {
    pub skey: Option<&'a str>,
    pub space_type: Option<&'a str>,
    pub members: &'a [&'a SpaceClient],
    pub read_policy: Option<J>,
    pub write_policy: Option<J>,
    pub app_access: Option<J>,
    /// Skip createSpace, leaving the space ungoverned.
    pub ungoverned: bool,
}

pub async fn put_member(owner: &SpaceClient, space: &str, member: &SpaceClient, read: bool, write: bool) -> Resp {
    owner
        .post(
            "com.atproto.simplespace.putMember",
            json!({"space": space, "did": member.did, "read": read, "write": write}),
        )
        .await
}

pub async fn remove_member(owner: &SpaceClient, space: &str, member: &SpaceClient) -> Resp {
    owner.post("com.atproto.simplespace.removeMember", json!({"space": space, "did": member.did})).await
}

pub async fn delegation_token(actor: &SpaceClient, space: &str) -> String {
    actor.delegation_token(space).await.ok()["token"].as_str().unwrap().to_string()
}

/// getSpaceCredential at `host`, signed by `holder` for `token`.
pub async fn exchange(
    http: &reqwest::Client,
    holder: &Holder,
    host: &str,
    space: &str,
    token: &str,
    attestation: Option<&str>,
) -> Resp {
    let mut body = json!({"space": space});
    if let Some(a) = attestation {
        body["clientAttestation"] = json!(a);
    }
    let mut rb = http.post(format!("{host}/xrpc/com.atproto.space.getSpaceCredential"));
    for (k, v) in holder.headers(&format!("Bearer {token}"), None) {
        rb = rb.header(k, v);
    }
    resp(rb.json(&body).send().await.unwrap()).await
}

/// One write's options (the reference's `WriteOptions`).
#[derive(Default, Clone)]
pub struct W {
    pub collection: Option<String>,
    pub rkey: Option<String>,
    pub text: Option<String>,
    pub record: Option<J>,
    pub validate: Option<bool>,
}

impl W {
    pub fn new() -> W {
        W::default()
    }
    pub fn rkey(mut self, k: &str) -> W {
        self.rkey = Some(k.into());
        self
    }
    pub fn text(mut self, t: &str) -> W {
        self.text = Some(t.into());
        self
    }
    pub fn collection(mut self, c: &str) -> W {
        self.collection = Some(c.into());
        self
    }
    pub fn record(mut self, r: J) -> W {
        self.record = Some(r);
        self
    }
    pub fn validate(mut self, v: bool) -> W {
        self.validate = Some(v);
        self
    }
    fn body(&self, actor: &SpaceClient, space: &str, default_rkey: Option<&str>) -> J {
        let collection = self.collection.clone().unwrap_or_else(|| TEST_COLLECTION.into());
        let rec = self.record.clone().unwrap_or_else(|| record(&collection, self.text.as_deref().unwrap_or("hello")));
        let mut b = json!({"space": space, "repo": actor.did, "collection": collection, "record": rec});
        if let Some(k) = self.rkey.as_deref().or(default_rkey) {
            b["rkey"] = json!(k);
        }
        if let Some(v) = self.validate {
            b["validate"] = json!(v);
        }
        b
    }
}

/// `sc.write`: createRecord into the actor's own repo.
pub async fn write(actor: &SpaceClient, space: &str, w: W) -> Resp {
    actor.post("com.atproto.space.createRecord", w.body(actor, space, None)).await
}

/// `sc.put`: putRecord, rkey `self` by default.
pub async fn put(actor: &SpaceClient, space: &str, w: W) -> Resp {
    actor.post("com.atproto.space.putRecord", w.body(actor, space, Some("self"))).await
}

/// `sc.del`.
pub async fn del(actor: &SpaceClient, space: &str, collection: Option<&str>, rkey: &str) -> Resp {
    let collection = collection.unwrap_or(TEST_COLLECTION);
    actor
        .post(
            "com.atproto.space.deleteRecord",
            json!({"space": space, "repo": actor.did, "collection": collection, "rkey": rkey}),
        )
        .await
}

pub fn create_op(rkey: &str, text: &str) -> J {
    json!({"$type": "com.atproto.space.applyWrites#create", "collection": TEST_COLLECTION, "rkey": rkey, "value": record(TEST_COLLECTION, text)})
}

/// The actor's repo in `space` as its owner reads it (`sc.repoState`):
/// the head's rev and set hash, or None while unwritten.
pub async fn repo_state(actor: &SpaceClient, space: &str) -> Option<(String, Vec<u8>)> {
    let r = actor.get("com.atproto.space.getLatestCommit", &[("space", space), ("repo", &actor.did)]).await;
    if r.status == 400 && r.error_name() == Some("RepoNotFound") {
        return None;
    }
    let c = &r.ok()["commit"];
    Some((c["rev"].as_str().unwrap().to_string(), bytes_field(&c["hash"])))
}

/// Every record of the actor's repo in `space`, paged as its owner.
pub async fn all_records(actor: &SpaceClient, space: &str) -> Vec<J> {
    let (mut out, mut cursor) = (Vec::new(), None::<String>);
    for _ in 0..1000 {
        let mut q = vec![("space", space), ("repo", actor.did.as_str()), ("limit", "100")];
        if let Some(c) = &cursor {
            q.push(("cursor", c.as_str()));
        }
        let r = actor.get("com.atproto.space.listRecords", &q).await.ok();
        let recs = r["records"].as_array().cloned().unwrap_or_default();
        let done = recs.is_empty() || r["cursor"].as_str().is_none();
        out.extend(recs);
        if done {
            break;
        }
        cursor = r["cursor"].as_str().map(String::from);
    }
    out
}

/// `sc.expectSetHashMatchesStore`: the set hash folded from the records
/// the owner lists equals the head's (an empty set while unwritten).
pub async fn expect_set_hash_matches_store(actor: &SpaceClient, space: &str) {
    let mut set = LtHash::default();
    for r in all_records(actor, space).await {
        let (coll, rkey) = (r["collection"].as_str().unwrap(), r["rkey"].as_str().unwrap());
        set.add(&commit::element(coll, rkey, r["cid"].as_str().unwrap()));
    }
    match repo_state(actor, space).await {
        Some((_, hash)) => assert_eq!(set.digest().to_vec(), hash, "the records don't fold to the head's set hash"),
        None => assert!(set.is_empty(), "records listed in an unwritten repo"),
    }
}

/// A syncer's set hash from listRepoOps ops (`RepoCommit.applyOp`).
pub fn replay(ops: &[J]) -> LtHash {
    let mut set = LtHash::default();
    for op in ops {
        fold(&mut set, op);
    }
    set
}

pub fn commit_matches(set: &LtHash, c: &J) -> bool {
    let sc: SignedCommit = signed_commit(c);
    assert_eq!(sc.ver, 1, "commit ver");
    commit::matches(set, &sc)
}

/// The account's `#atproto` key as a did:key (describeRepo).
pub async fn did_key(s: &TestServer, did: &str) -> String {
    let j = s.describe_repo(did).await.ok();
    let vm = j["didDoc"]["verificationMethod"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"].as_str().is_some_and(|i| i.ends_with("#atproto")))
        .unwrap()
        .clone();
    format!("did:key:{}", vm["publicKeyMultibase"].as_str().unwrap())
}

/// A service JWT signed by the actor's account key, as its PDS's outbox
/// signs one (getServiceAuth won't mint a space method's for a password
/// session).
pub async fn service_jwt(actor: &SpaceClient, aud: &str, lxm: &str) -> String {
    let app = &actor.srv.app;
    let acct = app.account(&actor.did).await.ok().expect("account");
    let key = app.secrets.account_signing_key(&acct).await.unwrap();
    vlpds::auth::service_auth_jwt(&key, &actor.did, aud, Some(lxm), 60).unwrap()
}

/// POST `nsid` at `base` with a service JWT.
pub async fn post_service(base: &str, nsid: &str, jwt: &str, body: J) -> Resp {
    Xrpc::new(base).post(nsid, &body, &Auth::Bearer(jwt.into())).await
}

/// The same account signed in again over OAuth for `scope` (`atproto` added).
pub async fn regrant(a: &SpaceClient, scope: &str) -> SpaceClient {
    let srv = oauth::Srv { app: a.srv.app.clone(), base: a.srv.base.clone(), http: a.srv.http.clone() };
    let scope = format!("atproto {scope}");
    let key = oauth::DpopKey::new();
    let acct = oauth::Account { did: a.did.clone(), handle: a.handle.clone(), jwt: a.session_jwt.clone() };
    let t = oauth::grant(&srv, &mut oauth::Browser::default(), &oauth::Flow::loopback(&scope, &key), &acct).await;
    SpaceClient {
        srv,
        did: a.did.clone(),
        handle: a.handle.clone(),
        session_jwt: a.session_jwt.clone(),
        key,
        access: t.access,
        scope: t.scope,
        holder: Holder::new(),
    }
}

/// The actor's OAuth token and DPoP key presented to another PDS.
pub async fn post_at(a: &SpaceClient, base: &str, nsid: &str, body: J) -> Resp {
    let srv = oauth::Srv { app: a.srv.app.clone(), base: base.into(), http: a.srv.http.clone() };
    let r = oauth::xrpc_dpop(&srv, &a.key, &a.access, "POST", nsid, Some(body)).await;
    Resp { status: r.status, headers: r.headers, body: serde_json::to_vec(&r.body).unwrap().into(), json: r.body }
}

/// uploadBlob over the actor's password session (a public method).
pub async fn upload_blob(actor: &SpaceClient, bytes: &[u8]) -> J {
    let x = Xrpc::new(&actor.srv.base);
    let r = x
        .post_bytes(
            "com.atproto.repo.uploadBlob",
            bytes.to_vec(),
            "image/png",
            &Auth::Bearer(actor.session_jwt.clone()),
        )
        .await;
    r.ok()["blob"].clone()
}

pub fn blob_cid(blob: &J) -> String {
    blob["ref"]["$link"].as_str().unwrap().to_string()
}

pub async fn public_get_blob(base: &str, did: &str, cid: &str) -> Resp {
    Xrpc::new(base).get("com.atproto.sync.getBlob", &[("did", did), ("cid", cid)], &Auth::None).await
}

// ---------------------------------------------------------------------------
// space credentials
// ---------------------------------------------------------------------------

/// A space credential and the holder key it's bound to.
pub struct Cred {
    pub credential: String,
    pub holder: Holder,
    pub http: reqwest::Client,
}

impl Cred {
    pub fn claims(&self) -> J {
        jwt_claims(&self.credential)
    }

    /// The same credential presented with another key.
    pub fn rebound(&self, holder: Holder) -> Cred {
        Cred { credential: self.credential.clone(), holder, http: self.http.clone() }
    }

    pub fn jti(&self) -> String {
        self.claims()["jti"].as_str().unwrap().to_string()
    }

    /// A GET at `base`, signed for `repo`, else the space's authority.
    pub async fn get(&self, base: &str, nsid: &str, query: &[(&str, &str)]) -> Resp {
        let find = |k: &str| query.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
        let aud = find("repo").unwrap_or_else(|| authority_of(find("space").expect("a space param"))).to_string();
        self.get_for(base, nsid, query, &aud).await
    }

    pub async fn get_for(&self, base: &str, nsid: &str, query: &[(&str, &str)], aud: &str) -> Resp {
        signed_get_as(&self.http, &self.holder, base, nsid, query, &self.credential, aud).await
    }

    pub async fn post(&self, base: &str, nsid: &str, body: J) -> Resp {
        let aud = body["repo"].as_str().unwrap_or_else(|| authority_of(body["space"].as_str().unwrap())).to_string();
        let mut rb = self.http.post(format!("{base}/xrpc/{nsid}"));
        for (k, v) in self.holder.headers(&format!("Atproto-Space {}", self.credential), Some(&aud)) {
            rb = rb.header(k, v);
        }
        resp(rb.json(&body).send().await.unwrap()).await
    }

    /// The signed headers for `aud` (`createSpaceSigHeaders`).
    pub fn headers(&self, aud: &str) -> Vec<(String, String)> {
        self.holder.headers(&format!("Atproto-Space {}", self.credential), Some(aud))
    }
}

/// A GET at `base` with exactly these headers.
pub async fn raw_get(base: &str, nsid: &str, query: &[(&str, &str)], headers: &[(String, String)]) -> Resp {
    let mut rb = reqwest::Client::new().get(xrpc_url(base, nsid, query));
    for (k, v) in headers {
        rb = rb.header(k, v);
    }
    resp(rb.send().await.unwrap()).await
}

pub async fn raw_post(base: &str, nsid: &str, body: J, headers: &[(String, String)]) -> Resp {
    let mut rb = reqwest::Client::new().post(format!("{base}/xrpc/{nsid}"));
    for (k, v) in headers {
        rb = rb.header(k, v);
    }
    resp(rb.json(&body).send().await.unwrap()).await
}

/// A space token signed by `key` as `iss` (the reference's
/// `createSpaceToken`), for tokens no endpoint would mint.
pub fn space_token(ty: TokenType, key: &vlatproto::crypto::Keypair, m: Mint) -> String {
    token::encode(ty, &m, "ES256K", now_secs(), &token::new_jti(), |b| Ok::<_, ()>(key.sign(b))).unwrap()
}

// ---------------------------------------------------------------------------
// MockService
// ---------------------------------------------------------------------------

/// One request a [`MockService`] received.
#[derive(Clone, Debug)]
pub struct Call {
    /// `/xrpc/<lxm>`.
    pub lxm: String,
    /// The JSON body, or the query as an object.
    pub body: J,
    pub auth: Option<String>,
}

/// A did:web on loopback whose document names an `#atproto` key and the
/// given services, all pointing at itself. Records every XRPC call and
/// answers with [`MockService::respond`]'s status and body.
pub struct MockService {
    pub did: String,
    pub url: String,
    pub service_id: String,
    pub key: Arc<vlatproto::crypto::Keypair>,
    calls: Arc<Mutex<Vec<Call>>>,
    respond: Arc<Mutex<(u16, J)>>,
    /// Answers used once each, ahead of `respond`.
    queued: Arc<Mutex<std::collections::VecDeque<(u16, J)>>>,
    doc_ok: Arc<AtomicBool>,
    /// Held by a test to stall every call after it is recorded.
    pub gate: Arc<tokio::sync::Mutex<()>>,
}

impl MockService {
    /// `services`: (id without '#', type); the first is [`Self::service_ref`]'s.
    pub async fn spawn(services: &[(&str, &str)]) -> MockService {
        use axum::response::IntoResponse;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (did, url) = (format!("did:web:127.0.0.1%3A{}", addr.port()), format!("http://{addr}"));
        let key = Arc::new(vlatproto::crypto::Keypair::generate());
        let service: Vec<J> = services
            .iter()
            .map(|(id, ty)| json!({"id": format!("#{id}"), "type": ty, "serviceEndpoint": url}))
            .collect();
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": key.did_key().strip_prefix("did:key:").unwrap(),
            }],
            "service": service,
        });
        let calls: Arc<Mutex<Vec<Call>>> = Default::default();
        let respond = Arc::new(Mutex::new((200u16, json!({}))));
        let doc_ok = Arc::new(AtomicBool::new(true));
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let queued: Arc<Mutex<std::collections::VecDeque<(u16, J)>>> = Default::default();
        let (c, r, d, g, q) = (calls.clone(), respond.clone(), doc_ok.clone(), gate.clone(), queued.clone());
        let router = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let (c, r, d, g, q, doc) = (c.clone(), r.clone(), d.clone(), g.clone(), q.clone(), doc.clone());
            async move {
                let path = req.uri().path().to_string();
                if path == "/.well-known/did.json" {
                    return match d.load(Ordering::SeqCst) {
                        true => axum::Json(doc).into_response(),
                        false => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    };
                }
                let Some(lxm) = path.strip_prefix("/xrpc/").map(String::from) else {
                    return axum::http::StatusCode::NOT_FOUND.into_response();
                };
                let query = J::Object(
                    reqwest::Url::parse(&format!("http://h{}", req.uri()))
                        .map(|u| u.query_pairs().map(|(k, v)| (k.into_owned(), J::String(v.into_owned()))).collect())
                        .unwrap_or_default(),
                );
                let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(String::from);
                let raw = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap_or_default();
                let body = match raw.is_empty() {
                    true => query,
                    false => {
                        serde_json::from_slice(&raw).unwrap_or_else(|_| J::String(String::from_utf8_lossy(&raw).into()))
                    }
                };
                c.lock().push(Call { lxm, body, auth });
                drop(g.lock().await);
                let next = q.lock().pop_front();
                let (status, body) = next.unwrap_or_else(|| r.lock().clone());
                (axum::http::StatusCode::from_u16(status).unwrap(), axum::Json(body)).into_response()
            }
        });
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        MockService {
            did,
            url,
            service_id: services.first().map(|s| s.0.to_string()).unwrap_or_default(),
            key,
            calls,
            respond,
            queued,
            doc_ok,
            gate,
        }
    }

    /// A remote space host (`#atproto_space_host`, `#atproto_pds`).
    pub async fn space_host() -> MockService {
        Self::spawn(&[("atproto_space_host", "AtprotoSpaceHost"), ("atproto_pds", "AtprotoPersonalDataServer")]).await
    }

    /// A syncing service (`#atproto_space_syncer`).
    pub async fn syncer() -> MockService {
        Self::spawn(&[("atproto_space_syncer", "AtprotoSpaceService")]).await
    }

    /// `did#serviceId`, the form a notify target or managing app is named by.
    pub fn service_ref(&self) -> String {
        format!("{}#{}", self.did, self.service_id)
    }

    pub fn respond(&self, status: u16, body: J) {
        *self.respond.lock() = (status, body);
    }

    /// Answer the next call (after any already queued) with this, once.
    pub fn respond_once(&self, status: u16, body: J) {
        self.queued.lock().push_back((status, body));
    }

    /// Serve the DID document (`true`) or answer it with a 500.
    pub fn serve_doc(&self, ok: bool) {
        self.doc_ok.store(ok, Ordering::SeqCst);
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().clone()
    }

    pub fn calls_to(&self, lxm: &str) -> Vec<Call> {
        self.calls().into_iter().filter(|c| c.lxm == lxm).collect()
    }

    /// Waits until `n` calls to `lxm` have arrived (None: they didn't
    /// within `within`).
    pub async fn await_calls(&self, lxm: &str, n: usize, within: Duration) -> Option<Vec<Call>> {
        eventually(within, || {
            let v = self.calls_to(lxm);
            std::future::ready((v.len() >= n).then_some(v))
        })
        .await
    }

    /// A space token signed by this DID's key.
    pub fn token(&self, ty: TokenType, m: Mint) -> String {
        space_token(ty, &self.key, m)
    }
}

// ---------------------------------------------------------------------------
// MockClientApp
// ---------------------------------------------------------------------------

/// How a [`MockClientApp`] publishes its keys.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Keys {
    /// `jwks_uri`, served.
    Uri,
    /// `jwks_uri`, answering 404.
    UriMissing,
    /// An inline `jwks`.
    Inline,
    None,
}

/// An OAuth client publishing `client-metadata.json` (and a JWKS) over
/// HTTP on a loopback IP, signing client attestations with ES256.
pub struct MockClientApp {
    pub client_id: String,
    pub jwks_uri: String,
    pub key: p256::ecdsa::SigningKey,
    pub kid: String,
    keys: Arc<Mutex<Keys>>,
    metadata_ok: Arc<AtomicBool>,
}

/// An ES256 public JWK.
pub fn p256_jwk(key: &p256::ecdsa::SigningKey, kid: &str) -> J {
    let p = key.verifying_key().to_sec1_point(false);
    let b = p.as_bytes();
    json!({"kty": "EC", "crv": "P-256", "x": b64url(&b[1..33]), "y": b64url(&b[33..65]), "kid": kid, "alg": "ES256", "use": "sig"})
}

pub fn new_p256() -> p256::ecdsa::SigningKey {
    <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate()
}

/// What to put in an attestation (`MockClientApp.attest`'s options).
#[derive(Default)]
pub struct Attest<'a> {
    pub sign_with: Option<&'a p256::ecdsa::SigningKey>,
    pub iss: Option<&'a str>,
    pub sub: Option<&'a str>,
    pub expires_in: Option<i64>,
    /// Some(None): no `jti` claim.
    pub jti: Option<Option<&'a str>>,
}

impl MockClientApp {
    pub async fn spawn(keys: Keys) -> MockClientApp {
        use axum::response::IntoResponse;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (client_id, jwks_uri) = (format!("{base}/client-metadata.json"), format!("{base}/jwks.json"));
        let key = new_p256();
        let kid = "key-1".to_string();
        let jwk = p256_jwk(&key, &kid);
        let keys = Arc::new(Mutex::new(keys));
        let metadata_ok = Arc::new(AtomicBool::new(true));
        let (k, m, cid, ju) = (keys.clone(), metadata_ok.clone(), client_id.clone(), jwks_uri.clone());
        let router = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let (k, m, cid, ju, jwk) = (k.clone(), m.clone(), cid.clone(), ju.clone(), jwk.clone());
            async move {
                let keys = *k.lock();
                match req.uri().path() {
                    "/client-metadata.json" if m.load(Ordering::SeqCst) => {
                        let mut md = json!({
                            "client_id": cid,
                            "client_name": "Mock Space App",
                            // a web client may not redirect to a loopback address
                            "redirect_uris": ["https://app.example.com/cb"],
                            "response_types": ["code"],
                            "grant_types": ["authorization_code"],
                            "scope": "atproto",
                            "application_type": "web",
                            "token_endpoint_auth_method": "private_key_jwt",
                            "token_endpoint_auth_signing_alg": "ES256",
                            "dpop_bound_access_tokens": true,
                        });
                        match keys {
                            Keys::Uri | Keys::UriMissing => md["jwks_uri"] = json!(ju),
                            Keys::Inline => md["jwks"] = json!({"keys": [jwk]}),
                            Keys::None => {}
                        }
                        axum::Json(md).into_response()
                    }
                    "/jwks.json" if keys == Keys::Uri => axum::Json(json!({"keys": [jwk]})).into_response(),
                    _ => axum::http::StatusCode::NOT_FOUND.into_response(),
                }
            }
        });
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        MockClientApp { client_id, jwks_uri, key, kid, keys, metadata_ok }
    }

    pub fn set_keys(&self, k: Keys) {
        *self.keys.lock() = k;
    }

    /// Serve the client metadata (`true`) or answer it with a 404.
    pub fn serve_metadata(&self, ok: bool) {
        self.metadata_ok.store(ok, Ordering::SeqCst);
    }

    /// An attestation for `space_host` (`spaceHostAud(authority)`).
    pub fn attest(&self, space_host: &str, o: Attest) -> String {
        use p256::ecdsa::signature::Signer;
        let now = now_secs();
        let header = json!({"alg": "ES256", "typ": "atproto-client-attestation+jwt", "kid": self.kid});
        let mut claims = json!({
            "iss": o.iss.unwrap_or(&self.client_id),
            "sub": o.sub.or(o.iss).unwrap_or(&self.client_id),
            "aud": space_host,
            "iat": now,
            "exp": now + o.expires_in.unwrap_or(60),
        });
        match o.jti {
            Some(None) => {}
            Some(Some(j)) => claims["jti"] = json!(j),
            None => claims["jti"] = json!(token::new_jti()),
        }
        let input = format!("{}.{}", b64url(header.to_string()), b64url(claims.to_string()));
        let sig: p256::ecdsa::Signature = o.sign_with.unwrap_or(&self.key).sign(input.as_bytes());
        format!("{input}.{}", b64url(sig.to_bytes()))
    }
}

/// The reference harness itself: a [`MockService`] serves its DID document
/// and records calls with the configured answer, and a [`MockClientApp`]'s
/// attestation verifies against the key its metadata publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ref_harness_self_check() {
    let svc = MockService::syncer().await;
    let http = reqwest::Client::new();
    let doc: J = http.get(format!("{}/.well-known/did.json", svc.url)).send().await.unwrap().json().await.unwrap();
    assert_eq!(doc["id"], json!(svc.did));
    assert_eq!(doc["service"][0]["id"], json!("#atproto_space_syncer"));
    assert_eq!(svc.service_ref(), format!("{}#atproto_space_syncer", svc.did));
    svc.respond(503, json!({"error": "Unavailable"}));
    let r = http
        .post(format!("{}/xrpc/com.atproto.space.notifyWrite", svc.url))
        .header("authorization", "Bearer x")
        .json(&json!({"space": "at://did:plc:a/space/a.b.c/k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 503);
    let calls = svc.calls_to("com.atproto.space.notifyWrite");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].body["space"], json!("at://did:plc:a/space/a.b.c/k"));
    assert_eq!(calls[0].auth.as_deref(), Some("Bearer x"));
    svc.serve_doc(false);
    assert_eq!(http.get(format!("{}/.well-known/did.json", svc.url)).send().await.unwrap().status().as_u16(), 500);

    let app = MockClientApp::spawn(Keys::Uri).await;
    let md: J = http.get(&app.client_id).send().await.unwrap().json().await.unwrap();
    assert_eq!(md["client_id"], json!(app.client_id));
    let jwks: J = http.get(md["jwks_uri"].as_str().unwrap()).send().await.unwrap().json().await.unwrap();
    let att = app.attest("did:plc:x#atproto_space_host", Attest::default());
    let parts: Vec<&str> = att.split('.').collect();
    let jwk = &jwks["keys"][0];
    let dec = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap();
    let mut sec1 = vec![4u8];
    sec1.extend(dec(jwk["x"].as_str().unwrap()));
    sec1.extend(dec(jwk["y"].as_str().unwrap()));
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sig = p256::ecdsa::Signature::from_slice(&dec(parts[2])).unwrap();
    use p256::ecdsa::signature::Verifier;
    vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).expect("attestation signed by the published key");
    let claims = jwt_claims(&att);
    assert_eq!(
        (claims["iss"].clone(), claims["aud"].clone()),
        (json!(app.client_id), json!("did:plc:x#atproto_space_host"))
    );
    assert!(claims["jti"].is_string());
    assert!(jwt_claims(&app.attest("a", Attest { jti: Some(None), ..Default::default() }))["jti"].is_null());
    app.set_keys(Keys::UriMissing);
    assert_eq!(http.get(&app.jwks_uri).send().await.unwrap().status().as_u16(), 404);

    let tok = svc.token(
        TokenType::Delegation,
        Mint { iss: &svc.did, sub: "at://x/space/a.b.c/k", aud: Some("y"), ..Default::default() },
    );
    let parsed = token::parse(TokenType::Delegation, &tok).unwrap();
    parsed.verify_signature(&svc.key.did_key()).expect("a hand-minted token verifies under its signer's key");
    assert!(tid_at(600_000_000) > tid_at(0));
    let later = tid_at(60_000_000);
    assert!(next_tid(Some(&later)) > later);
}
