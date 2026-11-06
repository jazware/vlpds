//! Spaces test client ([`SpaceClient`]): an OAuth account granted `space:`
//! scopes (tests/all/oauth.rs `grant`), a P-256 did:key holder for the
//! credential exchange, and signed reads (`vlpds::space::httpsig`).
//!
//! - `SpaceClient::new(&server, name, scope)`: account, PAR, consent, token.
//! - `get`/`post`: DPoP-authenticated XRPC as that account.
//! - `credential(space)`: getDelegationToken, then getSpaceCredential at the
//!   authority's host, bound to the holder key (`credentialKid`).
//! - `signed_get(base, nsid, query, credential, audience)`: a read with
//!   `Authorization: Atproto-Space-Credential`, signed over the
//!   authorization and audience headers; a read that returns a commit or a
//!   record asks for a MAC against the repo's `#atproto_kem` key and checks
//!   the one that comes back, as a syncer must.

use super::{Resp, TestServer};
use crate::oauth::{self, Browser, DpopKey, Flow, Srv};
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value as J};
use vlpds::space::{commit, httpsig, mac};

pub struct SpaceClient {
    pub srv: Srv,
    pub did: String,
    pub handle: String,
    /// The account's password session (legacy auth).
    pub session_jwt: String,
    pub key: DpopKey,
    pub access: String,
    pub scope: String,
    pub holder: Holder,
}

/// A P-256 did:key: the key a space credential is bound to.
pub struct Holder {
    pub sk: p256::ecdsa::SigningKey,
    pub did: String,
}

impl Holder {
    pub fn new() -> Holder {
        let sk = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
        let mut mk = vec![0x80, 0x24];
        mk.extend_from_slice(sk.verifying_key().to_sec1_point(true).as_bytes());
        Holder { sk, did: format!("did:key:z{}", bs58::encode(mk).into_string()) }
    }

    fn sign(&self, base: &[u8]) -> String {
        use base64::Engine;
        let sig: p256::ecdsa::Signature = self.sk.sign(base);
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    /// The headers of a request with `credential` to `audience`, signed as
    /// the reference's client signs them (`createSpaceSigHeaders`).
    pub fn headers(&self, credential: &str, audience: &str) -> Vec<(String, String)> {
        httpsig::sign_headers(credential, audience, |b| {
            let sig: p256::ecdsa::Signature = self.sk.sign(b);
            sig.to_bytes().into()
        })
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    /// A signature over `authorization` and `audience` as given (a test's
    /// own scheme or parameters), the label's and tag's as the client's.
    pub fn sign_raw(&self, authorization: &str, audience: &str) -> String {
        self.sign(&httpsig::signature_base(authorization, audience, &httpsig::signature_input()))
    }
}

impl Default for Holder {
    fn default() -> Self {
        Holder::new()
    }
}

/// `https?://.../xrpc/{nsid}?{query}`, the query form-encoded.
pub fn xrpc_url(base: &str, nsid: &str, query: &[(&str, &str)]) -> String {
    let q: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", oauth::enc(k), oauth::enc(v))).collect();
    match q.is_empty() {
        true => format!("{base}/xrpc/{nsid}"),
        false => format!("{base}/xrpc/{nsid}?{}", q.join("&")),
    }
}

pub async fn resp(r: reqwest::Response) -> Resp {
    let status = r.status().as_u16();
    let headers = r.headers().clone();
    let body = r.bytes().await.unwrap_or_default();
    let json = serde_json::from_slice(&body).unwrap_or(J::Null);
    Resp { status, headers, body, json }
}

fn oauth_resp(r: oauth::Resp) -> Resp {
    let body = bytes::Bytes::from(serde_json::to_vec(&r.body).unwrap());
    Resp { status: r.status, headers: r.headers, body, json: r.body }
}

/// A space URI.
pub fn space_uri(authority: &str, space_type: &str, skey: &str) -> String {
    format!("at://{authority}/space/{space_type}/{skey}")
}

impl SpaceClient {
    /// A new account on `s`, which a loopback client is granted `scope` for
    /// (`atproto` is added if missing).
    pub async fn new(s: &TestServer, name: &str, scope: &str) -> SpaceClient {
        let srv = Srv {
            app: s.app.clone(),
            base: s.url.clone(),
            http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
        };
        let acct = oauth::create_account(&srv, name).await;
        let scope = match scope.split(' ').any(|x| x == "atproto") {
            true => scope.to_string(),
            false => format!("atproto {scope}"),
        };
        let key = DpopKey::new();
        let t = oauth::grant(&srv, &mut Browser::default(), &Flow::loopback(&scope, &key), &acct).await;
        SpaceClient {
            srv,
            did: acct.did,
            handle: acct.handle,
            session_jwt: acct.jwt,
            key,
            access: t.access,
            scope: t.scope,
            holder: Holder::new(),
        }
    }

    pub async fn get(&self, nsid: &str, query: &[(&str, &str)]) -> Resp {
        let path = xrpc_url("", nsid, query);
        let nsid = path.strip_prefix("/xrpc/").unwrap();
        oauth_resp(oauth::xrpc_dpop(&self.srv, &self.key, &self.access, "GET", nsid, None).await)
    }

    /// A GET whose answer isn't JSON (getRepo's CAR): status, content type
    /// and body.
    pub async fn get_raw(&self, nsid: &str, query: &[(&str, &str)]) -> (u16, String, Vec<u8>) {
        let url = xrpc_url(&self.srv.base, nsid, query);
        for attempt in 0..2 {
            let r = self
                .srv
                .http
                .get(&url)
                .header("dpop", self.key.proof("GET", &url, Some(&self.access)))
                .header("authorization", format!("DPoP {}", self.access))
                .send()
                .await
                .unwrap();
            let status = r.status().as_u16();
            self.key.update_nonce(r.headers());
            let ctype = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let body = r.bytes().await.unwrap().to_vec();
            let nonce = serde_json::from_slice::<J>(&body).is_ok_and(|j| j["error"] == "use_dpop_nonce");
            if attempt == 0 && nonce {
                continue;
            }
            return (status, ctype, body);
        }
        unreachable!()
    }

    /// A POST of raw bytes (importRepo's CAR) with a query.
    pub async fn post_bytes(&self, nsid: &str, query: &[(&str, &str)], body: Vec<u8>, ctype: &str) -> Resp {
        let url = xrpc_url(&self.srv.base, nsid, query);
        for attempt in 0..2 {
            let r = self
                .srv
                .http
                .post(&url)
                .header("dpop", self.key.proof("POST", &url, Some(&self.access)))
                .header("authorization", format!("DPoP {}", self.access))
                .header("content-type", ctype)
                .body(body.clone())
                .send()
                .await
                .unwrap();
            self.key.update_nonce(r.headers());
            let out = resp(r).await;
            if attempt == 0 && out.json["error"] == "use_dpop_nonce" {
                continue;
            }
            return out;
        }
        unreachable!()
    }

    /// An existing account on `s` (its password `oauth::PASSWORD`),
    /// which a loopback client is granted `scope` for.
    pub async fn for_account(s: &TestServer, did: &str, handle: &str, session_jwt: &str, scope: &str) -> SpaceClient {
        let srv = Srv {
            app: s.app.clone(),
            base: s.url.clone(),
            http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
        };
        let acct = oauth::Account { did: did.into(), handle: handle.into(), jwt: session_jwt.into() };
        let scope = match scope.split(' ').any(|x| x == "atproto") {
            true => scope.to_string(),
            false => format!("atproto {scope}"),
        };
        let key = DpopKey::new();
        let t = oauth::grant(&srv, &mut Browser::default(), &Flow::loopback(&scope, &key), &acct).await;
        SpaceClient {
            srv,
            did: acct.did,
            handle: acct.handle,
            session_jwt: acct.jwt,
            key,
            access: t.access,
            scope: t.scope,
            holder: Holder::new(),
        }
    }

    pub async fn post(&self, nsid: &str, body: J) -> Resp {
        oauth_resp(oauth::xrpc_dpop(&self.srv, &self.key, &self.access, "POST", nsid, Some(body)).await)
    }

    /// simplespace.createSpace with the default policies; the space's URI.
    pub async fn create_space(&self, space_type: &str, skey: &str) -> String {
        let r = self
            .post(
                "com.atproto.simplespace.createSpace",
                json!({
                    "spaceType": space_type,
                    "skey": skey,
                    "readPolicy": {"$type": "com.atproto.simplespace.defs#memberListPolicy"},
                    "writePolicy": {"$type": "com.atproto.simplespace.defs#memberListPolicy"},
                    "appAccess": {"$type": "com.atproto.simplespace.defs#open"},
                }),
            )
            .await;
        r.ok()["uri"].as_str().unwrap().to_string()
    }

    pub async fn create_record(&self, space: &str, collection: &str, rkey: Option<&str>, record: J) -> Resp {
        let mut body = json!({"space": space, "repo": self.did, "collection": collection, "record": record});
        if let Some(r) = rkey {
            body["rkey"] = json!(r);
        }
        self.post("com.atproto.space.createRecord", body).await
    }

    pub async fn put_record(&self, space: &str, collection: &str, rkey: &str, record: J) -> Resp {
        let body = json!({"space": space, "repo": self.did, "collection": collection, "rkey": rkey, "record": record});
        self.post("com.atproto.space.putRecord", body).await
    }

    pub async fn delete_record(&self, space: &str, collection: &str, rkey: &str) -> Resp {
        let body = json!({"space": space, "repo": self.did, "collection": collection, "rkey": rkey});
        self.post("com.atproto.space.deleteRecord", body).await
    }

    pub async fn apply_writes(&self, space: &str, writes: J) -> Resp {
        self.post("com.atproto.space.applyWrites", json!({"space": space, "repo": self.did, "writes": writes})).await
    }

    pub async fn delegation_token(&self, space: &str) -> Resp {
        self.get("com.atproto.space.getDelegationToken", &[("space", space)]).await
    }

    /// getSpaceCredential at `host` (the authority's PDS) for `token`,
    /// signed by this client's holder key.
    pub async fn exchange(&self, host: &str, space: &str, token: &str) -> Resp {
        self.exchange_as(&self.holder, host, space, token).await
    }

    pub async fn exchange_as(&self, holder: &Holder, host: &str, space: &str, token: &str) -> Resp {
        self.exchange_with(holder, host, space, token, None).await
    }

    /// getSpaceCredential with a client attestation (an `appAccess` allow
    /// list's proof of which app asks).
    pub async fn exchange_with(
        &self,
        holder: &Holder,
        host: &str,
        space: &str,
        token: &str,
        attestation: Option<&str>,
    ) -> Resp {
        let mut body = json!({"space": space, "credentialKid": holder.did, "delegationToken": token});
        if let Some(a) = attestation {
            body["clientAttestation"] = json!(a);
        }
        get_space_credential(&self.srv.http, host, body).await
    }

    /// A fresh delegation token for `space` exchanged at `host`, with an
    /// optional client attestation; the response as is.
    pub async fn try_credential_at(&self, host: &str, space: &str, attestation: Option<&str>) -> Resp {
        let token = self.delegation_token(space).await.ok()["token"].as_str().unwrap().to_string();
        self.exchange_with(&self.holder, host, space, &token, attestation).await
    }

    /// A credential for `space` from the authority at `host`: the whole
    /// chain, each step asserted to succeed.
    pub async fn credential_at(&self, host: &str, space: &str) -> String {
        let token = self.delegation_token(space).await.ok()["token"].as_str().unwrap().to_string();
        let r = self.exchange(host, space, &token).await;
        r.ok()["credential"].as_str().unwrap().to_string()
    }

    /// [`Self::credential_at`] on this client's own PDS.
    pub async fn credential(&self, space: &str) -> String {
        let host = self.srv.base.clone();
        self.credential_at(&host, space).await
    }

    /// A read at `base` with `credential`, signed for `audience` by this
    /// client's holder key.
    pub async fn signed_get(
        &self,
        base: &str,
        nsid: &str,
        query: &[(&str, &str)],
        credential: &str,
        audience: &str,
    ) -> Resp {
        signed_get_as(&self.srv.http, &self.holder, base, nsid, query, credential, audience).await
    }

    pub async fn signed_post(&self, base: &str, nsid: &str, body: J, credential: &str, audience: &str) -> Resp {
        signed_post_as(&self.srv.http, &self.holder, base, nsid, body, credential, audience).await
    }
}

/// A credential call with a JSON body (registerNotify, unregisterNotify),
/// signed by `holder`.
pub async fn signed_post_as(
    http: &reqwest::Client,
    holder: &Holder,
    base: &str,
    nsid: &str,
    body: J,
    credential: &str,
    audience: &str,
) -> Resp {
    let mut rb = http.post(xrpc_url(base, nsid, &[]));
    for (k, v) in holder.headers(credential, audience) {
        rb = rb.header(k, v);
    }
    resp(rb.json(&body).send().await.unwrap()).await
}

/// getSpaceCredential at `host` with `body` as is.
pub async fn get_space_credential(http: &reqwest::Client, host: &str, body: J) -> Resp {
    resp(http.post(format!("{host}/xrpc/com.atproto.space.getSpaceCredential")).json(&body).send().await.unwrap())
        .await
}

/// The MAC type of a method that returns one.
pub fn mac_type(nsid: &str) -> Option<&'static str> {
    match nsid {
        "com.atproto.space.getLatestCommit" | "com.atproto.space.getRepo" | "com.atproto.space.listRepoOps" => {
            Some(mac::COMMIT_MAC_TYPE)
        }
        "com.atproto.space.getRecord" => Some(mac::RECORD_MAC_TYPE),
        _ => None,
    }
}

/// `did`'s `#atproto_kem` key, as `base` resolves its DID.
pub async fn kem_key_at(http: &reqwest::Client, base: &str, did: &str) -> Option<String> {
    let r = resp(http.get(xrpc_url(base, "com.atproto.identity.resolveDid", &[("did", did)])).send().await.unwrap()).await;
    vlpds::space::kem::kem_key_of(&r.json["didDoc"])
}

/// A fresh key share against `repo`'s KEM key (resolved at `base`): the
/// `Atproto-Space-Want-Mac` value for `ty` and the shared secret.
pub async fn want_mac(http: &reqwest::Client, base: &str, repo: &str, ty: &str) -> (String, [u8; 32]) {
    let kem = kem_key_at(http, base, repo).await.unwrap_or_else(|| panic!("{repo} has no #atproto_kem key"));
    let (share, secret) = vlpds::space::kem::encapsulate(&kem).unwrap();
    (mac::format_want_mac(ty, &share), secret)
}

/// Asserts a successful MAC-bearing response's MAC (verifyCommit /
/// verifyRecord past the MAC): the commit's or record's, under `secret`.
pub fn check_mac(nsid: &str, query: &[(&str, &str)], r: &Resp, secret: &[u8; 32]) {
    let Some(ty) = mac_type(nsid) else { return };
    let q = |k: &str| query.iter().find(|(n, _)| *n == k).map(|(_, v)| *v).unwrap_or_default();
    let header = r.headers.get(mac::MAC_HEADER).and_then(|v| v.to_str().ok());
    if r.status != 200 {
        return;
    }
    assert!(
        r.headers.get_all("vary").iter().any(|v| v.to_str().unwrap_or("").contains("Atproto-Space-Want-Mac")),
        "{nsid}: Vary names Atproto-Space-Want-Mac"
    );
    let commit = match nsid {
        "com.atproto.space.getRepo" => Some(vlpds::space::star::parse(&r.body).expect("a STAR archive").commit),
        "com.atproto.space.getRecord" => None,
        _ if r.json.get("commit").is_some() => Some(commit::Commit::from_json(&r.json["commit"]).unwrap()),
        // a listRepoOps page short of the head: no commit, no MAC
        _ => {
            assert!(header.is_none(), "{nsid}: a MAC without a commit");
            return;
        }
    };
    let m = mac::parse_mac(header, ty).unwrap_or_else(|e| panic!("{nsid}: {e}"));
    match commit {
        Some(c) => assert!(commit::verify(&c, q("space"), q("repo"), secret, &m), "{nsid}: the commit's MAC"),
        None => {
            let (uri, cid) = (r.json["uri"].as_str().unwrap(), r.json["cid"].as_str().unwrap());
            let cid = vlatproto::cid::Cid::parse(cid).unwrap().to_bytes();
            assert!(mac::verify_record_mac(secret, uri, &cid, &m), "{nsid}: the record's MAC");
            let value = vlatproto::cbor::Value::from_json(&r.json["value"]).unwrap().to_cbor();
            assert_eq!(vlatproto::cid::Cid::dag_cbor(&value).to_bytes(), cid, "{nsid}: the record is its CID");
        }
    }
}

/// A credential read signed by `holder`.
pub async fn signed_get_as(
    http: &reqwest::Client,
    holder: &Holder,
    base: &str,
    nsid: &str,
    query: &[(&str, &str)],
    credential: &str,
    audience: &str,
) -> Resp {
    let mut rb = http.get(xrpc_url(base, nsid, query));
    for (k, v) in holder.headers(credential, audience) {
        rb = rb.header(k, v);
    }
    let mut secret = None;
    if let Some(ty) = mac_type(nsid) {
        let repo = query.iter().find(|(k, _)| *k == "repo").map(|(_, v)| *v).unwrap_or(audience);
        // a repo whose host (here) has no KEM key for it is asked anyway
        if let Some(kem) = kem_key_at(http, base, repo).await {
            let (share, s) = vlpds::space::kem::encapsulate(&kem).unwrap();
            rb = rb.header(mac::WANT_MAC_HEADER, mac::format_want_mac(ty, &share));
            secret = Some(s);
        }
    }
    let r = resp(rb.send().await.unwrap()).await;
    if let Some(s) = &secret {
        check_mac(nsid, query, &r, s);
    }
    r
}

/// What a getRepo archive holds, checked as the reference's
/// `verifyRepoStarFull` checks one past the MAC ([`signed_get_as`] checks
/// that): the metadata names `repo` in `space`, the paths are in strict
/// order, and the records fold to the commit's data.
pub struct Star {
    pub commit: commit::Commit,
    pub paths: Vec<String>,
    pub records: Vec<(String, Vec<u8>)>,
}

pub fn verify_star(body: &[u8], space: &str, repo: &str) -> Star {
    let p = vlpds::space::star::parse(body).unwrap_or_else(|e| panic!("a STAR archive: {e}"));
    assert_eq!((p.commit.space.as_str(), p.commit.repo.as_str()), (space, repo), "the archive's commit");
    assert_eq!(p.commit.ver, 1);
    let paths = p.records.iter().map(|(k, _)| k.clone()).collect();
    Star { commit: p.commit, paths, records: p.records }
}

/// A commit from its JSON (`com.atproto.space.defs#commit`).
pub fn commit_of(c: &J) -> commit::Commit {
    commit::Commit::from_json(c).unwrap_or_else(|e| panic!("{e}: {c}"))
}
