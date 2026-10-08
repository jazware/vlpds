//! Permission-set lexicons for `include:` scopes, and space type
//! declarations for bare `space:` grants, resolved the atproto way (DNS
//! `_lexicon` authority, then a getRecord proof verified end to end) and
//! persisted, so token refreshes keep working while a publisher is
//! unreachable (as the reference LexiconGetter does).
//!
//! The token endpoint never waits on a publisher it has a copy from: it uses
//! the last good copy and re-resolves a stale one in the background, so a
//! slow publisher can't hold a code exchange or refresh open (and with it
//! the window in which it races a revocation).

use super::scopes::{is_nsid, IncludeScope, Permission};
use super::store::{self, StoredLexicon};
use super::util::now_secs;
use crate::lexicon::SpaceDecl;
use crate::xrpc::App;
use serde_json::Value as J;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use vlsync_atproto::cbor::Value;
use vlsync_atproto::cid::Cid;

const REFRESH: Duration = Duration::from_secs(300);
/// After a failed background re-resolution.
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// For a permission set with no copy anywhere.
const INLINE_BUDGET: Duration = Duration::from_secs(3);
const LEXICON_COLLECTION: &str = "com.atproto.lexicon.schema";
const MAX_CAR_BYTES: usize = 1 << 20;

type LexiconCache = parking_lot::Mutex<HashMap<String, (Instant, J)>>;

/// Stale entries are the fallback while a publisher is unreachable.
static CACHE: LazyLock<Arc<LexiconCache>> =
    LazyLock::new(|| crate::caches::track(crate::caches::Cache::PermissionSets, Default::default()));
static OVERRIDES: LazyLock<parking_lot::Mutex<HashMap<String, String>>> = LazyLock::new(Default::default);
/// Being re-resolved in the background.
static IN_FLIGHT: LazyLock<parking_lot::Mutex<std::collections::HashSet<String>>> = LazyLock::new(Default::default);

/// Tests: pins the authority DID of e.g. "example.com" for `com.example.*`,
/// bypassing DNS.
pub fn override_authority(authority: &str, did: &str) {
    OVERRIDES.lock().insert(authority.to_ascii_lowercase(), did.to_string());
}

/// `--lexicon-authority-override <authority>=<did>` (dev mode only): each
/// NSID authority (`example.com` for `com.example.*`) resolves to its DID
/// without the DNS `_lexicon` lookup, so a local app can publish lexicons
/// from a repo on this server. Every entry is checked before any is used.
pub fn apply_authority_overrides(entries: &[String], dev_mode: bool) -> anyhow::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(dev_mode, "--lexicon-authority-override is for development: it needs --dev-mode");
    let mut parsed = Vec::with_capacity(entries.len());
    for e in entries {
        let Some((authority, did)) = e.split_once('=') else {
            anyhow::bail!("--lexicon-authority-override {e:?}: expected <authority>=<did>");
        };
        let authority = authority.trim().to_ascii_lowercase();
        let did = did.trim();
        anyhow::ensure!(
            vlsync_atproto::syntax::valid_handle(&authority),
            "--lexicon-authority-override {e:?}: {authority:?} isn't a domain"
        );
        anyhow::ensure!(
            super::scopes::is_atproto_did(did),
            "--lexicon-authority-override {e:?}: {did:?} isn't a did:plc or did:web"
        );
        parsed.push((authority, did.to_string()));
    }
    for (authority, did) in parsed {
        tracing::warn!(%authority, %did, "lexicon authority overridden (--lexicon-authority-override, dev mode)");
        override_authority(&authority, &did);
    }
    Ok(())
}

/// Tests: drops `nsid`'s in-memory copy, so its next use looks it up again.
pub fn forget_cached(nsid: &str) {
    CACHE.lock().remove(nsid);
}

/// Tests: whether `nsid` has an in-memory copy, i.e. whether it was looked
/// up since [`forget_cached`].
pub fn is_cached(nsid: &str) -> bool {
    CACHE.lock().contains_key(nsid)
}

/// All segments but the name, reversed.
pub fn nsid_authority(nsid: &str) -> String {
    let segs: Vec<&str> = nsid.split('.').collect();
    segs[..segs.len().saturating_sub(1)].iter().rev().cloned().collect::<Vec<_>>().join(".").to_ascii_lowercase()
}

/// What a lexicon document must be to be used (and cached), and what is
/// taken from it.
type Check<T> = fn(&str, &J) -> Result<T, String>;

/// `defs.main`.
async fn permission_set(app: &App, nsid: &str) -> Result<J, String> {
    lexicon(app, nsid, main_def).await
}

async fn lexicon<T: Send>(app: &App, nsid: &str, check: Check<T>) -> Result<T, String> {
    if !is_nsid(nsid) {
        return Err(format!("invalid NSID {nsid}"));
    }
    if let Some((at, doc)) = CACHE.lock().get(nsid) {
        if at.elapsed() < REFRESH {
            return check(nsid, doc);
        }
    }
    match resolve(app, nsid).await {
        Ok((uri, doc)) => {
            let out = check(nsid, &doc)?;
            cache_put(nsid, Instant::now(), doc.clone());
            let stored = StoredLexicon { uri, doc, updated_at: now_secs() };
            if let Err(e) = store::put_lexicon(app, nsid, &stored).await {
                tracing::warn!(nsid, "persisting lexicon failed: {}", e.description);
            }
            Ok(out)
        }
        Err(e) => {
            // the last good copy: memory, then durable
            if let Some((_, doc)) = CACHE.lock().get(nsid) {
                return check(nsid, doc);
            }
            if let Ok(Some(l)) = store::get_lexicon(app, nsid).await {
                cache_put(nsid, Instant::now() - REFRESH + Duration::from_secs(30), l.doc.clone());
                return check(nsid, &l.doc);
            }
            Err(e)
        }
    }
}

/// A full cache drops its stale entries, then all.
fn cache_put(nsid: &str, at: Instant, doc: J) {
    let cap = crate::caches::cap(crate::caches::Cache::PermissionSets);
    let mut m = CACHE.lock();
    if m.len() >= cap && !m.contains_key(nsid) {
        m.retain(|_, (at, _)| at.elapsed() < REFRESH);
        if m.len() >= cap {
            m.clear();
        }
    }
    m.insert(nsid.to_string(), (at, doc));
}

fn main_def(nsid: &str, doc: &J) -> Result<J, String> {
    if doc.get("lexicon").and_then(|v| v.as_i64()) != Some(1) {
        return Err(format!("Invalid Lexicon document for {nsid}"));
    }
    if doc.get("id").and_then(|v| v.as_str()) != Some(nsid) {
        return Err(format!("Invalid document id for {nsid}"));
    }
    let main =
        doc.get("defs").and_then(|d| d.get("main")).ok_or_else(|| format!("Lexicon {nsid} has no main definition"))?;
    if main.get("type").and_then(|v| v.as_str()) != Some("permission-set") {
        return Err(format!("Lexicon document is not a permission set: {nsid}"));
    }
    if !main.get("permissions").is_some_and(|p| p.is_array()) {
        return Err(format!("Invalid permission set {nsid}"));
    }
    Ok(main.clone())
}

/// (at-uri, doc), uncached.
pub(crate) async fn resolve(app: &App, nsid: &str) -> Result<(String, J), String> {
    let did = resolve_authority(nsid).await?;
    let uri = format!("at://{did}/{LEXICON_COLLECTION}/{nsid}");
    let doc = fetch_record(app, &did, nsid).await.map_err(|e| format!("Failed to fetch lexicon at {uri}: {e}"))?;
    Ok((uri, doc))
}

async fn resolve_authority(nsid: &str) -> Result<String, String> {
    let authority = nsid_authority(nsid);
    if let Some(d) = OVERRIDES.lock().get(&authority) {
        return Ok(d.clone());
    }
    let name = format!("_lexicon.{authority}.");
    let fail = |m: String| format!("Failed to resolve lexicon DID authority for {nsid}: {m}");
    let records = tokio::time::timeout(Duration::from_secs(5), crate::handle_resolver::resolver(None).txt(&name))
        .await
        .map_err(|_| fail("DNS timeout".into()))?
        .map_err(fail)?;
    let dids: Vec<String> = records.iter().filter_map(|l| l.strip_prefix("did=").map(String::from)).collect();
    match dids.as_slice() {
        [d] if super::scopes::is_atproto_did(d) => Ok(d.clone()),
        [_] => Err(fail("invalid DID in DNS TXT record".into())),
        [] => Err(fail("No DID found in DNS TXT records".into())),
        _ => Err(fail("Multiple DIDs found in DNS TXT records".into())),
    }
}

async fn fetch_record(app: &App, did: &str, nsid: &str) -> Result<J, String> {
    let rpath = format!("{LEXICON_COLLECTION}/{nsid}");
    // hosted here: no proof needed
    if let Ok(a) = app.account(did).await {
        let v =
            app.record_value(did, Some(a.repo_gen), &rpath).await.map_err(|e| e.message)?.ok_or("Record not found")?;
        let (_, bytes) = crate::state::decode_record_value(&v).map_err(|e| e.to_string())?;
        let rec = Value::decode(&bytes).map_err(|e| e.to_string())?;
        return check_record_type(rec.to_json());
    }
    let doc = app.did_resolver.resolve(did).await.map_err(|e| e.to_string())?;
    let pds = vlsync_atproto::did_resolver::service_endpoint(&doc, "atproto_pds")
        .ok_or("No atproto PDS service endpoint in DID document")?;
    let key =
        vlsync_atproto::did_resolver::signing_key_multibase(&doc).ok_or("No atproto signing key in DID document")?;
    let url = format!(
        "{}/xrpc/com.atproto.sync.getRecord?did={}&collection={}&rkey={}",
        pds.trim_end_matches('/'),
        super::util::encode_uri_component(did),
        LEXICON_COLLECTION,
        super::util::encode_uri_component(nsid)
    );
    let car = fetch_bytes(&url, app.config.dev_mode).await?;
    verify_record_proof(&car, did, &key, &rpath)
}

fn check_record_type(rec: J) -> Result<J, String> {
    if rec.get("$type").and_then(|v| v.as_str()) != Some(LEXICON_COLLECTION) {
        return Err(format!("Invalid record type: expected {LEXICON_COLLECTION}"));
    }
    Ok(rec)
}

async fn fetch_bytes(url: &str, dev_mode: bool) -> Result<Vec<u8>, String> {
    use futures::StreamExt;
    let resp = vlsync_atproto::http::guarded(dev_mode)
        .get(url)?
        .header("accept", "application/vnd.ipld.car")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status()));
    }
    let mut buf = Vec::new();
    let mut s = resp.bytes_stream();
    while let Some(c) = s.next().await {
        let c = c.map_err(|e| e.to_string())?;
        if buf.len() + c.len() > MAX_CAR_BYTES {
            return Err("response too large".into());
        }
        buf.extend_from_slice(&c);
    }
    Ok(buf)
}

/// Every block hashes to its CID, the root commit is `did`'s and signed by
/// `key_multibase`, and its MST maps `rpath` to the included record.
pub fn verify_record_proof(car: &[u8], did: &str, key_multibase: &str, rpath: &str) -> Result<J, String> {
    let (roots, blocks) = vlsync_atproto::car::read_car(car).map_err(|e| e.to_string())?;
    let root = *roots.first().ok_or("CAR has no root")?;
    let mut map: HashMap<Cid, Vec<u8>> = HashMap::new();
    for (c, data) in blocks {
        if Cid::dag_cbor(data) != c {
            return Err("block does not match its CID".into());
        }
        map.insert(c, data.to_vec());
    }
    let commit = Value::decode(map.get(&root).ok_or("missing commit block")?).map_err(|e| e.to_string())?;
    if commit.get("did").and_then(|v| v.as_str()) != Some(did) {
        return Err("Invalid repo did".into());
    }
    let Some(Value::Bytes(sig)) = commit.get("sig") else {
        return Err("commit is not signed".into());
    };
    let Value::Map(fields) = &commit else {
        return Err("invalid commit".into());
    };
    let unsigned = Value::Map(fields.iter().filter(|(k, _)| k != "sig").cloned().collect());
    if !verify_sig(key_multibase, &unsigned.to_cbor(), sig)? {
        return Err("Invalid signature on commit".into());
    }
    let Some(Value::Link(data)) = commit.get("data") else {
        return Err("commit has no data".into());
    };
    // only the nodes on rpath's path: the proof needs nothing else, and
    // the rest of an attacker's block set is never decoded
    let tree = vlsync_atproto::mst::Tree::load_path_from_blocks(&map, *data, rpath.as_bytes())
        .map_err(|e| format!("{e:?}"))?;
    let rcid = tree.get(rpath.as_bytes()).map_err(|e| format!("{e:?}"))?.ok_or("Record not found in proof")?;
    let rec = Value::decode(map.get(&rcid).ok_or("record block missing")?).map_err(|e| e.to_string())?;
    check_record_type(rec.to_json())
}

/// Compact signatures, low-S only (high-S is Ok(false), as the reference's
/// default verification).
pub(crate) fn verify_sig(multibase: &str, msg: &[u8], sig: &[u8]) -> Result<bool, String> {
    verify_multikey(multibase, msg, sig, false)
}

/// Inter-service JWTs only: the reference's `allowMalleableSig: true`.
pub(crate) fn verify_sig_malleable(multibase: &str, msg: &[u8], sig: &[u8]) -> Result<bool, String> {
    verify_multikey(multibase, msg, sig, true)
}

fn verify_multikey(multibase: &str, msg: &[u8], sig: &[u8], allow_high_s: bool) -> Result<bool, String> {
    let raw = bs58::decode(multibase.strip_prefix('z').ok_or("unsupported multibase")?)
        .into_vec()
        .map_err(|e| e.to_string())?;
    match raw.as_slice() {
        [0xe7, 0x01, key @ ..] => if allow_high_s {
            vlsync_atproto::crypto::verify_k256_malleable(key, msg, sig)
        } else {
            vlsync_atproto::crypto::verify_k256(key, msg, sig)
        }
        .map_err(|e| e.to_string()),
        [0x80, 0x24, key @ ..] => {
            use p256::ecdsa::signature::Verifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|e| e.to_string())?;
            let s = p256::ecdsa::Signature::from_slice(sig).map_err(|e| e.to_string())?;
            // `p256` itself accepts both forms; a different low-S form = it was high-S
            let low = s.normalize_s();
            if low != s && !allow_high_s {
                return Ok(false);
            }
            Ok(vk.verify(msg, &low).is_ok())
        }
        _ => Err("unsupported key type".into()),
    }
}

async fn permission_set_cached(app: &Arc<App>, nsid: &str) -> Result<J, String> {
    lexicon_cached(app, nsid, main_def).await
}

async fn lexicon_cached<T: Send + 'static>(app: &Arc<App>, nsid: &str, check: Check<T>) -> Result<T, String> {
    if !is_nsid(nsid) {
        return Err(format!("invalid NSID {nsid}"));
    }
    let cached = CACHE.lock().get(nsid).map(|(at, doc)| (at.elapsed() >= REFRESH, doc.clone()));
    let cached = match cached {
        Some(c) => Some(c),
        None => match store::get_lexicon(app, nsid).await {
            Ok(Some(l)) => {
                cache_put(nsid, Instant::now() - REFRESH, l.doc.clone());
                Some((true, l.doc))
            }
            _ => None,
        },
    };
    match cached {
        Some((stale, doc)) => {
            if stale {
                refresh_in_background(app, nsid, check);
            }
            check(nsid, &doc)
        }
        None => tokio::time::timeout(INLINE_BUDGET, lexicon(app, nsid, check))
            .await
            .map_err(|_| format!("Timed out resolving lexicon {nsid}"))?,
    }
}

fn refresh_in_background<T: Send + 'static>(app: &Arc<App>, nsid: &str, check: Check<T>) {
    if !IN_FLIGHT.lock().insert(nsid.to_string()) {
        return;
    }
    let (app, nsid) = (app.clone(), nsid.to_string());
    tokio::spawn(async move {
        let _ = lexicon(&app, &nsid, check).await;
        {
            // still stale = the resolution failed (lexicon() fell back
            // to the old copy): back off instead of retrying on every call
            let mut m = CACHE.lock();
            if let Some((at, _)) = m.get_mut(&nsid) {
                if at.elapsed() >= REFRESH {
                    *at = Instant::now() - REFRESH + RETRY_AFTER;
                }
            }
        }
        IN_FLIGHT.lock().remove(&nsid);
    });
}

fn space_decl(nsid: &str, doc: &J) -> Result<SpaceDecl, String> {
    crate::lexicon::space_declaration(nsid, doc)
}

/// A space type's declaration, for the consent screen (`name`, or its
/// `title` once proposals #118 lands).
pub async fn space_declaration(app: &App, nsid: &str) -> Result<SpaceDecl, String> {
    tokio::time::timeout(INLINE_BUDGET, lexicon(app, nsid, space_decl))
        .await
        .map_err(|_| format!("Timed out resolving space type {nsid}"))?
}

pub enum TokenScopeError {
    /// A permission set didn't resolve now; a retry may work.
    Lookup(String),
    /// A bare writing grant has no collections from its approval: it was
    /// approved before `--spaces`, or its type didn't resolve then. Only a
    /// new approval fixes it.
    NotApproved(String),
}

impl std::fmt::Display for TokenScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenScopeError::Lookup(m) | TokenScopeError::NotApproved(m) => f.write_str(m),
        }
    }
}

/// `include:` scopes replaced by the permissions their sets grant, then
/// with `--spaces` each `space:` grant made concrete
/// (`LexiconManager.buildTokenScope`), in bounded time: a bare grant that
/// writes takes the collections its type declared when the account
/// approved it (`consented`, by type), and `self` becomes `did`. Taking
/// them from the approval rather than a fresh lookup means a code exchange
/// or refresh never grants writes the consent screen didn't show; a type
/// that didn't resolve then fails the request, as the reference's does.
pub async fn build_token_scope_cached(
    app: &Arc<App>,
    scope: &str,
    did: &str,
    consented: Option<&BTreeMap<String, Vec<String>>>,
) -> Result<String, TokenScopeError> {
    let spaces = app.config.spaces;
    let has_space = spaces && scope.split(' ').any(super::scopes::is_space_scope);
    if !has_space && !scope.split(' ').any(|s| IncludeScope::parse(s).is_some()) {
        return Ok(scope.to_string());
    }
    let mut out: Vec<String> = Vec::new();
    let mut others: Vec<String> = Vec::new();
    for s in scope.split(' ') {
        match IncludeScope::parse(s) {
            Some(inc) => {
                let set = permission_set_cached(app, &inc.nsid).await.map_err(TokenScopeError::Lookup)?;
                out.extend(inc.to_permissions(&set, spaces).iter().map(|p| p.to_scope_string()));
            }
            None => others.push(s.to_string()),
        }
    }
    out.extend(others);
    if !spaces {
        return Ok(out.join(" "));
    }
    let mut concrete = Vec::with_capacity(out.len());
    for s in out {
        let Some(Permission::Space(p)) = Permission::parse(&s) else {
            concrete.push(s);
            continue;
        };
        let p = if p.needs_declaration() {
            match consented.and_then(|c| c.get(&p.space_type)) {
                Some(c) => p.with_default_collections(c),
                None => {
                    return Err(TokenScopeError::NotApproved(format!(
                        "Space type {} could not be resolved when access was approved",
                        p.space_type
                    )))
                }
            }
        } else {
            p
        };
        concrete.push(Permission::Space(p.with_resolved_authority(did)).to_scope_string());
    }
    Ok(concrete.join(" "))
}

pub async fn permission_sets_for_scope(app: &App, scope: &str) -> Result<Vec<(IncludeScope, J)>, String> {
    let mut out = Vec::new();
    for s in scope.split(' ') {
        if let Some(inc) = IncludeScope::parse(s) {
            let set = permission_set(app, &inc.nsid).await?;
            out.push((inc, set));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::Generate;

    /// Record proofs (commit signatures) take low-S only; service-auth JWTs
    /// also take the high-S form, for both curves.
    #[test]
    fn signature_malleability() {
        let msg = b"signed bytes";
        // P-256
        let sk = p256::ecdsa::SigningKey::generate();
        let mut mk = vec![0x80, 0x24];
        mk.extend_from_slice(sk.verifying_key().to_sec1_point(true).as_bytes());
        let p256_key = format!("z{}", bs58::encode(mk).into_string());
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, msg);
        let low = sig.normalize_s();
        let high = p256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
        assert!(high.normalize_s() != high, "high-S form");
        for (key, low, high) in [(p256_key, low.to_bytes().to_vec(), high.to_bytes().to_vec()), {
            // K-256
            let kp = vlsync_atproto::crypto::Keypair::generate();
            let low = kp.sign(msg);
            let s = k256::ecdsa::Signature::from_slice(&low).unwrap();
            let high = k256::ecdsa::Signature::from_scalars(s.r(), -*s.s()).unwrap();
            (kp.public_multibase(), low.to_vec(), high.to_bytes().to_vec())
        }] {
            assert_eq!(super::verify_sig(&key, msg, &low), Ok(true));
            assert_eq!(super::verify_sig(&key, msg, &high), Ok(false), "record proofs reject high-S");
            assert_eq!(super::verify_sig_malleable(&key, msg, &low), Ok(true));
            assert_eq!(super::verify_sig_malleable(&key, msg, &high), Ok(true), "service auth tolerates high-S");
            assert_eq!(super::verify_sig_malleable(&key, b"other", &high), Ok(false));
            assert_eq!(super::verify_sig(&key, b"other", &low), Ok(false));
        }
    }

    #[test]
    fn authority() {
        assert_eq!(super::nsid_authority("app.bsky.feed.post"), "feed.bsky.app");
        assert_eq!(super::nsid_authority("com.example.authBasic"), "example.com");
    }
}
