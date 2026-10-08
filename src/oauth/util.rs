//! Helpers shared by the OAuth modules, and the single-use (replay) claims.

use sha2::{Digest, Sha256};

pub fn now_secs() -> i64 {
    (vlsync_atproto::tid::now_micros() / 1_000_000) as i64
}

pub use crate::prims::{b64u, b64u_decode, hmac_sha256};

pub fn sha256(b: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(b.as_ref()).into()
}

pub fn sha256_b64u(b: impl AsRef<[u8]>) -> String {
    b64u(sha256(b))
}

/// `{prefix}{base64url(n random bytes)}`
pub fn random_id(prefix: &str, n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    format!("{prefix}{}", b64u(b))
}

/// Every node shares `jwt_secret`, so derived keys agree across nodes with
/// no stored state.
pub fn derive_secret(server_secret: &str, label: &str) -> [u8; 32] {
    hmac_sha256(server_secret.as_bytes(), &[b"vlpds-oauth-v1", label.as_bytes()])
}

fn hex_upper(b: u8) -> [u8; 3] {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    [b'%', H[(b >> 4) as usize], H[(b & 15) as usize]]
}

/// JS `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(std::str::from_utf8(&hex_upper(b)).unwrap());
        }
    }
    out
}

/// As `URLSearchParams.toString()` does.
pub fn form_encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"*-._".contains(&b) {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push_str(std::str::from_utf8(&hex_upper(b)).unwrap());
        }
    }
    out
}

pub fn form_encode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode_component(k), form_encode_component(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// JS `decodeURIComponent`: None on malformed input.
pub fn percent_decode_strict(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// WHATWG urlencoded: lenient, bad escapes kept verbatim.
fn form_decode_component(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 3 <= b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// WHATWG semantics.
pub fn parse_form(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (form_decode_component(k), form_decode_component(v)),
            None => (form_decode_component(p), String::new()),
        })
        .collect()
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Claimed at the owner of `routing`'s partition, so every node checks a
/// given key against the same set (mod.rs).
#[derive(Clone, Debug)]
pub struct Replay {
    pub routing: String,
    pub key: String,
    /// Unix secs.
    pub until: i64,
}

pub fn client_routing(client_id: &str) -> String {
    format!("oauth:client:{}", sha256_b64u(client_id))
}

pub fn jkt_routing(jkt: &str) -> String {
    format!("oauth:jkt:{jkt}")
}

/// Every claim's own window is shorter; this only bounds what a caller or
/// peer passes, whatever `exp` a client put in its JWT.
pub const MAX_CLAIM_TTL: i64 = 600;

/// Each kind has its own replay cache, so a flood of resource-request
/// proofs can't evict authorization-server claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimKind {
    /// Memory only.
    ResourceProof = 0,
    AsProof = 1,
    Assertion = 2,
    RequestObject = 3,
    /// Released right after (PKCE code_challenge claims).
    Guard = 4,
    /// WebAuthn challenges (`xrpc::passkeys`), at the account's owner.
    Passkey = 5,
}

impl ClaimKind {
    const ALL: [ClaimKind; 6] = [
        ClaimKind::ResourceProof,
        ClaimKind::AsProof,
        ClaimKind::Assertion,
        ClaimKind::RequestObject,
        ClaimKind::Guard,
        ClaimKind::Passkey,
    ];

    /// By the prefix its maker gives `key`.
    pub fn of(key: &str, durable: bool) -> ClaimKind {
        if key.starts_with("dpop:") {
            if durable {
                ClaimKind::AsProof
            } else {
                ClaimKind::ResourceProof
            }
        } else if key.starts_with("assert:") {
            ClaimKind::Assertion
        } else if key.starts_with("jar:") {
            ClaimKind::RequestObject
        } else if key.starts_with("wa:") {
            ClaimKind::Passkey
        } else {
            ClaimKind::Guard
        }
    }

    /// (entries, entries per routing key) of this kind's cache.
    fn caps(self) -> (usize, usize) {
        match self {
            ClaimKind::ResourceProof => (2_000_000, 50_000),
            ClaimKind::AsProof | ClaimKind::Assertion | ClaimKind::RequestObject => (500_000, 50_000),
            ClaimKind::Guard => (100_000, 1_000),
            ClaimKind::Passkey => (200_000, 10_000),
        }
    }
}

/// Per `App`, not per process, so in-process test clusters behave like
/// separate machines.
pub(crate) struct NodeState {
    replays: [ReplayCache; 6],
    pub(crate) locks: Vec<std::sync::Arc<tokio::sync::Mutex<()>>>,
}

impl NodeState {
    fn replays(&self, kind: ClaimKind) -> &ReplayCache {
        &self.replays[kind as usize]
    }
}

static NODES: parking_lot::RwLock<Vec<(usize, std::sync::Arc<NodeState>)>> = parking_lot::RwLock::new(Vec::new());

pub(crate) fn node_state(app: &crate::xrpc::App) -> std::sync::Arc<NodeState> {
    let id = app as *const crate::xrpc::App as usize;
    if let Some((_, n)) = NODES.read().iter().find(|(k, _)| *k == id) {
        return n.clone();
    }
    let mut w = NODES.write();
    if let Some((_, n)) = w.iter().find(|(k, _)| *k == id) {
        return n.clone();
    }
    let n = std::sync::Arc::new(NodeState {
        replays: ClaimKind::ALL.map(|k| {
            let (max, per_group) = k.caps();
            ReplayCache::new(max, per_group)
        }),
        locks: (0..256).map(|_| std::sync::Arc::new(tokio::sync::Mutex::new(()))).collect(),
    });
    w.push((id, n.clone()));
    n
}

/// `p/{routing}\0oauth/replay/{sha256(key)}` -> `until`, JSON.
pub const REPLAY_ROW: &str = "oauth/replay/";

fn replay_row(key: &str) -> String {
    format!("{REPLAY_ROW}{}", sha256_b64u(key))
}

/// This node owns `routing`'s partition. False: a replay.
///
/// The in-memory set settles concurrent claims. A `durable` claim is also
/// checked against and written to the partition before it counts, so a new
/// owner after a failover, or this node after evicting it from a full cache,
/// still sees the claims accepted before.
pub async fn claim_replay_owned(
    app: &crate::xrpc::App,
    routing: &str,
    key: &str,
    until: i64,
    durable: bool,
    holder: u64,
) -> Result<bool, vlsync_atproto::xrpc::XrpcError> {
    let until = until.min(now_secs() + MAX_CLAIM_TTL);
    if !node_state(app).replays(ClaimKind::of(key, durable)).insert_held(routing, key, until, holder) {
        return Ok(false);
    }
    if !durable {
        return Ok(true);
    }
    let name = replay_row(key);
    if let Some(v) = app.get_private(routing, &name).await? {
        let prev: i64 = serde_json::from_slice(&v).unwrap_or(i64::MAX);
        if prev > now_secs() {
            return Ok(false);
        }
    }
    let m = vlsync_store::segment::Mutation {
        key: crate::state::private_key(routing, &name).into(),
        val: Some(serde_json::to_vec(&until).unwrap().into()),
    };
    app.put_private(routing, vec![m]).await?;
    Ok(true)
}

/// Tests: what a node that just took over a partition starts with.
pub fn forget_replays(app: &crate::xrpc::App) {
    for c in &node_state(app).replays {
        c.clear();
    }
}

/// For a guard whose durable record is now written.
pub fn release_replay_local(app: &crate::xrpc::App, key: &str) {
    node_state(app).replays(ClaimKind::of(key, false)).remove(key);
}

pub fn sweep_replays(app: &crate::xrpc::App) {
    for c in &node_state(app).replays {
        c.sweep();
    }
}

/// TTL set bounded in total and per routing key. Full, it evicts the entry
/// closest to expiry (of the routing key over its cap, else of the whole
/// set) instead of refusing, which would let one flooding client lock every
/// other client out. Evicting is safe for persisted claims, and for
/// memory-only proofs only affects a key over its own cap: an evicted proof
/// could be replayed for the rest of its short window, and only with its
/// access token.
pub struct ReplayCache {
    inner: parking_lot::Mutex<ReplayInner>,
    max: usize,
    max_per_group: usize,
}

#[derive(Default)]
struct ReplayInner {
    /// key -> (until, seq, group, holder: 0 = none)
    map: std::collections::HashMap<String, (i64, u64, std::sync::Arc<str>, u64)>,
    /// (until, seq) -> key: expiry order
    order: std::collections::BTreeMap<(i64, u64), String>,
    /// group -> its entries' (until, seq)
    groups: std::collections::HashMap<std::sync::Arc<str>, std::collections::BTreeSet<(i64, u64)>>,
    seq: u64,
}

impl ReplayInner {
    fn remove_at(&mut self, at: (i64, u64)) {
        if let Some(key) = self.order.remove(&at) {
            if let Some((_, _, g, _)) = self.map.remove(&key) {
                if let Some(set) = self.groups.get_mut(&g) {
                    set.remove(&at);
                    if set.is_empty() {
                        self.groups.remove(&g);
                    }
                }
            }
        }
    }

    fn expire(&mut self, now: i64) {
        while let Some((&at, _)) = self.order.first_key_value().filter(|(at, _)| at.0 <= now) {
            self.remove_at(at);
        }
    }
}

impl ReplayCache {
    pub fn new(max: usize, max_per_group: usize) -> ReplayCache {
        ReplayCache {
            inner: parking_lot::Mutex::new(ReplayInner::default()),
            max: max.max(1),
            max_per_group: max_per_group.max(1),
        }
    }

    /// Also done on every insert; the GC calls it so an idle cache does not
    /// hold its peak size.
    pub fn sweep(&self) {
        self.inner.lock().expire(now_secs());
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn clear(&self) {
        *self.inner.lock() = ReplayInner::default();
    }

    fn remove(&self, key: &str) {
        let mut g = self.inner.lock();
        if let Some(&(until, seq, _, _)) = g.map.get(key) {
            g.remove_at((until, seq));
        }
    }

    /// False: a replay. Never refuses a new key: a full set evicts.
    pub fn insert_unique(&self, group: &str, key: &str, expires_at: i64) -> bool {
        self.insert_held(group, key, expires_at, 0)
    }

    /// [`Self::insert_unique`], except that a key claimed by the same
    /// nonzero `holder` (one request, sent again) is not a replay.
    pub fn insert_held(&self, group: &str, key: &str, expires_at: i64, holder: u64) -> bool {
        let now = now_secs();
        let mut g = self.inner.lock();
        g.expire(now);
        if let Some(&(_, _, _, h)) = g.map.get(key) {
            return holder != 0 && h == holder;
        }
        if expires_at <= now {
            // nothing to remember: it can't be presented again in time
            return true;
        }
        g.seq += 1;
        let at = (expires_at, g.seq);
        let group: std::sync::Arc<str> = match g.groups.get_key_value(group) {
            Some((k, _)) => k.clone(),
            None => group.into(),
        };
        g.map.insert(key.to_string(), (expires_at, at.1, group.clone(), holder));
        g.order.insert(at, key.to_string());
        let over = {
            let set = g.groups.entry(group).or_default();
            set.insert(at);
            (set.len() > self.max_per_group).then(|| *set.first().expect("non-empty"))
        };
        if let Some(oldest) = over {
            g.remove_at(oldest);
        }
        while g.map.len() > self.max {
            let oldest = *g.order.first_key_value().expect("non-empty").0;
            g.remove_at(oldest);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding() {
        assert_eq!(encode_uri_component("a b/c:d?e"), "a%20b%2Fc%3Ad%3Fe");
        assert_eq!(form_encode_component("a b/c*"), "a+b%2Fc*");
        assert_eq!(percent_decode_strict("a%2Fb"), Some("a/b".into()));
        assert_eq!(percent_decode_strict("a%2"), None);
        assert_eq!(
            parse_form("a=1&b=x+y&a=%2F&c"),
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "x y".into()),
                ("a".into(), "/".into()),
                ("c".into(), "".into())
            ]
        );
    }

    #[test]
    fn replay() {
        let c = ReplayCache::new(10, 10);
        let exp = now_secs() + 60;
        assert!(c.insert_unique("g", "x", exp));
        assert!(!c.insert_unique("g", "x", exp));
        assert!(c.insert_unique("g", "y", exp));
        c.remove("x");
        assert!(c.insert_unique("g", "x", exp), "released");
        // already expired: accepted, not kept
        assert!(c.insert_unique("g", "old", now_secs() - 1));
        assert_eq!(c.len(), 2);

        // a holder's own claim again is not a replay; anyone else's is
        assert!(c.insert_held("g", "h", exp, 7));
        assert!(c.insert_held("g", "h", exp, 7), "same holder");
        assert!(!c.insert_held("g", "h", exp, 8), "another holder");
        assert!(!c.insert_unique("g", "h", exp), "no holder");
        assert!(c.insert_unique("g", "n", exp));
        assert!(!c.insert_held("g", "n", exp, 7), "claimed without a holder");
        assert_eq!(c.len(), 4);
    }

    /// A full cache evicts (the entry closest to expiry) instead of refusing
    /// new claims; one routing key over its cap evicts only its own entries.
    #[test]
    fn replay_cache_full_evicts() {
        let now = now_secs();
        let c = ReplayCache::new(100, 10);
        // another client's claims, expiring late
        for i in 0..5 {
            assert!(c.insert_unique("victim", &format!("v{i}"), now + 300));
        }
        // a flood from one routing key: never refused, capped at 10 of its own
        for i in 0..1_000 {
            assert!(c.insert_unique("flood", &format!("f{i}"), now + 60 + i), "claim {i} refused");
        }
        assert_eq!(c.len(), 15);
        for i in 0..5 {
            assert!(
                !c.insert_unique("victim", &format!("v{i}"), now + 300),
                "victim claim {i} evicted by another key's flood"
            );
        }
        // the newest of the flood are still claimed
        assert!(!c.insert_unique("flood", "f999", now + 60));
        // a flood across many keys fills the whole set: still no refusal,
        // the soonest-expiring entries go first
        for i in 0..1_000 {
            assert!(c.insert_unique(&format!("k{i}"), &format!("m{i}"), now + 400 + i));
        }
        assert_eq!(c.len(), 100);
        assert!(!c.insert_unique("k999", "m999", now + 400));
    }
}
