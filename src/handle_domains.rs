//! The domains this PDS gives out handles under: `--handle-domain` (the
//! primary, always served) plus any the operator adds at runtime, stored for
//! the cluster in `{prefix}/config/handle-domains.json`. Every node keeps
//! the set in memory and re-reads the object as the rate-limit config is
//! (`crate::ratelimit::runtime`): a conditional GET at startup, every
//! [`REFRESH_EVERY`], and when a peer nudges after a change. An unreadable
//! object keeps the last good set.

use object_store::{GetOptions, PutMode, PutOptions, PutPayload};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vlsync_store::store::Store;

/// Peers are nudged on every change, so this only bounds staleness after a
/// lost nudge.
pub const REFRESH_EVERY: Duration = Duration::from_secs(10);
const CALL_DEADLINE: Duration = Duration::from_secs(5);
const CAS_RETRIES: usize = 5;
pub const MAX_DOMAINS: usize = 100;
/// Room for a service handle's longest first label (18) and its dot.
const MAX_DOMAIN_LEN: usize = 253 - 19;

pub fn config_path(store: &Store) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/config/handle-domains.json", store.prefix))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Doc {
    #[serde(default)]
    pub domains: Vec<Added>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Added {
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
}

pub struct HandleDomains {
    primary: String,
    /// The stored object; its domains may include the primary.
    stored: RwLock<Arc<Doc>>,
    seen_etag: Mutex<Option<String>>,
    io: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
    started: AtomicBool,
}

/// `name` is `domain` or under it, ASCII case aside; Some(the labels before
/// `.domain`) when under it, Some("") when it is the domain.
fn front<'a>(name: &'a str, domain: &str) -> Option<&'a str> {
    let (n, d) = (name.as_bytes(), domain.as_bytes());
    if n.eq_ignore_ascii_case(d) {
        return Some("");
    }
    let cut = n.len().checked_sub(d.len() + 1)?;
    (n[cut] == b'.' && n[cut + 1..].eq_ignore_ascii_case(d)).then(|| &name[..cut])
}

/// The longest of `domains` that `name` is or is under, and the labels
/// before it.
pub fn longest<'a, 'd>(name: &'a str, domains: impl Iterator<Item = &'d str>) -> Option<(&'a str, &'d str)> {
    let name = name.trim_end_matches('.');
    domains.filter_map(|d| front(name, d).map(|f| (f, d))).max_by_key(|(_, d)| d.len())
}

/// What an account with `handle` counts under in the kept totals
/// (`crate::totals`): the handle without its first label, lowercased. It
/// counts toward the longest served domain that suffix is or is under,
/// which is the longest one the handle is strictly under.
pub fn handle_suffix(handle: &str) -> Option<Box<str>> {
    let (_, rest) = handle.trim_end_matches('.').split_once('.')?;
    (!rest.is_empty()).then(|| rest.to_ascii_lowercase().into())
}

impl HandleDomains {
    pub fn new(primary: &str) -> HandleDomains {
        HandleDomains {
            primary: primary.trim_end_matches('.').to_ascii_lowercase(),
            stored: Default::default(),
            seen_etag: Default::default(),
            io: Default::default(),
            wake: Default::default(),
            started: AtomicBool::new(false),
        }
    }

    pub fn primary(&self) -> &str {
        &self.primary
    }

    /// The primary, then the extras in the order they were added.
    pub fn list(&self) -> Vec<Added> {
        let mut out = vec![Added { domain: self.primary.clone(), added_at: None, added_by: None }];
        out.extend(self.stored.read().domains.iter().filter(|a| a.domain != self.primary).cloned());
        out
    }

    /// When the stored set last changed.
    pub fn updated_at(&self) -> Option<String> {
        self.stored.read().updated_at.clone()
    }

    pub fn names(&self) -> Vec<String> {
        self.list().into_iter().map(|a| a.domain).collect()
    }

    /// The served domain `name` is, or is under: the longest match on a
    /// label boundary, ASCII case ignored.
    pub fn served(&self, name: &str) -> Option<String> {
        self.matching(name).map(|(_, d)| d)
    }

    /// The served domain `name` is strictly under (the longest), and the
    /// labels before it. None for a served domain itself, even one under a
    /// shorter served domain: it is never a handle.
    pub fn under<'a>(&self, name: &'a str) -> Option<(&'a str, String)> {
        self.matching(name).filter(|(f, _)| !f.is_empty())
    }

    fn matching<'a>(&self, name: &'a str) -> Option<(&'a str, String)> {
        let stored = self.stored.read();
        longest(name, std::iter::once(self.primary.as_str()).chain(stored.domains.iter().map(|a| a.domain.as_str())))
            .map(|(f, d)| (f, d.to_string()))
    }

    fn install(&self, doc: Doc, etag: Option<String>) {
        *self.stored.write() = Arc::new(doc);
        *self.seen_etag.lock() = etag;
    }

    /// Asks the refresher to re-read the object now.
    pub fn wake(&self) {
        self.wake.notify_one();
    }
}

/// Why `domain` can't be served, if it can't. `domain` as typed: no
/// trimming or lowercasing, so what's stored is what was asked for.
pub fn invalid(domain: &str) -> Option<String> {
    if domain.is_empty() {
        return Some("empty domain".into());
    }
    if domain.bytes().any(|b| b.is_ascii_uppercase()) {
        return Some(format!("{domain}: use lowercase"));
    }
    if domain.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
        return Some(format!("{domain}: an IP address is not a domain"));
    }
    if !vlatproto::syntax::valid_handle(domain) {
        return Some(format!("{domain}: not a valid DNS name of two or more labels"));
    }
    if domain.len() > MAX_DOMAIN_LEN {
        return Some(format!("{domain}: longer than {MAX_DOMAIN_LEN} characters, leaving no room for a handle"));
    }
    if vlatproto::syntax::disallowed_handle_tld(domain) {
        return Some(format!("{domain}: handles can't end in that TLD"));
    }
    if crate::space::fanout::is_public_suffix(domain) {
        return Some(format!("{domain}: a public suffix, which no one PDS can own"));
    }
    None
}

#[derive(Debug)]
pub enum SaveError {
    Invalid(String),
    Exists(String),
    NotFound(String),
    Primary,
    TooMany,
    Store(String),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Invalid(m) => write!(f, "{m}"),
            SaveError::Exists(d) => write!(f, "{d} is already served"),
            SaveError::NotFound(d) => write!(f, "{d} is not a served handle domain"),
            SaveError::Primary => write!(f, "the primary handle domain (--handle-domain) can't be removed"),
            SaveError::TooMany => write!(f, "at most {MAX_DOMAINS} handle domains"),
            SaveError::Store(e) => write!(f, "config store error: {e}"),
        }
    }
}

async fn bounded<T>(f: impl std::future::Future<Output = object_store::Result<T>>) -> object_store::Result<T> {
    match tokio::time::timeout(CALL_DEADLINE, f).await {
        Ok(r) => r,
        Err(_) => Err(object_store::Error::Generic { store: "handle-domains", source: "config call timed out".into() }),
    }
}

/// None when absent.
async fn fetch(store: &Store, etag: Option<String>) -> object_store::Result<Option<(bytes::Bytes, Option<String>)>> {
    let path = config_path(store);
    let got = bounded(async {
        let r = store.raw.get_opts(&path, GetOptions { if_none_match: etag, ..Default::default() }).await?;
        let e = r.meta.e_tag.clone();
        Ok((r.bytes().await?, e))
    })
    .await;
    match got {
        Ok(x) => Ok(Some(x)),
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Re-reads the object (conditional on the last ETag) and installs it if it
/// changed. Returns whether the set was replaced.
pub async fn refresh(d: &HandleDomains, store: &Store) -> anyhow::Result<bool> {
    let _io = d.io.lock().await;
    let seen = d.seen_etag.lock().clone();
    let got = match fetch(store, seen.clone()).await {
        Ok(g) => g,
        Err(object_store::Error::NotModified { .. }) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let Some((bytes, etag)) = got else {
        if seen.is_none() && d.stored.read().domains.is_empty() {
            return Ok(false);
        }
        d.install(Doc::default(), None);
        return Ok(true);
    };
    match serde_json::from_slice::<Doc>(&bytes) {
        Ok(doc) => {
            let n = doc.domains.len();
            d.install(doc, etag);
            tracing::info!(extra = n, "handle domains loaded");
            Ok(true)
        }
        Err(e) => {
            *d.seen_etag.lock() = etag;
            tracing::warn!("handle-domains.json unreadable (keeping the last good set): {e}");
            Ok(false)
        }
    }
}

/// Starts this node's refresher (once): a load now, then every
/// [`REFRESH_EVERY`] or when woken. Stops when `d` is dropped.
pub fn spawn_refresher(d: &Arc<HandleDomains>, store: Store) {
    if d.started.swap(true, Ordering::AcqRel) {
        return;
    }
    let weak = Arc::downgrade(d);
    tokio::spawn(async move {
        loop {
            let Some(d) = weak.upgrade() else { return };
            if let Err(e) = refresh(&d, &store).await {
                tracing::warn!("handle domain refresh failed (retrying): {e:#}");
            }
            tokio::select! {
                _ = tokio::time::sleep(REFRESH_EVERY) => {}
                _ = d.wake.notified() => {}
            }
        }
    });
}

fn is_conflict(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::Precondition { .. } | object_store::Error::AlreadyExists { .. })
}

/// Read-modify-write of the stored set under CAS; installs the result on
/// this node.
async fn update(
    d: &HandleDomains,
    store: &Store,
    f: impl Fn(&mut Doc) -> Result<(), SaveError>,
) -> Result<Doc, SaveError> {
    let _io = d.io.lock().await;
    let store_err = |e: object_store::Error| SaveError::Store(e.to_string());
    for _ in 0..CAS_RETRIES {
        let cur = fetch(store, None).await.map_err(store_err)?;
        let (mut doc, etag) = match cur {
            None => (Doc::default(), None),
            Some((b, e)) => {
                // an unreadable object is replaced: refresh() already kept
                // the last good set, which is what the operator sees
                let doc = serde_json::from_slice(&b).unwrap_or_else(|_| Doc::clone(&d.stored.read()));
                (doc, e)
            }
        };
        f(&mut doc)?;
        doc.updated_at = Some(vlatproto::events::now_rfc3339());
        let mode = match etag {
            Some(e) => crate::cluster::if_match(Some(e)),
            None => PutMode::Create,
        };
        let body = serde_json::to_vec_pretty(&doc).map_err(|e| SaveError::Store(e.to_string()))?;
        let put = bounded(store.raw.put_opts(
            &config_path(store),
            PutPayload::from(body),
            PutOptions { mode, ..Default::default() },
        ))
        .await;
        match put {
            Ok(r) => {
                d.install(doc.clone(), r.e_tag);
                return Ok(doc);
            }
            Err(e) if is_conflict(&e) => continue,
            Err(e) => return Err(store_err(e)),
        }
    }
    Err(SaveError::Store("handle-domains.json kept changing under the update".into()))
}

pub async fn add(d: &HandleDomains, store: &Store, domain: &str, by: &str) -> Result<Doc, SaveError> {
    if let Some(m) = invalid(domain) {
        return Err(SaveError::Invalid(m));
    }
    let (primary, by) = (d.primary.clone(), by.to_string());
    update(d, store, |doc| {
        if domain == primary || doc.domains.iter().any(|a| a.domain == domain) {
            return Err(SaveError::Exists(domain.into()));
        }
        if doc.domains.len() + 1 >= MAX_DOMAINS {
            return Err(SaveError::TooMany);
        }
        doc.domains.push(Added {
            domain: domain.into(),
            added_at: Some(vlatproto::events::now_rfc3339()),
            added_by: Some(by.clone()),
        });
        Ok(())
    })
    .await
}

pub async fn remove(d: &HandleDomains, store: &Store, domain: &str) -> Result<Doc, SaveError> {
    if domain == d.primary {
        return Err(SaveError::Primary);
    }
    update(d, store, |doc| {
        let before = doc.domains.len();
        doc.domains.retain(|a| a.domain != domain);
        if doc.domains.len() == before {
            return Err(SaveError::NotFound(domain.into()));
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::ObjectStoreExt;

    fn with(extra: &[&str]) -> HandleDomains {
        let d = HandleDomains::new("pds.test");
        let doc = Doc {
            domains: extra.iter().map(|x| Added { domain: x.to_string(), added_at: None, added_by: None }).collect(),
            updated_at: None,
        };
        d.install(doc, None);
        d
    }

    #[test]
    fn longest_suffix_on_label_boundaries() {
        let d = with(&["example.org", "at.example.org"]);
        assert_eq!(d.served("alice.pds.test").as_deref(), Some("pds.test"));
        assert_eq!(d.served("pds.test").as_deref(), Some("pds.test"));
        assert_eq!(d.served("ALICE.PDS.Test.").as_deref(), Some("pds.test"));
        assert_eq!(d.served("bob.at.example.org").as_deref(), Some("at.example.org"));
        assert_eq!(d.under("bob.at.example.org"), Some(("bob", "at.example.org".to_string())));
        assert_eq!(d.under("x.y.example.org"), Some(("x.y", "example.org".to_string())));
        assert_eq!(d.served("at.example.org").as_deref(), Some("at.example.org"));
        // a served domain is never a handle under a shorter one
        assert_eq!(d.under("at.example.org"), None);
        assert_eq!(d.under("example.org"), None);
        assert_eq!(d.served("notexample.org"), None);
        assert_eq!(d.served("alice.pds.test.evil.com"), None);
        assert_eq!(d.served("é.pds.test").as_deref(), Some("pds.test"));
        assert_eq!(d.served(""), None);
        assert_eq!(d.names(), vec!["pds.test", "example.org", "at.example.org"]);
    }

    #[test]
    fn suffixes_count_under_the_longest_domain_above_the_handle() {
        assert_eq!(handle_suffix("Alice.PDS.test.").as_deref(), Some("pds.test"));
        assert_eq!(handle_suffix("bob.at.example.org").as_deref(), Some("at.example.org"));
        assert_eq!(handle_suffix("example"), None);
        assert_eq!(handle_suffix("x."), None);
        let d = with(&["example.org", "at.example.org"]);
        let under = |h: &str| handle_suffix(h).and_then(|s| d.served(&s));
        assert_eq!(under("bob.at.example.org").as_deref(), Some("at.example.org"));
        assert_eq!(under("x.y.example.org").as_deref(), Some("example.org"));
        // a handle that is a served domain counts under the one above it
        assert_eq!(under("at.example.org").as_deref(), Some("example.org"));
        assert_eq!(under("alice.elsewhere.com"), None);
    }

    #[test]
    fn validation() {
        assert_eq!(invalid("at.example.com"), None);
        assert_eq!(invalid("my-app.fly.dev"), None);
        for bad in [
            "",
            "Example.com",
            "1.2.3.4",
            "[::1]",
            "::1",
            "com",
            "example..com",
            "-x.example.com",
            "example.com.",
            "x.local",
            "x.onion",
            "fly.dev",
            "github.io",
            "co.uk",
            "a b.com",
        ] {
            assert!(invalid(bad).is_some(), "{bad:?} accepted");
        }
        let long = ["a".repeat(60), "b".repeat(60), "c".repeat(60), "d".repeat(60), "com".into()].join(".");
        assert!(invalid(&long).unwrap().contains("no room"));
    }

    #[tokio::test]
    async fn add_remove_and_peers_pick_it_up() {
        let store = Store::memory(None);
        let (a, b) = (HandleDomains::new("pds.test"), HandleDomains::new("pds.test"));
        assert!(!refresh(&b, &store).await.unwrap());
        add(&a, &store, "example.org", "tester").await.unwrap();
        assert_eq!(a.served("x.example.org").as_deref(), Some("example.org"));
        assert_eq!(b.served("x.example.org"), None);
        assert!(refresh(&b, &store).await.unwrap());
        assert_eq!(b.served("x.example.org").as_deref(), Some("example.org"));
        assert!(!refresh(&b, &store).await.unwrap(), "then 304s");
        assert!(matches!(add(&b, &store, "example.org", "t").await, Err(SaveError::Exists(_))));
        assert!(matches!(add(&b, &store, "pds.test", "t").await, Err(SaveError::Exists(_))));
        assert!(matches!(remove(&b, &store, "pds.test").await, Err(SaveError::Primary)));
        assert!(matches!(remove(&b, &store, "nope.org").await, Err(SaveError::NotFound(_))));
        remove(&b, &store, "example.org").await.unwrap();
        assert!(refresh(&a, &store).await.unwrap());
        assert_eq!(a.served("x.example.org"), None);
        // garbage keeps the last good set
        add(&a, &store, "example.net", "t").await.unwrap();
        store.raw.put(&config_path(&store), PutPayload::from_static(b"{{")).await.unwrap();
        assert!(!refresh(&a, &store).await.unwrap());
        assert_eq!(a.served("x.example.net").as_deref(), Some("example.net"));
    }
}
