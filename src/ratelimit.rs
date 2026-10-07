//! Rate limits with the reference PDS's buckets and values
//! (packages/pds/src/rate-limits.ts and the handlers' `rateLimit` arrays),
//! in-memory fixed windows like its `MemoryRateLimiter`; DESIGN.md "Rate
//! limits: observability and runtime config".
//!
//! vlpds adds a per-IP and a cross-IP per-account cap to both createSession
//! and the OAuth sign-in (password guessing is Argon2 CPU; the reference's
//! oauth-provider has no sign-in limits of its own). The per-account cap
//! lets anyone hold an account's sign-ins off for up to an hour, app
//! password ones included: createSession spends it before it knows which
//! password it was given. Live sessions keep working. reserveSigningKey is
//! unauthenticated and costs a KMS wrap and a stored row per new key, hence
//! its per-IP and per-node caps. IPv6 clients are keyed by their /64.
//!
//! IP-keyed buckets are checked by [`layer`] before the handler; DID- and
//! body-keyed ones by handlers through [`check`] after auth and input
//! validation, as the reference does. Both report into a request-scoped
//! task-local so the response gets the RateLimit-* headers of the tightest
//! bucket consumed.
//!
//! Counters are per node. Per-DID buckets are effectively exact because
//! requests for a DID are served by its owner (createSession routes by its
//! body, never by query or an unverified token). Per-IP buckets count what
//! one node serves, keyed by the client address the entry node resolved
//! ([`ClientIp`]), so a client spreading requests across N nodes can get up
//! to N times the per-IP budget.
//!
//! Mail (vlpds additions): besides each mailing endpoint's own buckets,
//! every account mail spends its recipient's budget (`mail-recipient-*`,
//! keyed by DID, so counted on its owner), the node's (`mail-node-hour`, a
//! burst guard) and the cluster's (`mail-cluster-day`, [`mail_budget`]: the
//! mail provider's quota is per account, so a per-node budget would grow
//! with the cluster) before its token is minted: `xrpc::server::deliver`
//! takes the permit that spending yields, so no path can mail without it.
//! Admin sendEmail is exempt.

pub mod config;
pub mod mail_budget;
pub mod runtime;

use crate::xrpc::XrpcError;
use axum::extract::{ConnectInfo, MatchedPath, Request};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use parking_lot::{Mutex, RwLock};
use prometheus::{IntCounter, IntCounterVec, IntGauge};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyKind {
    Ip,
    /// `{identifier}-{client ip}`
    IdentifierIp,
    Did,
    /// One counter for the whole node ([`NODE_KEY`]).
    Node,
    /// One counter for the whole cluster ([`CLUSTER_KEY`]), in the bucket.
    Cluster,
    /// A space credential's `jti`.
    Credential,
    /// `{did} {did}`: an account and a space authority.
    DidPair,
}

pub const NODE_KEY: &str = "node";
pub const CLUSTER_KEY: &str = "cluster";

/// A built-in bucket's defaults. `idx` is its position in [`BUILTIN`].
#[derive(Debug)]
pub struct Limit {
    pub idx: usize,
    pub name: &'static str,
    pub key: KeyKind,
    /// For the console.
    pub scope: &'static str,
    pub window_ms: u64,
    pub points: u32,
}

macro_rules! limit {
    ($id:ident, $idx:expr, $name:expr, $key:ident, $scope:expr, $window:expr, $points:expr) => {
        pub const $id: Limit =
            Limit { idx: $idx, name: $name, key: KeyKind::$key, scope: $scope, window_ms: $window, points: $points };
    };
}

limit!(
    GLOBAL_IP,
    0,
    "global-ip",
    Ip,
    "every XRPC call except sync.getRepo and an account moving in sending blobs its repo references; OAuth sign-in",
    5 * MINUTE,
    3000
);
limit!(GET_REPO, 1, "com.atproto.sync.getRepo-0", Ip, "sync.getRepo", 5 * MINUTE, 6000);
limit!(
    CREATE_SESSION_DAY,
    2,
    "com.atproto.server.createSession-0",
    IdentifierIp,
    "server.createSession; OAuth sign-in",
    DAY,
    300
);
limit!(
    CREATE_SESSION_5MIN,
    3,
    "com.atproto.server.createSession-1",
    IdentifierIp,
    "server.createSession; OAuth sign-in",
    5 * MINUTE,
    30
);
limit!(
    CREATE_ACCOUNT,
    4,
    "com.atproto.server.createAccount-0",
    Ip,
    "server.createAccount; OAuth sign-up",
    5 * MINUTE,
    100
);
limit!(DELETE_ACCOUNT, 5, "com.atproto.server.deleteAccount-0", Ip, "server.deleteAccount", 5 * MINUTE, 50);
limit!(
    REQUEST_PASSWORD_RESET_DAY,
    6,
    "com.atproto.server.requestPasswordReset-0",
    Ip,
    "server.requestPasswordReset",
    DAY,
    50
);
limit!(
    REQUEST_PASSWORD_RESET_HOUR,
    7,
    "com.atproto.server.requestPasswordReset-1",
    Ip,
    "server.requestPasswordReset",
    HOUR,
    15
);
limit!(RESET_PASSWORD, 8, "com.atproto.server.resetPassword-0", Ip, "server.resetPassword", 5 * MINUTE, 50);
limit!(
    UPLOAD_BLOB,
    9,
    "com.atproto.repo.uploadBlob-0",
    Ip,
    "repo.uploadBlob, except an account moving in sending blobs its repo references",
    DAY,
    1000
);
limit!(UPDATE_HANDLE_5MIN, 10, "com.atproto.identity.updateHandle-0", Did, "identity.updateHandle", 5 * MINUTE, 10);
limit!(UPDATE_HANDLE_DAY, 11, "com.atproto.identity.updateHandle-1", Did, "identity.updateHandle", DAY, 50);
limit!(
    REQUEST_ACCOUNT_DELETE_DAY,
    12,
    "com.atproto.server.requestAccountDelete-0",
    Did,
    "server.requestAccountDelete",
    DAY,
    15
);
limit!(
    REQUEST_ACCOUNT_DELETE_HOUR,
    13,
    "com.atproto.server.requestAccountDelete-1",
    Did,
    "server.requestAccountDelete",
    HOUR,
    5
);
limit!(
    REQUEST_EMAIL_CONFIRMATION_DAY,
    14,
    "com.atproto.server.requestEmailConfirmation-0",
    Did,
    "server.requestEmailConfirmation",
    DAY,
    15
);
limit!(
    REQUEST_EMAIL_CONFIRMATION_HOUR,
    15,
    "com.atproto.server.requestEmailConfirmation-1",
    Did,
    "server.requestEmailConfirmation",
    HOUR,
    5
);
limit!(
    REQUEST_EMAIL_UPDATE_DAY,
    16,
    "com.atproto.server.requestEmailUpdate-0",
    Did,
    "server.requestEmailUpdate",
    DAY,
    15
);
limit!(
    REQUEST_EMAIL_UPDATE_HOUR,
    17,
    "com.atproto.server.requestEmailUpdate-1",
    Did,
    "server.requestEmailUpdate",
    HOUR,
    5
);
limit!(
    REPO_WRITE_HOUR,
    18,
    "repo-write-hour",
    Did,
    "every repo write (create 3, update 2, delete 1 points)",
    HOUR,
    5000
);
limit!(REPO_WRITE_DAY, 19, "repo-write-day", Did, "every repo write (create 3, update 2, delete 1 points)", DAY, 35000);
limit!(OAUTH_SIGN_IN_IP, 20, "oauth-sign-in-ip", Ip, "OAuth sign-in form posts", 5 * MINUTE, 100);
limit!(
    SIGN_IN_ACCOUNT,
    21,
    "sign-in-account",
    Did,
    "server.createSession; OAuth sign-in (both steps), from any IP",
    HOUR,
    100
);
limit!(OAUTH_IP, 22, "oauth-ip", Ip, "OAuth /oauth/par, /oauth/token, /oauth/revoke", 5 * MINUTE, 3000);
limit!(RESERVE_SIGNING_KEY_IP, 23, "com.atproto.server.reserveSigningKey-0", Ip, "server.reserveSigningKey", HOUR, 100);
limit!(
    RESERVE_SIGNING_KEY_NODE,
    24,
    "reserve-signing-key-node",
    Node,
    "server.reserveSigningKey calls that reserve a new key (one KMS wrap each)",
    DAY,
    5000
);
limit!(
    REQUEST_PLC_OPERATION_SIGNATURE_DAY,
    25,
    "com.atproto.identity.requestPlcOperationSignature-0",
    Did,
    "identity.requestPlcOperationSignature",
    DAY,
    15
);
limit!(
    REQUEST_PLC_OPERATION_SIGNATURE_HOUR,
    26,
    "com.atproto.identity.requestPlcOperationSignature-1",
    Did,
    "identity.requestPlcOperationSignature",
    HOUR,
    5
);
limit!(
    PASSWORD_RESET_ACCOUNT_DAY,
    27,
    "password-reset-account-day",
    Did,
    "server.requestPasswordReset mails to one account, from any IP (over it: answered OK, not mailed)",
    DAY,
    15
);
limit!(
    PASSWORD_RESET_ACCOUNT_HOUR,
    28,
    "password-reset-account-hour",
    Did,
    "server.requestPasswordReset mails to one account, from any IP (over it: answered OK, not mailed)",
    HOUR,
    5
);
limit!(
    MAIL_RECIPIENT_DAY,
    29,
    "mail-recipient-day",
    Did,
    "every account mail to one recipient (DID, else address), all kinds; admin sendEmail exempt",
    DAY,
    30
);
limit!(
    MAIL_RECIPIENT_HOUR,
    30,
    "mail-recipient-hour",
    Did,
    "every account mail to one recipient (DID, else address), all kinds; admin sendEmail exempt",
    HOUR,
    10
);
limit!(
    MAIL_NODE_HOUR,
    31,
    "mail-node-hour",
    Node,
    "every account mail this node sends; admin sendEmail exempt",
    HOUR,
    200
);
// Default points: --mail-daily-budget ([`Limiter::defaults`]).
limit!(
    MAIL_CLUSTER_DAY,
    32,
    "mail-cluster-day",
    Cluster,
    "every account mail the cluster sends (the mail provider's quota); admin sendEmail exempt",
    DAY,
    DEFAULT_MAIL_DAILY_BUDGET
);
// Each check of a custom domain is a DNS lookup and an HTTPS fetch the
// caller picks. The account page re-checks every 15 s while it waits for a
// new record, which is 20 per 5 min.
limit!(CHECK_HANDLE_5MIN, 33, "vlpds.identity.checkHandle-0", Did, "vlpds.identity.checkHandle", 5 * MINUTE, 60);
limit!(CHECK_HANDLE_DAY, 34, "vlpds.identity.checkHandle-1", Did, "vlpds.identity.checkHandle", DAY, 1000);
// Each registration rewrites the account's passkeys row and mails its owner.
limit!(
    PASSKEY_REGISTER_ACCOUNT,
    35,
    "passkey-register-account",
    Did,
    "vlpds.server.startPasskeyRegistration (passkeys added to one account)",
    DAY,
    10
);
limit!(
    PASSKEY_SIGN_IN_IP,
    36,
    "passkey-sign-in-ip",
    Ip,
    "the account page's passkey sign-in (startPasskeySignIn, createPasskeySession)",
    5 * MINUTE,
    100
);

// Spaces (vlpds additions; the reference limits only space writes, which
// share the repo-write buckets). Space reads are counted on the repo's
// owner, getSpaceCredential (a durable jti claim each) and inbound
// notifyWrite (a durable entry each) on the authority's, and
// notifyCredentialRevoked (a cluster-wide CAS write each) where it lands.
limit!(
    SPACE_READ_CREDENTIAL,
    37,
    "space-read-credential",
    Credential,
    "com.atproto.space reads and space host methods with one space credential",
    5 * MINUTE,
    3000
);
limit!(
    SPACE_READ_ACCOUNT,
    38,
    "space-read-account",
    Did,
    "com.atproto.space reads by an account's own OAuth session",
    5 * MINUTE,
    3000
);
limit!(
    SPACE_CREDENTIAL,
    39,
    "space-credential",
    DidPair,
    "space.getSpaceCredential per account and space authority",
    HOUR,
    300
);
limit!(SPACE_NOTIFY_IN, 40, "space-notify-in", Did, "space.notifyWrite received, per writer", 5 * MINUTE, 1000);
limit!(
    SPACE_REVOKE,
    41,
    "space-revoke",
    Did,
    "credentials newly revoked by space.notifyCredentialRevoked, per space authority",
    HOUR,
    1000
);

limit!(SPACE_IMPORT, 42, "space-import", Did, "vlpds.space.importRepo per account, before its body is read", HOUR, 100);
limit!(
    SPACE_REVOKE_AUD,
    43,
    "space-revoke-aud",
    Did,
    "credentials newly revoked by space.notifyCredentialRevoked, per account here giving the stake",
    HOUR,
    2000
);
limit!(SPACE_CREATE, 44, "space-create", Did, "simplespace.createSpace per account", DAY, 100);
limit!(SPACE_REGISTER, 45, "space-register", Credential, "space.registerNotify with one space credential", HOUR, 60);

pub const DEFAULT_MAIL_DAILY_BUDGET: u32 = 900;

pub const BUILTIN: [&Limit; 46] = [
    &GLOBAL_IP,
    &GET_REPO,
    &CREATE_SESSION_DAY,
    &CREATE_SESSION_5MIN,
    &CREATE_ACCOUNT,
    &DELETE_ACCOUNT,
    &REQUEST_PASSWORD_RESET_DAY,
    &REQUEST_PASSWORD_RESET_HOUR,
    &RESET_PASSWORD,
    &UPLOAD_BLOB,
    &UPDATE_HANDLE_5MIN,
    &UPDATE_HANDLE_DAY,
    &REQUEST_ACCOUNT_DELETE_DAY,
    &REQUEST_ACCOUNT_DELETE_HOUR,
    &REQUEST_EMAIL_CONFIRMATION_DAY,
    &REQUEST_EMAIL_CONFIRMATION_HOUR,
    &REQUEST_EMAIL_UPDATE_DAY,
    &REQUEST_EMAIL_UPDATE_HOUR,
    &REPO_WRITE_HOUR,
    &REPO_WRITE_DAY,
    &OAUTH_SIGN_IN_IP,
    &SIGN_IN_ACCOUNT,
    &OAUTH_IP,
    &RESERVE_SIGNING_KEY_IP,
    &RESERVE_SIGNING_KEY_NODE,
    &REQUEST_PLC_OPERATION_SIGNATURE_DAY,
    &REQUEST_PLC_OPERATION_SIGNATURE_HOUR,
    &PASSWORD_RESET_ACCOUNT_DAY,
    &PASSWORD_RESET_ACCOUNT_HOUR,
    &MAIL_RECIPIENT_DAY,
    &MAIL_RECIPIENT_HOUR,
    &MAIL_NODE_HOUR,
    &MAIL_CLUSTER_DAY,
    &CHECK_HANDLE_5MIN,
    &CHECK_HANDLE_DAY,
    &PASSKEY_REGISTER_ACCOUNT,
    &PASSKEY_SIGN_IN_IP,
    &SPACE_READ_CREDENTIAL,
    &SPACE_READ_ACCOUNT,
    &SPACE_CREDENTIAL,
    &SPACE_NOTIFY_IN,
    &SPACE_REVOKE,
    &SPACE_IMPORT,
    &SPACE_REVOKE_AUD,
    &SPACE_CREATE,
    &SPACE_REGISTER,
];

/// A confidential client's backend calls these for all of its users from
/// one address: raise or exempt it with an IP override.
const OAUTH_IP_PATHS: [&str; 3] = ["/oauth/par", "/oauth/token", "/oauth/revoke"];

/// Checked by the handler, which renders its own page on a 429.
const OAUTH_FORM_PATHS: [&str; 3] = ["/oauth/authorize/sign-in", "/oauth/account/sign-in", "/oauth/authorize/sign-up"];

pub const CREATE_POINTS: u32 = 3;
pub const UPDATE_POINTS: u32 = 2;
pub const DELETE_POINTS: u32 = 1;

fn ip_route_limits(path: &str) -> &'static [&'static Limit] {
    match path {
        "/xrpc/com.atproto.sync.getRepo" => &[&GET_REPO],
        "/xrpc/com.atproto.server.createAccount" => &[&CREATE_ACCOUNT],
        "/xrpc/com.atproto.server.deleteAccount" => &[&DELETE_ACCOUNT],
        "/xrpc/com.atproto.server.requestPasswordReset" => &[&REQUEST_PASSWORD_RESET_DAY, &REQUEST_PASSWORD_RESET_HOUR],
        "/xrpc/com.atproto.server.resetPassword" => &[&RESET_PASSWORD],
        "/xrpc/com.atproto.server.reserveSigningKey" => &[&RESERVE_SIGNING_KEY_IP],
        _ => &[],
    }
}

pub fn unlimited_path(path: &str) -> bool {
    path == "/xrpc/_health" || path == "/xrpc/com.atproto.sync.subscribeRepos"
}

#[derive(Clone, Debug)]
pub struct Spec {
    pub name: Arc<str>,
    pub key: KeyKind,
    pub scope: Arc<str>,
    pub window_ms: u64,
    pub points: u32,
    pub enabled: bool,
    /// Groups heavy hitters by bucket name (stable within the process).
    tag: u64,
}

impl Spec {
    pub fn new(name: &str, key: KeyKind, scope: &str, window_ms: u64, points: u32, enabled: bool) -> Spec {
        Spec { name: name.into(), key, scope: scope.into(), window_ms, points, enabled, tag: name_tag(name) }
    }

    fn of(l: &Limit) -> Spec {
        Spec::new(l.name, l.key, l.scope, l.window_ms, l.points, true)
    }
}

fn name_tag(name: &str) -> u64 {
    let mut h = std::hash::DefaultHasher::new();
    name.hash(&mut h);
    h.finish()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Exempt,
    /// Same window, same counter.
    Points(u32),
}

#[derive(Clone, Debug)]
pub struct Ov {
    /// Bucket names it covers (empty: every bucket).
    pub limiters: Vec<String>,
    pub action: Action,
}

impl Ov {
    fn covers(&self, name: &str) -> bool {
        self.limiters.is_empty() || self.limiters.iter().any(|l| l == name)
    }
}

/// Immutable; a config change installs a new one ([`Limiter::install`]).
#[derive(Debug)]
pub struct Policy {
    /// 0: no config object, defaults.
    pub version: u64,
    pub enabled: bool,
    pub(crate) builtin: Vec<Spec>,
    /// `/xrpc/{nsid}` -> extra IP-keyed bucket (`route:{nsid}`).
    pub(crate) routes: BTreeMap<String, Spec>,
    pub(crate) ip_ov: Vec<(Cidr, Ov)>,
    pub(crate) did_ov: HashMap<String, Vec<Ov>>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            version: 0,
            enabled: true,
            builtin: BUILTIN.iter().map(|l| Spec::of(l)).collect(),
            routes: BTreeMap::new(),
            ip_ov: Vec::new(),
            did_ov: HashMap::new(),
        }
    }
}

impl Policy {
    /// The built-in defaults with the flag-set ones (`--mail-daily-budget`).
    pub fn defaults(mail_daily_budget: u32) -> Policy {
        let mut p = Policy::default();
        p.builtin[MAIL_CLUSTER_DAY.idx].points = mail_daily_budget;
        p
    }

    pub fn builtin(&self, l: &Limit) -> &Spec {
        &self.builtin[l.idx]
    }

    pub fn specs(&self) -> impl Iterator<Item = &Spec> {
        self.builtin.iter().chain(self.routes.values())
    }

    pub fn spec(&self, name: &str) -> Option<&Spec> {
        self.specs().find(|s| &*s.name == name)
    }

    fn ip_matches(&self, ip: Option<IpAddr>) -> Vec<usize> {
        match ip {
            Some(ip) if !self.ip_ov.is_empty() => {
                self.ip_ov.iter().enumerate().filter(|(_, (c, _))| c.contains(&ip)).map(|(i, _)| i).collect()
            }
            _ => Vec::new(),
        }
    }

    /// `ip_ov`: the IP overrides the request's client IP matched. Exempt
    /// wins; otherwise the largest custom limit.
    pub fn override_for(&self, name: &str, key: &str, ip_ov: &[usize]) -> Option<Action> {
        if self.did_ov.is_empty() && ip_ov.is_empty() {
            return None;
        }
        let dids = self.did_ov.get(key).into_iter().flatten();
        let ips = ip_ov.iter().filter_map(|i| self.ip_ov.get(*i).map(|(_, o)| o));
        let mut out = None;
        for o in dids.chain(ips).filter(|o| o.covers(name)) {
            match (o.action, out) {
                (Action::Exempt, _) => return Some(Action::Exempt),
                (Action::Points(p), Some(Action::Points(q))) if q >= p => {}
                (a, _) => out = Some(a),
            }
        }
        out
    }

    /// For display: the client IP is recovered from the key. None: exempt.
    pub fn limit_for_key(&self, spec: &Spec, key: &str) -> Option<u32> {
        // an IPv6 key is its /64 ([`ip_key`]): its network address stands in
        let parse = |k: &str| k.trim_end_matches("/64").parse::<IpAddr>().ok();
        let ip = match spec.key {
            KeyKind::Ip => parse(key),
            KeyKind::IdentifierIp => key.rsplit_once('-').and_then(|(_, ip)| parse(ip)),
            KeyKind::Did | KeyKind::Node | KeyKind::Cluster | KeyKind::Credential | KeyKind::DidPair => None,
        };
        match self.override_for(&spec.name, key, &self.ip_matches(ip)) {
            Some(Action::Exempt) => None,
            Some(Action::Points(p)) => Some(p),
            None => Some(spec.points),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub limit: u32,
    pub window_ms: u64,
    pub remaining: u32,
    /// Unix ms.
    pub reset_ms: u64,
    pub exceeded: bool,
}

#[derive(Clone, Copy)]
struct Window {
    reset_ms: u64,
    used: u32,
}

#[derive(Clone, Debug)]
struct Cand {
    id: u64,
    window_ms: u64,
    key: Box<str>,
    used: u32,
    reset_ms: u64,
}

struct Shard {
    map: HashMap<u64, Window>,
    /// Heavy-hitter candidates by bucket tag.
    top: HashMap<u64, Vec<Cand>>,
    next_sweep_ms: u64,
}

const SHARDS: usize = 64;
/// Only when touched.
const SWEEP_EVERY_MS: u64 = 10_000;
/// A top-N list is exact unless more than this many of its keys hash to one
/// shard.
const TOP_PER_SHARD: usize = 8;
/// Identifiers are client-chosen.
const TOP_KEY_MAX: usize = 96;

pub struct Counters {
    shards: Box<[Mutex<Shard>]>,
    hasher: std::collections::hash_map::RandomState,
}

impl Default for Counters {
    fn default() -> Self {
        Counters {
            shards: (0..SHARDS)
                .map(|_| Mutex::new(Shard { map: HashMap::new(), top: HashMap::new(), next_sweep_ms: 0 }))
                .collect(),
            hasher: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Consumer {
    pub key: String,
    pub used: u32,
    /// None: exempt by an override.
    pub limit: Option<u32>,
    pub reset_ms: u64,
}

impl Counters {
    /// Windows are keyed by (bucket, window length, key): a new limit keeps
    /// a key's live window, a new window length starts a fresh one.
    fn window_id(&self, spec: &Spec, key: &str) -> u64 {
        let mut h = self.hasher.build_hasher();
        spec.name.hash(&mut h);
        spec.window_ms.hash(&mut h);
        key.hash(&mut h);
        h.finish()
    }

    fn shard(&self, id: u64) -> &Mutex<Shard> {
        &self.shards[(id >> 58) as usize % SHARDS]
    }

    fn consume_spec(&self, spec: &Spec, limit: u32, key: &str, points: u32, now_ms: u64) -> Status {
        let id = self.window_id(spec, key);
        let mut guard = self.shard(id).lock();
        let shard = &mut *guard;
        if now_ms >= shard.next_sweep_ms {
            shard.map.retain(|_, w| w.reset_ms > now_ms);
            shard.top.retain(|_, l| {
                l.retain(|c| c.reset_ms > now_ms);
                !l.is_empty()
            });
            shard.next_sweep_ms = now_ms + SWEEP_EVERY_MS;
        }
        let w = shard.map.entry(id).or_insert(Window { reset_ms: now_ms + spec.window_ms, used: 0 });
        if w.reset_ms <= now_ms {
            *w = Window { reset_ms: now_ms + spec.window_ms, used: 0 };
        }
        // As rate-limiter-flexible: points are counted even when rejected.
        w.used = w.used.saturating_add(points);
        let (used, reset_ms) = (w.used, w.reset_ms);
        track(shard.top.entry(spec.tag).or_default(), id, spec.window_ms, key, used, reset_ms, now_ms);
        Status {
            limit,
            window_ms: spec.window_ms,
            remaining: limit.saturating_sub(used),
            reset_ms,
            exceeded: used > limit,
        }
    }

    /// Takes back points [`Self::consume_spec`] counted, as long as the
    /// window it counted them in (`reset_ms`) is still the live one.
    /// Returns the window's points used after the refund.
    fn refund_spec(&self, spec: &Spec, key: &str, points: u32, reset_ms: u64) -> Option<u32> {
        let id = self.window_id(spec, key);
        let mut guard = self.shard(id).lock();
        let shard = &mut *guard;
        let w = shard.map.get_mut(&id).filter(|w| w.reset_ms == reset_ms)?;
        w.used = w.used.saturating_sub(points);
        let used = w.used;
        if let Some(c) = shard.top.get_mut(&spec.tag).and_then(|l| l.iter_mut().find(|c| c.id == id)) {
            c.used = used;
        }
        Some(used)
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().map.len()).sum()
    }

    /// Approximate: see [`TOP_PER_SHARD`].
    pub fn top(&self, policy: &Policy, n: usize, now_ms: u64) -> BTreeMap<String, Vec<Consumer>> {
        let mut by_tag: HashMap<u64, Vec<Cand>> = HashMap::new();
        for s in self.shards.iter() {
            let s = s.lock();
            for (tag, l) in &s.top {
                by_tag.entry(*tag).or_default().extend(l.iter().filter(|c| c.reset_ms > now_ms).cloned());
            }
        }
        let mut out = BTreeMap::new();
        for spec in policy.specs() {
            let Some(mut cands) = by_tag.remove(&spec.tag) else { continue };
            cands.retain(|c| c.window_ms == spec.window_ms);
            if cands.is_empty() {
                continue;
            }
            cands.sort_by(|a, b| b.used.cmp(&a.used).then_with(|| a.key.cmp(&b.key)));
            cands.truncate(n);
            let list = cands
                .into_iter()
                .map(|c| Consumer {
                    limit: policy.limit_for_key(spec, &c.key),
                    key: c.key.into(),
                    used: c.used,
                    reset_ms: c.reset_ms,
                })
                .collect();
            out.insert(spec.name.to_string(), list);
        }
        out
    }
}

/// Allocates only when a key enters the list; expired entries weigh nothing.
fn track(list: &mut Vec<Cand>, id: u64, window_ms: u64, key: &str, used: u32, reset_ms: u64, now_ms: u64) {
    if let Some(c) = list.iter_mut().find(|c| c.id == id) {
        c.used = used;
        c.reset_ms = reset_ms;
        return;
    }
    let cand = || Cand { id, window_ms, key: truncate(key, TOP_KEY_MAX).into(), used, reset_ms };
    if list.len() < TOP_PER_SHARD {
        list.push(cand());
        return;
    }
    let weight = |c: &Cand| if c.reset_ms <= now_ms { 0 } else { c.used };
    if let Some((i, min)) = list.iter().enumerate().map(|(i, c)| (i, weight(c))).min_by_key(|x| x.1) {
        if used > min {
            list[i] = cand();
        }
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

static REJECTIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "vlpds_rate_limit_rejections_total",
        "Requests over a rate-limit bucket, by bucket and route (matched XRPC method or path, else _proxy_or_unmatched)",
        &["limiter", "route"]
    )
    .unwrap()
});
pub(crate) static CONFIG_VERSION: LazyLock<IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "vlpds_rate_limit_config_version",
        "Version of the rate-limit config object in force on this node (0: flag defaults)"
    )
    .unwrap()
});
pub(crate) static CONFIG_ERRORS: LazyLock<IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "vlpds_rate_limit_config_errors_total",
        "Rate-limit config objects rejected by validation (the last good config stays in force)"
    )
    .unwrap()
});
pub(crate) static CONFIG_LOADS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "vlpds_rate_limit_config_loads_total",
        "Rate-limit config refreshes by result (applied, unchanged, invalid, error)",
        &["result"]
    )
    .unwrap()
});

const REJECT_MINUTES: usize = 15;
/// Past it, new series share one row.
const MAX_REJECT_SERIES: usize = 1024;

#[derive(Clone, Copy, Default)]
struct Ring {
    /// (unix minute, count), slot = minute % REJECT_MINUTES.
    mins: [(u64, u64); REJECT_MINUTES],
    total: u64,
}

#[derive(Default)]
pub struct Rejections {
    map: Mutex<HashMap<(Arc<str>, String), Ring>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RejectionCount {
    pub limiter: String,
    pub route: String,
    /// The current minute plus the previous 0 / 4 / 14.
    pub last1m: u64,
    pub last5m: u64,
    pub last15m: u64,
    pub total: u64,
}

impl Rejections {
    pub fn record(&self, limiter: &Arc<str>, route: &str, now_ms: u64) {
        REJECTIONS.with_label_values(&[&**limiter, route]).inc();
        let minute = now_ms / MINUTE;
        let mut m = self.map.lock();
        let k = (limiter.clone(), route.to_string());
        let k = if m.len() >= MAX_REJECT_SERIES && !m.contains_key(&k) {
            (Arc::from("_other"), "_other".to_string())
        } else {
            k
        };
        let r = m.entry(k).or_default();
        let slot = &mut r.mins[(minute % REJECT_MINUTES as u64) as usize];
        if slot.0 != minute {
            *slot = (minute, 0);
        }
        slot.1 += 1;
        r.total += 1;
    }

    pub fn snapshot(&self, now_ms: u64) -> Vec<RejectionCount> {
        let minute = now_ms / MINUTE;
        let within = |r: &Ring, n: u64| -> u64 {
            r.mins.iter().filter(|(m, _)| *m + n > minute && *m <= minute).map(|(_, c)| c).sum()
        };
        let mut v: Vec<RejectionCount> = self
            .map
            .lock()
            .iter()
            .map(|((l, route), r)| RejectionCount {
                limiter: l.to_string(),
                route: route.clone(),
                last1m: within(r, 1),
                last5m: within(r, 5),
                last15m: within(r, 15),
                total: r.total,
            })
            .collect();
        v.sort_by(|a, b| {
            b.last5m
                .cmp(&a.last5m)
                .then(b.total.cmp(&a.total))
                .then_with(|| (&a.limiter, &a.route).cmp(&(&b.limiter, &b.route)))
        });
        v
    }
}

#[derive(Clone, Debug)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, bits) = match s.trim().split_once('/') {
            Some((ip, b)) => (ip.parse::<IpAddr>().ok()?, Some(b.parse::<u8>().ok()?)),
            None => (s.trim().parse::<IpAddr>().ok()?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max);
        (bits <= max).then_some(Cidr { net: ip, bits })
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
            let (full, rem) = ((bits / 8) as usize, bits % 8);
            a[..full] == b[..full] && (rem == 0 || (a[full] ^ b[full]) & (0xffu8 << (8 - rem)) == 0)
        }
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(i)) => prefix_eq(&n.octets(), &i.octets(), self.bits),
            (IpAddr::V6(n), IpAddr::V6(i)) => prefix_eq(&n.octets(), &i.octets(), self.bits),
            _ => false,
        }
    }
}

/// The TCP peer, or, when it is a trusted proxy, the right-most
/// `X-Forwarded-For` entry that isn't itself trusted (Express `trust proxy`
/// semantics). The walk stops at an entry that doesn't parse, so a garbled
/// entry never lets it reach further-left (client-written) ones.
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, trusted: &[Cidr]) -> Option<IpAddr> {
    let peer = peer?.to_canonical();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|c| c.contains(ip));
    if trusted.is_empty() || !is_trusted(&peer) {
        return Some(peer);
    }
    let mut ip = peer;
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .map(|v| v.to_str().unwrap_or(""))
        .flat_map(|v| v.split(','))
        .collect();
    for hop in hops.into_iter().rev() {
        let Some(h) = parse_hop(hop) else { break };
        ip = h.to_canonical();
        if !is_trusted(&ip) {
            break;
        }
    }
    Some(ip)
}

/// An IP, `v4:port`, `[v6]` or `[v6]:port`.
fn parse_hop(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (v6, tail) = rest.split_once(']')?;
        if !(tail.is_empty() || tail.strip_prefix(':').is_some_and(|p| p.parse::<u16>().is_ok())) {
            return None;
        }
        return v6.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    let (v4, port) = s.split_once(':')?;
    port.parse::<u16>().ok()?;
    v4.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

/// IPv6 as its /64: one subscriber's allocation, which it can fill with
/// fresh addresses at will.
pub fn ip_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            format!("{net}/64")
        }
    }
}

/// Request extension: the client address as the entry node resolved it.
/// On a forwarded request it wins over the TCP peer, which is the
/// forwarding node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Only honored next to a valid `x-vlpds-forwarded` token.
pub const CLIENT_IP_HEADER: &str = "x-vlpds-client-ip";

pub fn request_client_ip(headers: &HeaderMap, ext: &axum::http::Extensions, trusted: &[Cidr]) -> Option<IpAddr> {
    if let Some(ClientIp(ip)) = ext.get::<ClientIp>() {
        return Some(*ip);
    }
    let peer = ext.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    client_ip(headers, peer, trusted)
}

pub struct Limiter {
    counters: Counters,
    pub trusted: Vec<Cidr>,
    pub bypass_key: Option<String>,
    /// False: the config can still be edited, but this node counts nothing.
    pub enabled_by_flag: bool,
    /// For the bypass check's tokens.
    cfg: crate::server::Config,
    policy: RwLock<Arc<Policy>>,
    pub rejections: Rejections,
    pub runtime: runtime::Runtime,
    /// `mail-cluster-day`'s default points.
    pub mail_daily_budget: u32,
    pub mail_budget: mail_budget::Budget,
    mail_budget_started: std::sync::atomic::AtomicBool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSnapshot {
    pub node: String,
    pub enabled_by_flag: bool,
    pub config_version: u64,
    pub config_error: Option<runtime::ConfigError>,
    pub loaded_at_ms: Option<u64>,
    pub checked_at_ms: Option<u64>,
    pub top: BTreeMap<String, Vec<Consumer>>,
    pub rejections: Vec<RejectionCount>,
    pub live_windows: usize,
}

impl Limiter {
    pub fn new(cfg: &crate::server::Config) -> Limiter {
        LazyLock::force(&REJECTIONS);
        LazyLock::force(&CONFIG_VERSION);
        LazyLock::force(&CONFIG_ERRORS);
        LazyLock::force(&CONFIG_LOADS);
        LazyLock::force(&mail_budget::ERRORS);
        mail_budget::set_gauges(cfg.mail_daily_budget, 0);
        Limiter {
            counters: Counters::default(),
            trusted: cfg
                .trusted_proxies
                .iter()
                .filter_map(|s| {
                    let c = Cidr::parse(s);
                    if c.is_none() {
                        tracing::warn!(proxy = %s, "ignoring unparseable trusted proxy");
                    }
                    c
                })
                .collect(),
            bypass_key: cfg.rate_limit_bypass_key.clone().filter(|k| !k.is_empty()),
            enabled_by_flag: cfg.rate_limits_enabled,
            cfg: cfg.clone(),
            policy: RwLock::new(Arc::new(Policy::defaults(cfg.mail_daily_budget))),
            rejections: Rejections::default(),
            runtime: runtime::Runtime::default(),
            mail_daily_budget: cfg.mail_daily_budget,
            mail_budget: mail_budget::Budget::default(),
            mail_budget_started: Default::default(),
        }
    }

    pub fn defaults(&self) -> Policy {
        Policy::defaults(self.mail_daily_budget)
    }

    pub fn policy(&self) -> Arc<Policy> {
        self.policy.read().clone()
    }

    /// Requests already running finish on the old policy; counters are
    /// untouched.
    pub fn install(&self, p: Policy) {
        CONFIG_VERSION.set(p.version as i64);
        *self.policy.write() = Arc::new(p);
    }

    pub fn snapshot(&self, node: &str, top: usize) -> NodeSnapshot {
        let now = now_ms();
        let policy = self.policy();
        let st = self.runtime.status();
        let mut top = self.counters.top(&policy, top, now);
        let spec = policy.builtin(&MAIL_CLUSTER_DAY);
        if let Some(used) = self.mail_budget.last().map(|s| s.used_in(spec.window_ms, now)).filter(|u| *u > 0) {
            let reset_ms = mail_budget::window_start(spec.window_ms, now) + spec.window_ms;
            top.insert(
                spec.name.to_string(),
                vec![Consumer { key: CLUSTER_KEY.into(), used, limit: Some(spec.points), reset_ms }],
            );
        }
        NodeSnapshot {
            node: node.to_string(),
            enabled_by_flag: self.enabled_by_flag,
            config_version: policy.version,
            config_error: st.error,
            loaded_at_ms: st.loaded_at_ms,
            checked_at_ms: st.checked_at_ms,
            top,
            rejections: self.rejections.snapshot(now),
            live_windows: self.counters.len(),
        }
    }

    fn bypassed(&self, headers: &HeaderMap) -> bool {
        let hdr = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
        if let Some(t) = hdr("x-vlpds-internal") {
            if crate::xrpc::internal::internal_token_ok(&self.cfg, t) {
                return true;
            }
        }
        if let (Some(k), Some(v)) = (&self.bypass_key, hdr("x-ratelimit-bypass")) {
            if crate::auth::token_eq(k, v) {
                return true;
            }
        }
        if let Some(b) = hdr("authorization").and_then(|v| v.strip_prefix("Basic ")) {
            if crate::auth::basic_admin_ok(b, &self.cfg.admin_token) {
                return true;
            }
        }
        false
    }

    /// For mail budgets, which protect the recipient rather than the
    /// server: the request's bypasses (internal token, bypass key, admin
    /// auth) and IP overrides don't lift them; a DID override does. Off
    /// with `--no-rate-limits` or the config's global switch, like every
    /// bucket. `report`: give the response these buckets' RateLimit-*
    /// headers (never where they would tell the caller whether an address
    /// has an account).
    pub fn consume_unbypassable(
        &self,
        limits: &[&'static Limit],
        key: &str,
        route: &str,
        report: bool,
    ) -> Result<(), XrpcError> {
        let policy = self.policy();
        if !self.enabled_by_flag || !policy.enabled {
            return Ok(());
        }
        let now = now_ms();
        let mut exceeded = false;
        for l in limits {
            let spec = policy.builtin(l);
            if !spec.enabled {
                continue;
            }
            let limit = match policy.override_for(&spec.name, key, &[]) {
                Some(Action::Exempt) => continue,
                Some(Action::Points(p)) => p,
                None => spec.points,
            };
            let s = self.counters.consume_spec(spec, limit, key, 1, now);
            if s.exceeded {
                exceeded = true;
                self.rejections.record(&spec.name, route, now);
            }
            if report {
                let _ = CTX.try_with(|c| c.borrow_mut().record(s));
            }
        }
        if exceeded {
            crate::metrics::RATE_LIMITED.inc();
            return Err(exceeded_error());
        }
        Ok(())
    }
}

impl Limiter {
    /// Sets the gauges from the budget object as last read.
    pub(crate) fn publish_mail_budget(&self) {
        let policy = self.policy();
        let spec = policy.builtin(&MAIL_CLUSTER_DAY);
        let used = self.mail_budget.last().map_or(0, |s| s.used_in(spec.window_ms, now_ms()));
        mail_budget::set_gauges(spec.points, used);
    }

    /// The cluster's `mail-cluster-day`, like [`Self::consume_unbypassable`]
    /// but counted in the bucket ([`mail_budget`]). Overrides don't apply:
    /// it stands for the mail provider's quota, which has none.
    pub async fn consume_cluster_mail(
        &self,
        store: &crate::store::Store,
        route: &str,
        report: bool,
    ) -> Result<(), XrpcError> {
        let policy = self.policy();
        let spec = policy.builtin(&MAIL_CLUSTER_DAY);
        if !self.enabled_by_flag || !policy.enabled || !spec.enabled {
            return Ok(());
        }
        let now = now_ms();
        let spent = match self.mail_budget.spend(store, spec.points, spec.window_ms, now).await {
            Ok(s) => s,
            Err(e) => {
                mail_budget::ERRORS.inc();
                tracing::warn!("cluster mail budget unavailable, mailing without spending it: {e}");
                return Ok(());
            }
        };
        mail_budget::set_gauges(spec.points, spent.used());
        let exceeded = matches!(spent, mail_budget::Spend::Exhausted(_));
        if report {
            let s = Status {
                limit: spec.points,
                window_ms: spec.window_ms,
                remaining: spec.points.saturating_sub(spent.used()),
                reset_ms: mail_budget::window_start(spec.window_ms, now) + spec.window_ms,
                exceeded,
            };
            let _ = CTX.try_with(|c| c.borrow_mut().record(s));
        }
        if exceeded {
            self.rejections.record(&spec.name, route, now);
            crate::metrics::RATE_LIMITED.inc();
            return Err(exceeded_error());
        }
        Ok(())
    }
}

struct Ctx {
    limiter: Arc<Limiter>,
    policy: Arc<Policy>,
    ip: String,
    ip_ov: Vec<usize>,
    route: Option<MatchedPath>,
    bypass: bool,
    /// Every bucket this request counted in.
    seen: Vec<Status>,
    /// Which of `seen` is the global per-IP bucket, if it counted there.
    global: Option<usize>,
}

impl Ctx {
    fn record(&mut self, s: Status) {
        self.seen.push(s);
    }

    /// Least remaining; exceeded wins.
    fn tightest(&self) -> Option<Status> {
        self.seen.iter().copied().reduce(|t, s| {
            if (s.exceeded && !t.exceeded) || (s.exceeded == t.exceeded && s.remaining < t.remaining) {
                s
            } else {
                t
            }
        })
    }

    fn refund_global(&mut self) {
        let Some(i) = self.global.take() else { return };
        let spec = self.policy.builtin(&GLOBAL_IP);
        if let Some(used) = self.limiter.counters.refund_spec(spec, &self.ip, 1, self.seen[i].reset_ms) {
            self.seen[i].remaining = self.seen[i].limit.saturating_sub(used);
        }
    }

    /// Bounded by the router's routes.
    fn route_label(&self) -> &str {
        match &self.route {
            Some(m) => m.as_str().strip_prefix("/xrpc/").unwrap_or(m.as_str()),
            None => "_proxy_or_unmatched",
        }
    }

    fn consume(&mut self, limits: &[&'static Limit], key: &str, points: u32) -> Result<(), XrpcError> {
        let policy = self.policy.clone();
        self.consume_specs(limits.iter().map(|l| policy.builtin(l)), key, points)
    }

    fn consume_specs<'a>(
        &mut self,
        specs: impl Iterator<Item = &'a Spec>,
        key: &str,
        points: u32,
    ) -> Result<(), XrpcError> {
        if self.bypass || points == 0 || !self.policy.enabled {
            return Ok(());
        }
        let now = now_ms();
        let mut exceeded = false;
        for spec in specs {
            if !spec.enabled {
                continue;
            }
            let limit = match self.policy.override_for(&spec.name, key, &self.ip_ov) {
                Some(Action::Exempt) => continue,
                Some(Action::Points(p)) => p,
                None => spec.points,
            };
            let s = self.limiter.counters.consume_spec(spec, limit, key, points, now);
            if s.exceeded {
                exceeded = true;
                self.limiter.rejections.record(&spec.name, self.route_label(), now);
            }
            self.record(s);
        }
        if exceeded {
            crate::metrics::RATE_LIMITED.inc();
            return Err(exceeded_error());
        }
        Ok(())
    }
}

tokio::task_local! {
    static CTX: RefCell<Ctx>;
    /// Set by [`unlimited`]: a request [`layer`] was never going to see.
    static UNLIMITED: ();
}

fn exceeded_error() -> XrpcError {
    XrpcError {
        status: StatusCode::TOO_MANY_REQUESTS,
        error: "RateLimitExceeded".into(),
        message: "Rate Limit Exceeded".into(),
    }
}

/// Outside a rate-limited request: Ok.
fn with_ctx(f: impl FnOnce(&mut Ctx) -> Result<(), XrpcError>) -> Result<(), XrpcError> {
    CTX.try_with(|c| f(&mut c.borrow_mut())).unwrap_or_else(|_| {
        // a handler's check on a path [`layer`] passes through would
        // silently allow everything
        debug_assert!(UNLIMITED.try_with(|_| ()).is_ok(), "rate-limit check on a path ratelimit::layer skips");
        Ok(())
    })
}

/// Stands in for [`layer`] with rate limits off.
pub async fn unlimited(req: Request, next: axum::middleware::Next) -> Response {
    UNLIMITED.scope((), next.run(req)).await
}

/// No-op when rate limiting is off or bypassed.
pub fn check(limits: &[&'static Limit], key: &str, points: u32) -> Result<(), XrpcError> {
    with_ctx(|c| c.consume(limits, key, points))
}

/// Keyed by `{prefix}-{client ip}`.
pub fn check_with_ip(limits: &[&'static Limit], prefix: &str, points: u32) -> Result<(), XrpcError> {
    with_ctx(|c| {
        let key = format!("{prefix}-{}", c.ip);
        c.consume(limits, &key, points)
    })
}

pub fn check_ip(limits: &[&'static Limit], points: u32) -> Result<(), XrpcError> {
    with_ctx(|c| {
        let key = c.ip.clone();
        c.consume(limits, &key, points)
    })
}

/// Gives back the global per-IP point [`layer`] took for this request, for
/// a request found exempt only once the handler has read it (an arriving
/// account's upload of a blob its repo references). Exact: the point is
/// counted on this node, which forwarded requests reach before [`layer`].
pub fn refund_global_ip() {
    let _ = CTX.try_with(|c| c.borrow_mut().refund_global());
}

pub fn check_repo_write(did: Option<&str>, points: u32) -> Result<(), XrpcError> {
    match did {
        Some(d) => check(&[&REPO_WRITE_HOUR, &REPO_WRITE_DAY], d, points),
        None => Ok(()),
    }
}

fn set_headers(h: &mut HeaderMap, s: &Status) {
    let num = |n: u64| HeaderValue::from(n);
    h.insert(HeaderName::from_static("ratelimit-limit"), num(s.limit as u64));
    h.insert(HeaderName::from_static("ratelimit-remaining"), num(s.remaining as u64));
    h.insert(HeaderName::from_static("ratelimit-reset"), num(s.reset_ms / 1000));
    if let Ok(v) = HeaderValue::from_str(&format!("{};w={}", s.limit, s.window_ms / 1000)) {
        h.insert(HeaderName::from_static("ratelimit-policy"), v);
    }
    if s.exceeded {
        let secs = s.reset_ms.saturating_sub(now_ms()).div_ceil(1000);
        h.insert(header::RETRY_AFTER, num(secs));
    }
}

pub async fn layer(
    axum::extract::State(limiter): axum::extract::State<Arc<Limiter>>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path();
    let post = req.method() == axum::http::Method::POST;
    let oauth_form = post && OAUTH_FORM_PATHS.contains(&path);
    let oauth_endpoint = post && OAUTH_IP_PATHS.contains(&path);
    if !oauth_form && !oauth_endpoint && (!path.starts_with("/xrpc/") || unlimited_path(path)) {
        return next.run(req).await;
    }
    // the admin token's bypass, for the operator a proxy named
    let operator = req.extensions().get::<crate::admin_proxy::ProxyIdentity>().is_some_and(|p| p.operator().is_some());
    let bypass = operator || limiter.bypassed(req.headers());
    let ip_addr = request_client_ip(req.headers(), req.extensions(), &limiter.trusted);
    let ip = ip_addr.map(ip_key).unwrap_or_else(|| "unknown".into());
    let route: &[&Limit] = if oauth_endpoint { &[&OAUTH_IP] } else { ip_route_limits(path) };
    let global = !oauth_form && !oauth_endpoint && path != "/xrpc/com.atproto.sync.getRepo";
    let policy = limiter.policy();
    let custom = policy.routes.get(path).cloned();
    let ctx = Ctx {
        ip_ov: policy.ip_matches(ip_addr),
        route: req.extensions().get::<MatchedPath>().cloned(),
        policy,
        limiter,
        ip,
        bypass,
        seen: Vec::new(),
        global: None,
    };
    CTX.scope(RefCell::new(ctx), async move {
        let pre = CTX.with(|c| {
            let mut c = c.borrow_mut();
            let ip = c.ip.clone();
            let g = if global {
                let r = c.consume(&[&GLOBAL_IP], &ip, 1);
                c.global = c.seen.len().checked_sub(1);
                r
            } else {
                Ok(())
            };
            let r = c.consume(route, &ip, 1);
            let x = match &custom {
                Some(spec) => c.consume_specs(std::iter::once(spec), &ip, 1),
                None => Ok(()),
            };
            g.and(r).and(x)
        });
        let mut resp = match pre {
            Ok(()) => next.run(req).await,
            Err(_) if oauth_endpoint => (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(
                    serde_json::json!({"error": "rate_limit_exceeded", "error_description": "Rate Limit Exceeded"}),
                ),
            )
                .into_response(),
            Err(e) => e.into_response(),
        };
        if let Some(s) = CTX.with(|c| c.borrow().tightest()) {
            set_headers(resp.headers_mut(), &s);
        }
        resp
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window() {
        let c = Counters::default();
        const L: Limit = Limit { idx: 0, name: "t", key: KeyKind::Ip, scope: "", window_ms: 1000, points: 5 };
        let spec = Spec::of(&L);
        let consume = |key: &str, points, now| c.consume_spec(&spec, L.points, key, points, now);
        for i in 0..5 {
            let s = consume("k", 1, 10);
            assert!(!s.exceeded);
            assert_eq!(s.remaining, 4 - i);
        }
        assert!(consume("k", 1, 500).exceeded);
        assert!(!consume("k2", 5, 500).exceeded);
        let s = consume("k", 1, 1010);
        assert!(!s.exceeded);
        assert_eq!(s.reset_ms, 2010);
        // expired windows are swept from each shard as it is touched
        assert_eq!(c.len(), 2);
        for i in 0..1000 {
            consume(&format!("x{i}"), 1, 100_000);
        }
        assert_eq!(c.len(), 1000, "old windows of every touched shard dropped");
    }

    #[test]
    fn builtin_table_is_indexed() {
        for (i, l) in BUILTIN.iter().enumerate() {
            assert_eq!(l.idx, i, "{}", l.name);
        }
        let mut names: Vec<_> = BUILTIN.iter().map(|l| l.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), BUILTIN.len());
    }

    #[test]
    fn new_limit_keeps_the_window_new_window_starts_fresh() {
        let c = Counters::default();
        let mut spec = Policy::default().builtin(&GLOBAL_IP).clone();
        for _ in 0..10 {
            c.consume_spec(&spec, 10, "1.2.3.4", 1, 0);
        }
        assert!(c.consume_spec(&spec, 10, "1.2.3.4", 1, 1).exceeded);
        // raised limit, same window: the 11 points used so far still count
        let s = c.consume_spec(&spec, 20, "1.2.3.4", 1, 2);
        assert_eq!((s.exceeded, s.remaining), (false, 8));
        // a different window length: a fresh window
        spec.window_ms = 60_000;
        let s = c.consume_spec(&spec, 20, "1.2.3.4", 1, 3);
        assert_eq!(s.remaining, 19);
    }

    #[test]
    fn refund_only_into_the_window_it_was_counted_in() {
        let c = Counters::default();
        let p = Policy::default();
        let spec = p.builtin(&GLOBAL_IP).clone();
        let s = c.consume_spec(&spec, 10, "1.2.3.4", 3, 0);
        assert_eq!(c.refund_spec(&spec, "1.2.3.4", 1, s.reset_ms), Some(2));
        assert_eq!(c.top(&p, 1, 1)["global-ip"][0].used, 2);
        // a key that never counted, or a window since replaced: nothing
        assert_eq!(c.refund_spec(&spec, "5.6.7.8", 1, s.reset_ms), None);
        let next = c.consume_spec(&spec, 10, "1.2.3.4", 1, s.reset_ms);
        assert_eq!(next.remaining, 9);
        assert_eq!(c.refund_spec(&spec, "1.2.3.4", 1, s.reset_ms), None);
        assert_eq!(c.consume_spec(&spec, 10, "1.2.3.4", 0, s.reset_ms + 1).remaining, 9);
    }

    #[test]
    fn heavy_hitters_are_bounded_and_ordered() {
        let c = Counters::default();
        let p = Policy::default();
        let spec = p.builtin(&GLOBAL_IP).clone();
        // 5000 distinct keys using 1..=50 points each, plus three heavy keys
        for i in 0..5000u32 {
            c.consume_spec(&spec, spec.points, &format!("10.0.{}.{}", i / 256, i % 256), i % 50 + 1, 1000);
        }
        for (k, n) in [("1.1.1.1", 900), ("2.2.2.2", 800), ("3.3.3.3", 700)] {
            c.consume_spec(&spec, spec.points, k, n, 1000);
        }
        let top = c.top(&p, 5, 1001);
        let l = &top["global-ip"];
        assert_eq!(l.len(), 5);
        assert_eq!((l[0].key.as_str(), l[0].used), ("1.1.1.1", 900));
        assert_eq!((l[1].key.as_str(), l[1].used), ("2.2.2.2", 800));
        assert_eq!((l[2].key.as_str(), l[2].used), ("3.3.3.3", 700));
        assert_eq!(l[3].used, 50);
        assert_eq!(l[0].limit, Some(3000));
        let cands: usize = c.shards.iter().map(|s| s.lock().top.values().map(|v| v.len()).sum::<usize>()).sum();
        assert!(cands <= SHARDS * TOP_PER_SHARD, "{cands} candidates");
        // expired windows drop out of the report
        assert!(c.top(&p, 5, 1000 + spec.window_ms + 1).is_empty());
    }

    #[test]
    fn long_keys_are_truncated() {
        let c = Counters::default();
        let p = Policy::default();
        let spec = p.builtin(&CREATE_SESSION_5MIN).clone();
        let key = format!("{}-1.2.3.4", "é".repeat(200));
        c.consume_spec(&spec, 30, &key, 1, 0);
        let top = c.top(&p, 1, 1);
        assert!(top[spec.name.as_ref()][0].key.len() <= TOP_KEY_MAX);
    }

    #[test]
    fn rejections_window() {
        let r = Rejections::default();
        let l: Arc<str> = "global-ip".into();
        let t0 = 100 * MINUTE;
        r.record(&l, "com.atproto.repo.createRecord", t0);
        r.record(&l, "com.atproto.repo.createRecord", t0 + 2 * MINUTE);
        r.record(&l, "com.atproto.repo.createRecord", t0 + 10 * MINUTE);
        let s = r.snapshot(t0 + 10 * MINUTE);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].last1m, s[0].last5m, s[0].last15m, s[0].total), (1, 1, 3, 3));
        // 20 minutes on, only the total remains
        let s = r.snapshot(t0 + 30 * MINUTE);
        assert_eq!((s[0].last15m, s[0].total), (0, 3));
    }

    #[test]
    fn cidr_and_forwarded_for() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!c.contains(&"11.1.2.3".parse().unwrap()));
        assert!(Cidr::parse("::1").unwrap().contains(&"::1".parse().unwrap()));
        // IPv4-mapped IPv6 clients match IPv4 blocks
        assert!(c.contains(&"::ffff:10.0.0.1".parse().unwrap()));
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4, 10.0.0.2".parse().unwrap());
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        // untrusted peer: XFF ignored
        assert_eq!(client_ip(&h, Some(peer), &[]), Some(peer));
        // trusted peer: right-most untrusted hop
        assert_eq!(client_ip(&h, Some(peer), &[c]), Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn forwarded_for_ports_and_garbage() {
        let trusted = [Cidr::parse("10.0.0.0/8").unwrap()];
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let ip = |xff: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", xff.parse().unwrap());
            client_ip(&h, Some(peer), &trusted).unwrap().to_string()
        };
        // ports are stripped (v4 and bracketed v6)
        assert_eq!(ip("9.9.9.9, 1.2.3.4:5678"), "1.2.3.4");
        assert_eq!(ip("9.9.9.9, [2001:db8::7]:443"), "2001:db8::7");
        assert_eq!(ip("[2001:db8::8]"), "2001:db8::8");
        assert_eq!(ip("1.2.3.4:5678, 10.0.0.9:80"), "1.2.3.4");
        // an unparseable entry stops the walk at the last trusted hop: the
        // client-written entries left of it are never reached
        assert_eq!(ip("6.6.6.6, unknown, 10.0.0.2"), "10.0.0.2");
        assert_eq!(ip("6.6.6.6, 1.2.3.4:http"), "10.0.0.1");
        assert_eq!(ip("6.6.6.6, [::1]x"), "10.0.0.1");
        // several headers read as one list
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
        h.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(client_ip(&h, Some(peer), &trusted), Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn ipv6_keys_are_the_64() {
        let k = |s: &str| ip_key(s.parse().unwrap());
        assert_eq!(k("1.2.3.4"), "1.2.3.4");
        assert_eq!(k("::ffff:1.2.3.4"), "1.2.3.4");
        assert_eq!(k("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_eq!(k("2001:db8:1:2:ffff:ffff:ffff:ffff"), "2001:db8:1:2::/64");
        assert_ne!(k("2001:db8:1:3::1"), k("2001:db8:1:2::1"));
        // the console's limit lookup finds IP overrides for a /64 key
        let mut p = Policy::default();
        p.ip_ov.push((Cidr::parse("2001:db8:1::/48").unwrap(), Ov { limiters: vec![], action: Action::Exempt }));
        let spec = p.builtin(&GLOBAL_IP).clone();
        assert_eq!(p.limit_for_key(&spec, "2001:db8:1:2::/64"), None);
        assert_eq!(p.limit_for_key(&spec, "2001:db8:2:2::/64"), Some(3000));
    }

    #[test]
    fn unbypassable_honours_did_overrides_and_the_switches() {
        let cfg = crate::server::Config::default();
        let l = Limiter::new(&cfg);
        let spend = |l: &Limiter, key: &str| l.consume_unbypassable(&[&MAIL_RECIPIENT_HOUR], key, "mail:t", false);
        for _ in 0..MAIL_RECIPIENT_HOUR.points {
            assert!(spend(&l, "did:plc:a").is_ok());
        }
        assert!(spend(&l, "did:plc:a").is_err_and(|e| e.error == "RateLimitExceeded"));
        assert!(spend(&l, "did:plc:b").is_ok());
        let mut p = Policy::default();
        p.did_ov.insert(
            "did:plc:a".into(),
            vec![Ov { limiters: vec!["mail-recipient-hour".into()], action: Action::Exempt }],
        );
        l.install(p);
        assert!(spend(&l, "did:plc:a").is_ok());
        l.install(Policy { enabled: false, ..Policy::default() });
        assert!(spend(&l, "did:plc:a").is_ok());
        let off = Limiter::new(&crate::server::Config { rate_limits_enabled: false, ..cfg });
        for _ in 0..=MAIL_RECIPIENT_HOUR.points {
            assert!(spend(&off, "did:plc:a").is_ok());
        }
    }

    /// A forwarding peer's [`ClientIp`] wins over the TCP peer (the
    /// forwarding node) and over X-Forwarded-For.
    #[test]
    fn client_ip_extension_wins() {
        let mut ext = axum::http::Extensions::new();
        ext.insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 9))));
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "7.7.7.7".parse().unwrap());
        let trusted = [Cidr::parse("10.0.0.0/8").unwrap()];
        assert_eq!(request_client_ip(&h, &ext, &trusted), Some("7.7.7.7".parse().unwrap()));
        ext.insert(ClientIp("203.0.113.5".parse().unwrap()));
        assert_eq!(request_client_ip(&h, &ext, &trusted), Some("203.0.113.5".parse().unwrap()));
    }
}
