//! Read-after-write on proxied AppView reads (reference
//! `packages/pds/src/read-after-write`, `api/app/bsky/{actor,feed}`).
//!
//! For getProfile(s), getActorLikes, getAuthorFeed, getTimeline and
//! getPostThread, the requester's own records written after the AppView's
//! indexed rev (`atproto-repo-rev`) are merged into the response, so a post
//! or profile edit shows at once. The records come from the owner's
//! per-repo recent-writes log ([`crate::recent_writes`]), else one read of
//! the repo's records. A response with no such records (nearly all) streams
//! through untouched, compressed or not; one with them is buffered,
//! decoded, munged as the reference does and re-serialized, with
//! `Atproto-Upstream-Lag` (ms since the oldest merged post/profile write).
//! Like the reference, any `atproto-proxy` target's response is munged, so
//! the upstream is untrusted here: at most [`MAX_CODINGS`] codings, zstd
//! windows of at most 2^[`ZSTD_WINDOW_LOG_MAX`], 10 MiB decoded, decoding
//! and parsing of larger bodies on blocking threads (at most one per core),
//! and at most [`MUNGE_BUDGET`] decoded bytes being munged at once (a
//! response past it is returned unmunged). DESIGN.md "Read-after-write".

use super::*;
use crate::recent_writes::{self, Rec, Since};
use std::collections::HashMap;
use std::sync::LazyLock;

const REPO_REV: &str = "atproto-repo-rev";
const UPSTREAM_LAG: &str = "atproto-upstream-lag";
const THREAD_VIEW_POST: &str = "app.bsky.feed.defs#threadViewPost";
const REASON_REPOST: &str = "app.bsky.feed.defs#reasonRepost";
const GET_POSTS: &str = "app.bsky.feed.getPosts";
const GET_POST_THREAD: &str = "app.bsky.feed.getPostThread";
const GET_FEED_GENERATOR: &str = "app.bsky.feed.getFeedGenerator";
const GET_LIST: &str = "app.bsky.graph.getList";

/// The proxied methods the reference munges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Profile,
    Profiles,
    ActorLikes,
    AuthorFeed,
    Timeline,
    PostThread,
}

impl Kind {
    pub(super) fn of(lxm: &str) -> Option<Kind> {
        Some(match lxm {
            "app.bsky.actor.getProfile" => Kind::Profile,
            "app.bsky.actor.getProfiles" => Kind::Profiles,
            "app.bsky.feed.getActorLikes" => Kind::ActorLikes,
            "app.bsky.feed.getAuthorFeed" => Kind::AuthorFeed,
            "app.bsky.feed.getTimeline" => Kind::Timeline,
            GET_POST_THREAD => Kind::PostThread,
            _ => return None,
        })
    }
}

struct Counters {
    log_nothing: prometheus::IntCounter,
    log_records: prometheus::IntCounter,
    store_read: prometheus::IntCounter,
    munged: prometheus::IntCounter,
    unchanged: prometheus::IntCounter,
    failed: prometheus::IntCounter,
}

/// Label lookups done once: the no-records path is the proxy's hot path.
static COUNTERS: LazyLock<Counters> = LazyLock::new(|| {
    let c = |l: &str| crate::metrics::READ_AFTER_WRITE.with_label_values(&[l]);
    Counters {
        log_nothing: c("log_nothing"),
        log_records: c("log_records"),
        store_read: c("store_read"),
        munged: c("munged"),
        unchanged: c("unchanged"),
        failed: c("failed"),
    }
});

// Content codings
// ---------------

/// Content codings a munged response can be decoded from.
fn decodable(coding: &str) -> bool {
    ["gzip", "x-gzip", "deflate", "br", "zstd", "identity"].iter().any(|c| coding.eq_ignore_ascii_case(c))
}

/// The client's Accept-Encoding limited to codings this PDS can decode
/// (the reference negotiates its own list for the same reason); None keeps
/// the client's as it is (nearly always: `gzip`, `gzip, deflate, br`, ...).
/// `*` stands for the decodable ones; nothing left means identity.
fn accept_encoding(client: Option<&header::HeaderValue>) -> Option<header::HeaderValue> {
    let v = client?.to_str().ok()?;
    fn name(part: &str) -> &str {
        part.split(';').next().unwrap_or("").trim()
    }
    if v.split(',').all(|p| decodable(name(p)) || name(p).is_empty()) {
        return None;
    }
    let named: Vec<&str> = v.split(',').map(name).collect();
    let mut out: Vec<String> = Vec::new();
    for part in v.split(',') {
        let n = name(part);
        let params = part.find(';').map(|i| part[i..].trim()).unwrap_or("");
        if n == "*" {
            // `*` stands only for the codings not named explicitly
            // ("gzip, *;q=0" must not turn into "gzip, gzip;q=0")
            let rest =
                ["gzip", "deflate", "br"].into_iter().filter(|c| !named.iter().any(|x| x.eq_ignore_ascii_case(c)));
            out.extend(rest.map(|c| format!("{c}{params}")));
        } else if decodable(n) {
            out.push(part.trim().to_string());
        }
    }
    let out = if out.is_empty() { "identity".to_string() } else { out.join(", ") };
    header::HeaderValue::from_str(&out).ok()
}

/// The reference's Accept-Encoding negotiation for the responses it may have
/// to decode and re-encode (`@atproto-labs/xrpc-utils`
/// `negotiateContentEncoding`): a malformed header is a 400 (`Invalid
/// accept-encoding: "<part>"`), and one that rules out identity and every
/// coding this PDS can decode is a 406.
fn check_accept_encoding(client: Option<&header::HeaderValue>) -> XResult<()> {
    let Some(v) = client.and_then(|v| v.to_str().ok()).filter(|v| !v.is_empty()) else {
        return Ok(());
    };
    let mut q_of: HashMap<String, f64> = HashMap::new();
    for def in v.split(',') {
        let invalid = || XrpcError::bad("InvalidRequest", format!("Invalid accept-encoding: \"{def}\""));
        let parts: Vec<&str> = def.trim().splitn(3, ';').collect();
        if parts.len() > 2 || parts[0].is_empty() || parts[0].contains('=') {
            return Err(invalid());
        }
        let mut q = 1.0;
        if let Some(params) = parts.get(1) {
            let kv: Vec<&str> = params.splitn(3, '=').collect();
            if kv.len() != 2 || !(kv[0] == "q" || kv[0] == "Q") {
                return Err(invalid());
            }
            q = kv[1].trim().parse::<f64>().map_err(|_| invalid())?;
            if !(q == 0.0 || (0.001..=1.0).contains(&q)) {
                return Err(invalid());
            }
        }
        q_of.insert(parts[0].to_ascii_lowercase(), q);
    }
    let q = |n: &str| q_of.get(n).or_else(|| q_of.get("*")).copied();
    let identity_ok = q("identity").is_none_or(|q| q > 0.0);
    let coded_ok = ["gzip", "deflate", "br"].iter().any(|c| q(c).is_some_and(|q| q > 0.0));
    if !identity_ok && !coded_ok {
        return Err(xerr(
            StatusCode::NOT_ACCEPTABLE,
            "NotAcceptable",
            "this service does not support any of the requested encodings",
        ));
    }
    Ok(())
}

/// Codings decoded per body at most (`gzip, gzip, ...` chains multiply the
/// work; real upstreams apply one).
pub(super) const MAX_CODINGS: usize = 2;
/// zstd's default limit (2^27, a 128 MiB window allocation per decoder) is
/// far above what a JSON response needs; 2^23 (8 MiB) is the window the
/// zstd CLI and HTTP encoders use up to level 19.
pub(super) const ZSTD_WINDOW_LOG_MAX: u32 = 23;
/// Decoded bytes of responses being munged at once (their parsed form is
/// ~10x): past it a response with records to merge is returned as is.
pub(super) const MUNGE_BUDGET: usize = 32 << 20;
/// Bodies at most this size (identity) are parsed and re-serialized on the
/// IO thread; larger or compressed ones on a blocking thread.
const INLINE_BYTES: usize = 64 << 10;

/// Codings applied to a body, in order (Content-Encoding lists them in the
/// order they were applied); None if one can't be decoded, or there are
/// more than [`MAX_CODINGS`].
pub(super) fn codings(h: &HeaderMap) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for v in h.get_all(header::CONTENT_ENCODING) {
        for c in v.to_str().ok()?.split(',') {
            let c = c.trim().to_ascii_lowercase();
            if c.is_empty() || c == "identity" {
                continue;
            }
            if !decodable(&c) || out.len() == MAX_CODINGS {
                return None;
            }
            out.push(c);
        }
    }
    Some(out)
}

/// Decodes `body`, at most `max` bytes out after every coding (the
/// reference bounds the decoded size too).
pub(super) fn decode(body: Bytes, codings: &[String], max: usize) -> Result<Bytes, String> {
    use std::io::Read;
    if codings.len() > MAX_CODINGS {
        return Err("too many content-encodings".into());
    }
    let mut cur = body;
    for c in codings.iter().rev() {
        let mut out = Vec::new();
        let limit = max as u64 + 1;
        let r = match c.as_str() {
            "gzip" | "x-gzip" => flate2::read::MultiGzDecoder::new(&cur[..]).take(limit).read_to_end(&mut out),
            "deflate" => flate2::read::ZlibDecoder::new(&cur[..]).take(limit).read_to_end(&mut out),
            "br" => brotli_decompressor::Decompressor::new(&cur[..], 4096).take(limit).read_to_end(&mut out),
            "zstd" => zstd::stream::read::Decoder::new(&cur[..]).and_then(|mut d| {
                d.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
                d.take(limit).read_to_end(&mut out)
            }),
            other => return Err(format!("unsupported content-encoding: \"{other}\"")),
        };
        r.map_err(|_| "unable to decode request body".to_string())?;
        if out.len() > max {
            return Err("upstream response too large".into());
        }
        cur = Bytes::from(out);
    }
    Ok(cur)
}

/// Blocking threads decoding/parsing munged responses at once.
static CPU: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(std::thread::available_parallelism().map_or(4, |n| n.get())));
/// [`MUNGE_BUDGET`] in KiB permits.
static MEM: LazyLock<tokio::sync::Semaphore> = LazyLock::new(|| tokio::sync::Semaphore::new(MUNGE_BUDGET >> 10));

/// Runs `f` here when `inline`, else on a blocking thread (one per core at
/// most).
async fn cpu<T: Send + 'static>(inline: bool, f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    if inline {
        return Ok(f());
    }
    let _p = CPU.acquire().await.map_err(|e| e.to_string())?;
    tokio::task::spawn_blocking(f).await.map_err(|e| e.to_string())
}

// Local records
// -------------

/// A local record as the reference's `RecordDescript`.
struct Desc {
    uri: String,
    cid: String,
    /// When it was written (from its rev), ISO 8601 with milliseconds.
    indexed_at: String,
    record: J,
}

/// The reference's `LocalRecords`.
#[derive(Default)]
struct Local {
    profile: Option<Desc>,
    /// oldest first
    posts: Vec<Desc>,
}

impl Local {
    /// ms since the oldest merged write (reference `getLocalLag`).
    fn lag(&self) -> Option<i64> {
        let oldest = self.profile.iter().chain(&self.posts).map(|d| &d.indexed_at).min()?;
        let t = chrono::DateTime::parse_from_rfc3339(oldest).ok()?;
        Some(chrono::Utc::now().timestamp_millis() - t.timestamp_millis())
    }
}

fn rev_time(rev: u64) -> String {
    let us = vlsync_atproto::tid::Tid(rev).micros() as i64;
    chrono::DateTime::from_timestamp_micros(us).unwrap_or_default().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn record_json(bytes: &[u8]) -> Option<J> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    vlsync_atproto::cbor::write_json(bytes, &mut out).ok()?;
    serde_json::from_slice(&out).ok()
}

fn local_of(did: &str, recs: Vec<Rec>) -> Local {
    let mut l = Local::default();
    for r in recs {
        let Some(record) = r.bytes.as_deref().and_then(record_json) else { continue };
        let d =
            Desc { uri: format!("at://{did}/{}", r.path), cid: r.cid.to_string(), indexed_at: rev_time(r.rev), record };
        if &*r.path == recent_writes::PROFILE_PATH {
            l.profile = Some(d);
        } else if crate::worker::collection_of(&r.path) == recent_writes::POST {
            l.posts.push(d);
        }
    }
    l
}

/// The requester's records written after `since` (the reference's
/// `getRecordsSinceRev`: the oldest 10, any collection), from the log or,
/// when it doesn't know, the store (and the log learns it).
async fn records_since(app: &App, did: &str, part: recent_writes::Part, since: u64) -> anyhow::Result<Vec<Rec>> {
    match recent_writes::lookup(did, part, since) {
        Since::Nothing => {
            COUNTERS.log_nothing.inc();
            return Ok(Vec::new());
        }
        Since::Records(r) => {
            COUNTERS.log_records.inc();
            return Ok(r);
        }
        Since::Unknown => COUNTERS.store_read.inc(),
    }
    let gen = recent_writes::generation(did);
    let p = app.partition(did).map_err(|e| anyhow::anyhow!(e.message))?;
    if (p.id, p.epoch) != part {
        return Ok(Vec::new()); // moved mid-request
    }
    let Some(raw) = p.db.get(state::head_key(did)).await? else { return Ok(Vec::new()) };
    let head = state::Head::decode(&raw)?;
    let nonempty = head.data != *vlsync_atproto::mst::EMPTY_ROOT;
    if since >= head.rev.0 {
        let read = recent_writes::Read { head: head.rev.0, base: head.rev.0, old_exists: nonempty, recs: Vec::new() };
        recent_writes::fill(did, part, gen, read, since);
        return Ok(Vec::new());
    }
    // no rev index: scan the repo's records for those written after `since`,
    // keeping only the oldest MAX_RECS of them (a max-heap on (rev, path))
    let repo_gen = app.repo_gen(did).await.map_err(|e| anyhow::anyhow!(e.message))?;
    let prefix = state::record_prefix(did, repo_gen);
    let mut iter = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?;
    let mut kept = std::collections::BinaryHeap::<ByRev>::with_capacity(recent_writes::MAX_RECS + 1);
    let (mut above, mut old, mut top) = (0usize, false, head.rev.0);
    while let Some(kv) = iter.next().await? {
        let rev = state::record_value_rev(&kv.value);
        if rev <= since {
            old = true;
            continue;
        }
        above += 1;
        top = top.max(rev);
        let path = std::str::from_utf8(&kv.key[prefix.len()..])?;
        if kept.len() == recent_writes::MAX_RECS && kept.peek().is_some_and(|m| (rev, path) >= (m.0.rev, &*m.0.path)) {
            continue;
        }
        let (cid, bytes) = state::decode_record_value(&kv.value)?;
        let bytes = recent_writes::keeps_bytes(path).then(|| Bytes::copy_from_slice(&bytes));
        kept.push(ByRev(Rec { path: path.into(), rev, cid, bytes }));
        if kept.len() > recent_writes::MAX_RECS {
            kept.pop();
        }
    }
    let mut recs: Vec<Rec> = kept.into_sorted_vec().into_iter().map(|r| r.0).collect();
    if above <= recent_writes::MAX_RECS {
        let read = recent_writes::Read { head: top, base: since, old_exists: old, recs };
        return Ok(match recent_writes::fill(did, part, gen, read, since) {
            Since::Records(r) => r,
            _ => Vec::new(),
        });
    }
    // too many to keep them all: the answer for `since` is kept until the
    // repo changes (an AppView that lags polls with the same rev)
    recs.truncate(recent_writes::LIMIT);
    let answer = if old { recs } else { Vec::new() };
    recent_writes::fill_lagging(did, part, gen, top, since, answer.clone());
    Ok(answer)
}

/// A record ordered by (rev, path), as [`recent_writes`] orders them.
struct ByRev(Rec);

impl PartialEq for ByRev {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o).is_eq()
    }
}
impl Eq for ByRev {}
impl PartialOrd for ByRev {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for ByRev {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.0.rev, &*self.0.path).cmp(&(o.0.rev, &*o.0.path))
    }
}

// Views of local records (reference LocalViewer)
// ----------------------------------------------

/// `util.format(pattern, ...args)` for `%s` (and `%%`).
fn format_pattern(pattern: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(pattern.len() + 128);
    let mut args = args.iter();
    let mut rest = pattern;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if let Some(t) = tail.strip_prefix("%s") {
            out.push_str(args.next().copied().unwrap_or("%s"));
            rest = t;
        } else if let Some(t) = tail.strip_prefix("%%") {
            out.push('%');
            rest = t;
        } else {
            out.push('%');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    for a in args {
        out.push(' ');
        out.push_str(a);
    }
    out
}

/// A blob's CID (reference `getBlobCidString`; legacy `{cid}` blobs too).
fn blob_cid(b: &J) -> Option<&str> {
    b.pointer("/ref/$link").and_then(J::as_str).or_else(|| b.get("cid").and_then(J::as_str))
}

/// An embed of lexicon type `t` (`t` or `t#main`).
fn is_type(v: &J, t: &str) -> bool {
    v.get("$type").and_then(J::as_str).is_some_and(|ty| ty == t || ty.strip_suffix("#main") == Some(t))
}

fn str_at<'a>(v: &'a J, ptr: &str) -> Option<&'a str> {
    v.pointer(ptr).and_then(J::as_str)
}

/// A munge step that can't proceed: the original response is returned.
#[derive(Debug)]
struct Abort;

type M<T> = Result<T, Abort>;

struct Viewer<'a> {
    app: &'a App,
    did: &'a str,
    acct: &'a CachedAcct,
}

impl Viewer<'_> {
    fn image_url(&self, preset: &str, cid: &str) -> String {
        match &self.app.config.appview_cdn_url_pattern {
            Some(p) => format_pattern(p, &[preset, self.did, cid]),
            None => format!("{}/xrpc/com.atproto.sync.getBlob?did={}&cid={cid}", self.app.public_url, self.did),
        }
    }

    fn image(&self, preset: &str, blob: &J) -> M<String> {
        Ok(self.image_url(preset, blob_cid(blob).ok_or(Abort)?))
    }

    /// Sets (or, when absent, removes) `key`.
    fn set(view: &mut J, key: &str, v: Option<J>) {
        if let Some(o) = view.as_object_mut() {
            match v {
                Some(v) => {
                    o.insert(key.into(), v);
                }
                None => {
                    o.remove(key);
                }
            }
        }
    }

    fn update_basic(&self, view: &mut J, record: &J) -> M<()> {
        Self::set(view, "displayName", record.get("displayName").cloned());
        let avatar = record.get("avatar").map(|a| self.image("avatar", a)).transpose()?;
        Self::set(view, "avatar", avatar.map(J::String));
        Ok(())
    }

    fn update_view(&self, view: &mut J, record: &J) -> M<()> {
        self.update_basic(view, record)?;
        Self::set(view, "description", record.get("description").cloned());
        Ok(())
    }

    fn update_detailed(&self, view: &mut J, record: &J) -> M<()> {
        self.update_view(view, record)?;
        let banner = record.get("banner").map(|b| self.image("banner", b)).transpose()?;
        Self::set(view, "banner", banner.map(J::String));
        Ok(())
    }

    /// The requester's ProfileViewBasic from its account and current
    /// profile record (None: no account).
    async fn profile_basic(&self) -> M<Option<J>> {
        let Ok(acct) = self.app.account(self.did).await else { return Ok(None) };
        let raw = self
            .app
            .record_value(self.did, Some(acct.repo_gen), recent_writes::PROFILE_PATH)
            .await
            .map_err(|_| Abort)?;
        let profile = match raw {
            Some(v) => state::decode_record_value(&v).ok().and_then(|(_, b)| record_json(&b)),
            None => None,
        };
        let handle = if acct.handle.is_empty() { "handle.invalid".to_string() } else { acct.handle.clone() };
        let mut v = json!({"did": self.did, "handle": handle});
        if let Some(p) = &profile {
            if let Some(d) = p.get("displayName") {
                v["displayName"] = d.clone();
            }
            if let Some(a) = p.get("avatar") {
                v["avatar"] = J::String(self.image("avatar", a)?);
            }
        }
        Ok(Some(v))
    }

    /// GET from the AppView as the requester.
    async fn appview(&self, lxm: &str, params: &[(&str, &str)]) -> M<J> {
        appview_json(self.app, lxm, params, Some((self.did, self.acct))).await.map_err(|_| Abort)
    }

    /// PostViews of `posts` (reference `getPost`), by URI; None where the
    /// author can't be built.
    async fn posts(&self, posts: &[&Desc]) -> M<HashMap<String, Option<J>>> {
        let mut out = HashMap::new();
        if posts.is_empty() {
            return Ok(out);
        }
        let author = self.profile_basic().await?;
        for d in posts {
            let view = match &author {
                None => None,
                Some(author) => {
                    let embed = match d.record.get("embed") {
                        Some(e) => self.post_embed(e).await?,
                        None => None,
                    };
                    let mut v = json!({
                        "uri": d.uri,
                        "cid": d.cid,
                        "likeCount": 0,
                        "replyCount": 0,
                        "repostCount": 0,
                        "quoteCount": 0,
                        "author": author,
                        "record": d.record,
                    });
                    if let Some(e) = embed {
                        v["embed"] = e;
                    }
                    v["indexedAt"] = J::String(d.indexed_at.clone());
                    Some(v)
                }
            };
            out.insert(d.uri.clone(), view);
        }
        Ok(out)
    }

    async fn post_embed(&self, embed: &J) -> M<Option<J>> {
        if is_type(embed, "app.bsky.embed.images") {
            Ok(Some(self.images_embed(embed)?))
        } else if is_type(embed, "app.bsky.embed.external") {
            Ok(Some(self.external_embed(embed)?))
        } else if is_type(embed, "app.bsky.embed.record") {
            Ok(Some(self.record_embed(embed).await?))
        } else if is_type(embed, "app.bsky.embed.recordWithMedia") {
            let media = embed.get("media").ok_or(Abort)?;
            let media = if is_type(media, "app.bsky.embed.images") {
                self.images_embed(media)?
            } else if is_type(media, "app.bsky.embed.external") {
                self.external_embed(media)?
            } else {
                return Ok(None);
            };
            let record = self.record_embed(embed.get("record").ok_or(Abort)?).await?;
            Ok(Some(json!({"$type": "app.bsky.embed.recordWithMedia#view", "record": record, "media": media})))
        } else {
            Ok(None)
        }
    }

    fn images_embed(&self, embed: &J) -> M<J> {
        let imgs = embed.get("images").and_then(J::as_array).ok_or(Abort)?;
        let mut out = Vec::with_capacity(imgs.len());
        for img in imgs {
            let blob = img.get("image").ok_or(Abort)?;
            let mut v = json!({
                "thumb": self.image("feed_thumbnail", blob)?,
                "fullsize": self.image("feed_fullsize", blob)?,
            });
            if let Some(a) = img.get("aspectRatio") {
                v["aspectRatio"] = a.clone();
            }
            if let Some(a) = img.get("alt") {
                v["alt"] = a.clone();
            }
            out.push(v);
        }
        Ok(json!({"$type": "app.bsky.embed.images#view", "images": out}))
    }

    fn external_embed(&self, embed: &J) -> M<J> {
        let ext = embed.get("external").ok_or(Abort)?;
        let mut v = json!({});
        for k in ["uri", "title", "description"] {
            if let Some(x) = ext.get(k) {
                v[k] = x.clone();
            }
        }
        if let Some(t) = ext.get("thumb") {
            v["thumb"] = J::String(self.image("feed_thumbnail", t)?);
        }
        Ok(json!({"$type": "app.bsky.embed.external#view", "external": v}))
    }

    async fn record_embed(&self, embed: &J) -> M<J> {
        let uri = str_at(embed, "/record/uri").ok_or(Abort)?;
        let view = match uri.strip_prefix("at://").and_then(|r| r.split('/').nth(1)) {
            Some(recent_writes::POST) => {
                let data = self.appview(GET_POSTS, &[("uris", uri)]).await?;
                data.pointer("/posts/0").map(|post| {
                    let mut v = json!({"$type": "app.bsky.embed.record#viewRecord"});
                    for (from, to) in [
                        ("uri", "uri"),
                        ("cid", "cid"),
                        ("author", "author"),
                        ("record", "value"),
                        ("labels", "labels"),
                    ] {
                        if let Some(x) = post.get(from) {
                            v[to] = x.clone();
                        }
                    }
                    if let Some(e) = post.get("embed") {
                        v["embeds"] = json!([e]);
                    }
                    if let Some(x) = post.get("indexedAt") {
                        v["indexedAt"] = x.clone();
                    }
                    v
                })
            }
            Some("app.bsky.feed.generator") => {
                let data = self.appview(GET_FEED_GENERATOR, &[("feed", uri)]).await?;
                Some(typed(data.get("view").ok_or(Abort)?, "app.bsky.feed.defs#generatorView"))
            }
            Some("app.bsky.graph.list") => {
                let data = self.appview(GET_LIST, &[("list", uri)]).await?;
                Some(typed(data.get("list").ok_or(Abort)?, "app.bsky.graph.defs#listView"))
            }
            _ => None,
        };
        let record = view
            .unwrap_or_else(|| json!({"$type": "app.bsky.embed.record#viewNotFound", "uri": uri, "notFound": true}));
        Ok(json!({"$type": "app.bsky.embed.record#view", "record": record}))
    }
}

/// `v` with `$type` set (lex `$build`).
fn typed(v: &J, t: &str) -> J {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.insert("$type".into(), J::String(t.into()));
    }
    v
}

// Munging (reference api/app/bsky/*)
// ----------------------------------

fn feed_items(v: &mut J) -> M<&mut Vec<J>> {
    let feed = v.get_mut("feed").and_then(J::as_array_mut).ok_or(Abort)?;
    if feed.iter().any(|i| i.pointer("/post/author").is_none_or(|a| !a.is_object())) {
        return Err(Abort);
    }
    Ok(feed)
}

/// Overlays the local profile on the requester's authors in a feed.
fn update_authors(viewer: &Viewer<'_>, feed: &mut [J], profile: &J) -> M<()> {
    for item in feed {
        let author = item.pointer_mut("/post/author").ok_or(Abort)?;
        if str_at(author, "/did") == Some(viewer.did) {
            viewer.update_basic(author, profile)?;
        }
    }
    Ok(())
}

/// Reference `formatAndInsertPostsInFeed`.
async fn insert_posts_in_feed(viewer: &Viewer<'_>, feed: &mut Vec<J>, posts: &[Desc]) -> M<()> {
    if posts.is_empty() {
        return Ok(());
    }
    let last = feed.last().and_then(|i| str_at(i, "/post/indexedAt")).unwrap_or("1970-01-01T00:00:00.000Z").to_string();
    let newest_first: Vec<&Desc> = posts.iter().filter(|p| p.indexed_at.as_str() > last.as_str()).rev().collect();
    let views = viewer.posts(&newest_first).await?;
    for d in newest_first {
        let Some(Some(post)) = views.get(&d.uri) else { continue };
        let at = post["indexedAt"].as_str().unwrap_or_default();
        let idx = feed.iter().position(|fi| str_at(fi, "/post/indexedAt").is_some_and(|t| t < at));
        let item = json!({"post": post});
        match idx {
            Some(i) => feed.insert(i, item),
            None => feed.push(item),
        }
    }
    Ok(())
}

/// Reference `isUsersFeed` (getAuthorFeed munges only the requester's own).
fn is_users_feed(feed: &[J], did: &str) -> bool {
    let Some(first) = feed.first() else { return false };
    match first.get("reason").filter(|r| !r.is_null()) {
        None => str_at(first, "/post/author/did") == Some(did),
        Some(r) => is_type(r, REASON_REPOST) && str_at(r, "/by/did") == Some(did),
    }
}

/// The replies a thread gets (reference `findPostsInThread`).
fn posts_in_thread<'a>(thread: &J, posts: &[&'a Desc]) -> Vec<&'a Desc> {
    let root = str_at(thread, "/post/uri");
    let thread_root = str_at(thread, "/post/record/reply/root/uri");
    posts
        .iter()
        .copied()
        .filter(|p| match str_at(&p.record, "/reply/root/uri") {
            None => false,
            Some(r) => Some(r) == root || Some(r) == thread_root,
        })
        .collect()
}

/// Reference `insertIntoThreadReplies`: a reply goes first among its
/// parent's replies, wherever the parent is in the tree.
fn insert_reply(view: &mut J, parent: &str, reply: &J) {
    if str_at(view, "/post/uri") == Some(parent) {
        let mut replies = vec![reply.clone()];
        if let Some(J::Array(old)) = view.get_mut("replies").map(std::mem::take) {
            replies.extend(old);
        }
        view["replies"] = J::Array(replies);
        return;
    }
    if let Some(J::Array(rs)) = view.get_mut("replies") {
        for r in rs.iter_mut().filter(|r| is_type(r, THREAD_VIEW_POST)) {
            insert_reply(r, parent, reply);
        }
    }
}

fn thread_view_post(post: &J) -> J {
    json!({"$type": THREAD_VIEW_POST, "post": post})
}

/// Reference `addPostsToThread`.
async fn add_posts_to_thread(viewer: &Viewer<'_>, thread: &mut J, posts: &[&Desc]) -> M<()> {
    let in_thread = posts_in_thread(thread, posts);
    if in_thread.is_empty() {
        return Ok(());
    }
    let views = viewer.posts(&in_thread).await?;
    for d in in_thread {
        let (Some(parent), Some(Some(post))) = (str_at(&d.record, "/reply/parent/uri"), views.get(&d.uri)) else {
            continue;
        };
        insert_reply(thread, parent, &thread_view_post(post));
    }
    Ok(())
}

async fn munge(kind: Kind, viewer: &Viewer<'_>, mut v: J, local: &Local) -> M<J> {
    if !v.is_object() {
        return Err(Abort);
    }
    let me = viewer.did;
    match kind {
        Kind::Profile => {
            str_at(&v, "/did").ok_or(Abort)?;
            if let Some(p) = local.profile.as_ref().filter(|_| str_at(&v, "/did") == Some(me)) {
                viewer.update_detailed(&mut v, &p.record)?;
            }
        }
        Kind::Profiles => {
            let profiles = v.get_mut("profiles").and_then(J::as_array_mut).ok_or(Abort)?;
            if let Some(p) = &local.profile {
                for prof in profiles.iter_mut() {
                    if str_at(prof, "/did") == Some(me) {
                        viewer.update_detailed(prof, &p.record)?;
                    }
                }
            }
        }
        Kind::ActorLikes => {
            let feed = feed_items(&mut v)?;
            if let Some(p) = &local.profile {
                update_authors(viewer, feed, &p.record)?;
            }
        }
        Kind::AuthorFeed => {
            let feed = feed_items(&mut v)?;
            if is_users_feed(feed, me) {
                if let Some(p) = &local.profile {
                    update_authors(viewer, feed, &p.record)?;
                }
                insert_posts_in_feed(viewer, feed, &local.posts).await?;
            }
        }
        Kind::Timeline => {
            let feed = feed_items(&mut v)?;
            insert_posts_in_feed(viewer, feed, &local.posts).await?;
        }
        Kind::PostThread => {
            let thread = v.get_mut("thread").ok_or(Abort)?;
            if is_type(thread, THREAD_VIEW_POST) {
                let posts: Vec<&Desc> = local.posts.iter().collect();
                add_posts_to_thread(viewer, thread, &posts).await?;
            }
        }
    }
    Ok(v)
}

fn munged_response(body: &J, lag: Option<i64>) -> Response {
    let mut r = Response::new(Body::from(serde_json::to_vec(body).unwrap_or_default()));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json; charset=utf-8"));
    if let Some(l) = lag {
        h.insert(UPSTREAM_LAG, l.into());
    }
    r
}

/// Proxies `f` for `kind` with read-after-write (reference
/// `pipethroughReadAfterWrite`). `f.iss` is the requester.
pub(super) async fn proxy(
    app: &App,
    target: &Target<'_>,
    mut f: Forward<'_>,
    acct: &CachedAcct,
    kind: Kind,
) -> XResult<Response> {
    let did = f.iss.expect("read-after-write needs the requester");
    let pq = f.path_and_query;
    check_accept_encoding(f.headers.get(header::ACCEPT_ENCODING))?;
    f.accept_encoding = accept_encoding(f.headers.get(header::ACCEPT_ENCODING));
    let (parts, body) = send(app, target, f, Some(acct)).await?;
    if parts.status.as_u16() >= 400 {
        let err = UpstreamError::read(parts, body).await;
        if kind == Kind::PostThread && err.error.as_deref() == Some("NotFound") {
            if let Some(r) = thread_not_found(app, acct, did, pq, &err.headers).await {
                return Ok(r);
            }
        }
        return Ok(err.into_response());
    }
    let Some(rev) = parts.headers.get(REPO_REV).and_then(|v| v.to_str().ok()).and_then(vlsync_atproto::tid::Tid::parse)
    else {
        return Ok(passthrough(parts, body));
    };
    let json = parts.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_none_or(is_json_content_type);
    if !json {
        return Ok(passthrough(parts, body));
    }
    let recs = match records_since(app, did, acct.part, rev.0).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(did, "read-after-write: local records: {e}");
            COUNTERS.failed.inc();
            return Ok(passthrough(parts, body));
        }
    };
    if recs.is_empty() {
        return Ok(passthrough(parts, body));
    }
    let Some(codings) = codings(&parts.headers) else {
        COUNTERS.unchanged.inc();
        return Ok(passthrough(parts, body)); // an encoding we can't read (we didn't ask for it)
    };
    let raw = axum::body::to_bytes(body, MAX_RESPONSE_BYTES).await.map_err(|e| upstream_failure(&e.to_string()))?;
    let original = |raw: Bytes| passthrough(parts.clone(), Body::from(raw));
    let inline = codings.is_empty() && raw.len() <= INLINE_BYTES;
    let r = raw.clone();
    let decoded = cpu(inline, move || decode(r, &codings, MAX_RESPONSE_BYTES))
        .await
        .and_then(|r| r)
        .map_err(|e| upstream_failure(&e))?;
    // its parsed form stays in memory while munging (AppView calls)
    let kib = (decoded.len() >> 10).max(1) as u32;
    let Ok(_mem) = MEM.try_acquire_many(kib) else {
        tracing::debug!(did, bytes = decoded.len(), "read-after-write: over the munge budget, returned as is");
        COUNTERS.unchanged.inc();
        return Ok(original(raw));
    };
    let inline = decoded.len() <= INLINE_BYTES;
    let Ok(Ok(v)) = cpu(inline, move || serde_json::from_slice::<J>(&decoded)).await else {
        COUNTERS.unchanged.inc();
        return Ok(original(raw));
    };
    let local = local_of(did, recs);
    let viewer = Viewer { app, did, acct };
    match munge(kind, &viewer, v, &local).await {
        Ok(v) => {
            COUNTERS.munged.inc();
            let lag = local.lag();
            cpu(inline, move || munged_response(&v, lag)).await.map_err(|e| upstream_failure(&e))
        }
        Err(Abort) => {
            COUNTERS.unchanged.inc();
            Ok(original(raw))
        }
    }
}

/// The at-URI's (authority, collection, rkey).
fn at_uri_parts(uri: &str) -> Option<(&str, Option<&str>, Option<&str>)> {
    let rest = uri.strip_prefix("at://")?;
    let rest = rest.split(['?', '#']).next()?;
    let mut it = rest.splitn(3, '/');
    let host = it.next().filter(|h| !h.is_empty())?;
    Some((host, it.next().filter(|s| !s.is_empty()), it.next().filter(|s| !s.is_empty())))
}

fn query_params(pq: &str) -> Vec<(String, String)> {
    reqwest::Url::parse(&format!("http://x{pq}"))
        .map(|u| u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect())
        .unwrap_or_default()
}

/// getPostThread of the requester's own post the AppView hasn't indexed
/// yet (reference `readAfterWriteNotFound`): the thread is built locally,
/// its parents fetched from the AppView.
async fn thread_not_found(app: &App, acct: &CachedAcct, did: &str, pq: &str, headers: &HeaderMap) -> Option<Response> {
    let rev = headers.get(REPO_REV)?.to_str().ok().and_then(vlsync_atproto::tid::Tid::parse)?;
    let params = query_params(pq);
    let param = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let (host, coll, rkey) = at_uri_parts(param("uri")?)?;
    if host != did {
        // a handle: only the requester's own matters
        if host.starts_with("did:") || app.account(did).await.ok()?.handle != host.to_ascii_lowercase() {
            return None;
        }
    }
    let uri = format!("at://{did}/{}/{}", coll?, rkey?);
    let recs = records_since(app, did, acct.part, rev.0).await.ok()?;
    let local = local_of(did, recs);
    let found = local.posts.iter().find(|p| p.uri == uri)?;
    let viewer = Viewer { app, did, acct };
    let views = viewer.posts(&[found]).await.ok()?;
    let mut thread = thread_view_post(views.get(&uri)?.as_ref()?);
    let rest: Vec<&Desc> = local.posts.iter().filter(|p| p.uri != uri).collect();
    add_posts_to_thread(&viewer, &mut thread, &rest).await.ok()?;
    // reference getHighestParent: the post's own parent (it has no parent view yet)
    let parent =
        Some(&found.record).filter(|r| is_type(r, recent_writes::POST)).and_then(|r| str_at(r, "/reply/parent/uri"));
    if let Some(parent) = parent {
        let mut q = vec![("uri", parent), ("depth", "0")];
        if let Some(h) = param("parentHeight") {
            q.push(("parentHeight", h));
        }
        if let Ok(res) = viewer.appview(GET_POST_THREAD, &q).await {
            if let Some(t) = res.get("thread") {
                thread["parent"] = t.clone();
            }
        }
    }
    Some(munged_response(&json!({ "thread": thread }), local.lag()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn util_format() {
        assert_eq!(
            format_pattern("https://cdn/img/%s/plain/%s/%s@jpeg", &["avatar", "did:x", "bafy"]),
            "https://cdn/img/avatar/plain/did:x/bafy@jpeg"
        );
        assert_eq!(format_pattern("%s%%", &["a", "b"]), "a% b");
    }

    #[test]
    fn accept_encodings() {
        let hv = |s: &str| header::HeaderValue::from_str(s).unwrap();
        assert!(accept_encoding(Some(&hv("gzip, deflate"))).is_none());
        assert!(accept_encoding(None).is_none());
        assert!(accept_encoding(Some(&hv("gzip, br"))).is_none());
        assert!(accept_encoding(Some(&hv("br, zstd"))).is_none());
        assert_eq!(accept_encoding(Some(&hv("compress"))).unwrap(), "identity");
        assert_eq!(accept_encoding(Some(&hv("gzip, compress"))).unwrap(), "gzip");
        assert_eq!(accept_encoding(Some(&hv("compress;q=1, *;q=0.5"))).unwrap(), "gzip;q=0.5, deflate;q=0.5, br;q=0.5");
        assert_eq!(accept_encoding(Some(&hv("gzip, *;q=0"))).unwrap(), "gzip, deflate;q=0, br;q=0");
        assert_eq!(accept_encoding(Some(&hv("br, *;q=0"))).unwrap(), "br, gzip;q=0, deflate;q=0");
    }

    #[test]
    fn accept_encoding_negotiation() {
        let hv = |s: &str| header::HeaderValue::from_str(s).unwrap();
        let check = |s: &str| check_accept_encoding(Some(&hv(s))).map_err(|e| (e.status.as_u16(), e.message));
        for ok in
            ["identity", "gzip, *;q=0", "invalid", "br", "br, identity;q=0", "gzip;q=0.5, deflate", "GZIP;Q=1", "*"]
        {
            assert!(check(ok).is_ok(), "{ok}");
        }
        assert!(check_accept_encoding(None).is_ok());
        for bad in [";q=1", "gzip;q=2", "gzip;foo=1", "gzip;q", "gzip;q=1;x", "gzip, ", "q=1"] {
            assert_eq!(check(bad).unwrap_err().0, 400, "{bad}");
        }
        assert_eq!(check(";q=1").unwrap_err().1, "Invalid accept-encoding: \";q=1\"");
        for none in ["invalid, *;q=0", "identity;q=0", "compress, identity;q=0", "*;q=0", "br;q=0, identity;q=0"] {
            assert_eq!(
                check(none).unwrap_err(),
                (406, "this service does not support any of the requested encodings".to_string()),
                "{none}"
            );
        }
    }

    #[test]
    fn decodes() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"{\"a\":1}").unwrap();
        let gz = Bytes::from(e.finish().unwrap());
        let m = MAX_RESPONSE_BYTES;
        assert_eq!(&decode(gz.clone(), &["gzip".into()], m).unwrap()[..], b"{\"a\":1}");
        assert!(decode(Bytes::from_static(b"nope"), &["gzip".into()], m).is_err());
        let zs = Bytes::from(zstd::encode_all(&b"{}"[..], 1).unwrap());
        assert_eq!(&decode(zs, &["zstd".into()], m).unwrap()[..], b"{}");
        let mut br = Vec::new();
        brotli::BrotliCompress(&mut &b"{\"b\":2}"[..], &mut br, &Default::default()).unwrap();
        assert_eq!(&decode(Bytes::from(br), &["br".into()], m).unwrap()[..], b"{\"b\":2}");
        assert!(decode(Bytes::from_static(b"nope"), &["br".into()], m).is_err());
    }

    /// Untrusted upstream bodies decode within bounds: a zstd frame asking
    /// for a window above 2^23 is refused (not a 128 MiB+ allocation), a
    /// chain of more than two codings isn't decoded at all, and a bomb
    /// stops at the decoded limit.
    #[test]
    fn decoding_is_bounded() {
        use std::io::Write;
        // window log 27 (zstd's default maximum): refused here
        let data = vec![b'a'; 1 << 20];
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        enc.set_parameter(zstd::stream::raw::CParameter::WindowLog(27)).unwrap();
        enc.include_contentsize(false).unwrap();
        enc.write_all(&data).unwrap();
        let big_window = Bytes::from(enc.finish().unwrap());
        assert!(decode(big_window, &["zstd".into()], MAX_RESPONSE_BYTES).is_err());
        // window log 23: fine
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        enc.set_parameter(zstd::stream::raw::CParameter::WindowLog(23)).unwrap();
        enc.write_all(&data).unwrap();
        let ok = Bytes::from(enc.finish().unwrap());
        assert_eq!(decode(ok, &["zstd".into()], MAX_RESPONSE_BYTES).unwrap().len(), 1 << 20);
        // coding chains: two decode, three are refused (header and decode)
        let gz = |b: &[u8]| {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(b).unwrap();
            e.finish().unwrap()
        };
        let twice = Bytes::from(gz(&gz(b"{}")));
        assert_eq!(&decode(twice, &["gzip".into(), "gzip".into()], 1024).unwrap()[..], b"{}");
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_ENCODING, header::HeaderValue::from_static("gzip, gzip"));
        assert_eq!(codings(&h).map(|c| c.len()), Some(2));
        h.insert(header::CONTENT_ENCODING, header::HeaderValue::from_static("gzip, gzip, gzip"));
        assert_eq!(codings(&h), None);
        assert!(decode(Bytes::new(), &["gzip".into(), "gzip".into(), "gzip".into()], 1024).is_err());
        // a bomb: 64 MiB of zeros in ~64 KiB, stopped at the limit
        let bomb = Bytes::from(gz(&vec![0u8; 64 << 20]));
        assert!(bomb.len() < 1 << 20);
        assert_eq!(decode(bomb, &["gzip".into()], MAX_RESPONSE_BYTES).unwrap_err(), "upstream response too large");
    }

    #[test]
    fn thread_replies_nest() {
        let mut t = json!({"$type": THREAD_VIEW_POST, "post": {"uri": "at://a/p/1"}, "replies": [
            {"$type": THREAD_VIEW_POST, "post": {"uri": "at://a/p/2"}}
        ]});
        insert_reply(&mut t, "at://a/p/2", &thread_view_post(&json!({"uri": "at://a/p/3"})));
        insert_reply(&mut t, "at://a/p/1", &thread_view_post(&json!({"uri": "at://a/p/4"})));
        assert_eq!(t["replies"][0]["post"]["uri"], "at://a/p/4");
        assert_eq!(t["replies"][1]["replies"][0]["post"]["uri"], "at://a/p/3");
    }
}
