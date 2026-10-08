//! Lexicon validation: one schema interpreter over schemas compiled once
//! ([`Lexicons`]), with messages as @atproto/lexicon words them.
//!
//! - Records, like the reference's `validateRecord`: a record whose `$type`
//!   has a schema is checked and reported `valid`; unknown types are
//!   `unknown` unless `validate: true` was requested.
//! - XRPC params and JSON inputs of the bundled com.atproto.* methods,
//!   checked by the extractors. Outputs are checked in debug builds only, to
//!   catch handler bugs in the test suite at no prod cost.
//! - Opt-in dynamic resolution of record types without a bundled schema
//!   (the reference has none yet): a write waits at most the configured
//!   timeout and otherwise treats the type as unknown, while the resolution
//!   finishes in the background for later writes.
//!
//! Like the reference, extra object properties are allowed and open-union
//! members of unknown types are not validated; refs from a resolved lexicon
//! into other unbundled lexicons are not followed. `lexicons/bundle.json`
//! is regenerated with `lexicons/bundle.py`.

use crate::xrpc::App;
use futures::FutureExt;
use serde_json::Value as J;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use unicode_segmentation::UnicodeSegmentation;
use vlsync_atproto::cbor::{JsonValue, Value};
use vlsync_atproto::syntax;

static BUNDLE: LazyLock<Lexicons> = LazyLock::new(|| {
    let docs: HashMap<String, J> =
        serde_json::from_str(include_str!("../lexicons/bundle.json")).expect("bundled lexicons");
    Lexicons::compile(docs.iter().map(|(k, d)| (k.as_str(), d)), None)
});

/// `Some("valid" | "unknown")`, or `None` when skipped (`validate: false`).
pub type ValidationStatus = Option<&'static str>;

/// `record`'s `$type` is already set to `collection`. Bundled schemas take
/// precedence over `resolved` ([`resolve_record_schema`]).
pub fn validate_record<N: Node>(
    collection: &str,
    rkey: &str,
    record: &N,
    validate: Option<bool>,
    resolved: Option<&Lexicons>,
) -> Result<ValidationStatus, String> {
    if validate == Some(false) {
        return Ok(None);
    }
    let resolved = resolved.filter(|d| d.id.as_deref() == Some(collection));
    let found = match BUNDLE.records.get(collection) {
        Some(r) => Some((&*BUNDLE, r)),
        None => resolved.and_then(|d| Some((d, d.records.get(collection)?))),
    };
    let Some((set, main)) = found else {
        if validate == Some(true) {
            return Err(format!("Unknown lexicon type: {collection}"));
        }
        return Ok(Some("unknown"));
    };
    let key = &*main.key;
    let key_ok = match key {
        "tid" => valid_tid(rkey),
        "nsid" => syntax::valid_nsid(rkey),
        "any" | "record-key" => syntax::valid_rkey(rkey),
        k => match k.strip_prefix("literal:") {
            Some(lit) => rkey == lit,
            None => syntax::valid_rkey(rkey),
        },
    };
    if !key_ok {
        return Err(format!("Invalid record key for {collection}: must be {key}, got {rkey:?}"));
    }
    let mut v = Validator::new("record", resolved);
    v.check(set, &main.schema, record).map_err(|e| format!("Invalid {collection} record: {e}"))?;
    Ok(Some("valid"))
}

/// [`syntax::valid_tid`] through a lookup table (every TID record key pays
/// for it). Same accepted strings (tests/all/shrike_adopt.rs).
pub fn valid_tid(s: &str) -> bool {
    // bit 0: base32-sortable character; bit 1: allowed first character
    const T: [u8; 256] = {
        let mut t = [0u8; 256];
        let all = b"234567abcdefghijklmnopqrstuvwxyz";
        let mut i = 0;
        while i < all.len() {
            t[all[i] as usize] = if i < 16 { 3 } else { 1 };
            i += 1;
        }
        t
    };
    let b = s.as_bytes();
    b.len() == 13 && T[b[0] as usize] & 2 != 0 && b.iter().all(|&c| T[c as usize] & 1 != 0)
}

fn is_record(d: &J) -> bool {
    d["type"] == "record"
}

/// `#name` / `nsid#name` / `nsid` -> (nsid, name), relative to `ctx`.
fn split_ref<'a>(r: &'a str, ctx: &'a str) -> (&'a str, &'a str) {
    match r.split_once('#') {
        Some(("", name)) => (ctx, name),
        Some((nsid, name)) => (nsid, name),
        None => (r, "main"),
    }
}

/// Methods whose vlpds input deliberately extends the lexicon:
/// updateAccountSigningKey generates a key when `signingKey` is omitted.
const EXTENDED_INPUTS: &[&str] = &["com.atproto.admin.updateAccountSigningKey"];

pub fn has_input_schema(nsid: &str) -> bool {
    !EXTENDED_INPUTS.contains(&nsid) && BUNDLE.methods.get(nsid).is_some_and(|m| m.input.is_some())
}

pub fn has_params(nsid: &str) -> bool {
    BUNDLE.methods.get(nsid).is_some_and(|m| m.params.is_some())
}

pub fn validate_input<N: Node>(nsid: &str, body: &N) -> Result<(), String> {
    if EXTENDED_INPUTS.contains(&nsid) {
        return Ok(());
    }
    validate_payload(BUNDLE.methods.get(nsid).and_then(|m| m.input.as_ref()), "Input", body)
}

pub fn validate_output(nsid: &str, body: &J) -> Result<(), String> {
    validate_payload(BUNDLE.methods.get(nsid).and_then(|m| m.output.as_ref()), "Output", body)
}

fn validate_payload<N: Node>(schema: Option<&Schema>, root: &str, body: &N) -> Result<(), String> {
    let Some(schema) = schema else {
        return Ok(());
    };
    if !matches!(body.kind(), Kind::Map) {
        return Err(format!("{root} must be an object"));
    }
    Validator::new(root, None).check(&BUNDLE, schema, body)
}

/// The raw pairs are decoded per the param types like the reference's
/// `decodeQueryParams`. Empty values count as absent; unknown params are
/// ignored.
pub fn validate_params(nsid: &str, pairs: &[(String, String)]) -> Result<(), String> {
    let Some(params) = BUNDLE.methods.get(nsid).and_then(|m| m.params.as_ref()) else {
        return Ok(());
    };
    for p in params {
        let k = &*p.name;
        let decode = |s: &str| match p.item {
            ParamType::Integer => s.parse::<i64>().map(J::from).unwrap_or_else(|_| J::String(s.into())),
            ParamType::Boolean => match s {
                "true" => J::Bool(true),
                "false" => J::Bool(false),
                _ => J::String(s.into()),
            },
            ParamType::Other => J::String(s.into()),
        };
        let mut vals = pairs.iter().filter(|(pk, v)| pk == k && !v.is_empty()).map(|(_, v)| decode(v));
        let value = if p.is_array {
            let a: Vec<J> = vals.collect();
            (!a.is_empty()).then_some(J::Array(a))
        } else {
            vals.next()
        };
        match value {
            None if p.required => return Err(format!("Params must have the property \"{k}\"")),
            None => {}
            Some(v) => Validator::new(k, None).check(&BUNDLE, &p.schema, &v)?,
        }
    }
    Ok(())
}

pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
const RESOLVED_TTL: Duration = Duration::from_secs(600);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);

type Resolution = futures::future::Shared<futures::future::BoxFuture<'static, Option<Arc<Lexicons>>>>;

enum Slot {
    Done {
        at: Instant,
        doc: Option<Arc<Lexicons>>,
    },
    /// In flight; `prev` is the last good document, served meanwhile.
    Pending {
        fut: Resolution,
        prev: Option<Arc<Lexicons>>,
    },
}

impl Slot {
    fn fresh(&self) -> bool {
        match self {
            Slot::Done { at, doc } => at.elapsed() < if doc.is_some() { RESOLVED_TTL } else { NEGATIVE_TTL },
            Slot::Pending { .. } => true,
        }
    }
}

/// Resolved, failed or in flight.
static RESOLVED: LazyLock<Arc<Resolved>> =
    LazyLock::new(|| crate::caches::track(crate::caches::Cache::Lexicons, Default::default()));

struct Resolved(parking_lot::Mutex<lru::LruCache<String, Slot>>);

impl Default for Resolved {
    fn default() -> Self {
        Resolved(parking_lot::Mutex::new(lru::LruCache::unbounded()))
    }
}

impl crate::caches::Len for Resolved {
    fn len(&self) -> usize {
        self.0.lock().len()
    }
}

/// The cap is runtime-configurable, so it isn't the LRU's own.
fn insert_capped(m: &mut lru::LruCache<String, Slot>, k: String, v: Slot) {
    m.put(k, v);
    let cap = crate::caches::cap(crate::caches::Cache::Lexicons).max(1);
    while m.len() > cap {
        m.pop_lru();
    }
}

/// Only when resolution is enabled, validation isn't skipped and no schema
/// is bundled. Waits at most `Config::resolve_lexicons`; None on failure or
/// timeout. Concurrent writes of the same type share one resolution.
pub async fn resolve_record_schema(app: &Arc<App>, collection: &str, validate: Option<bool>) -> Option<Arc<Lexicons>> {
    let timeout = app.config.resolve_lexicons?;
    if validate == Some(false) || BUNDLE.records.contains_key(collection) || !syntax::valid_nsid(collection) {
        return None;
    }
    let (fut, prev) = {
        let mut m = RESOLVED.0.lock();
        match m.get(collection) {
            Some(Slot::Pending { fut, prev }) => (fut.clone(), prev.clone()),
            Some(s @ Slot::Done { doc, .. }) if s.fresh() => return doc.clone(),
            other => {
                let prev = match other {
                    Some(Slot::Done { doc, .. }) => doc.clone(),
                    _ => None,
                };
                let fut = spawn_resolution(app.clone(), collection.to_string(), prev.clone());
                insert_capped(&mut m, collection.to_string(), Slot::Pending { fut: fut.clone(), prev: prev.clone() });
                (fut, prev)
            }
        }
    };
    tokio::time::timeout(timeout, fut).await.unwrap_or(prev)
}

/// Resolves in a task of its own, so a write that stops waiting doesn't
/// cancel it; the result lands in the cache either way. A failed refresh
/// keeps serving the last good document.
fn spawn_resolution(app: Arc<App>, nsid: String, prev: Option<Arc<Lexicons>>) -> Resolution {
    let task = tokio::spawn(async move {
        let doc = crate::oauth::lexicon::resolve(&app, &nsid).await.and_then(|(_, doc)| record_lexicon(&nsid, doc));
        let doc = match doc {
            Ok(d) => Some(Arc::new(d)),
            Err(e) => {
                tracing::debug!(nsid, "lexicon resolution failed: {e}");
                prev
            }
        };
        insert_capped(&mut RESOLVED.0.lock(), nsid, Slot::Done { at: Instant::now(), doc: doc.clone() });
        doc
    });
    async move { task.await.ok().flatten() }.boxed().shared()
}

fn record_lexicon(nsid: &str, doc: J) -> Result<Lexicons, String> {
    if doc["lexicon"].as_i64() != Some(1) || doc["id"] != nsid {
        return Err(format!("Invalid Lexicon document for {nsid}"));
    }
    if !doc["defs"]["main"].get("record").is_some_and(|r| r.is_object()) || !is_record(&doc["defs"]["main"]) {
        return Err(format!("Lexicon {nsid} is not a record type"));
    }
    Ok(Lexicons::resolved(&doc))
}

/// A space type declaration: a lexicon whose main def is `"type": "space"`,
/// the consent unit of `space:` OAuth scopes (@atproto/lexicon `lexSpace`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceDecl {
    pub name: String,
    /// (language tag, name)
    pub name_lang: Vec<(String, String)>,
    pub description: Option<String>,
    pub key: Option<String>,
    pub collections: Vec<String>,
}

pub fn space_declaration(nsid: &str, doc: &J) -> Result<SpaceDecl, String> {
    if doc["lexicon"].as_i64() != Some(1) || doc["id"] != nsid {
        return Err(format!("Invalid Lexicon document for {nsid}"));
    }
    let defs = doc["defs"].as_object().ok_or_else(|| format!("Invalid Lexicon document for {nsid}"))?;
    const MAIN_ONLY: &[&str] = &["record", "permission-set", "space", "procedure", "query", "subscription"];
    if defs.iter().any(|(k, d)| k != "main" && d["type"].as_str().is_some_and(|t| MAIN_ONLY.contains(&t))) {
        return Err(
            "Records, permission sets, spaces, procedures, queries, and subscriptions must be the main definition."
                .into(),
        );
    }
    let main = defs
        .get("main")
        .filter(|m| m["type"] == "space")
        .ok_or_else(|| format!("Lexicon {nsid} is not a space type"))?;
    let bad = |field: &str| format!("Invalid space type {nsid}: {field}");
    let opt_str = |k: &str| match main.get(k) {
        None => Ok(None),
        Some(J::String(v)) => Ok(Some(v.clone())),
        Some(_) => Err(bad(k)),
    };
    // proposals #118 renames `name` to `title`; either is taken
    let field = if main.get("name").is_none() && main.get("title").is_some() { "title" } else { "name" };
    // zod's string length: UTF-16 code units
    let name = main[field]
        .as_str()
        .filter(|n| (1..=64).contains(&n.encode_utf16().count()))
        .ok_or_else(|| bad(field))?
        .to_string();
    let lang_field = format!("{field}:lang");
    let name_lang = match main.get(&lang_field) {
        None => Vec::new(),
        Some(J::Object(m)) => m
            .iter()
            .map(|(lang, v)| match v.as_str() {
                Some(v) if valid_language(lang) => Ok((lang.clone(), v.to_string())),
                _ => Err(bad(&lang_field)),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(bad(&lang_field)),
    };
    // a bare grant takes these as its collections, so a `*` or junk here
    // would widen it or make it unusable after consent
    let collections = main["collections"]
        .as_array()
        .and_then(|c| {
            c.iter().map(|v| v.as_str().filter(|n| syntax::valid_nsid(n)).map(String::from)).collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| bad("collections"))?;
    let key = opt_str("key")?;
    let key_ok = |k: &str| match k {
        "tid" | "nsid" | "any" | "record-key" => true,
        k => k.strip_prefix("literal:").is_some_and(syntax::valid_rkey),
    };
    if key.as_deref().is_some_and(|k| !key_ok(k)) {
        return Err(bad("key"));
    }
    Ok(SpaceDecl { name, name_lang, description: opt_str("description")?, key, collections })
}

/// Lexicon documents compiled into an arena of defs with refs resolved to
/// indexes and message fragments precomputed, so validation never touches
/// the JSON. A resolved document is a set of its own whose refs to other
/// NSIDs point into the bundle.
pub struct Lexicons {
    defs: Vec<Schema>,
    index: HashMap<Box<str>, HashMap<Box<str>, u32>>,
    records: HashMap<Box<str>, Record>,
    methods: HashMap<Box<str>, Method>,
    /// None for the bundle.
    id: Option<Box<str>>,
}

struct Record {
    key: Box<str>,
    schema: Schema,
}

struct Method {
    params: Option<Vec<Param>>,
    /// `application/json` only.
    input: Option<Schema>,
    output: Option<Schema>,
}

struct Param {
    name: Box<str>,
    schema: Schema,
    is_array: bool,
    /// The item type for arrays.
    item: ParamType,
    required: bool,
}

enum ParamType {
    Integer,
    Boolean,
    Other,
}

enum Target {
    Local(u32),
    /// From a resolved document.
    Bundle(u32),
    /// From the bundle, a def it doesn't have: a resolved document for that
    /// NSID may define it.
    Unbundled(Box<str>, Box<str>),
    Missing,
}

/// `token`, `params`, `query`, `procedure`, `subscription` and unknown types
/// compile to [`Schema::Any`].
enum Schema {
    Any,
    Object(Box<Object>),
    Ref(Target),
    Union(Box<Union>),
    String(Box<Str>),
    Integer(Box<Int>),
    Boolean { konst: Option<bool> },
    Bytes { min: Option<u64>, max: Option<u64> },
    CidLink,
    Blob(Box<Blob>),
    Array(Box<Array>),
    Unknown,
    Null,
}

struct Object {
    /// (name, nullable), in declaration order.
    required: Vec<(Box<str>, bool)>,
    /// (name, schema, nullable), in the document's key order.
    props: Vec<(Box<str>, Schema, bool)>,
}

struct Union {
    ctx: Box<str>,
    refs: Vec<(Box<str>, Box<str>, Target)>,
    /// Closed unions' error message.
    closed: Option<String>,
}

struct Str {
    konst: Option<Box<str>>,
    enumeration: Option<(Vec<Box<str>>, String)>,
    max_len: Option<u64>,
    min_len: Option<u64>,
    min_graphemes: Option<u64>,
    max_graphemes: Option<u64>,
    format: Option<Format>,
}

#[derive(Clone, Copy)]
enum Format {
    Datetime,
    Uri,
    AtUri,
    Did,
    Handle,
    AtIdentifier,
    Nsid,
    Cid,
    Language,
    Tid,
    RecordKey,
    SpaceRef,
}

struct Int {
    /// None never matches.
    konst: Option<(Option<i64>, String)>,
    enumeration: Option<(Vec<i64>, String)>,
    min: Option<i64>,
    max: Option<i64>,
}

struct Blob {
    accept: Option<(Vec<Box<str>>, String)>,
    max_size: Option<i64>,
}

struct Array {
    min: Option<u64>,
    max: Option<u64>,
    items: Option<Schema>,
}

impl Lexicons {
    /// `own` is a resolved document's NSID.
    fn compile<'d>(docs: impl Iterator<Item = (&'d str, &'d J)> + Clone, own: Option<&str>) -> Self {
        let mut index: HashMap<Box<str>, HashMap<Box<str>, u32>> = HashMap::new();
        let mut order = Vec::new();
        for (nsid, doc) in docs.clone() {
            let names = index.entry(nsid.into()).or_default();
            for (name, d) in doc.get("defs").and_then(|d| d.as_object()).into_iter().flatten() {
                names.insert(name.as_str().into(), order.len() as u32);
                order.push((nsid, d));
            }
        }
        let mut set = Lexicons {
            defs: Vec::with_capacity(order.len()),
            index,
            records: HashMap::new(),
            methods: HashMap::new(),
            id: own.map(Into::into),
        };
        let defs: Vec<Schema> = order.iter().map(|(nsid, d)| set.schema(d, nsid)).collect();
        for (nsid, doc) in docs {
            let main = &doc["defs"]["main"];
            if is_record(main) {
                let schema = set.schema(&main["record"], nsid);
                let key = main["key"].as_str().unwrap_or("any").into();
                set.records.insert(nsid.into(), Record { key, schema });
            } else if matches!(main["type"].as_str(), Some("query" | "procedure")) {
                let m = set.method(main, nsid);
                set.methods.insert(nsid.into(), m);
            }
        }
        set.defs = defs;
        set
    }

    pub fn resolved(doc: &J) -> Self {
        let id = doc["id"].as_str().unwrap_or("");
        Lexicons::compile(std::iter::once((id, doc)), Some(id))
    }

    fn lookup(&self, nsid: &str, name: &str) -> Option<u32> {
        self.index.get(nsid)?.get(name).copied()
    }

    fn target(&self, nsid: &str, name: &str) -> Target {
        match &self.id {
            // a resolved document: its own defs, else the bundle's
            Some(id) if **id == *nsid => self.lookup(nsid, name).map_or(Target::Missing, Target::Local),
            Some(_) => BUNDLE.lookup(nsid, name).map_or(Target::Missing, Target::Bundle),
            None => self.lookup(nsid, name).map_or_else(|| Target::Unbundled(nsid.into(), name.into()), Target::Local),
        }
    }

    fn method(&self, m: &J, nsid: &str) -> Method {
        let payload = |which: &str| {
            let p = m.get(which)?;
            (p["encoding"] == "application/json").then(|| p.get("schema")).flatten().map(|s| self.schema(s, nsid))
        };
        let params = m.get("parameters").map(|params| {
            let required =
                |k: &str| params.get("required").and_then(|r| r.as_array()).is_some_and(|r| r.iter().any(|x| x == k));
            let props = params.get("properties").and_then(|p| p.as_object());
            props
                .into_iter()
                .flatten()
                .map(|(k, pd)| {
                    let is_array = pd["type"] == "array";
                    let item_type = if is_array { pd["items"]["type"].as_str() } else { pd["type"].as_str() };
                    Param {
                        name: k.as_str().into(),
                        schema: self.schema(pd, nsid),
                        is_array,
                        item: match item_type {
                            Some("integer") => ParamType::Integer,
                            Some("boolean") => ParamType::Boolean,
                            _ => ParamType::Other,
                        },
                        required: required(k),
                    }
                })
                .collect()
        });
        Method { params, input: payload("input"), output: payload("output") }
    }

    fn schema(&self, d: &J, ctx: &str) -> Schema {
        let u64_of = |k: &str| d.get(k).and_then(|m| m.as_u64());
        let t = d["type"].as_str().unwrap_or("");
        match t {
            "object" => Schema::Object(Box::new(self.object(d, ctx))),
            "record" => Schema::Object(Box::new(self.object(&d["record"], ctx))),
            "ref" => {
                let (nsid, name) = split_ref(d["ref"].as_str().unwrap_or(""), ctx);
                Schema::Ref(self.target(nsid, name))
            }
            "union" => {
                let raw = d["refs"].as_array();
                let refs = raw
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r.as_str())
                    .map(|r| {
                        let (nsid, name) = split_ref(r, ctx);
                        (nsid.into(), name.into(), self.target(nsid, name))
                    })
                    .collect();
                let closed = (d["closed"].as_bool() == Some(true))
                    .then(|| format!("$type must be one of {}", join(raw.map_or(&[][..], |a| a), ", ")));
                Schema::Union(Box::new(Union { ctx: ctx.into(), refs, closed }))
            }
            "string" => {
                let format = match d.get("format").and_then(|f| f.as_str()) {
                    Some("datetime") => Some(Format::Datetime),
                    Some("uri") => Some(Format::Uri),
                    Some("at-uri") => Some(Format::AtUri),
                    Some("did") => Some(Format::Did),
                    Some("handle") => Some(Format::Handle),
                    Some("at-identifier") => Some(Format::AtIdentifier),
                    Some("nsid") => Some(Format::Nsid),
                    Some("cid") => Some(Format::Cid),
                    Some("language") => Some(Format::Language),
                    Some("tid") => Some(Format::Tid),
                    Some("record-key") => Some(Format::RecordKey),
                    Some("space-ref") => Some(Format::SpaceRef),
                    _ => None,
                };
                Schema::String(Box::new(Str {
                    konst: d.get("const").and_then(|c| c.as_str()).map(Into::into),
                    enumeration: d
                        .get("enum")
                        .and_then(|e| e.as_array())
                        .map(|e| (e.iter().filter_map(|x| x.as_str()).map(Into::into).collect(), join(e, "|"))),
                    max_len: u64_of("maxLength"),
                    min_len: u64_of("minLength"),
                    min_graphemes: u64_of("minGraphemes"),
                    max_graphemes: u64_of("maxGraphemes"),
                    format,
                }))
            }
            "integer" => Schema::Integer(Box::new(Int {
                konst: d.get("const").map(|c| (c.as_i64(), c.to_string())),
                enumeration: d
                    .get("enum")
                    .and_then(|e| e.as_array())
                    .map(|e| (e.iter().filter_map(|x| x.as_i64()).collect(), join(e, "|"))),
                min: d.get("minimum").and_then(|m| m.as_i64()),
                max: d.get("maximum").and_then(|m| m.as_i64()),
            })),
            "boolean" => Schema::Boolean { konst: d.get("const").and_then(|c| c.as_bool()) },
            "bytes" => Schema::Bytes { min: u64_of("minLength"), max: u64_of("maxLength") },
            "cid-link" => Schema::CidLink,
            "blob" => Schema::Blob(Box::new(Blob {
                accept: d
                    .get("accept")
                    .and_then(|a| a.as_array())
                    .map(|a| (a.iter().filter_map(|x| x.as_str()).map(Into::into).collect(), d["accept"].to_string())),
                max_size: d.get("maxSize").and_then(|m| m.as_i64()),
            })),
            "array" => Schema::Array(Box::new(Array {
                min: u64_of("minLength"),
                max: u64_of("maxLength"),
                items: d.get("items").map(|i| self.schema(i, ctx)),
            })),
            "unknown" => Schema::Unknown,
            "null" => Schema::Null,
            _ => Schema::Any,
        }
    }

    fn object(&self, d: &J, ctx: &str) -> Object {
        let nullable = |k: &str| d.get("nullable").and_then(|n| n.as_array()).is_some_and(|n| n.iter().any(|x| x == k));
        let required = d
            .get("required")
            .and_then(|r| r.as_array())
            .into_iter()
            .flatten()
            .filter_map(|k| k.as_str())
            .map(|k| (k.into(), nullable(k)))
            .collect();
        let props = d
            .get("properties")
            .and_then(|p| p.as_object())
            .into_iter()
            .flatten()
            .map(|(k, pd)| (k.as_str().into(), self.schema(pd, ctx), nullable(k)))
            .collect();
        Object { required, props }
    }
}

/// A data-model value the interpreter can check. In JSON, `$link` /
/// `$bytes` objects are CIDs and bytes, as the reference's `jsonToLex`.
pub trait Node: Sized {
    fn kind(&self) -> Kind<'_, Self>;
    fn get(&self, key: &str) -> Option<&Self>;
}

pub enum Kind<'a, N> {
    Null,
    Bool(bool),
    Int(i64),
    Float,
    Text(&'a str),
    /// Length.
    Bytes(usize),
    Link,
    Array(&'a [N]),
    Map,
}

impl Node for Value {
    fn kind(&self) -> Kind<'_, Value> {
        match self {
            Value::Null => Kind::Null,
            Value::Bool(b) => Kind::Bool(*b),
            Value::Int(n) => Kind::Int(*n),
            Value::Bytes(b) => Kind::Bytes(b.len()),
            Value::Text(s) => Kind::Text(s),
            Value::Array(a) => Kind::Array(a),
            Value::Map(_) => Kind::Map,
            Value::Link(_) => Kind::Link,
        }
    }

    fn get(&self, key: &str) -> Option<&Value> {
        Value::get(self, key)
    }
}

impl Node for J {
    fn kind(&self) -> Kind<'_, J> {
        match self {
            J::Null => Kind::Null,
            J::Bool(b) => Kind::Bool(*b),
            J::Number(n) => n.as_i64().map_or(Kind::Float, Kind::Int),
            J::String(s) => Kind::Text(s),
            J::Array(a) => Kind::Array(a),
            J::Object(o) => match (o.len(), o.get("$link"), o.get("$bytes")) {
                (1, Some(J::String(_)), _) => Kind::Link,
                (1, _, Some(J::String(b))) => Kind::Bytes(b.trim_end_matches('=').len() * 3 / 4),
                _ => Kind::Map,
            },
        }
    }

    fn get(&self, key: &str) -> Option<&J> {
        self.as_object()?.get(key)
    }
}

impl Node for JsonValue<'_> {
    fn kind(&self) -> Kind<'_, Self> {
        match self {
            JsonValue::Null => Kind::Null,
            JsonValue::Bool(b) => Kind::Bool(*b),
            JsonValue::Int(n) => Kind::Int(*n),
            JsonValue::Float(_) | JsonValue::BigUint(_) => Kind::Float,
            JsonValue::Str(s) => Kind::Text(s),
            JsonValue::Array(a) => Kind::Array(a),
            JsonValue::Object(o) => match &o[..] {
                [(k, JsonValue::Str(_))] if k == "$link" => Kind::Link,
                [(k, JsonValue::Str(b))] if k == "$bytes" => Kind::Bytes(b.trim_end_matches('=').len() * 3 / 4),
                _ => Kind::Map,
            },
        }
    }

    fn get(&self, key: &str) -> Option<&Self> {
        JsonValue::get(self, key)
    }
}

fn text<N: Node>(v: Option<&N>) -> Option<&str> {
    match v?.kind() {
        Kind::Text(s) => Some(s),
        _ => None,
    }
}

/// Most refs followed at once: an untrusted resolved lexicon may reference
/// itself in a cycle.
const MAX_DEPTH: u32 = 128;

/// Formatted only when there is an error.
enum Seg<'a> {
    Key(&'a str),
    Index(usize),
}

struct Validator<'a> {
    root: &'a str,
    path: Vec<Seg<'a>>,
    /// For bundle refs to defs the bundle lacks.
    doc: Option<&'a Lexicons>,
    depth: u32,
}

impl<'a> Validator<'a> {
    fn new(root: &'a str, doc: Option<&'a Lexicons>) -> Self {
        Validator { root, path: Vec::new(), doc, depth: 0 }
    }

    fn resolve(&self, set: &'a Lexicons, t: &'a Target) -> Option<(&'a Lexicons, &'a Schema)> {
        match t {
            Target::Local(i) => Some((set, &set.defs[*i as usize])),
            Target::Bundle(i) => Some((&*BUNDLE, &BUNDLE.defs[*i as usize])),
            Target::Unbundled(nsid, name) => {
                let d = self.doc.filter(|d| d.id.as_deref() == Some(&**nsid))?;
                let i = d.lookup(nsid, name)?;
                Some((d, &d.defs[i as usize]))
            }
            Target::Missing => None,
        }
    }

    fn err(&self, m: impl std::fmt::Display) -> String {
        let mut p = self.root.to_string();
        for seg in &self.path {
            match seg {
                Seg::Key(k) => {
                    p.push('/');
                    p.push_str(k);
                }
                Seg::Index(i) => p.push_str(&format!("/{i}")),
            }
        }
        format!("{p} {m}")
    }

    fn nested<T>(&mut self, seg: Seg<'a>, f: impl FnOnce(&mut Self) -> T) -> T {
        self.path.push(seg);
        let r = f(self);
        self.path.pop();
        r
    }

    fn follow<N: Node>(&mut self, set: &'a Lexicons, t: &'a Target, v: &N) -> Result<(), String> {
        let Some((set, target)) = self.resolve(set, t) else {
            return Ok(());
        };
        if self.depth >= MAX_DEPTH {
            return Err(self.err("exceeds the maximum schema depth"));
        }
        self.depth += 1;
        let r = self.check(set, target, v);
        self.depth -= 1;
        r
    }

    fn check<N: Node>(&mut self, set: &'a Lexicons, d: &'a Schema, v: &N) -> Result<(), String> {
        match d {
            Schema::Object(o) => self.object(set, o, v),
            Schema::Ref(t) => self.follow(set, t, v),
            Schema::Union(u) => self.union(set, u, v),
            Schema::String(s) => self.string(s, v),
            Schema::Integer(d) => {
                let Kind::Int(n) = v.kind() else {
                    return Err(self.err("must be an integer"));
                };
                if let Some((c, shown)) = &d.konst {
                    if *c != Some(n) {
                        return Err(self.err(format!("must be {shown}")));
                    }
                }
                if let Some((e, shown)) = &d.enumeration {
                    if !e.contains(&n) {
                        return Err(self.err(format!("must be one of ({shown})")));
                    }
                }
                if let Some(m) = d.min.filter(|&m| n < m) {
                    return Err(self.err(format!("can not be less than {m}")));
                }
                if let Some(m) = d.max.filter(|&m| n > m) {
                    return Err(self.err(format!("can not be greater than {m}")));
                }
                Ok(())
            }
            Schema::Boolean { konst } => match v.kind() {
                Kind::Bool(b) => match konst {
                    Some(c) if *c != b => Err(self.err(format!("must be {c}"))),
                    _ => Ok(()),
                },
                _ => Err(self.err("must be a boolean")),
            },
            Schema::Bytes { min, max } => {
                let Kind::Bytes(n) = v.kind() else {
                    return Err(self.err("must be a byte array"));
                };
                if let Some(m) = max.filter(|&m| n as u64 > m) {
                    return Err(self.err(format!("must not be larger than {m} bytes")));
                }
                if let Some(m) = min.filter(|&m| (n as u64) < m) {
                    return Err(self.err(format!("must not be smaller than {m} bytes")));
                }
                Ok(())
            }
            Schema::CidLink => match v.kind() {
                Kind::Link => Ok(()),
                _ => Err(self.err("must be a CID")),
            },
            Schema::Blob(b) => self.blob(b, v),
            Schema::Array(a) => {
                let Kind::Array(items) = v.kind() else {
                    return Err(self.err("must be an array"));
                };
                let n = items.len() as u64;
                if let Some(m) = a.max.filter(|&m| n > m) {
                    return Err(self.err(format!("must not have more than {m} elements")));
                }
                if let Some(m) = a.min.filter(|&m| n < m) {
                    return Err(self.err(format!("must not have fewer than {m} elements")));
                }
                if let Some(item) = &a.items {
                    for (i, x) in items.iter().enumerate() {
                        self.nested(Seg::Index(i), |s| s.check(set, item, x))?;
                    }
                }
                Ok(())
            }
            Schema::Unknown => match v.kind() {
                Kind::Map => Ok(()),
                _ => Err(self.err("must be an object")),
            },
            Schema::Null => match v.kind() {
                Kind::Null => Ok(()),
                _ => Err(self.err("must be null")),
            },
            Schema::Any => Ok(()),
        }
    }

    fn object<N: Node>(&mut self, set: &'a Lexicons, d: &'a Object, v: &N) -> Result<(), String> {
        if !matches!(v.kind(), Kind::Map) {
            return Err(self.err("must be an object"));
        }
        for (k, nullable) in &d.required {
            let missing = match v.get(k) {
                None => true,
                Some(x) => matches!(x.kind(), Kind::Null) && !nullable,
            };
            if missing {
                return Err(self.err(format!("must have the property \"{k}\"")));
            }
        }
        for (k, pd, nullable) in &d.props {
            let Some(x) = v.get(k) else { continue };
            if *nullable && matches!(x.kind(), Kind::Null) {
                continue;
            }
            self.nested(Seg::Key(k), |s| s.check(set, pd, x))?;
        }
        Ok(())
    }

    fn union<N: Node>(&mut self, set: &'a Lexicons, d: &'a Union, v: &N) -> Result<(), String> {
        let t = match v.kind() {
            Kind::Map => text(v.get("$type")),
            _ => None,
        };
        let Some(t) = t else {
            return Err(self.err("must be an object which includes the \"$type\" property"));
        };
        let (tn, tname) = split_ref(t, &d.ctx);
        match d.refs.iter().find(|(n, name, _)| **n == *tn && **name == *tname) {
            Some((_, _, target)) => self.follow(set, target, v),
            None => match &d.closed {
                Some(msg) => Err(self.err(msg)),
                None => Ok(()),
            },
        }
    }

    fn string<N: Node>(&mut self, d: &Str, v: &N) -> Result<(), String> {
        let Kind::Text(s) = v.kind() else {
            return Err(self.err("must be a string"));
        };
        if let Some(c) = &d.konst {
            if **c != *s {
                return Err(self.err(format!("must be {c}")));
            }
        }
        if let Some((e, shown)) = &d.enumeration {
            if !e.iter().any(|x| **x == *s) {
                return Err(self.err(format!("must be one of ({shown})")));
            }
        }
        // lengths are UTF-8 bytes, worded as characters like the reference
        let n = s.len() as u64;
        if let Some(m) = d.max_len.filter(|&m| n > m) {
            return Err(self.err(format!("must not be longer than {m} characters")));
        }
        if let Some(m) = d.min_len.filter(|&m| n < m) {
            return Err(self.err(format!("must not be shorter than {m} characters")));
        }
        let (min_g, max_g) = (d.min_graphemes, d.max_graphemes);
        if min_g.is_some() || max_g.is_some() {
            // cheap bounds first: graphemes <= chars <= bytes
            let n = if max_g.is_some_and(|m| s.len() as u64 <= m) && min_g.is_none() {
                0
            } else {
                s.graphemes(true).count() as u64
            };
            if let Some(m) = min_g.filter(|&m| n < m) {
                return Err(self.err(format!("must not be shorter than {m} graphemes")));
            }
            if let Some(m) = max_g.filter(|&m| n > m) {
                return Err(self.err(format!("must not be longer than {m} graphemes")));
            }
        }
        if let Some(f) = d.format {
            let (ok, msg) = match f {
                Format::Datetime => {
                    (valid_datetime(s), "must be an valid atproto datetime (both RFC-3339 and ISO-8601)")
                }
                Format::Uri => (valid_uri(s), "must be a uri"),
                Format::AtUri => (valid_at_uri(s) || space_at_uri(s).is_some(), "must be a valid at-uri"),
                Format::Did => (syntax::valid_did(s), "must be a valid did"),
                Format::Handle => (syntax::valid_handle(s), "must be a valid handle"),
                Format::AtIdentifier => {
                    (crate::xrpc::extract::valid_at_identifier(s), "must be a valid did or a handle")
                }
                Format::Nsid => (syntax::valid_nsid(s), "must be a valid nsid"),
                // the syntax check first: it accepts nearly every parseable CID
                Format::Cid => (
                    crate::xrpc::extract::valid_cid_syntax(s) || vlsync_atproto::cid::Cid::parse(s).is_ok(),
                    "must be a cid string",
                ),
                Format::Language => (valid_language(s), "must be a well-formed BCP 47 language tag"),
                Format::Tid => (valid_tid(s), "must be a valid TID"),
                Format::RecordKey => (syntax::valid_rkey(s), "must be a valid Record Key"),
                Format::SpaceRef => (space_at_uri(s).is_some_and(|u| u.record.is_none()), "must be a valid space ref"),
            };
            if !ok {
                return Err(self.err(msg));
            }
        }
        Ok(())
    }

    fn blob<N: Node>(&mut self, d: &Blob, v: &N) -> Result<(), String> {
        if !matches!(v.kind(), Kind::Map) || text(v.get("$type")) != Some("blob") {
            return Err(self.err("should be a blob ref"));
        }
        let Some(mime) = text(v.get("mimeType")) else {
            return Err(self.err("should be a blob ref"));
        };
        let size = match v.get("size").map(|s| s.kind()) {
            Some(Kind::Int(n)) => Some(n),
            _ => None,
        };
        if let Some((accept, shown)) = &d.accept {
            let ok = accept.iter().any(|a| {
                &**a == "*/*" || **a == *mime || a.strip_suffix("/*").is_some_and(|p| mime.split('/').next() == Some(p))
            });
            if !ok {
                return Err(self.err(format!("mime type {mime:?} is not accepted (accepted: {shown})")));
            }
        }
        if let (Some(max), Some(size)) = (d.max_size, size) {
            if size > max {
                return Err(self.err(format!("file is too large: {size} bytes (max {max})")));
            }
        }
        Ok(())
    }
}

/// Like JS `Array.join` (strings unquoted).
fn join(items: &[J], sep: &str) -> String {
    items.iter().map(|x| x.as_str().map_or_else(|| x.to_string(), String::from)).collect::<Vec<_>>().join(sep)
}

fn digits(s: &str) -> Option<u32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok())?
}

/// RFC 3339 / ISO 8601 intersection with `Z` or `±hh:mm`, not `-00:00`,
/// a real calendar date, and within years 0000-9999 once normalized to UTC.
pub fn valid_datetime(s: &str) -> bool {
    if s.len() > 64 || s.ends_with("-00:00") || !s.is_ascii() {
        return false;
    }
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return false;
    }
    let (Some(year), Some(month), Some(day), Some(hour), Some(min), Some(sec)) = (
        digits(&s[0..4]),
        digits(&s[5..7]),
        digits(&s[8..10]),
        digits(&s[11..13]),
        digits(&s[14..16]),
        digits(&s[17..19]),
    ) else {
        return false;
    };
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        let n = r.bytes().take_while(|b| b.is_ascii_digit()).count();
        if n == 0 {
            return false;
        }
        rest = &r[n..];
    }
    let offset_min: i64 = match rest {
        "Z" => 0,
        _ => {
            let ob = rest.as_bytes();
            if ob.len() != 6 || !matches!(ob[0], b'+' | b'-') || ob[3] != b':' {
                return false;
            }
            let (Some(oh), Some(om)) = (digits(&rest[1..3]), digits(&rest[4..6])) else {
                return false;
            };
            if oh > 23 || om > 59 {
                return false;
            }
            let m = (oh * 60 + om) as i64;
            if ob[0] == b'-' {
                -m
            } else {
                m
            }
        }
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&month) || day < 1 || day > mdays[month as usize - 1] {
        return false;
    }
    if hour > 23 || min > 59 || sec > 59 {
        return false;
    }
    // normalized to UTC it must stay within 0000-01-01 .. 9999-12-31
    let minutes = (hour * 60 + min) as i64 - offset_min;
    if year == 0 && month == 1 && day == 1 && minutes < 0 {
        return false;
    }
    if year == 9999 && month == 12 && day == 31 && minutes >= 24 * 60 {
        return false;
    }
    true
}

/// `scheme:[//]rest` with no whitespace (@atproto/syntax isUriString).
pub fn valid_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    s.len() <= 8192
        && !scheme.is_empty()
        && scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && rest.chars().next().is_some_and(|c| c != '/' && !c.is_whitespace())
        && !rest.chars().any(char::is_whitespace)
}

/// Strict AT URI: `at://AUTHORITY[/NSID[/RKEY]][#/JSON-POINTER]`, as
/// @atproto/syntax `isAtUriString` checks it (the fragment is a `/`-rooted
/// JSON pointer in its URI charset, with valid percent-encoding). Public
/// URIs only: backlink derivation's verdicts are frozen (segment.rs), so
/// the lexicon `at-uri` format adds [`space_at_uri`] next to it.
pub fn valid_at_uri(s: &str) -> bool {
    if s.len() > 8192 || !s.is_ascii() {
        return false;
    }
    let s = match s.split_once('#') {
        Some((uri, frag)) if valid_at_uri_fragment(frag) => uri,
        Some(_) => return false,
        None => s,
    };
    let Some(rest) = s.strip_prefix("at://") else {
        return false;
    };
    let mut parts = rest.split('/');
    let authority = parts.next().unwrap_or("");
    if !crate::xrpc::extract::valid_at_identifier(authority) {
        return false;
    }
    match (parts.next(), parts.next(), parts.next()) {
        (None, ..) => true,
        (Some(c), None, _) => syntax::valid_nsid(c),
        (Some(c), Some(r), None) => syntax::valid_nsid(c) && syntax::valid_rkey(r),
        _ => false,
    }
}

/// A strict space AT URI, fragment allowed (@atproto/syntax
/// `isSpaceAtUriString`). No string is both this and a [`valid_at_uri`]:
/// `space` isn't an NSID.
pub fn space_at_uri(s: &str) -> Option<syntax::SpaceUri<'_>> {
    if s.len() > 8192 || !s.is_ascii() {
        return None;
    }
    let uri = match s.split_once('#') {
        Some((uri, frag)) => valid_at_uri_fragment(frag).then_some(uri)?,
        None => s,
    };
    syntax::parse_space_uri(uri)
}

fn valid_at_uri_fragment(f: &str) -> bool {
    if !f.starts_with('/') || !f.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~:@!$&'()*+,;=%[]/-".contains(&b)) {
        return false;
    }
    // percent-escapes must decode to UTF-8 (decodeURIComponent)
    let mut out = Vec::with_capacity(f.len());
    let mut b = f.bytes();
    while let Some(c) = b.next() {
        if c != b'%' {
            out.push(c);
            continue;
        }
        let hex = |c: Option<u8>| c.and_then(|c| (c as char).to_digit(16));
        match (hex(b.next()), hex(b.next())) {
            (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
            _ => return false,
        }
    }
    std::str::from_utf8(&out).is_ok()
}

/// A well-formed BCP 47 language tag, as @atproto/syntax `parseLanguageString`
/// (lex-schema's `isLanguageString`) checks it: the RFC 5646 grammar
/// (langtag, private use, the grandfathered tags), a lowercase 2-3 letter
/// primary subtag, and no repeated variant or extension singleton.
pub fn valid_language(s: &str) -> bool {
    const GRANDFATHERED: &[&str] = &[
        "en-GB-oed",
        "i-ami",
        "i-bnn",
        "i-default",
        "i-enochian",
        "i-hak",
        "i-klingon",
        "i-lux",
        "i-mingo",
        "i-navajo",
        "i-pwn",
        "i-tao",
        "i-tay",
        "i-tsu",
        "sgn-BE-FR",
        "sgn-BE-NL",
        "sgn-CH-DE",
        "art-lojban",
        "cel-gaulish",
        "no-bok",
        "no-nyn",
        "zh-guoyu",
        "zh-hakka",
        "zh-min",
        "zh-min-nan",
        "zh-xiang",
    ];
    if GRANDFATHERED.contains(&s) {
        return true;
    }
    let tags: Vec<&str> = s.split('-').collect();
    let alnum =
        |t: &str, lo: usize, hi: usize| (lo..=hi).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric());
    let alpha = |t: &str, n: usize| t.len() == n && t.bytes().all(|b| b.is_ascii_alphabetic());
    // privateuse: x-1*8alphanum ...
    let private_use = |rest: &[&str]| !rest.is_empty() && rest.iter().all(|t| alnum(t, 1, 8));
    if tags[0].eq_ignore_ascii_case("x") {
        return private_use(&tags[1..]);
    }
    let primary = tags[0];
    if !(2..=3).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    let mut i = 1;
    // extlang: up to three 3-letter subtags
    while i < tags.len() && i <= 3 && alpha(tags[i], 3) {
        i += 1;
    }
    if i < tags.len() && alpha(tags[i], 4) {
        i += 1; // script
    }
    if i < tags.len() && (alpha(tags[i], 2) || (tags[i].len() == 3 && tags[i].bytes().all(|b| b.is_ascii_digit()))) {
        i += 1; // region
    }
    let mut variants: Vec<String> = Vec::new();
    while i < tags.len()
        && (alnum(tags[i], 5, 8)
            || (tags[i].len() == 4 && tags[i].as_bytes()[0].is_ascii_digit() && alnum(tags[i], 4, 4)))
    {
        let v = tags[i].to_ascii_lowercase();
        if variants.contains(&v) {
            return false;
        }
        variants.push(v);
        i += 1;
    }
    let mut singletons: Vec<u8> = Vec::new();
    while i < tags.len() && tags[i].len() == 1 && alnum(tags[i], 1, 1) && !tags[i].eq_ignore_ascii_case("x") {
        let c = tags[i].as_bytes()[0].to_ascii_lowercase();
        if singletons.contains(&c) {
            return false;
        }
        singletons.push(c);
        i += 1;
        let start = i;
        while i < tags.len() && alnum(tags[i], 2, 8) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    if i < tags.len() && tags[i].eq_ignore_ascii_case("x") {
        return private_use(&tags[i + 1..]);
    }
    i == tags.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_like_the_reference() {
        // @atproto/syntax parseLanguageString (and the interop fixtures)
        for ok in [
            "ja",
            "ban",
            "pt-BR",
            "hy-Latn-IT-arevela",
            "zh-Hant",
            "sgn-BE-NL",
            "es-419",
            "en-GB-boont-r-extended-sequence-x-private",
            "zh-hakka",
            "i-default",
            "de-CH-1901",
            "qaa-Qaaa-QM-x-southern",
            "X-fr-CH",
            "x-foo",
            "de-X-foo",
            "sl-rozaj-biske",
            "en-u-co-phonebk-t-en-US",
            "zh-yue-HK",
        ] {
            assert!(valid_language(ok), "{ok}");
        }
        for bad in [
            "",
            "jaja",
            ".",
            "123",
            "JA",
            "j",
            "ja-",
            "a-DE",
            "x",
            "i",
            "i-foo",
            "enU-9",
            "en--US",
            "en-a",
            "en-a-bb-a-cc",
            "sl-rozaj-rozaj",
            "en-US-abc",
            "en-x",
            "de-419-DE",
        ] {
            assert!(!valid_language(bad), "{bad}");
        }
    }

    #[test]
    fn at_uri_fragments() {
        for ok in [
            "at://did:plc:abc/app.bsky.feed.post/3jzfcijpj2z2a#/text",
            "at://did:plc:abc#/a/b~0c",
            "at://alice.test/app.bsky.feed.post#/%C3%A9",
        ] {
            assert!(valid_at_uri(ok), "{ok}");
        }
        for bad in [
            "at://did:plc:abc#",
            "at://did:plc:abc#frag",
            "at://did:plc:abc#/a#/b",
            "at://did:plc:abc#/a b",
            "at://did:plc:abc#/%FF",
            "at://did:plc:abc#/%G0",
            "at://did:plc:abc/app.bsky.feed.post/rkey/#/frag",
            "at://did:plc:abc?q#/frag",
        ] {
            assert!(!valid_at_uri(bad), "{bad}");
        }
    }

    #[test]
    fn datetimes() {
        for ok in [
            "1985-04-12T23:20:50.123Z",
            "1985-04-12T23:20:50Z",
            "1985-04-12T23:20:50.123-07:00",
            "0000-01-01T00:00:00.000Z",
            "2024-02-29T00:00:00Z",
        ] {
            assert!(valid_datetime(ok), "{ok}");
        }
        for bad in [
            "1985-04-12T23:20:50.123z",
            "1985-04-12T23:20:50.Z",
            "1985-04-12T23:20:50.123-00:00",
            "1985-04-12T23:20:50.123+0000",
            "1985-00-12T23:20:50.123Z",
            "2023-02-29T00:00:00Z",
            "0000-01-01T00:00:00+01:00",
            "1985-04-12",
        ] {
            assert!(!valid_datetime(bad), "{bad}");
        }
    }

    #[test]
    fn bundled_lexicons_parse() {
        assert!(BUNDLE.records.contains_key("app.bsky.feed.post"));
        let rec = Value::from_json(&serde_json::json!({
            "$type": "app.bsky.feed.post", "text": "hi", "createdAt": "2024-01-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(validate_record("app.bsky.feed.post", "3jui7kd54zh2y", &rec, None, None), Ok(Some("valid")));
        let bad = Value::from_json(&serde_json::json!({"$type": "app.bsky.feed.post", "createdAt": "x"})).unwrap();
        assert!(validate_record("app.bsky.feed.post", "3jui7kd54zh2y", &bad, None, None).is_err());
        assert!(validate_record("app.bsky.actor.profile", "3jui7kd54zh2y", &rec, None, None).is_err());
    }

    #[test]
    fn resolved_record_lexicon() {
        let doc = serde_json::json!({
            "lexicon": 1, "id": "com.example.thing",
            "defs": {
                "main": {"type": "record", "key": "tid", "record": {"type": "object",
                    "required": ["n"],
                    "properties": {"n": {"type": "integer", "maximum": 5}, "loop": {"type": "ref", "ref": "#loop"}}}},
                "loop": {"type": "ref", "ref": "#loop"}
            }
        });
        let doc = Lexicons::resolved(&doc);
        let rec = |j| Value::from_json(&j).unwrap();
        let ok = rec(serde_json::json!({"$type": "com.example.thing", "n": 3}));
        assert_eq!(validate_record("com.example.thing", "3jui7kd54zh2y", &ok, None, Some(&doc)), Ok(Some("valid")));
        assert_eq!(validate_record("com.example.thing", "3jui7kd54zh2y", &ok, None, None), Ok(Some("unknown")));
        let big = rec(serde_json::json!({"$type": "com.example.thing", "n": 9}));
        assert_eq!(
            validate_record("com.example.thing", "3jui7kd54zh2y", &big, None, Some(&doc)),
            Err("Invalid com.example.thing record: record/n can not be greater than 5".into())
        );
        // a self-referencing def is cut off instead of overflowing the stack
        let cyc = rec(serde_json::json!({"$type": "com.example.thing", "n": 1, "loop": {}}));
        assert!(validate_record("com.example.thing", "3jui7kd54zh2y", &cyc, None, Some(&doc))
            .unwrap_err()
            .contains("maximum schema depth"));
        // a document for another NSID is ignored
        assert_eq!(validate_record("com.example.other", "x", &ok, None, Some(&doc)), Ok(Some("unknown")));
    }

    #[test]
    fn xrpc_input_and_params() {
        let n = "com.atproto.repo.createRecord";
        assert!(has_input_schema(n) && !has_input_schema("com.atproto.repo.getRecord"));
        let body = serde_json::json!({"repo": "did:plc:abc", "collection": "app.bsky.feed.post", "record": {}});
        assert_eq!(validate_input(n, &body), Ok(()));
        assert_eq!(
            validate_input(n, &serde_json::json!({"repo": "did:plc:abc", "record": {}})),
            Err("Input must have the property \"collection\"".into())
        );
        assert_eq!(
            validate_input(n, &serde_json::json!({"repo": 1, "collection": "a.b.c", "record": {}})),
            Err("Input/repo must be a string".into())
        );
        assert_eq!(validate_input(n, &serde_json::json!([])), Err("Input must be an object".into()));
        let aw = serde_json::json!({"repo": "did:plc:abc", "writes": [{"$type": "com.atproto.repo.applyWrites#nope"}]});
        assert!(validate_input("com.atproto.repo.applyWrites", &aw)
            .unwrap_err()
            .starts_with("Input/writes/0 $type must be one of #create, #update, #delete"));
        let p = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let q = "com.atproto.repo.listRecords";
        assert_eq!(validate_params(q, &p(&[("repo", "did:plc:abc"), ("collection", "a.b.c")])), Ok(()));
        assert_eq!(
            validate_params(q, &p(&[("repo", "did:plc:abc")])),
            Err("Params must have the property \"collection\"".into())
        );
        assert_eq!(
            validate_params(q, &p(&[("repo", "did:plc:abc"), ("collection", "a.b.c"), ("limit", "500")])),
            Err("limit can not be greater than 100".into())
        );
        assert_eq!(
            validate_params(q, &p(&[("repo", "did:plc:abc"), ("collection", "a.b.c"), ("reverse", "maybe")])),
            Err("reverse must be a boolean".into())
        );
        // $link / $bytes objects are CIDs and bytes in JSON
        let out = serde_json::json!({"uri": "at://did:plc:abc/a.b.c/x", "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm", "value": {}});
        assert_eq!(validate_output("com.atproto.repo.getRecord", &out), Ok(()));
        assert_eq!(
            validate_output("com.atproto.repo.getRecord", &serde_json::json!({"value": {}})),
            Err("Output must have the property \"uri\"".into())
        );
    }

    /// The "space URIs" cases of @atproto/syntax tests/aturi-string.test.ts
    /// (atproto 5b95b2f2). Its lenient-only cases (`testLoose`) are invalid
    /// here: lexicon formats are strict.
    #[test]
    fn space_at_uris() {
        let long_skey = format!("at://did:plc:asdf123/space/com.example.group/{}", "x".repeat(513));
        for ok in [
            "at://did:plc:asdf123/space/com.example.group/default",
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/com.atproto.feed.post/abc123",
            "at://did:plc:asdf123/space/com.example.group/self",
            "at://did:plc:asdf123/space/com.example.group/3jui7kd54zh2y",
            "at://did:plc:asdf123/space/com.example.group/a.b-c_d~e:f",
            "at://did:plc:asdf123/space/com.example.group/default#/frag",
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/com.atproto.feed.post/abc#/frag",
            "at://did:web:example.com/space/com.example.group/default",
        ] {
            assert!(space_at_uri(ok).is_some(), "{ok}");
            assert!(!valid_at_uri(ok), "{ok}");
        }
        for bad in [
            "at://did:plc:asdf123/space/short/default",
            "at://not a did/space/com.example.group/default",
            "at://user.bsky.social/space/com.example.group/default",
            "at://did:plc:asdf123/space/com.example.group/default/user.bsky.social/com.atproto.feed.post/abc123",
            "at://did:plc:asdf123/space/com.example.group/.",
            "at://did:plc:asdf123/space/com.example.group/..",
            &long_skey,
            "at://did:plc:asdf123/space/com.example.group",
            "at://did:plc:asdf123/space",
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1",
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/short/abc123",
            "at://did:plc:asdf123/space/com.example.group/default#",
            "at://did:plc:asdf123/space/com.example.group/default#/a#/b",
            // testLoose: strict rejects these
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/com.atproto.feed.post/%%%",
            "at://did:plc:asdf123/space/com.example.group/default?foo=bar",
            "at://did:plc:asdf123/space/com.example.group/default/",
            // the marker is case-sensitive, and the tail is all or nothing
            "at://did:plc:asdf123/SPACE/com.example.group/default",
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/com.atproto.feed.post",
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/com.atproto.feed.post/abc/x",
            "at://did:plc:asdf123/spacey/com.example.group/default",
            "at://did:plc:asdf123/space//default",
            "AT://did:plc:asdf123/space/com.example.group/default",
            "at://did:plc:asdf123/space/com.example.group/défault",
        ] {
            assert!(space_at_uri(bad).is_none(), "{bad}");
            assert!(!valid_at_uri(bad), "{bad}");
        }
        let u = space_at_uri(
            "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/com.atproto.feed.post/abc123#/x",
        )
        .unwrap();
        assert_eq!(
            u,
            syntax::SpaceUri {
                authority: "did:plc:asdf123",
                space_type: "com.example.group",
                skey: "default",
                record: Some(("did:plc:user1", "com.atproto.feed.post", "abc123")),
            }
        );
        // public URIs are unchanged
        assert!(space_at_uri("at://did:plc:asdf123/com.atproto.feed.post/abc").is_none());
        assert!(valid_at_uri("at://did:plc:asdf123/com.atproto.feed.post/abc"));
    }

    /// @atproto/lexicon tests/general.test.ts "Applies space-ref formatting
    /// constraint", plus the `at-uri` format taking both kinds of URI.
    #[test]
    fn space_formats() {
        let doc = Lexicons::resolved(&serde_json::json!({
            "lexicon": 1, "id": "com.example.spaceRef",
            "defs": {"main": {"type": "record", "key": "any", "record": {"type": "object", "properties": {
                "space": {"type": "string", "format": "space-ref"},
                "uri": {"type": "string", "format": "at-uri"}
            }}}}
        }));
        let check = |field: &str, v: &str| {
            let rec = Value::from_json(&serde_json::json!({"$type": "com.example.spaceRef", field: v})).unwrap();
            validate_record("com.example.spaceRef", "self", &rec, None, Some(&doc))
        };
        let space = "at://did:plc:12345678abcdefghijklmnop/space/com.example.group/default";
        let in_space = "at://did:plc:12345678abcdefghijklmnop/space/com.example.group/default/did:plc:12345678abcdefghijklmnoq/com.example.test/self";
        assert_eq!(check("space", space), Ok(Some("valid")));
        assert_eq!(check("space", &format!("{space}#/frag")), Ok(Some("valid")));
        for bad in [
            in_space,
            "at://did:plc:12345678abcdefghijklmnop/com.example.test/self",
            "at://test.bsky.social/space/com.example.group/default",
            "not a space ref",
        ] {
            assert_eq!(
                check("space", bad),
                Err("Invalid com.example.spaceRef record: record/space must be a valid space ref".into()),
                "{bad}"
            );
        }
        for ok in [space, in_space, "at://did:plc:12345678abcdefghijklmnop/com.example.test/self"] {
            assert_eq!(check("uri", ok), Ok(Some("valid")), "{ok}");
        }
        assert!(check("uri", "at://did:plc:x/space/com.example.group").is_err());
    }

    /// A public record pointing into a space validates (a like's strongRef
    /// is an `at-uri`), while backlink derivation still ignores it: its
    /// verdicts are frozen (segment.rs).
    #[test]
    fn public_record_referencing_a_space() {
        let uri = "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/app.bsky.feed.post/3jui7kd54zh2y";
        let like = serde_json::json!({
            "$type": "app.bsky.feed.like", "createdAt": "2026-10-01T00:00:00Z",
            "subject": {"uri": uri, "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"}
        });
        let rec = Value::from_json(&like).unwrap();
        assert_eq!(validate_record("app.bsky.feed.like", "3jui7kd54zh2y", &rec, None, None), Ok(Some("valid")));
        assert_eq!(crate::backlinks::link("app.bsky.feed.like", &rec.to_cbor()), None);
    }

    #[test]
    fn space_declarations() {
        let decl = serde_json::json!({
            "lexicon": 1, "id": "com.example.group",
            "defs": {"main": {"type": "space", "name": "Group", "name:lang": {"pt-BR": "Grupo"},
                "key": "any", "description": "a group", "collections": ["com.example.post", "com.example.like"]}}
        });
        assert_eq!(
            space_declaration("com.example.group", &decl),
            Ok(SpaceDecl {
                name: "Group".into(),
                name_lang: vec![("pt-BR".into(), "Grupo".into())],
                description: Some("a group".into()),
                key: Some("any".into()),
                collections: vec!["com.example.post".into(), "com.example.like".into()],
            })
        );
        let with = |f: &dyn Fn(&mut J)| {
            let mut d = decl.clone();
            f(&mut d);
            space_declaration("com.example.group", &d)
        };
        assert!(with(&|_| {}).is_ok());
        assert!(with(&|d| d["defs"]["main"]["name"] = "".into()).is_err());
        assert!(with(&|d| d["defs"]["main"]["name"] = "x".repeat(65).into()).is_err());
        assert!(with(&|d| d["defs"]["main"]["name"] = "\u{1F600}".repeat(32).into()).is_ok());
        assert!(with(&|d| d["defs"]["main"]["name"] = "\u{1F600}".repeat(33).into()).is_err());
        assert!(with(&|d| d["defs"]["main"]["collections"] = serde_json::json!([1])).is_err());
        assert!(with(&|d| d["defs"]["main"].as_object_mut().unwrap().remove("collections").map(drop).unwrap()).is_err());
        assert!(with(&|d| d["defs"]["main"]["name:lang"] = serde_json::json!({"not a tag": "x"})).is_err());
        assert!(with(&|d| d["defs"]["main"]["key"] = 1.into()).is_err());
        for bad in ["*", "com.example.*", "not an nsid", "", "com.example"] {
            assert!(
                with(&|d| d["defs"]["main"]["collections"] = serde_json::json!(["com.example.post", bad])).is_err(),
                "{bad}"
            );
        }
        for key in ["tid", "nsid", "any", "record-key", "literal:self"] {
            assert!(with(&|d| d["defs"]["main"]["key"] = key.into()).is_ok(), "{key}");
        }
        for key in ["*", "uuid", "literal:", "literal:a b"] {
            assert!(with(&|d| d["defs"]["main"]["key"] = key.into()).is_err(), "{key}");
        }
        assert!(with(&|d| d["defs"]["main"]["type"] = "record".into()).is_err());
        let titled = with(&|d| {
            let m = d["defs"]["main"].as_object_mut().unwrap();
            let name = m.remove("name").unwrap();
            m.remove("name:lang");
            m.insert("title".into(), name);
            m.insert("title:lang".into(), serde_json::json!({"pt-BR": "Grupo"}));
        });
        assert_eq!(titled.as_ref().map(|d| (d.name.as_str(), d.name_lang.len())), Ok(("Group", 1)));
        assert!(with(&|d| d["defs"]["main"].as_object_mut().unwrap().remove("name").map(drop).unwrap()).is_err());
        assert!(with(&|d| d["id"] = "com.example.other".into()).is_err());
        assert_eq!(
            with(&|d| d["defs"]["other"] = serde_json::json!({"type": "space", "name": "x", "collections": []})),
            Err(
                "Records, permission sets, spaces, procedures, queries, and subscriptions must be the main definition."
                    .into()
            )
        );
        // a declaration is no data schema
        let doc = Lexicons::resolved(&decl);
        assert!(doc.records.is_empty() && doc.methods.is_empty());
    }
}
