//! atproto OAuth permission grammar, ported from `@atproto/oauth-scopes`.
//! The schema engine mirrors the reference `Parser` exactly, normalization
//! included, so scope strings round-trip identically to TypeScript.

use super::util::{encode_uri_component, form_encode, parse_form, percent_decode_strict};
use serde_json::Value as J;

const STATIC_SCOPES: [&str; 4] = ["atproto", "transition:email", "transition:generic", "transition:chat.bsky"];

/// `isScopeStringFor`.
fn is_scope_string_for(value: &str, prefix: &str) -> bool {
    if value.len() > prefix.len() {
        let next = value.as_bytes()[prefix.len()];
        (next == b':' || next == b'?') && value.starts_with(prefix)
    } else {
        value == prefix
    }
}

enum Params {
    None,
    Query(Vec<(String, String)>),
    Lex(serde_json::Map<String, J>),
}

/// A scope string or a lexicon permission object.
pub struct Syntax {
    pub prefix: String,
    pub positional: Option<String>,
    params: Params,
}

enum Param {
    Absent,
    /// Wrong arity.
    Invalid,
    Values(Vec<J>),
}

impl Syntax {
    /// `ScopeStringSyntax.fromString`. None when a percent escape is malformed.
    pub fn from_string(scope: &str) -> Option<Syntax> {
        let param_idx = scope.find('?');
        let colon_idx = scope.find(':');
        let prefix_end = match (param_idx, colon_idx) {
            (None, None) => return Some(Syntax { prefix: scope.into(), positional: None, params: Params::None }),
            (Some(a), None) | (None, Some(a)) => a,
            (Some(a), Some(b)) => a.min(b),
        };
        let prefix = scope[..prefix_end].to_string();
        let positional = match (colon_idx, param_idx) {
            (Some(c), None) => Some(percent_decode_strict(&scope[c + 1..])?),
            (Some(c), Some(p)) if c < p => Some(percent_decode_strict(&scope[c + 1..p])?),
            _ => None,
        };
        let params = match param_idx {
            Some(p) if p < scope.len() - 1 => Params::Query(parse_form(&scope[p + 1..])),
            _ => Params::None,
        };
        Some(Syntax { prefix, positional, params })
    }

    /// `LexPermissionSyntax`: a permission object from a permission-set lexicon.
    pub fn from_lex(perm: &serde_json::Map<String, J>) -> Option<Syntax> {
        let prefix = perm.get("resource")?.as_str()?.to_string();
        Some(Syntax { prefix, positional: None, params: Params::Lex(perm.clone()) })
    }

    /// A space type is `spaceType` in a lexicon permission (whose `type` is
    /// "permission"), and indigo's scope strings take that name too.
    fn canonical<'a>(&self, key: &'a str) -> &'a str {
        match (self.prefix.as_str(), key) {
            ("space", "spaceType") => "type",
            _ => key,
        }
    }

    fn keys(&self) -> Vec<String> {
        match &self.params {
            Params::None => vec![],
            Params::Query(q) => {
                let mut out: Vec<String> = Vec::new();
                for (k, _) in q {
                    let k = self.canonical(k);
                    if !out.iter().any(|o| o == k) {
                        out.push(k.to_string());
                    }
                }
                out
            }
            Params::Lex(m) => {
                m.keys().filter(|k| *k != "type" && *k != "resource").map(|k| self.canonical(k).to_string()).collect()
            }
        }
    }

    fn get(&self, key: &str, multiple: bool) -> Param {
        match &self.params {
            Params::None => Param::Absent,
            Params::Query(q) => {
                let vals: Vec<J> =
                    q.iter().filter(|(k, _)| self.canonical(k) == key).map(|(_, v)| J::String(v.clone())).collect();
                if vals.is_empty() {
                    Param::Absent
                } else if !multiple && vals.len() > 1 {
                    Param::Invalid
                } else {
                    Param::Values(vals)
                }
            }
            Params::Lex(m) => {
                let key = match (self.prefix.as_str(), key) {
                    ("space", "type") => "spaceType",
                    (_, "type" | "resource") => return Param::Absent,
                    _ => key,
                };
                match m.get(key) {
                    None => Param::Absent,
                    Some(J::Null) => Param::Invalid,
                    Some(J::Array(a)) => {
                        if multiple {
                            Param::Values(a.clone())
                        } else {
                            Param::Invalid
                        }
                    }
                    Some(v) => {
                        if multiple {
                            Param::Invalid
                        } else {
                            Param::Values(vec![v.clone()])
                        }
                    }
                }
            }
        }
    }
}

/// The reference leaves these unescaped.
fn normalize_uri_component(v: &str) -> String {
    v.replace("%3A", ":")
        .replace("%2F", "/")
        .replace("%2B", "+")
        .replace("%2C", ",")
        .replace("%40", "@")
        .replace("%25", "%")
}

fn syntax_to_string(prefix: &str, positional: Option<&str>, params: &[(String, String)]) -> String {
    let mut s = prefix.to_string();
    if let Some(p) = positional {
        s.push(':');
        s.push_str(&normalize_uri_component(&encode_uri_component(p)));
    }
    if !params.is_empty() {
        s.push('?');
        s.push_str(&normalize_uri_component(&form_encode(params)));
    }
    s
}

type Validate = fn(&str) -> bool;
type Normalize = fn(Vec<String>) -> Vec<String>;

struct ParamDef {
    name: &'static str,
    multiple: bool,
    required: bool,
    default: Option<&'static [&'static str]>,
    validate: Validate,
    normalize: Option<Normalize>,
}

struct Schema {
    prefix: &'static str,
    params: &'static [ParamDef],
    positional: Option<&'static str>,
}

/// None: undefined.
type Values = Vec<(&'static str, Option<Vec<String>>)>;

fn val<'a>(v: &'a Values, name: &str) -> Option<&'a Vec<String>> {
    v.iter().find(|(k, _)| *k == name).and_then(|(_, v)| v.as_ref())
}

fn as_param_str(v: &J) -> Option<String> {
    match v {
        J::String(s) => Some(s.clone()),
        // never passes any validator
        _ => None,
    }
}

impl Schema {
    fn parse(&self, syn: &Syntax) -> Option<Values> {
        for k in syn.keys() {
            if !self.params.iter().any(|d| d.name == k) {
                return None;
            }
        }
        let mut out = Values::new();
        for d in self.params {
            let is_pos = self.positional == Some(d.name);
            match syn.get(d.name, d.multiple) {
                Param::Invalid => return None,
                Param::Values(vals) => {
                    if is_pos && syn.positional.is_some() {
                        return None;
                    }
                    if d.multiple && vals.is_empty() {
                        return None;
                    }
                    let mut strs = Vec::with_capacity(vals.len());
                    for v in &vals {
                        let s = as_param_str(v)?;
                        if !(d.validate)(&s) {
                            return None;
                        }
                        strs.push(s);
                    }
                    out.push((d.name, Some(strs)));
                }
                Param::Absent => {
                    if let (true, Some(p)) = (is_pos, syn.positional.as_ref()) {
                        if !(d.validate)(p) {
                            return None;
                        }
                        out.push((d.name, Some(vec![p.clone()])));
                    } else if d.required {
                        return None;
                    } else {
                        out.push((d.name, d.default.map(|d| d.iter().map(|s| s.to_string()).collect())));
                    }
                }
            }
        }
        Some(out)
    }

    fn format(&self, values: &Values) -> String {
        let mut params: Vec<(String, String)> = Vec::new();
        let mut positional: Option<String> = None;
        for d in self.params {
            let Some(v) = val(values, d.name) else {
                continue;
            };
            let norm = match d.normalize {
                Some(f) => f(v.clone()),
                None => v.clone(),
            };
            if !d.required {
                if let Some(def) = d.default {
                    if same_set(def, &norm) {
                        continue;
                    }
                }
            }
            if d.multiple {
                if self.positional == Some(d.name) && norm.len() == 1 {
                    positional = Some(norm[0].clone());
                } else {
                    let mut seen: Vec<&String> = Vec::new();
                    for x in &norm {
                        if !seen.contains(&x) {
                            seen.push(x);
                            params.push((d.name.to_string(), x.clone()));
                        }
                    }
                }
            } else if self.positional == Some(d.name) {
                positional = Some(norm[0].clone());
            } else {
                params.retain(|(k, _)| k != d.name);
                params.push((d.name.to_string(), norm[0].clone()));
            }
        }
        syntax_to_string(self.prefix, positional.as_deref(), &params)
    }
}

fn same_set(a: &[&str], b: &[String]) -> bool {
    a.iter().all(|x| b.iter().any(|y| y == x)) && b.iter().all(|y| a.iter().any(|x| x == y))
}

/// `@atproto/syntax` isValidNsid.
pub fn is_nsid(s: &str) -> bool {
    if s.len() > 317 || !s.is_ascii() {
        return false;
    }
    let segs: Vec<&str> = s.split('.').collect();
    if segs.len() < 3 {
        return false;
    }
    let (name, domain) = segs.split_last().unwrap();
    if domain.iter().map(|d| d.len() + 1).sum::<usize>() - 1 > 253 {
        return false;
    }
    for (i, seg) in domain.iter().enumerate() {
        let b = seg.as_bytes();
        if b.is_empty() || b.len() > 63 || b[0] == b'-' || b[b.len() - 1] == b'-' {
            return false;
        }
        if !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-') {
            return false;
        }
        if i == 0 && b[0].is_ascii_digit() {
            return false;
        }
    }
    let nb = name.as_bytes();
    !nb.is_empty() && nb.len() <= 63 && nb[0].is_ascii_alphabetic() && nb.iter().all(|c| c.is_ascii_alphanumeric())
}

/// Hostname-level did:web only, with a port only for localhost.
pub fn is_atproto_did(s: &str) -> bool {
    if s.starts_with("did:plc:") {
        return vlsync_atproto::plc::valid_plc_did(s);
    }
    if let Some(host) = s.strip_prefix("did:web:") {
        if host.is_empty() || host.contains(':') || host.len() > 253 {
            return false;
        }
        let decoded = host.replace("%3A", ":").replace("%3a", ":");
        let (h, port) = match decoded.split_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.to_string())),
            None => (decoded.clone(), None),
        };
        if let Some(p) = port {
            if h != "localhost" || p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
        }
        return !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    }
    false
}

fn is_fragment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?%".contains(&b))
}

fn is_did_ref_absolute(s: &str) -> bool {
    match s.split_once('#') {
        Some((did, frag)) => is_atproto_did(did) && is_fragment(frag),
        None => false,
    }
}

fn is_string_slash_string(v: &str) -> bool {
    match v.find('/') {
        None => false,
        Some(i) => i != 0 && i != v.len() - 1 && !v[i + 1..].contains('/') && !v.contains(' '),
    }
}

fn is_mime(v: &str) -> bool {
    is_string_slash_string(v) && !v.contains('*')
}

pub fn is_accept(v: &str) -> bool {
    v == "*/*" || (is_string_slash_string(v) && (!v.contains('*') || v.ends_with("/*")))
}

fn matches_accept(accept: &str, mime: &str) -> bool {
    if accept == "*/*" {
        true
    } else if let Some(base) = accept.strip_suffix('*') {
        mime.starts_with(base)
    } else {
        accept == mime
    }
}

fn v_collection(v: &str) -> bool {
    v == "*" || is_nsid(v)
}
fn v_repo_action(v: &str) -> bool {
    REPO_ACTIONS.contains(&v)
}
fn v_aud(v: &str) -> bool {
    v == "*" || is_did_ref_absolute(v)
}
fn v_account_attr(v: &str) -> bool {
    ["email", "repo", "status"].contains(&v)
}
fn v_account_action(v: &str) -> bool {
    ["read", "manage"].contains(&v)
}
fn v_identity_attr(v: &str) -> bool {
    ["handle", "*"].contains(&v)
}

const REPO_ACTIONS: [&str; 3] = ["create", "update", "delete"];

/// `read` implies `read_self`, so the default omits it.
const SPACE_ACTIONS: [&str; 5] = ["read_self", "read", "create", "update", "delete"];
const SPACE_DEFAULT_ACTIONS: [&str; 4] = ["read", "create", "update", "delete"];

fn v_space_type(v: &str) -> bool {
    v == "*" || is_nsid(v)
}
fn v_space_authority(v: &str) -> bool {
    v == "*" || v == "self" || vlsync_atproto::syntax::valid_did(v)
}
fn v_space_key(v: &str) -> bool {
    v == "*" || vlsync_atproto::syntax::valid_rkey(v)
}
fn v_space_action(v: &str) -> bool {
    SPACE_ACTIONS.contains(&v)
}
fn v_space_manage(v: &str) -> bool {
    REPO_ACTIONS.contains(&v)
}
fn n_space_action(v: Vec<String>) -> Vec<String> {
    SPACE_ACTIONS.iter().filter(|a| v.iter().any(|x| x == *a)).map(|s| s.to_string()).collect()
}

fn n_collection(v: Vec<String>) -> Vec<String> {
    if v.len() > 1 {
        if v.iter().any(|x| x == "*") {
            return vec!["*".into()];
        }
        let mut u = v;
        u.sort();
        u.dedup();
        return u;
    }
    v
}
fn n_repo_action(v: Vec<String>) -> Vec<String> {
    REPO_ACTIONS.iter().filter(|a| v.iter().any(|x| x == *a)).map(|s| s.to_string()).collect()
}
fn n_lxm(v: Vec<String>) -> Vec<String> {
    if v.len() > 1 && v.iter().any(|x| x == "*") {
        return vec!["*".into()];
    }
    let mut u = v;
    u.sort();
    u.dedup();
    u
}
fn n_accept(v: Vec<String>) -> Vec<String> {
    if v.iter().any(|x| x == "*/*") {
        return vec!["*/*".into()];
    }
    let lower: Vec<String> = v.iter().map(|s| s.to_lowercase()).collect();
    let mut out: Vec<String> = lower
        .iter()
        .filter(|x| {
            if x.ends_with("/*") {
                return true;
            }
            let base = x.split('/').next().unwrap_or("");
            !lower.iter().any(|y| *y == format!("{base}/*"))
        })
        .cloned()
        .collect();
    out.sort();
    out
}

static REPO: Schema = Schema {
    prefix: "repo",
    params: &[
        ParamDef {
            name: "collection",
            multiple: true,
            required: true,
            default: None,
            validate: v_collection,
            normalize: Some(n_collection),
        },
        ParamDef {
            name: "action",
            multiple: true,
            required: false,
            default: Some(&REPO_ACTIONS),
            validate: v_repo_action,
            normalize: Some(n_repo_action),
        },
    ],
    positional: Some("collection"),
};

static RPC: Schema = Schema {
    prefix: "rpc",
    params: &[
        ParamDef {
            name: "lxm",
            multiple: true,
            required: true,
            default: None,
            validate: v_collection,
            normalize: Some(n_lxm),
        },
        ParamDef { name: "aud", multiple: false, required: true, default: None, validate: v_aud, normalize: None },
    ],
    positional: Some("lxm"),
};

static BLOB: Schema = Schema {
    prefix: "blob",
    params: &[ParamDef {
        name: "accept",
        multiple: true,
        required: true,
        default: None,
        validate: is_accept,
        normalize: Some(n_accept),
    }],
    positional: Some("accept"),
};

static ACCOUNT: Schema = Schema {
    prefix: "account",
    params: &[
        ParamDef {
            name: "attr",
            multiple: false,
            required: true,
            default: None,
            validate: v_account_attr,
            normalize: None,
        },
        ParamDef {
            name: "action",
            multiple: true,
            required: false,
            default: Some(&["read"]),
            validate: v_account_action,
            normalize: None,
        },
    ],
    positional: Some("attr"),
};

static IDENTITY: Schema = Schema {
    prefix: "identity",
    params: &[ParamDef {
        name: "attr",
        multiple: false,
        required: true,
        default: None,
        validate: v_identity_attr,
        normalize: None,
    }],
    positional: Some("attr"),
};

/// `space:<type>`; a missing `collection` means no write targets, and a
/// missing `manage` no management.
static SPACE: Schema = Schema {
    prefix: "space",
    params: &[
        ParamDef {
            name: "type",
            multiple: false,
            required: true,
            default: None,
            validate: v_space_type,
            normalize: None,
        },
        ParamDef {
            name: "authority",
            multiple: false,
            required: false,
            default: Some(&["self"]),
            validate: v_space_authority,
            normalize: None,
        },
        ParamDef {
            name: "skey",
            multiple: false,
            required: false,
            default: Some(&["*"]),
            validate: v_space_key,
            normalize: None,
        },
        ParamDef {
            name: "collection",
            multiple: true,
            required: false,
            default: None,
            validate: v_collection,
            normalize: Some(n_collection),
        },
        ParamDef {
            name: "action",
            multiple: true,
            required: false,
            default: Some(&SPACE_DEFAULT_ACTIONS),
            validate: v_space_action,
            normalize: Some(n_space_action),
        },
        ParamDef {
            name: "manage",
            multiple: true,
            required: false,
            default: None,
            validate: v_space_manage,
            normalize: Some(n_repo_action),
        },
    ],
    positional: Some("type"),
};

static INCLUDE: Schema = Schema {
    prefix: "include",
    params: &[
        ParamDef { name: "nsid", multiple: false, required: true, default: None, validate: is_nsid, normalize: None },
        ParamDef {
            name: "aud",
            multiple: false,
            required: false,
            default: None,
            validate: is_did_ref_absolute,
            normalize: None,
        },
    ],
    positional: Some("nsid"),
};

#[derive(Clone, Debug, PartialEq)]
pub enum Permission {
    Repo { collection: Vec<String>, action: Vec<String> },
    Rpc { aud: String, lxm: Vec<String> },
    Blob { accept: Vec<String> },
    Account { attr: String, action: Vec<String> },
    Identity { attr: String },
    Space(SpacePermission),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SpacePermission {
    pub space_type: String,
    /// A DID, `*`, or `self`: the granting account.
    pub authority: String,
    pub skey: String,
    pub collection: Option<Vec<String>>,
    pub action: Vec<String>,
    pub manage: Option<Vec<String>>,
}

/// The space a request touches.
#[derive(Clone, Copy, Debug)]
pub struct SpaceTarget<'a> {
    pub space_type: &'a str,
    pub authority: &'a str,
    pub skey: &'a str,
}

/// What a request does in a space (`SpacePermissionMatchOperation`).
#[derive(Clone, Copy, Debug)]
pub enum SpaceAccess<'a> {
    Read,
    ReadSelf,
    /// create | update | delete, of a collection.
    Write(&'a str, &'a str),
    /// create | update | delete, of some collection: what a request needs
    /// before it knows which (importRepo, before its body is read).
    WriteAny(&'a str),
    /// create | update | delete of the space itself.
    Manage(&'a str),
}

impl SpacePermission {
    /// `self` is resolved when the token is issued
    /// ([`Self::with_resolved_authority`]); an unresolved one matches
    /// nothing, since a target's authority is always a DID.
    pub fn matches(&self, t: &SpaceTarget, access: SpaceAccess) -> bool {
        if self.space_type != "*" && self.space_type != t.space_type {
            return false;
        }
        if self.authority != "*" && self.authority != t.authority {
            return false;
        }
        if self.skey != "*" && self.skey != t.skey {
            return false;
        }
        let has = |a: &str| self.action.iter().any(|x| x == a);
        match access {
            SpaceAccess::Manage(op) => self.manage.as_ref().is_some_and(|m| m.iter().any(|x| x == op)),
            SpaceAccess::Read => has("read"),
            SpaceAccess::ReadSelf => has("read") || has("read_self"),
            SpaceAccess::Write(action, coll) => {
                has(action) && self.collection.as_ref().is_some_and(|c| c.iter().any(|x| x == "*" || x == coll))
            }
            SpaceAccess::WriteAny(action) => has(action) && self.collection.as_ref().is_some_and(|c| !c.is_empty()),
        }
    }

    /// Whether the grant writes anything, so whether its collections matter.
    pub fn writes(&self) -> bool {
        self.action.iter().any(|a| REPO_ACTIONS.contains(&a.as_str()))
    }

    /// A bare grant that writes: its collections come from its type's
    /// declaration. One that writes nothing needs none.
    pub fn needs_declaration(&self) -> bool {
        self.collection.is_none() && self.space_type != "*" && self.writes()
    }

    /// `withDefaultCollections`: a bare grant takes its type declaration's
    /// collections.
    pub fn with_default_collections(mut self, collections: &[String]) -> SpacePermission {
        if self.collection.is_none() && !collections.is_empty() {
            self.collection = Some(collections.to_vec());
        }
        self
    }

    /// `withResolvedAuthority`: `self` becomes the granting account.
    pub fn with_resolved_authority(mut self, user: &str) -> SpacePermission {
        if self.authority == "self" {
            self.authority = user.to_string();
        }
        self
    }

    /// `scopeNeededFor`: the narrowest scope that would grant `access`.
    pub fn needed_for(t: &SpaceTarget, access: SpaceAccess) -> String {
        let one = |s: &str| Some(vec![s.to_string()]);
        let (collection, action, manage) = match access {
            SpaceAccess::Manage(op) => (None, one("read_self"), one(op)),
            SpaceAccess::Read => (None, one("read"), None),
            SpaceAccess::ReadSelf => (None, one("read_self"), None),
            SpaceAccess::Write(action, coll) => (one(coll), one(action), None),
            SpaceAccess::WriteAny(action) => (one("*"), one(action), None),
        };
        SPACE.format(&vec![
            ("type", one(t.space_type)),
            ("authority", one(t.authority)),
            ("skey", one(t.skey)),
            ("collection", collection),
            ("action", action),
            ("manage", manage),
        ])
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IncludeScope {
    pub nsid: String,
    pub aud: Option<String>,
}

fn first(v: &Values, k: &str) -> String {
    val(v, k).and_then(|x| x.first().cloned()).unwrap_or_default()
}

impl Permission {
    pub fn from_syntax(syn: &Syntax) -> Option<Permission> {
        match syn.prefix.as_str() {
            "repo" => {
                let v = REPO.parse(syn)?;
                Some(Permission::Repo {
                    collection: val(&v, "collection")?.clone(),
                    action: val(&v, "action")?.clone(),
                })
            }
            "rpc" => {
                let v = RPC.parse(syn)?;
                let aud = first(&v, "aud");
                let lxm = val(&v, "lxm")?.clone();
                // rpc:*?aud=* is forbidden
                if aud == "*" && lxm.iter().any(|x| x == "*") {
                    return None;
                }
                Some(Permission::Rpc { aud, lxm })
            }
            "blob" => {
                let v = BLOB.parse(syn)?;
                Some(Permission::Blob { accept: val(&v, "accept")?.clone() })
            }
            "account" => {
                let v = ACCOUNT.parse(syn)?;
                Some(Permission::Account { attr: first(&v, "attr"), action: val(&v, "action")?.clone() })
            }
            "identity" => {
                let v = IDENTITY.parse(syn)?;
                Some(Permission::Identity { attr: first(&v, "attr") })
            }
            "space" => {
                let v = SPACE.parse(syn)?;
                Some(Permission::Space(SpacePermission {
                    space_type: first(&v, "type"),
                    authority: first(&v, "authority"),
                    skey: first(&v, "skey"),
                    collection: val(&v, "collection").cloned(),
                    action: val(&v, "action")?.clone(),
                    manage: val(&v, "manage").cloned(),
                }))
            }
            _ => None,
        }
    }

    pub fn parse(scope: &str) -> Option<Permission> {
        for p in ["repo", "rpc", "blob", "account", "identity", "space"] {
            if is_scope_string_for(scope, p) {
                return Permission::from_syntax(&Syntax::from_string(scope)?);
            }
        }
        None
    }

    pub fn to_scope_string(&self) -> String {
        match self {
            Permission::Repo { collection, action } => {
                REPO.format(&vec![("collection", Some(collection.clone())), ("action", Some(action.clone()))])
            }
            Permission::Rpc { aud, lxm } => {
                RPC.format(&vec![("lxm", Some(lxm.clone())), ("aud", Some(vec![aud.clone()]))])
            }
            Permission::Blob { accept } => BLOB.format(&vec![("accept", Some(accept.clone()))]),
            Permission::Account { attr, action } => {
                ACCOUNT.format(&vec![("attr", Some(vec![attr.clone()])), ("action", Some(action.clone()))])
            }
            Permission::Identity { attr } => IDENTITY.format(&vec![("attr", Some(vec![attr.clone()]))]),
            Permission::Space(p) => SPACE.format(&vec![
                ("type", Some(vec![p.space_type.clone()])),
                ("authority", Some(vec![p.authority.clone()])),
                ("skey", Some(vec![p.skey.clone()])),
                ("collection", p.collection.clone()),
                ("action", Some(p.action.clone())),
                ("manage", p.manage.clone()),
            ]),
        }
    }

    pub fn matches_repo(&self, coll: &str, act: &str) -> bool {
        matches!(self, Permission::Repo { collection, action }
            if action.iter().any(|a| a == act) && collection.iter().any(|c| c == "*" || c == coll))
    }
    pub fn matches_rpc(&self, l: &str, a: &str) -> bool {
        matches!(self, Permission::Rpc { aud, lxm }
            if (aud == "*" || aud == a) && lxm.iter().any(|x| x == "*" || x == l))
    }
    pub fn matches_blob(&self, mime: &str) -> bool {
        matches!(self, Permission::Blob { accept } if is_mime(mime) && accept.iter().any(|a| matches_accept(a, mime)))
    }
    pub fn matches_account(&self, at: &str, act: &str) -> bool {
        matches!(self, Permission::Account { attr, action }
            if attr == at && (action.iter().any(|a| a == "manage") || action.iter().any(|a| a == act)))
    }
    pub fn matches_identity(&self, at: &str) -> bool {
        matches!(self, Permission::Identity { attr } if attr == "*" || attr == at)
    }
}

impl IncludeScope {
    pub fn parse(scope: &str) -> Option<IncludeScope> {
        if !is_scope_string_for(scope, "include") {
            return None;
        }
        let v = INCLUDE.parse(&Syntax::from_string(scope)?)?;
        Some(IncludeScope { nsid: first(&v, "nsid"), aud: val(&v, "aud").and_then(|a| a.first().cloned()) })
    }

    pub fn to_scope_string(&self) -> String {
        INCLUDE.format(&vec![("nsid", Some(vec![self.nsid.clone()])), ("aud", self.aud.clone().map(|a| vec![a]))])
    }

    /// Same NSID group: everything up to the last '.'.
    fn is_parent_authority_of(&self, other: &str) -> bool {
        if other == "*" {
            return false;
        }
        let Some(group_end) = self.nsid.rfind('.') else {
            return false;
        };
        if group_end + 1 >= other.len() {
            return false;
        }
        other.as_bytes().get(..=group_end) == self.nsid.as_bytes().get(..=group_end)
    }

    /// `permission_set`: its `defs.main`. `spaces`: whether its space
    /// permissions count (`--spaces`).
    pub fn to_permissions(&self, permission_set: &J, spaces: bool) -> Vec<Permission> {
        let mut out = Vec::new();
        let Some(perms) = permission_set.get("permissions").and_then(|p| p.as_array()) else {
            return out;
        };
        for p in perms {
            let Some(obj) = p.as_object() else { continue };
            let resource = obj.get("resource").and_then(|r| r.as_str()).unwrap_or("");
            let syn = match resource {
                "repo" => Syntax::from_lex(obj),
                "rpc" => {
                    // permission sets may not fix an rpc audience
                    match obj.get("aud") {
                        None => {}
                        Some(J::String(a)) if a == "*" => {}
                        Some(_) => continue,
                    }
                    if obj.get("inheritAud") == Some(&J::Bool(true)) && obj.get("aud").is_none() && self.aud.is_some() {
                        let mut o = obj.clone();
                        o.remove("inheritAud");
                        o.insert("aud".into(), J::String(self.aud.clone().unwrap()));
                        Syntax::from_lex(&o)
                    } else {
                        Syntax::from_lex(obj)
                    }
                }
                "space" if spaces => Syntax::from_lex(obj),
                _ => continue,
            };
            let Some(syn) = syn else { continue };
            let Some(perm) = Permission::from_syntax(&syn) else {
                continue;
            };
            let allowed = match &perm {
                Permission::Rpc { lxm, .. } => lxm.iter().all(|l| self.is_parent_authority_of(l)),
                Permission::Repo { collection, .. } => collection.iter().all(|c| self.is_parent_authority_of(c)),
                // only the type: its collections may live under another authority
                Permission::Space(p) => self.is_parent_authority_of(&p.space_type),
                _ => false,
            };
            if allowed {
                out.push(perm);
            }
        }
        out
    }
}

/// `isAtprotoOauthScope`, without `space:` scopes, which are only offered
/// with `--spaces` ([`is_space_scope`]).
pub fn is_atproto_oauth_scope(v: &str) -> bool {
    STATIC_SCOPES.contains(&v)
        || Permission::parse(v).is_some_and(|p| !matches!(p, Permission::Space(_)))
        || IncludeScope::parse(v).is_some()
}

pub fn is_space_scope(v: &str) -> bool {
    matches!(Permission::parse(v), Some(Permission::Space(_)))
}

/// `normalizeAtprotoOauthScopeValue`.
#[cfg(test)]
fn normalize_scope_value(v: &str) -> Option<String> {
    if STATIC_SCOPES.contains(&v) {
        return Some(v.to_string());
    }
    if let Some(p) = Permission::parse(v) {
        return Some(p.to_scope_string());
    }
    IncludeScope::parse(v).map(|i| i.to_scope_string())
}

/// An access token's scopes. The `allows_*` methods are the reference's
/// `ScopePermissionsTransition`.
#[derive(Clone, Debug, Default)]
pub struct ScopeSet {
    raw: Vec<String>,
    perms: Vec<Permission>,
    generic: bool,
    chat: bool,
    email: bool,
}

impl ScopeSet {
    pub fn new(scope: &str) -> ScopeSet {
        let raw: Vec<String> = scope.split(' ').filter(|s| !s.is_empty()).map(String::from).collect();
        let perms = raw.iter().filter_map(|s| Permission::parse(s)).collect();
        ScopeSet {
            generic: raw.iter().any(|s| s == "transition:generic"),
            chat: raw.iter().any(|s| s == "transition:chat.bsky"),
            email: raw.iter().any(|s| s == "transition:email"),
            raw,
            perms,
        }
    }

    pub fn has(&self, scope: &str) -> bool {
        self.raw.iter().any(|s| s == scope)
    }

    pub fn allows_repo(&self, collection: &str, action: &str) -> bool {
        self.generic || self.perms.iter().any(|p| p.matches_repo(collection, action))
    }

    pub fn allows_rpc(&self, lxm: &str, aud: &str) -> bool {
        if self.generic && (lxm == "*" || !lxm.starts_with("chat.bsky.")) {
            return true;
        }
        if self.chat && lxm.starts_with("chat.bsky.") {
            return true;
        }
        self.perms.iter().any(|p| p.matches_rpc(lxm, aud))
    }

    pub fn allows_blob(&self, mime: &str) -> bool {
        self.generic || self.perms.iter().any(|p| p.matches_blob(mime))
    }

    pub fn allows_account(&self, attr: &str, action: &str) -> bool {
        if attr == "email" && action == "read" && self.email {
            return true;
        }
        self.perms.iter().any(|p| p.matches_account(attr, action))
    }

    pub fn allows_identity(&self, attr: &str) -> bool {
        self.perms.iter().any(|p| p.matches_identity(attr))
    }

    /// No transition scope grants space access.
    pub fn allows_space(&self, t: &SpaceTarget, access: SpaceAccess) -> bool {
        self.perms.iter().any(|p| matches!(p, Permission::Space(s) if s.matches(t, access)))
    }

    /// Whether a `space:` grant covers a service token for space method
    /// `lxm`, which an app sends to another host as `user`: a revocation
    /// needs authority powers (`manage`, or the user's own spaces), a
    /// notifyWrite a write action, anything else some space grant.
    /// `transition:generic` and `rpc:` alone never do.
    pub fn allows_space_service_auth(&self, lxm: &str, user: &str) -> bool {
        let lxm = lxm.to_ascii_lowercase();
        self.perms.iter().any(|p| match p {
            Permission::Space(s) => match lxm.as_str() {
                "com.atproto.space.notifycredentialrevoked" => {
                    s.manage.as_ref().is_some_and(|m| !m.is_empty()) || s.authority == user
                }
                "com.atproto.space.notifywrite" => s.writes(),
                _ => true,
            },
            _ => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> Option<String> {
        normalize_scope_value(s)
    }

    #[test]
    fn repo_parse_and_format() {
        assert_eq!(norm("repo:app.bsky.feed.post").unwrap(), "repo:app.bsky.feed.post");
        assert_eq!(
            norm("repo:app.bsky.feed.post?action=create&action=update&action=delete").unwrap(),
            "repo:app.bsky.feed.post"
        );
        assert_eq!(
            norm("repo:app.bsky.feed.post?action=delete&action=create").unwrap(),
            "repo:app.bsky.feed.post?action=create&action=delete"
        );
        assert_eq!(
            norm("repo?collection=app.bsky.feed.post&collection=app.bsky.feed.like").unwrap(),
            "repo?collection=app.bsky.feed.like&collection=app.bsky.feed.post"
        );
        assert_eq!(norm("repo?collection=*&collection=app.bsky.feed.like").unwrap(), "repo:*");
        assert_eq!(norm("repo:*").unwrap(), "repo:*");
        assert!(norm("repo").is_none());
        assert!(norm("repo:not-an-nsid").is_none());
        assert!(norm("repo:app.bsky.feed.post?action=read").is_none());
        assert!(norm("repo:app.bsky.feed.post?collection=app.bsky.feed.like").is_none());
        assert!(norm("repo:app.bsky.feed.post?foo=bar").is_none());
        let p = Permission::parse("repo:app.bsky.feed.like").unwrap();
        assert!(p.matches_repo("app.bsky.feed.like", "create"));
        assert!(!p.matches_repo("app.bsky.feed.post", "create"));
        let p = Permission::parse("repo:*?action=delete").unwrap();
        assert!(p.matches_repo("x.y.z", "delete"));
        assert!(!p.matches_repo("x.y.z", "create"));
    }

    #[test]
    fn rpc() {
        assert!(Permission::parse("rpc:*?aud=*").is_none());
        assert!(Permission::parse("rpc:app.bsky.feed.getFeed").is_none(), "aud required");
        let p = Permission::parse("rpc:app.bsky.feed.getFeed?aud=did:web:api.bsky.app%23bsky_appview").unwrap();
        assert!(p.matches_rpc("app.bsky.feed.getFeed", "did:web:api.bsky.app#bsky_appview"));
        assert!(!p.matches_rpc("app.bsky.feed.getFeed", "did:web:other.example#x"));
        // reference tests/proxied/proxy-oauth-aud.test.ts: the proxy checks
        // `did#serviceId`; the same DID with another service id, or the bare
        // DID, does not match
        assert!(!p.matches_rpc("app.bsky.feed.getFeed", "did:web:api.bsky.app#atproto_other"));
        assert!(!p.matches_rpc("app.bsky.feed.getFeed", "did:web:api.bsky.app"));
        assert_eq!(p.to_scope_string(), "rpc:app.bsky.feed.getFeed?aud=did:web:api.bsky.app%23bsky_appview");
        let p = Permission::parse("rpc?lxm=app.bsky.feed.getFeed&lxm=app.bsky.actor.getProfile&aud=*").unwrap();
        assert_eq!(p.to_scope_string(), "rpc?lxm=app.bsky.actor.getProfile&lxm=app.bsky.feed.getFeed&aud=*");
        assert!(p.matches_rpc("app.bsky.actor.getProfile", "did:web:x.com#y"));
    }

    #[test]
    fn blob() {
        let p = Permission::parse("blob:image/*").unwrap();
        assert!(p.matches_blob("image/png"));
        assert!(!p.matches_blob("video/mp4"));
        assert!(!p.matches_blob("image/*"));
        assert_eq!(
            norm("blob?accept=image/png&accept=image/*&accept=video/mp4").unwrap(),
            "blob?accept=image/*&accept=video/mp4"
        );
        assert_eq!(norm("blob?accept=image/png&accept=*/*").unwrap(), "blob:*/*");
        assert!(norm("blob:image").is_none());
        assert!(norm("blob:*/png").is_none());
    }

    #[test]
    fn account_identity() {
        let p = Permission::parse("account:email").unwrap();
        assert!(p.matches_account("email", "read"));
        assert!(!p.matches_account("email", "manage"));
        assert_eq!(p.to_scope_string(), "account:email");
        let p = Permission::parse("account:repo?action=manage").unwrap();
        assert!(p.matches_account("repo", "read"));
        assert!(p.matches_account("repo", "manage"));
        assert!(Permission::parse("account:foo").is_none());
        assert!(Permission::parse("identity:*").unwrap().matches_identity("handle"));
        assert!(Permission::parse("identity:handle").unwrap().matches_identity("handle"));
        assert!(!Permission::parse("identity:handle").unwrap().matches_identity("*"));
        assert!(Permission::parse("identity").is_none());
    }

    #[test]
    fn include() {
        let i = IncludeScope::parse("include:com.example.authBasic?aud=did:web:example.com%23svc").unwrap();
        assert_eq!(i.nsid, "com.example.authBasic");
        assert_eq!(i.aud.as_deref(), Some("did:web:example.com#svc"));
        assert_eq!(i.to_scope_string(), "include:com.example.authBasic?aud=did:web:example.com%23svc");
        assert!(i.is_parent_authority_of("com.example.foo"));
        assert!(i.is_parent_authority_of("com.example.foo.bar"));
        assert!(!i.is_parent_authority_of("com.other.foo"));
        assert!(!i.is_parent_authority_of("com.example"));
        assert!(!i.is_parent_authority_of("*"));
        let set = serde_json::json!({
            "type": "permission-set",
            "permissions": [
                {"type": "permission", "resource": "repo", "collection": ["com.example.post", "com.example.like"]},
                {"type": "permission", "resource": "repo", "collection": ["app.bsky.feed.post"]},
                {"type": "permission", "resource": "rpc", "lxm": ["com.example.getThing"], "inheritAud": true},
                {"type": "permission", "resource": "rpc", "lxm": ["com.example.fixed"], "aud": "did:web:x.com#y"},
                {"type": "permission", "resource": "blob", "accept": ["*/*"]},
            ]
        });
        let perms: Vec<String> = i.to_permissions(&set, false).iter().map(|p| p.to_scope_string()).collect();
        assert_eq!(
            perms,
            vec![
                "repo?collection=com.example.like&collection=com.example.post",
                "rpc:com.example.getThing?aud=did:web:example.com%23svc"
            ]
        );
        // without aud, inheritAud is an unknown key -> dropped
        let i2 = IncludeScope::parse("include:com.example.authBasic").unwrap();
        assert_eq!(i2.to_permissions(&set, false).len(), 1);
    }

    #[test]
    fn transition() {
        let s = ScopeSet::new("atproto transition:generic");
        assert!(s.allows_repo("app.bsky.feed.post", "create"));
        assert!(s.allows_blob("image/png"));
        assert!(s.allows_rpc("app.bsky.feed.getTimeline", "did:web:api.bsky.app#bsky_appview"));
        assert!(!s.allows_rpc("chat.bsky.convo.listConvos", "did:web:api.bsky.chat#bsky_chat"));
        assert!(!s.allows_account("email", "read"));
        let s = ScopeSet::new("atproto transition:chat.bsky transition:email");
        assert!(s.allows_rpc("chat.bsky.convo.listConvos", "did:web:api.bsky.chat#bsky_chat"));
        assert!(s.allows_account("email", "read"));
        assert!(!s.allows_account("email", "manage"));
        let s = ScopeSet::new("atproto repo:app.bsky.feed.like");
        assert!(s.allows_repo("app.bsky.feed.like", "create"));
        assert!(!s.allows_repo("app.bsky.feed.post", "create"));
        assert!(!s.allows_blob("image/png"));
    }

    #[test]
    fn validity() {
        for s in [
            "atproto",
            "transition:generic",
            "repo:*",
            "include:com.example.foo",
            "identity:handle",
            "account:status?action=manage",
        ] {
            assert!(is_atproto_oauth_scope(s), "{s}");
        }
        for s in ["openid", "repo", "transition:foo", "include:*", "rpc:*?aud=*"] {
            assert!(!is_atproto_oauth_scope(s), "{s}");
        }
        assert!(is_nsid("app.bsky.feed.post"));
        assert!(!is_nsid("app.bsky"));
        assert!(!is_nsid("1app.bsky.feed"));
        assert!(!is_nsid("app.bsky.feed-post"));
        assert!(is_atproto_did("did:plc:abcdefghijklmnopqrstuvwx"));
        assert!(is_atproto_did("did:web:localhost%3A1234"));
        assert!(!is_atproto_did("did:web:example.com%3A1234"));
    }
    /// Reference oauth-scopes `space-permission.test.ts`.
    #[test]
    fn space() {
        let sp = |s: &str| match Permission::parse(s) {
            Some(Permission::Space(p)) => Some(p),
            _ => None,
        };
        let p = sp("space:com.atmoboards.forum").unwrap();
        assert_eq!((p.authority.as_str(), p.skey.as_str(), p.collection.as_ref()), ("self", "*", None));
        assert_eq!(p.action, ["read", "create", "update", "delete"]);
        assert_eq!(Permission::Space(p).to_scope_string(), "space:com.atmoboards.forum");
        let p = sp("space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default").unwrap();
        assert_eq!((p.authority.as_str(), p.skey.as_str()), ("did:plc:abc123xyz", "default"));
        assert_eq!(sp("space:*?authority=*").unwrap().space_type, "*");
        assert_eq!(sp("space:com.x.y?action=create&action=update").unwrap().action, ["create", "update"]);
        assert_eq!(sp("space:com.x.y?manage=update&manage=delete").unwrap().manage.unwrap(), ["update", "delete"]);
        let p = Permission::parse("space:com.x.y?manage=delete&manage=update&action=update&action=read").unwrap();
        assert_eq!(p.to_scope_string(), "space:com.x.y?action=read&action=update&manage=update&manage=delete");
        for bad in [
            "space:com.example.x?manage=bogus",
            "space:foo bar",
            "space:short",
            "space:*?authority=not-a-did",
            "space:*?authority=did:",
            "space:com.example.x?action=bogus",
            "space:com.example.x?collection=not_an_nsid",
            "space:com.example.x?skey=",
            "space:com.example.x?skey=a%2Fb",
            "space:com.example.x?skey=..",
        ] {
            assert!(sp(bad).is_none(), "{bad}");
        }
        assert!(!is_atproto_oauth_scope("space:com.example.x"), "offered only with --spaces");
        assert!(is_space_scope("space:com.example.x"));
        let t = SpaceTarget { space_type: "com.atmoboards.forum", authority: "did:plc:abc", skey: "default" };
        assert_eq!(
            SpacePermission::needed_for(&t, SpaceAccess::Read),
            "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read"
        );
        assert_eq!(
            SpacePermission::needed_for(&t, SpaceAccess::Write("create", "com.atmoboards.thread")),
            "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&collection=com.atmoboards.thread&action=create"
        );
        assert_eq!(
            SpacePermission::needed_for(&t, SpaceAccess::Manage("update")),
            "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read_self&manage=update"
        );
        // what a refusal suggests grants exactly that
        for a in [
            SpaceAccess::Read,
            SpaceAccess::ReadSelf,
            SpaceAccess::Write("create", "com.atmoboards.thread"),
            SpaceAccess::Manage("update"),
        ] {
            let p = sp(&SpacePermission::needed_for(&t, a)).unwrap();
            assert!(p.matches(&t, a), "{a:?}");
            // and confers no writes it wasn't asked for
            if !matches!(a, SpaceAccess::Write(..)) {
                assert!(!p.matches(&t, SpaceAccess::Write("create", "com.atmoboards.thread")), "{a:?}");
            }
        }
        // an unresolved `self` matches nothing; resolved, only that account
        let p = sp("space:com.atmoboards.forum?action=read&action=create&collection=com.atmoboards.thread").unwrap();
        assert!(!p.matches(&t, SpaceAccess::Read));
        let p = p.with_resolved_authority("did:plc:abc");
        assert_eq!(p.authority, "did:plc:abc");
        assert!(p.matches(&t, SpaceAccess::Read));
        assert!(!p.matches(&SpaceTarget { authority: "did:plc:other", ..t }, SpaceAccess::Read));
        // reads ignore collections; read implies read_self
        assert!(p.matches(&t, SpaceAccess::ReadSelf));
        assert!(p.matches(&t, SpaceAccess::Write("create", "com.atmoboards.thread")));
        assert!(!p.matches(&t, SpaceAccess::Write("create", "com.atmoboards.post")));
        assert!(!p.matches(&t, SpaceAccess::Write("update", "com.atmoboards.thread")));
        assert!(!p.matches(&t, SpaceAccess::Manage("create")));
        let p = sp("space:com.atmoboards.forum?authority=*&action=read_self&collection=com.atmoboards.thread").unwrap();
        assert!(p.matches(&t, SpaceAccess::ReadSelf));
        assert!(!p.matches(&t, SpaceAccess::Read));
        // no collection: no write targets
        assert!(!sp("space:*?authority=*").unwrap().matches(&t, SpaceAccess::Write("create", "a.b.c")));
        let p = sp("space:com.atmoboards.forum?authority=*&collection=*").unwrap();
        assert!(p.matches(&t, SpaceAccess::Write("update", "any.collection.name")));
        assert!(!p.matches(&t, SpaceAccess::Manage("update")), "the default grant manages nothing");
        let p = sp("space:com.atmoboards.forum?authority=*&action=read&manage=update").unwrap();
        assert!(p.matches(&t, SpaceAccess::Manage("update")));
        assert!(!p.matches(&t, SpaceAccess::Manage("delete")));
        assert!(!sp("space:com.atmoboards.forum?authority=*&action=create").unwrap().matches(&t, SpaceAccess::Read));
        let p = sp("space:com.atmoboards.forum?authority=*&skey=other").unwrap();
        assert!(!p.matches(&t, SpaceAccess::Read));
        let p = sp("space:*?authority=did:plc:abc").unwrap();
        assert!(p.matches(&SpaceTarget { space_type: "com.example.different", ..t }, SpaceAccess::Read));
        for skey in ["self", "3jui7kd54zh2y", "a.b-c_d~e:f", &"x".repeat(512)] {
            assert_eq!(sp(&format!("space:com.example.x?skey={skey}")).unwrap().skey, skey);
        }
        for skey in ["hello%20world", ".", "a%23b", &"x".repeat(513)] {
            assert!(sp(&format!("space:com.example.x?skey={skey}")).is_none(), "{skey}");
        }
        let input = "space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default&collection=com.atmoboards.thread&action=create";
        assert_eq!(Permission::parse(input).unwrap().to_scope_string(), input);
    }

    /// Reference `withDefaultCollections` and `withResolvedAuthority`.
    #[test]
    fn space_grant_time() {
        let sp = |s: &str| match Permission::parse(s) {
            Some(Permission::Space(p)) => p,
            _ => panic!("{s}"),
        };
        let decl = ["com.atmoboards.thread".to_string(), "com.atmoboards.reply".to_string()];
        let p = sp("space:com.atmoboards.forum?authority=*").with_default_collections(&decl);
        assert_eq!(p.collection.as_deref(), Some(&decl[..]));
        let t = SpaceTarget { space_type: "com.atmoboards.forum", authority: "did:plc:abc", skey: "default" };
        assert!(p.matches(&t, SpaceAccess::Write("create", "com.atmoboards.thread")));
        assert_eq!(
            Permission::Space(p).to_scope_string(),
            "space:com.atmoboards.forum?authority=*&collection=com.atmoboards.reply&collection=com.atmoboards.thread"
        );
        let named = sp("space:com.atmoboards.forum?collection=com.atmoboards.thread");
        assert_eq!(named.clone().with_default_collections(&decl[1..]), named);
        let star = sp("space:com.atmoboards.forum?collection=*");
        assert_eq!(star.clone().with_default_collections(&decl), star);
        let bare = sp("space:com.atmoboards.forum");
        assert_eq!(bare.clone().with_default_collections(&[]), bare);
        assert_eq!(bare.clone().with_resolved_authority("did:plc:abc").authority, "did:plc:abc");
        for a in ["did:plc:xyz", "*"] {
            let p = sp(&format!("space:com.atmoboards.forum?authority={a}"));
            assert_eq!(p.clone().with_resolved_authority("did:plc:abc"), p);
        }
        assert!(bare.writes());
        assert!(!sp("space:com.atmoboards.forum?action=read&manage=update").writes());
    }

    /// indigo atproto/auth/testdata/permission_scopes_{valid,invalid}.txt
    /// (PR #1445): its `space` lines. indigo names the type `spaceType` where
    /// the reference says `type`; both are taken.
    #[test]
    fn indigo_space_scopes() {
        for ok in [
            "space:com.example.bookmarks",
            "space:com.atmoboards.forum?authority=*",
            "space:com.atmoboards.forum?authority=*&action=read",
            "space:com.atmoboards.forum?authority=*&action=read_self",
            "space:com.atmoboards.forum?authority=*&collection=*",
            "space:com.atmoboards.forum?authority=did:plc:abc123&skey=default&collection=com.atmoboards.thread&action=create&action=update",
            "space:com.atmoboards.forum?authority=*&action=read_self&manage=update&manage=delete",
            "space:com.atmoboards.forum?authority=*&manage=update&manage=delete",
            "space:*?authority=did:plc:abc123",
            "space?spaceType=com.example.bookmarks",
            "space:*",
            "space:com.example.bookmarks?authority=self",
            "space:com.example.bookmarks?skey=*",
            "space:com.example.bookmarks?collection=*",
            "space:com.example.forum?action=read_self&authority=%2A",
        ] {
            assert!(is_space_scope(ok), "{ok}");
        }
        assert_eq!(
            Permission::parse("space?spaceType=com.example.bookmarks").unwrap().to_scope_string(),
            "space:com.example.bookmarks"
        );
        assert_eq!(
            Permission::parse("space?type=com.example.bookmarks").unwrap().to_scope_string(),
            "space:com.example.bookmarks"
        );
        for bad in [
            "space",
            "space:123",
            "space?spaceType=123",
            "space?spaceType=com.example.bookmarks&spaceType=com.example.prefs",
            "space:com.example.bookmarks?spaceType=com.example.bookmarks",
            "space:com.example.forum?authority=123",
            "space:com.example.forum?authority=did:web:example.com&authority=did:web:example.org",
            "space:com.example.forum?skey=/",
            "space:com.example.forum?skey=1&skey=2",
            "space:com.example.forum?action=123",
            "space:com.example.forum?manage=123",
            "space:com.example.forum?collection=123",
            "space?type=com.example.a&spaceType=com.example.b",
        ] {
            assert!(!is_space_scope(bad), "{bad}");
        }
    }

    /// Reference include-scope.test.ts "space": a set's space permissions
    /// count only with `--spaces`, only under the set's own NSID group, never
    /// for every type, and with collections from anywhere.
    #[test]
    fn include_space() {
        let i = IncludeScope::parse("include:com.example.calendar.auth").unwrap();
        let set = |perm: J| serde_json::json!({"type": "permission-set", "permissions": [perm]});
        let compiled = |perm: J| -> Vec<String> {
            i.to_permissions(&set(perm), true).iter().map(|p| p.to_scope_string()).collect()
        };
        let perm = serde_json::json!({"type": "permission", "resource": "space",
            "spaceType": "com.example.calendar.group", "action": ["read", "create", "update", "delete"]});
        assert_eq!(compiled(perm.clone()), ["space:com.example.calendar.group"]);
        assert!(i.to_permissions(&set(perm), false).is_empty(), "flag off: none");
        assert_eq!(
            compiled(
                serde_json::json!({"type": "permission", "resource": "space", "spaceType": "com.example.calendar.group",
                "collection": ["com.example.calendar.event"], "action": ["create", "update"]})
            ),
            ["space:com.example.calendar.group?collection=com.example.calendar.event&action=create&action=update"]
        );
        assert!(compiled(
            serde_json::json!({"type": "permission", "resource": "space", "spaceType": "app.bsky.group"})
        )
        .is_empty());
        assert!(compiled(serde_json::json!({"type": "permission", "resource": "space", "spaceType": "*"})).is_empty());
        assert_eq!(
            compiled(
                serde_json::json!({"type": "permission", "resource": "space", "spaceType": "com.example.calendar.group",
                "collection": ["app.bsky.feed.post"]})
            ),
            ["space:com.example.calendar.group?collection=app.bsky.feed.post"]
        );
        assert_eq!(
            compiled(
                serde_json::json!({"type": "permission", "resource": "space", "spaceType": "com.example.calendar.group",
                "collection": ["*"]})
            ),
            ["space:com.example.calendar.group?collection=*"]
        );
        assert!(compiled(serde_json::json!({"type": "permission", "resource": "space"})).is_empty());
    }

    /// `is_atproto_did` delegates did:plc to `vlsync_atproto::plc::valid_plc_did`; both must
    /// accept exactly the old inline rule (24 base32-lowercase chars).
    #[test]
    fn plc_dids_match_old_rule() {
        let old = |s: &str| {
            s.strip_prefix("did:plc:")
                .is_some_and(|id| s.len() == 32 && id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
        };
        let base = "abcdefghijklmnopqrstuvwx";
        let mut cases: Vec<String> =
            vec![String::new(), "did:plc:".into(), format!("did:plc:{base}a"), format!("did:plc:{}", &base[1..])];
        for i in 0..24 {
            for c in (0u8..=255).filter(|c| c.is_ascii()) {
                let mut id = base.as_bytes().to_vec();
                id[i] = c;
                cases.push(format!("did:plc:{}", String::from_utf8(id).unwrap()));
            }
        }
        cases.push(format!("did:plc:{}", "é".repeat(12)));
        cases.push(format!("did:PLC:{base}"));
        for c in &cases {
            assert_eq!(is_atproto_did(c), old(c), "{c:?}");
            assert_eq!(vlsync_atproto::plc::valid_plc_did(c), old(c), "{c:?}");
        }
    }
}
