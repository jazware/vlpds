//! A request's scopes as the consent screen and the connected-apps list show
//! them: one row per app (NSID namespace) or account feature, each
//! effective permission once, sorted by what's at stake.
//!
//! Grants are additive, so a checkbox can only take something away if it
//! drops every source of what it shows. A row holds every requested scope
//! for its app or feature, sets included, and unticking it drops them all.
//! Which row a scope lands in ([`grant_key`]) depends only on the scope
//! strings, never on a lookup, so the consent POST maps ticked rows back to
//! scopes from the stored request alone.

use super::scopes::{IncludeScope, Permission, SpacePermission};
use serde::Serialize;
use serde_json::Value as J;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Tier {
    /// Can take over, lock out, or read everything private.
    Control,
    /// Visible to others under the account's name, or reaches outside the app.
    AsYou,
    /// The app's own data.
    ThisApp,
}

impl Tier {
    pub fn tag(self) -> Option<&'static str> {
        match self {
            Tier::Control => Some("Account control"),
            Tier::AsYou => Some("As you"),
            Tier::ThisApp => None,
        }
    }

    pub fn class(self) -> &'static str {
        match self {
            Tier::Control => "t1",
            Tier::AsYou => "t2",
            Tier::ThisApp => "t3",
        }
    }
}

/// One line of an opened row: a verb, what it acts on, the NSIDs.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Line {
    pub verb: String,
    pub objects: String,
    pub code: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetInfo {
    pub nsid: String,
    pub title: Option<String>,
    pub detail: Option<String>,
    /// The domain that published it (the NSID authority).
    pub publisher: String,
    /// The NSID group it may grant under.
    pub group: String,
    /// Entries the spec says to ignore (wrong resource, outside its group).
    pub ignored: usize,
    /// No copy of it could be read.
    pub unavailable: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub key: String,
    /// What the row's checkbox posts: the grant keys of its scopes.
    #[serde(skip)]
    pub grants: Vec<String>,
    pub label: String,
    pub tier: Tier,
    pub summary: String,
    /// The connected-apps list's chip.
    pub chip: String,
    pub lines: Vec<Line>,
    /// Inline scopes that add to the row's sets.
    pub not_in_set: Vec<Line>,
    pub sets: Vec<SetInfo>,
    /// Rows Full access took in.
    pub includes: Vec<String>,
    /// The requested scopes it holds, as requested.
    pub scopes: Vec<String>,
    /// No checkbox: always granted.
    pub fixed: bool,
    /// Ticked when the page loads.
    pub checked: bool,
    pub warnings: Vec<String>,
}

/// Names for `space:` grants (`--spaces`): type declarations by NSID and
/// the handles of authority DIDs that resolve back to them. A missing one
/// shows the NSID or the DID.
#[derive(Debug, Default)]
pub struct SpaceNames {
    pub decls: HashMap<String, crate::lexicon::SpaceDecl>,
    pub handles: HashMap<String, String>,
}

pub struct Request<'a> {
    /// Space-separated, as requested (or as granted, for a session).
    pub scope: &'a str,
    /// Each `include:` scope's set, or why it couldn't be read.
    pub sets: &'a [(IncludeScope, Result<J, String>)],
    pub client_id: &'a str,
    pub loopback: bool,
    /// Some with `--spaces`.
    pub names: Option<&'a SpaceNames>,
}

/// atproto has no client-declared "required" scopes; only `atproto` itself,
/// without which the token grants nothing.
pub const REQUIRED_SCOPES: [&str; 1] = ["atproto"];

const IDENTITY: &str = "identity";

const SPACE_UNIVERSAL_READ_WARNING: &str = "This app is asking to read every space on the network: whatever anyone \
shares with you in a space, anywhere. That's a very broad grant. Only allow it for an app you trust completely.";
const SPACE_UNIVERSAL_WRITE_WARNING: &str = "This app is asking to write in every space on the network you're a \
member of, as you. That's a very broad grant. Only allow it for an app you trust completely.";
const SPACE_UNIVERSAL_READ_WRITE_WARNING: &str = "This app is asking to read whatever anyone shares with you in a \
space, anywhere on the network, and to write in every space you're a member of, as you. That's a very broad grant. \
Only allow it for an app you trust completely.";

/// A `space:*?authority=*` grant that reads what others share or writes
/// anything. One that only reads your own space repos gets no warning.
fn space_warning(p: &SpacePermission) -> Option<&'static str> {
    if p.space_type != "*" || p.authority != "*" {
        return None;
    }
    let reads = p.action.iter().any(|a| a == "read");
    let writes = p.writes() || p.manage.as_ref().is_some_and(|m| !m.is_empty());
    match (reads, writes) {
        (true, true) => Some(SPACE_UNIVERSAL_READ_WRITE_WARNING),
        (true, false) => Some(SPACE_UNIVERSAL_READ_WARNING),
        (false, true) => Some(SPACE_UNIVERSAL_WRITE_WARNING),
        (false, false) => None,
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Identity,
    Handle,
    Status,
    Import,
    Email,
    Generic,
    Messages,
    AnyApp,
    AnyRequest,
    Several,
    Ns(String),
    Uploads,
    Space(String),
    /// A set no copy of which could be read: its own row.
    Missing(String),
    Other,
}

impl Kind {
    fn key(&self) -> String {
        match self {
            Kind::Identity => IDENTITY.into(),
            Kind::Handle => "handle".into(),
            Kind::Status => "status".into(),
            Kind::Import => "import".into(),
            Kind::Email => "email".into(),
            Kind::Generic => "generic".into(),
            Kind::Messages => "messages".into(),
            Kind::AnyApp => "any-app".into(),
            Kind::AnyRequest => "any-request".into(),
            Kind::Several => "several".into(),
            Kind::Ns(n) => format!("ns:{n}"),
            Kind::Uploads => "uploads".into(),
            Kind::Space(t) => format!("space:{t}"),
            Kind::Missing(n) => format!("set:{n}"),
            Kind::Other => "other".into(),
        }
    }

    /// Order inside a tier; ties keep request order. Account features
    /// lead only among account control.
    fn rank(&self, own: bool, tier: Tier) -> u8 {
        match self {
            Kind::Status | Kind::Import | Kind::Email if tier != Tier::Control => 10,
            Kind::Identity => 0,
            Kind::Handle => 1,
            Kind::Status => 2,
            Kind::Import => 3,
            Kind::Email => 4,
            Kind::Generic => 5,
            Kind::Messages => 6,
            Kind::AnyApp => 7,
            Kind::AnyRequest => 8,
            Kind::Space(_) => 9,
            Kind::Uploads => 11,
            Kind::Ns(_) if own => 12,
            _ => 10,
        }
    }

    /// What Full access (`transition:generic`) already grants.
    fn generic_covers(&self) -> bool {
        matches!(self, Kind::AnyApp | Kind::AnyRequest | Kind::Several | Kind::Ns(_) | Kind::Uploads)
    }
}

/// The NSID group a set may grant under: its NSID minus the name.
fn set_group(nsid: &str) -> String {
    nsid.rsplit_once('.').map_or(nsid, |(g, _)| g).to_string()
}

/// The row an NSID belongs to: the longest requested set group it falls
/// under, else its first two segments (three under `com.atproto`, which
/// every app shares).
fn namespace(nsid: &str, groups: &[String]) -> String {
    if let Some(g) = groups
        .iter()
        .filter(|g| nsid.len() > g.len() && nsid.starts_with(g.as_str()) && nsid.as_bytes()[g.len()] == b'.')
        .max_by_key(|g| g.len())
    {
        return g.clone();
    }
    let take = if nsid.starts_with("com.atproto.") { 3 } else { 2 };
    nsid.split('.').take(take).collect::<Vec<_>>().join(".")
}

fn nsids_kind(nsids: &[String], groups: &[String], any: Kind) -> Kind {
    if nsids.iter().any(|n| n == "*") {
        return any;
    }
    let mut ns = nsids.iter().map(|n| namespace(n, groups));
    match ns.next() {
        Some(first) if ns.all(|n| n == first) => Kind::Ns(first),
        _ => Kind::Several,
    }
}

fn is_chat(lxm: &str) -> bool {
    lxm.starts_with("chat.bsky.")
}

fn permission_kind(p: &Permission, groups: &[String]) -> Kind {
    match p {
        Permission::Identity { .. } => Kind::Handle,
        Permission::Account { attr, .. } => match attr.as_str() {
            "email" => Kind::Email,
            "repo" => Kind::Import,
            _ => Kind::Status,
        },
        Permission::Blob { .. } => Kind::Uploads,
        Permission::Repo { collection, .. } => nsids_kind(collection, groups, Kind::AnyApp),
        Permission::Rpc { lxm, .. } => {
            if !lxm.is_empty() && lxm.iter().all(|l| is_chat(l)) {
                Kind::Messages
            } else {
                nsids_kind(lxm, groups, Kind::AnyRequest)
            }
        }
        Permission::Space(s) => Kind::Space(s.space_type.clone()),
    }
}

fn scope_kind(s: &str, groups: &[String]) -> Kind {
    match s {
        "atproto" => Kind::Identity,
        "transition:generic" => Kind::Generic,
        "transition:chat.bsky" => Kind::Messages,
        "transition:email" => Kind::Email,
        _ => match (Permission::parse(s), IncludeScope::parse(s)) {
            (Some(p), _) => permission_kind(&p, groups),
            (None, Some(inc)) => Kind::Ns(set_group(&inc.nsid)),
            _ => Kind::Other,
        },
    }
}

/// The requested scopes, each once, in request order.
pub fn scope_list(scope: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for s in scope.split(' ').filter(|s| !s.is_empty()) {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

fn set_groups(scopes: &[&str]) -> Vec<String> {
    scopes.iter().filter_map(|s| IncludeScope::parse(s)).map(|i| set_group(&i.nsid)).collect()
}

/// What a row's checkbox posts for `s`: its row's key, or for a set
/// `set:<nsid>`, so a set's grant never depends on whether it could be
/// read when the page was drawn.
pub fn grant_key(s: &str, scope: &str) -> String {
    grant_key_in(s, &set_groups(&scope_list(scope)))
}

fn grant_key_in(s: &str, groups: &[String]) -> String {
    match IncludeScope::parse(s) {
        Some(inc) => format!("set:{}", inc.nsid),
        None => scope_kind(s, groups).key(),
    }
}

/// The scopes of `requested` whose grant key is in `ticked`; None (refuse)
/// when a required scope isn't. `transition:chat.bsky` "depends on and does
/// not function without" `transition:generic`, so it goes when generic does.
pub fn granted_scope(requested: &str, ticked: &[String]) -> Option<String> {
    let scopes = scope_list(requested);
    let groups = set_groups(&scopes);
    let mut granted: Vec<&str> =
        scopes.iter().copied().filter(|s| ticked.iter().any(|t| *t == grant_key_in(s, &groups))).collect();
    if !REQUIRED_SCOPES.iter().all(|r| granted.contains(r)) {
        return None;
    }
    if scopes.contains(&"transition:generic") && !granted.contains(&"transition:generic") {
        granted.retain(|s| *s != "transition:chat.bsky");
    }
    Some(granted.join(" "))
}

/// The client's host, if it has one it could own a namespace through.
fn client_host(client_id: &str, loopback: bool) -> Option<String> {
    if loopback {
        return None;
    }
    let rest = client_id.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = host.split(':').next()?.to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// An NSID namespace as the domain it reads as: `place.stream` is stream.place.
pub fn ns_domain(ns: &str) -> String {
    ns.split('.').rev().collect::<Vec<_>>().join(".").to_ascii_lowercase()
}

/// Whether `ns` is the client's own: its domain and the client's host have
/// the same registrable domain on the public suffix list, so a host under
/// a shared suffix (`someone.github.io`) owns only its own name.
pub fn owns(client_id: &str, loopback: bool, ns: &str) -> bool {
    let Some(host) = client_host(client_id, loopback) else {
        return false;
    };
    let domain = ns_domain(ns);
    match (psl::domain_str(&host), psl::domain_str(&domain)) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

/// A loopback client ID (`http://localhost`, no port), which names no host.
pub fn is_loopback(client_id: &str) -> bool {
    client_id.strip_prefix("http://localhost").is_some_and(|r| r.is_empty() || r.starts_with('/') || r.starts_with('?'))
}

/// What the account page calls a client: its host, or the loopback label.
pub fn client_label(client_id: &str, loopback: bool) -> String {
    match loopback {
        true => "A development app running on your own computer".into(),
        false => client_host(client_id, false).unwrap_or_else(|| client_id.to_string()),
    }
}

fn ns_label(ns: &str) -> String {
    match ns {
        "app.bsky" => "Bluesky".into(),
        "chat.bsky" => "Bluesky chat".into(),
        "com.atproto.moderation" => "Reports".into(),
        "com.atproto.repo" => "Your repository".into(),
        "com.atproto.server" => "Your account and sessions".into(),
        "com.atproto.identity" => "Your handle and identity".into(),
        "com.atproto.sync" => "Repository sync".into(),
        "com.atproto.label" => "Labels".into(),
        "com.atproto.lexicon" => "Lexicons".into(),
        _ => ns_domain(ns),
    }
}

/// Bluesky record types by name, in the order they're listed.
const KNOWN_COLLECTIONS: &[(&str, &str)] = &[
    ("app.bsky.feed.post", "posts"),
    ("app.bsky.feed.like", "likes"),
    ("app.bsky.feed.repost", "reposts"),
    ("app.bsky.feed.threadgate", "threadgates"),
    ("app.bsky.feed.postgate", "postgates"),
    ("app.bsky.feed.generator", "feeds"),
    ("app.bsky.graph.follow", "follows"),
    ("app.bsky.graph.block", "blocks"),
    ("app.bsky.graph.list", "lists"),
    ("app.bsky.graph.listitem", "list members"),
    ("app.bsky.graph.listblock", "list blocks"),
    ("app.bsky.graph.starterpack", "starter packs"),
    ("app.bsky.graph.verification", "verifications"),
    ("app.bsky.actor.profile", "profile"),
    ("app.bsky.actor.status", "status"),
    ("app.bsky.actor.link", "links"),
    ("app.bsky.labeler.service", "labeler"),
    ("chat.bsky.actor.declaration", "chat settings"),
];

/// Namespaces whose record types are named from [`KNOWN_COLLECTIONS`]
/// alone: the rest are counted, not spelled out.
const NAMED_NAMESPACES: [&str; 2] = ["app.bsky", "chat.bsky"];

/// Known methods: what they do and to what.
fn method(lxm: &str) -> Option<(&'static str, &'static str)> {
    Some(match lxm {
        "app.bsky.actor.getProfile" | "app.bsky.actor.getProfiles" => ("Read", "profiles"),
        "app.bsky.actor.getPreferences" => ("Read", "preferences"),
        "app.bsky.actor.putPreferences" => ("Change", "preferences"),
        "app.bsky.actor.searchActors" | "app.bsky.actor.searchActorsTypeahead" => ("Search", "accounts"),
        "app.bsky.feed.getTimeline" => ("Read", "your timeline"),
        "app.bsky.feed.getFeed" | "app.bsky.feed.getFeedGenerator" | "app.bsky.feed.getFeedGenerators" => {
            ("Read", "feeds")
        }
        "app.bsky.feed.getPosts" | "app.bsky.feed.getPostThread" => ("Read", "posts"),
        "app.bsky.feed.searchPosts" => ("Search", "posts"),
        "app.bsky.notification.listNotifications" => ("Read", "notifications"),
        "app.bsky.notification.registerPush" => ("Register", "push notifications"),
        "app.bsky.notification.unregisterPush" => ("Unregister", "push notifications"),
        "app.bsky.contact.importContacts" => ("Import", "your contacts"),
        "com.atproto.moderation.createReport" => ("Send", "reports"),
        _ => return None,
    })
}

/// Methods worth naming however many there are.
fn sensitive(lxm: &str) -> Option<&'static str> {
    match lxm {
        "app.bsky.contact.importContacts" => Some("including importing your contacts"),
        _ => None,
    }
}

/// Bluesky's method areas by name; others are "Other".
fn bsky_area(sub: &str) -> Option<&'static str> {
    Some(match sub {
        "graph" => "Follows, mutes and lists",
        "feed" => "Feeds and posts",
        "notification" => "Notifications",
        "video" => "Video",
        "actor" => "Profiles and preferences",
        "contact" => "Contacts",
        "draft" => "Drafts",
        "ageassurance" => "Age assurance",
        "bookmark" => "Bookmarks",
        _ => return None,
    })
}

const VERB_ORDER: [&str; 9] =
    ["Read", "Search", "Change", "Send", "Import", "Register", "Unregister", "Upload", "Call"];

/// "a, b and c".
fn join_and<S: AsRef<str>>(v: &[S]) -> String {
    match v {
        [] => String::new(),
        [one] => one.as_ref().to_string(),
        [rest @ .., last] => {
            format!("{} and {}", rest.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(", "), last.as_ref())
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// `pinnedRecord` is "pinned record".
fn words(seg: &str) -> String {
    let mut out = String::new();
    for (i, ch) in seg.chars().enumerate() {
        if ch.is_ascii_uppercase() && i > 0 {
            out.push(' ');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// create, update, delete as one phrase.
fn repo_verb(actions: &[String], short: bool) -> String {
    let has = |a: &str| actions.iter().any(|x| x == a);
    if short && has("create") && has("update") && has("delete") {
        return "Change".into();
    }
    let v: Vec<&str> = [("create", "create"), ("update", "change"), ("delete", "delete")]
        .iter()
        .filter(|(a, _)| has(a))
        .map(|(_, w)| *w)
        .collect();
    capitalize(&join_and(&v))
}

/// The service a request goes to, as a phrase.
fn aud_phrase(aud: &str) -> String {
    if aud == "*" {
        return "to any service".into();
    }
    let did = aud.split('#').next().unwrap_or(aud);
    match did.strip_prefix("did:web:") {
        Some(h) => format!("through {}", h.replace("%3A", ":")),
        None => format!("through {did}"),
    }
}

/// Collections the row names: known ones by name, others from their NSID
/// below the row's namespace.
struct Names {
    /// Display groups (sub-namespace), each with its items, in order.
    groups: Vec<(String, Vec<String>)>,
    /// Known namespace, unknown name: counted.
    more: usize,
    /// All names known: no sub-namespace word in front of each group.
    known: bool,
}

fn name_list(collections: &[String], ns: &str) -> Names {
    if NAMED_NAMESPACES.contains(&ns) {
        let mut groups: Vec<(String, Vec<String>)> = Vec::new();
        let mut more = 0;
        let mut known: Vec<(usize, &str, &str)> = Vec::new();
        for c in collections {
            match KNOWN_COLLECTIONS.iter().position(|(n, _)| n == c) {
                Some(i) => known.push((i, c, KNOWN_COLLECTIONS[i].1)),
                None => more += 1,
            }
        }
        known.sort();
        for (_, c, name) in known {
            let sub = c.split('.').nth(2).unwrap_or("").to_string();
            match groups.last_mut() {
                Some((s, v)) if *s == sub => v.push(name.to_string()),
                _ => groups.push((sub, vec![name.to_string()])),
            }
        }
        return Names { groups, more, known: true };
    }
    let mut sorted: Vec<&String> = collections.iter().collect();
    sorted.sort();
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for c in sorted {
        let rel = c.strip_prefix(ns).and_then(|r| r.strip_prefix('.')).unwrap_or(c);
        let segs: Vec<&str> = rel.split('.').collect();
        let (sub, item) = match segs.as_slice() {
            [one] => (String::new(), words(one)),
            [first, rest @ ..] => (first.to_string(), rest.iter().map(|s| words(s)).collect::<Vec<_>>().join(" ")),
            [] => continue,
        };
        match groups.last_mut() {
            Some((s, v)) if !sub.is_empty() && *s == sub => v.push(item),
            _ => groups.push((sub, vec![item])),
        }
    }
    Names { groups, more: 0, known: false }
}

impl Names {
    fn count(&self) -> usize {
        self.groups.iter().map(|(_, v)| v.len()).sum::<usize>() + self.more
    }

    fn grouped(&self) -> bool {
        self.count() > 4 || (!self.known && self.groups.iter().any(|(s, _)| !s.is_empty()))
    }

    /// For an opened row: "Badge def, issuance · Key".
    fn objects(&self) -> String {
        let mut parts: Vec<String> = if self.grouped() {
            self.groups
                .iter()
                .map(|(sub, items)| {
                    let list = items.join(", ");
                    match (self.known, sub.is_empty()) {
                        (false, false) => capitalize(&format!("{} {list}", words(sub))),
                        _ => capitalize(&list),
                    }
                })
                .collect()
        } else {
            let all: Vec<String> = self.groups.iter().flat_map(|(_, v)| v.clone()).collect();
            vec![capitalize(&all.join(", "))]
        };
        if self.more > 0 {
            parts.push(format!("{} more", self.more));
        }
        parts.retain(|p| !p.is_empty());
        parts.join(" · ")
    }

    /// For a chip: "posts, follows".
    fn phrase_list(&self) -> String {
        self.groups.iter().flat_map(|(_, v)| v.clone()).collect::<Vec<_>>().join(", ")
    }

    /// For a summary: "posts and follows".
    fn phrase(&self) -> String {
        let all: Vec<String> = self.groups.iter().flat_map(|(_, v)| v.clone()).collect();
        join_and(&all)
    }
}

/// NSIDs for a line, in the order their names are listed: each when
/// there are few, else by sub-namespace.
fn code_for(nsids: &[String], ns: &str) -> String {
    let mut nsids = nsids.to_vec();
    nsids.sort_by_key(|n| (KNOWN_COLLECTIONS.iter().position(|(k, _)| k == n).unwrap_or(usize::MAX), n.clone()));
    if nsids.len() <= 4 {
        return nsids.join(" · ");
    }
    let mut subs: Vec<(String, usize, String)> = Vec::new();
    for n in &nsids {
        let rel = n.strip_prefix(ns).and_then(|r| r.strip_prefix('.'));
        let sub = match rel.map(|r| r.split('.').collect::<Vec<_>>()) {
            Some(segs) if segs.len() > 1 => format!("{ns}.{}", segs[0]),
            _ => n.clone(),
        };
        match subs.iter_mut().find(|(s, _, _)| *s == sub) {
            Some(e) => e.1 += 1,
            None => subs.push((sub, 1, n.clone())),
        }
    }
    if subs.len() > 4 && nsids.iter().all(|n| n.starts_with(&format!("{ns}."))) {
        return format!("{ns}.*");
    }
    subs.iter().map(|(s, k, one)| if *k > 1 { format!("{s}.*") } else { one.clone() }).collect::<Vec<_>>().join(" · ")
}

/// Collections and the actions on each, merged.
fn repo_actions(perms: &[&Permission]) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for p in perms {
        let Permission::Repo { collection, action } = p else { continue };
        for c in collection {
            match out.iter_mut().find(|(x, _)| x == c) {
                Some((_, a)) => {
                    for x in action {
                        if !a.contains(x) {
                            a.push(x.clone());
                        }
                    }
                }
                None => out.push((c.clone(), action.clone())),
            }
        }
    }
    for (_, a) in &mut out {
        a.sort_by_key(|x| ["create", "update", "delete"].iter().position(|o| o == x));
    }
    out
}

/// Methods by service, merged.
fn rpc_methods(perms: &[&Permission]) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for p in perms {
        let Permission::Rpc { aud, lxm } = p else { continue };
        let e = match out.iter_mut().position(|(a, _)| a == aud) {
            Some(i) => &mut out[i].1,
            None => {
                out.push((aud.clone(), Vec::new()));
                &mut out.last_mut().unwrap().1
            }
        };
        for l in lxm {
            if !e.contains(l) {
                e.push(l.clone());
            }
        }
    }
    out
}

/// More methods than this to one service are counted by area.
const MANY_METHODS: usize = 8;

fn repo_lines(perms: &[&Permission], ns: &str) -> Vec<Line> {
    let mut by_actions: Vec<(Vec<String>, Vec<String>)> = Vec::new();
    for (c, a) in repo_actions(perms) {
        match by_actions.iter_mut().find(|(x, _)| *x == a) {
            Some((_, cs)) => cs.push(c),
            None => by_actions.push((a, vec![c])),
        }
    }
    by_actions
        .into_iter()
        .map(|(actions, cols)| {
            if cols.iter().any(|c| c == "*") {
                return Line { verb: repo_verb(&actions, false), objects: "Any record type".into(), code: "*".into() };
            }
            let n = name_list(&cols, ns);
            let verb = repo_verb(&actions, false);
            Line {
                verb: if n.grouped() {
                    format!("{verb} · {}", plural(n.count(), "record type", "record types"))
                } else {
                    verb
                },
                objects: n.objects(),
                code: code_for(&cols, ns),
            }
        })
        .collect()
}

fn rpc_lines(perms: &[&Permission], ns: &str) -> Vec<Line> {
    let mut out = Vec::new();
    for (aud, lxms) in rpc_methods(perms) {
        let via = aud_phrase(&aud);
        if lxms.iter().any(|l| l == "*") {
            out.push(Line { verb: "Any request".into(), objects: capitalize(&via), code: "*".into() });
            continue;
        }
        if lxms.len() > MANY_METHODS {
            out.push(many_methods_line(&lxms, &via, ns));
            continue;
        }
        // object -> verbs, in first-seen order
        let mut objs: Vec<(String, Vec<&'static str>, Vec<String>)> = Vec::new();
        for l in &lxms {
            let (verb, obj) = match method(l) {
                Some((v, o)) => (v, o.to_string()),
                None => ("Call", words(l.rsplit('.').next().unwrap_or(l))),
            };
            match objs.iter_mut().find(|(o, _, _)| *o == obj) {
                Some((_, vs, ls)) => {
                    if !vs.contains(&verb) {
                        vs.push(verb);
                    }
                    ls.push(l.clone());
                }
                None => objs.push((obj, vec![verb], vec![l.clone()])),
            }
        }
        let mut lines: Vec<(Vec<&'static str>, Vec<String>, Vec<String>)> = Vec::new();
        for (obj, mut verbs, ls) in objs {
            verbs.sort_by_key(|v| VERB_ORDER.iter().position(|o| o == v));
            match lines.iter_mut().find(|(v, _, _)| *v == verbs) {
                Some((_, os, all)) => {
                    os.push(obj);
                    all.extend(ls);
                }
                None => lines.push((verbs, vec![obj], ls)),
            }
        }
        for (verbs, objs, ls) in lines {
            let verbs: Vec<String> =
                verbs.iter().enumerate().map(|(i, v)| if i == 0 { v.to_string() } else { v.to_lowercase() }).collect();
            out.push(Line {
                verb: format!("{} · {via}", join_and(&verbs)),
                objects: capitalize(&objs.join(", ")),
                code: ls.join(" · "),
            });
        }
    }
    out
}

/// Counts per area, sensitive methods named.
fn many_methods_line(lxms: &[String], via: &str, ns: &str) -> Line {
    let bsky = ns == "app.bsky";
    let mut areas: Vec<(String, usize, Option<&'static str>, String)> = Vec::new();
    let mut other = 0;
    for l in lxms {
        let sub = l
            .strip_prefix(ns)
            .and_then(|r| r.strip_prefix('.'))
            .and_then(|r| r.split('.').next())
            .filter(|_| l.split('.').count() > ns.split('.').count() + 1);
        let name = match (sub, bsky) {
            (Some(s), true) => match bsky_area(s) {
                Some(a) => a.to_string(),
                None => {
                    other += 1;
                    continue;
                }
            },
            (Some(s), false) => capitalize(&words(s)),
            (None, _) => {
                other += 1;
                continue;
            }
        };
        let prefix = format!("{ns}.{}", sub.unwrap_or(""));
        match areas.iter_mut().find(|(a, _, _, _)| *a == name) {
            Some(e) => {
                e.1 += 1;
                e.2 = e.2.or(sensitive(l));
            }
            None => areas.push((name, 1, sensitive(l), prefix)),
        }
    }
    areas.sort_by_key(|a| std::cmp::Reverse(a.1));
    let mut objects: Vec<String> = areas
        .iter()
        .map(|(a, n, s, _)| match s {
            Some(s) => format!("{a} {n}, {s}"),
            None => format!("{a} {n}"),
        })
        .collect();
    if other > 0 {
        objects.push(format!("Other {other}"));
    }
    let mut code: Vec<String> = areas.iter().take(6).map(|(_, _, _, p)| format!("{p}.*")).collect();
    if areas.len() > 6 || other > 0 {
        code.push("…".into());
    }
    Line {
        verb: format!("Requests {via} · {}", plural(lxms.len(), "method", "methods")),
        objects: objects.join(" · "),
        code: code.join(" · "),
    }
}

fn space_lines(perms: &[&Permission], names: &SpaceNames) -> Vec<Line> {
    perms
        .iter()
        .filter_map(|p| match p {
            Permission::Space(s) => {
                Some(Line { verb: String::new(), objects: describe_space(s, names), code: s.space_type.clone() })
            }
            _ => None,
        })
        .collect()
}

/// A row's summary line from all it grants.
fn summary_of(perms: &[&Permission], ns: &str, names: &SpaceNames) -> String {
    let mut parts: Vec<String> = Vec::new();
    let repo = repo_actions(perms);
    if repo.iter().any(|(c, _)| c == "*") {
        parts.push("Create, change and delete any record".into());
    } else {
        let mut by_actions: Vec<(Vec<String>, Vec<String>)> = Vec::new();
        for (c, a) in repo {
            match by_actions.iter_mut().find(|(x, _)| *x == a) {
                Some((_, cs)) => cs.push(c),
                None => by_actions.push((a, vec![c])),
            }
        }
        for (a, cols) in by_actions {
            let n = name_list(&cols, ns);
            parts.push(match n.more == 0 && n.count() <= 4 {
                true => format!("{} {}", repo_verb(&a, true), n.phrase()),
                false => format!("{} {}", repo_verb(&a, false), plural(n.count(), "record type", "record types")),
            });
        }
    }
    let rpc = rpc_methods(perms);
    let total: usize = {
        let mut all: Vec<&String> = rpc.iter().flat_map(|(_, l)| l).collect();
        all.sort();
        all.dedup();
        all.len()
    };
    if rpc.iter().any(|(_, l)| l.iter().any(|x| x == "*")) {
        for (aud, l) in &rpc {
            if l.iter().any(|x| x == "*") {
                parts.push(format!("Any request {}", aud_phrase(aud)));
            }
        }
    } else if total > MANY_METHODS {
        parts.push(plural(total, "kind of request", "kinds of request"));
    } else {
        for line in rpc_lines(perms, ns) {
            let (verbs, via) = line.verb.split_once(" · ").unwrap_or((&line.verb, ""));
            let tail = if via == "to any service" { " to any service" } else { "" };
            parts.push(format!("{verbs} {}{tail}", line.objects.to_lowercase()));
        }
    }
    for p in perms {
        if let Permission::Space(s) = p {
            parts.push(describe_space(s, names));
        }
    }
    capitalize(&parts.join(" · "))
}

fn line_tier(p: &Permission, own: bool) -> Tier {
    match p {
        Permission::Repo { collection, .. } if collection.iter().any(|c| c == "*") => Tier::Control,
        Permission::Repo { .. } if own => Tier::ThisApp,
        Permission::Repo { .. } => Tier::AsYou,
        Permission::Rpc { lxm, .. } if lxm.iter().any(|l| l == "*") => Tier::Control,
        Permission::Rpc { lxm, .. } if lxm.iter().any(|l| sensitive(l).is_some()) => Tier::AsYou,
        Permission::Rpc { aud, .. } if aud == "*" => Tier::AsYou,
        Permission::Rpc { .. } => Tier::ThisApp,
        Permission::Blob { accept } if accept.iter().any(|a| a == "*/*") => Tier::AsYou,
        Permission::Blob { .. } => Tier::ThisApp,
        Permission::Space(s) if space_warning(s).is_some() => Tier::Control,
        Permission::Space(_) => Tier::AsYou,
        Permission::Identity { .. } => Tier::Control,
        Permission::Account { action, .. } if action.iter().any(|a| a == "manage") => Tier::Control,
        Permission::Account { .. } => Tier::AsYou,
    }
}

/// Inline permissions less what the row's sets already grant.
fn not_covered(inline: &[Permission], set_perms: &[Permission]) -> Vec<Permission> {
    let mut out = Vec::new();
    for p in inline {
        match p {
            Permission::Repo { collection, action } => {
                for c in collection {
                    let left: Vec<String> =
                        action.iter().filter(|a| !set_perms.iter().any(|s| s.matches_repo(c, a))).cloned().collect();
                    if !left.is_empty() {
                        out.push(Permission::Repo { collection: vec![c.clone()], action: left });
                    }
                }
            }
            Permission::Rpc { aud, lxm } => {
                let left: Vec<String> =
                    lxm.iter().filter(|l| !set_perms.iter().any(|s| s.matches_rpc(l, aud))).cloned().collect();
                if !left.is_empty() {
                    out.push(Permission::Rpc { aud: aud.clone(), lxm: left });
                }
            }
            Permission::Space(sp) if set_perms.iter().any(|s| matches!(s, Permission::Space(x) if x == sp)) => {}
            other => out.push(other.clone()),
        }
    }
    out
}

/// Every permission line of a row (repo, rpc, space), in that order.
fn lines_for(perms: &[&Permission], ns: &str, names: &SpaceNames) -> Vec<Line> {
    let mut v = repo_lines(perms, ns);
    v.extend(rpc_lines(perms, ns));
    v.extend(space_lines(perms, names));
    v
}

struct Acc {
    kind: Kind,
    first: usize,
    scopes: Vec<String>,
    grants: Vec<String>,
    inline: Vec<Permission>,
    sets: Vec<(IncludeScope, Result<J, String>)>,
    transitions: Vec<String>,
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

/// The rows for a request: the fixed identity line first, then by tier
/// (account control, as you, this app).
pub fn rows(r: &Request) -> Vec<Row> {
    let empty = SpaceNames::default();
    let names = r.names.unwrap_or(&empty);
    let spaces = r.names.is_some();
    let scopes = scope_list(r.scope);
    let groups = set_groups(&scopes);
    let mut accs: Vec<Acc> = Vec::new();
    for (i, s) in scopes.iter().enumerate() {
        let inc = IncludeScope::parse(s);
        let set = inc.as_ref().map(|inc| {
            r.sets.iter().find(|(x, _)| x == inc).map(|(_, j)| j.clone()).unwrap_or_else(|| Err("not looked up".into()))
        });
        let kind = match (&inc, &set) {
            (Some(inc), Some(Err(_))) => Kind::Missing(inc.nsid.clone()),
            _ => scope_kind(s, &groups),
        };
        let acc = match accs.iter_mut().position(|a| a.kind == kind) {
            Some(j) => &mut accs[j],
            None => {
                accs.push(Acc {
                    kind,
                    first: i,
                    scopes: vec![],
                    grants: vec![],
                    inline: vec![],
                    sets: vec![],
                    transitions: vec![],
                });
                accs.last_mut().unwrap()
            }
        };
        acc.scopes.push(s.to_string());
        push_unique(&mut acc.grants, &grant_key_in(s, &groups));
        match (inc, set) {
            (Some(inc), Some(set)) => acc.sets.push((inc, set)),
            _ => match Permission::parse(s) {
                Some(p) => acc.inline.push(p),
                None => acc.transitions.push(s.to_string()),
            },
        }
    }
    let mut rows: Vec<Built> = accs
        .into_iter()
        .map(|a| {
            let own = matches!(&a.kind, Kind::Ns(ns) if owns(r.client_id, r.loopback, ns));
            let (kind, first) = (a.kind.clone(), a.first);
            let (row, space) = build(a, names, spaces, own);
            Built { kind, first, own, space, row }
        })
        .collect();
    rows.sort_by_key(|b| (b.kind != Kind::Identity, b.row.tier, b.kind.rank(b.own, b.row.tier), b.first));
    absorb(&mut rows);
    rows.into_iter().map(|b| b.row).collect()
}

struct Built {
    kind: Kind,
    first: usize,
    own: bool,
    /// Grants something in a space, which Full access doesn't cover.
    space: bool,
    row: Row,
}

/// Full access takes in the rows it already grants: their checkboxes would
/// change nothing while it's ticked.
fn absorb(rows: &mut Vec<Built>) {
    if !rows.iter().any(|b| b.kind == Kind::Generic) {
        return;
    }
    let mut taken: Vec<Row> = Vec::new();
    let mut i = 0;
    while i < rows.len() {
        let b = &rows[i];
        if b.kind.generic_covers() && !b.space && b.row.sets.iter().all(|s| !s.unavailable) {
            taken.push(rows.remove(i).row);
        } else {
            i += 1;
        }
    }
    let g = rows.iter().position(|b| b.kind == Kind::Generic).unwrap();
    let full = &mut rows[g].row;
    for t in taken {
        full.includes.push(t.label);
        for k in t.grants {
            push_unique(&mut full.grants, &k);
        }
        full.scopes.extend(t.scopes);
        full.sets.extend(t.sets);
    }
}

fn fixed_row(key: String, label: &str, tier: Tier, summary: String, lines: Vec<Line>) -> Row {
    Row {
        key,
        grants: vec![],
        label: label.to_string(),
        tier,
        chip: label.to_string(),
        summary,
        lines,
        not_in_set: vec![],
        sets: vec![],
        includes: vec![],
        scopes: vec![],
        fixed: false,
        checked: true,
        warnings: vec![],
    }
}

fn build(a: Acc, names: &SpaceNames, spaces: bool, own: bool) -> (Row, bool) {
    let key = a.kind.key();
    let has_t = |t: &str| a.transitions.iter().any(|x| x == t);
    let mut row = match &a.kind {
        Kind::Identity => {
            let mut row = fixed_row(key, "Sees your handle and DID", Tier::ThisApp, String::new(), vec![]);
            row.fixed = true;
            row
        }
        Kind::Handle => {
            let all = a.inline.iter().any(|p| matches!(p, Permission::Identity { attr } if attr == "*"));
            match all {
                true => fixed_row(
                    key,
                    "Your identity",
                    Tier::Control,
                    "Change your handle and DID document. Can break or take your account".into(),
                    vec![],
                ),
                false => fixed_row(key, "Your handle", Tier::Control, "Change your handle".into(), vec![]),
            }
        }
        Kind::Status | Kind::Import | Kind::Email => {
            let manage = a
                .inline
                .iter()
                .any(|p| matches!(p, Permission::Account { action, .. } if action.iter().any(|x| x == "manage")));
            let (label, read, change, object) = match a.kind {
                Kind::Status => (
                    "Account status",
                    "See whether your account is active",
                    "Deactivate and reactivate your account",
                    "Account status",
                ),
                Kind::Import => (
                    "Repository import",
                    "See your repository's import status",
                    "Import a repository into your account",
                    "Repository import",
                ),
                _ => ("Email", "Read your email address", "Read and change your email address", "Email address"),
            };
            match manage {
                true => fixed_row(key, label, Tier::Control, change.into(), vec![]),
                false => fixed_row(
                    key,
                    label,
                    Tier::AsYou,
                    read.into(),
                    vec![Line { verb: "Read".into(), objects: object.into(), code: a.scopes.join(" · ") }],
                ),
            }
        }
        Kind::Generic => fixed_row(
            key,
            "Full access",
            Tier::Control,
            "Create, change and delete any record · Upload any file · Requests to any service except private messages"
                .into(),
            vec![],
        ),
        Kind::Messages => {
            let mut parts: Vec<String> = Vec::new();
            if has_t("transition:chat.bsky") {
                parts.push("Read and send Bluesky private messages · Needs Full access".into());
            }
            for (aud, lxm) in rpc_methods(&a.inline.iter().collect::<Vec<_>>()) {
                let via = if aud == "did:web:api.bsky.chat#bsky_chat" {
                    String::new()
                } else {
                    format!(" {}", aud_phrase(&aud))
                };
                let n = plural(lxm.len(), "kind of request", "kinds of request");
                parts.push(format!("Private messages{via}: {n}"));
            }
            let mut row = fixed_row(key, "Private messages", Tier::Control, parts.join(" · "), vec![]);
            row.lines = rpc_lines(&a.inline.iter().collect::<Vec<_>>(), "chat.bsky");
            row
        }
        Kind::Uploads => {
            let mut accept: Vec<String> = Vec::new();
            for p in &a.inline {
                if let Permission::Blob { accept: acc } = p {
                    for x in acc {
                        push_unique(&mut accept, x);
                    }
                }
            }
            let any = accept.iter().any(|x| x == "*/*");
            let kinds: Vec<String> = if any {
                vec!["any file type".into()]
            } else {
                accept
                    .iter()
                    .map(|x| match x.as_str() {
                        "image/*" => "images".to_string(),
                        "video/*" => "video".to_string(),
                        "audio/*" => "audio".to_string(),
                        other => other.to_string(),
                    })
                    .collect()
            };
            let what = capitalize(&kinds.join(", "));
            let mut row = fixed_row(
                key,
                "Uploads",
                if any { Tier::AsYou } else { Tier::ThisApp },
                what.clone(),
                vec![Line {
                    verb: "Upload".into(),
                    objects: what,
                    code: if any {
                        "blob:*/*".into()
                    } else {
                        accept.iter().map(|a| format!("blob:{a}")).collect::<Vec<_>>().join(" · ")
                    },
                }],
            );
            row.chip = format!("Uploads: {}", if any { "any file".to_string() } else { kinds.join(", ") });
            row
        }
        Kind::Missing(nsid) => {
            let mut row = fixed_row(key.clone(), nsid, Tier::AsYou, "Contents unavailable".into(), vec![]);
            row.checked = false;
            row.sets = a.sets.iter().map(|(inc, _)| set_info(inc, None, spaces)).collect();
            row
        }
        Kind::Other => fixed_row(key, "Other", Tier::AsYou, a.scopes.join(" · "), vec![]),
        Kind::AnyApp | Kind::AnyRequest | Kind::Several | Kind::Ns(_) | Kind::Space(_) => {
            return permission_row(a, names, spaces, own);
        }
    };
    row.scopes = a.scopes;
    row.grants = a.grants;
    (row, false)
}

fn set_info(inc: &IncludeScope, set: Option<&J>, spaces: bool) -> SetInfo {
    let str_of = |k: &str| set.and_then(|j| j.get(k)).and_then(|t| t.as_str()).map(String::from);
    let ignored = set.map_or(0, |j| {
        let n = j.get("permissions").and_then(|p| p.as_array()).map_or(0, |a| a.len());
        n.saturating_sub(inc.to_permissions(j, spaces).len())
    });
    SetInfo {
        nsid: inc.nsid.clone(),
        title: str_of("title"),
        detail: str_of("detail"),
        publisher: super::lexicon::nsid_authority(&inc.nsid),
        group: set_group(&inc.nsid),
        ignored,
        unavailable: set.is_none(),
    }
}

/// A row of repo, rpc and space permissions: an app's namespace, any app,
/// several apps, or a space type.
fn permission_row(a: Acc, names: &SpaceNames, spaces: bool, own: bool) -> (Row, bool) {
    let ns = match &a.kind {
        Kind::Ns(n) => n.clone(),
        _ => String::new(),
    };
    let mut set_perms: Vec<Permission> = Vec::new();
    let mut sets: Vec<SetInfo> = Vec::new();
    for (inc, set) in &a.sets {
        let j = set.as_ref().ok();
        if let Some(j) = j {
            set_perms.extend(inc.to_permissions(j, spaces));
        }
        sets.push(set_info(inc, j, spaces));
    }
    let all: Vec<&Permission> = set_perms.iter().chain(&a.inline).collect();
    let (lines, not_in_set) = if a.sets.is_empty() {
        (lines_for(&a.inline.iter().collect::<Vec<_>>(), &ns, names), vec![])
    } else {
        let extra = not_covered(&a.inline, &set_perms);
        (
            lines_for(&set_perms.iter().collect::<Vec<_>>(), &ns, names),
            lines_for(&extra.iter().collect::<Vec<_>>(), &ns, names),
        )
    };
    let tier = all.iter().map(|p| line_tier(p, own)).min().unwrap_or(Tier::ThisApp);
    let label = match &a.kind {
        Kind::Ns(n) => ns_label(n),
        Kind::AnyApp => "Every app's records".into(),
        Kind::AnyRequest => {
            let auds: Vec<String> = rpc_methods(&all).into_iter().map(|(aud, _)| aud).collect();
            match auds.as_slice() {
                [one] => format!("Any request {}", aud_phrase(one)),
                _ => "Any request".into(),
            }
        }
        Kind::Several => "Several apps".into(),
        Kind::Space(t) if t == "*" => "Every space".into(),
        Kind::Space(t) => names.decls.get(t).map(|d| format!("{} spaces", d.name)).unwrap_or_else(|| t.clone()),
        _ => String::new(),
    };
    let mut warnings: Vec<String> = Vec::new();
    if spaces {
        for p in &all {
            if let Permission::Space(s) = p {
                let s = match names.decls.get(&s.space_type) {
                    Some(d) if s.space_type != "*" => s.clone().with_default_collections(&d.collections),
                    _ => s.clone(),
                };
                if let Some(w) = space_warning(&s) {
                    push_unique(&mut warnings, w);
                }
            }
        }
    }
    let summary = if all.is_empty() { "Grants nothing".to_string() } else { summary_of(&all, &ns, names) };
    let only_repo = !all.is_empty() && all.iter().all(|p| matches!(p, Permission::Repo { .. }));
    let chip = match (&a.kind, only_repo) {
        (Kind::Ns(_), true) => {
            let cols = repo_actions(&all);
            let n = names_of(&cols, &ns);
            if n.count() <= 3 && n.more == 0 {
                format!("{label}: {}", n.phrase_list())
            } else {
                format!("{label}: {}", plural(n.count(), "record type", "record types"))
            }
        }
        _ => label.clone(),
    };
    let space = all.iter().any(|p| matches!(p, Permission::Space(_)));
    let row = Row {
        key: a.kind.key(),
        grants: a.grants,
        label,
        tier,
        summary,
        chip,
        lines,
        not_in_set,
        sets,
        includes: vec![],
        scopes: a.scopes,
        fixed: all.is_empty() && a.inline.is_empty(),
        checked: true,
        warnings,
    };
    (row, space)
}

fn names_of(cols: &[(String, Vec<String>)], ns: &str) -> Names {
    name_list(&cols.iter().map(|(c, _)| c.clone()).collect::<Vec<_>>(), ns)
}

/// Reference consent `SpaceRow`: the declaration's name for the type, the
/// authority's verified handle (else its DID), and a bare grant's writes as
/// its declaration's collections, which is what the token will carry.
pub fn describe_space(p: &SpacePermission, names: &SpaceNames) -> String {
    let decl = names.decls.get(&p.space_type);
    let p = match decl {
        Some(d) if p.space_type != "*" => p.clone().with_default_collections(&d.collections),
        _ => p.clone(),
    };
    let owner = match p.authority.as_str() {
        "self" => "your account".to_string(),
        did => names.handles.get(did).map(|h| format!("@{h}")).unwrap_or_else(|| did.to_string()),
    };
    let kind = decl.map(|d| d.name.clone()).unwrap_or_else(|| p.space_type.clone());
    let what = match (p.space_type.as_str(), p.authority.as_str()) {
        ("*", "*") => "All spaces on the network".to_string(),
        ("*", _) => format!("All spaces on {owner}"),
        (_, "*") => format!("{kind} spaces"),
        _ => format!("{kind} spaces on {owner}"),
    };
    let mut parts: Vec<String> = Vec::new();
    if p.action.iter().any(|a| a == "read") {
        parts.push("read what members share with you".into());
    } else if p.action.iter().any(|a| a == "read_self") {
        parts.push("read your own space repos".into());
    }
    let verbs: Vec<&str> =
        p.action.iter().map(String::as_str).filter(|a| ["create", "update", "delete"].contains(a)).collect();
    let write = match verbs.len() {
        3 => "write".to_string(),
        _ => join_and(&verbs),
    };
    if let Some(c) = p.collection.as_ref().filter(|_| !verbs.is_empty()) {
        let colls = match c.iter().any(|c| c == "*") {
            true => "any collection".to_string(),
            false => join_and(&c.iter().map(String::as_str).collect::<Vec<_>>()),
        };
        parts.push(format!("{write} records in {colls}"));
    }
    // the token request fails rather than guess at what was meant
    let unresolved =
        (p.collection.is_none() && !verbs.is_empty() && decl.is_none() && p.space_type != "*").then(|| {
            format!(
                "{write} records in the collections {} declares, which could not be looked up, so approving this will fail",
                p.space_type
            )
        });
    if let Some(m) = p.manage.as_ref().filter(|m| !m.is_empty()) {
        let ops: Vec<&str> = m
            .iter()
            .map(|op| match op.as_str() {
                "create" => "create",
                "update" => "change",
                _ => "delete",
            })
            .collect();
        let members = if m.iter().any(|op| op == "update") { " and their members" } else { "" };
        parts.push(format!("{} spaces{members}", join_and(&ops)));
    }
    match (parts.is_empty(), unresolved) {
        (true, None) => format!("{what}: no access"),
        (true, Some(u)) => format!("{what}: {u}"),
        (false, None) => format!("{what}: {}", join_and(&parts)),
        (false, Some(u)) => format!("{what}: {}. It also asks to {u}", join_and(&parts)),
    }
}

/// The set notes an opened row shows: who published it, and that it can grow.
pub fn set_note(s: &SetInfo) -> String {
    match s.unavailable {
        true => format!("Set published by {}. Its contents couldn't be loaded, so it's unticked.", s.publisher),
        false => format!("Set published by {}. Can add {} permissions later.", s.publisher, s.group),
    }
}

/// The raw scopes under "Requested scopes", grouped by row, the identity
/// row last.
pub fn raw_groups(rows: &[Row]) -> Vec<(String, Vec<String>, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    let mut identity = None;
    for r in rows {
        let notes: Vec<String> = r
            .sets
            .iter()
            .filter(|s| s.ignored > 0)
            .map(|s| {
                format!(
                    "{} in {} {} ignored",
                    plural(s.ignored, "entry", "entries"),
                    s.nsid,
                    if s.ignored == 1 { "is" } else { "are" }
                )
            })
            .collect();
        let g = (if r.key == IDENTITY { "Who you are".into() } else { r.label.clone() }, r.scopes.clone(), notes);
        match r.key == IDENTITY {
            true => identity = Some(g),
            false => out.push(g),
        }
    }
    out.extend(identity);
    out
}

#[cfg(test)]
mod tests;
