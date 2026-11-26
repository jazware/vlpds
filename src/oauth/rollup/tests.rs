//! The rows for real apps' requests (testdata/oauth: their client metadata
//! and permission sets as published).

use super::*;
use serde_json::json;

const STREAMPLACE: &str = include_str!("../../../testdata/oauth/clients/stream.place.json");
const GRAYSKY: &str = include_str!("../../../testdata/oauth/clients/graysky.app.json");
const BLACKSKY: &str = include_str!("../../../testdata/oauth/clients/blacksky.community.json");
const TOKIMEKI: &str = include_str!("../../../testdata/oauth/clients/poll.tokimeki.tech.json");
const SETS: [(&str, &str); 3] = [
    ("place.stream.authFull", include_str!("../../../testdata/oauth/lexicons/place.stream.authFull.json")),
    ("app.bsky.authFullApp", include_str!("../../../testdata/oauth/lexicons/app.bsky.authFullApp.json")),
    ("tech.tokimeki.poll.authFull", include_str!("../../../testdata/oauth/lexicons/tech.tokimeki.poll.authFull.json")),
];
/// TOKIMEKI Poll's granted scope as a session holds it: its metadata also
/// asks for transition:generic.
const TOKIMEKI_GRANTED: &str =
    "atproto repo:app.bsky.feed.post?action=create blob:image/* include:tech.tokimeki.poll.authFull";

struct App {
    client_id: String,
    scope: String,
}

fn app(metadata: &str) -> App {
    let m: J = serde_json::from_str(metadata).unwrap();
    App { client_id: m["client_id"].as_str().unwrap().into(), scope: m["scope"].as_str().unwrap().into() }
}

fn set_doc(nsid: &str) -> Option<J> {
    let (_, doc) = SETS.iter().find(|(n, _)| *n == nsid)?;
    let doc: J = serde_json::from_str(doc).unwrap();
    Some(doc["defs"]["main"].clone())
}

/// Each include: scope's set from the fixtures; `missing` ones fail.
fn sets(scope: &str, missing: &[&str]) -> Vec<(IncludeScope, Result<J, String>)> {
    scope
        .split(' ')
        .filter_map(IncludeScope::parse)
        .map(|inc| {
            let set = match missing.contains(&inc.nsid.as_str()) {
                true => Err("unreachable".to_string()),
                false => set_doc(&inc.nsid).ok_or_else(|| "no fixture".to_string()),
            };
            (inc, set)
        })
        .collect()
}

fn rows_for(client_id: &str, scope: &str, missing: &[&str]) -> Vec<Row> {
    let sets = sets(scope, missing);
    rows(&Request { scope, sets: &sets, client_id, loopback: false, names: None })
}

fn labels(rows: &[Row]) -> Vec<&str> {
    rows.iter().map(|r| r.label.as_str()).collect()
}

fn row<'a>(rows: &'a [Row], label: &str) -> &'a Row {
    rows.iter().find(|r| r.label == label).unwrap_or_else(|| panic!("no row {label}: {:?}", labels(rows)))
}

fn checkboxes(rows: &[Row]) -> usize {
    rows.iter().filter(|r| !r.fixed).count()
}

/// Every requested scope is in exactly one row.
fn assert_partition(scope: &str, rows: &[Row]) {
    let mut held: Vec<&str> = rows.iter().flat_map(|r| r.scopes.iter().map(String::as_str)).collect();
    held.sort();
    let mut want = scope_list(scope);
    want.sort();
    assert_eq!(held, want);
}

#[test]
fn streamplace_is_four_rows_and_the_identity_line() {
    let a = app(STREAMPLACE);
    let rows = rows_for(&a.client_id, &a.scope, &[]);
    assert_eq!(scope_list(&a.scope).len(), 42);
    assert_eq!(labels(&rows), ["Sees your handle and DID", "Bluesky", "Reports", "Uploads", "stream.place"]);
    assert_partition(&a.scope, &rows);
    assert!(rows[0].fixed && rows[0].grants == ["identity"]);
    assert_eq!(checkboxes(&rows), 4);

    let bsky = row(&rows, "Bluesky");
    assert_eq!(bsky.tier, Tier::AsYou);
    assert_eq!(bsky.summary, "Create posts · Change follows, blocks, profile and status · Read profiles");
    assert_eq!(
        bsky.lines[0],
        Line { verb: "Create".into(), objects: "Posts".into(), code: "app.bsky.feed.post".into() }
    );
    assert_eq!(bsky.lines[2].verb, "Read · through api.bsky.app");
    assert_eq!(bsky.chip, "Bluesky");
    let reports = row(&rows, "Reports");
    assert_eq!((reports.tier, reports.summary.as_str()), (Tier::AsYou, "Send reports to any service"));
    let uploads = row(&rows, "Uploads");
    assert_eq!(
        (uploads.tier, uploads.summary.as_str(), uploads.chip.as_str()),
        (Tier::AsYou, "Any file type", "Uploads: any file")
    );

    let sp = row(&rows, "stream.place");
    assert_eq!(sp.tier, Tier::ThisApp, "its own namespace");
    assert_eq!(sp.summary, "Create, change and delete 31 record types");
    assert_eq!(sp.chip, "stream.place: 31 record types");
    assert_eq!(sp.scopes.len(), 32, "the set and all 31 inline scopes");
    assert_eq!(sp.grants, ["set:place.stream.authFull", "ns:place.stream"]);
    assert_eq!(sp.sets.len(), 1);
    assert_eq!(sp.sets[0].title.as_deref(), Some("Full Streamplace Access"));
    assert_eq!(sp.sets[0].publisher, "stream.place");
    assert_eq!(sp.lines.len(), 1);
    assert_eq!(sp.lines[0].verb, "Create, change and delete · 28 record types");
    assert!(
        sp.lines[0].objects.starts_with("Badge def, issuance · Beta invite, request · "),
        "{}",
        sp.lines[0].objects
    );
    assert!(sp.lines[0].objects.ends_with(" · Video · Vod comment, draft video, gate"), "{}", sp.lines[0].objects);
    assert_eq!(sp.lines[0].code, "place.stream.*");
    assert_eq!(
        sp.not_in_set,
        [Line {
            verb: "Create, change and delete · 3 record types".into(),
            objects: "Chat access · Ingest audio rendition, video rendition".into(),
            code: "place.stream.chat.access · place.stream.ingest.audioRendition · place.stream.ingest.videoRendition"
                .into(),
        }]
    );
}

#[test]
fn graysky_folds_its_extras_into_the_bluesky_row() {
    let a = app(GRAYSKY);
    let rows = rows_for(&a.client_id, &a.scope, &[]);
    assert_partition(&a.scope, &rows);
    assert_eq!(labels(&rows), ["Sees your handle and DID", "Your handle", "Bluesky", "Reports", "Email", "Uploads"]);
    assert_eq!(row(&rows, "Your handle").tier, Tier::Control);
    let bsky = row(&rows, "Bluesky");
    assert_eq!(bsky.tier, Tier::AsYou);
    assert_eq!(bsky.summary, "Create, change and delete 18 record types · 113 kinds of request");
    assert_eq!(bsky.sets[0].title.as_deref(), Some("Full Bluesky Social App Permissions"));
    assert_eq!(bsky.sets[0].publisher, "bsky.app");
    assert_eq!(bsky.lines[0].verb, "Create, change and delete · 18 record types");
    assert!(bsky.lines[0].objects.ends_with(" · 3 more"), "{}", bsky.lines[0].objects);
    assert_eq!(bsky.lines[1].verb, "Requests through api.bsky.app · 113 methods");
    assert!(
        bsky.lines[1].objects.contains("Contacts 7, including importing your contacts"),
        "{}",
        bsky.lines[1].objects
    );
    assert!(bsky.lines[1].objects.ends_with("Other 27"), "{}", bsky.lines[1].objects);
    // the set grants prefs only through the AppView, push registration not at all
    assert_eq!(
        bsky.not_in_set,
        [
            Line {
                verb: "Read and change · to any service".into(),
                objects: "Preferences".into(),
                code: "app.bsky.actor.getPreferences · app.bsky.actor.putPreferences".into()
            },
            Line {
                verb: "Register · through graysky.app".into(),
                objects: "Push notifications".into(),
                code: "app.bsky.notification.registerPush".into()
            },
        ]
    );
    let email = row(&rows, "Email");
    assert_eq!((email.tier, email.summary.as_str()), (Tier::AsYou, "Read your email address"));
    let up = row(&rows, "Uploads");
    assert_eq!((up.tier, up.summary.as_str(), up.chip.as_str()), (Tier::ThisApp, "Images", "Uploads: images"));
}

#[test]
fn blacksky_is_all_account_control_with_email_merged() {
    let a = app(BLACKSKY);
    let rows = rows_for(&a.client_id, &a.scope, &[]);
    assert_partition(&a.scope, &rows);
    assert_eq!(
        labels(&rows),
        ["Sees your handle and DID", "Your handle", "Account status", "Email", "Full access", "Private messages"]
    );
    assert!(rows[1..].iter().all(|r| r.tier == Tier::Control), "{rows:?}");
    let email = row(&rows, "Email");
    assert_eq!(email.scopes, ["transition:email", "account:email?action=manage"]);
    assert_eq!(email.summary, "Read and change your email address");
    assert_eq!(row(&rows, "Private messages").summary, "Read and send Bluesky private messages · Needs Full access");
    assert!(row(&rows, "Full access").includes.is_empty());
}

#[test]
fn tokimeki_poll_as_granted_and_as_asked() {
    let a = app(TOKIMEKI);
    let rows = rows_for(&a.client_id, TOKIMEKI_GRANTED, &[]);
    assert_partition(TOKIMEKI_GRANTED, &rows);
    assert_eq!(labels(&rows), ["Sees your handle and DID", "Bluesky", "Uploads", "poll.tokimeki.tech"]);
    assert_eq!(row(&rows, "Bluesky").chip, "Bluesky: posts");
    let poll = row(&rows, "poll.tokimeki.tech");
    assert_eq!(poll.tier, Tier::ThisApp);
    assert_eq!(poll.summary, "Create and delete poll and vote");
    assert_eq!(poll.chip, "poll.tokimeki.tech: poll, vote");
    assert_eq!(poll.sets[0].title.as_deref(), Some("TOKIMEKI Poll"));
    assert_eq!(
        poll.lines,
        [Line {
            verb: "Create and delete".into(),
            objects: "Poll, vote".into(),
            code: "tech.tokimeki.poll.poll · tech.tokimeki.poll.vote".into()
        }]
    );

    // its metadata also asks for transition:generic, which already grants
    // all three: they fold into Full access
    let rows = rows_for(&a.client_id, &a.scope, &[]);
    assert_partition(&a.scope, &rows);
    assert_eq!(labels(&rows), ["Sees your handle and DID", "Full access"]);
    let full = row(&rows, "Full access");
    assert_eq!(full.includes, ["Bluesky", "Uploads", "poll.tokimeki.tech"]);
    assert_eq!(full.grants, ["generic", "ns:app.bsky", "uploads", "set:tech.tokimeki.poll.authFull"]);
}

#[test]
fn generic_absorbs_only_what_it_covers() {
    let scope = "atproto transition:generic repo:app.bsky.feed.post blob:image/* rpc:chat.bsky.convo.getLog?aud=did:web:api.bsky.chat%23bsky_chat account:email identity:handle";
    let rows = rows_for("https://app.example/m.json", scope, &[]);
    assert_partition(scope, &rows);
    assert_eq!(labels(&rows), ["Sees your handle and DID", "Your handle", "Full access", "Private messages", "Email"]);
    assert_eq!(row(&rows, "Full access").includes, ["Bluesky", "Uploads"]);
    // a set that couldn't be read isn't folded in: nothing says what it grants
    let scope = "atproto transition:generic include:place.stream.authFull";
    let rows = rows_for("https://stream.place/m.json", scope, &["place.stream.authFull"]);
    assert_eq!(labels(&rows), ["Sees your handle and DID", "Full access", "place.stream.authFull"]);
}

#[test]
fn own_namespace_by_the_public_suffix_list() {
    assert!(owns("https://stream.place/oauth/upstream/client-metadata.json", false, "place.stream"));
    assert!(owns("https://poll.tokimeki.tech/oauth/client-metadata.json", false, "tech.tokimeki.poll"));
    assert!(owns("https://poll.tokimeki.tech/oauth/client-metadata.json", false, "tech.tokimeki"));
    assert!(!owns("https://graysky.app/oauth-client-metadata.json", false, "app.bsky"));
    // a shared suffix: x.github.io owns its own name, not io.github
    assert!(!owns("https://x.github.io/client.json", false, "io.github"));
    assert!(owns("https://x.github.io/client.json", false, "io.github.x"));
    assert!(!owns("https://y.github.io/client.json", false, "io.github.x"));
    assert!(!owns("http://localhost", true, "localhost.x"));
    assert!(!owns("http://localhost?scope=atproto", true, "place.stream"));
    let rows = rows(&Request {
        scope: "atproto repo:place.stream.video",
        sets: &[],
        client_id: "http://localhost",
        loopback: true,
        names: None,
    });
    assert_eq!(row(&rows, "stream.place").tier, Tier::AsYou, "a loopback client owns nothing");
}

#[test]
fn ignored_set_entries_are_counted() {
    let set = json!({"type": "permission-set", "title": "T", "permissions": [
        {"type": "permission", "resource": "repo", "collection": ["com.example.app.thing"]},
        {"type": "permission", "resource": "repo", "collection": ["app.bsky.feed.post"]},
        {"type": "permission", "resource": "blob", "accept": ["*/*"]},
        {"type": "permission", "resource": "rpc", "lxm": ["com.example.app.get"], "aud": "did:web:x.example#y"},
    ]});
    let scope = "atproto include:com.example.app.auth";
    let sets = vec![(IncludeScope::parse("include:com.example.app.auth").unwrap(), Ok(set))];
    let rows = rows(&Request {
        scope,
        sets: &sets,
        client_id: "https://app.example.com/m.json",
        loopback: false,
        names: None,
    });
    let r = row(&rows, "app.example.com");
    assert_eq!(r.sets[0].ignored, 3);
    assert_eq!(r.tier, Tier::ThisApp);
    let raw = raw_groups(&rows);
    assert_eq!(raw[0].2, ["3 entries in com.example.app.auth are ignored"]);
}

#[test]
fn a_set_that_grants_nothing_has_no_checkbox() {
    let set = json!({"type": "permission-set", "title": "Nothing", "permissions": []});
    let scope = "atproto include:com.example.app.auth";
    let sets = vec![(IncludeScope::parse("include:com.example.app.auth").unwrap(), Ok(set))];
    let rows = rows(&Request {
        scope,
        sets: &sets,
        client_id: "https://app.example.com/m.json",
        loopback: false,
        names: None,
    });
    let r = row(&rows, "app.example.com");
    assert!(r.fixed);
    assert_eq!(r.summary, "Grants nothing");
    assert_eq!(granted_scope(scope, &["identity".into(), "set:com.example.app.auth".into()]).as_deref(), Some(scope));
}

/// One set that can't be read gets its own row, unticked; the others are
/// shown as usual.
#[test]
fn a_set_that_fails_is_its_own_unticked_row() {
    let scope = "atproto include:place.stream.authFull include:app.bsky.authFullApp?aud=did:web:api.bsky.app%23bsky_appview repo:app.bsky.feed.post";
    let rows = rows_for("https://stream.place/m.json", scope, &["app.bsky.authFullApp"]);
    assert_partition(scope, &rows);
    assert_eq!(labels(&rows), ["Sees your handle and DID", "app.bsky.authFullApp", "Bluesky", "stream.place"]);
    let failed = row(&rows, "app.bsky.authFullApp");
    assert_eq!((failed.tier, failed.summary.as_str(), failed.checked), (Tier::AsYou, "Contents unavailable", false));
    assert_eq!(failed.grants, ["set:app.bsky.authFullApp"]);
    assert!(failed.sets[0].unavailable);
    assert_eq!(row(&rows, "stream.place").sets[0].title.as_deref(), Some("Full Streamplace Access"));
    assert_eq!(row(&rows, "Bluesky").scopes, ["repo:app.bsky.feed.post"]);
    // the grant keys don't depend on the lookup
    let all: Vec<String> = rows.iter().flat_map(|r| r.grants.clone()).collect();
    let ok = rows_for("https://stream.place/m.json", scope, &[]);
    let mut ok_keys: Vec<String> = ok.iter().flat_map(|r| r.grants.clone()).collect();
    let mut all = all;
    all.sort();
    ok_keys.sort();
    assert_eq!(all, ok_keys);
}

/// What the browser posts with every box but `skip` ticked.
fn ticked_without(rows: &[Row], skip: Option<&str>) -> Vec<String> {
    rows.iter().filter(|r| Some(r.key.as_str()) != skip).flat_map(|r| r.grants.clone()).collect()
}

/// Unticking any one row grants exactly the request less that row's scopes.
#[test]
fn unticking_a_row_drops_exactly_its_scopes() {
    let cases = [
        (app(STREAMPLACE).client_id, app(STREAMPLACE).scope),
        (app(GRAYSKY).client_id, app(GRAYSKY).scope),
        (app(BLACKSKY).client_id, app(BLACKSKY).scope),
        (app(TOKIMEKI).client_id, app(TOKIMEKI).scope),
        (app(TOKIMEKI).client_id, TOKIMEKI_GRANTED.to_string()),
    ];
    for (client_id, scope) in cases {
        let rows = rows_for(&client_id, &scope, &[]);
        assert_eq!(
            granted_scope(&scope, &ticked_without(&rows, None)).as_deref(),
            Some(scope_list(&scope).join(" ").as_str())
        );
        for r in rows.iter().filter(|r| !r.fixed) {
            let granted = granted_scope(&scope, &ticked_without(&rows, Some(&r.key))).unwrap();
            let mut want: Vec<&str> =
                scope_list(&scope).into_iter().filter(|s| !r.scopes.iter().any(|x| x == s)).collect();
            if r.key == "generic" {
                want.retain(|s| *s != "transition:chat.bsky");
            }
            assert_eq!(granted, want.join(" "), "{client_id}: unticking {}", r.label);
        }
        assert_eq!(granted_scope(&scope, &ticked_without(&rows, Some("identity"))), None, "{client_id}");
    }
}

#[test]
fn a_forged_post_only_removes() {
    let a = app(STREAMPLACE);
    let forged: Vec<String> = ["identity", "ns:place.stream", "transition:generic", "repo:*", "ns:com.evil", "generic"]
        .map(String::from)
        .to_vec();
    let granted = granted_scope(&a.scope, &forged).unwrap();
    // the 31 inline place.stream scopes; the set needs its own key
    assert_eq!(granted.split(' ').count(), 32);
    assert!(granted.split(' ').all(|s| s == "atproto" || s.starts_with("repo?collection=place.stream.")), "{granted}");
}

#[test]
fn chat_goes_with_generic() {
    let scope = "atproto transition:generic transition:chat.bsky transition:email";
    let g = |keys: &[&str]| granted_scope(scope, &keys.iter().map(|k| k.to_string()).collect::<Vec<_>>());
    assert_eq!(g(&["identity", "generic", "messages", "email"]).as_deref(), Some(scope));
    assert_eq!(g(&["identity", "messages", "email"]).as_deref(), Some("atproto transition:email"));
    assert_eq!(g(&["identity", "generic"]).as_deref(), Some("atproto transition:generic"));
}

#[test]
fn the_rows_serialize_for_the_account_page() {
    let a = app(TOKIMEKI);
    let rows = rows_for(&a.client_id, TOKIMEKI_GRANTED, &[]);
    let j = serde_json::to_value(&rows).unwrap();
    assert_eq!(j[3]["label"], "poll.tokimeki.tech");
    assert_eq!(j[3]["tier"], "thisApp");
    assert_eq!(j[1]["tier"], "asYou");
    assert_eq!(j[3]["sets"][0]["title"], "TOKIMEKI Poll");
    assert_eq!(j[3]["notInSet"], json!([]));
    assert!(j[3].get("grants").is_none());
}

/// `VLPDS_ROLLUP_DUMP=<dir>` writes each fixture's consent page (for
/// `npm run consent-shots`) and their rows as listSessions would return
/// them (`oauth-sessions.json`, ui/dev/mock.mjs's).
#[test]
fn dump_rows() {
    let Ok(dir) = std::env::var("VLPDS_ROLLUP_DUMP") else { return };
    let mut sessions = Vec::new();
    for (name, client_id, scope) in [
        ("stream.place", app(STREAMPLACE).client_id, app(STREAMPLACE).scope),
        ("poll.tokimeki.tech", app(TOKIMEKI).client_id, TOKIMEKI_GRANTED.to_string()),
        ("blacksky.community", app(BLACKSKY).client_id, app(BLACKSKY).scope),
        ("graysky.app", app(GRAYSKY).client_id, app(GRAYSKY).scope),
    ] {
        let rows = rows_for(&client_id, &scope, &[]);
        sessions.push(
            json!({"clientId": client_id, "name": client_label(&client_id, false), "scope": scope, "rows": rows}),
        );
        let ctx = crate::oauth::ui::Ctx {
            request_uri: "urn:ietf:params:oauth:request_uri:req-x",
            csrf: "c",
            client_id: &client_id,
            loopback: false,
            server_name: "vlpds",
        };
        let html = crate::oauth::ui::consent(&Default::default(), &ctx, "did:plc:abc", "alice.example.com", &rows);
        std::fs::write(format!("{dir}/{name}.html"), html).unwrap();
    }
    let j = serde_json::to_string_pretty(&sessions).unwrap() + "\n";
    std::fs::write(format!("{dir}/oauth-sessions.json"), j).unwrap();
}
