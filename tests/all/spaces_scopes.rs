//! `space:` OAuth scopes end to end (`--spaces`; src/oauth/scopes.rs,
//! src/oauth/lexicon.rs, src/oauth/ui.rs, src/xrpc/authn.rs): grants made
//! concrete when the token is issued (a bare grant takes the collections
//! its type declared at consent and never more, one that didn't resolve
//! fails the token request, `self` becomes the account, `include:` sets
//! carry space permissions), collections and actions enforced on writes,
//! read vs read_self, the consent screen's names and warning, and the
//! Spaces rate-limit buckets.

use crate::common::spaces::{resp, SpaceClient};
use crate::common::*;
use crate::oauth::{self, Browser, DpopKey, Flow, Srv};

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

fn srv(s: &TestServer) -> Srv {
    Srv {
        app: s.app.clone(),
        base: s.url.clone(),
        http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
    }
}

/// Publishes `doc` as `nsid`'s lexicon from a new account and pins the
/// NSID authority's DNS lookup to it. Each test uses its own authority:
/// the pin is process-wide.
async fn publish(s: &TestServer, nsid: &str, main: J) {
    let publisher = s.create_account("lexpub").await;
    let lex = json!({"$type": "com.atproto.lexicon.schema", "lexicon": 1, "id": nsid, "defs": {"main": main}});
    s.xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": publisher.did, "collection": "com.atproto.lexicon.schema", "rkey": nsid, "record": lex, "validate": false}),
            &publisher.auth(),
        )
        .await
        .ok();
    vlpds::oauth::lexicon::override_authority(&vlpds::oauth::lexicon::nsid_authority(nsid), &publisher.did);
}

fn rec(coll: &str) -> J {
    json!({"$type": coll, "text": "hi", "createdAt": "2026-10-01T00:00:00.000Z"})
}

/// Another grant of `scope` to `c`'s account, by a new client key.
async fn regrant(c: &SpaceClient, scope: &str) -> SpaceClient {
    let acct = oauth::Account { did: c.did.clone(), handle: c.handle.clone(), jwt: c.session_jwt.clone() };
    let key = DpopKey::new();
    let t =
        oauth::grant(&c.srv, &mut Browser::default(), &Flow::loopback(&format!("atproto {scope}"), &key), &acct).await;
    SpaceClient {
        srv: Srv { app: c.srv.app.clone(), base: c.srv.base.clone(), http: c.srv.http.clone() },
        did: c.did.clone(),
        handle: c.handle.clone(),
        session_jwt: c.session_jwt.clone(),
        key,
        access: t.access,
        scope: t.scope,
        holder: Default::default(),
    }
}

fn scopes(c: &SpaceClient) -> Vec<&str> {
    c.scope.split(' ').collect()
}

/// A bare grant that writes takes its declaration's collections when the
/// token is issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bare_grant_takes_declared_collections() {
    let s = spawn().await;
    let ty = "com.c6decl.forum";
    publish(
        &s,
        ty,
        json!({"type": "space", "name": "Forum", "collections": ["com.c6decl.thread", "com.c6decl.reply"]}),
    )
    .await;
    let a = SpaceClient::new(&s, "c6bare", &format!("space:{ty}?manage=create")).await;
    let want = format!(
        "space:{ty}?authority={}&collection=com.c6decl.reply&collection=com.c6decl.thread&manage=create",
        a.did
    );
    assert!(scopes(&a).contains(&want.as_str()), "{}", a.scope);
    let space = a.create_space(ty, "main").await;
    a.create_record(&space, "com.c6decl.thread", Some("t1"), rec("com.c6decl.thread")).await.ok();
    a.create_record(&space, "com.c6decl.reply", Some("r1"), rec("com.c6decl.reply")).await.ok();
    let r = a.create_record(&space, "com.c6decl.other", None, rec("com.c6decl.other")).await;
    r.err(403, "ScopeMissingError");
    assert!(r.json["message"].as_str().unwrap().contains("collection=com.c6decl.other&action=create"), "{}", r.json);
    // the grant's default actions include update and delete
    a.put_record(&space, "com.c6decl.thread", "t1", rec("com.c6decl.thread")).await.ok();
    a.delete_record(&space, "com.c6decl.reply", "r1").await.ok();

    // a declaration naming `title` (proposals #118) works the same
    let titled = "com.c6title.album";
    publish(&s, titled, json!({"type": "space", "title": "Album", "collections": ["com.c6title.photo"]})).await;
    let t = regrant(&a, &format!("space:{titled}?action=create&manage=create")).await;
    let sp2 = t.create_space(titled, "pics").await;
    t.create_record(&sp2, "com.c6title.photo", None, rec("com.c6title.photo")).await.ok();
}

/// Signs `acct` in on a new flow for `scope` and returns the consent page
/// with what posting "allow" needs.
async fn consent_page(
    srv: &Srv,
    acct: &oauth::Account,
    scope: &str,
    key: &DpopKey,
) -> (Browser, String, oauth::Pkce, String) {
    let f = Flow::loopback(scope, key);
    let p = oauth::pkce();
    let mut b = Browser::default();
    let ru = f.request_uri(srv, &p, "c6u").await;
    let csrf = oauth::csrf_of(&b.authorize(srv, &f, &ru).await.2);
    let (st, _, html) = b.sign_in(srv, &ru, &csrf, &acct.handle, oauth::PASSWORD).await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("Authorize access"), "{html}");
    (b, ru, p, html)
}

/// Posts "allow" on the page [`consent_page`] returned, then exchanges the code.
async fn approve_and_exchange(
    srv: &Srv,
    acct: &oauth::Account,
    scope: &str,
    key: &DpopKey,
    (mut b, ru, p, html): (Browser, String, oauth::Pkce, String),
) -> oauth::Resp {
    let csrf = oauth::csrf_of(&html);
    let (st, h, body) = b
        .post(
            srv,
            "/oauth/authorize/consent",
            &[("request_uri", &ru), ("csrf", &csrf), ("did", &acct.did), ("action", "allow")],
        )
        .await;
    assert_eq!(st, 303, "{body}");
    let code = oauth::location_params(&h).1.get("code").expect("code").clone();
    oauth::exchange(srv, &Flow::loopback(scope, key), &code, &p, &[]).await
}

/// A bare grant that writes, whose declaration doesn't resolve while the
/// account approves it: the consent screen says the writes couldn't be
/// looked up and the token request fails, as the reference's does. That
/// holds when the declaration resolves by the time the code is exchanged,
/// so the token never carries writes the screen didn't show.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unresolved_declaration_fails_the_token_request() {
    let s = spawn().await;
    let srv = srv(&s);
    let acct = oauth::create_account(&srv, "c6unres").await;

    let missing = "com.c6nodecl.forum";
    vlpds::oauth::lexicon::override_authority(&vlpds::oauth::lexicon::nsid_authority(missing), &acct.did);
    let scope = format!("atproto space:{missing}?manage=create");
    let key = DpopKey::new();
    let page = consent_page(&srv, &acct, &scope, &key).await;
    consent_html_has(
        &page.3,
        &[&format!(
            "com.c6nodecl.forum spaces on your account: read what members share with you and create spaces. It also asks to write records in the collections {missing} declares, which could not be looked up, so approving this will fail"
        )],
    );
    let r = approve_and_exchange(&srv, &acct, &scope, &key, page).await;
    assert_eq!(r.status, 400, "{}", r.body);
    assert_eq!(r.body["error"], "invalid_request", "{}", r.body);
    assert!(r.body["error_description"].as_str().unwrap().contains(missing), "{}", r.body);

    // the lookup fails at consent and works by the exchange: still refused
    let late = "com.c6late.forum";
    vlpds::oauth::lexicon::override_authority(&vlpds::oauth::lexicon::nsid_authority(late), &acct.did);
    let scope = format!("atproto space:{late}?manage=create");
    let page = consent_page(&srv, &acct, &scope, &key).await;
    assert!(page.3.contains("could not be looked up"), "{}", page.3);
    publish(&s, late, json!({"type": "space", "name": "Late", "collections": ["com.c6late.thread"]})).await;
    let r = approve_and_exchange(&srv, &acct, &scope, &key, page).await;
    assert_eq!(r.status, 400, "the exchange widened the grant: {}", r.body);
    assert_eq!(r.body["error"], "invalid_request", "{}", r.body);
    // it does resolve now: a new approval gets the collections
    let t = oauth::grant(&srv, &mut Browser::default(), &Flow::loopback(&scope, &key), &acct).await;
    assert!(t.scope.contains("collection=com.c6late.thread"), "{}", t.scope);

    // a declaration that isn't a space type doesn't resolve either
    let not_space = "com.c6notspace.forum";
    publish(&s, not_space, json!({"type": "permission-set", "permissions": []})).await;
    let scope = format!("atproto space:{not_space}?manage=create");
    let page = consent_page(&srv, &acct, &scope, &key).await;
    let r = approve_and_exchange(&srv, &acct, &scope, &key, page).await;
    assert_eq!(r.status, 400, "{}", r.body);

    // a bare grant that only reads needs no declaration
    let scope = format!("atproto space:{missing}?action=read");
    let t = oauth::grant(&srv, &mut Browser::default(), &Flow::loopback(&scope, &key), &acct).await;
    assert!(t.scope.contains(&format!("space:{missing}?authority={}&action=read", acct.did)), "{}", t.scope);
}

/// A refresh keeps the collections approved at consent, even after the
/// type's declaration grows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_never_widens_a_bare_grant() {
    let s = spawn().await;
    let srv = srv(&s);
    let acct = oauth::create_account(&srv, "c6refr").await;
    let ty = "com.c6grow.forum";
    publish(&s, ty, json!({"type": "space", "name": "Forum", "collections": ["com.c6grow.thread"]})).await;
    let scope = format!("atproto space:{ty}?manage=create");
    let key = DpopKey::new();
    let f = Flow::loopback(&scope, &key);
    let t = oauth::grant(&srv, &mut Browser::default(), &f, &acct).await;
    let narrow = format!("space:{ty}?authority={}&collection=com.c6grow.thread&manage=create", acct.did);
    assert!(t.scope.split(' ').any(|x| x == narrow), "{}", t.scope);

    publish(
        &s,
        ty,
        json!({"type": "space", "name": "Forum", "collections": ["com.c6grow.thread", "com.c6grow.reply"]}),
    )
    .await;
    vlpds::oauth::lexicon::forget_cached(ty);
    let key2 = DpopKey::new();
    let wide = oauth::grant(&srv, &mut Browser::default(), &Flow::loopback(&scope, &key2), &acct).await;
    assert!(wide.scope.contains("collection=com.c6grow.reply"), "the new declaration resolves: {}", wide.scope);

    let mut rt = t.refresh.expect("refresh token");
    for _ in 0..2 {
        let r = oauth::refresh(&srv, &f, &rt, &[]).await;
        let n = oauth::tokens(&r);
        assert!(n.scope.split(' ').any(|x| x == narrow), "refresh widened the grant: {}", n.scope);
        assert!(!n.scope.contains("com.c6grow.reply"), "{}", n.scope);
        rt = n.refresh.unwrap();
    }
}

/// A session approved before `--spaces` was enabled has a bare writing
/// grant but no approved collections: its refresh is refused with
/// invalid_grant (not server_error, which clients retry) and the session
/// ends, so the client signs in again and the account approves the writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_without_approved_collections_needs_a_new_grant() {
    let s = spawn().await;
    let srv = srv(&s);
    let acct = oauth::create_account(&srv, "c6pre").await;
    let ty = "com.c6pre.forum";
    publish(&s, ty, json!({"type": "space", "name": "Forum", "collections": ["com.c6pre.thread"]})).await;
    let scope = format!("atproto space:{ty}?manage=create");
    let key = DpopKey::new();
    let f = Flow::loopback(&scope, &key);
    let t = oauth::grant(&srv, &mut Browser::default(), &f, &acct).await;
    let sid = jwt_claims(&t.access)["sid"].as_str().unwrap().to_string();

    // what a session from before `--spaces` looks like
    let (mut row, raw) = vlpds::oauth::store::get_session_raw(&s.app, &acct.did, &sid).await.unwrap().expect("session");
    assert!(row.space_collections.is_some());
    row.space_collections = None;
    assert!(vlpds::oauth::store::put_session_if(&s.app, &row, vlpds::oauth::store::SessionGuard::Row(raw))
        .await
        .unwrap());

    let rt = t.refresh.expect("refresh token");
    let r = oauth::refresh(&srv, &f, &rt, &[]).await;
    assert_eq!(r.status, 400, "{}", r.body);
    assert_eq!(r.body["error"], "invalid_grant", "{}", r.body);
    assert!(r.body["error_description"].as_str().unwrap().contains(ty), "{}", r.body);
    assert!(vlpds::oauth::store::get_session(&s.app, &acct.did, &sid).await.unwrap().is_none());

    let again = oauth::grant(&srv, &mut Browser::default(), &Flow::loopback(&scope, &key), &acct).await;
    assert!(again.scope.contains("collection=com.c6pre.thread"), "{}", again.scope);
}

/// A code issued without any UI, as `prompt=none` needs.
async fn silent_code(srv: &Srv, b: &mut Browser, f: &Flow<'_>) -> (String, oauth::Pkce) {
    let p = oauth::pkce();
    let ru = f.request_uri(srv, &p, "auto").await;
    let (st, h, body) = b.authorize(srv, f, &ru).await;
    assert_eq!(st, 303, "{body}");
    (oauth::location_params(&h).1.get("code").expect("auto-approved").clone(), p)
}

/// A login that skips consent (a confidential client the account already
/// approved, here with prompt=none) looks up only the declarations of bare
/// grants that write, the only ones the token needs, so a login without
/// any waits on no lookup, and one with them gets their collections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_approved_login_looks_up_only_bare_writing_grants() {
    use vlpds::oauth::lexicon::{forget_cached, is_cached};
    let s = spawn().await;
    let srv = srv(&s);
    let acct = oauth::create_account(&srv, "c6auto").await;
    let (ro, named, bare) = ("com.c6autoro.forum", "com.c6autonm.forum", "com.c6autobr.forum");
    for (t, coll) in [(ro, "com.c6autoro.thread"), (named, "com.c6autonm.thread"), (bare, "com.c6autobr.thread")] {
        publish(&s, t, json!({"type": "space", "name": "Forum", "collections": [coll]})).await;
    }
    let lean = format!("atproto space:{ro}?action=read space:{named}?collection=com.c6autonm.thread&action=create");
    let full = format!("{lean} space:{bare}?action=create");

    let (sk, jwk) = oauth::client_key();
    let redirect = "https://app.example.com/callback";
    let client_id = oauth::serve_metadata(|id| {
        let mut md = oauth::confidential_metadata(id, redirect, &jwk);
        md["scope"] = J::String(full.clone());
        md
    })
    .await;
    let assertion = || oauth::client_assertion(&sk, &client_id, &srv.base);
    let key = DpopKey::new();
    let flow = |scope: &str, silent: bool| {
        let f = Flow::new(&client_id, redirect, scope, &key)
            .with("client_assertion_type", oauth::JWT_BEARER)
            .with("client_assertion", &assertion());
        if silent {
            f.with("prompt", "none")
        } else {
            f
        }
    };
    let mut b = Browser::default();
    let p = oauth::pkce();
    oauth::authorize_interactive(&srv, &mut b, &flow(&full, false), &acct, &p).await;

    for t in [ro, named, bare] {
        forget_cached(t);
    }
    silent_code(&srv, &mut b, &flow(&lean, true)).await;
    assert!(!is_cached(ro) && !is_cached(named) && !is_cached(bare), "a login without bare writing grants looked up");

    let (code, p) = silent_code(&srv, &mut b, &flow(&full, true)).await;
    assert!(is_cached(bare), "the bare writing grant's declaration");
    assert!(!is_cached(ro) && !is_cached(named), "grants that need no declaration were looked up");
    let auth = assertion();
    let r = oauth::exchange(
        &srv,
        &flow(&full, true),
        &code,
        &p,
        &[("client_assertion_type", oauth::JWT_BEARER), ("client_assertion", &auth)],
    )
    .await;
    let t = oauth::tokens(&r);
    assert!(t.scope.contains("collection=com.c6autobr.thread"), "{}", t.scope);
}

/// `authority=self` is resolved to the account when the token is issued, so
/// the grant covers only the account's own spaces; a type or an authority
/// not granted is refused, and so is an action.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn types_authorities_and_actions_are_enforced() {
    let s = spawn().await;
    let ty = "com.c6enf.group";
    let coll = "com.c6enf.post";
    let a = SpaceClient::new(
        &s,
        "c6enf",
        &format!("space:{ty}?collection={coll}&action=read&action=create&manage=create space:com.c6enf.other?authority=*&action=read_self&manage=create"),
    )
    .await;
    assert!(a.scope.contains(&format!("space:{ty}?authority={}&collection={coll}", a.did)), "{}", a.scope);
    assert!(!a.scope.contains("authority=self"), "{}", a.scope);
    let space = a.create_space(ty, "main").await;
    a.create_record(&space, coll, Some("p1"), rec(coll)).await.ok();

    // a collection not granted
    let r = a.create_record(&space, "com.c6enf.reply", None, rec("com.c6enf.reply")).await;
    r.err(403, "ScopeMissingError");
    // actions not granted: update (putRecord over an existing record) and delete
    let r = a.put_record(&space, coll, "p1", rec(coll)).await;
    r.err(403, "ScopeMissingError");
    assert!(r.json["message"].as_str().unwrap().contains("action=update"), "{}", r.json);
    a.put_record(&space, coll, "p2", rec(coll)).await.ok();
    let r = a.delete_record(&space, coll, "p1").await;
    r.err(403, "ScopeMissingError");
    assert!(r.json["message"].as_str().unwrap().contains("action=delete"), "{}", r.json);
    let r = a
        .apply_writes(
            &space,
            json!([{"$type": "com.atproto.space.applyWrites#delete", "collection": coll, "rkey": "p1"}]),
        )
        .await;
    r.err(403, "ScopeMissingError");

    // a type not granted for writing: its grant reads only
    let other = a.create_space("com.c6enf.other", "o").await;
    a.create_record(&other, coll, None, rec(coll)).await.err(403, "ScopeMissingError");
    a.get("com.atproto.space.listRecords", &[("space", &other), ("repo", &a.did)]).await.ok();
    // a type with no grant at all
    let r = a
        .post(
            "com.atproto.simplespace.createSpace",
            json!({
                "spaceType": "com.c6enf.third",
                "skey": "t",
                "readPolicy": {"$type": "com.atproto.simplespace.defs#memberListPolicy"},
                "writePolicy": {"$type": "com.atproto.simplespace.defs#memberListPolicy"},
                "appAccess": {"$type": "com.atproto.simplespace.defs#open"},
            }),
        )
        .await;
    r.err(403, "ScopeMissingError");

    // an authority not granted: another account's space of the granted type
    let b = SpaceClient::new(&s, "c6enfb", &format!("space:{ty}?collection={coll}&manage=create")).await;
    let theirs = b.create_space(ty, "main").await;
    let r = a.create_record(&theirs, coll, None, rec(coll)).await;
    r.err(403, "ScopeMissingError");
    assert!(r.json["message"].as_str().unwrap().contains(&format!("authority={}", b.did)), "{}", r.json);
    let r = a.get("com.atproto.space.listRecords", &[("space", &theirs), ("repo", &a.did)]).await;
    r.err(403, "ScopeMissingError");
    a.delegation_token(&theirs).await.err(403, "ScopeMissingError");

    // putRecord resolves to update: an update-only grant updates without create
    let u = regrant(&a, &format!("space:{ty}?collection={coll}&action=update")).await;
    u.put_record(&space, coll, "p1", rec(coll)).await.ok();
    let r = u.put_record(&space, coll, "p9", rec(coll)).await;
    r.err(403, "ScopeMissingError");
    assert!(r.json["message"].as_str().unwrap().contains("action=create"), "{}", r.json);
    u.create_record(&space, coll, None, rec(coll)).await.err(403, "ScopeMissingError");
}

/// read_self reads only the account's own repo and never mints a
/// delegation token; read reads the whole space, and its token exchanges
/// for a credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_self_vs_read() {
    let s = spawn().await;
    let ty = "com.c6read.group";
    let coll = "com.c6read.post";
    let a = SpaceClient::new(
        &s,
        "c6rs",
        &format!("space:{ty}?collection={coll}&action=read_self&action=create&manage=create"),
    )
    .await;
    let space = a.create_space(ty, "main").await;
    a.create_record(&space, coll, Some("x"), rec(coll)).await.ok();
    a.get("com.atproto.space.getRecord", &[("space", &space), ("repo", &a.did), ("collection", coll), ("rkey", "x")])
        .await
        .ok();
    a.get("com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &a.did)]).await.ok();
    let r = a.delegation_token(&space).await;
    r.err(403, "ScopeMissingError");
    assert_eq!(
        r.json["message"],
        format!(r#"Missing required scope "space:{ty}?authority={}&skey=main&action=read""#, a.did)
    );

    let full = regrant(&a, &format!("space:{ty}?action=read")).await;
    let cred = full.credential(&space).await;
    let q = [("space", space.as_str()), ("repo", a.did.as_str()), ("collection", coll), ("rkey", "x")];
    full.signed_get(&s.url, "com.atproto.space.getRecord", &q, &cred, &a.did).await.ok();
}

/// listSpaces unfiltered needs a wildcard grant (the filters are the scope
/// target); a filtered listing needs the type.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_spaces_wildcard() {
    let s = spawn().await;
    let ty = "com.c6list.group";
    let a = SpaceClient::new(&s, "c6ls", &format!("space:{ty}?action=read_self&manage=create")).await;
    let space = a.create_space(ty, "main").await;
    // `self` resolved: a filter naming the account is covered, any authority isn't
    a.get("com.atproto.space.listSpaces", &[("spaceType", ty), ("did", &a.did)]).await.ok();
    a.get("com.atproto.space.listSpaces", &[("spaceType", ty)]).await.err(403, "ScopeMissingError");
    a.get("com.atproto.space.listSpaces", &[]).await.err(403, "ScopeMissingError");
    let w = regrant(&a, "space:*?authority=*&action=read_self").await;
    let all = w.get("com.atproto.space.listSpaces", &[]).await.ok();
    assert_eq!(all["spaces"][0]["uri"], space.as_str());
    w.get("com.atproto.space.listSpaces", &[("spaceType", ty)]).await.ok();
    // a wildcard type at one authority covers that authority only
    let one = regrant(&a, &format!("space:*?authority={}&action=read_self", a.did)).await;
    one.get("com.atproto.space.listSpaces", &[("did", &a.did)]).await.ok();
    one.get("com.atproto.space.listSpaces", &[]).await.err(403, "ScopeMissingError");
}

/// An `include:` permission set's space permissions (under its own NSID
/// group) are granted, made concrete like a direct grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn include_carries_space_permissions() {
    let s = spawn().await;
    let set = "com.c6inc.auth";
    publish(
        &s,
        set,
        json!({"type": "permission-set", "title": "Group chat", "permissions": [
            {"type": "permission", "resource": "space", "spaceType": "com.c6inc.group",
             "collection": ["com.c6inc.msg"], "action": ["read", "create"], "manage": ["create"]},
            {"type": "permission", "resource": "space", "spaceType": "app.bsky.group", "collection": ["*"]},
            {"type": "permission", "resource": "space", "spaceType": "*"},
        ]}),
    )
    .await;
    let a = SpaceClient::new(&s, "c6inc", &format!("include:{set}")).await;
    assert_eq!(
        scopes(&a),
        [
            format!(
                "space:com.c6inc.group?authority={}&collection=com.c6inc.msg&action=read&action=create&manage=create",
                a.did
            )
            .as_str(),
            "atproto"
        ]
    );
    let space = a.create_space("com.c6inc.group", "chat").await;
    a.create_record(&space, "com.c6inc.msg", None, rec("com.c6inc.msg")).await.ok();
    a.delegation_token(&space).await.ok();
}

fn consent_html_has(html: &str, needles: &[&str]) {
    for n in needles {
        assert!(html.contains(n), "consent page should show {n:?}: {html}");
    }
}

/// The consent page names a space type by its declaration and an
/// authority by its verified handle (else its DID). A grant on every space
/// that only reads your own space repos gets no warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consent_names_and_warning() {
    let s = spawn().await;
    let ty = "com.c6ui.forum";
    publish(&s, ty, json!({"type": "space", "name": "Book Club", "collections": ["com.c6ui.thread"]})).await;
    let srv = srv(&s);
    let owner = oauth::create_account(&srv, "c6owner").await;
    let user = oauth::create_account(&srv, "c6user").await;
    // its document never resolves, so no handle is shown
    let stranger = "did:web:localhost";
    let scope = format!(
        "atproto space:{ty}?authority={} space:{ty}?authority={stranger}&action=read_self space:com.c6ui.nodecl?action=read space:*?authority=*&action=read_self",
        owner.did
    );
    let key = DpopKey::new();
    let html = consent_page(&srv, &user, &scope, &key).await.3;
    consent_html_has(
        &html,
        &[
            // the declaration's name and the bare grant's declared collections
            &format!(
                "Book Club spaces on @{}: read what members share with you and write records in com.c6ui.thread",
                owner.handle
            ),
            &format!("Book Club spaces on {stranger}: read your own space repos"),
            "com.c6ui.nodecl spaces on your account: read what members share with you",
            "All spaces on the network: read your own space repos",
        ],
    );
    assert!(!html.contains("class=\"warn\""), "reading your own space repos is no warning: {html}");

    // writes on every space warn, even without reading others' data
    let scope = "atproto space:*?authority=*&collection=*&action=create&action=read_self";
    let html = consent_page(&srv, &user, scope, &key).await.3;
    consent_html_has(
        &html,
        &[
            "All spaces on the network: read your own space repos and create records in any collection",
            "asking to write in every space on the network",
        ],
    );
    assert_eq!(html.matches("class=\"warn\"").count(), 1, "{html}");

    // reading what anyone shares, anywhere, gets the loud one
    let html = consent_page(&srv, &user, "atproto space:*?authority=*&action=read", &key).await.3;
    consent_html_has(
        &html,
        &[
            "All spaces on the network: read what members share with you",
            "asking to read every space on the network: whatever anyone shares with you",
        ],
    );
    assert_eq!(html.matches("class=\"warn\"").count(), 1, "{html}");

    // a narrower read gets no warning
    let html =
        consent_page(&srv, &user, &format!("atproto space:{ty}?authority={}&action=read", owner.did), &key).await.3;
    consent_html_has(&html, &[&format!("Book Club spaces on @{}: read what members share with you", owner.handle)]);
    assert!(!html.contains("class=\"warn\""), "{html}");
    let html = consent_page(&srv, &user, &format!("atproto space:*?authority={}&action=read", owner.did), &key).await.3;
    consent_html_has(&html, &[&format!("All spaces on @{}: read what members share with you", owner.handle)]);
    assert!(!html.contains("class=\"warn\""), "{html}");
}

async fn set_limits(s: &TestServer, limiters: J) {
    s.xrpc
        .post(
            "vlpds.admin.updateRateLimits",
            &json!({"config": {"limiters": limiters}, "ifVersion": 0, "actor": "it-test"}),
            &Auth::Admin,
        )
        .await
        .ok();
}

async fn service_jwt(s: &TestServer, iss: &str, aud: &str, lxm: &str) -> String {
    let acct = s.app.account(iss).await.ok().unwrap();
    let key = s.app.secrets.account_signing_key(&acct).await.unwrap();
    vlpds::auth::service_auth_jwt(&key, iss, aud, Some(lxm), 60).unwrap()
}

async fn signed_read(s: &TestServer, who: &SpaceClient, space: &str, repo: &str, cred: &str) -> Resp {
    let q = [("space", space), ("repo", repo)];
    who.signed_get(&s.url, "com.atproto.space.getLatestCommit", &q, cred, repo).await
}

async fn bearer_post(s: &TestServer, nsid: &str, jwt: &str, body: J) -> Resp {
    let r = reqwest::Client::new().post(format!("{}/xrpc/{nsid}", s.url)).bearer_auth(jwt).json(&body).send().await;
    resp(r.unwrap()).await
}

/// Each Spaces bucket answers 429 once its points are spent: reads per
/// credential and per account, getSpaceCredential per (account,
/// authority), inbound notifyWrite per writer, revocations per authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_rate_buckets_trip() {
    let s = TestServer::spawn_with(|c| {
        c.spaces = true;
        c.rate_limits_enabled = true;
    })
    .await;
    let ty = "com.c6rl.group";
    let coll = "com.c6rl.post";
    let full =
        format!("space:{ty}?authority=*&collection={coll}&action=read&action=create&manage=create&manage=update");
    let a = SpaceClient::new(&s, "c6rla", &full).await;
    let b = SpaceClient::new(&s, "c6rlb", &full).await;
    let space = a.create_space(ty, "main").await;
    a.create_record(&space, coll, Some("x"), rec(coll)).await.ok();
    a.post("com.atproto.simplespace.putMember", json!({"space": space, "did": b.did, "read": true, "write": true}))
        .await
        .ok();
    set_limits(
        &s,
        json!({
            "space-read-account": {"points": 2},
            "space-read-credential": {"points": 2},
            "space-credential": {"points": 2},
            "space-notify-in": {"points": 1},
            "space-revoke": {"points": 1},
        }),
    )
    .await;
    let tripped = |r: &Resp, limit: i64| {
        r.err(429, "RateLimitExceeded");
        assert_eq!(r.header("ratelimit-limit").and_then(|v| v.parse::<i64>().ok()), Some(limit), "{r:?}");
    };

    // space-read-account: the account's own OAuth reads
    let own = [("space", space.as_str()), ("repo", a.did.as_str())];
    for _ in 0..2 {
        a.get("com.atproto.space.getLatestCommit", &own).await.ok();
    }
    tripped(&a.get("com.atproto.space.listRecords", &own).await, 2);
    tripped(&a.get("com.atproto.space.listSpaces", &[("spaceType", ty)]).await, 2);
    // another account has its own budget
    b.get("com.atproto.space.listSpaces", &[("spaceType", ty)]).await.ok();

    // space-credential: per (account, authority); a refused exchange keeps its token
    let c1 = b.credential(&space).await;
    b.credential(&space).await;
    let token = b.delegation_token(&space).await.ok()["token"].as_str().unwrap().to_string();
    tripped(&b.exchange(&s.url, &space, &token).await, 2);
    a.credential(&space).await;

    // space-read-credential: per credential
    for _ in 0..2 {
        signed_read(&s, &b, &space, &a.did, &c1).await.ok();
    }
    tripped(&signed_read(&s, &b, &space, &a.did, &c1).await, 2);
    let c2 = a.credential(&space).await;
    signed_read(&s, &a, &space, &a.did, &c2).await.ok();

    // space-notify-in: per writer (b's notifyWrite reaching its authority)
    let notify = json!({"space": space, "repo": b.did, "repoRev": "3l2cqzy5yf22a", "data": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}});
    let jwt = service_jwt(&s, &b.did, &a.did, "com.atproto.space.notifyWrite").await;
    let first = bearer_post(&s, "com.atproto.space.notifyWrite", &jwt, notify.clone()).await;
    assert_ne!(first.status, 429, "{first:?}");
    let jwt = service_jwt(&s, &b.did, &a.did, "com.atproto.space.notifyWrite").await;
    tripped(&bearer_post(&s, "com.atproto.space.notifyWrite", &jwt, notify).await, 1);

    // space-revoke: per authority
    let revoke = |jti: &str| json!({"space": space, "credentials": [jti]});
    let lxm = "com.atproto.space.notifyCredentialRevoked";
    let jwt = service_jwt(&s, &a.did, &b.did, lxm).await;
    bearer_post(&s, lxm, &jwt, revoke("3l2cqzy5yf22b")).await.ok();
    let jwt = service_jwt(&s, &a.did, &b.did, lxm).await;
    tripped(&bearer_post(&s, lxm, &jwt, revoke("3l2cqzy5yf22c")).await, 1);

    // the console sees who talks to which authority only as a keyed hash
    let rl = s.xrpc.get("vlpds.admin.getRateLimits", &[("top", "50")], &Auth::Admin).await.ok();
    for bucket in ["space-credential", "space-read-credential"] {
        let top = rl["top"][bucket].as_array().unwrap_or_else(|| panic!("{bucket} in {rl}"));
        assert!(!top.is_empty(), "{rl}");
        for c in top {
            let k = c["key"].as_str().unwrap();
            assert!(k.len() == 32 && k.bytes().all(|b| b.is_ascii_hexdigit()), "{bucket} key {k}");
        }
    }
}

/// With `--spaces` off nothing changes: `space:` scopes aren't offered and
/// a permission set's space permissions are dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flag_off_grants_no_space_permissions() {
    let s = TestServer::spawn().await;
    let set = "com.c6off.auth";
    publish(
        &s,
        set,
        json!({"type": "permission-set", "permissions": [
            {"type": "permission", "resource": "space", "spaceType": "com.c6off.group", "collection": ["*"]},
            {"type": "permission", "resource": "repo", "collection": ["com.c6off.thing"]},
        ]}),
    )
    .await;
    let srv = srv(&s);
    let acct = oauth::create_account(&srv, "c6off").await;
    let key = DpopKey::new();
    let t =
        oauth::grant(&srv, &mut Browser::default(), &Flow::loopback(&format!("atproto include:{set}"), &key), &acct)
            .await;
    assert_eq!(t.scope, "repo:com.c6off.thing atproto");
}

/// `--lexicon-authority-override` (dev mode only): refused without
/// --dev-mode, by the binary at startup and by the setting itself; with
/// it, a bare grant's type declaration resolves from the overriding DID's
/// repo, the consent screen names it and the grant takes its collections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lexicon_authority_override_is_dev_only_and_resolves_declarations() {
    use vlpds::oauth::lexicon::apply_authority_overrides;
    let o = tokio::process::Command::new(env!("CARGO_BIN_EXE_vlpds"))
        .args(["--lexicon-authority-override", "c6ovr.example=did:web:c6ovr.example"])
        .env_remove("VLPDS_DEV_MODE")
        .output()
        .await
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success() && stderr.contains("--dev-mode"), "{stderr}");
    let e =
        |v: &[&str], dev: bool| apply_authority_overrides(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>(), dev);
    assert!(e(&["c6ovr.example=did:web:c6ovr.example"], false).is_err(), "without dev mode");
    assert!(e(&["c6ovr.example"], true).is_err(), "no DID");
    assert!(e(&["not a domain=did:web:c6ovr.example"], true).is_err(), "not a domain");
    assert!(e(&["c6ovr.example=did:key:z6Mk"], true).is_err(), "not an atproto DID");
    assert!(e(&[], false).is_ok(), "no overrides needs nothing");

    let s = spawn().await;
    let ty = "com.c6ovr.forum";
    let publisher = s.create_account("c6ovrpub").await;
    let lex = json!({"$type": "com.atproto.lexicon.schema", "lexicon": 1, "id": ty, "defs": {"main": {"type": "space", "name": "Override Forum", "collections": ["com.c6ovr.thread"]}}});
    s.xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": publisher.did, "collection": "com.atproto.lexicon.schema", "rkey": ty, "record": lex, "validate": false}),
            &publisher.auth(),
        )
        .await
        .ok();
    apply_authority_overrides(&[format!("C6OVR.com={}", publisher.did)], true).unwrap();

    let srv = srv(&s);
    let acct = oauth::create_account(&srv, "c6ovr").await;
    let scope = format!("atproto space:{ty}?manage=create");
    let key = DpopKey::new();
    let page = consent_page(&srv, &acct, &scope, &key).await;
    consent_html_has(&page.3, &["Override Forum spaces on your account"]);
    let r = approve_and_exchange(&srv, &acct, &scope, &key, page).await;
    let t = oauth::tokens(&r);
    let want = format!("space:{ty}?authority={}&collection=com.c6ovr.thread&manage=create", acct.did);
    assert!(t.scope.split(' ').any(|x| x == want), "{}", t.scope);
}
