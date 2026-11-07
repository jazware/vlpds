//! The account page's "Your spaces" section (ui/src/pages/account/Spaces.tsx):
//! the served client metadata names its redirect URI and owner scope, then
//! the flow it runs, as the UI runs it on a plain-http dev host (a loopback
//! client declaring the metadata's scope): the narrow read grant, the owner
//! grant on top of it, then revocation. The https client's metadata itself
//! is checked in `oauth::client`'s unit tests (a web client can't redirect
//! to 127.0.0.1).

use crate::common::spaces::SpaceClient;
use crate::common::*;
use crate::oauth::{as_post, enc, exchange, grant, pkce, tokens, xrpc_dpop, Account, Browser, DpopKey, Flow, Srv};

const TYPE: &str = "com.example.group";
const READ: &str = "atproto space:*?authority=*&action=read_self";
const OWNER: &str = "space:*?action=read_self&manage=update&manage=delete";

fn srv(s: &TestServer) -> Srv {
    Srv {
        app: s.app.clone(),
        base: s.url.clone(),
        http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_party_read_then_owner_grant() {
    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let owner = SpaceClient::new(
        &s,
        "sapo",
        "space:com.example.group?collection=com.example.post&action=read&action=create&manage=create",
    )
    .await;
    let other = SpaceClient::new(&s, "sapx", "space:com.example.group?action=read_self&manage=create").await;
    let space = owner.create_space(TYPE, "main").await;
    let theirs = other.create_space(TYPE, "theirs").await;
    let member = s.create_account("sapm").await;

    let md = s.xrpc.http.get(format!("{}/oauth/client-metadata.json", s.url)).send().await.unwrap();
    let md: J = md.json().await.unwrap();
    let callback = format!("{}/account/oauth/callback", s.url);
    assert!(md["redirect_uris"].as_array().unwrap().iter().any(|u| u == &callback), "{md}");
    let declared = md["scope"].as_str().unwrap();
    assert!(declared.split(' ').any(|v| v == OWNER), "{md}");
    let client_id = crate::oauth::loopback_client_id(declared, &callback);

    let srv = srv(&s);
    let acct = Account { did: owner.did.clone(), handle: owner.handle.clone(), jwt: owner.session_jwt.clone() };
    let key = DpopKey::new();
    let mut browser = Browser::default();

    // an undeclared scope or redirect is refused at PAR
    let wide = format!("{READ} space:*?authority=*&action=read_self&manage=update");
    let r = Flow::new(&client_id, &callback, &wide, &key).par(&srv, &pkce(), "x").await;
    assert_eq!(r.body["error"], "invalid_scope", "{}", r.body);
    let r = Flow::new(&client_id, &format!("{}/account", s.url), READ, &key).par(&srv, &pkce(), "x").await;
    assert_eq!(r.status, 400, "{}", r.body);

    // the narrow grant reads the user's spaces and their governance, and manages nothing
    let read = grant(&srv, &mut browser, &Flow::new(&client_id, &callback, READ, &key), &acct).await;
    let get = |tok: String, nsid: &'static str, q: String| {
        let (srv, key) = (&srv, &key);
        async move { xrpc_dpop(srv, key, &tok, "GET", &format!("{nsid}?{q}"), None).await }
    };
    let q = format!("space={}", enc(&space));
    let listed = get(read.access.clone(), "com.atproto.space.listSpaces", String::new()).await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert!(listed.body["spaces"].as_array().unwrap().iter().any(|x| x["uri"] == space.as_str()), "{}", listed.body);
    assert_eq!(get(read.access.clone(), "com.atproto.space.getSpace", q.clone()).await.status, 200);
    assert_eq!(get(read.access.clone(), "com.atproto.memberspace.listMembers", q.clone()).await.status, 200);
    let put = json!({"space": space, "did": member.did, "read": true, "write": false});
    let r = xrpc_dpop(&srv, &key, &read.access, "POST", "com.atproto.memberspace.putMember", Some(put.clone())).await;
    assert_eq!(r.status, 403, "{}", r.body);

    // the owner grant, requested on top of the first: `self` comes back as the user's DID
    let both = format!("{READ} {OWNER}");
    let key2 = DpopKey::new();
    let f = Flow::new(&client_id, &callback, &both, &key2);
    let p = pkce();
    let code = crate::oauth::authorize_interactive(&srv, &mut browser, &f, &acct, &p).await;
    let ownerg = tokens(&exchange(&srv, &f, &code, &p, &[]).await);
    let resolved = format!("space:*?authority={}&action=read_self&manage=update&manage=delete", owner.did);
    assert!(ownerg.scope.split(' ').any(|v| v == resolved), "{}", ownerg.scope);
    assert!(ownerg.scope.split(' ').any(|v| v == "space:*?authority=*&action=read_self"), "{}", ownerg.scope);

    let post = |nsid: &'static str, body: J| {
        let (srv, key2, tok) = (&srv, &key2, ownerg.access.clone());
        async move { xrpc_dpop(srv, key2, &tok, "POST", nsid, Some(body)).await }
    };
    assert_eq!(post("com.atproto.memberspace.putMember", put).await.status, 200);
    let m =
        xrpc_dpop(&srv, &key2, &ownerg.access, "GET", &format!("com.atproto.memberspace.listMembers?{q}"), None).await;
    assert_eq!(m.body["members"], json!([{"did": member.did, "read": true, "write": false}]));
    let rm = json!({"space": space, "did": member.did});
    assert_eq!(post("com.atproto.memberspace.removeMember", rm).await.status, 200);
    // someone else's space stays out of reach
    let r = post("com.atproto.space.deleteSpace", json!({"space": theirs})).await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(post("com.atproto.space.deleteSpace", json!({"space": space})).await.status, 200);
    let gone = get(read.access.clone(), "com.atproto.space.getSpace", q.clone()).await;
    assert_eq!(gone.body["error"], "SpaceNotFound", "{}", gone.body);

    // signing out revokes: the refresh token's session, and its access token with it
    for (t, k) in [(&read, &key), (&ownerg, &key2)] {
        let rt = t.refresh.clone().expect("refresh token");
        assert_eq!(as_post(&srv, k, "/oauth/revoke", &[("client_id", &client_id), ("token", &rt)]).await.status, 200);
        let r = xrpc_dpop(&srv, k, &t.access, "GET", "com.atproto.space.listSpaces", None).await;
        assert_eq!(r.status, 401, "{}", r.body);
    }
}
