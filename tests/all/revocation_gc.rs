//! Session revocations (`sec/rvk/` rows) outlive a deleted account, so a DID
//! that comes back can't revive its old access tokens, and are collected,
//! a bounded number per tick, once every token they revoke has expired.
use crate::common::*;

async fn revocation_rows(s: &TestServer, did: &str) -> Vec<String> {
    let p = s.app.partition(did).ok().unwrap();
    let prefix = vlpds::state::private_key(did, "sec/rvk/");
    let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
    let mut out = Vec::new();
    while let Some(kv) = it.next().await.unwrap() {
        out.push(String::from_utf8_lossy(&kv.key[prefix.len()..]).to_string());
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocations_of_deleted_accounts_are_collected_after_expiry() {
    let s = TestServer::spawn().await;
    let a = s.create_account("rvk").await;
    let b = s.create_account("rvk").await;
    // a: one session ended (a family revocation), then the account deleted
    // (revoke-all); b: two password changes (two revoke-all rows)
    let sess = s.create_session(&a.handle, PASSWORD).await.ok();
    s.xrpc
        .post_empty("com.atproto.server.deleteSession", &Auth::Bearer(sess["refreshJwt"].as_str().unwrap().into()))
        .await
        .ok();
    s.xrpc.post_empty("com.atproto.server.requestAccountDelete", &a.auth()).await.ok();
    let token = s.mail_token(&a.email).await.expect("delete token");
    s.xrpc
        .post(
            "com.atproto.server.deleteAccount",
            &json!({"did": a.did, "password": PASSWORD, "token": token}),
            &Auth::None,
        )
        .await
        .ok();
    for _ in 0..2 {
        s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": b.email}), &Auth::None).await.ok();
        let t = s.mail_token(&b.email).await.expect("reset token");
        s.xrpc
            .post("com.atproto.server.resetPassword", &json!({"token": t, "password": PASSWORD}), &Auth::None)
            .await
            .ok();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let ra = revocation_rows(&s, &a.did).await;
    assert_eq!(ra.len(), 2, "{ra:?}");
    assert_eq!(revocation_rows(&s, &b.did).await.len(), 2);
    // the deleted account's old token stays refused
    s.xrpc.get("com.atproto.server.getSession", &[], &a.auth()).await.client_err();
    s.xrpc.get("com.atproto.server.getSession", &[], &b.auth()).await.client_err();

    let now = chrono::Utc::now().timestamp();
    let mut sw = vlpds::oauth::gc::Sweeper::new();
    let st = sw.tick(&s.app, now, 10_000, 10_000).await.unwrap();
    assert_eq!(st.claims_removed, 0, "nothing expired yet: {st:?}");
    // past the access-token lifetime (+ slack): the family revocation goes;
    // revoke-all rows are kept for the refresh-token lifetime
    let later = now + 3 * 3600;
    let st = sw.tick(&s.app, later, 10_000, 10).await.unwrap();
    assert_eq!(st.claims_removed, 1, "{st:?}");
    assert_eq!(revocation_rows(&s, &b.did).await.len(), 2);
    // past the refresh-token lifetime (+ slack): bounded deletions per tick
    let later = now + 91 * 86_400;
    let st = sw.tick(&s.app, later, 10_000, 2).await.unwrap();
    assert_eq!(st.claims_removed, 2, "{st:?}");
    let st = sw.tick(&s.app, later, 10_000, 10).await.unwrap();
    assert_eq!(st.claims_removed, 1, "{st:?}");
    assert!(revocation_rows(&s, &a.did).await.is_empty());
    assert!(revocation_rows(&s, &b.did).await.is_empty());
    // b still works with a fresh session
    s.create_session(&b.handle, PASSWORD).await.ok();
}
