//! Reference PDS plc-operations.test.ts cases not covered by `plc`: the
//! signature-request email and the exact error messages of signPlcOperation.
use crate::common::*;
use std::sync::Arc;
use vlatproto::crypto::Keypair;
use vlpds::plc::mock::MockPlc;

/// "does not allow signing plc operation without a token", "requests a plc
/// signature", "does not sign a plc operation with a bad token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plc_signature_request_mail_and_token_errors() {
    let plc = MockPlc::start().await;
    let key = Arc::new(Keypair::generate());
    let s = TestServer::spawn_plc(&plc.url, key).await;
    let a = s.create_account("alice").await;
    let sample = Keypair::generate().did_key();
    let sign = |body: J| {
        let (s, a) = (&s, &a);
        async move { s.xrpc.post("com.atproto.identity.signPlcOperation", &body, &a.auth()).await }
    };

    let r = sign(json!({"rotationKeys": [sample]})).await;
    r.err(400, "InvalidRequest");
    assert!(r.text().contains("email confirmation token required to sign PLC operations"), "{}", r.text());

    s.xrpc.post_empty("com.atproto.identity.requestPlcOperationSignature", &a.auth()).await.ok();
    let mail = s.dev_mail(&a.email).await.ok();
    let msgs = mail["messages"].as_array().unwrap();
    let m = msgs.iter().rev().find(|m| m["purpose"] == json!("plc_operation")).expect("plc_operation mail");
    assert_eq!(m["to"], json!(a.email));
    assert_eq!(m["subject"], json!("PLC Update Operation Requested"));
    assert!(m["html"].as_str().unwrap_or_default().contains("PLC update requested"), "{m}");
    assert!(m["token"].is_string());

    let r = sign(json!({"token": "123456", "rotationKeys": [sample]})).await;
    r.err(400, "InvalidToken");
    assert!(r.text().contains("Token is invalid"), "{}", r.text());
}
