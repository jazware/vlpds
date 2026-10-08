//! Signing hardening (src/crypto.rs): with faults injected into an account's
//! signatures (a flipped signature bit, or a flipped bit of the scalar while
//! signing), no faulty signature reaches the firehose or a client, the
//! write retries once with a fresh nonce and otherwise fails cleanly (503
//! `SignatureFault`, nothing applied), the failure metric moves, and repeated
//! faults fail-stop the node.
use crate::common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use vlsync_atproto::crypto::fault::{self, Fault};
use vlsync_atproto::crypto::Purpose;

fn failures(p: Purpose) -> u64 {
    vlsync_atproto::crypto::SIGNATURE_VERIFY_FAILURES.with_label_values(&[p.as_str()]).get()
}

fn create(a: &TestAccount, rkey: &str) -> J {
    json!({"repo": a.did, "collection": "com.example.note", "rkey": rkey, "record": {"$type": "com.example.note", "text": rkey}})
}

/// The only test that injects faults or replaces the fail-stop: the fault
/// window and the hook are process-wide.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn faulty_signatures_are_never_emitted_and_repeats_fail_stop() {
    let stops = Arc::new(AtomicUsize::new(0));
    let hook = stops.clone();
    vlsync_atproto::crypto::set_fail_stop_hook(Some(Arc::new(move |reason| {
        assert_eq!(reason, "signature_fault");
        hook.fetch_add(1, Ordering::SeqCst);
    })));
    let s = TestServer::spawn().await;
    let a = s.create_account("sigfault").await;
    let vk = s.signing_key(&a.did).await;
    let key_id = vk.to_sec1_point(true).as_bytes().to_vec();
    let mut sub = s.subscribe_from_now().await;
    let c0 = failures(Purpose::Commit);

    // one fault: re-signed with a fresh nonce, the write succeeds
    fault::inject(&key_id, Fault::Signature, 1);
    let one = s.xrpc.post("com.atproto.repo.createRecord", &create(&a, "one-fault"), &a.auth()).await.ok();
    assert_eq!(failures(Purpose::Commit), c0 + 1);
    assert_eq!(stops.load(Ordering::SeqCst), 0);

    // two in a row (a flipped scalar): 503, nothing applied
    fault::inject(&key_id, Fault::Secret, 2);
    s.xrpc.post("com.atproto.repo.createRecord", &create(&a, "two-faults"), &a.auth()).await.err(503, "SignatureFault");
    assert_eq!(failures(Purpose::Commit), c0 + 3);
    // three within a minute: fail-stop
    assert_eq!(stops.load(Ordering::SeqCst), 1);
    assert_ne!(s.get_record(&a.did, "com.example.note", "two-faults").await.status, 200);
    let (_, rev) = s.latest_commit(&a.did).await;
    assert_eq!(Some(rev.as_str()), one["commit"]["rev"].as_str(), "the failed write moved the head");

    // the repo reloads from durable state and writes go on
    let after = s.xrpc.post("com.atproto.repo.createRecord", &create(&a, "after"), &a.auth()).await.ok();
    let after_rev = after["commit"]["rev"].as_str().unwrap().to_string();
    assert!(after_rev > rev);

    // the firehose: exactly the two good commits, both validly signed, in
    // an unbroken since/prevData chain
    let frames = sub.until(FH_TIMEOUT, |fs| fs.iter().any(|f| f.commit().is_some_and(|c| c.rev == after_rev))).await;
    let commits: Vec<CommitEvt> = frames.iter().filter_map(|f| f.commit()).filter(|c| c.repo == a.did).collect();
    assert_eq!(commits.len(), 2, "{:?}", commits.iter().map(|c| &c.rev).collect::<Vec<_>>());
    for c in &commits {
        c.commit_obj().verify(&vk).unwrap_or_else(|e| panic!("emitted a bad signature at {}: {e}", c.rev));
        assert!(c.ops.iter().all(|o| !o.path.ends_with("/two-faults")));
    }
    assert_eq!(commits[1].since.as_deref(), Some(commits[0].rev.as_str()));
    assert_eq!(commits[1].prev_data, Some(commits[0].commit_obj().data));
    // and what clients read
    let repo = s.get_repo(&a.did).await;
    repo.commit().verify(&vk).unwrap();
    let paths: Vec<String> = repo.entries().into_iter().map(|(p, _)| p).collect();
    assert!(paths.iter().any(|p| p.ends_with("/one-fault")) && paths.iter().any(|p| p.ends_with("/after")));
    assert!(!paths.iter().any(|p| p.ends_with("/two-faults")));

    // service-auth JWTs: one fault re-signed, two a 503 with no token
    let sa0 = failures(Purpose::ServiceAuth);
    let q = [("aud", "did:web:appview.example.com"), ("lxm", "app.bsky.feed.getTimeline")];
    fault::inject(&key_id, Fault::Signature, 1);
    let tok = s.xrpc.get("com.atproto.server.getServiceAuth", &q, &a.auth()).await.ok();
    let tok = tok["token"].as_str().unwrap();
    let (input, sig) = tok.rsplit_once('.').unwrap();
    let sig = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig).unwrap();
    assert!(vlsync_atproto::crypto::verify_k256(&key_id, input.as_bytes(), &sig).unwrap());
    fault::inject(&key_id, Fault::Signature, 2);
    let r = s.xrpc.get("com.atproto.server.getServiceAuth", &q, &a.auth()).await;
    r.err(503, "SignatureFault");
    assert!(r.json.get("token").is_none());
    assert_eq!(failures(Purpose::ServiceAuth), sa0 + 3);
    // still within the minute: each further fault fail-stops again
    assert_eq!(stops.load(Ordering::SeqCst), 4);
    // scrapeable
    let m = vlpds::metrics::render();
    for p in ["commit", "service_auth", "oauth_token", "key_load"] {
        assert!(m.contains(&format!("vlpds_signature_verify_failures_total{{purpose=\"{p}\"}}")), "{p} not exported");
    }
    vlsync_atproto::crypto::set_fail_stop_hook(None);
}
