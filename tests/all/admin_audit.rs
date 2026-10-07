//! Every admin write leaves an audit entry naming the operator
//! (src/xrpc/admin_audit.rs): one call of each method in
//! `admin_audit::AUDITED`, checked for its action, actor, how the actor got
//! in (`token` here; the proxy and forwards are in admin_proxy.rs), its
//! subject and detail, and that no password, code, address or message
//! text reached the log. A method added to AUDITED without a case here
//! fails the test.

use crate::common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vlpds::crypto::Keypair;
use vlpds::plc::mock::MockPlc;

const NODE: &str = "audit-node";
const ALICE: &str = "alice@example.com";

async fn entries(s: &TestServer) -> Vec<J> {
    let log = s.xrpc.get("vlpds.admin.getAuditLog", &[("limit", "200")], &Auth::Admin).await.ok();
    log["entries"].as_array().unwrap().clone()
}

fn count(all: &[J], action: &str) -> usize {
    all.iter().filter(|e| e["action"] == action).count()
}

/// Runs `call` and returns the `n` entries with `action` it wrote, newest
/// first; each one a token caller's, named `actor`.
async fn audited<F: std::future::Future<Output = J>>(
    s: &TestServer,
    action: &str,
    n: usize,
    actor: &str,
    call: F,
) -> (J, Vec<J>) {
    let before = count(&entries(s).await, action);
    let out = call.await;
    let all = entries(s).await;
    assert_eq!(count(&all, action), before + n, "{action}: {n} new entries expected");
    let new: Vec<J> = all.into_iter().filter(|e| e["action"] == action).take(n).collect();
    for e in &new {
        assert_eq!((&e["actor"], &e["auth"]), (&json!(actor), &json!("token")), "{e}");
        assert_eq!(e["node"], NODE, "{e}");
    }
    (out, new)
}

async fn post(s: &TestServer, nsid: &str, body: J) -> J {
    s.xrpc.post(nsid, &body, &Auth::Admin).await.ok()
}

fn account(did: &str) -> J {
    json!({"kind": "account", "did": did})
}

fn other(kind: &str, id: &str) -> J {
    json!({"kind": kind, "did": "", "id": id})
}

/// A node with PLC (and an operator recovery key) and a node id of its own,
/// so the crash hook below touches no other test.
async fn server(plc: &MockPlc) -> TestServer {
    let url = plc.url.clone();
    TestServer::spawn_with(move |c| {
        use_plc(c, url, Arc::new(Keypair::generate()));
        c.plc.recovery_did_key = Some(Keypair::generate().did_key());
        c.cluster.as_mut().unwrap().node_id = NODE.into();
    })
    .await
}

async fn layout(s: &TestServer) -> J {
    s.xrpc.get("vlpds.admin.getShardLayout", &[], &Auth::Admin).await.ok()
}

async fn settled(s: &TestServer) -> J {
    eventually(Duration::from_secs(20), || async {
        let l = layout(s).await;
        l["op"].is_null().then_some(l)
    })
    .await
    .expect("no reshard in flight")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn every_audited_admin_write_names_its_operator() {
    let plc = MockPlc::start().await;
    let s = server(&plc).await;
    let a = s.create_account("aud").await;
    // values that must never reach an entry
    let mut secrets: Vec<String> = vec![ADMIN_TOKEN.into(), a.email.clone(), a.password.clone()];
    let mut tested = Vec::new();

    for (nsid, actions) in vlpds::xrpc::admin_audit::AUDITED {
        tested.push(*nsid);
        match *nsid {
            "com.atproto.admin.deleteAccount" => {
                let v = s.create_account("auddel").await;
                secrets.push(v.email.clone());
                let (_, e) = audited(&s, "account.delete", 1, "admin", post(&s, nsid, json!({"did": v.did}))).await;
                assert_eq!(e[0]["subject"], account(&v.did));
                assert_eq!(e[0]["detail"], json!({"handle": v.handle, "retry": false}));
            }
            "com.atproto.admin.disableAccountInvites" | "com.atproto.admin.enableAccountInvites" => {
                let body = json!({"account": a.did, "note": "invite spam"});
                let (_, e) = audited(&s, actions[0], 1, "admin", post(&s, nsid, body)).await;
                assert_eq!((&e[0]["subject"], &e[0]["reason"]), (&account(&a.did), &json!("invite spam")));
            }
            "com.atproto.admin.disableInviteCodes" => {
                let body = json!({"accounts": [a.did]});
                let (_, e) = audited(&s, "invites.disable_codes", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], account(&a.did));
                assert_eq!(e[0]["detail"]["accounts"], json!([a.did]));
            }
            "com.atproto.admin.sendEmail" => {
                let body = json!({
                    "recipientDid": a.did, "senderDid": "did:example:mod", "subject": "About your account",
                    "content": "<p>please read this private notice</p>", "comment": "first warning",
                });
                let (_, e) = audited(&s, "mail.send", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!((&e[0]["subject"], &e[0]["reason"]), (&account(&a.did), &json!("first warning")));
                assert_eq!(e[0]["detail"], json!({"toDomain": "example.com", "purpose": "admin"}));
                secrets.extend(["About your account".into(), "private notice".into()]);
            }
            "com.atproto.admin.updateAccountEmail" => {
                // a typed name is kept, and labelled as typed
                let body = json!({"account": a.did, "email": "renamed-inbox@mail.example.org", "actor": ALICE});
                let (_, e) = audited(&s, "account.email", 1, ALICE, post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], account(&a.did));
                assert_eq!(e[0]["detail"], json!({"domain": "mail.example.org", "previousDomain": "example.com"}));
                secrets.push("renamed-inbox".into());
            }
            "com.atproto.admin.updateAccountHandle" => {
                let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("audren"));
                let body = json!({"did": a.did, "handle": handle});
                let (_, e) = audited(&s, "account.handle", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], account(&a.did));
                assert_eq!(e[0]["detail"], json!({"handle": handle, "previous": a.handle}));
            }
            "com.atproto.admin.updateAccountPassword" => {
                let pw = "correct-horse-battery-staple-9";
                secrets.push(pw.into());
                let body = json!({"did": a.did, "password": pw});
                let (_, e) = audited(&s, "account.password", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], account(&a.did));
                assert!(e[0].get("detail").is_none(), "{}", e[0]);
            }
            "com.atproto.admin.updateAccountSigningKey" => {
                let (r, e) =
                    audited(&s, "account.signing_key", 1, "admin", post(&s, nsid, json!({"did": a.did}))).await;
                assert_eq!(e[0]["subject"], account(&a.did));
                assert_eq!(e[0]["detail"], json!({"publicKey": r["signingKey"], "source": "generated"}));
            }
            "com.atproto.admin.updateSubjectStatus" => {
                let subject = json!({"$type": "com.atproto.admin.defs#repoRef", "did": a.did});
                for (attr, applied, action) in [
                    ("deactivated", true, "account.deactivate"),
                    ("deactivated", false, "account.activate"),
                    ("takedown", true, "takedown"),
                    ("takedown", false, "restore"),
                ] {
                    let body = json!({"subject": subject, attr: {"applied": applied}});
                    let (_, e) = audited(&s, action, 1, "admin", post(&s, nsid, body)).await;
                    assert_eq!(e[0]["subject"], account(&a.did));
                }
            }
            "com.atproto.server.createInviteCode" => {
                let body = json!({"useCount": 2, "forAccount": a.did});
                let (r, e) = audited(&s, "invites.create", 1, "admin", post(&s, nsid, body)).await;
                secrets.push(r["code"].as_str().unwrap().into());
                assert_eq!(e[0]["subject"], account(&a.did));
                assert_eq!((&e[0]["detail"]["codes"], &e[0]["detail"]["useCount"]), (&json!(1), &json!(2)));
            }
            "com.atproto.server.createInviteCodes" => {
                let b = s.create_account("audinv").await;
                let body = json!({"codeCount": 2, "useCount": 1, "forAccounts": [a.did, b.did]});
                let (r, e) = audited(&s, "invites.create", 1, "admin", post(&s, nsid, body)).await;
                for per in r["codes"].as_array().unwrap() {
                    secrets.extend(per["codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()));
                }
                assert!(e[0].get("subject").is_none(), "two accounts: no one subject {}", e[0]);
                assert_eq!(e[0]["detail"]["codes"], 4);
                assert_eq!(e[0]["detail"]["forAccounts"], json!([a.did, b.did]));
            }
            "vlpds.admin.abortReshard" => {
                let target = layout(&s).await["shards"][0]["id"].as_u64().unwrap();
                // the op's driver (this node) stalls after cloning until aborted
                let stuck = Arc::new(AtomicUsize::new(0));
                let st = stuck.clone();
                vlpds::reshard::set_crash_hook(
                    NODE,
                    Some(Arc::new(move |p: &str| p == "cloned" && st.fetch_add(1, Ordering::SeqCst) < 1_000_000)),
                );
                post(&s, "vlpds.admin.splitShard", json!({"shard": target})).await;
                eventually(Duration::from_secs(20), || async { (stuck.load(Ordering::SeqCst) >= 3).then_some(()) })
                    .await
                    .expect("the driver stalled after cloning");
                let (r, e) = audited(&s, "shard.abort", 1, "admin", post(&s, nsid, json!({}))).await;
                vlpds::reshard::set_crash_hook(NODE, None);
                assert_eq!(r["aborted"]["parents"], json!([target]), "{r}");
                assert_eq!(e[0]["subject"], other("shard", &target.to_string()));
                assert_eq!(e[0]["detail"]["parents"], json!([target]));
                // nothing to abort: no entry
                audited(&s, "shard.abort", 0, "admin", post(&s, nsid, json!({}))).await;
                settled(&s).await;
            }
            "vlpds.admin.addHandleDomain" | "vlpds.admin.removeHandleDomain" => {
                let domain = format!("{}.example.net", unique_name("aud"));
                if *nsid == "vlpds.admin.removeHandleDomain" {
                    post(&s, "vlpds.admin.addHandleDomain", json!({"domain": domain})).await;
                }
                let body = json!({"domain": domain, "force": true});
                let (_, e) = audited(&s, actions[0], 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], other("domain", &domain));
            }
            "vlpds.admin.backfillStorageStats" => {
                audited(&s, "storage.backfill", 0, "admin", post(&s, nsid, json!({"dryRun": true}))).await;
                let body = json!({"maxRequests": 100, "pagesPerSecond": 50});
                let (_, e) = audited(&s, "storage.backfill", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["detail"]["maxRequests"], 100);
            }
            "vlpds.admin.clearLockout" => {
                let body = json!({"did": a.did, "reason": "verified by phone"});
                let (_, e) = audited(&s, "lockout.clear", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], account(&a.did));
            }
            "vlpds.admin.createAccount" => {
                let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("audnew"));
                let email = format!("{}@example.com", unique_name("audnew"));
                secrets.push(email.clone());
                let body = json!({"handle": handle, "email": email, "reason": "support ticket"});
                let (r, e) = audited(&s, "account.create", 1, "admin", post(&s, nsid, body)).await;
                secrets.push(r["password"].as_str().unwrap().into());
                assert_eq!(e[0]["subject"], account(r["did"].as_str().unwrap()));
            }
            "vlpds.admin.createCase" | "vlpds.admin.updateCase" => {
                let body = json!({"source": "notice from example.org", "subjects": [account(&a.did)]});
                let (c, e) = audited(&s, "case.create", 1, "admin", post(&s, "vlpds.admin.createCase", body)).await;
                assert_eq!(e[0]["caseId"], c["id"]);
                let body = json!({"id": c["id"], "status": "dismissed"});
                let (_, e) = audited(&s, "case.update", 1, "admin", post(&s, "vlpds.admin.updateCase", body)).await;
                assert_eq!(e[0]["caseId"], c["id"]);
            }
            "vlpds.admin.ensureRecoveryKey" | "vlpds.admin.rotatePlcKeys" | "vlpds.admin.rewrapSecrets" => {
                audited(&s, actions[0], 0, "admin", post(&s, nsid, json!({"dryRun": true, "perSecond": 50}))).await;
                let (r, e) = audited(&s, actions[0], 1, "admin", post(&s, nsid, json!({"perSecond": 50}))).await;
                assert_eq!(e[0]["subject"], other("node", NODE));
                assert_eq!(e[0]["detail"]["shards"], r["scanned"].as_array().unwrap().len());
                assert_eq!(e[0]["detail"]["accounts"], r["accounts"]);
            }
            "vlpds.admin.kickSubscriber" => {
                let _sub = s.subscribe(None).await;
                let conn = eventually(Duration::from_secs(10), || async {
                    let r = s.xrpc.get("vlpds.admin.listFirehoseSubscribers", &[], &Auth::Admin).await.ok();
                    r["subscribers"][0]["conn"].as_str().map(String::from)
                })
                .await
                .expect("subscriber listed");
                let (_, e) = audited(&s, "firehose.kick", 1, "admin", post(&s, nsid, json!({"conn": conn}))).await;
                assert_eq!(e[0]["subject"], other("node", NODE));
                assert_eq!(e[0]["detail"], json!({"conn": conn}));
            }
            "vlpds.admin.mergeShards" | "vlpds.admin.splitShard" => {
                let l = settled(&s).await;
                let (left, right) = (&l["shards"][0]["id"], &l["shards"][1]["id"]);
                let body = if *nsid == "vlpds.admin.splitShard" {
                    json!({"shard": left, "wait": true})
                } else {
                    json!({"left": left, "right": right, "wait": true})
                };
                let (r, e) = audited(&s, actions[0], 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(r["done"], true, "{r}");
                assert_eq!(e[0]["subject"], other("shard", &left.to_string()));
                if *nsid == "vlpds.admin.mergeShards" {
                    assert_eq!(e[0]["detail"]["right"], *right);
                }
                // a refused plan is audited again, with why
                let bad = json!({"shard": 999_999});
                let refused = async {
                    let r = s.xrpc.post("vlpds.admin.splitShard", &bad, &Auth::Admin).await;
                    r.err(400, "InvalidRequest");
                    r.json
                };
                let (_, e) = audited(&s, "shard.split", 2, "admin", refused).await;
                assert_eq!(e[0]["detail"]["started"], e[1]["id"]);
                assert!(e[0]["detail"]["failed"].is_string(), "{}", e[0]);
            }
            "vlpds.admin.moderate" => {
                for action in ["takedown", "restore"] {
                    let body = json!({"kind": "account", "did": a.did, "action": action, "reason": "report 12"});
                    let (_, e) = audited(&s, action, 1, "admin", post(&s, nsid, body)).await;
                    assert_eq!((&e[0]["subject"], &e[0]["reason"]), (&account(&a.did), &json!("report 12")));
                }
            }
            "vlpds.admin.publishIdentity" => {
                let (_, e) = audited(&s, "identity.publish", 1, "admin", post(&s, nsid, json!({"did": a.did}))).await;
                assert_eq!(e[0]["subject"], account(&a.did));
                assert_eq!(e[0]["detail"]["syncPlc"], false);
            }
            "vlpds.admin.rebuildRepo" => {
                let dry = json!({"did": a.did, "dryRun": true});
                audited(&s, "repo.rebuild", 0, "admin", post(&s, nsid, dry)).await;
                let (r, e) = audited(&s, "repo.rebuild", 1, "admin", post(&s, nsid, json!({"did": a.did}))).await;
                assert_eq!(e[0]["subject"], account(&a.did));
                assert_eq!(e[0]["detail"]["rev"], r["rev"]);
            }
            "vlpds.admin.recountRepo" => {
                let (_, e) = audited(&s, "repo.recount", 1, "admin", post(&s, nsid, json!({"did": a.did}))).await;
                assert_eq!(e[0]["subject"], account(&a.did));
            }
            // needs --spaces and a live notify registration:
            // spaces_console.rs registration_removal_is_audited checks it
            "vlpds.admin.removeSpaceRegistration" => {}
            "vlpds.admin.requestCrawl" | "vlpds.admin.setCrawlers" => {
                // nothing listens there: the ask fails at once
                let relay = "http://127.0.0.1:9";
                let (_, e) = audited(&s, actions[0], 1, "admin", post(&s, nsid, json!({"relays": [relay]}))).await;
                assert_eq!(e[0]["subject"], other("config", "crawlers"));
                assert_eq!(e[0]["detail"]["relays"], json!([relay]));
            }
            "vlpds.admin.resetSecondFactors" => {
                let b = s.create_account("audrst").await;
                let body = json!({"did": b.did, "reason": "lost every factor"});
                // one entry before the reset, one after
                let (_, e) = audited(&s, "second_factors.reset", 2, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["detail"]["started"], e[1]["id"]);
            }
            "vlpds.admin.revokeAppPassword" => {
                let b = s.create_account("audapp").await;
                let r = s.xrpc.post("com.atproto.server.createAppPassword", &json!({"name": "bot"}), &b.auth()).await;
                secrets.push(r.ok()["password"].as_str().unwrap().into());
                let body = json!({"did": b.did, "name": "bot"});
                let (_, e) = audited(&s, "app_password.revoke", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], account(&b.did));
            }
            "vlpds.admin.revokeSessions" => {
                let b = s.create_account("audses").await;
                let (_, e) = audited(&s, "sessions.revoke", 1, "admin", post(&s, nsid, json!({"did": b.did}))).await;
                assert_eq!(e[0]["subject"], account(&b.did));
            }
            "vlpds.admin.setBlobQuota" => {
                let body = json!({"did": a.did, "bytes": 1_000_000});
                let (_, e) = audited(&s, "quota.set", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], account(&a.did));
            }
            "vlpds.admin.setFeatureLevel" => {
                let st = s.xrpc.get("vlpds.admin.getClusterStatus", &[], &Auth::Admin).await.ok();
                let level = st["version"]["active"].clone();
                let body = json!({"level": level});
                let (_, e) = audited(&s, "feature_level.set", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], other("config", "featureLevel"));
                assert_eq!(e[0]["detail"]["active"], level);
            }
            "vlpds.admin.updateRateLimits" => {
                let v = s.xrpc.get("vlpds.admin.getRateLimits", &[], &Auth::Admin).await.ok()["configVersion"].clone();
                let body = json!({
                    "config": {"limiters": {"repo-write-hour": {"points": 6000}}},
                    "ifVersion": v, "note": "raise for an import",
                });
                let (r, e) = audited(&s, "ratelimits.update", 1, "admin", post(&s, nsid, body)).await;
                assert_eq!(e[0]["subject"], other("config", "ratelimits"));
                assert_eq!(e[0]["reason"], "raise for an import");
                assert_eq!(e[0]["detail"], json!({"version": r["version"], "changes": 1}));
            }
            other => panic!("{other} is in AUDITED with no case here: add one"),
        }
    }
    assert_eq!(tested.len(), vlpds::xrpc::admin_audit::AUDITED.len());

    let log = serde_json::to_string(&entries(&s).await).unwrap();
    for x in &secrets {
        assert!(!log.contains(x.as_str()), "the audit log holds {x:?}");
    }
}

/// The moderation service's writes are audited as the service: its DID,
/// `auth: service`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moderation_service_writes_name_the_service() {
    let plc = MockPlc::start().await;
    let key = Keypair::generate();
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [key.did_key()],
        "verificationMethods": {"atproto": key.did_key()},
        "alsoKnownAs": ["at://mod.example.com"],
        "services": {},
        "prev": null,
    });
    let op = vlpds::plc::sign(op, &key).unwrap();
    let mod_did = vlpds::plc::did_for_genesis(&op).unwrap();
    let r = reqwest::Client::new().post(format!("{}/{mod_did}", plc.url)).json(&op).send().await.unwrap();
    assert!(r.status().is_success());
    let (url, m) = (plc.url.clone(), mod_did.clone());
    let s = TestServer::spawn_with(move |c| {
        c.plc_url = url;
        c.mod_service_did = Some(m);
    })
    .await;
    let pds = s.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok()["did"].clone();
    let a = s.create_account("audsvc").await;
    let calls = [
        (
            "com.atproto.admin.updateSubjectStatus",
            json!({"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": a.did}, "deactivated": {"applied": true}}),
            "account.deactivate",
        ),
        ("com.atproto.admin.disableAccountInvites", json!({"account": a.did}), "invites.disable_account"),
        (
            "com.atproto.admin.sendEmail",
            json!({"recipientDid": a.did, "senderDid": mod_did, "content": "hello"}),
            "mail.send",
        ),
    ];
    for (nsid, body, action) in calls {
        let jwt = vlpds::auth::service_auth_jwt(&key, &mod_did, pds.as_str().unwrap(), Some(nsid), 60).unwrap();
        s.xrpc.post(nsid, &body, &Auth::Bearer(jwt)).await.ok();
        let log = s.xrpc.get("vlpds.admin.getAuditLog", &[("did", a.did.as_str())], &Auth::Admin).await.ok();
        let e = log["entries"].as_array().unwrap().iter().find(|e| e["action"] == action).cloned();
        let e = e.unwrap_or_else(|| panic!("{action}: {log}"));
        assert_eq!((&e["actor"], &e["auth"]), (&json!(mod_did), &json!("service")), "{e}");
    }
}
