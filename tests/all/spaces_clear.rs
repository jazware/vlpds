//! com.atproto.space.clearRecords (`--spaces`; src/xrpc/space.rs,
//! `crate::space::repo::clear`): a repo emptied at a new rev with no ops,
//! the authority told, the `delete` grants it needs, and the published
//! records an authority's own repo keeps.

use crate::common::spaces::{commit_of, SpaceClient};
use crate::common::*;
use std::time::Duration;

const TYPE: &str = "com.example.group";
const POST: &str = "com.example.post";
const NOTE: &str = "com.example.note";
const EMPTY: &str = "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad";
const OWNER: &str =
    "space:com.example.group?collection=com.example.post&action=read&action=create&action=delete&manage=create&manage=update&manage=delete";

fn member_scope(delete: &[&str]) -> String {
    let mut s =
        format!("space:com.example.group?authority=*&collection={POST}&collection={NOTE}&action=read&action=create");
    for c in delete {
        s.push_str(&format!(" space:com.example.group?authority=*&collection={c}&action=delete"));
    }
    s
}

fn rec(collection: &str, text: &str) -> J {
    json!({"$type": collection, "text": text, "createdAt": "2026-10-01T00:00:00.000Z"})
}

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

async fn latest(c: &SpaceClient, space: &str) -> (String, String) {
    let r = c.get("com.atproto.space.getLatestCommit", &[("space", space), ("repo", &c.did)]).await.ok();
    let commit = commit_of(&r["commit"]);
    (commit.rev, hex::encode(commit.data))
}

async fn clear(c: &SpaceClient, space: &str, repo: &str) -> Resp {
    c.post("com.atproto.space.clearRecords", json!({"space": space, "repo": repo})).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_empties_a_members_repo_and_tells_the_authority() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "scl1", OWNER).await;
    let space = owner.create_space(TYPE, "c1").await;
    let member = SpaceClient::new(&s, "scl2", &member_scope(&[])).await;
    owner
        .post(
            "com.atproto.memberspace.putMember",
            json!({"space": space, "did": member.did, "read": true, "write": true}),
        )
        .await
        .ok();
    // nothing yet: a no-op
    clear(&member, &space, &member.did).await.ok();
    for (c, k) in [(POST, "a"), (POST, "b"), (NOTE, "n")] {
        member.create_record(&space, c, Some(k), rec(c, k)).await.ok();
    }
    let (rev0, data0) = latest(&member, &space).await;
    assert_ne!(data0, EMPTY);

    // a delete grant for every collection held
    clear(&member, &space, &member.did).await.err(403, "ScopeMissingError");
    let posts =
        SpaceClient::for_account(&s, &member.did, &member.handle, &member.session_jwt, &member_scope(&[POST])).await;
    clear(&posts, &space, &member.did).await.err(403, "ScopeMissingError");
    let all =
        SpaceClient::for_account(&s, &member.did, &member.handle, &member.session_jwt, &member_scope(&[POST, NOTE]))
            .await;
    // only one's own repo
    clear(&all, &space, &owner.did).await.err_status(403);
    assert_eq!(latest(&member, &space).await, (rev0.clone(), data0), "refusals change nothing");

    assert_eq!(clear(&all, &space, &member.did).await.ok(), json!({}));
    let (rev1, data1) = latest(&member, &space).await;
    assert!(rev1 > rev0, "a new rev");
    assert_eq!(data1, EMPTY, "the empty repo's digest");
    let r = member.get("com.atproto.space.listRecords", &[("space", &space), ("repo", &member.did)]).await.ok();
    assert_eq!(r["records"], json!([]));
    // ops from before: the clear's commit alone
    let r = member
        .get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &member.did), ("since", &rev0)])
        .await
        .ok();
    assert_eq!(r["ops"], json!([]), "{r}");
    assert_eq!(commit_of(&r["commit"]).rev, rev1);
    let r = member.get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &member.did)]).await.ok();
    assert_eq!(r["ops"], json!([]), "the oplog is cleared: {r}");

    // the authority hears of it: still a writer, at the new rev
    let cred = owner.credential(&space).await;
    let mut seen = J::Null;
    for _ in 0..100 {
        let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
        seen = r.ok();
        let hit = seen["repos"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["did"] == json!(member.did) && w["repoRev"] == json!(rev1));
        if hit {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let w = seen["repos"].as_array().unwrap().iter().find(|w| w["did"] == json!(member.did)).cloned();
    assert_eq!(w.as_ref().map(|w| w["repoRev"].clone()), Some(json!(rev1)), "{seen}");

    // clearing an empty repo: no new rev
    clear(&all, &space, &member.did).await.ok();
    assert_eq!(latest(&member, &space).await.0, rev1);
    // and a later write repopulates it
    member.create_record(&space, POST, Some("c"), rec(POST, "c")).await.ok();
    let (rev2, data2) = latest(&member, &space).await;
    assert!(rev2 > rev1 && data2 != EMPTY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_authority_keeps_its_published_records() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "scl3", OWNER).await;
    let r = owner
        .post(
            "com.atproto.space.createSpace",
            json!({"spaceType": TYPE, "skey": "pub", "policy": {"$type": "com.atproto.memberspace.policy", "publishPolicy": true}}),
        )
        .await;
    let space = r.ok()["uri"].as_str().unwrap().to_string();
    owner.create_record(&space, POST, Some("a"), rec(POST, "a")).await.ok();
    owner.create_record(&space, POST, Some("b"), rec(POST, "b")).await.ok();
    let (rev0, _) = latest(&owner, &space).await;
    // the kept collection takes no grant (OWNER has none for it)
    clear(&owner, &space, &owner.did).await.ok();
    let (rev1, data1) = latest(&owner, &space).await;
    assert!(rev1 > rev0);
    // listRecords is per collection: the posts are gone, the policy stays
    let posts = owner
        .get("com.atproto.space.listRecords", &[("space", &space), ("repo", &owner.did), ("collection", POST)])
        .await;
    assert_eq!(posts.ok()["records"], json!([]));
    let p = owner
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &owner.did), ("collection", "com.atproto.space.policy"), ("rkey", "self")],
        )
        .await
        .ok();
    let cid = p["cid"].as_str().unwrap().to_string();
    // the digest covers the policy record alone
    let mut h = vlpds::space::lthash::LtHash::default();
    h.add(&vlpds::space::commit::element("com.atproto.space.policy", "self", &cid));
    assert_eq!(data1, hex::encode(h.digest()));
    assert_ne!(data1, EMPTY);
    // nothing left to clear: no new rev
    clear(&owner, &space, &owner.did).await.ok();
    assert_eq!(latest(&owner, &space).await.0, rev1);
}
