//! vlpds-specific sync 1.1 property test.
//!
//! Drives a seeded random mix of writes (createRecord / putRecord /
//! deleteRecord / applyWrites), including coalescing-heavy concurrent bursts
//! on one repo and across repos, then checks every firehose event:
//!
//! - seqs strictly increase (gaps allowed);
//! - every `#commit` is signed by the account key, its blocks hash correctly,
//!   and inverting its ops on the partial tree loaded from its blocks yields
//!   exactly `prevData`;
//! - per DID, `since` equals the previous event's rev and `prevData` equals
//!   the previous commit's data (the chain starts at the account's `#sync`);
//! - every acknowledged write appears in the commit it was acked with;
//! - replaying the ops reproduces both the client-side model and getRepo;
//! - replaying from cursor 0 is byte-identical, and a mid-stream cursor
//!   yields exactly the suffix.
//!
//! Seed: VLPDS_PROP_SEED (default fixed); size: VLPDS_PROP_SCALE (default 1).
use crate::common::*;
use rand::{seq::SliceRandom, Rng, SeedableRng};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

// Not app.bsky.*: the generated records ({text, createdAt} under arbitrary
// rkeys) aren't valid for those lexicons, which are validated on write as in
// the reference (repo/prepare.ts validateRecord). Sync semantics don't depend
// on the collection.
const COLLS: &[&str] = &["com.example.post", "com.example.like", "com.example.follow", "com.example.thing"];

type Model = BTreeMap<String, String>; // path -> record cid

#[derive(Debug, Clone)]
enum Op {
    Create {
        coll: String,
        rkey: Option<String>,
        text: String,
    },
    Put {
        coll: String,
        rkey: String,
        text: String,
    },
    Delete {
        coll: String,
        rkey: String,
    },
    Apply(Vec<ApplyW>),
    /// Must fail: create at an existing path.
    DupCreate {
        coll: String,
        rkey: String,
    },
    /// Must fail: delete with a wrong swapRecord.
    BadSwapDelete {
        coll: String,
        rkey: String,
    },
}

#[derive(Debug, Clone)]
enum ApplyW {
    Create { coll: String, rkey: String, text: String },
    Update { coll: String, rkey: String, text: String },
    Delete { coll: String, rkey: String },
}

fn rec(coll: &str, text: &str) -> J {
    json!({"$type": coll, "text": text, "createdAt": "2026-09-30T00:00:00.000Z"})
}

/// Acknowledged write: which commit it was acked with and the path effects.
#[derive(Debug, Clone)]
struct Ack {
    did: String,
    commit: String,
    rev: String,
    effects: Vec<(String, Option<String>)>, // path -> Some(cid) | None (deleted)
}

struct Gen {
    rng: rand::rngs::StdRng,
    n: u64,
}

impl Gen {
    fn rkey(&mut self) -> String {
        self.n += 1;
        format!("k{:05}{}", self.n, ["a", "b", "c", "d"][self.rng.gen_range(0..4)])
    }
    fn coll(&mut self) -> String {
        COLLS[self.rng.gen_range(0..COLLS.len())].to_string()
    }
    fn text(&mut self) -> String {
        format!("t{}", self.rng.gen::<u32>())
    }

    /// One op against `model`, touching only paths not in `busy` (so ops in a
    /// concurrent burst commute). Marks the paths it touches as busy.
    fn op(&mut self, model: &Model, busy: &mut std::collections::HashSet<String>, allow_fail: bool) -> Op {
        let free: Vec<&String> = model.keys().filter(|p| !busy.contains(*p)).collect();
        let pick_existing = |g: &mut Gen, busy: &mut std::collections::HashSet<String>| -> Option<(String, String)> {
            let p = free.choose(&mut g.rng)?.to_string();
            if busy.contains(&p) {
                return None;
            }
            busy.insert(p.clone());
            let (c, r) = p.split_once('/').unwrap();
            Some((c.to_string(), r.to_string()))
        };
        let roll = self.rng.gen_range(0..100);
        match roll {
            0..=29 => {
                let coll = self.coll();
                let text = self.text();
                if self.rng.gen_bool(0.3) {
                    Op::Create { coll, rkey: None, text }
                } else {
                    let rkey = self.rkey();
                    busy.insert(format!("{coll}/{rkey}"));
                    Op::Create { coll, rkey: Some(rkey), text }
                }
            }
            30..=44 => match pick_existing(self, busy) {
                Some((coll, rkey)) => Op::Put { text: self.text(), coll, rkey },
                None => {
                    let (coll, rkey) = (self.coll(), self.rkey());
                    busy.insert(format!("{coll}/{rkey}"));
                    Op::Put { text: self.text(), coll, rkey }
                }
            },
            45..=59 => match pick_existing(self, busy) {
                Some((coll, rkey)) => Op::Delete { coll, rkey },
                None => Op::Create { coll: self.coll(), rkey: None, text: self.text() },
            },
            60..=93 => {
                let n = self.rng.gen_range(1..=12);
                let mut ws = Vec::new();
                for _ in 0..n {
                    match self.rng.gen_range(0..3) {
                        0 => {
                            let (coll, rkey) = (self.coll(), self.rkey());
                            busy.insert(format!("{coll}/{rkey}"));
                            ws.push(ApplyW::Create { text: self.text(), coll, rkey });
                        }
                        1 => {
                            if let Some((coll, rkey)) = pick_existing(self, busy) {
                                ws.push(ApplyW::Update { text: self.text(), coll, rkey });
                            }
                        }
                        _ => {
                            if let Some((coll, rkey)) = pick_existing(self, busy) {
                                ws.push(ApplyW::Delete { coll, rkey });
                            }
                        }
                    }
                }
                if ws.is_empty() {
                    let (coll, rkey) = (self.coll(), self.rkey());
                    busy.insert(format!("{coll}/{rkey}"));
                    ws.push(ApplyW::Create { text: self.text(), coll, rkey });
                }
                Op::Apply(ws)
            }
            _ if allow_fail => match pick_existing(self, busy) {
                // the path must stay put for the duration of a burst, so it is marked busy too
                Some((coll, rkey)) if self.rng.gen_bool(0.5) => Op::DupCreate { coll, rkey },
                Some((coll, rkey)) => Op::BadSwapDelete { coll, rkey },
                None => Op::Create { coll: self.coll(), rkey: None, text: self.text() },
            },
            _ => Op::Create { coll: self.coll(), rkey: None, text: self.text() },
        }
    }
}

/// Executes one op. Ok(Some(ack)) for a successful write, Ok(None) for an
/// expected failure, Err for anything unexpected.
async fn exec(x: &Xrpc, a: &TestAccount, op: &Op) -> Result<Option<Ack>, String> {
    let auth = a.auth();
    let ack = |j: &J, effects| Ack {
        did: a.did.clone(),
        commit: j["commit"]["cid"].as_str().unwrap_or_default().to_string(),
        rev: j["commit"]["rev"].as_str().unwrap_or_default().to_string(),
        effects,
    };
    match op {
        Op::Create { coll, rkey, text } => {
            let mut body = json!({"repo": a.did, "collection": coll, "record": rec(coll, text)});
            if let Some(r) = rkey {
                body["rkey"] = json!(r);
            }
            let r = x.post("com.atproto.repo.createRecord", &body, &auth).await;
            if !r.is_ok() {
                return Err(format!("createRecord {coll}/{rkey:?}: {}", r.text()));
            }
            let path = r.json["uri"].as_str().unwrap().splitn(4, '/').nth(3).unwrap().to_string();
            Ok(Some(ack(&r.json, vec![(path, Some(r.json["cid"].as_str().unwrap().to_string()))])))
        }
        Op::Put { coll, rkey, text } => {
            let r = x
                .post(
                    "com.atproto.repo.putRecord",
                    &json!({"repo": a.did, "collection": coll, "rkey": rkey, "record": rec(coll, text)}),
                    &auth,
                )
                .await;
            if !r.is_ok() {
                return Err(format!("putRecord {coll}/{rkey}: {}", r.text()));
            }
            Ok(Some(ack(&r.json, vec![(format!("{coll}/{rkey}"), Some(r.json["cid"].as_str().unwrap().to_string()))])))
        }
        Op::Delete { coll, rkey } => {
            let r = x
                .post("com.atproto.repo.deleteRecord", &json!({"repo": a.did, "collection": coll, "rkey": rkey}), &auth)
                .await;
            if !r.is_ok() {
                return Err(format!("deleteRecord {coll}/{rkey}: {}", r.text()));
            }
            Ok(Some(ack(&r.json, vec![(format!("{coll}/{rkey}"), None)])))
        }
        Op::Apply(ws) => {
            let writes: Vec<J> = ws
                .iter()
                .map(|w| match w {
                    ApplyW::Create { coll, rkey, text } => {
                        json!({"$type": "com.atproto.repo.applyWrites#create", "collection": coll, "rkey": rkey, "value": rec(coll, text)})
                    }
                    ApplyW::Update { coll, rkey, text } => {
                        json!({"$type": "com.atproto.repo.applyWrites#update", "collection": coll, "rkey": rkey, "value": rec(coll, text)})
                    }
                    ApplyW::Delete { coll, rkey } => json!({"$type": "com.atproto.repo.applyWrites#delete", "collection": coll, "rkey": rkey}),
                })
                .collect();
            let r = x.post("com.atproto.repo.applyWrites", &json!({"repo": a.did, "writes": writes}), &auth).await;
            if !r.is_ok() {
                return Err(format!("applyWrites ({} writes): {}", ws.len(), r.text()));
            }
            let results = r.json["results"].as_array().cloned().unwrap_or_default();
            if results.len() != ws.len() {
                return Err(format!("applyWrites returned {} results for {} writes", results.len(), ws.len()));
            }
            let effects = ws
                .iter()
                .zip(results.iter())
                .map(|(w, res)| match w {
                    ApplyW::Create { coll, rkey, .. } | ApplyW::Update { coll, rkey, .. } => {
                        (format!("{coll}/{rkey}"), Some(res["cid"].as_str().unwrap_or_default().to_string()))
                    }
                    ApplyW::Delete { coll, rkey } => (format!("{coll}/{rkey}"), None),
                })
                .collect();
            Ok(Some(ack(&r.json, effects)))
        }
        Op::DupCreate { coll, rkey } => {
            let r = x
                .post(
                    "com.atproto.repo.createRecord",
                    &json!({"repo": a.did, "collection": coll, "rkey": rkey, "record": rec(coll, "dup")}),
                    &auth,
                )
                .await;
            if r.is_ok() || r.status >= 500 {
                return Err(format!("duplicate createRecord {coll}/{rkey} should fail with 4xx: {}", r.text()));
            }
            Ok(None)
        }
        Op::BadSwapDelete { coll, rkey } => {
            let wrong = "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm";
            let r = x
                .post(
                    "com.atproto.repo.deleteRecord",
                    &json!({"repo": a.did, "collection": coll, "rkey": rkey, "swapRecord": wrong}),
                    &auth,
                )
                .await;
            if !(r.status == 400 && r.error_name() == Some("InvalidSwap")) {
                return Err(format!(
                    "deleteRecord with wrong swapRecord {coll}/{rkey}: want 400 InvalidSwap, got {}",
                    r.text()
                ));
            }
            Ok(None)
        }
    }
}

/// Runs `ops` (account index, op) concurrently; results in the same order.
async fn concurrently(
    x: &Xrpc,
    accts: &[TestAccount],
    ops: Vec<(usize, Op)>,
) -> Vec<(usize, Result<Option<Ack>, String>)> {
    let hs: Vec<_> = ops
        .into_iter()
        .map(|(i, op)| {
            let (x, a) = (x.clone(), accts[i].clone());
            (i, tokio::spawn(async move { exec(&x, &a, &op).await }))
        })
        .collect();
    let mut out = Vec::new();
    for (i, h) in hs {
        out.push((i, h.await.unwrap()));
    }
    out
}

/// Client-side state: per-account models, acked writes, unexpected errors.
struct Run {
    models: Vec<Model>,
    acks: Vec<Ack>,
    errors: Vec<String>,
}

impl Run {
    fn new(accounts: usize) -> Run {
        Run { models: vec![Model::new(); accounts], acks: Vec::new(), errors: Vec::new() }
    }

    fn record(&mut self, i: usize, r: Result<Option<Ack>, String>, tag: &str) {
        match r {
            Ok(Some(a)) => {
                apply_ack(&mut self.models[i], &a);
                self.acks.push(a);
            }
            Ok(None) => {}
            Err(e) => self.errors.push(format!("{tag}: {e}")),
        }
    }

    fn assert_no_errors(&self) {
        assert!(
            self.errors.is_empty(),
            "{} write errors:\n  {}",
            self.errors.len(),
            self.errors.iter().take(30).cloned().collect::<Vec<_>>().join("\n  ")
        );
    }
}

fn apply_ack(model: &mut Model, ack: &Ack) {
    for (p, c) in &ack.effects {
        match c {
            Some(c) => model.insert(p.clone(), c.clone()),
            None => model.remove(p),
        };
    }
}

/// Per DID: the last event's rev and data.
#[derive(Default, Clone)]
struct Chain {
    rev: Option<String>,
    data: Option<Cid>,
}

/// Validates the whole event stream; returns (failures, per-DID repo state
/// from ops, per-DID commits).
fn validate_stream(
    frames: &[Frame],
    keys: &HashMap<String, k256::ecdsa::VerifyingKey>,
) -> (Vec<String>, HashMap<String, Model>, HashMap<String, Vec<CommitEvt>>) {
    let mut fails = Vec::new();
    let mut chains: HashMap<String, Chain> = HashMap::new();
    let mut state: HashMap<String, Model> = HashMap::new();
    let mut commits: HashMap<String, Vec<CommitEvt>> = HashMap::new();
    let mut last_seq = i64::MIN;
    for f in frames {
        if f.op != 1 {
            fails.push(format!("error frame on stream: {:?}", f.body.to_json()));
            continue;
        }
        let Some(seq) = f.seq() else {
            if f.kind() != "#info" {
                fails.push(format!("{} frame without seq", f.kind()));
            }
            continue;
        };
        if seq <= last_seq {
            fails.push(format!("seq not increasing: {last_seq} -> {seq}"));
        }
        last_seq = seq;
        let did = f.did().unwrap_or_default().to_string();
        let Some(key) = keys.get(&did) else { continue };
        match f.kind() {
            "#sync" => {
                let ev = f.sync().unwrap();
                let c = ev.commit_obj();
                if let Err(e) = c.verify(key) {
                    fails.push(format!("seq {seq} #sync {did}: bad signature: {e}"));
                }
                if c.rev != ev.rev {
                    fails.push(format!("seq {seq} #sync {did}: event rev {} != commit rev {}", ev.rev, c.rev));
                }
                let ch = chains.entry(did.clone()).or_default();
                if let Some(prev) = &ch.rev {
                    if ev.rev <= *prev {
                        fails.push(format!("seq {seq} #sync {did}: rev {} not after {prev}", ev.rev));
                    }
                }
                *ch = Chain { rev: Some(ev.rev.clone()), data: Some(c.data) };
                // a #sync resets the repo to what its blocks hold (account
                // creation's: empty)
                let tree = vlatproto::mst::Tree::load_from_blocks(&ev.blocks, c.data);
                let st = state.entry(did.clone()).or_default();
                st.clear();
                if let Ok(t) = tree {
                    t.walk(&mut |k, v| {
                        st.insert(String::from_utf8_lossy(k).to_string(), v.to_string());
                    });
                }
            }
            "#commit" => {
                let ev = f.commit().unwrap();
                let tag = format!("seq {seq} #commit {did} rev {}", ev.rev);
                if ev.blocks_roots.first() != Some(&ev.commit) {
                    fails.push(format!("{tag}: blocks CAR root {:?} != commit {}", ev.blocks_roots, ev.commit));
                }
                for (c, b) in &ev.blocks {
                    if Cid::dag_cbor(b) != *c {
                        fails.push(format!("{tag}: block {c} does not hash to its CID"));
                    }
                }
                let Some(cblock) = ev.blocks.get(&ev.commit) else {
                    fails.push(format!("{tag}: commit block missing"));
                    continue;
                };
                let c = CommitObj::decode(cblock).unwrap();
                if let Err(e) = c.verify(key) {
                    fails.push(format!("{tag}: bad signature: {e}"));
                }
                if c.did != did || c.rev != ev.rev || c.version != 3 {
                    fails.push(format!("{tag}: commit object did={} rev={} version={}", c.did, c.rev, c.version));
                }
                if ev.ops.is_empty() {
                    fails.push(format!("{tag}: no ops"));
                }
                if ev.too_big || ev.rebase {
                    fails.push(format!("{tag}: tooBig/rebase set"));
                }
                for op in &ev.ops {
                    if let Some(cid) = op.cid {
                        if !ev.blocks.contains_key(&cid) {
                            fails.push(format!("{tag}: record block {cid} for {} missing", op.path));
                        }
                    }
                }
                // chain continuity
                let ch = chains.entry(did.clone()).or_default();
                match &ch.rev {
                    None => fails.push(format!("{tag}: first event for DID is a #commit (expected #sync first)")),
                    Some(prev) => {
                        if ev.since.as_deref() != Some(prev.as_str()) {
                            fails.push(format!("{tag}: since {:?} != previous rev {prev}", ev.since));
                        }
                        if ev.rev <= *prev {
                            fails.push(format!("{tag}: rev not after previous {prev}"));
                        }
                    }
                }
                if ev.prev_data.is_none() {
                    fails.push(format!("{tag}: missing prevData"));
                } else if ch.data.is_some() && ev.prev_data != ch.data {
                    fails.push(format!("{tag}: prevData {:?} != previous data {:?}", ev.prev_data, ch.data));
                }
                // inversion
                match ev.invert() {
                    Ok(root) => {
                        if Some(root) != ev.prev_data {
                            fails.push(format!(
                                "{tag}: inverted root {root} != prevData {:?} (ops {:?})",
                                ev.prev_data, ev.ops
                            ));
                        }
                    }
                    Err(e) => fails.push(format!("{tag}: inversion failed: {e}")),
                }
                *ch = Chain { rev: Some(ev.rev.clone()), data: Some(c.data) };
                let st = state.entry(did.clone()).or_default();
                for op in &ev.ops {
                    match op.action.as_str() {
                        "create" | "update" => {
                            if op.action == "create" && st.contains_key(&op.path) {
                                fails.push(format!("{tag}: create of existing {}", op.path));
                            }
                            if op.action == "update"
                                && st.get(&op.path).map(|s| s.as_str()) != op.prev.map(|p| p.to_string()).as_deref()
                            {
                                fails.push(format!(
                                    "{tag}: update {} prev {:?} != current {:?}",
                                    op.path,
                                    op.prev,
                                    st.get(&op.path)
                                ));
                            }
                            st.insert(op.path.clone(), op.cid.map(|c| c.to_string()).unwrap_or_default());
                        }
                        "delete" => {
                            let cur = st.remove(&op.path);
                            if cur.as_deref() != op.prev.map(|p| p.to_string()).as_deref() {
                                fails.push(format!("{tag}: delete {} prev {:?} != current {cur:?}", op.path, op.prev));
                            }
                        }
                        a => fails.push(format!("{tag}: unknown action {a}")),
                    }
                }
                commits.entry(did.clone()).or_default().push(ev);
            }
            "#identity" | "#account" => {}
            other => fails.push(format!("seq {seq}: unexpected event type {other}")),
        }
    }
    (fails, state, commits)
}

fn seed() -> u64 {
    std::env::var("VLPDS_PROP_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x005e_ed11)
}

fn scale() -> usize {
    std::env::var("VLPDS_PROP_SCALE").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sync11_random_writes_firehose_invariants() {
    let seed = seed();
    eprintln!("sync11 property test seed={seed} (set VLPDS_PROP_SEED to reproduce)");
    let s = TestServer::spawn_with(|c| {
        c.workers = 4;
    })
    .await;
    let mut sub = s.subscribe(Some(0)).await;
    let mut g = Gen { rng: rand::rngs::StdRng::seed_from_u64(seed), n: 0 };

    let n_accounts = 5;
    let mut accts = Vec::new();
    for i in 0..n_accounts {
        accts.push(s.create_account(&format!("p{i}")).await);
    }
    let mut run = Run::new(n_accounts);

    // phase 1: sequential random ops across accounts
    for _ in 0..(150 * scale()) {
        let i = g.rng.gen_range(0..n_accounts);
        let op = g.op(&run.models[i], &mut Default::default(), true);
        let r = exec(&s.xrpc, &accts[i], &op).await;
        run.record(i, r, "phase1");
    }

    // phase 2: coalescing bursts on one hot repo (ops on distinct paths)
    let hot = 0;
    for burst in 0..(4 * scale()) {
        let mut busy = Default::default();
        let ops = (0..120).map(|_| (hot, g.op(&run.models[hot], &mut busy, burst % 2 == 1))).collect();
        for (i, r) in concurrently(&s.xrpc, &accts, ops).await {
            run.record(i, r, &format!("burst {burst}"));
        }
    }

    // phase 3: concurrent bursts across all repos at once
    for round in 0..(2 * scale()) {
        let mut ops = Vec::new();
        for i in 0..n_accounts {
            let mut busy = Default::default();
            ops.extend((0..40).map(|_| (i, g.op(&run.models[i], &mut busy, false))));
        }
        for (i, r) in concurrently(&s.xrpc, &accts, ops).await {
            run.record(i, r, &format!("cross-repo round {round}"));
        }
    }
    run.assert_no_errors();
    let Run { models, acks, .. } = run;

    // wait until every repo's latest commit has been seen on the firehose
    let mut want: HashMap<String, String> = HashMap::new();
    for a in &accts {
        want.insert(a.did.clone(), s.latest_commit(&a.did).await.0.to_string());
    }
    let frames = sub
        .until(Duration::from_secs(60), |fs| {
            let mut seen = std::collections::HashSet::new();
            for f in fs {
                if f.kind() == "#commit" {
                    if let (Some(d), Some(Value::Link(c))) = (f.did(), f.body.get("commit")) {
                        if want.get(d) == Some(&c.to_string()) {
                            seen.insert(d.to_string());
                        }
                    }
                }
            }
            seen.len() == want.len()
        })
        .await;

    let mut keys = HashMap::new();
    for a in &accts {
        keys.insert(a.did.clone(), s.signing_key(&a.did).await);
    }
    let (mut fails, state, commits) = validate_stream(&frames, &keys);

    // acked writes appear in the commit they were acked with
    let mut by_commit: HashMap<(String, String), &CommitEvt> = HashMap::new();
    for (d, cs) in &commits {
        for c in cs {
            by_commit.insert((d.clone(), c.commit.to_string()), c);
        }
    }
    for a in &acks {
        match by_commit.get(&(a.did.clone(), a.commit.clone())) {
            None => fails.push(format!(
                "acked commit {} (rev {}) for {} never appeared on the firehose",
                a.commit, a.rev, a.did
            )),
            Some(c) => {
                if c.rev != a.rev {
                    fails.push(format!("ack rev {} != firehose rev {} for commit {}", a.rev, c.rev, a.commit));
                }
                for (p, cid) in &a.effects {
                    match c.ops.iter().find(|o| &o.path == p) {
                        None => fails.push(format!("acked write {p} missing from commit {} ops", a.commit)),
                        Some(o) => {
                            let got = if o.action == "delete" { None } else { o.cid.map(|c| c.to_string()) };
                            if &got != cid {
                                fails
                                    .push(format!("acked write {p} = {cid:?} but commit op says {} {got:?}", o.action));
                            }
                        }
                    }
                }
            }
        }
    }

    // replayed ops == client model == getRepo
    for (i, a) in accts.iter().enumerate() {
        let from_ops = state.get(&a.did).cloned().unwrap_or_default();
        if from_ops != models[i] {
            let diff: Vec<_> = models[i]
                .iter()
                .filter(|(k, v)| from_ops.get(*k) != Some(*v))
                .map(|(k, _)| k.clone())
                .chain(from_ops.keys().filter(|k| !models[i].contains_key(*k)).cloned())
                .take(10)
                .collect();
            fails.push(format!(
                "{}: firehose replay ({} records) != acked-write model ({} records); e.g. {diff:?}",
                a.did,
                from_ops.len(),
                models[i].len()
            ));
        }
        let repo = s.get_repo(&a.did).await;
        if let Err(e) = repo.commit().verify(&keys[&a.did]) {
            fails.push(format!("{}: getRepo commit signature: {e}", a.did));
        }
        let exported: Model = repo.entries().into_iter().map(|(k, v)| (k, v.to_string())).collect();
        if exported != models[i] {
            fails.push(format!("{}: getRepo has {} records, model has {}", a.did, exported.len(), models[i].len()));
        }
        if let Some(last) = commits.get(&a.did).and_then(|c| c.last()) {
            if last.commit != repo.root {
                fails.push(format!("{}: getRepo root {} != last firehose commit {}", a.did, repo.root, last.commit));
            }
        }
    }

    // coalescing actually happened on the hot repo (informational unless absent entirely)
    let hot_commits = commits.get(&accts[hot].did).map(|c| c.len()).unwrap_or(0);
    let hot_acks = acks.iter().filter(|a| a.did == accts[hot].did).count();
    eprintln!("hot repo: {hot_acks} acked writes in {hot_commits} commits; total frames {}", frames.len());

    // replay determinism: cursor 0 yields byte-identical frames
    let mut replay = s.subscribe(Some(0)).await;
    let last_seq = frames.iter().filter_map(|f| f.seq()).max().unwrap();
    let again = replay
        .until(Duration::from_secs(30), |fs| fs.last().and_then(|f| f.seq()).map(|q| q >= last_seq).unwrap_or(false))
        .await;
    let live: Vec<&Vec<u8>> = frames.iter().filter(|f| f.seq().is_some()).map(|f| &f.raw).collect();
    let rep: Vec<&Vec<u8>> = again.iter().filter(|f| f.seq().is_some()).map(|f| &f.raw).collect();
    if live != rep {
        fails.push(format!("replay from cursor 0 differs from live stream ({} vs {} frames)", live.len(), rep.len()));
    }

    // mid-stream cursor yields exactly the suffix
    let seqs: Vec<i64> = frames.iter().filter_map(|f| f.seq()).collect();
    let mid = seqs[seqs.len() / 2];
    let mut tail = s.subscribe(Some(mid)).await;
    let got = tail
        .until(Duration::from_secs(30), |fs| fs.last().and_then(|f| f.seq()).map(|q| q >= last_seq).unwrap_or(false))
        .await;
    let got_seqs: Vec<i64> = got.iter().filter_map(|f| f.seq()).collect();
    let want_seqs: Vec<i64> = seqs.iter().copied().filter(|q| *q > mid).collect();
    if got_seqs != want_seqs {
        fails.push(format!(
            "cursor {mid}: got {} events (first {:?}), want {} (first {:?})",
            got_seqs.len(),
            got_seqs.first(),
            want_seqs.len(),
            want_seqs.first()
        ));
    }

    assert!(
        fails.is_empty(),
        "seed {seed}: {} sync 1.1 violations:\n  {}",
        fails.len(),
        fails.iter().take(40).cloned().collect::<Vec<_>>().join("\n  ")
    );
}

/// Same invariants, smaller, with many seeds: catches shape-dependent MST
/// proof bugs that a single seed can miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sync11_many_seeds_single_repo_bursts() {
    let s = TestServer::spawn().await;
    let mut sub = s.subscribe(Some(0)).await;
    let a = s.create_account("seeds").await;
    let accts = [a.clone()];
    let mut run = Run::new(1);
    for sd in 0..(12 * scale() as u64) {
        let mut g = Gen { rng: rand::rngs::StdRng::seed_from_u64(seed() ^ (sd * 7919)), n: sd * 100_000 };
        let mut busy = Default::default();
        let k = g.rng.gen_range(5..60);
        let ops = (0..k).map(|_| (0, g.op(&run.models[0], &mut busy, false))).collect();
        for (i, r) in concurrently(&s.xrpc, &accts, ops).await {
            run.record(i, r, &format!("seed {sd}"));
        }
    }
    run.assert_no_errors();
    let head = s.latest_commit(&a.did).await.0;
    let frames = sub
        .until(Duration::from_secs(60), |fs| {
            fs.last()
                .map(|f| f.kind() == "#commit" && matches!(f.body.get("commit"), Some(Value::Link(c)) if *c == head))
                .unwrap_or(false)
        })
        .await;
    let mut keys = HashMap::new();
    keys.insert(a.did.clone(), s.signing_key(&a.did).await);
    let (fails, state, _) = validate_stream(&frames, &keys);
    assert!(
        fails.is_empty(),
        "{} violations:\n  {}",
        fails.len(),
        fails.iter().take(40).cloned().collect::<Vec<_>>().join("\n  ")
    );
    assert_eq!(state.get(&a.did).cloned().unwrap_or_default(), run.models[0], "firehose replay != model");
}

fn set(body: &mut Value, key: &str, v: Value) {
    if let Value::Map(m) = body {
        for (k, x) in m.iter_mut() {
            if k == key {
                *x = v;
                return;
            }
        }
    }
    panic!("no {key}");
}

/// The validator is not vacuous: tampered events are reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_detects_tampering() {
    let s = TestServer::spawn().await;
    let mut sub = s.subscribe(Some(0)).await;
    let a = s.create_account("tamper").await;
    // enough records that the tree has interior nodes
    for i in 0..40 {
        s.post(&a, &format!("p{i}")).await;
    }
    let last = s.post(&a, "last").await;
    let head = Cid::parse(last.commit_cid.as_deref().unwrap()).unwrap();
    let frames = sub
        .until(FH_TIMEOUT, |fs| {
            fs.last().map(|f| matches!(f.body.get("commit"), Some(Value::Link(c)) if *c == head)).unwrap_or(false)
        })
        .await;
    let mut keys = HashMap::new();
    keys.insert(a.did.clone(), s.signing_key(&a.did).await);
    let (fails, _, _) = validate_stream(&frames, &keys);
    assert!(fails.is_empty(), "untampered stream failed: {fails:?}");

    let idx = frames.len() - 1;
    // 1. wrong since
    let mut t = frames.clone();
    set(&mut t[idx].body, "since", Value::Text("2222222222222".into()));
    assert!(validate_stream(&t, &keys).0.iter().any(|f| f.contains("since")), "since tamper not detected");
    // 2. wrong prevData
    let mut t = frames.clone();
    set(&mut t[idx].body, "prevData", Value::Link(Cid::dag_cbor(b"nope")));
    assert!(validate_stream(&t, &keys).0.iter().any(|f| f.contains("prevData")), "prevData tamper not detected");
    // 3. drop an MST node from blocks (inversion must fail)
    let ev = frames[idx].commit().unwrap();
    let data = ev.commit_obj().data;
    let mut car = Vec::new();
    vlatproto::car::write_header(&mut car, &ev.commit);
    for (c, b) in &ev.blocks {
        if *c != data || ev.blocks.len() < 3 {
            vlatproto::car::write_block(&mut car, c, b);
        }
    }
    let mut t = frames.clone();
    set(&mut t[idx].body, "blocks", Value::Bytes(car));
    assert!(
        validate_stream(&t, &keys).0.iter().any(|f| f.contains("inversion") || f.contains("inverted")),
        "missing proof block not detected"
    );
    // 4. wrong signing key
    let other = vlatproto::crypto::Keypair::generate();
    let mut k2 = HashMap::new();
    k2.insert(a.did.clone(), k256::ecdsa::VerifyingKey::from_sec1_bytes(&other.public_key_sec1()).unwrap());
    assert!(validate_stream(&frames, &k2).0.iter().any(|f| f.contains("signature")), "bad signature not detected");
    // 5. op claims a different record CID than the tree holds
    let mut t = frames.clone();
    if let Some(Value::Array(ops)) = t[idx].body.get("ops").cloned() {
        let mut ops = ops;
        set(&mut ops[0], "cid", Value::Link(Cid::dag_cbor(b"other record")));
        set(&mut t[idx].body, "ops", Value::Array(ops));
    } else {
        panic!("no ops");
    }
    assert!(
        validate_stream(&t, &keys).0.iter().any(|f| f.contains("inversion") || f.contains("op says")),
        "op cid tamper not detected"
    );
    // 6. a dropped event breaks the per-DID chain
    let mut t = frames.clone();
    t.remove(idx - 1);
    assert!(
        validate_stream(&t, &keys).0.iter().any(|f| f.contains("since") || f.contains("prevData")),
        "dropped event not detected"
    );
    // 7. reordered events (seq goes backwards)
    let mut t = frames.clone();
    t.swap(idx - 1, idx);
    assert!(validate_stream(&t, &keys).0.iter().any(|f| f.contains("seq not increasing")), "reordering not detected");
}
