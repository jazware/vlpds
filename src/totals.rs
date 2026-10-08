//! Account totals for the operator dashboard (DESIGN.md "Account totals"):
//! accounts by status, and repos by the UTC day of their latest commit,
//! kept exact under every change instead of counted by a periodic scan.
//!
//! Each slot's totals are one row, `0x01 ‖ slot ‖ T/`, so they split, merge
//! and move with the slot like every other key. A repo's worker knows its
//! account's status and head before and after each change, and puts the
//! [`Delta`] on the log entry. The sequencer (the one place a shard's
//! entries are ordered) folds it into the shard's in-memory totals and
//! appends the slot's new row to the entry's mutations, so the row lands in
//! the same batch as the change. Rows are absolute, not increments: replaying
//! an entry twice is harmless, as for every other mutation.
//!
//! A shard opens without reading the rows (one seek per slot through every
//! L0 and sorted run: seconds after a day of writes). Until the background
//! load is done, a change is written as a delta row keyed by its entry's
//! seq, `0x01 ‖ slot ‖ T/ ‖ seq`, which is just as idempotent; the load adds
//! a slot's delta rows to its row, and the slot's next row write deletes
//! them.
//!
//! Active accounts are also counted by their handle's suffix (the handle
//! without its first label), and `vlpds.admin.listHandleDomains` maps each
//! suffix to the longest served domain it is or is under when it reads. Why
//! the suffix and not the served domain: which domains are served changes
//! at runtime and reaches each node a moment apart, so a count keyed by
//! domain would need every slot recounted, in log order, on every add and
//! remove. A suffix depends only on the account row, so it moves, splits
//! and replays like the rest of the row. A row written before suffixes were
//! counted lacks them: the load counts that slot's account rows from the
//! same snapshot as its rows, and writes the result back.
//!
//! The console's account filter counts ride along: unconfirmed email, and
//! active without a second factor, are flags of the account row
//! ([`flags_of`]), so they move with the same account deltas. "Second
//! factor" is what the row records (`totpEnabled`, `emailAuthFactorAt`,
//! `passkeys`): the fast-path flags sign-in already keeps, plus the passkey
//! count each passkey change writes. A row written before the flags were
//! counted is seeded from the account rows like the suffixes.

use crate::state::{self, Account, Head};
use bytes::{BufMut, Bytes};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use vlatproto::tid::Tid;
use vlsync_store::segment::Mutation;

pub const STATUSES: [&str; 5] = ["active", "deactivated", "takendown", "suspended", "other"];

/// (label, days): a window counts the repos whose latest commit's UTC day
/// is at most `days` days before today's, so "1d" is yesterday and today.
pub const WINDOWS: [(&str, u32); 3] = [("1d", 1), ("7d", 7), ("30d", 30)];

/// Rows of slots seeded by the load written per log entry.
const SAVE_PER_ENTRY: usize = 512;

/// Days a row keeps, past the widest window: a shard's next owner whose
/// clock is a little behind still finds every day of its windows.
const KEEP_DAYS: u32 = 32;

const DAY_MICROS: u64 = 86_400_000_000;

pub const FAMILY: &[u8] = b"T/";

pub fn key(slot: u16) -> Vec<u8> {
    vlsync_store::keys::slot_family(slot, FAMILY)
}

pub fn status_index(status: Option<&str>) -> u8 {
    match status {
        None => 0,
        Some(s) => STATUSES[1..4].iter().position(|k| *k == s).map_or(4, |i| i as u8 + 1),
    }
}

pub fn day_of(rev: Tid) -> u32 {
    (rev.micros() / DAY_MICROS) as u32
}

pub fn today() -> u32 {
    (vlatproto::tid::now_micros() / DAY_MICROS) as u32
}

fn cutoff(today: u32) -> u32 {
    today.saturating_sub(KEEP_DAYS)
}

pub const UNCONFIRMED: u8 = 1;
/// Active, with no second factor on the row.
pub const NO_2FA: u8 = 2;

/// The filter flags of an account row's parts.
pub fn flags(status: Option<&str>, email_confirmed: bool, extra: &serde_json::Map<String, serde_json::Value>) -> u8 {
    let mut f = 0;
    if !email_confirmed {
        f |= UNCONFIRMED;
    }
    let second = extra.get("totpEnabled").and_then(|v| v.as_bool()) == Some(true)
        || extra.get("emailAuthFactorAt").is_some_and(|v| v.is_string())
        || extra.get("passkeys").and_then(|v| v.as_u64()).is_some_and(|n| n > 0);
    if status.is_none() && !second {
        f |= NO_2FA;
    }
    f
}

pub fn flags_of(account: &Account) -> u8 {
    flags(account.status.as_deref(), account.email_confirmed, &account.extra)
}

/// What one repo counts toward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepoKey {
    pub status: u8,
    pub day: u32,
    pub flags: u8,
}

impl RepoKey {
    /// None: the account is gone (deleted).
    pub fn of(account: &Account, head: &Head) -> Option<RepoKey> {
        (account.status.as_deref() != Some("deleted")).then(|| RepoKey {
            status: status_index(account.status.as_deref()),
            day: day_of(head.rev),
            flags: flags_of(account),
        })
    }
}

/// The handle suffix an account counts under: active accounts only.
pub fn suffix_of(account: &Account) -> Option<Box<str>> {
    account.status.is_none().then(|| crate::handle_domains::handle_suffix(&account.handle)).flatten()
}

/// What an account counts toward, for changes that may touch its handle
/// or status.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counted {
    pub repo: Option<RepoKey>,
    pub suffix: Option<Box<str>>,
}

impl Counted {
    pub fn of(account: &Account, head: &Head) -> Counted {
        Counted { repo: RepoKey::of(account, head), suffix: suffix_of(account) }
    }
}

/// One repo's change: before -> after (None = no account).
#[derive(Clone, Debug)]
pub struct Delta {
    pub slot: u16,
    pub before: Option<RepoKey>,
    pub after: Option<RepoKey>,
    /// The suffix it counts under, before -> after, when that changed.
    pub suffix: Option<(Option<Box<str>>, Option<Box<str>>)>,
}

impl Delta {
    /// A change that leaves the handle and status alone (a commit). None
    /// when nothing it counts toward changed.
    pub fn new(did: &str, before: Option<RepoKey>, after: Option<RepoKey>) -> Option<Delta> {
        (before != after).then(|| Delta { slot: vlsync_store::slots::slot_of(did), before, after, suffix: None })
    }

    pub fn account(did: &str, before: Counted, after: Counted) -> Option<Delta> {
        let suffix = (before.suffix != after.suffix).then_some((before.suffix, after.suffix));
        (before.repo != after.repo || suffix.is_some()).then(|| Delta {
            slot: vlsync_store::slots::slot_of(did),
            before: before.repo,
            after: after.repo,
            suffix,
        })
    }

    /// Changes nothing: the entry only carries rows of slots the load
    /// seeded.
    pub fn save_seeded() -> Delta {
        Delta { slot: 0, before: None, after: None, suffix: None }
    }

    fn changes(&self) -> bool {
        self.before != self.after || self.suffix.is_some()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// By [`STATUSES`] index.
    pub accounts: [i64; 5],
    /// (UTC day, repos whose latest commit is on it), ascending; days before
    /// the cutoff linger until the row's next write but are never counted.
    pub days: Vec<(u32, i64)>,
    /// Active accounts by handle suffix ([`suffix_of`]).
    pub suffixes: BTreeMap<Box<str>, i64>,
    /// Accounts with [`UNCONFIRMED`], and with [`NO_2FA`].
    pub unconfirmed: i64,
    pub no2fa: i64,
}

impl Totals {
    fn add(&mut self, k: RepoKey, n: i64, cutoff: u32) {
        self.accounts[k.status as usize] += n;
        if k.flags & UNCONFIRMED != 0 {
            self.unconfirmed += n;
        }
        if k.flags & NO_2FA != 0 {
            self.no2fa += n;
        }
        if k.day < cutoff {
            return;
        }
        match self.days.binary_search_by_key(&k.day, |d| d.0) {
            Ok(i) => {
                self.days[i].1 += n;
                if self.days[i].1 == 0 {
                    self.days.remove(i);
                }
            }
            Err(i) => self.days.insert(i, (k.day, n)),
        }
    }

    fn add_suffix(&mut self, s: &str, n: i64) {
        match self.suffixes.get_mut(s) {
            Some(c) => {
                *c += n;
                if *c == 0 {
                    self.suffixes.remove(s);
                }
            }
            None => _ = self.suffixes.insert(s.into(), n),
        }
    }

    fn add_delta(&mut self, d: &Delta, cut: u32) {
        for (k, n) in [(d.before, -1), (d.after, 1)] {
            if let Some(k) = k {
                self.add(k, n, cut);
            }
        }
        if let Some((before, after)) = &d.suffix {
            for (s, n) in [(before, -1), (after, 1)] {
                if let Some(s) = s {
                    self.add_suffix(s, n);
                }
            }
        }
    }

    fn prune(&mut self, cutoff: u32) {
        self.days.retain(|d| d.0 >= cutoff);
    }

    pub fn merge(&mut self, o: &Totals) {
        self.merge_counts(o);
        for (s, n) in &o.suffixes {
            self.add_suffix(s, *n);
        }
        self.unconfirmed += o.unconfirmed;
        self.no2fa += o.no2fa;
    }

    /// [`Totals::merge`] without what a seed counts (the suffixes and flags).
    pub fn merge_counts(&mut self, o: &Totals) {
        for (a, b) in self.accounts.iter_mut().zip(o.accounts) {
            *a += b;
        }
        for &(day, n) in &o.days {
            match self.days.binary_search_by_key(&day, |d| d.0) {
                Ok(i) => self.days[i].1 += n,
                Err(i) => self.days.insert(i, (day, n)),
            }
        }
        self.days.retain(|d| d.1 != 0);
    }

    /// Every account has a repo.
    pub fn repos(&self) -> i64 {
        self.accounts.iter().sum()
    }

    /// Repos whose latest commit is within `days` UTC days of `today` (or later).
    pub fn written_within(&self, days: u32, today: u32) -> i64 {
        let from = today.saturating_sub(days);
        self.days.iter().filter(|d| d.0 >= from).map(|d| d.1).sum()
    }

    /// Zigzag varints: the five status counts, the number of days, then
    /// per day its distance from the previous one (the first: absolute)
    /// and its count; then the number of suffixes, and per suffix its
    /// length, its bytes and its count; then the unconfirmed and no-2FA
    /// counts. ~100 bytes for a slot active on every day kept, plus each
    /// suffix.
    pub fn encode(&self) -> Bytes {
        let suffix_bytes: usize = self.suffixes.keys().map(|s| s.len() + 4).sum();
        let mut b = Vec::with_capacity(27 + 6 * self.days.len() + suffix_bytes);
        for a in self.accounts {
            put_varint(&mut b, zigzag(a));
        }
        put_varint(&mut b, self.days.len() as u64);
        let mut prev = 0u32;
        for &(day, n) in &self.days {
            put_varint(&mut b, (day - prev) as u64);
            put_varint(&mut b, zigzag(n));
            prev = day;
        }
        put_varint(&mut b, self.suffixes.len() as u64);
        for (s, n) in &self.suffixes {
            put_varint(&mut b, s.len() as u64);
            b.extend_from_slice(s.as_bytes());
            put_varint(&mut b, zigzag(*n));
        }
        put_varint(&mut b, zigzag(self.unconfirmed));
        put_varint(&mut b, zigzag(self.no2fa));
        b.into()
    }

    pub fn decode(b: &[u8]) -> anyhow::Result<Totals> {
        Ok(Totals::decode_row(b)?.0)
    }

    /// The totals, and whether the row counts suffixes and flags (rows
    /// written before those were counted end after the days, or after the
    /// suffixes).
    pub fn decode_row(mut b: &[u8]) -> anyhow::Result<(Totals, bool)> {
        let mut t = Totals::default();
        for a in &mut t.accounts {
            *a = unzigzag(get_varint(&mut b)?);
        }
        let n = get_varint(&mut b)? as usize;
        anyhow::ensure!(n <= 1 << 16, "totals row: {n} days");
        let mut day = 0u32;
        for _ in 0..n {
            day = day
                .checked_add(u32::try_from(get_varint(&mut b)?)?)
                .ok_or_else(|| anyhow::anyhow!("totals row: day overflow"))?;
            t.days.push((day, unzigzag(get_varint(&mut b)?)));
        }
        if b.is_empty() {
            return Ok((t, false));
        }
        let n = get_varint(&mut b)? as usize;
        anyhow::ensure!(n <= 1 << 20, "totals row: {n} suffixes");
        for _ in 0..n {
            let len = get_varint(&mut b)? as usize;
            anyhow::ensure!(len <= b.len(), "totals row: truncated suffix");
            let (s, rest) = b.split_at(len);
            let s = std::str::from_utf8(s).map_err(|_| anyhow::anyhow!("totals row: suffix not UTF-8"))?;
            b = rest;
            t.suffixes.insert(s.into(), unzigzag(get_varint(&mut b)?));
        }
        if b.is_empty() {
            return Ok((t, false));
        }
        t.unconfirmed = unzigzag(get_varint(&mut b)?);
        t.no2fa = unzigzag(get_varint(&mut b)?);
        anyhow::ensure!(b.is_empty(), "totals row: {} trailing bytes", b.len());
        Ok((t, true))
    }
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    (v >> 1) as i64 ^ -((v & 1) as i64)
}

fn put_varint(b: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        b.put_u8(v as u8 | 0x80);
        v >>= 7;
    }
    b.put_u8(v as u8);
}

fn get_varint(b: &mut &[u8]) -> anyhow::Result<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = b.split_first().ok_or_else(|| anyhow::anyhow!("totals row: truncated"))?;
        *b = rest;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
    anyhow::bail!("totals row: varint too long")
}

/// A delta row's key: the slot's row key, then the seq of the entry that
/// wrote it (unique: seqs only grow across a shard's owners).
fn delta_key(slot: u16, seq: i64) -> Bytes {
    let mut k = key(slot);
    k.extend_from_slice(&seq.to_be_bytes());
    k.into()
}

/// A loaded slot: its totals, and the delta rows the DB still holds (or
/// will, once their entries apply), deleted with the next row write.
#[derive(Default)]
struct Slot {
    row: Totals,
    deltas: Vec<Bytes>,
}

/// One slot's rows as [`ShardTotals::read`] found them.
#[derive(Debug, Default)]
pub struct SlotRows {
    pub slot: u16,
    pub row: Option<Totals>,
    pub deltas: Vec<(Bytes, Totals)>,
    /// The slot's suffixes and flags, counted from its account rows in the
    /// read's snapshot, when a row predates those counts. Only `suffixes`,
    /// `unconfirmed` and `no2fa` are set.
    pub seed: Option<Totals>,
}

/// A shard's totals as of the last entry the sequencer took. They load in
/// the background after the shard opens (`spawn_load`); until then a slot's
/// change is written as a delta row next to its row, and the load adds the
/// slot's delta rows (those in the DB and those taken since the open) to
/// its row.
pub struct ShardTotals {
    slots: HashMap<u16, Slot>,
    /// Delta rows taken for slots not loaded yet.
    pending: HashMap<u16, Vec<(Bytes, Totals)>>,
    /// Over the loaded slots; every slot once `loaded`.
    sum: Totals,
    loaded: bool,
    /// Slots the load seeded whose rows aren't written yet.
    unsaved: BTreeSet<u16>,
}

impl Default for ShardTotals {
    /// Loaded, with no rows: a shard with nothing in it yet.
    fn default() -> ShardTotals {
        ShardTotals {
            slots: HashMap::new(),
            pending: HashMap::new(),
            sum: Totals::default(),
            loaded: true,
            unsaved: BTreeSet::new(),
        }
    }
}

impl ShardTotals {
    /// For a shard opened over existing state, before [`spawn_load`].
    pub fn unloaded() -> ShardTotals {
        ShardTotals { loaded: false, ..Default::default() }
    }

    /// Every slot's rows, from one snapshot: one family scan (delta rows
    /// sort right after their slot's row), and a scan of the account rows
    /// when some slot's rows predate suffix counts.
    pub async fn read(db: &slatedb::Db) -> anyhow::Result<Vec<SlotRows>> {
        #[derive(serde::Deserialize)]
        struct Row<'a> {
            #[serde(borrow)]
            handle: std::borrow::Cow<'a, str>,
            #[serde(borrow, default)]
            status: Option<std::borrow::Cow<'a, str>>,
            #[serde(default)]
            email_confirmed: bool,
            #[serde(flatten)]
            extra: serde_json::Map<String, serde_json::Value>,
        }
        let snap = db.snapshot()?;
        let opts = slatedb::config::ScanOptions { read_ahead_bytes: 1 << 20, max_fetch_tasks: 2, ..Default::default() };
        let mut scan = state::FamilyScan::new(snap.as_ref(), FAMILY, None, &opts).await?;
        let mut out: Vec<SlotRows> = Vec::new();
        let mut stale = BTreeSet::new();
        while let Some(kv) = scan.next().await? {
            let Some(slot) = vlsync_store::keys::key_slot(&kv.key) else { continue };
            let body = vlsync_store::keys::key_body(&kv.key);
            let (row, counts_suffixes) =
                Totals::decode_row(&kv.value).map_err(|e| e.context(format!("slot {slot}")))?;
            if !counts_suffixes {
                stale.insert(slot);
            }
            if out.last().is_none_or(|o| o.slot != slot) {
                out.push(SlotRows { slot, ..Default::default() });
            }
            let o = out.last_mut().unwrap();
            match body.len() - FAMILY.len() {
                0 => o.row = Some(row),
                8 => o.deltas.push((kv.key, row)),
                n => anyhow::bail!("slot {slot}: totals key with a {n}-byte suffix"),
            }
        }
        if stale.is_empty() {
            return Ok(out);
        }
        let started = std::time::Instant::now();
        let mut seeds: HashMap<u16, Totals> = stale.iter().map(|s| (*s, Totals::default())).collect();
        let mut accts = state::FamilyScan::new(snap.as_ref(), state::ACCOUNT_FAMILY, None, &opts).await?;
        while let Some(kv) = accts.next().await? {
            let Some(seed) = vlsync_store::keys::key_slot(&kv.key).and_then(|s| seeds.get_mut(&s)) else { continue };
            let Ok(a) = serde_json::from_slice::<Row>(&kv.value) else { continue };
            if a.status.as_deref() == Some("deleted") {
                continue;
            }
            let f = flags(a.status.as_deref(), a.email_confirmed, &a.extra);
            seed.unconfirmed += i64::from(f & UNCONFIRMED != 0);
            seed.no2fa += i64::from(f & NO_2FA != 0);
            if a.status.is_some() {
                continue;
            }
            if let Some(s) = crate::handle_domains::handle_suffix(&a.handle) {
                *seed.suffixes.entry(s).or_default() += 1;
            }
        }
        for o in &mut out {
            o.seed = seeds.remove(&o.slot);
        }
        tracing::info!(
            slots = stale.len(),
            ms = started.elapsed().as_millis() as u64,
            "account totals: counted handle suffixes and filter flags of rows that lacked them"
        );
        Ok(out)
    }

    /// Installs what [`ShardTotals::read`] found, read after the shard opened.
    /// A slot's row only changes once it is loaded, and until then its
    /// delta rows only accumulate, all of them in `pending` since the open:
    /// so the read plus the pending rows it missed is the slot's state.
    pub fn install(&mut self, rows: Vec<SlotRows>, today: u32) {
        if self.loaded {
            return;
        }
        let cut = cutoff(today);
        for r in rows {
            let pending = self.pending.remove(&r.slot).unwrap_or_default();
            self.install_slot(r, pending, cut);
        }
        for (slot, pending) in std::mem::take(&mut self.pending) {
            self.install_slot(SlotRows { slot, ..Default::default() }, pending, cut);
        }
        self.sum.prune(cut);
        self.loaded = true;
    }

    fn install_slot(&mut self, r: SlotRows, pending: Vec<(Bytes, Totals)>, cut: u32) {
        let seeded = r.seed.is_some();
        let mut s = Slot { row: r.row.unwrap_or_default(), deltas: Vec::new() };
        if let Some(seed) = r.seed {
            s.row.suffixes = seed.suffixes;
            s.row.unconfirmed = seed.unconfirmed;
            s.row.no2fa = seed.no2fa;
        }
        for (k, d) in r.deltas {
            if !s.deltas.contains(&k) {
                // a seed counted the account rows these changes are in
                match seeded {
                    true => s.row.merge_counts(&d),
                    false => s.row.merge(&d),
                }
                s.deltas.push(k);
            }
        }
        for (k, d) in pending {
            if !s.deltas.contains(&k) {
                s.row.merge(&d);
                s.deltas.push(k);
            }
        }
        s.row.prune(cut);
        self.sum.merge(&s.row);
        if seeded {
            self.unsaved.insert(r.slot);
        }
        self.slots.insert(r.slot, s);
    }

    /// Appends the slot's new row (and the deletes of its delta rows) to
    /// `muts`, or a delta row while the shard's totals are loading. `seq`
    /// is the entry's. Once loaded, also the rows of up to
    /// [`SAVE_PER_ENTRY`] slots the load seeded.
    pub fn apply(&mut self, d: &Delta, today: u32, seq: i64, muts: &mut Vec<Mutation>) {
        let cut = cutoff(today);
        if !self.loaded {
            if !d.changes() {
                return;
            }
            let mut delta = Totals::default();
            delta.add_delta(d, cut);
            let k = delta_key(d.slot, seq);
            muts.push(Mutation { key: k.clone(), val: Some(delta.encode()) });
            self.pending.entry(d.slot).or_default().push((k, delta));
            return;
        }
        if d.changes() {
            let s = self.slots.entry(d.slot).or_default();
            s.row.add_delta(d, cut);
            self.sum.add_delta(d, cut);
            s.row.prune(cut);
            self.sum.prune(cut);
            muts.push(Mutation { key: key(d.slot).into(), val: Some(s.row.encode()) });
            muts.extend(s.deltas.drain(..).map(|key| Mutation { key, val: None }));
            self.unsaved.remove(&d.slot);
        }
        for _ in 0..SAVE_PER_ENTRY {
            let Some(slot) = self.unsaved.pop_first() else { break };
            let Some(s) = self.slots.get_mut(&slot) else { continue };
            muts.push(Mutation { key: key(slot).into(), val: Some(s.row.encode()) });
            muts.extend(s.deltas.drain(..).map(|key| Mutation { key, val: None }));
        }
    }

    /// Entries it takes to write every seeded slot's row.
    pub fn unsaved_entries(&self) -> usize {
        self.unsaved.len().div_ceil(SAVE_PER_ENTRY)
    }

    /// None while loading.
    pub fn sum(&self) -> Option<&Totals> {
        self.loaded.then_some(&self.sum)
    }
}

/// Nodes whose totals loads wait (tests: writes while loading).
static HELD: std::sync::LazyLock<parking_lot::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(Default::default);

/// Until dropped, node `node_id`'s totals loads wait before reading.
#[doc(hidden)]
pub fn hold_loads(node_id: &str) -> HeldLoads {
    HELD.lock().insert(node_id.to_string());
    HeldLoads(node_id.to_string())
}

#[doc(hidden)]
pub struct HeldLoads(String);

impl Drop for HeldLoads {
    fn drop(&mut self) {
        HELD.lock().remove(&self.0);
    }
}

/// Loads `sink`'s totals in the background, retrying until they load or the
/// shard closes; then sends `log` the entries that write the rows of slots
/// it seeded, so the next load doesn't count them again.
pub fn spawn_load(
    sink: &std::sync::Arc<crate::nodelog::ShardSink>,
    node_id: &str,
    log: tokio::sync::mpsc::Sender<crate::nodelog::LogEntry>,
) {
    let weak = std::sync::Arc::downgrade(sink);
    let (id, db, node_id) = (sink.id, sink.db.clone(), node_id.to_string());
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let mut backoff = std::time::Duration::from_millis(200);
        while HELD.lock().contains(&node_id) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        loop {
            match ShardTotals::read(db.as_ref()).await {
                Ok(rows) => {
                    let Some(sink) = weak.upgrade() else { return };
                    let saves = {
                        let mut t = sink.totals.lock();
                        t.install(rows, today());
                        t.unsaved_entries()
                    };
                    crate::metrics::TOTALS_LOAD_SECONDS.observe(started.elapsed().as_secs_f64());
                    drop(sink);
                    for _ in 0..saves {
                        let e = crate::nodelog::LogEntry {
                            shard: id,
                            frames: Vec::new(),
                            muts: Vec::new(),
                            ack: None,
                            pending: None,
                            enqueued: std::time::Instant::now(),
                            totals: Some(Delta::save_seeded()),
                        };
                        if log.send(e).await.is_err() {
                            return;
                        }
                    }
                    return;
                }
                Err(e) => {
                    if weak.upgrade().is_none_or(|s| s.barrier_taken()) {
                        return;
                    }
                    tracing::warn!(shard = id.0, "loading account totals: {e:#}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(std::time::Duration::from_secs(10));
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_from_the_row() {
        let mut a = Account { email_confirmed: false, ..Default::default() };
        assert_eq!(flags_of(&a), UNCONFIRMED | NO_2FA);
        a.email_confirmed = true;
        assert_eq!(flags_of(&a), NO_2FA);
        for (k, v) in [
            ("totpEnabled", serde_json::json!(true)),
            ("emailAuthFactorAt", serde_json::json!("2026-10-01T00:00:00Z")),
            ("passkeys", serde_json::json!(2)),
        ] {
            let mut b = a.clone();
            b.extra.insert(k.into(), v);
            assert_eq!(flags_of(&b), 0, "{k}");
        }
        for (k, v) in [("totpEnabled", serde_json::json!(false)), ("passkeys", serde_json::json!(0))] {
            let mut b = a.clone();
            b.extra.insert(k.into(), v);
            assert_eq!(flags_of(&b), NO_2FA, "{k}");
        }
        // only active accounts lack a factor
        a.status = Some("deactivated".into());
        assert_eq!(flags_of(&a), 0);
    }

    #[test]
    fn statuses() {
        assert_eq!(status_index(None), 0);
        assert_eq!(status_index(Some("deactivated")), 1);
        assert_eq!(status_index(Some("takendown")), 2);
        assert_eq!(status_index(Some("suspended")), 3);
        assert_eq!(status_index(Some("deleted")), 4);
    }

    fn suffixes(s: &[(&str, i64)]) -> BTreeMap<Box<str>, i64> {
        s.iter().map(|(k, n)| (Box::from(*k), *n)).collect()
    }

    /// A row as a build that didn't count suffixes (nor flags) wrote it.
    fn without_suffixes(t: &Totals) -> Bytes {
        let b = Totals { suffixes: BTreeMap::new(), unconfirmed: 0, no2fa: 0, ..t.clone() }.encode();
        b.slice(..b.len() - 3)
    }

    /// A row as a build that counted suffixes but not flags wrote it.
    fn without_flags(t: &Totals) -> Bytes {
        let b = Totals { unconfirmed: 0, no2fa: 0, ..t.clone() }.encode();
        b.slice(..b.len() - 2)
    }

    #[test]
    fn rows_round_trip() {
        for t in [
            Totals::default(),
            Totals {
                accounts: [1, 0, 7, -3, i64::MAX],
                days: vec![(20_000, 1), (20_001, -2), (20_031, 1 << 40)],
                suffixes: suffixes(&[("pds.test", 3), ("at.example.org", -1)]),
                unconfirmed: 4,
                no2fa: -2,
            },
        ] {
            assert_eq!(Totals::decode_row(&t.encode()).unwrap(), (t.clone(), true));
            let old = Totals { suffixes: BTreeMap::new(), unconfirmed: 0, no2fa: 0, ..t.clone() };
            assert_eq!(Totals::decode_row(&without_suffixes(&t)).unwrap(), (old, false));
            let old = Totals { unconfirmed: 0, no2fa: 0, ..t.clone() };
            assert_eq!(Totals::decode_row(&without_flags(&t)).unwrap(), (old, false));
        }
        let t = Totals {
            accounts: [1; 5],
            days: vec![(9, 9)],
            suffixes: suffixes(&[("a.test", 1)]),
            unconfirmed: 1,
            no2fa: 1,
        };
        let mut b = t.encode().to_vec();
        b.push(0);
        assert!(Totals::decode(&b).is_err());
        assert!(Totals::decode(&b[..3]).is_err());
        assert!(Totals::decode(&b[..b.len() - 2]).is_err(), "one flag count");
        assert!(Totals::decode(&b[..b.len() - 5]).is_err());
    }

    fn k(status: u8, day: u32) -> Option<RepoKey> {
        Some(RepoKey { status, day, flags: 0 })
    }

    fn apply(s: &mut ShardTotals, d: Delta, today: u32) -> Vec<Mutation> {
        let mut muts = Vec::new();
        s.apply(&d, today, 0, &mut muts);
        muts
    }

    /// Rows and their sum follow creates, writes on later days, status
    /// changes and deletes; days past the cutoff are dropped, and a repo
    /// whose last write is older than that leaves no trace in the days.
    #[test]
    fn deltas_windows_and_cutoff() {
        let mut s = ShardTotals::default();
        let d = |slot, before, after| Delta { slot, before, after, suffix: None };
        let today = 20_000;
        apply(&mut s, d(1, None, k(0, today - 40)), today);
        apply(&mut s, d(1, None, k(0, today - 3)), today);
        apply(&mut s, d(2, None, k(0, today)), today);
        apply(&mut s, d(2, k(0, today), k(1, today)), today);
        apply(&mut s, d(2, None, k(2, today - 1)), today);
        let m = apply(&mut s, d(1, k(0, today - 3), k(0, today)), today);
        assert_eq!(
            Totals::decode(m[0].val.as_ref().unwrap()).unwrap(),
            Totals { accounts: [2, 0, 0, 0, 0], days: vec![(today, 1)], ..Default::default() }
        );
        let sum = s.sum().unwrap().clone();
        assert_eq!(sum.accounts, [2, 1, 1, 0, 0]);
        assert_eq!(sum.repos(), 4);
        assert_eq!(sum.written_within(0, today), 2);
        assert_eq!(sum.written_within(1, today), 3);
        assert_eq!(sum.written_within(30, today), 3);
        // the 40-day-old repo is deleted: only its status count moves
        apply(&mut s, d(1, k(0, today - 40), None), today);
        assert_eq!(s.sum().unwrap().accounts, [1, 1, 1, 0, 0]);
        assert_eq!(s.sum().unwrap().written_within(30, today), 3);
        // a month on, nothing is within 1d and the old days are gone
        let later = today + 33;
        apply(&mut s, d(2, k(1, today), k(3, today)), later);
        assert_eq!(s.sum().unwrap().written_within(30, later), 0);
        assert!(s.sum().unwrap().days.is_empty(), "{:?}", s.sum().unwrap().days);
        assert_eq!(s.sum().unwrap().accounts, [1, 0, 1, 1, 0]);
    }

    /// A handle change alone moves only the suffixes; a deactivation takes
    /// the account out of them.
    #[test]
    fn handle_and_status_changes_move_suffixes() {
        let mut s = ShardTotals::default();
        let c = |status, sfx: Option<&str>| Counted { repo: k(status, 20_000), suffix: sfx.map(Box::from) };
        let mut d = |before, after| {
            apply(&mut s, Delta::account("did:plc:x", before, after).expect("a change"), 20_000);
        };
        d(Counted::default(), c(0, Some("pds.test")));
        d(Counted::default(), c(0, Some("pds.test")));
        d(c(0, Some("pds.test")), c(0, Some("at.example.org")));
        d(c(0, Some("pds.test")), c(1, None));
        assert!(Delta::account("did:plc:x", c(0, Some("a.test")), c(0, Some("a.test"))).is_none());
        assert_eq!(s.sum().unwrap().suffixes, suffixes(&[("at.example.org", 1)]));
        assert_eq!(s.sum().unwrap().accounts, [1, 1, 0, 0, 0]);
    }

    type Db = std::collections::BTreeMap<Bytes, Bytes>;
    /// Account id -> the suffix and flags it counts under: the account rows.
    type Accounts = HashMap<u32, (Option<Box<str>>, u8)>;

    const SLOTS: u32 = 17;

    /// What [`ShardTotals::read`] returns, from a key-value map and the
    /// account rows.
    fn read(db: &Db, accts: &Accounts) -> Vec<SlotRows> {
        let mut out: Vec<SlotRows> = Vec::new();
        let mut stale = BTreeSet::new();
        for (k, v) in db {
            let slot = vlsync_store::keys::key_slot(k).unwrap();
            if out.last().is_none_or(|o| o.slot != slot) {
                out.push(SlotRows { slot, ..Default::default() });
            }
            let o = out.last_mut().unwrap();
            let (row, counts) = Totals::decode_row(v).unwrap();
            if !counts {
                stale.insert(slot);
            }
            match vlsync_store::keys::key_body(k).len() - FAMILY.len() {
                0 => o.row = Some(row),
                _ => o.deltas.push((k.clone(), row)),
            }
        }
        for o in &mut out {
            if stale.contains(&o.slot) {
                let mut seed = Totals::default();
                for (_, (sfx, flags)) in accts.iter().filter(|(id, _)| (*id % SLOTS) as u16 == o.slot) {
                    if let Some(sfx) = sfx {
                        *seed.suffixes.entry(sfx.clone()).or_default() += 1;
                    }
                    seed.unconfirmed += i64::from(flags & UNCONFIRMED != 0);
                    seed.no2fa += i64::from(flags & NO_2FA != 0);
                }
                o.seed = Some(seed);
            }
        }
        out
    }

    /// Randomized deltas against the per-repo truth, through reopens of the
    /// shard whose totals load at a random later point (from a read taken
    /// before more deltas, as the background load's scan can be), and
    /// sometimes never before the next reopen. Now and then every row is
    /// rewritten as a build that didn't count suffixes left it, and the
    /// load seeds them from the account rows.
    #[test]
    fn matches_truth_through_lazy_loads() {
        use rand::{Rng, SeedableRng};
        const SUFFIXES: [&str; 4] = ["pds.test", "a.test", "at.a.test", "elsewhere.com"];
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut repos: HashMap<u32, Counted> = HashMap::new();
        let mut accts = Accounts::new();
        let mut db = Db::new();
        let mut s = ShardTotals::default();
        let mut snapshot: Option<Vec<_>> = None;
        let mut today = 20_000u32;
        let mut seq = 0i64;
        let mut seeded = 0;
        for step in 0..30_000u32 {
            if rng.gen_ratio(1, 500) {
                today += 1;
            }
            if rng.gen_ratio(1, 700) {
                s = ShardTotals::unloaded();
                snapshot = None;
            }
            if rng.gen_ratio(1, 2_000) {
                let legacy: fn(&Totals) -> Bytes = if rng.gen() { without_suffixes } else { without_flags };
                for v in db.values_mut() {
                    *v = legacy(&Totals::decode(v).unwrap());
                }
                s = ShardTotals::unloaded();
                snapshot = None;
                seeded += 1;
            }
            if s.sum().is_none() {
                if snapshot.is_none() && rng.gen_ratio(1, 20) {
                    snapshot = Some(read(&db, &accts));
                } else if snapshot.is_some() && rng.gen_ratio(1, 20) {
                    s.install(snapshot.take().unwrap(), today);
                }
            }
            let id = rng.gen_range(0..300u32);
            let slot = (id % SLOTS) as u16;
            let before = repos.get(&id).cloned().unwrap_or_default();
            let after = if rng.gen_ratio(1, 10) {
                Counted::default()
            } else {
                let status = rng.gen_range(0..5);
                let suffix = (status == 0).then(|| Box::from(SUFFIXES[rng.gen_range(0..SUFFIXES.len())]));
                let flags = rng.gen_range(0..4u8) & if status == 0 { 3 } else { UNCONFIRMED };
                Counted { repo: Some(RepoKey { status, day: today - rng.gen_range(0..2), flags }), suffix }
            };
            match after.repo {
                Some(_) => repos.insert(id, after.clone()),
                None => repos.remove(&id),
            };
            let mut muts = Vec::new();
            if let Some(mut d) = Delta::account("did:plc:x", before, after.clone()) {
                d.slot = slot;
                seq += 1;
                s.apply(&d, today, seq, &mut muts);
            } else if rng.gen_ratio(1, 4) {
                seq += 1;
                s.apply(&Delta::save_seeded(), today, seq, &mut muts);
            }
            // the entry's batch: the account row and the totals rows together
            match after.repo {
                Some(r) => accts.insert(id, (after.suffix, r.flags)),
                None => accts.remove(&id),
            };
            for m in muts {
                match m.val {
                    Some(v) => db.insert(m.key, v),
                    None => db.remove(&m.key),
                };
            }
            if step % 997 == 0 || step == 29_999 {
                if s.sum().is_none() {
                    s.install(read(&db, &accts), today);
                    snapshot = None;
                }
                let mut want = Totals::default();
                for r in repos.values() {
                    want.accounts[r.repo.unwrap().status as usize] += 1;
                    if let Some(sfx) = &r.suffix {
                        want.add_suffix(sfx, 1);
                    }
                    want.unconfirmed += i64::from(r.repo.unwrap().flags & UNCONFIRMED != 0);
                    want.no2fa += i64::from(r.repo.unwrap().flags & NO_2FA != 0);
                }
                let sum = s.sum().unwrap();
                assert_eq!(sum.accounts, want.accounts, "step {step}");
                assert_eq!(sum.suffixes, want.suffixes, "step {step}");
                assert_eq!((sum.unconfirmed, sum.no2fa), (want.unconfirmed, want.no2fa), "step {step}");
                for (_, days) in WINDOWS {
                    let n = repos.values().filter(|r| r.repo.unwrap().day + days >= today).count() as i64;
                    assert_eq!(sum.written_within(days, today), n, "step {step}");
                }
                let mut reloaded = ShardTotals::unloaded();
                reloaded.install(read(&db, &accts), today);
                assert_eq!(reloaded.sum().unwrap().accounts, want.accounts, "step {step}");
                assert_eq!(reloaded.sum().unwrap().suffixes, want.suffixes, "step {step}");
                assert_eq!(
                    (reloaded.sum().unwrap().unconfirmed, reloaded.sum().unwrap().no2fa),
                    (want.unconfirmed, want.no2fa),
                    "step {step}"
                );
                for (_, days) in WINDOWS {
                    assert_eq!(reloaded.sum().unwrap().written_within(days, today), sum.written_within(days, today));
                }
                assert!(
                    db.len()
                        <= SLOTS as usize
                            + s.pending.values().map(Vec::len).sum::<usize>()
                            + s.slots.values().map(|x| x.deltas.len()).sum::<usize>()
                );
            }
        }
        assert!(seeded > 5, "{seeded} reseeds");
    }

    /// Once the seeded rows are written, a reload counts no account rows.
    #[test]
    fn seeded_rows_are_saved() {
        let mut db = Db::new();
        let t = Totals { accounts: [2, 0, 0, 0, 0], days: vec![(20_000, 2)], ..Default::default() };
        for slot in 0..1_000u16 {
            db.insert(key(slot).into(), without_suffixes(&t));
        }
        let accts: Accounts = (0..2 * SLOTS).map(|id| (id, (Some(Box::from("pds.test")), NO_2FA))).collect();
        let mut s = ShardTotals::unloaded();
        s.install(read(&db, &accts), 20_000);
        assert_eq!(s.unsaved_entries(), 1_000usize.div_ceil(SAVE_PER_ENTRY));
        for _ in 0..s.unsaved_entries() {
            let mut muts = Vec::new();
            s.apply(&Delta::save_seeded(), 20_000, 1, &mut muts);
            for m in muts {
                db.insert(m.key, m.val.unwrap());
            }
        }
        assert_eq!(s.unsaved_entries(), 0);
        let rows = read(&db, &accts);
        assert!(rows.iter().all(|r| r.seed.is_none()));
        let mut reloaded = ShardTotals::unloaded();
        reloaded.install(rows, 20_000);
        assert_eq!(reloaded.sum().unwrap().suffixes, suffixes(&[("pds.test", 2 * SLOTS as i64)]));
        assert_eq!(reloaded.sum().unwrap().no2fa, 2 * SLOTS as i64);

        assert_eq!(reloaded.sum(), s.sum());
    }
}
