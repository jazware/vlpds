//! `vlpds admin ...`: the reference PDS's `pdsadmin` and its
//! packages/pds/src/scripts, plus vlpds-only cluster operations, as admin
//! XRPC against any node. Per-node maintenance goes to every node
//! `getClusterStatus` lists, relayed by the `--url` node over peer mTLS
//! (`forward::NODE_HEADER`). ops/RUNBOOK.md "Admin CLI" maps pdsadmin
//! commands to these.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value as J};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

pub struct Opts {
    /// Any node of the cluster.
    pub url: String,
    pub token: String,
    /// Raw JSON results instead of tables.
    pub json: bool,
}

#[derive(clap::Subcommand, Debug)]
pub enum Cmd {
    /// Print the shard layout and any split/merge in progress.
    Layout,
    /// Split a shard in two, online.
    ShardSplit {
        shard: u32,
        /// First slot of the upper half (default: the range's midpoint).
        #[arg(long)]
        at: Option<u32>,
        /// Return once planned instead of waiting for the flip.
        #[arg(long)]
        no_wait: bool,
    },
    /// Merge two adjacent shards (`left` holds the lower slots), online.
    ShardMerge {
        left: u32,
        right: u32,
        #[arg(long)]
        no_wait: bool,
    },
    /// Abort the split/merge in progress (only before it flips).
    ReshardAbort,
    /// Accounts (pdsadmin account ...).
    #[command(subcommand)]
    Account(AccountCmd),
    /// Create invite code(s) (pdsadmin create-invite-code).
    CreateInviteCode {
        /// Uses per code.
        #[arg(long, default_value_t = 1)]
        uses: i64,
        /// How many codes.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// The account the codes belong to (default: admin).
        #[arg(long)]
        for_account: Option<String>,
        /// Only for handles under this served domain.
        #[arg(long)]
        handle_domain: Option<String>,
    },
    /// The domains handles are given out under: the primary
    /// (--handle-domain) and any added at runtime, for the whole cluster.
    #[command(subcommand)]
    HandleDomain(HandleDomainCmd),
    /// Ask relays to crawl this PDS (pdsadmin request-crawl). Relays:
    /// hostnames or URLs, comma-separated (default: the node's --crawlers).
    RequestCrawl {
        #[arg(value_delimiter = ',')]
        relays: Vec<String>,
    },
    /// Emit #identity for DIDs (script publish-identity).
    PublishIdentity {
        dids: Vec<String>,
        /// Also the DIDs in this file (one per line).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Make each DID's PLC `atproto` key the signing key this PDS holds,
    /// then re-sign the repo and emit #identity + #sync (script
    /// rotate-keys). `--generate`: rotate to a fresh signing key instead
    /// (admin updateAccountSigningKey, which re-signs too).
    RotateKeys {
        dids: Vec<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        generate: bool,
    },
    /// Move every account's PLC rotation key from a retired server key to
    /// the current one, on every node (vlpds.admin.rotatePlcKeys).
    RotatePlcKeys {
        #[arg(long)]
        dry_run: bool,
        /// Only the node at --url.
        #[arg(long)]
        node_only: bool,
    },
    /// Add the operator recovery key (--plc-recovery-did-key) to every
    /// account's PLC rotation keys that lacks it, ahead of the server key
    /// and behind any keys the user added, on every node
    /// (vlpds.admin.ensureRecoveryKey).
    EnsureRecoveryKey {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        node_only: bool,
        /// Accounts started per second on each node (the directory
        /// rate-limits).
        #[arg(long)]
        per_second: Option<f64>,
    },
    /// Rewrap every secret at rest under the current KEK, on every node
    /// (vlpds.admin.rewrapSecrets).
    RewrapSecrets {
        #[arg(long)]
        dry_run: bool,
        /// Also unwrap blobs already under the current KEK id (finds older
        /// Cloud KMS or Vault Transit key versions).
        #[arg(long)]
        check_versions: bool,
        #[arg(long)]
        node_only: bool,
    },
    /// Check a repo's stored state (commit, records, MST, persisted nodes,
    /// indexes); exits 1 if anything is wrong.
    CheckRepo { did: String },
    /// Check an account's repo in one space (records against the head's set
    /// hash and count, the oplog against the records, the notify outbox and
    /// the space host's rows); exits 1 if anything is wrong.
    CheckSpace { did: String, space: String },
    /// Re-derive a repo from its records and sign a new commit, #sync
    /// (script rebuild-repo).
    RebuildRepo {
        did: String,
        /// Check and show what would be written; change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Cluster-wide operations: status, feature levels.
    #[command(subcommand)]
    Cluster(ClusterCmd),
}

#[derive(clap::Subcommand, Debug)]
pub enum ClusterCmd {
    /// Nodes, leases, shard ownership, firehose position.
    Status,
    /// Raise the cluster's feature level (vlpds.admin.setFeatureLevel) once
    /// every node runs a build that supports it. The point of no return:
    /// builds that can't run the new level can no longer join, so rollback
    /// is forward-fix only (ops/RUNBOOK.md "Rolling upgrade").
    Finalize {
        /// The level (default: the active level + 1).
        #[arg(long)]
        level: Option<u32>,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Lower the cluster's feature level (vlpds.admin.setFeatureLevel with
    /// `lower`): only past levels that gate wire behavior, never past a
    /// persistent one (it wrote formats older builds can't read), and only
    /// when every live node can run the lower level.
    Lower {
        /// The level to go back to.
        #[arg(long)]
        level: u32,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum HandleDomainCmd {
    /// Every served domain with its active accounts.
    List {
        /// Count every account row instead of reading the kept totals.
        #[arg(long)]
        recount: bool,
    },
    /// Serve handles under another domain (DNS for it must point here).
    Add { domain: String },
    /// Stop serving a domain. Refused while active accounts have handles
    /// under it, unless forced: their handles then stop resolving.
    Remove {
        domain: String,
        #[arg(long)]
        force: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum AccountCmd {
    /// Every account: handle, email, DID.
    List {
        /// Only emails starting with this.
        #[arg(long)]
        email: Option<String>,
    },
    /// Create an account with a generated password.
    Create {
        email: String,
        handle: String,
        /// Use this password instead of a generated one.
        #[arg(long)]
        password: Option<String>,
        /// Use this invite code (default: a new single-use code when the
        /// PDS requires one).
        #[arg(long)]
        invite_code: Option<String>,
    },
    /// Delete an account (permanent).
    Delete {
        did: String,
        #[arg(long, short)]
        yes: bool,
    },
    /// Take an account down.
    Takedown {
        did: String,
        /// Takedown reference (default: the current unix time).
        #[arg(long = "ref")]
        reference: Option<String>,
    },
    /// Reverse a takedown.
    Untakedown { did: String },
    /// Set a new (generated) password.
    ResetPassword {
        did: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// The account's admin view.
    Info { did: String },
}

#[derive(Clone)]
struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Client {
    fn new(url: &str, token: &str) -> Client {
        Client { http: reqwest::Client::new(), base: url.trim_end_matches('/').to_string(), token: token.to_string() }
    }

    fn url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{nsid}", self.base)
    }

    async fn get(&self, nsid: &str, query: &[(&str, &str)]) -> Result<J> {
        self.send(nsid, self.http.get(self.url(nsid)).query(query), true).await
    }

    async fn post(&self, nsid: &str, body: &J) -> Result<J> {
        self.send(nsid, self.http.post(self.url(nsid)).json(body), true).await
    }

    /// Relayed by this node.
    async fn post_to_node(&self, node: &str, nsid: &str, body: &J) -> Result<J> {
        let rb = self.http.post(self.url(nsid)).header(crate::forward::NODE_HEADER, node).json(body);
        self.send(nsid, rb, true).await.with_context(|| format!("node {node}"))
    }

    /// Without admin credentials (createAccount).
    async fn post_public(&self, nsid: &str, body: &J) -> Result<J> {
        self.send(nsid, self.http.post(self.url(nsid)).json(body), false).await
    }

    async fn send(&self, nsid: &str, rb: reqwest::RequestBuilder, admin: bool) -> Result<J> {
        let rb = if admin { rb.basic_auth("admin", Some(&self.token)) } else { rb };
        let r =
            rb.timeout(Duration::from_secs(600)).send().await.with_context(|| format!("{nsid} at {}", self.base))?;
        let status = r.status();
        let body = r.text().await?;
        let j: J =
            if body.trim().is_empty() { J::Null } else { serde_json::from_str(&body).unwrap_or(J::String(body)) };
        if !status.is_success() {
            match (j["error"].as_str(), j["message"].as_str()) {
                (Some(e), Some(m)) => bail!("{nsid}: {} {e}: {m}", status.as_u16()),
                (Some(e), None) => bail!("{nsid}: {} {e}", status.as_u16()),
                _ => bail!("{nsid}: {status}: {j}"),
            }
        }
        Ok(j)
    }
}

async fn handle_domain(c: &Client, cmd: HandleDomainCmd, opts: &Opts, out: &mut dyn Write) -> Result<()> {
    let r = match cmd {
        HandleDomainCmd::List { recount } => {
            let q: &[(&str, &str)] = if recount { &[("recount", "true")] } else { &[] };
            c.get("vlpds.admin.listHandleDomains", q).await?
        }
        HandleDomainCmd::Add { domain } => c.post("vlpds.admin.addHandleDomain", &json!({"domain": domain})).await?,
        HandleDomainCmd::Remove { domain, force } => {
            let r = c.post("vlpds.admin.removeHandleDomain", &json!({"domain": domain, "force": force})).await?;
            if opts.json {
                return pretty(out, &r);
            }
            writeln!(out, "removed {} ({} active accounts under it)", s(&r["domain"]), s(&r["accounts"]))?;
            return Ok(());
        }
    };
    if opts.json {
        return pretty(out, &r);
    }
    let mut rows = vec![vec!["DOMAIN".to_string(), "ACCOUNTS".into(), "ADDED".into()]];
    for d in r["domains"].as_array().into_iter().flatten() {
        let added = if d["primary"] == json!(true) { "primary (--handle-domain)".into() } else { s(&d["addedAt"]) };
        rows.push(vec![s(&d["domain"]), s(&d["accounts"]), added]);
    }
    write!(out, "{}", table(&rows))?;
    if r["countsPartial"] == json!(true) {
        writeln!(out, "(some nodes or shards didn't answer or are still loading their totals: counts may be low)")?;
    }
    Ok(())
}

/// Like pdsadmin's.
fn generate_password() -> String {
    use rand::Rng;
    rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(24).map(char::from).collect()
}

fn check_did(did: &str) -> Result<()> {
    if !did.starts_with("did:") {
        bail!("DID parameter must start with \"did:\": {did}");
    }
    Ok(())
}

/// `dids` plus the non-empty, non-`#` lines of `file`.
fn did_list(mut dids: Vec<String>, file: Option<&PathBuf>) -> Result<Vec<String>> {
    if let Some(f) = file {
        let s = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        dids.extend(s.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from));
    }
    if dids.is_empty() {
        bail!("no DIDs given");
    }
    for d in &dids {
        check_did(d)?;
    }
    Ok(dids)
}

fn confirm(prompt: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("{prompt}: refusing without --yes (stdin is not a terminal)");
    }
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> =
        (0..cols).map(|i| rows.iter().filter_map(|r| r.get(i)).map(|c| c.chars().count()).max().unwrap_or(0)).collect();
    let mut out = String::new();
    for r in rows {
        let mut line = String::new();
        for (i, c) in r.iter().enumerate() {
            if i + 1 < r.len() {
                line.push_str(&format!("{c:<w$}  ", w = widths[i]));
            } else {
                line.push_str(c);
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn s(v: &J) -> String {
    match v {
        J::Null => "-".into(),
        J::String(s) => s.clone(),
        v => v.to_string(),
    }
}

fn pretty(out: &mut dyn Write, j: &J) -> Result<()> {
    writeln!(out, "{}", serde_json::to_string_pretty(j)?)?;
    Ok(())
}

/// An error (including a failed item of a batch, or a repo check with
/// problems) means exit 1.
pub async fn run(cmd: Cmd, opts: &Opts, out: &mut dyn Write) -> Result<()> {
    let c = Client::new(&opts.url, &opts.token);
    match cmd {
        Cmd::Layout => pretty(out, &c.get("vlpds.admin.getShardLayout", &[]).await?),
        Cmd::ShardSplit { shard, at, no_wait } => {
            pretty(out, &c.post("vlpds.admin.splitShard", &json!({"shard": shard, "at": at, "wait": !no_wait})).await?)
        }
        Cmd::ShardMerge { left, right, no_wait } => pretty(
            out,
            &c.post("vlpds.admin.mergeShards", &json!({"left": left, "right": right, "wait": !no_wait})).await?,
        ),
        Cmd::ReshardAbort => pretty(out, &c.post("vlpds.admin.abortReshard", &json!({})).await?),
        Cmd::Account(a) => account(&c, a, opts, out).await,
        Cmd::CreateInviteCode { uses, count, for_account, handle_domain } => {
            let mut codes = Vec::new();
            for _ in 0..count.max(1) {
                let mut body = json!({"useCount": uses});
                if let Some(a) = &for_account {
                    body["forAccount"] = json!(a);
                }
                if let Some(d) = &handle_domain {
                    body["handleDomain"] = json!(d);
                }
                let r = c.post("com.atproto.server.createInviteCode", &body).await?;
                codes.push(r["code"].as_str().context("no code in reply")?.to_string());
            }
            if opts.json {
                return pretty(out, &json!({"codes": codes}));
            }
            for code in codes {
                writeln!(out, "{code}")?;
            }
            Ok(())
        }
        Cmd::HandleDomain(h) => handle_domain(&c, h, opts, out).await,
        Cmd::RequestCrawl { relays } => {
            let r = c.post("vlpds.admin.requestCrawl", &json!({"relays": relays})).await?;
            let results = r["results"].as_array().cloned().unwrap_or_default();
            if opts.json {
                pretty(out, &r)?;
            } else {
                for x in &results {
                    let what = if x["ok"] == json!(true) {
                        "ok".to_string()
                    } else {
                        format!("FAILED {} {}", s(&x["status"]), s(&x["error"]))
                    };
                    writeln!(out, "Requesting crawl of {} from {}: {what}", s(&r["hostname"]), s(&x["relay"]))?;
                }
            }
            let failed = results.iter().filter(|x| x["ok"] != json!(true)).count();
            if failed > 0 {
                bail!("{failed} of {} relays failed", results.len());
            }
            if !opts.json {
                writeln!(out, "done")?;
            }
            Ok(())
        }
        Cmd::PublishIdentity { dids, file } => {
            let dids = did_list(dids, file.as_ref())?;
            per_did(&dids, opts, out, |did| {
                let c = c.clone();
                async move {
                    let r = c.post("vlpds.admin.publishIdentity", &json!({"did": did})).await?;
                    Ok((format!("published identity evt for {did} ({})", s(&r["handle"])), r))
                }
            })
            .await
        }
        Cmd::RotateKeys { dids, file, generate } => {
            let dids = did_list(dids, file.as_ref())?;
            per_did(&dids, opts, out, |did| {
                let c = c.clone();
                async move {
                    if generate {
                        let r = c.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": did})).await?;
                        return Ok((format!("{did}: new signing key {}", s(&r["signingKey"])), r));
                    }
                    let r = c.post("vlpds.admin.publishIdentity", &json!({"did": did, "syncPlc": true})).await?;
                    let what = match r["plcUpdated"].as_bool() {
                        Some(true) => "PLC signing key updated, repo re-signed, identity published",
                        Some(false) => "PLC signing key already current, repo re-signed, identity published",
                        None => "not a did:plc (nothing to update), repo re-signed, identity published",
                    };
                    Ok((format!("{did}: {what}"), r))
                }
            })
            .await
        }
        Cmd::RotatePlcKeys { dry_run, node_only } => {
            let cols = ["accounts", "current", "rotated", "foreign", "failed"];
            per_node(&c, node_only, opts, out, "vlpds.admin.rotatePlcKeys", json!({"dryRun": dry_run}), &cols).await
        }
        Cmd::EnsureRecoveryKey { dry_run, node_only, per_second } => {
            let cols = ["accounts", "present", "added", "foreign", "full", "failed"];
            let body = json!({"dryRun": dry_run, "perSecond": per_second});
            per_node(&c, node_only, opts, out, "vlpds.admin.ensureRecoveryKey", body, &cols).await
        }
        Cmd::RewrapSecrets { dry_run, check_versions, node_only } => {
            let cols = ["accounts", "stale", "signingKeys", "totpSecrets", "reservedKeys", "failed"];
            let body = json!({"dryRun": dry_run, "checkVersions": check_versions});
            per_node(&c, node_only, opts, out, "vlpds.admin.rewrapSecrets", body, &cols).await
        }
        Cmd::CheckRepo { did } => {
            check_did(&did)?;
            let r = c.get("vlpds.admin.checkRepo", &[("did", &did)]).await?;
            if opts.json {
                pretty(out, &r)?;
            } else {
                write_check(out, &r)?;
            }
            if r["ok"] != json!(true) {
                bail!("{did}: {} problem(s)", r["problems"].as_array().map_or(0, Vec::len));
            }
            Ok(())
        }
        Cmd::CheckSpace { did, space } => {
            check_did(&did)?;
            if !space.starts_with("at://") {
                bail!("space must be a space URI (at://{{authority}}/space/{{type}}/{{skey}}): {space}");
            }
            let r = c.get("vlpds.admin.checkSpace", &[("did", &did), ("space", &space)]).await?;
            if opts.json {
                pretty(out, &r)?;
            } else {
                write_space_check(out, &r)?;
            }
            if r["ok"] != json!(true) {
                bail!("{did} in {space}: {} problem(s)", r["problems"].as_array().map_or(0, Vec::len));
            }
            Ok(())
        }
        Cmd::RebuildRepo { did, dry_run, yes } => {
            check_did(&did)?;
            let dry = c.post("vlpds.admin.rebuildRepo", &json!({"did": did, "dryRun": true})).await?;
            if dry_run {
                if opts.json {
                    return pretty(out, &dry);
                }
                write_check(out, &dry["before"])?;
                writeln!(out, "would write {} records under a new commit (dry run)", s(&dry["records"]))?;
                return Ok(());
            }
            if !yes {
                write_check(&mut std::io::stderr(), &dry["before"])?;
                if !confirm(&format!("Rewrite {did} from its {} records under a new commit?", s(&dry["records"])))? {
                    bail!("aborted");
                }
            }
            let r = c.post("vlpds.admin.rebuildRepo", &json!({"did": did})).await?;
            if opts.json {
                return pretty(out, &r);
            }
            writeln!(out, "Record count : {}", s(&r["records"]))?;
            writeln!(
                out,
                "Nodes before : {} stored, {} expected",
                s(&r["before"]["nodes"]["stored"]),
                s(&r["before"]["nodes"]["expected"])
            )?;
            writeln!(out, "New commit   : {} (rev {})", s(&r["commit"]), s(&r["rev"]))?;
            writeln!(
                out,
                "After        : {}",
                if r["after"]["ok"] == json!(true) { "ok".to_string() } else { s(&r["after"]["problems"]) }
            )?;
            Ok(())
        }
        Cmd::Cluster(ClusterCmd::Status) => {
            let r = c.get("vlpds.admin.getClusterStatus", &[]).await?;
            if opts.json {
                return pretty(out, &r);
            }
            write_cluster(out, &r)
        }
        Cmd::Cluster(ClusterCmd::Finalize { level, yes }) => {
            let (st, active) = active_level(&c).await?;
            let level = level.unwrap_or(active + 1);
            if level > active && !yes {
                let nodes: Vec<String> = st["nodes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|n| format!("{} (max {})", s(&n["node"]), s(&n["maxLevel"])))
                    .collect();
                eprintln!("Active level {active}; nodes: {}", nodes.join(", "));
                if !confirm(&format!("Raise the cluster to feature level {level}? Builds that can't run it will no longer start (no rollback by redeploy)"))? {
                    bail!("aborted");
                }
            }
            let r = c.post("vlpds.admin.setFeatureLevel", &json!({"level": level})).await?;
            if opts.json {
                return pretty(out, &r);
            }
            writeln!(out, "Feature level: {} (was {active})", s(&r["active"]))?;
            if let Some(h) = r["history"].as_array().and_then(|h| h.last()) {
                writeln!(out, "Since        : {} by {}", s(&h["at"]), s(&h["by"]))?;
            }
            Ok(())
        }
        Cmd::Cluster(ClusterCmd::Lower { level, yes }) => {
            let (_, active) = active_level(&c).await?;
            if level < active && !yes && !confirm(&format!("Lower the cluster from feature level {active} to {level}? Writers switch back at their next segment"))? {
                bail!("aborted");
            }
            let r = c.post("vlpds.admin.setFeatureLevel", &json!({"level": level, "lower": true})).await?;
            if opts.json {
                return pretty(out, &r);
            }
            writeln!(out, "Feature level: {} (was {active})", s(&r["active"]))?;
            Ok(())
        }
    }
}

async fn active_level(c: &Client) -> Result<(J, u32)> {
    let st = c.get("vlpds.admin.getClusterStatus", &[]).await?;
    let active = st["version"]["active"].as_u64().context("getClusterStatus has no active feature level")? as u32;
    Ok((st, active))
}

async fn account(c: &Client, cmd: AccountCmd, opts: &Opts, out: &mut dyn Write) -> Result<()> {
    match cmd {
        AccountCmd::List { email } => {
            let mut accounts = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let mut q: Vec<(&str, &str)> = vec![("limit", "100")];
                if let Some(e) = &email {
                    q.push(("email", e));
                }
                if let Some(cu) = &cursor {
                    q.push(("cursor", cu));
                }
                let r = c.get("com.atproto.admin.searchAccounts", &q).await?;
                for k in ["unreachableNodes", "unsupportedNodes", "missingShards"] {
                    if let Some(v) = r.get(k) {
                        eprintln!("warning: listing incomplete: {k} {v}");
                    }
                }
                accounts.extend(r["accounts"].as_array().cloned().unwrap_or_default());
                match r["cursor"].as_str() {
                    Some(next) if Some(next) != cursor.as_deref() => cursor = Some(next.to_string()),
                    _ => break,
                }
            }
            if opts.json {
                return pretty(out, &J::Array(accounts));
            }
            let mut rows = vec![vec!["Handle".into(), "Email".into(), "DID".into()]];
            rows.extend(accounts.iter().map(|a| vec![s(&a["handle"]), s(&a["email"]), s(&a["did"])]));
            write!(out, "{}", table(&rows))?;
            Ok(())
        }
        AccountCmd::Create { email, handle, password, invite_code } => {
            let password = password.unwrap_or_else(generate_password);
            let invite = match invite_code {
                Some(code) => Some(code),
                None => {
                    let d = c.get("com.atproto.server.describeServer", &[]).await?;
                    if d["inviteCodeRequired"] == json!(true) {
                        let r = c.post("com.atproto.server.createInviteCode", &json!({"useCount": 1})).await?;
                        Some(r["code"].as_str().context("no invite code in reply")?.to_string())
                    } else {
                        None
                    }
                }
            };
            let mut body = json!({"email": email, "handle": handle, "password": password});
            if let Some(code) = invite {
                body["inviteCode"] = json!(code);
            }
            let r = c.post_public("com.atproto.server.createAccount", &body).await?;
            let did = r["did"].as_str().filter(|d| d.starts_with("did:")).context("no DID in createAccount reply")?;
            let handle = r["handle"].as_str().unwrap_or(&handle);
            if opts.json {
                return pretty(out, &json!({"did": did, "handle": handle, "password": password}));
            }
            writeln!(out, "\nAccount created successfully!\n-----------------------------")?;
            writeln!(out, "Handle   : {handle}\nDID      : {did}\nPassword : {password}")?;
            writeln!(out, "-----------------------------\nSave this password, it will not be displayed again.\n")?;
            Ok(())
        }
        AccountCmd::Delete { did, yes } => {
            check_did(&did)?;
            if !yes && !confirm(&format!("This action is permanent. Delete {did}?"))? {
                bail!("aborted");
            }
            c.post("com.atproto.admin.deleteAccount", &json!({"did": did})).await?;
            done(out, opts, json!({"did": did, "deleted": true}), &format!("{did} deleted"))
        }
        AccountCmd::Takedown { did, reference } => {
            check_did(&did)?;
            let reference = reference.unwrap_or_else(|| (vlsync_atproto::tid::now_micros() / 1_000_000).to_string());
            let body = json!({
                "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": did},
                "takedown": {"applied": true, "ref": reference},
            });
            c.post("com.atproto.admin.updateSubjectStatus", &body).await?;
            done(
                out,
                opts,
                json!({"did": did, "takedown": {"applied": true, "ref": reference}}),
                &format!("{did} taken down (ref {reference})"),
            )
        }
        AccountCmd::Untakedown { did } => {
            check_did(&did)?;
            let body = json!({
                "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": did},
                "takedown": {"applied": false},
            });
            c.post("com.atproto.admin.updateSubjectStatus", &body).await?;
            done(out, opts, json!({"did": did, "takedown": {"applied": false}}), &format!("{did} untaken down"))
        }
        AccountCmd::ResetPassword { did, password } => {
            check_did(&did)?;
            let password = password.unwrap_or_else(generate_password);
            c.post("com.atproto.admin.updateAccountPassword", &json!({"did": did, "password": password})).await?;
            done(
                out,
                opts,
                json!({"did": did, "password": password}),
                &format!("\nPassword reset for {did}\nNew password: {password}\n"),
            )
        }
        AccountCmd::Info { did } => {
            check_did(&did)?;
            let r = c.get("com.atproto.admin.getAccountInfo", &[("did", &did)]).await?;
            let st = c.get("com.atproto.admin.getSubjectStatus", &[("did", &did)]).await.unwrap_or(J::Null);
            if opts.json {
                return pretty(out, &json!({"account": r, "status": st}));
            }
            let mut rows = Vec::new();
            for k in ["did", "handle", "email", "emailConfirmedAt", "indexedAt", "deactivatedAt", "invitesDisabled"] {
                rows.push(vec![format!("{k}:"), s(&r[k])]);
            }
            rows.push(vec!["takedown:".into(), s(&st["takedown"]["applied"])]);
            rows.push(vec!["invites:".into(), r["invites"].as_array().map_or(0, Vec::len).to_string()]);
            write!(out, "{}", table(&rows))?;
            Ok(())
        }
    }
}

fn done(out: &mut dyn Write, opts: &Opts, j: J, human: &str) -> Result<()> {
    if opts.json {
        return pretty(out, &j);
    }
    writeln!(out, "{human}")?;
    Ok(())
}

/// A failure doesn't stop the rest, as in the reference scripts.
async fn per_did<F, Fut>(dids: &[String], opts: &Opts, out: &mut dyn Write, f: F) -> Result<()>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(String, J)>>,
{
    let (mut results, mut failed) = (Vec::new(), 0);
    for did in dids {
        match f(did.clone()).await {
            Ok((line, j)) => {
                if !opts.json {
                    writeln!(out, "{line}")?;
                }
                results.push(json!({"did": did, "ok": true, "result": j}));
            }
            Err(e) => {
                failed += 1;
                if !opts.json {
                    writeln!(out, "{did}: FAILED: {e:#}")?;
                }
                results.push(json!({"did": did, "ok": false, "error": format!("{e:#}")}));
            }
        }
    }
    if opts.json {
        pretty(out, &J::Array(results))?;
    }
    if failed > 0 {
        bail!("{failed} of {} DIDs failed", dids.len());
    }
    Ok(())
}

/// (name, addr, node id to relay to; None: `c`'s node alone).
async fn cluster_nodes(c: &Client) -> Result<Vec<(String, String, Option<String>)>> {
    let r = c.get("vlpds.admin.getClusterStatus", &[]).await?;
    let nodes: Vec<(String, String, Option<String>)> = r["nodes"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|n| {
                    let id = n["node"].as_str()?.to_string();
                    Some((id.clone(), n["addr"].as_str()?.to_string(), Some(id)))
                })
                .collect()
        })
        .unwrap_or_default();
    if nodes.is_empty() {
        let name = r["node"].as_str().filter(|n| !n.is_empty()).unwrap_or("this node");
        return Ok(vec![(name.to_string(), c.base.clone(), None)]);
    }
    Ok(nodes)
}

pub type NodeHook = std::sync::Arc<dyn Fn(String) -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

static AFTER_NODE: parking_lot::Mutex<Option<NodeHook>> = parking_lot::Mutex::new(None);

/// Tests: awaited after each node's answer to a per-node command, with the
/// node's name (to move a shard between two nodes' calls).
pub fn set_after_node_hook(h: Option<NodeHook>) {
    *AFTER_NODE.lock() = h;
}

/// How long missing shards are rerun on their owners before the command
/// fails: long enough for a handoff, or a dead node's lease to expire and a
/// peer to take its shards over.
const COVERAGE_WAIT: Duration = Duration::from_secs(120);

/// Rounds in a row a live owner may answer a rerun with an error (not a
/// handoff: waiting would not help) before the command fails.
const COVERAGE_ERROR_ROUNDS: usize = 3;

/// Prints a table of `cols` per node and the totals. Each node scans the
/// shards it owns when called and lists them (`scanned`); a shard that moved
/// between two nodes' calls is in neither list, so the union is checked
/// against the current layout and missing shards are rerun on their owners
/// (`shards` in the body), until covered or for `COVERAGE_WAIT`; shards
/// still missing then fail the command.
async fn per_node(
    c: &Client,
    node_only: bool,
    opts: &Opts,
    out: &mut dyn Write,
    nsid: &str,
    body: J,
    cols: &[&str],
) -> Result<()> {
    let nodes =
        if node_only { vec![("this node".to_string(), c.base.clone(), None)] } else { cluster_nodes(c).await? };
    let mut results = Vec::new();
    let mut covered = std::collections::HashSet::new();
    let call = |name: String, url: String, id: Option<String>, body: J| async move {
        let r = match &id {
            Some(id) => c.post_to_node(id, nsid, &body).await,
            None => c.post(nsid, &body).await,
        };
        let row = match r {
            Ok(r) => json!({"node": name, "url": url, "ok": true, "result": r}),
            Err(e) => json!({"node": name, "url": url, "ok": false, "error": format!("{e:#}")}),
        };
        let hook = AFTER_NODE.lock().clone();
        if let Some(h) = hook {
            h(name).await;
        }
        row
    };
    for (node, url, id) in &nodes {
        results.push(call(node.clone(), url.clone(), id.clone(), body.clone()).await);
    }
    let mut missing = Vec::new();
    // in a cluster, a node's error leaves its shards missing (rerun below)
    let mut coverage_checked = false;
    let deadline = tokio::time::Instant::now() + COVERAGE_WAIT;
    let mut backoff = Duration::from_millis(100);
    // Mid-handoff, the table can still name the old owner (answering an
    // empty scan, or gone), or the new one before it has opened the shard:
    // those reruns are retried, their rows shown only if the command gives up.
    let mut pending = Vec::new();
    let mut error_rounds = 0;
    loop {
        if node_only {
            break;
        }
        for r in &results {
            covered.extend(r["result"]["scanned"].as_array().into_iter().flatten().filter_map(J::as_u64));
        }
        let st = c.get("vlpds.admin.getClusterStatus", &[]).await?;
        // not a cluster: the one node owns every shard
        let Some(shards) = st["layout"]["shards"].as_array() else { break };
        coverage_checked = true;
        let owners = st["table"].as_array().cloned().unwrap_or_default();
        let live: std::collections::HashSet<&str> =
            st["nodes"].as_array().into_iter().flatten().filter_map(|n| n["node"].as_str()).collect();
        missing = shards
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                let id = r["id"].as_u64()?;
                (!covered.contains(&id)).then(|| (id, owners.get(i).and_then(J::as_str).map(str::to_string)))
            })
            .collect::<Vec<(u64, Option<String>)>>();
        if missing.is_empty() {
            break;
        }
        if error_rounds >= COVERAGE_ERROR_ROUNDS || tokio::time::Instant::now() >= deadline {
            results.append(&mut pending);
            break;
        }
        if !pending.is_empty() || missing.iter().all(|(_, o)| o.is_none()) {
            tokio::time::sleep(backoff.min(deadline.saturating_duration_since(tokio::time::Instant::now()))).await;
            backoff = (backoff * 2).min(Duration::from_secs(2));
        }
        pending.clear();
        let mut by_owner: std::collections::BTreeMap<String, Vec<u64>> = Default::default();
        for (id, owner) in &missing {
            if let Some(o) = owner {
                by_owner.entry(o.clone()).or_default().push(*id);
            }
        }
        let mut live_error = false;
        for (owner, ids) in by_owner {
            let mut b = body.clone();
            b["shards"] = json!(ids);
            let url = nodes.iter().find(|n| n.0 == owner).map(|n| n.1.clone()).unwrap_or_default();
            let is_live = live.contains(owner.as_str());
            let row = call(format!("{owner} (rerun)"), url, Some(owner), b).await;
            let scanned = row["result"]["scanned"].as_array().is_some_and(|s| !s.is_empty());
            if scanned || row["result"]["failed"].as_u64().unwrap_or(0) > 0 {
                results.push(row);
            } else {
                live_error |= is_live && row["ok"] != json!(true);
                pending.push(row);
            }
        }
        error_rounds = if live_error { error_rounds + 1 } else { 0 };
    }
    let mut failed: usize = results.iter().map(|r| r["result"]["failed"].as_u64().unwrap_or(0) as usize).sum();
    if !coverage_checked {
        failed += results.iter().filter(|r| r["ok"] != json!(true)).count();
    }
    if opts.json {
        pretty(out, &J::Array(results.clone()))?;
    } else {
        let mut rows =
            vec![std::iter::once("node".to_string()).chain(cols.iter().map(|c| c.to_string())).collect::<Vec<_>>()];
        let mut totals = vec![0u64; cols.len()];
        for r in &results {
            let mut row = vec![s(&r["node"])];
            if r["ok"] == json!(true) {
                for (i, k) in cols.iter().enumerate() {
                    totals[i] += r["result"][*k].as_u64().unwrap_or(0);
                    row.push(s(&r["result"][*k]));
                }
            } else {
                row.push(format!("ERROR: {}", s(&r["error"])));
            }
            rows.push(row);
        }
        if results.len() > 1 {
            rows.push(std::iter::once("total".to_string()).chain(totals.iter().map(u64::to_string)).collect());
        }
        write!(out, "{}", table(&rows))?;
        for r in &results {
            for e in r["result"]["errors"].as_array().into_iter().flatten() {
                writeln!(out, "{}: {}", s(&r["node"]), s(e))?;
            }
        }
        if body["dryRun"] == json!(true) {
            writeln!(out, "(dry run: nothing changed)")?;
        }
    }
    if !missing.is_empty() {
        let ids: Vec<String> =
            missing.iter().map(|(id, owner)| format!("{id} (owner {})", owner.as_deref().unwrap_or("none"))).collect();
        bail!("shards not scanned by any node: {}", ids.join(", "));
    }
    if failed > 0 {
        bail!("{failed} failure(s)");
    }
    Ok(())
}

fn write_check(out: &mut dyn Write, r: &J) -> Result<()> {
    let n = &r["nodes"];
    let ix = &r["indexes"];
    writeln!(out, "Repo         : {} ({})", s(&r["did"]), if r["ok"] == json!(true) { "ok" } else { "PROBLEMS" })?;
    writeln!(
        out,
        "Head         : {} rev {} data {}",
        s(&r["head"]["commit"]),
        s(&r["head"]["rev"]),
        s(&r["head"]["data"])
    )?;
    writeln!(
        out,
        "Commit       : cid {} data {} did {} signature {}",
        s(&r["commit"]["cidOk"]),
        s(&r["commit"]["dataOk"]),
        s(&r["commit"]["didOk"]),
        s(&r["commit"]["signatureOk"])
    )?;
    writeln!(out, "Records      : {} ({} bad)", s(&r["records"]["count"]), s(&r["records"]["badCount"]))?;
    writeln!(
        out,
        "MST          : rebuilt root {} (matches head: {})",
        s(&r["mst"]["rebuiltRoot"]),
        s(&r["mst"]["matchesHead"])
    )?;
    writeln!(
        out,
        "Stored nodes : {} stored, {} expected, {} missing, {} extra, {} corrupt",
        s(&n["stored"]),
        s(&n["expected"]),
        s(&n["missing"]),
        s(&n["extra"]),
        s(&n["corrupt"])
    )?;
    writeln!(
        out,
        "Indexes      : record-CID {} missing / {} stale, blob-ref {} missing / {} stale, collections missing {}",
        s(&ix["recordCidMissing"]),
        s(&ix["recordCidExtra"]),
        s(&ix["blobRefMissing"]),
        s(&ix["blobRefExtra"]),
        s(&ix["collectionsMissing"])
    )?;
    for p in r["problems"].as_array().into_iter().flatten() {
        writeln!(out, "  - {}", s(p))?;
    }
    Ok(())
}

fn write_space_check(out: &mut dyn Write, r: &J) -> Result<()> {
    let ok = if r["ok"] == json!(true) { "ok" } else { "PROBLEMS" };
    writeln!(out, "Repo         : {} in {} ({ok})", s(&r["did"]), s(&r["space"]))?;
    match r["head"].is_null() {
        true => writeln!(out, "Head         : none")?,
        false => writeln!(
            out,
            "Head         : rev {} records {} hash {}",
            s(&r["head"]["rev"]),
            s(&r["head"]["records"]),
            s(&r["head"]["hash"])
        )?,
    }
    let rec = &r["records"];
    writeln!(
        out,
        "Records      : {} ({} bad), rehash {} (matches head: {})",
        s(&rec["count"]),
        s(&rec["badCount"]),
        s(&rec["rehash"]),
        s(&rec["matchesHead"])
    )?;
    let ol = &r["oplog"];
    writeln!(
        out,
        "Oplog        : {} op(s) in {} rev(s), {} .. {} ({})",
        s(&ol["ops"]),
        s(&ol["revs"]),
        s(&ol["oldestRev"]),
        s(&ol["newestRev"]),
        if ol["complete"] == json!(true) { "complete" } else { "window" }
    )?;
    if !r["outbox"].is_null() {
        writeln!(out, "Outbox       : notify owed for rev {}", s(&r["outbox"]["repoRev"]))?;
    }
    if !r["host"].is_null() {
        let h = &r["host"];
        writeln!(
            out,
            "Space host   : {} writer(s), {} listRepos row(s), max spaceRev {}{}",
            s(&h["writers"]),
            s(&h["seq"]),
            s(&h["maxSpaceRev"]),
            if h["live"] == json!(true) { "" } else { " (deleted)" }
        )?;
    }
    for p in r["problems"].as_array().into_iter().flatten() {
        writeln!(out, "  - {}", s(p))?;
    }
    Ok(())
}

fn write_cluster(out: &mut dyn Write, r: &J) -> Result<()> {
    let table_owners = r["table"].as_array().cloned().unwrap_or_default();
    let unowned = table_owners.iter().filter(|o| o.is_null()).count();
    writeln!(out, "Node         : {} (lease valid: {})", s(&r["node"]), s(&r["leaseValid"]))?;
    writeln!(
        out,
        "Shards       : {} in layout v{}, {} owned here, {} unowned",
        s(&r["shards"]),
        s(&r["layout"]["version"]),
        r["owned"].as_array().map_or(0, Vec::len),
        unowned
    )?;
    if !r["layout"]["op"].is_null() {
        writeln!(out, "Reshard      : {}", r["layout"]["op"])?;
    }
    writeln!(
        out,
        "Firehose     : last emitted {}, min watermark {}",
        s(&r["firehose"]["lastEmitted"]),
        s(&r["firehose"]["minWatermark"])
    )?;
    let v = &r["version"];
    if !v.is_null() {
        let target = if v["target"].is_null() { String::new() } else { format!(", raising to {}", s(&v["target"])) };
        writeln!(
            out,
            "Feature level: {} active{target} (this build {}..={}, rev {})",
            s(&v["active"]),
            s(&v["binary"]["min"]),
            s(&v["binary"]["max"]),
            s(&v["binary"]["rev"])
        )?;
        if v["mixedBuilds"] == json!(true) {
            writeln!(out, "Builds       : mixed ({})", s(&v["revs"]))?;
        }
        if !v["finalizable"].is_null() {
            writeln!(
                out,
                "Finalize     : every node can run level {}: `vlpds admin cluster finalize --level {}`",
                s(&v["finalizable"]),
                s(&v["finalizable"])
            )?;
        }
        if !v["finalizedAt"].is_null() {
            writeln!(out, "Finalized    : at {} (older builds can no longer join)", s(&v["finalizedAt"]))?;
        }
    }
    if r["fencedLogs"].as_object().is_some_and(|m| !m.is_empty()) {
        writeln!(out, "Fenced logs  : {}", r["fencedLogs"])?;
    }
    let nodes = r["nodes"].as_array().cloned().unwrap_or_default();
    if !nodes.is_empty() {
        writeln!(out)?;
        let mut rows = vec![["node", "addr", "reachable", "lease", "owned", "durable", "writer", "rev", "levels"]
            .map(String::from)
            .to_vec()];
        for n in &nodes {
            let name = if n["self"] == json!(true) { format!("{}*", s(&n["node"])) } else { s(&n["node"]) };
            let levels = format!("{}..={}", s(&n["minLevel"]), s(&n["maxLevel"]));
            rows.push(vec![
                name,
                s(&n["addr"]),
                s(&n["reachable"]),
                s(&n["leaseValid"]),
                s(&n["owned"]),
                s(&n["logDurableOrdinal"]),
                s(&n["writer"]),
                s(&n["rev"]),
                levels,
            ]);
        }
        write!(out, "{}", table(&rows))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align() {
        let t = table(&[vec!["a".into(), "bb".into(), "c".into()], vec!["ddd".into(), "e".into(), "".into()]]);
        assert_eq!(t, "a    bb  c\nddd  e\n");
    }

    #[test]
    fn passwords_and_dids() {
        let p = generate_password();
        assert_eq!(p.len(), 24);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(p, generate_password());
        assert!(check_did("did:plc:abc").is_ok());
        assert!(check_did("alice.test").is_err());
        let dir = std::env::temp_dir().join(format!("vlpds-dids-{}", std::process::id()));
        std::fs::write(&dir, "did:plc:a\n\n# comment\n  did:web:b  \n").unwrap();
        assert_eq!(did_list(vec!["did:plc:c".into()], Some(&dir)).unwrap(), ["did:plc:c", "did:plc:a", "did:web:b"]);
        std::fs::write(&dir, "not-a-did\n").unwrap();
        assert!(did_list(vec![], Some(&dir)).is_err());
        let _ = std::fs::remove_file(&dir);
        assert!(did_list(vec![], None).is_err());
    }
}
