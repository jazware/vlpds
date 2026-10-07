//! Outbound email over SMTP or over Cloudflare Email Sending's REST API
//! (DESIGN.md "Email"). Sending never blocks the request path: a full queue
//! drops the mail and counts it. The queue is in memory, so mail queued when
//! a node stops is lost (the user asks again), as with the reference PDS's
//! in-process nodemailer. Neither this nor the log-only mailer logs the
//! token or body above debug level, and nothing logs the API token.

mod templates;

pub use templates::{html_to_text, Branding, Email, SECURITY_PURPOSE};

use crate::xrpc::{Mail, Mailer};
use lettre::message::{header::ContentType, Mailbox, MultiPart};
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::transport::smtp::PoolConfig;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use prometheus::{
    exponential_buckets, register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge,
    Histogram, IntCounter, IntCounterVec, IntGauge,
};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};

/// TCP connect, and in lettre each SMTP command's read/write.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// One whole attempt: connect, EHLO/STARTTLS/AUTH, envelope and DATA, or
/// the API request and its response body.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_QUEUE: usize = 1024;
const DEFAULT_CONCURRENCY: usize = 4;
/// Waits before the 2nd, 3rd and 4th attempts.
const DEFAULT_BACKOFF: [Duration; 3] = [Duration::from_secs(2), Duration::from_secs(10), Duration::from_secs(60)];

macro_rules! lazy {
    ($name:ident: $t:ty = $e:expr) => {
        pub static $name: LazyLock<$t> = LazyLock::new(|| $e.unwrap());
    };
}
lazy!(MAIL_MESSAGES: IntCounterVec = register_int_counter_vec!("vlpds_mail_messages_total", "Outbound mail by result (sent; failed: permanent rejection or retries exhausted; dropped: queue full or mailer stopped) and purpose", &["result", "purpose"]));
lazy!(MAIL_SUPPRESSED: IntCounterVec = register_int_counter_vec!("vlpds_mail_suppressed_total", "Account mails not sent, by purpose and reason (recipient_limit: mail-recipient-*; node_limit: mail-node-hour; cluster_limit: mail-cluster-day; account_limit: password-reset-account-*, answered OK; dedup: an email sign-in code under a minute old is still live)", &["purpose", "reason"]));
lazy!(MAIL_RETRIES: IntCounter = register_int_counter!("vlpds_mail_retries_total", "Send attempts retried after a transient failure (SMTP 4xx, HTTP 429/5xx, connection error, timeout)"));
lazy!(MAIL_QUEUE: IntGauge = register_int_gauge!("vlpds_mail_queue_depth", "Mails queued or being sent (all of this process's mailers)"));
lazy!(MAIL_SEND_SECONDS: Histogram = register_histogram!("vlpds_mail_send_seconds", "One successful send, enqueue to accepted (incl. retries)", exponential_buckets(0.01, 2.0, 14).unwrap()));

/// This process's recent mail for the console (`vlpds.admin.listMail`):
/// purpose, the account it was for, the recipient's domain and the outcome.
/// Never the address, the body or a token.
pub static MAIL_LOG: LazyLock<MailLog> = LazyLock::new(MailLog::default);

#[derive(Default)]
pub struct MailLog {
    inner: parking_lot::Mutex<(u64, std::collections::VecDeque<MailLogEntry>)>,
    /// Told the id of each entry added or updated (the admin change feed); a
    /// watcher answering false is dropped.
    watchers: parking_lot::Mutex<Vec<Box<dyn Fn(u64) -> bool + Send + Sync>>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailLogEntry {
    pub id: u64,
    /// Unix ms it was queued (or refused).
    pub at: u64,
    pub purpose: String,
    /// The account it was sent for; None for mail to an address with no
    /// account behind it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub to_domain: String,
    /// queued | retrying | sent | failed | dropped | suppressed | logged
    /// (no mailer configured: written to the log only)
    pub status: String,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// suppressed: the budget that refused it (recipient_limit, node_limit,
    /// cluster_limit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix ms of the final outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done_at: Option<u64>,
    /// Queued to accepted, retries included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_ms: Option<u64>,
}

fn now_ms() -> u64 {
    crate::tid::now_micros() / 1000
}

/// The part after the last `@`, which is all the console may show of a
/// recipient.
pub fn recipient_domain(to: &str) -> String {
    let addr = to.rsplit_once('<').map_or(to, |(_, a)| a).trim().trim_end_matches('>');
    addr.rsplit_once('@').map(|(_, d)| d.trim().to_ascii_lowercase()).unwrap_or_default()
}

/// Provider errors can quote the recipient back: every word with an `@` in
/// it goes.
pub fn redact_error(why: &str) -> String {
    let s = why.split_whitespace().map(|w| if w.contains('@') { "[address]" } else { w }).collect::<Vec<_>>().join(" ");
    s.chars().take(300).collect()
}

impl MailLog {
    pub const KEPT: usize = 200;

    fn push(&self, purpose: &str, did: Option<&str>, to: &str, status: &str, f: impl FnOnce(&mut MailLogEntry)) -> u64 {
        let mut g = self.inner.lock();
        g.0 += 1;
        let mut e = MailLogEntry {
            id: g.0,
            at: now_ms(),
            purpose: purpose.to_string(),
            did: did.map(String::from),
            to_domain: recipient_domain(to),
            status: status.into(),
            attempts: 0,
            error: None,
            reason: None,
            done_at: None,
            send_ms: None,
        };
        f(&mut e);
        if g.1.len() >= Self::KEPT {
            g.1.pop_front();
        }
        g.1.push_back(e);
        let id = g.0;
        drop(g);
        self.changed(id);
        id
    }

    pub fn watch(&self, f: Box<dyn Fn(u64) -> bool + Send + Sync>) {
        self.watchers.lock().push(f);
    }

    fn changed(&self, id: u64) {
        self.watchers.lock().retain(|f| f(id));
    }

    pub fn queued(&self, purpose: &str, did: Option<&str>, to: &str) -> u64 {
        self.push(purpose, did, to, "queued", |_| {})
    }

    pub fn suppressed(&self, purpose: &str, did: Option<&str>, to: &str, reason: &str) {
        self.push(purpose, did, to, "suppressed", |e| {
            e.reason = Some(reason.into());
            e.done_at = Some(e.at);
        });
    }

    pub fn logged(&self, purpose: &str, did: Option<&str>, to: &str) {
        self.push(purpose, did, to, "logged", |e| e.done_at = Some(e.at));
    }

    fn update(&self, id: u64, f: impl FnOnce(&mut MailLogEntry)) {
        let mut g = self.inner.lock();
        if let Some(e) = g.1.iter_mut().rev().find(|e| e.id == id) {
            f(e);
            drop(g);
            self.changed(id);
        }
    }

    fn finish(&self, id: u64, status: &str, attempts: u32, error: Option<&str>) {
        self.update(id, |e| {
            let now = now_ms();
            e.status = status.into();
            e.attempts = attempts;
            e.error = error.map(redact_error);
            e.done_at = Some(now);
            if status == "sent" {
                e.send_ms = Some(now.saturating_sub(e.at));
            }
        });
    }

    /// Newest first; with `did`, only that account's.
    pub fn recent(&self, limit: usize, did: Option<&str>) -> Vec<MailLogEntry> {
        let g = self.inner.lock();
        g.1.iter().rev().filter(|e| did.is_none() || e.did.as_deref() == did).take(limit).cloned().collect()
    }
}

/// For `server::Config`, which is `Clone + Debug`.
#[derive(Clone)]
pub struct SharedMailer(pub Arc<dyn Mailer>);

impl std::fmt::Debug for SharedMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedMailer")
    }
}

impl std::ops::Deref for SharedMailer {
    type Target = dyn Mailer;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

#[derive(Clone)]
pub struct SmtpConfig {
    /// Nodemailer's URL form, as the reference's PDS_EMAIL_SMTP_URL:
    /// `smtp://` upgrades with STARTTLS when offered (`?tls=required`
    /// insists, `?tls=none` is plaintext), `smtps://` is implicit TLS. A
    /// path sets the EHLO name.
    pub url: String,
    /// `addr@host` or `Name <addr@host>`.
    pub from: String,
    pub queue: usize,
    /// Also the SMTP connection pool's size.
    pub concurrency: usize,
    pub backoff: Vec<Duration>,
    /// PEM CA certificate(s) trusted for the server's certificate on top of
    /// the webpki roots (a relay with a private CA).
    pub ca_pem: Option<Vec<u8>>,
}

/// Redacts the URL's password.
impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = match reqwest::Url::parse(&self.url) {
            Ok(mut u) if u.password().is_some() => {
                let _ = u.set_password(Some("redacted"));
                u.to_string()
            }
            Ok(u) => u.to_string(),
            Err(_) => "<unparsable>".into(),
        };
        f.debug_struct("SmtpConfig")
            .field("url", &url)
            .field("from", &self.from)
            .field("queue", &self.queue)
            .field("concurrency", &self.concurrency)
            .field("backoff", &self.backoff)
            .field("ca_pem", &self.ca_pem.is_some())
            .finish()
    }
}

impl SmtpConfig {
    pub fn new(url: impl Into<String>, from: impl Into<String>) -> Self {
        SmtpConfig {
            url: url.into(),
            from: from.into(),
            queue: DEFAULT_QUEUE,
            concurrency: DEFAULT_CONCURRENCY,
            backoff: DEFAULT_BACKOFF.to_vec(),
            ca_pem: None,
        }
    }
}

/// Cloudflare Email Sending's REST API: a JSON POST with a bearer token,
/// for hosts whose provider blocks outbound SMTP.
#[derive(Clone)]
pub struct ApiConfig {
    /// `https://api.cloudflare.com/client/v4/accounts/{account_id}/email/sending/send`.
    /// `http://` only to a loopback host (tests): the token is a bearer
    /// credential.
    pub url: String,
    /// An API token with Email Sending: Edit.
    pub token: String,
    pub from: String,
    pub queue: usize,
    /// Also the HTTP connection pool's idle size.
    pub concurrency: usize,
    pub backoff: Vec<Duration>,
}

impl std::fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfig")
            .field("url", &self.url)
            .field("token", &"redacted")
            .field("from", &self.from)
            .field("queue", &self.queue)
            .field("concurrency", &self.concurrency)
            .field("backoff", &self.backoff)
            .finish()
    }
}

impl ApiConfig {
    pub fn new(url: impl Into<String>, token: impl Into<String>, from: impl Into<String>) -> Self {
        ApiConfig {
            url: url.into(),
            token: token.into(),
            from: from.into(),
            queue: DEFAULT_QUEUE,
            concurrency: DEFAULT_CONCURRENCY,
            backoff: DEFAULT_BACKOFF.to_vec(),
        }
    }
}

/// One mailer's flags. At most one of `smtp_url` and `api_url`.
#[derive(Default)]
pub struct Flags<'a> {
    pub smtp_url: Option<String>,
    pub api_url: Option<String>,
    pub api_token: Option<String>,
    pub from: Option<String>,
    pub ca_file: Option<&'a Path>,
}

/// None: log-only. A transport without a from address (or the reverse), or
/// both transports, is an error. Must run inside the tokio runtime.
pub fn from_flags(f: Flags<'_>) -> anyhow::Result<Option<SharedMailer>> {
    let m = start_if_set(f, "", "email-from-address", ("PDS_EMAIL_SMTP_URL", "PDS_EMAIL_FROM_ADDRESS"))?;
    if m.is_none() {
        tracing::info!(
            "email disabled (no --email-smtp-url or --email-api-url): mail is logged without its token and not sent"
        );
    }
    Ok(m)
}

/// The reference's ModerationMailer, for admin sendEmail. None: it falls
/// back to the main mailer (DESIGN.md "Email").
pub fn moderation_from_flags(f: Flags<'_>) -> anyhow::Result<Option<SharedMailer>> {
    let m = start_if_set(
        f,
        "moderation-",
        "moderation-email-address",
        ("PDS_MODERATION_EMAIL_SMTP_URL", "PDS_MODERATION_EMAIL_ADDRESS"),
    )?;
    if m.is_some() {
        tracing::info!("moderation email (admin sendEmail) has its own mailer");
    }
    Ok(m)
}

/// The SMTP URL and from address fall back to the reference PDS's env vars.
fn start_if_set(
    f: Flags<'_>,
    prefix: &str,
    from_flag: &str,
    (url_env, from_env): (&str, &str),
) -> anyhow::Result<Option<SharedMailer>> {
    let smtp = pick(f.smtp_url, url_env);
    let api = f.api_url.filter(|v| !v.is_empty());
    let from = pick(f.from, from_env);
    let (smtp_flag, api_flag) = (format!("--{prefix}email-smtp-url"), format!("--{prefix}email-api-url"));
    if smtp.is_some() && api.is_some() {
        anyhow::bail!("email config: set only one of {smtp_flag} and {api_flag}");
    }
    if smtp.is_none() && api.is_none() {
        anyhow::ensure!(from.is_none(), "email config: --{from_flag} is set without {smtp_flag} or {api_flag}");
        return Ok(None);
    }
    let Some(from) = from else {
        anyhow::bail!("email config: {} needs --{from_flag}", if smtp.is_some() { &smtp_flag } else { &api_flag });
    };
    let mailer = match (smtp, api) {
        (Some(url), _) => {
            let ca_pem = match f.ca_file {
                Some(p) => {
                    Some(std::fs::read(p).map_err(|e| anyhow::anyhow!("--email-smtp-ca-file {}: {e}", p.display()))?)
                }
                None => None,
            };
            QueueMailer::start_smtp(SmtpConfig { ca_pem, ..SmtpConfig::new(url, from) })?
        }
        (None, Some(url)) => {
            let token = f.api_token.filter(|t| !t.is_empty()).ok_or_else(|| {
                anyhow::anyhow!("email config: {api_flag} needs --{prefix}email-api-token-file (or --email-api-token)")
            })?;
            QueueMailer::start_api(ApiConfig::new(url, token, from))?
        }
        (None, None) => unreachable!(),
    };
    Ok(Some(SharedMailer(Arc::new(mailer))))
}

/// A non-empty flag value, else the non-empty env var `k`.
fn pick(v: Option<String>, k: &str) -> Option<String> {
    v.filter(|v| !v.is_empty()).or_else(|| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// A bounded queue in front of one transport.
pub struct QueueMailer {
    tx: mpsc::Sender<(u64, Mail)>,
}

impl QueueMailer {
    /// Needs a tokio runtime.
    pub fn start_smtp(cfg: SmtpConfig) -> anyhow::Result<QueueMailer> {
        let from = parse_from(&cfg.from)?;
        let (transport, host) = transport(&cfg)?;
        tracing::info!(smtp_host = %host, from = %from, "email enabled (SMTP)");
        let sender = Sender { transport: Transport::Smtp(transport), from, backoff: cfg.backoff };
        Ok(Self::spawn(sender, cfg.queue, cfg.concurrency))
    }

    /// Needs a tokio runtime.
    pub fn start_api(cfg: ApiConfig) -> anyhow::Result<QueueMailer> {
        let from = parse_from(&cfg.from)?;
        let api = Api::new(&cfg)?;
        tracing::info!(api_host = %api.host, from = %from, "email enabled (HTTP API)");
        let sender = Sender { transport: Transport::Api(api), from, backoff: cfg.backoff };
        Ok(Self::spawn(sender, cfg.queue, cfg.concurrency))
    }

    fn spawn(sender: Sender, queue: usize, concurrency: usize) -> QueueMailer {
        let (tx, rx) = mpsc::channel(queue.max(1));
        tokio::spawn(run(rx, Arc::new(sender), concurrency.max(1)));
        QueueMailer { tx }
    }
}

fn parse_from(from: &str) -> anyhow::Result<Mailbox> {
    from.parse().map_err(|e| anyhow::anyhow!("--email-from-address {from:?}: {e}"))
}

impl Mailer for QueueMailer {
    fn send(&self, mail: &Mail) {
        let id = MAIL_LOG.queued(&mail.purpose, mail.did.as_deref(), &mail.to);
        match self.tx.try_send((id, mail.clone())) {
            Ok(()) => MAIL_QUEUE.inc(),
            Err(e) => {
                let why = match e {
                    mpsc::error::TrySendError::Full(_) => "queue full",
                    mpsc::error::TrySendError::Closed(_) => "mailer stopped",
                };
                MAIL_LOG.finish(id, "dropped", 0, Some(why));
                MAIL_MESSAGES.with_label_values(&["dropped", &mail.purpose]).inc();
                tracing::warn!(to = %mail.to, purpose = %mail.purpose, "mail dropped: {why}");
            }
        }
    }
}

/// nodemailer's default for smtp:// is opportunistic STARTTLS, lettre's is
/// plaintext (which it spells without `tls=`).
fn normalize_url(url: &str) -> anyhow::Result<String> {
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let mut params: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
    let tls = params.iter().position(|p| p.starts_with("tls="));
    if base.starts_with("smtp://") {
        match tls.map(|i| params[i]) {
            // nodemailer's smtp://: upgrade with STARTTLS when the server offers it
            None => params.push("tls=opportunistic"),
            Some("tls=none") => {
                params.remove(tls.unwrap());
            }
            Some("tls=required" | "tls=opportunistic") => {}
            Some(other) => anyhow::bail!("--email-smtp-url: unknown {other} (required, opportunistic, none)"),
        }
    } else if !base.starts_with("smtps://") {
        anyhow::bail!("--email-smtp-url must be smtp:// or smtps://");
    }
    Ok(if params.is_empty() { base.to_string() } else { format!("{base}?{}", params.join("&")) })
}

/// Also returns the host for logs: the URL may hold a password.
fn transport(cfg: &SmtpConfig) -> anyhow::Result<(AsyncSmtpTransport<Tokio1Executor>, String)> {
    let url = normalize_url(&cfg.url)?;
    let host = url
        .split_once("://")
        .map(|(_, r)| r)
        .and_then(|r| r.split(['/', '?']).next())
        .map(|r| r.rsplit('@').next().unwrap_or(r).to_string())
        .unwrap_or_default();
    let mut b = AsyncSmtpTransport::<Tokio1Executor>::from_url(&url)
        .map_err(|e| anyhow::anyhow!("--email-smtp-url (host {host:?}): {e}"))?;
    if let Some(pem) = &cfg.ca_pem {
        b = b.tls(with_ca(&url, pem)?);
    }
    let t =
        b.timeout(Some(CONNECT_TIMEOUT)).pool_config(PoolConfig::new().max_size(cfg.concurrency.max(1) as u32)).build();
    Ok((t, host))
}

/// The TLS mode `from_url` picked for the normalized `url`, re-made with
/// `pem`'s certificates added to the trusted roots.
fn with_ca(url: &str, pem: &[u8]) -> anyhow::Result<Tls> {
    let u = reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("--email-smtp-url: {e}"))?;
    let domain = u.host_str().unwrap_or_default().trim_matches(['[', ']']).to_string();
    let mode = u.query_pairs().find(|(k, _)| k == "tls").map(|(_, v)| v.into_owned());
    let wrap: fn(TlsParameters) -> Tls = match (u.scheme(), mode.as_deref()) {
        ("smtps", _) => Tls::Wrapper,
        (_, Some("required")) => Tls::Required,
        (_, Some("opportunistic")) => Tls::Opportunistic,
        _ => return Ok(Tls::None),
    };
    let cert = Certificate::from_pem(pem).map_err(|e| anyhow::anyhow!("--email-smtp-ca-file: {e}"))?;
    let params = TlsParameters::builder(domain)
        .add_root_certificate(cert)
        .build_rustls()
        .map_err(|e| anyhow::anyhow!("--email-smtp-ca-file: {e}"))?;
    Ok(wrap(params))
}

struct Api {
    client: reqwest::Client,
    url: reqwest::Url,
    /// Marked sensitive, so reqwest's and hyper's debug output hide it.
    auth: HeaderValue,
    host: String,
}

impl Api {
    fn new(cfg: &ApiConfig) -> anyhow::Result<Api> {
        let url = reqwest::Url::parse(&cfg.url).map_err(|e| anyhow::anyhow!("--email-api-url: {e}"))?;
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        let h = url.host_str().unwrap_or_default();
        let loopback =
            h == "localhost" || h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback());
        anyhow::ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && loopback),
            "--email-api-url must be https:// (host {host:?})"
        );
        anyhow::ensure!(
            url.username().is_empty() && url.password().is_none(),
            "--email-api-url must not carry credentials; use --email-api-token-file"
        );
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", cfg.token.trim()))
            .map_err(|_| anyhow::anyhow!("--email-api-token holds characters a header can't carry"))?;
        auth.set_sensitive(true);
        let client = crate::http::dedicated("mail", cfg.concurrency.max(1), None, false)?;
        Ok(Api { client, url, auth, host })
    }

    async fn send(&self, body: &bytes::Bytes) -> Result<(), Failure> {
        let r = self
            .client
            .post(self.url.clone())
            .header(AUTHORIZATION, self.auth.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body.clone())
            .send()
            .await
            .map_err(|e| Failure::transient(format!("request failed: {}", e.without_url())))?;
        let status = r.status();
        let body = r.bytes().await.unwrap_or_default();
        classify(status, &body)
    }
}

#[derive(Debug, PartialEq)]
struct Failure {
    retry: bool,
    why: String,
}

impl Failure {
    fn transient(why: String) -> Failure {
        Failure { retry: true, why }
    }
    fn permanent(why: String) -> Failure {
        Failure { retry: false, why }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ApiResponse {
    success: Option<bool>,
    errors: Vec<ApiError>,
    result: Option<ApiResult>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ApiError {
    code: Option<i64>,
    message: String,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ApiResult {
    permanent_bounces: Vec<serde_json::Value>,
    suppressed_recipients: Vec<serde_json::Value>,
}

/// 429, 408 and 5xx are transient, like SMTP 4xx. Any other non-2xx is
/// permanent (a bad token, an unonboarded sender, a malformed message), and
/// so is a 2xx that reports the one recipient bounced or suppressed. The
/// reason holds only the status and Cloudflare's error codes: the body
/// could echo the message.
fn classify(status: StatusCode, body: &[u8]) -> Result<(), Failure> {
    let parsed: Option<ApiResponse> = serde_json::from_slice(body).ok();
    let errors = parsed
        .as_ref()
        .map(|r| {
            r.errors
                .iter()
                .take(3)
                .map(|e| {
                    let msg: String = e.message.chars().take(120).collect();
                    match e.code {
                        Some(c) => format!("{c} {msg}"),
                        None => msg,
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let why = if errors.is_empty() { format!("HTTP {status}") } else { format!("HTTP {status}: {errors}") };
    if status.is_success() {
        // 2xx without a parsable body still means accepted: retrying could
        // deliver twice
        let Some(r) = parsed else { return Ok(()) };
        if r.success == Some(false) {
            return Err(Failure::permanent(why));
        }
        let res = r.result.unwrap_or_default();
        if !res.permanent_bounces.is_empty() {
            return Err(Failure::permanent("recipient bounced permanently".into()));
        }
        if !res.suppressed_recipients.is_empty() {
            return Err(Failure::permanent("recipient is on the suppression list".into()));
        }
        return Ok(());
    }
    if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::REQUEST_TIMEOUT || status.is_server_error() {
        Err(Failure::transient(why))
    } else {
        Err(Failure::permanent(why))
    }
}

/// Cloudflare's JSON form: a bare address, or `{address, name}` with a
/// display name. Message-ID and Date are set by Cloudflare (it refuses
/// them in `headers`).
fn api_body(from: &Mailbox, m: &Mail) -> anyhow::Result<bytes::Bytes> {
    fn addr(m: &Mailbox) -> serde_json::Value {
        match &m.name {
            Some(n) if !n.is_empty() => serde_json::json!({"address": m.email.to_string(), "name": n}),
            _ => serde_json::Value::String(m.email.to_string()),
        }
    }
    let to: Mailbox = m.to.parse().map_err(|e| anyhow::anyhow!("recipient: {e}"))?;
    let mut body = serde_json::json!({
        "from": addr(from),
        "to": addr(&to),
        "subject": m.subject,
        "text": m.body,
    });
    if let Some(html) = &m.html {
        body["html"] = serde_json::Value::String(html.clone());
    }
    Ok(serde_json::to_vec(&body)?.into())
}

enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    Api(Api),
}

enum Prepared {
    Smtp(Message),
    Api(bytes::Bytes),
}

struct Sender {
    transport: Transport,
    from: Mailbox,
    backoff: Vec<Duration>,
}

impl Sender {
    fn prepare(&self, m: &Mail) -> anyhow::Result<Prepared> {
        Ok(match self.transport {
            Transport::Smtp(_) => Prepared::Smtp(message(&self.from, m)?),
            Transport::Api(_) => Prepared::Api(api_body(&self.from, m)?),
        })
    }

    async fn attempt(&self, p: &Prepared) -> Result<(), Failure> {
        match (&self.transport, p) {
            (Transport::Smtp(t), Prepared::Smtp(msg)) => match t.send(msg.clone()).await {
                Ok(_) => Ok(()),
                Err(e) => Err(Failure { retry: smtp_retryable(&e), why: e.to_string() }),
            },
            (Transport::Api(a), Prepared::Api(body)) => a.send(body).await,
            _ => unreachable!("prepared for the other transport"),
        }
    }
}

async fn run(mut rx: mpsc::Receiver<(u64, Mail)>, sender: Arc<Sender>, concurrency: usize) {
    let slots = Arc::new(Semaphore::new(concurrency));
    while let Some((id, mail)) = rx.recv().await {
        let Ok(slot) = slots.clone().acquire_owned().await else { break };
        let sender = sender.clone();
        tokio::spawn(async move {
            send_one(&sender, id, mail).await;
            MAIL_QUEUE.dec();
            drop(slot);
        });
    }
}

fn message(from: &Mailbox, m: &Mail) -> anyhow::Result<Message> {
    let to: Mailbox = m.to.parse().map_err(|e| anyhow::anyhow!("recipient: {e}"))?;
    // lettre sets no Message-ID, and some receivers (Gmail) refuse or junk
    // mail without one; the sender's domain, not the container's hostname
    let id = format!("<{}@{}>", hex::encode(rand::random::<[u8; 16]>()), from.email.domain());
    let b = Message::builder().from(from.clone()).to(to).subject(m.subject.as_str()).message_id(Some(id));
    Ok(match &m.html {
        // multipart/alternative: text/plain first, text/html preferred
        Some(html) => b.multipart(MultiPart::alternative_plain_html(m.body.clone(), html.clone()))?,
        None => b.header(ContentType::TEXT_PLAIN).body(m.body.clone())?,
    })
}

fn smtp_retryable(e: &lettre::transport::smtp::Error) -> bool {
    !(e.is_permanent() || e.is_client())
}

/// ±25%.
fn jitter(d: Duration) -> Duration {
    d.mul_f64(0.75 + rand::random::<f64>() * 0.5)
}

async fn send_one(s: &Sender, id: u64, mail: Mail) {
    let started = std::time::Instant::now();
    let fail = |why: &str, attempts: usize| {
        MAIL_LOG.finish(id, "failed", attempts as u32, Some(why));
        MAIL_MESSAGES.with_label_values(&["failed", &mail.purpose]).inc();
        tracing::warn!(to = %mail.to, purpose = %mail.purpose, attempts, "mail not sent: {why}");
    };
    let p = match s.prepare(&mail) {
        Ok(p) => p,
        Err(e) => return fail(&format!("invalid message: {e}"), 0),
    };
    let mut attempt = 0;
    loop {
        attempt += 1;
        let f = match tokio::time::timeout(SEND_TIMEOUT, s.attempt(&p)).await {
            Ok(Ok(())) => {
                MAIL_LOG.finish(id, "sent", attempt as u32, None);
                MAIL_MESSAGES.with_label_values(&["sent", &mail.purpose]).inc();
                MAIL_SEND_SECONDS.observe(started.elapsed().as_secs_f64());
                tracing::info!(to = %mail.to, purpose = %mail.purpose, attempts = attempt, "mail sent");
                return;
            }
            Ok(Err(f)) => f,
            Err(_) => Failure::transient(format!("send timed out after {SEND_TIMEOUT:?}")),
        };
        let Some(wait) = s.backoff.get(attempt - 1).filter(|_| f.retry) else {
            return fail(&f.why, attempt);
        };
        MAIL_RETRIES.inc();
        MAIL_LOG.update(id, |e| {
            e.status = "retrying".into();
            e.attempts = attempt as u32;
            e.error = Some(redact_error(&f.why));
        });
        tracing::info!(to = %mail.to, purpose = %mail.purpose, attempt, "mail send failed, retrying: {}", f.why);
        tokio::time::sleep(jitter(*wait)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_defaults_follow_nodemailer() {
        assert_eq!(normalize_url("smtp://u:p@h:587").unwrap(), "smtp://u:p@h:587?tls=opportunistic");
        assert_eq!(normalize_url("smtp://h?tls=none").unwrap(), "smtp://h");
        assert_eq!(normalize_url("smtp://h?tls=required").unwrap(), "smtp://h?tls=required");
        assert_eq!(normalize_url("smtps://u:p@h").unwrap(), "smtps://u:p@h");
        assert!(normalize_url("http://h").is_err());
        assert!(normalize_url("smtp://h?tls=bogus").is_err());
    }

    fn flags(smtp: Option<&str>, api: Option<&str>, token: Option<&str>, from: Option<&str>) -> Flags<'static> {
        Flags {
            smtp_url: smtp.map(Into::into),
            api_url: api.map(Into::into),
            api_token: token.map(Into::into),
            from: from.map(Into::into),
            ca_file: None,
        }
    }

    #[tokio::test]
    async fn partial_config_is_an_error() {
        assert!(
            from_flags(flags(Some("smtp://h"), None, None, Some(""))).is_err()
                || std::env::var("PDS_EMAIL_FROM_ADDRESS").is_ok()
        );
        assert!(QueueMailer::start_smtp(SmtpConfig::new("smtp://h", "not an address")).is_err());
        let (_, host) = transport(&SmtpConfig::new("smtps://user:secret@mail.example.com:465/ehlo", "a@b.c")).unwrap();
        assert_eq!(host, "mail.example.com:465");
    }

    #[tokio::test]
    async fn exactly_one_transport() {
        let api = "https://api.cloudflare.com/client/v4/accounts/x/email/sending/send";
        let e = from_flags(flags(Some("smtps://h"), Some(api), Some("t"), Some("a@b.c"))).err().unwrap().to_string();
        assert!(e.contains("only one of --email-smtp-url and --email-api-url"), "{e}");
        let e = moderation_from_flags(flags(Some("smtps://h"), Some(api), Some("t"), Some("a@b.c")))
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("--moderation-email-smtp-url and --moderation-email-api-url"), "{e}");
        let e = from_flags(flags(None, Some(api), None, Some("a@b.c"))).err().unwrap().to_string();
        assert!(e.contains("--email-api-token-file"), "{e}");
        if std::env::var("PDS_EMAIL_FROM_ADDRESS").is_err() {
            let e = from_flags(flags(None, Some(api), Some("t"), None)).err().unwrap().to_string();
            assert!(e.contains("--email-api-url needs --email-from-address"), "{e}");
        }
        assert!(from_flags(flags(None, Some(api), Some("t"), Some("vlpds <a@b.c>"))).unwrap().is_some());
    }

    #[tokio::test]
    async fn api_url_must_be_https_unless_loopback() {
        let start = |url: &str| QueueMailer::start_api(ApiConfig::new(url, "t", "a@b.c")).map(|_| ());
        assert!(start("http://api.cloudflare.com/x").is_err());
        assert!(start("https://user:pw@api.cloudflare.com/x").is_err());
        assert!(start("ftp://localhost/x").is_err());
        assert!(start("https://api.cloudflare.com/x").is_ok());
        assert!(start("http://127.0.0.1:9/x").is_ok());
        assert!(start("http://localhost:9/x").is_ok());
        assert!(QueueMailer::start_api(ApiConfig::new("https://h/x", "bad\ntoken", "a@b.c")).is_err());
    }

    #[test]
    fn mail_log_keeps_no_address() {
        assert_eq!(recipient_domain("Alice <alice@Example.COM>"), "example.com");
        assert_eq!(recipient_domain("bob@mail.example.org"), "mail.example.org");
        assert_eq!(recipient_domain("nobody"), "");
        assert_eq!(
            redact_error("550 5.1.1 <bob@example.org>: Recipient address rejected"),
            "550 5.1.1 [address] Recipient address rejected"
        );
        let log = MailLog::default();
        let id = log.queued("confirm_email", Some("did:plc:fixture"), "carol@example.net");
        log.update(id, |e| e.status = "retrying".into());
        log.finish(id, "failed", 3, Some("rejected carol@example.net"));
        log.suppressed("reset_password", None, "dave@example.net", "recipient_limit");
        let mine = log.recent(10, Some("did:plc:fixture"));
        assert_eq!((mine.len(), mine[0].did.as_deref()), (1, Some("did:plc:fixture")));
        let r = log.recent(10, None);
        assert_eq!((r[0].status.as_str(), r[0].reason.as_deref()), ("suppressed", Some("recipient_limit")));
        assert_eq!((r[1].status.as_str(), r[1].attempts), ("failed", 3));
        let all = serde_json::to_string(&r).unwrap();
        assert!(!all.contains("carol") && !all.contains("dave"), "{all}");
    }

    #[test]
    fn api_config_debug_hides_the_token() {
        let d = format!("{:?}", ApiConfig::new("https://h/x", "s3cret-token", "a@b.c"));
        assert!(!d.contains("s3cret-token"), "{d}");
    }

    fn mail(to: &str, html: Option<&str>) -> Mail {
        Mail {
            to: to.into(),
            subject: "Password Reset Requested".into(),
            body: "code ABCDE-12345".into(),
            html: html.map(Into::into),
            purpose: "reset_password".into(),
            did: None,
            token: Some("ABCDE-12345".into()),
            sent_at: String::new(),
        }
    }

    fn body(from: &str, m: &Mail) -> serde_json::Value {
        serde_json::from_slice(&api_body(&from.parse().unwrap(), m).unwrap()).unwrap()
    }

    #[test]
    fn api_body_matches_cloudflares_schema() {
        let b = body("pds.example.com <noreply@pds.example.com>", &mail("erin@example.com", Some("<p>hi</p>")));
        assert_eq!(
            b,
            serde_json::json!({
                "from": {"address": "noreply@pds.example.com", "name": "pds.example.com"},
                "to": "erin@example.com",
                "subject": "Password Reset Requested",
                "text": "code ABCDE-12345",
                "html": "<p>hi</p>",
            })
        );
        let b = body("noreply@vlpds.test", &mail("Erin <erin@example.com>", None));
        assert_eq!(b["from"], "noreply@vlpds.test");
        assert_eq!(b["to"], serde_json::json!({"address": "erin@example.com", "name": "Erin"}));
        assert!(b.get("html").is_none());
        assert!(api_body(&"a@b.c".parse().unwrap(), &mail("not an address", None)).is_err());
    }

    #[test]
    fn api_status_classification() {
        let ok = br#"{"success":true,"errors":[],"messages":[],"result":{"delivered":["e@x.com"],"permanent_bounces":[],"queued":[]}}"#;
        assert_eq!(classify(StatusCode::OK, ok), Ok(()));
        let queued = br#"{"success":true,"result":{"delivered":[],"permanent_bounces":[],"queued":["e@x.com"]}}"#;
        assert_eq!(classify(StatusCode::OK, queued), Ok(()));
        assert_eq!(classify(StatusCode::OK, b"not json"), Ok(()));
        let bounced = br#"{"success":true,"result":{"delivered":[],"permanent_bounces":["e@x.com"],"queued":[]}}"#;
        assert!(!classify(StatusCode::OK, bounced).unwrap_err().retry);
        let suppressed = br#"{"success":true,"result":{"suppressed_recipients":["e@x.com"]}}"#;
        assert!(!classify(StatusCode::OK, suppressed).unwrap_err().retry);

        let err = |code: u16, n: i64, msg: &str| {
            let b = serde_json::json!({"success": false, "errors": [{"code": n, "message": msg}], "result": null});
            classify(StatusCode::from_u16(code).unwrap(), b.to_string().as_bytes()).unwrap_err()
        };
        let f = err(429, 10004, "email.sending.error.throttled");
        assert!(f.retry);
        assert_eq!(f.why, "HTTP 429 Too Many Requests: 10004 email.sending.error.throttled");
        assert!(err(500, 10002, "email.sending.error.internal_server").retry);
        assert!(err(503, 10100, "email.sending.error.authentication.upstream").retry);
        for (s, c) in [(400, 10001), (400, 10200), (401, 10101), (403, 10102), (403, 10203), (404, 10000)] {
            assert!(!err(s, c, "x").retry, "{s} {c}");
        }
        assert!(classify(StatusCode::BAD_GATEWAY, b"<html>").unwrap_err().retry);
        assert_eq!(classify(StatusCode::BAD_GATEWAY, b"<html>").unwrap_err().why, "HTTP 502 Bad Gateway");
        assert!(classify(StatusCode::REQUEST_TIMEOUT, b"").unwrap_err().retry);
    }
}
