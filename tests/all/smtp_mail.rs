//! Outbound email over SMTP (src/mail.rs) against a tiny in-test SMTP server:
//! a password reset reaches the SMTP server with the right envelope, subject
//! and token as multipart/alternative (text + the reference's HTML layout);
//! admin sendEmail goes to the moderation mailer when one is configured,
//! else the main one; transient (4xx) failures are retried, permanent (5xx)
//! ones are not; a full queue drops instead of blocking the request path;
//! smtps:// (implicit TLS, as Cloudflare Email Sending) authenticates and
//! trusts a private CA only when given one (`ca_pem`).
use crate::common::*;
use base64::Engine;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use vlpds::mail::{QueueMailer, SharedMailer, SmtpConfig, MAIL_MESSAGES, MAIL_RETRIES};
use vlpds::xrpc::{Mail, Mailer};

#[derive(Debug)]
struct Received {
    from: String,
    rcpt: Vec<String>,
    data: String,
}

type Replies = Arc<Mutex<VecDeque<String>>>;

/// Minimal SMTP responder: no STARTTLS/AUTH. `mail_from_replies` answers the
/// first MAIL FROM commands (across connections) with these replies instead
/// of 250, e.g. "451 4.3.0 busy".
async fn fake_smtp(mail_from_replies: &[&str]) -> (SocketAddr, mpsc::UnboundedReceiver<Received>, Arc<Mutex<usize>>) {
    let (addr, rx, mail_froms, _) = fake_server(mail_from_replies, None).await;
    (addr, rx, mail_froms)
}

/// With `tls`: implicit TLS (SMTPS) with AUTH PLAIN/LOGIN advertised; each
/// AUTH PLAIN's decoded credentials ("|user|pass") go to the returned log.
async fn fake_server(
    mail_from_replies: &[&str],
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> (SocketAddr, mpsc::UnboundedReceiver<Received>, Arc<Mutex<usize>>, Arc<Mutex<Vec<String>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let replies: Replies = Arc::new(Mutex::new(mail_from_replies.iter().map(|s| s.to_string()).collect()));
    let mail_froms = Arc::new(Mutex::new(0usize));
    let auths = Arc::new(Mutex::new(Vec::new()));
    let (seen, auth_log) = (mail_froms.clone(), auths.clone());
    tokio::spawn(async move {
        while let Ok((sock, _)) = l.accept().await {
            let (tx, replies, seen, auth_log, tls) =
                (tx.clone(), replies.clone(), seen.clone(), auth_log.clone(), tls.clone());
            tokio::spawn(async move {
                match tls {
                    Some(acc) => {
                        if let Ok(s) = acc.accept(sock).await {
                            session(s, tx, replies, seen, Some(auth_log)).await
                        }
                    }
                    None => session(sock, tx, replies, seen, None).await,
                }
            });
        }
    });
    (addr, rx, mail_froms, auths)
}

async fn session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    sock: S,
    tx: mpsc::UnboundedSender<Received>,
    replies: Replies,
    seen: Arc<Mutex<usize>>,
    auth_log: Option<Arc<Mutex<Vec<String>>>>,
) {
    let (r, mut w) = tokio::io::split(sock);
    let mut r = BufReader::new(r);
    w.write_all(b"220 fake.test ESMTP\r\n").await.ok();
    w.flush().await.ok();
    let (mut from, mut rcpt) = (String::new(), Vec::new());
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let up = line.to_ascii_uppercase();
        let arg =
            |s: &str| s.split_once(':').map(|(_, v)| v.trim().trim_matches(['<', '>']).to_string()).unwrap_or_default();
        let reply: String = if up.starts_with("EHLO") || up.starts_with("HELO") {
            if auth_log.is_some() {
                "250-fake.test\r\n250 AUTH PLAIN LOGIN".into()
            } else {
                "250 fake.test".into()
            }
        } else if let (Some(log), true) = (&auth_log, up.starts_with("AUTH PLAIN ")) {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&line.trim_end().as_bytes()["AUTH PLAIN ".len()..])
                .unwrap_or_default();
            log.lock().push(String::from_utf8_lossy(&raw).replace('\0', "|"));
            "235 2.7.0 ok".into()
        } else if up.starts_with("MAIL FROM") {
            *seen.lock() += 1;
            match replies.lock().pop_front() {
                Some(r) => r,
                None => {
                    from = arg(&line);
                    "250 2.1.0 ok".into()
                }
            }
        } else if up.starts_with("RCPT TO") {
            rcpt.push(arg(&line));
            "250 2.1.5 ok".into()
        } else if up.starts_with("DATA") {
            w.write_all(b"354 go ahead\r\n").await.ok();
            w.flush().await.ok();
            let mut data = String::new();
            loop {
                line.clear();
                if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                if line == ".\r\n" {
                    break;
                }
                data.push_str(&line);
            }
            let _ = tx.send(Received { from: std::mem::take(&mut from), rcpt: std::mem::take(&mut rcpt), data });
            "250 2.0.0 queued".into()
        } else if up.starts_with("RSET") || up.starts_with("NOOP") {
            from.clear();
            rcpt.clear();
            "250 ok".into()
        } else if up.starts_with("QUIT") {
            w.write_all(b"221 bye\r\n").await.ok();
            w.flush().await.ok();
            return;
        } else {
            "502 unknown".into()
        };
        if w.write_all(format!("{reply}\r\n").as_bytes()).await.is_err() || w.flush().await.is_err() {
            return;
        }
    }
}

fn cfg(addr: SocketAddr) -> SmtpConfig {
    SmtpConfig {
        backoff: vec![Duration::from_millis(20); 3],
        ..SmtpConfig::new(format!("smtp://{addr}"), "vlpds <noreply@vlpds.test>")
    }
}

fn mail(purpose: &str, to: &str) -> Mail {
    Mail {
        to: to.into(),
        subject: "Test".into(),
        body: "code ABCDE-12345".into(),
        html: None,
        purpose: purpose.into(),
        did: None,
        token: Some("ABCDE-12345".into()),
        sent_at: String::new(),
    }
}

async fn next(rx: &mut mpsc::UnboundedReceiver<Received>) -> Received {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("no mail within 20 s")
        .expect("smtp server stopped")
}

fn count(result: &str, purpose: &str) -> u64 {
    MAIL_MESSAGES.with_label_values(&[result, purpose]).get()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn password_reset_is_mailed_over_smtp() {
    let (addr, mut rx, _) = fake_smtp(&[]).await;
    let mailer = QueueMailer::start_smtp(cfg(addr)).unwrap();
    let s = TestServer::spawn_with(|c| c.mailer = Some(SharedMailer(Arc::new(mailer)))).await;
    let a = s.create_account("smtp").await;

    s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": a.email}), &Auth::None).await.ok();
    let m = loop {
        let m = next(&mut rx).await;
        if m.data.contains("Password Reset Requested") {
            break m;
        }
    };
    assert_eq!(m.rcpt, vec![a.email.to_ascii_lowercase()]);
    assert_eq!(m.from, "noreply@vlpds.test");
    assert!(m.data.contains("Subject: Password Reset Requested\r\n"), "{}", m.data);
    let id = m.data.lines().find_map(|l| l.strip_prefix("Message-ID: ")).expect("Message-ID");
    assert!(id.starts_with('<') && id.ends_with("@vlpds.test>") && id.len() == 32 + "<@vlpds.test>".len(), "{id}");
    assert!(m.data.to_ascii_lowercase().contains(&format!("to: {}", a.email.to_ascii_lowercase())), "{}", m.data);

    // dev mode still keeps the mailbox; its token is the one in the SMTP body
    let token = s.mail_token(&a.email).await.expect("dev mailbox token");
    let ps = parts(&m.data);
    assert_eq!(ps.len(), 2, "{}", m.data);
    assert!(ps[0].0.starts_with("text/plain"), "{:?}", ps[0].0);
    assert!(ps[1].0.starts_with("text/html"), "{:?}", ps[1].0);
    let (text, html) = (&ps[0].1, &ps[1].1);
    assert!(text.contains(&format!("\n{token}\n")), "token {token} not in text: {text}");
    assert!(text.contains(&format!("reset the password for the account @{}.", a.handle)), "{text}");
    assert!(html.contains(&format!(">{token}</code>")), "token {token} not in html: {html}");
    assert!(html.contains("<title>Reset password</title>"), "{html}");
    assert!(html.contains(&format!(">@<!-- -->{}<!-- -->.</span>", a.handle)), "{html}");
    // and it resets the password
    s.xrpc
        .post("com.atproto.server.resetPassword", &json!({"token": token, "password": "a-new-password-1"}), &Auth::None)
        .await
        .ok();
}

/// (content-type, decoded body) of each part of a multipart message as the
/// fake server received it (still dot-stuffed).
fn parts(data: &str) -> Vec<(String, String)> {
    let data = data.replace("\r\n..", "\r\n.");
    let head = data.split("\r\n\r\n").next().unwrap();
    assert!(
        head.to_ascii_lowercase().contains("content-type: multipart/alternative"),
        "not multipart/alternative: {head}"
    );
    let b = head.split("boundary=\"").nth(1).and_then(|r| r.split('"').next()).expect("boundary");
    let sep = format!("--{b}");
    data.split(sep.as_str())
        .skip(1)
        .filter(|p| !p.starts_with("--"))
        .map(|p| {
            let p = p.trim_start_matches("\r\n");
            let (h, body) = p.split_once("\r\n\r\n").unwrap();
            let hl = h.to_ascii_lowercase();
            let header = |name: &str| {
                hl.lines().find_map(|l| l.strip_prefix(name)).map(|v| v.trim().to_string()).unwrap_or_default()
            };
            let body = body.trim_end_matches("\r\n");
            let decoded = match header("content-transfer-encoding:").as_str() {
                "base64" => String::from_utf8(
                    base64::engine::general_purpose::STANDARD.decode(body.replace("\r\n", "")).unwrap(),
                )
                .unwrap(),
                "quoted-printable" => qp_decode(body),
                _ => body.replace("\r\n", "\n"),
            };
            (header("content-type:"), decoded)
        })
        .collect()
}

fn qp_decode(s: &str) -> String {
    let s = s.replace("=\r\n", "").replace("\r\n", "\n");
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' && i + 3 <= b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

/// Waits for a mail whose subject is `subject` (skipping others).
async fn next_with_subject(rx: &mut mpsc::UnboundedReceiver<Received>, subject: &str) -> Received {
    loop {
        let m = next(rx).await;
        if m.data.contains(&format!("Subject: {subject}\r\n")) {
            return m;
        }
    }
}

/// True if no mail with `subject` arrives within `wait`.
async fn none_with_subject(rx: &mut mpsc::UnboundedReceiver<Received>, subject: &str, wait: Duration) -> bool {
    tokio::time::timeout(wait, next_with_subject(rx, subject)).await.is_err()
}

const MOD_HTML: &str = "<p>Hello &amp; welcome</p><p>Your post was <b>removed</b>.</p>";

async fn admin_send(s: &TestServer, did: &str, subject: &str) {
    let r = s
        .xrpc
        .post(
            "com.atproto.admin.sendEmail",
            &json!({"recipientDid": did, "content": MOD_HTML, "subject": subject, "senderDid": "did:plc:admin"}),
            &Auth::Admin,
        )
        .await
        .ok();
    assert_eq!(r["sent"], json!(true));
}

fn assert_moderation_mail(m: &Received) {
    let ps = parts(&m.data);
    assert_eq!(ps.len(), 2, "{}", m.data);
    assert!(ps[0].0.starts_with("text/plain") && ps[1].0.starts_with("text/html"), "{ps:?}");
    // the HTML content goes out as is, with a derived text part
    assert_eq!(ps[1].1, MOD_HTML);
    assert_eq!(ps[0].1, "Hello & welcome\n\nYour post was removed.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_send_email_uses_the_moderation_mailer() {
    let (main_addr, mut main_rx, _) = fake_smtp(&[]).await;
    let (mod_addr, mut mod_rx, _) = fake_smtp(&[]).await;
    let main = QueueMailer::start_smtp(cfg(main_addr)).unwrap();
    let modm = QueueMailer::start_smtp(SmtpConfig {
        backoff: vec![Duration::from_millis(20); 3],
        ..SmtpConfig::new(format!("smtp://{mod_addr}"), "Moderation <moderation@vlpds.test>")
    })
    .unwrap();
    let s = TestServer::spawn_with(|c| {
        c.mailer = Some(SharedMailer(Arc::new(main)));
        c.moderation_mailer = Some(SharedMailer(Arc::new(modm)));
    })
    .await;
    let a = s.create_account("modmail").await;
    admin_send(&s, &a.did, "A note from the moderators").await;
    let m = next_with_subject(&mut mod_rx, "A note from the moderators").await;
    assert_eq!(m.from, "moderation@vlpds.test");
    assert_eq!(m.rcpt, vec![a.email.to_ascii_lowercase()]);
    assert_moderation_mail(&m);
    assert!(none_with_subject(&mut main_rx, "A note from the moderators", Duration::from_millis(500)).await);

    // account mail still goes through the main mailer
    s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": a.email}), &Auth::None).await.ok();
    let m = next_with_subject(&mut main_rx, "Password Reset Requested").await;
    assert_eq!(m.from, "noreply@vlpds.test");
    assert!(none_with_subject(&mut mod_rx, "Password Reset Requested", Duration::from_millis(500)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_send_email_falls_back_to_the_main_mailer() {
    let (addr, mut rx, _) = fake_smtp(&[]).await;
    let mailer = QueueMailer::start_smtp(cfg(addr)).unwrap();
    let s = TestServer::spawn_with(|c| c.mailer = Some(SharedMailer(Arc::new(mailer)))).await;
    let a = s.create_account("modfb").await;
    admin_send(&s, &a.did, "Fallback notice").await;
    let m = next_with_subject(&mut rx, "Fallback notice").await;
    assert_eq!(m.from, "noreply@vlpds.test");
    assert_moderation_mail(&m);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_failures_are_retried() {
    let (addr, mut rx, mail_froms) = fake_smtp(&["451 4.3.0 try again", "421 4.7.0 busy"]).await;
    let m = QueueMailer::start_smtp(cfg(addr)).unwrap();
    let retries = MAIL_RETRIES.get();
    m.send(&mail("test_transient", "bob@example.com"));
    let r = next(&mut rx).await;
    assert_eq!(r.rcpt, vec!["bob@example.com".to_string()]);
    assert!(r.data.contains("code ABCDE-12345"));
    assert_eq!(*mail_froms.lock(), 3);
    assert!(MAIL_RETRIES.get() >= retries + 2);
    for _ in 0..100 {
        if count("sent", "test_transient") == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("sent counter not bumped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permanent_failures_are_not_retried() {
    let (addr, _rx, mail_froms) = fake_smtp(&["550 5.7.1 rejected"]).await;
    let m = QueueMailer::start_smtp(cfg(addr)).unwrap();
    m.send(&mail("test_permanent", "carol@example.com"));
    for _ in 0..250 {
        if count("failed", "test_permanent") == 1 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(*mail_froms.lock(), 1, "a 5xx must not be retried");
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("failed counter not bumped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_queue_drops_without_blocking() {
    // accepts connections but never greets: every send hangs until its timeout
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    let m = QueueMailer::start_smtp(SmtpConfig { queue: 1, concurrency: 1, ..cfg(addr) }).unwrap();
    let t = std::time::Instant::now();
    for _ in 0..10 {
        m.send(&mail("test_overflow", "dave@example.com"));
    }
    assert!(t.elapsed() < Duration::from_millis(100), "send blocked: {:?}", t.elapsed());
    // queue of 1, at most one in flight and one waiting for a send slot
    assert!(count("dropped", "test_overflow") >= 7, "dropped {}", count("dropped", "test_overflow"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtps_with_auth_and_a_private_ca() {
    use rustls_pki_types::pem::PemObject;
    let ca = vlpds::peer_tls::create_ca("smtp test CA", 1).unwrap();
    let leaf = vlpds::peer_tls::issue_node(&ca.cert_pem, &ca.key_pem, "smtp", &["localhost".into()], 1).unwrap();
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(leaf.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(vlpds::peer_tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let (addr, mut rx, _, auths) = fake_server(&[], Some(tokio_rustls::TlsAcceptor::from(Arc::new(server)))).await;
    let url = format!("smtps://api_token:secret-token@localhost:{}", addr.port());

    // the webpki roots alone don't trust it: nothing is authenticated or sent
    let m = QueueMailer::start_smtp(SmtpConfig {
        backoff: vec![],
        ..SmtpConfig::new(url.clone(), "vlpds <noreply@vlpds.test>")
    })
    .unwrap();
    m.send(&mail("test_smtps_untrusted", "erin@example.com"));
    for _ in 0..250 {
        if count("failed", "test_smtps_untrusted") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(count("failed", "test_smtps_untrusted"), 1);
    assert!(auths.lock().is_empty());

    let m = QueueMailer::start_smtp(SmtpConfig {
        ca_pem: Some(ca.cert_pem.into_bytes()),
        ..SmtpConfig::new(url, "vlpds <noreply@vlpds.test>")
    })
    .unwrap();
    m.send(&mail("test_smtps", "erin@example.com"));
    let r = next(&mut rx).await;
    assert_eq!(r.rcpt, vec!["erin@example.com".to_string()]);
    assert_eq!(r.from, "noreply@vlpds.test");
    assert_eq!(*auths.lock(), vec!["|api_token|secret-token".to_string()]);
}
