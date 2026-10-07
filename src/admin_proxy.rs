//! Operator identity from a trusted proxy, on the admin listener only
//! (`--admin-listen`; docs/operations/admin-console.md "Sign-in through a
//! proxy"). A proxy in front of that listener (Caddy with Tailscale whois,
//! `tailscale serve`, Cloudflare Access, oauth2-proxy) names the operator in
//! one header; vlpds takes it only from `--admin-proxy-from` addresses and
//! only for `--admin-operators` logins, and then treats the request as the
//! admin token would, with that login in the audit log.
//!
//! The identity is ambient, like a cookie: the operator's browser carries it
//! to whatever page asks, and every response allows any origin (CORS `*`).
//! So a request that a browser marks cross-site gets no identity: a write
//! must show it came from the console's own origin (`Sec-Fetch-Site:
//! same-origin`, or an `Origin` naming this host), and a read refused only
//! when the browser says it's cross-site (a curl read sends neither).
//! An `Authorization` header always wins: token auth is unchanged.
//!
//! A request the entry node forwards to an account's owner carries the
//! login in [`OPERATOR_HEADER`], trusted there only next to a valid
//! forwarded marker (`forward::FORWARDED_HEADER`).

use crate::ratelimit::Cidr;
use axum::http::{header, HeaderMap, HeaderName, Method};
use std::net::IpAddr;
use std::sync::Arc;

/// Peer-only: the operator a forwarded request was authenticated as.
pub const OPERATOR_HEADER: &str = "x-vlpds-operator";

/// Longest login kept (an email address fits).
const MAX_LOGIN: usize = 256;

#[derive(Clone, Debug)]
pub struct Settings {
    pub header: HeaderName,
    pub from: Vec<Cidr>,
    pub operators: Vec<String>,
}

impl Settings {
    pub fn parse(header: &str, from: &[String], operators: &[String]) -> anyhow::Result<Settings> {
        let name = HeaderName::from_bytes(header.trim().as_bytes())
            .map_err(|_| anyhow::anyhow!("--admin-proxy-header: {header:?} is not a header name"))?;
        let reserved = [
            header::AUTHORIZATION.as_str(),
            header::COOKIE.as_str(),
            header::HOST.as_str(),
            header::ORIGIN.as_str(),
            "sec-fetch-site",
            "x-forwarded-for",
            crate::ratelimit::CLIENT_IP_HEADER,
        ];
        anyhow::ensure!(
            !reserved.contains(&name.as_str()) && !name.as_str().starts_with("x-vlpds-"),
            "--admin-proxy-header: {name} is a header vlpds reads for something else"
        );
        let mut nets = Vec::new();
        for s in from.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let c = Cidr::parse(s).ok_or_else(|| anyhow::anyhow!("--admin-proxy-from: {s:?} is not an IP or CIDR"))?;
            anyhow::ensure!(c.bits() > 0, "--admin-proxy-from: {s} trusts every address; name the proxy");
            nets.push(c);
        }
        anyhow::ensure!(!nets.is_empty(), "--admin-proxy-header needs --admin-proxy-from (the proxy's addresses)");
        let operators: Vec<String> = operators.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        anyhow::ensure!(!operators.is_empty(), "--admin-proxy-header needs --admin-operators (the logins allowed in)");
        Ok(Settings { header: name, from: nets, operators })
    }

    fn trusts(&self, peer: IpAddr) -> bool {
        self.from.iter().any(|c| c.contains(&peer))
    }
}

/// Request extension: what the admin listener made of the proxy's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyIdentity {
    Operator(Arc<str>),
    /// A trusted proxy named someone, but not one the request may act as.
    Refused(String),
}

impl ProxyIdentity {
    pub fn operator(&self) -> Option<&str> {
        match self {
            ProxyIdentity::Operator(l) => Some(l),
            ProxyIdentity::Refused(_) => None,
        }
    }
}

/// The admin listener's verdict on one request. None: no identity (no
/// header, a peer outside `--admin-proxy-from`, or an Authorization header,
/// which token auth answers).
pub fn identify(s: &Settings, peer: Option<IpAddr>, headers: &HeaderMap, method: &Method) -> Option<ProxyIdentity> {
    let raw = headers.get(&s.header)?;
    if headers.contains_key(header::AUTHORIZATION) {
        return None;
    }
    if !peer.is_some_and(|p| s.trusts(p.to_canonical())) {
        tracing::debug!(peer = ?peer, header = %s.header, "admin proxy header from an untrusted peer: ignored");
        return None;
    }
    if headers.get_all(&s.header).iter().count() > 1 {
        return Some(ProxyIdentity::Refused(format!("more than one {} header", s.header)));
    }
    let login = raw.to_str().map(str::trim).unwrap_or("");
    if login.is_empty() || login.len() > MAX_LOGIN || login.chars().any(char::is_control) {
        return Some(ProxyIdentity::Refused(format!("{} is not a login", s.header)));
    }
    if !s.operators.iter().any(|o| o == login) {
        return Some(ProxyIdentity::Refused(format!("{login} is not an operator here")));
    }
    if let Err(why) = same_origin(headers, method) {
        return Some(ProxyIdentity::Refused(why));
    }
    Some(ProxyIdentity::Operator(login.into()))
}

/// Writes need the browser's word that the console's own origin sent them;
/// reads are refused only on its word that another site did. A non-browser
/// client sends neither header, so its reads pass and its writes don't
/// (scripts use the admin token).
fn same_origin(headers: &HeaderMap, method: &Method) -> Result<(), String> {
    let site = headers.get("sec-fetch-site").map(|v| v.to_str().unwrap_or("?"));
    let origin = headers.get(header::ORIGIN).map(|v| v.to_str().unwrap_or("?"));
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let cross = |why: String| Err(format!("cross-site request refused ({why}); use the console's own origin"));
    if let Some(site) = site.filter(|s| !matches!(*s, "same-origin" | "none")) {
        return cross(format!("Sec-Fetch-Site: {site}"));
    }
    if let Some(o) = origin.filter(|o| !origin_is_host(o, host)) {
        return cross(format!("Origin: {o}"));
    }
    let read = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if !read && site != Some("same-origin") && origin.is_none() {
        return cross("a write without Sec-Fetch-Site: same-origin or Origin".into());
    }
    Ok(())
}

/// `Origin` is `scheme://host[:port]`; the proxy passes the client's `Host`.
fn origin_is_host(origin: &str, host: Option<&str>) -> bool {
    let Some(host) = host else { return false };
    let Some((scheme, authority)) = origin.split_once("://") else { return false };
    if !matches!(scheme, "https" | "http") {
        return false;
    }
    let default = if scheme == "https" { ":443" } else { ":80" };
    let strip = |a: &str| a.strip_suffix(default).unwrap_or(a).to_ascii_lowercase();
    strip(authority) == strip(host)
}

/// The admin listener's outer layer: the proxy's header becomes a
/// [`ProxyIdentity`] extension and never reaches anything else.
pub async fn layer(
    axum::extract::State(app): axum::extract::State<Arc<crate::xrpc::App>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(s) = app.config.admin_proxy.as_deref() {
        let peer = req.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>().map(|c| c.0.ip());
        let id = identify(s, peer, req.headers(), req.method());
        req.headers_mut().remove(&s.header);
        if let Some(id) = id {
            req.extensions_mut().insert(id);
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn settings() -> Settings {
        Settings::parse(
            "Tailscale-User-Login",
            &["172.31.83.0/24".into(), "127.0.0.1".into()],
            &["alice@example.com".into()],
        )
        .unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("admin.example.com"));
        for (k, v) in pairs {
            h.append(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    const PROXY: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(172, 31, 83, 2)));
    const ALICE: &str = "alice@example.com";

    fn op() -> Option<ProxyIdentity> {
        Some(ProxyIdentity::Operator(ALICE.into()))
    }

    #[test]
    fn settings_refuse_what_cannot_work() {
        let ops = ["a@example.com".to_string()];
        let from = ["10.0.0.0/8".to_string()];
        assert!(Settings::parse("Authorization", &from, &ops).is_err());
        assert!(Settings::parse("x-vlpds-operator", &from, &ops).is_err());
        assert!(Settings::parse("bad header", &from, &ops).is_err());
        assert!(Settings::parse("X-Login", &["0.0.0.0/0".into()], &ops).is_err());
        assert!(Settings::parse("X-Login", &["nope".into()], &ops).is_err());
        assert!(Settings::parse("X-Login", &[], &ops).is_err());
        assert!(Settings::parse("X-Login", &from, &[" ".into()]).is_err());
        assert!(Settings::parse("X-Login", &from, &ops).is_ok());
    }

    #[test]
    fn trusted_peer_and_allowlist() {
        let s = settings();
        let h = headers(&[("tailscale-user-login", ALICE)]);
        assert_eq!(identify(&s, PROXY, &h, &Method::GET), op());
        // untrusted peer, or none known: the header means nothing
        assert_eq!(identify(&s, Some("100.64.0.9".parse().unwrap()), &h, &Method::GET), None);
        assert_eq!(identify(&s, None, &h, &Method::GET), None);
        // an IPv4-mapped peer is its IPv4 address
        assert_eq!(identify(&s, Some("::ffff:127.0.0.1".parse().unwrap()), &h, &Method::GET), op());
        let mallory = headers(&[("tailscale-user-login", "mallory@example.com")]);
        assert!(matches!(identify(&s, PROXY, &mallory, &Method::GET), Some(ProxyIdentity::Refused(_))));
        let two = headers(&[("tailscale-user-login", ALICE), ("tailscale-user-login", ALICE)]);
        assert!(matches!(identify(&s, PROXY, &two, &Method::GET), Some(ProxyIdentity::Refused(_))));
        // token auth answers a request that brings one
        let tok = headers(&[("tailscale-user-login", ALICE), ("authorization", "Basic x")]);
        assert_eq!(identify(&s, PROXY, &tok, &Method::POST), None);
        assert_eq!(identify(&s, PROXY, &headers(&[]), &Method::GET), None);
    }

    #[test]
    fn cross_site_requests_get_no_identity() {
        let s = settings();
        let id = |pairs: &[(&str, &str)], m: Method| {
            let mut all = vec![("tailscale-user-login", ALICE)];
            all.extend_from_slice(pairs);
            identify(&s, PROXY, &headers(&all), &m)
        };
        let refused = |r: Option<ProxyIdentity>| matches!(r, Some(ProxyIdentity::Refused(_)));
        // writes: only with evidence of the console's own origin
        assert_eq!(id(&[("sec-fetch-site", "same-origin")], Method::POST), op());
        assert_eq!(id(&[("origin", "https://admin.example.com")], Method::POST), op());
        assert_eq!(id(&[("origin", "https://ADMIN.example.com:443")], Method::POST), op());
        assert!(refused(id(&[], Method::POST)));
        assert!(refused(id(&[("sec-fetch-site", "none")], Method::POST)));
        assert!(refused(id(&[("sec-fetch-site", "cross-site")], Method::POST)));
        assert!(refused(id(&[("sec-fetch-site", "same-site")], Method::POST)));
        assert!(refused(id(&[("origin", "https://evil.example.net")], Method::POST)));
        assert!(refused(id(&[("origin", "null")], Method::POST)));
        assert!(refused(id(
            &[("sec-fetch-site", "same-origin"), ("origin", "https://evil.example.net")],
            Method::POST
        )));
        // reads: refused only when the browser says another site asked
        assert_eq!(id(&[], Method::GET), op());
        assert_eq!(id(&[("sec-fetch-site", "none")], Method::GET), op());
        assert_eq!(id(&[("sec-fetch-site", "same-origin")], Method::GET), op());
        assert!(refused(id(&[("sec-fetch-site", "cross-site")], Method::GET)));
        assert!(refused(id(&[("origin", "https://evil.example.net")], Method::GET)));
    }
}
