//! tokio-console's layer. The same file is in every service that has one.

use std::net::SocketAddr;
use std::time::Duration;

/// How long finished tasks, resources and async ops stay in the console.
/// console-subscriber's default of an hour held gigabytes in processes that
/// spawn many short-lived tasks.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(60);

/// Instrumentation events queued for the aggregator; past this they're
/// dropped and the console counts them. console-subscriber's default is
/// 102400.
pub const DEFAULT_EVENT_BUFFER: usize = 16 * 1024;

/// Updates queued for each console client before it's dropped: a minute at
/// the 1 s publish interval. An update can carry every task, so the default
/// of 4096 let a stalled client pin over an hour of them.
pub const DEFAULT_CLIENT_BUFFER: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub addr: SocketAddr,
    pub retention: Duration,
    pub event_buffer: usize,
    pub client_buffer: usize,
}

/// TOKIO_CONSOLE_BIND turns on tokio-console's server in a build with
/// `--cfg tokio_unstable`, as the images are. Its gRPC API has no auth, so
/// only a loopback address is taken. TOKIO_CONSOLE_RETENTION (`60s`, `5m`),
/// TOKIO_CONSOLE_BUFFER_CAPACITY and TOKIO_CONSOLE_CLIENT_BUFFER_CAPACITY
/// override the defaults above.
pub fn settings() -> Result<Option<Settings>, String> {
    let s = parse(|k| std::env::var(k).ok())?;
    if s.is_some() && !cfg!(tokio_unstable) {
        return Err(concat!(
            "TOKIO_CONSOLE_BIND is set, but this build has no ",
            "--cfg tokio_unstable; tokio-console stays off"
        )
        .into());
    }
    Ok(s)
}

fn parse(env: impl Fn(&str) -> Option<String>) -> Result<Option<Settings>, String> {
    let get = |k: &str| env(k).filter(|v| !v.is_empty());
    let Some(v) = get("TOKIO_CONSOLE_BIND") else {
        return Ok(None);
    };
    let off = "tokio-console stays off";
    let addr: SocketAddr = v.parse().map_err(|e| format!("TOKIO_CONSOLE_BIND={v}: {e}; {off}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!("TOKIO_CONSOLE_BIND={v} isn't a loopback address; {off}"));
    }
    let retention = match get("TOKIO_CONSOLE_RETENTION") {
        None => DEFAULT_RETENTION,
        Some(v) => duration(&v).ok_or_else(|| format!("TOKIO_CONSOLE_RETENTION={v} isn't like 60s or 5m; {off}"))?,
    };
    let capacity = |k: &str, default: usize| match get(k) {
        None => Ok(default),
        Some(v) => match v.parse::<usize>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!("{k}={v} isn't a positive count; {off}")),
        },
    };
    Ok(Some(Settings {
        addr,
        retention,
        event_buffer: capacity("TOKIO_CONSOLE_BUFFER_CAPACITY", DEFAULT_EVENT_BUFFER)?,
        client_buffer: capacity("TOKIO_CONSOLE_CLIENT_BUFFER_CAPACITY", DEFAULT_CLIENT_BUFFER)?,
    }))
}

/// `500ms`, `60s`, `5m`, `1h`, or bare seconds.
fn duration(v: &str) -> Option<Duration> {
    let v = v.trim();
    let digits = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let (n, unit) = v.split_at(digits);
    let n: u64 = n.parse().ok()?;
    match unit.trim() {
        "ms" => Some(Duration::from_millis(n)),
        "" | "s" => Some(Duration::from_secs(n)),
        "m" => n.checked_mul(60).map(Duration::from_secs),
        "h" => n.checked_mul(3600).map(Duration::from_secs),
        _ => None,
    }
}

#[cfg(tokio_unstable)]
pub fn layer<S>(s: &Settings) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    console_subscriber::ConsoleLayer::builder()
        .server_addr(s.addr)
        .retention(s.retention)
        .event_buffer_capacity(s.event_buffer)
        .client_buffer_capacity(s.client_buffer)
        .spawn()
}

#[cfg(not(tokio_unstable))]
pub fn layer<S>(_: &Settings) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber,
{
    tracing_subscriber::layer::Identity::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            let v = vars.iter().find(|(n, _)| *n == k)?;
            Some(v.1.to_string())
        }
    }

    #[test]
    fn off_without_bind() {
        assert_eq!(parse(env(&[])), Ok(None));
        assert_eq!(parse(env(&[("TOKIO_CONSOLE_BIND", "")])), Ok(None));
    }

    #[test]
    fn defaults() {
        let s = parse(env(&[("TOKIO_CONSOLE_BIND", "127.0.0.1:6669")])).unwrap().unwrap();
        assert_eq!(s.addr, "127.0.0.1:6669".parse().unwrap());
        assert_eq!(s.retention, Duration::from_secs(60));
        assert_eq!(s.event_buffer, DEFAULT_EVENT_BUFFER);
        assert_eq!(s.client_buffer, DEFAULT_CLIENT_BUFFER);
    }

    #[test]
    fn overrides() {
        let s = parse(env(&[
            ("TOKIO_CONSOLE_BIND", "[::1]:6669"),
            ("TOKIO_CONSOLE_RETENTION", "5m"),
            ("TOKIO_CONSOLE_BUFFER_CAPACITY", "1000"),
            ("TOKIO_CONSOLE_CLIENT_BUFFER_CAPACITY", "8"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(s.retention, Duration::from_secs(300));
        assert_eq!(s.event_buffer, 1000);
        assert_eq!(s.client_buffer, 8);
    }

    #[test]
    fn durations() {
        assert_eq!(duration("60s"), Some(Duration::from_secs(60)));
        assert_eq!(duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(duration("1d"), None);
        assert_eq!(duration("s"), None);
        assert_eq!(duration("-5s"), None);
    }

    #[test]
    fn rejects() {
        let bind = ("TOKIO_CONSOLE_BIND", "127.0.0.1:6669");
        assert!(parse(env(&[("TOKIO_CONSOLE_BIND", "0.0.0.0:6669")])).is_err());
        assert!(parse(env(&[("TOKIO_CONSOLE_BIND", "nope")])).is_err());
        assert!(parse(env(&[bind, ("TOKIO_CONSOLE_RETENTION", "soon")])).is_err());
        assert!(parse(env(&[bind, ("TOKIO_CONSOLE_BUFFER_CAPACITY", "0")])).is_err());
        let client = ("TOKIO_CONSOLE_CLIENT_BUFFER_CAPACITY", "x");
        assert!(parse(env(&[bind, client])).is_err());
    }
}
