//! What the node was started with, for `vlpds.admin.getConfig`: every
//! server flag with where its value came from (command line, environment or
//! built-in default), recorded once by `main` after parsing. Secret flags
//! never keep their value: only whether they are set and a short
//! fingerprint, so two nodes can be compared.

use sha2::{Digest, Sha256};
use std::sync::OnceLock;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Setting {
    /// `--public-url`
    pub flag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// flag | env | default | unset
    pub source: String,
    /// None for a secret, or a flag with no value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub secret: bool,
    /// Secrets only: `sha256:` and the first 8 hex digits of the effective
    /// value (read from its `-file` flag when that set it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// First line of the flag's help.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub help: String,
}

static SETTINGS: OnceLock<Vec<Setting>> = OnceLock::new();

pub fn fingerprint(v: &str) -> String {
    format!("sha256:{}", hex::encode(&Sha256::digest(v.as_bytes())[..4]))
}

/// Builds the list from clap's matches. `effective(id)` gives a secret
/// flag's value as the node uses it (after `-file` flags were read), keyed by
/// the arg id.
pub fn from_matches(
    cmd: &clap::Command,
    m: &clap::ArgMatches,
    effective: impl Fn(&str) -> Option<String>,
) -> Vec<Setting> {
    use clap::parser::ValueSource;
    let mut out = Vec::new();
    for a in cmd.get_arguments() {
        let id = a.get_id().as_str();
        let Some(long) = a.get_long() else { continue };
        if matches!(id, "help" | "version") {
            continue;
        }
        let secret = a.is_hide_env_values_set();
        let source = match m.value_source(id) {
            Some(ValueSource::CommandLine) => "flag",
            Some(ValueSource::EnvVariable) => "env",
            Some(ValueSource::DefaultValue) => "default",
            _ => "unset",
        };
        let raw: Option<String> = m
            .get_raw(id)
            .map(|vs| vs.map(|v| v.to_string_lossy().into_owned()).collect::<Vec<_>>().join(","))
            .filter(|v| !v.is_empty());
        let (value, fingerprint) = if secret {
            let eff = effective(id).filter(|v| !v.is_empty());
            (None, eff.as_deref().map(fingerprint))
        } else {
            (raw.map(|v| strip_userinfo(&v)), None)
        };
        let source = if secret && source == "unset" && fingerprint.is_some() { "file" } else { source };
        out.push(Setting {
            flag: format!("--{long}"),
            env: a.get_env().map(|e| e.to_string_lossy().into_owned()),
            source: source.into(),
            value,
            secret,
            fingerprint,
            help: a.get_help().map(|h| h.to_string().lines().next().unwrap_or("").to_string()).unwrap_or_default(),
        });
    }
    out
}

/// `https://user:pass@host/…` → `https://host/…`: a URL flag can carry
/// credentials without being marked secret.
fn strip_userinfo(v: &str) -> String {
    v.split(',')
        .map(|part| match part.split_once("://") {
            Some((scheme, rest)) => {
                let host_end = rest.find('/').unwrap_or(rest.len());
                match rest[..host_end].rfind('@') {
                    Some(at) => format!("{scheme}://{}", &rest[at + 1..]),
                    None => part.to_string(),
                }
            }
            None => part.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Once, at startup.
pub fn record(settings: Vec<Setting>) {
    let _ = SETTINGS.set(settings);
}

/// Empty for an in-process node (tests), which has no command line.
pub fn settings() -> &'static [Setting] {
    SETTINGS.get().map_or(&[], Vec::as_slice)
}

/// A `-file` flag that holds a secret: its plain sibling is secret, or its
/// name says so (`--kek-old-file` has no plain sibling).
fn is_secret_file(flag: &str, all: &[Setting]) -> bool {
    let Some(base) = flag.strip_suffix("-file") else { return false };
    all.iter().any(|s| s.flag == base && s.secret)
        || ["secret", "token", "key", "kek", "credentials", "jwt"].iter().any(|w| base.contains(w))
}

/// The secret files the node was started with and when each last changed
/// (a rotation shows as a recent `modifiedAt`), read when asked. The paths
/// are the flag values getConfig already shows.
pub fn secret_files(all: &[Setting]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for s in all.iter().filter(|s| s.source != "unset" && is_secret_file(&s.flag, all)) {
        for path in s.value.as_deref().unwrap_or("").split(',').filter(|p| !p.is_empty()) {
            let meta = std::fs::metadata(path);
            if s.source == "default" && meta.is_err() {
                continue;
            }
            let modified = meta
                .as_ref()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64);
            out.push(serde_json::json!({
                "flag": s.flag,
                "path": path,
                "modifiedAt": modified,
                "error": meta.err().map(|e| e.kind().to_string()),
            }));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, Command};

    #[test]
    fn sources_and_secrets() {
        let cmd = Command::new("t")
            .arg(Arg::new("public_url").long("public-url").env("T_PUBLIC_URL").default_value("http://localhost"))
            .arg(Arg::new("shards").long("shards").default_value("64"))
            .arg(Arg::new("admin_token").long("admin-token").env("T_ADMIN_TOKEN").hide_env_values(true))
            .arg(Arg::new("jwt_secret").long("jwt-secret").hide_env_values(true))
            .arg(Arg::new("plc_url").long("plc-url"));
        let m = cmd.clone().get_matches_from(["t", "--shards", "8", "--admin-token", "hunter2-hunter2"]);
        let s = from_matches(&cmd, &m, |id| (id == "admin_token").then(|| "hunter2-hunter2".to_string()));
        let get = |f: &str| s.iter().find(|x| x.flag == f).unwrap().clone();
        assert_eq!((get("--shards").source.as_str(), get("--shards").value.as_deref()), ("flag", Some("8")));
        assert_eq!(get("--public-url").source, "default");
        assert_eq!(get("--plc-url").source, "unset");
        let t = get("--admin-token");
        assert!(t.secret && t.value.is_none());
        assert_eq!(t.fingerprint.as_deref(), Some(fingerprint("hunter2-hunter2").as_str()));
        assert!(!serde_json::to_string(&s).unwrap().contains("hunter2"), "a secret's value never leaves");
        assert_eq!(get("--jwt-secret").fingerprint, None);
        assert_eq!(strip_userinfo("https://u:p@host.example/x@y"), "https://host.example/x@y");
        assert_eq!(strip_userinfo("bsky.network,https://a@b.example"), "bsky.network,https://b.example");
    }

    #[test]
    fn secret_file_ages() {
        let dir = std::env::temp_dir().join(format!("vlpds-cfg-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let tok = dir.join("admin-token");
        std::fs::write(&tok, "x").unwrap();
        let p = tok.to_string_lossy().into_owned();
        let set = |flag: &str, source: &str, value: Option<&str>, secret: bool| Setting {
            flag: flag.into(),
            env: None,
            source: source.into(),
            value: value.map(String::from),
            secret,
            fingerprint: None,
            help: String::new(),
        };
        let all = vec![
            set("--admin-token", "file", None, true),
            set("--admin-token-file", "flag", Some(&p), false),
            set("--exit-state-file", "flag", Some(&p), false),
            set("--kek-old-file", "flag", Some(&format!("{p},{}/gone", dir.display())), false),
            set("--vault-k8s-jwt-file", "default", Some("/nonexistent/vlpds/token"), false),
        ];
        let got = secret_files(&all);
        let flags: Vec<&str> = got.iter().map(|v| v["flag"].as_str().unwrap()).collect();
        assert_eq!(flags, ["--admin-token-file", "--kek-old-file", "--kek-old-file"], "{got:?}");
        assert!(got[0]["modifiedAt"].as_u64().unwrap() > 1_700_000_000_000);
        assert!(got[2]["modifiedAt"].is_null() && got[2]["error"].is_string());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
