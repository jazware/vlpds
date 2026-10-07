//! Which operator writes are audited, and as what. Every write an admin
//! credential (the token, a proxy-named operator or the moderation service)
//! can make writes an entry to the moderation audit log
//! (`vlpds.admin.getAuditLog`, src/xrpc/moderation.rs) naming who did it,
//! how they got in, the subject and a short detail. The few that don't are
//! in [`UNAUDITED`] with the reason. The test below scans the routers so a
//! new admin write can't land unlisted.
//!
//! Entries never hold a password, token, invite code, private key, email
//! body or a full email address (an address is kept to its domain, as the
//! mail log keeps it).

use super::moderation::SubjectRef;
use super::*;

/// Admin write methods and the audit actions they write. A dry run, or a
/// call that finds nothing to change (abortReshard with no op), writes none.
pub const AUDITED: &[(&str, &[&str])] = &[
    ("com.atproto.admin.deleteAccount", &["account.delete"]),
    ("com.atproto.admin.disableAccountInvites", &["invites.disable_account"]),
    ("com.atproto.admin.disableInviteCodes", &["invites.disable_codes"]),
    ("com.atproto.admin.enableAccountInvites", &["invites.enable_account"]),
    ("com.atproto.admin.sendEmail", &["mail.send"]),
    ("com.atproto.admin.updateAccountEmail", &["account.email"]),
    ("com.atproto.admin.updateAccountHandle", &["account.handle"]),
    ("com.atproto.admin.updateAccountPassword", &["account.password"]),
    ("com.atproto.admin.updateAccountSigningKey", &["account.signing_key"]),
    ("com.atproto.admin.updateSubjectStatus", &["takedown", "restore", "account.deactivate", "account.activate"]),
    ("com.atproto.server.createInviteCode", &["invites.create"]),
    ("com.atproto.server.createInviteCodes", &["invites.create"]),
    ("vlpds.admin.abortReshard", &["shard.abort"]),
    ("vlpds.admin.addHandleDomain", &["domain.add"]),
    ("vlpds.admin.backfillStorageStats", &["storage.backfill"]),
    ("vlpds.admin.clearLockout", &["lockout.clear"]),
    ("vlpds.admin.createAccount", &["account.create"]),
    ("vlpds.admin.createCase", &["case.create"]),
    ("vlpds.admin.ensureRecoveryKey", &["plc.recovery_key"]),
    ("vlpds.admin.kickSubscriber", &["firehose.kick"]),
    ("vlpds.admin.mergeShards", &["shard.merge"]),
    ("vlpds.admin.moderate", &["takedown", "restore"]),
    ("vlpds.admin.publishIdentity", &["identity.publish"]),
    ("vlpds.admin.rebuildRepo", &["repo.rebuild"]),
    ("vlpds.admin.recountRepo", &["repo.recount"]),
    ("vlpds.admin.removeHandleDomain", &["domain.remove"]),
    ("vlpds.admin.removeSpaceRegistration", &["space.registration.remove"]),
    ("vlpds.admin.requestCrawl", &["crawlers.request"]),
    ("vlpds.admin.resetSecondFactors", &["second_factors.reset"]),
    ("vlpds.admin.revokeAppPassword", &["app_password.revoke"]),
    ("vlpds.admin.revokeSessions", &["sessions.revoke"]),
    ("vlpds.admin.rewrapSecrets", &["secrets.rewrap"]),
    ("vlpds.admin.rotatePlcKeys", &["plc.rotate_keys"]),
    ("vlpds.admin.setBlobQuota", &["quota.set"]),
    ("vlpds.admin.setCrawlers", &["crawlers.set"]),
    ("vlpds.admin.setFeatureLevel", &["feature_level.set"]),
    ("vlpds.admin.splitShard", &["shard.split"]),
    ("vlpds.admin.updateCase", &["case.update"]),
    ("vlpds.admin.updateRateLimits", &["ratelimits.update"]),
];

/// Admin writes left out of the audit log on purpose.
pub const UNAUDITED: &[(&str, &str)] = &[
    (
        "vlpds.admin.bulkCreate",
        "simulation only (refused without --dev-mode or --allow-bulk-create): synthetic accounts for a load \
         generator, which calls it thousands of times",
    ),
    (
        "com.atproto.identity.refreshIdentity",
        "changes nothing: an admin caller only has the account's current identity announced again",
    ),
];

/// The audited methods' actions, for a reader of [`AUDITED`].
pub fn actions_of(nsid: &str) -> Option<&'static [&'static str]> {
    AUDITED.iter().find(|(n, _)| *n == nsid).map(|(_, a)| *a)
}

/// A body that has nothing but the console's `actor`.
#[derive(Deserialize, Default)]
pub(super) struct ActorIn {
    pub actor: Option<String>,
}

const MAX_NOTE: usize = 2000;

/// A reference method's free-text note or comment as an entry's reason:
/// trimmed, and cut (not refused, as the reference takes any length).
pub(super) fn bounded_note(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(MAX_NOTE).collect())
}

/// This node, as the subject of a per-node maintenance call.
pub(super) fn node_subject(app: &App) -> SubjectRef {
    SubjectRef::other("node", super::moderation::node_id(app))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// What marks a handler as taking admin credentials.
    const ADMIN_MARKERS: &[&str] = &["require_admin(", "require_moderator(", "Credentials::Admin", "admin_token"];

    /// `(nsid, handler)` of every POST route in `src`.
    fn post_routes(src: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut rest = src;
        while let Some(i) = rest.find(".route(\"/xrpc/") {
            rest = &rest[i + ".route(\"/xrpc/".len()..];
            let nsid = rest[..rest.find('"').unwrap()].to_string();
            // the method router: up to the paren closing `.route(`
            let mut depth = 1;
            let end = rest
                .char_indices()
                .find(|&(_, c)| {
                    depth += match c {
                        '(' => 1,
                        ')' => -1,
                        _ => 0,
                    };
                    depth == 0
                })
                .map(|(j, _)| j)
                .unwrap();
            let methods = &rest[..end];
            let mut m = methods;
            while let Some(p) = m.find("post(") {
                m = &m[p + "post(".len()..];
                out.push((nsid.clone(), m[..m.find(')').unwrap()].trim().to_string()));
            }
        }
        out
    }

    /// The text of `fn name(` up to its closing brace at column 0.
    fn body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
        let start = src.find(&format!("fn {name}("))?;
        let len = src[start..].find("\n}\n").unwrap_or(src.len() - start);
        Some(&src[start..start + len])
    }

    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                rust_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// Every POST route under `com.atproto.admin.*` and `vlpds.admin.*`, and
    /// every other one whose handler takes admin credentials: nsid -> file.
    fn admin_writes() -> BTreeMap<String, String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        let mut out = BTreeMap::new();
        for p in files {
            let src = std::fs::read_to_string(&p).unwrap();
            for (nsid, handler) in post_routes(&src) {
                let by_name = nsid.starts_with("com.atproto.admin.") || nsid.starts_with("vlpds.admin.");
                let by_auth = body(&src, &handler).is_some_and(|b| ADMIN_MARKERS.iter().any(|m| b.contains(m)));
                if by_name || by_auth {
                    out.insert(nsid, p.strip_prefix(&root).unwrap().display().to_string());
                }
            }
        }
        out
    }

    #[test]
    fn every_admin_write_is_audited_or_allowlisted() {
        let found = admin_writes();
        assert!(found.len() > 30, "the route scan found too little: {found:?}");
        let audited: BTreeSet<&str> = AUDITED.iter().map(|(n, _)| *n).collect();
        let allowed: BTreeSet<&str> = UNAUDITED.iter().map(|(n, _)| *n).collect();
        assert_eq!(audited.len(), AUDITED.len(), "AUDITED lists a method twice");
        assert!(audited.is_disjoint(&allowed), "both audited and allowlisted: {:?}", audited.intersection(&allowed));
        for (nsid, file) in &found {
            assert!(
                audited.contains(nsid.as_str()) || allowed.contains(nsid.as_str()),
                "{nsid} ({file}) is an admin write with no audit entry: audit it (Who::of + moderation::audit) \
                 and add it to AUDITED, or add it to UNAUDITED with the reason"
            );
        }
        for n in audited.iter().chain(&allowed) {
            assert!(found.contains_key(*n), "{n} is listed but isn't an admin write route (renamed or removed?)");
        }
        for (n, why) in UNAUDITED {
            assert!(why.len() > 20, "{n}: give the reason it isn't audited");
        }
    }

    #[test]
    fn route_scan_parses_method_routers() {
        let src = r#"
            Router::new()
                .route("/xrpc/a.b.c", get(read_it).post(write_it))
                .route("/xrpc/a.b.d", post(other))
                .route("/xrpc/a.b.e", get(nested(x)))
        "#;
        let r = post_routes(src);
        assert_eq!(r, [("a.b.c".to_string(), "write_it".to_string()), ("a.b.d".into(), "other".into())]);
    }

    #[test]
    fn notes_are_bounded() {
        assert_eq!(bounded_note(Some("  ")), None);
        assert_eq!(bounded_note(Some(" spam ")).as_deref(), Some("spam"));
        assert_eq!(bounded_note(Some(&"x".repeat(5000))).unwrap().len(), MAX_NOTE);
    }
}
