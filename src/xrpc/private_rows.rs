//! Golden format fixtures of private (`p/`) rows (tests/all/formats.rs,
//! DESIGN.md "Tests and CI"). The row types are private to their XRPC
//! modules, which each contribute a `fixture_rows` / `check_row` pair.

use serde_json::{json, Value as J};

/// (routing key, name, value)
pub type PrivateRow = (String, String, Vec<u8>);

/// Every kind of private row, with fixed values.
pub fn private_row_fixtures(did: &str) -> Vec<PrivateRow> {
    let mut rows = super::server::fixture_rows(did);
    rows.extend(super::admin::fixture_rows(did));
    rows.extend(super::email2fa::fixture_rows(did));
    rows.extend(super::proxy::fixture_rows(did));
    rows.extend(shared_fixture_rows(did));
    rows
}

/// Row kinds added after `private/rows.json` was frozen with level 1, in a
/// fixture file of their own (`private/blob_quota.json`).
pub fn blob_quota_row_fixtures(did: &str) -> Vec<PrivateRow> {
    super::blob_quota::fixture_rows(did)
}

/// Scoped app passwords, also added after level 1's `private/rows.json`
/// was frozen (`private/app_password_scopes.json`).
pub fn app_password_scope_row_fixtures(did: &str) -> Vec<PrivateRow> {
    super::server::scoped_app_password_fixture_rows(did)
}

/// Sign-in security rows (`private/sign_in.json`), added after that.
pub fn sign_in_row_fixtures(did: &str) -> Vec<PrivateRow> {
    super::signin::fixture_rows(did)
}

/// Passkeys, and the session rows that record which passkey signed them in
/// (`private/passkeys.json`), added after that.
pub fn passkey_row_fixtures(did: &str) -> Vec<PrivateRow> {
    use crate::oauth::client::ClientAuth;
    use crate::oauth::store as o;
    let cred = super::passkeys::auth_ref("AAEC");
    let mut rows = super::passkeys::fixture_rows(did);
    rows.extend(super::mfa::fixture_rows(did));
    rows.extend(super::server::passkey_session_fixture_rows(did, &cred));
    let ses = o::Session {
        id: "ses-passkey".into(),
        did: did.into(),
        client_id: "https://app.example/client-metadata.json".into(),
        client_auth: ClientAuth::None,
        dpop_jkt: "jkt".into(),
        scope: "atproto".into(),
        token_scope: "atproto".into(),
        created_at: 1_790_000_000,
        updated_at: 1_790_000_100,
        expires_at: 1_790_003_700,
        token_id: "tok-2".into(),
        refresh_gen: 0,
        refresh_salt: "salt".into(),
        device_id: Some("dev-passkey".into()),
        request_id: Some("req-passkey".into()),
        auth_cred: Some(cred.clone()),
        space_collections: None,
        created_ip: None,
        ip: None,
    };
    let dev = o::Device {
        id: "dev-passkey".into(),
        created_at: 1_790_000_000,
        last_seen_at: 1_790_000_100,
        user_agent: None,
        accounts: vec![o::DeviceAccount {
            did: did.into(),
            authenticated_at: 1_790_000_050,
            auth_epoch: "00ff".into(),
            auth_cred: Some(cred),
        }],
        pending_2fa: None,
        pending_2fa_failures: 0,
        pending_2fa_epoch: String::new(),
        trusted_until: 0,
    };
    rows.push((did.into(), o::session_key("ses-passkey"), enc(&ses)));
    rows.push(("oauth:dev:dev-passkey".into(), "oauth/dev".into(), enc(&dev)));
    rows
}

/// Decodes a private row the way its readers do: Ok(the row's kind), Err if
/// it doesn't decode, lacks a field its readers use, or doesn't re-encode to
/// the same bytes (a field this build would drop).
pub fn check_private_row(routing: &str, name: &str, val: &[u8]) -> anyhow::Result<&'static str> {
    type Check = fn(&str, &str, &[u8]) -> Option<anyhow::Result<&'static str>>;
    let checks: [Check; 9] = [
        super::server::check_row,
        super::admin::check_row,
        super::email2fa::check_row,
        super::proxy::check_row,
        super::blob_quota::check_row,
        super::signin::check_row,
        super::passkeys::check_row,
        super::mfa::check_row,
        check_shared_row,
    ];
    for check in checks {
        if let Some(r) = check(routing, name, val) {
            return r;
        }
    }
    anyhow::bail!("unknown private row {routing:?} {name:?}")
}

pub(super) use super::server::to_json_bytes as enc;

pub(super) fn typed_row<T: serde::Serialize + serde::de::DeserializeOwned>(
    kind: &'static str,
    val: &[u8],
) -> anyhow::Result<&'static str> {
    let v: T = serde_json::from_slice(val).map_err(|e| anyhow::anyhow!("{kind}: {e}"))?;
    anyhow::ensure!(serde_json::to_vec(&v)? == val, "{kind}: re-encodes differently (a field would be dropped)");
    Ok(kind)
}

/// A row written as a `json!` object: the fields its readers use, with
/// their JSON types ('s' string, 'u' unsigned, 'b' bool, '?' not null).
pub(super) fn json_row(kind: &'static str, val: &[u8], fields: &[(&str, char)]) -> anyhow::Result<&'static str> {
    let v: J = serde_json::from_slice(val).map_err(|e| anyhow::anyhow!("{kind}: {e}"))?;
    for (f, t) in fields {
        let x = &v[*f];
        let ok = match t {
            's' => x.is_string(),
            'u' => x.is_u64(),
            'b' => x.is_boolean(),
            _ => !x.is_null(),
        };
        anyhow::ensure!(ok, "{kind}: field {f} is not {t}: {v}");
    }
    anyhow::ensure!(serde_json::to_vec(&v)? == val, "{kind}: re-encodes differently");
    Ok(kind)
}

pub(super) fn utf8_row(kind: &'static str, val: &[u8]) -> anyhow::Result<&'static str> {
    std::str::from_utf8(val).map_err(|e| anyhow::anyhow!("{kind}: {e}"))?;
    Ok(kind)
}

/// TOTP and OAuth rows, whose types are public.
fn shared_fixture_rows(did: &str) -> Vec<PrivateRow> {
    use crate::oauth::client::ClientAuth;
    use crate::oauth::store as o;
    let mut totp = crate::totp::TotpState::default();
    totp.secret = Some("vw1.kid.dG90cC1zZWNyZXQ".into());
    totp.last_step = 59_666_666;
    totp.enabled_at = Some("2026-10-01T00:00:00.000Z".into());
    let client = "https://app.example/client-metadata.json";
    let params = o::AuthParams {
        client_id: client.into(),
        response_type: "code".into(),
        redirect_uri: "https://app.example/cb".into(),
        scope: "atproto transition:generic".into(),
        state: Some("st".into()),
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
        code_challenge_method: "S256".into(),
        response_mode: None,
        prompt: Some("consent".into()),
        login_hint: Some("fixture.test".into()),
        dpop_jkt: "jkt".into(),
        display: None,
        ui_locales: None,
    };
    let req = o::RequestData {
        client_id: client.into(),
        client_auth: ClientAuth::None,
        params,
        created_at: 1_790_000_000,
        expires_at: 1_790_000_300,
        device_id: Some("dev-fixture".into()),
        did: Some(did.into()),
        code_hash: Some("aGFzaA".into()),
        consumed: Some(("ses-fixture".into(), "tok-1".into())),
        auth_epoch: String::new(),
        auth_cred: None,
        space_collections: None,
    };
    let ses = o::Session {
        id: "ses-fixture".into(),
        did: did.into(),
        client_id: client.into(),
        client_auth: ClientAuth::PrivateKeyJwt { alg: "ES256".into(), kid: "k1".into(), jkt: "cjkt".into() },
        dpop_jkt: "jkt".into(),
        scope: "atproto include:app.example.perms".into(),
        token_scope: "atproto repo:app.example.post".into(),
        created_at: 1_790_000_000,
        updated_at: 1_790_000_100,
        expires_at: 1_790_003_700,
        token_id: "tok-1".into(),
        refresh_gen: 2,
        refresh_salt: "salt".into(),
        device_id: Some("dev-fixture".into()),
        request_id: Some("req-fixture".into()),
        auth_cred: None,
        space_collections: None,
        created_ip: None,
        ip: None,
    };

    let dev = o::Device {
        id: "dev-fixture".into(),
        created_at: 1_790_000_000,
        last_seen_at: 1_790_000_100,
        user_agent: Some("Mozilla/5.0".into()),
        accounts: vec![o::DeviceAccount {
            did: did.into(),
            authenticated_at: 1_790_000_050,
            auth_epoch: String::new(),
            auth_cred: None,
        }],
        pending_2fa: Some((did.into(), 1_790_000_060)),
        pending_2fa_failures: 1,
        pending_2fa_epoch: String::new(),
        trusted_until: 0,
    };
    let authz =
        o::Authorization { client_id: client.into(), scopes: vec!["atproto".into()], updated_at: 1_790_000_000 };
    let lex = o::StoredLexicon {
        uri: "at://did:plc:lex/com.atproto.lexicon.schema/app.example.perms".into(),
        doc: json!({"lexicon": 1, "id": "app.example.perms"}),
        updated_at: 1_790_000_000,
    };
    vec![
        (did.into(), crate::totp::PRIVATE_NAME.into(), enc(&totp)),
        (o::req_routing("req-fixture"), "oauth/req".into(), enc(&req)),
        (did.into(), o::session_key("ses-fixture"), enc(&ses)),
        ("oauth:dev:dev-fixture".into(), "oauth/dev".into(), enc(&dev)),
        (did.into(), "oauth/authz/aGFzaA".into(), enc(&authz)),
        ("oauth:lex:app.example.perms".into(), "oauth/lex".into(), enc(&lex)),
        ("oauth:cc:aGFzaA".into(), "oauth/cc".into(), enc(&1_790_000_000i64)),
        ("oauth:par:aGFzaA".into(), format!("{}aGFzaA", crate::oauth::util::REPLAY_ROW), enc(&1_790_000_300i64)),
    ]
}

fn check_shared_row(routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    use crate::oauth::store as o;
    Some(match name {
        // `sealed` is not stored: everything else must round-trip
        n if n == crate::totp::PRIVATE_NAME && routing.starts_with("did:") => {
            typed_row::<crate::totp::TotpState>("totp", val)
        }
        "oauth/req" => typed_row::<o::RequestData>("oauth request", val),
        "oauth/dev" => typed_row::<o::Device>("oauth device", val),
        "oauth/lex" => typed_row::<o::StoredLexicon>("oauth lexicon", val),
        "oauth/cc" => typed_row::<i64>("oauth code challenge", val),
        n if n.starts_with("oauth/ses/") => typed_row::<o::Session>("oauth session", val),
        n if n.starts_with("oauth/authz/") => typed_row::<o::Authorization>("oauth consent", val),
        n if n.starts_with(crate::oauth::util::REPLAY_ROW) => typed_row::<i64>("oauth replay", val),
        _ => return None,
    })
}
