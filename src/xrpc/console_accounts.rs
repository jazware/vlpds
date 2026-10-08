//! The console's account calls beyond its read models
//! (docs/operations/admin-console.md, "Console API"): an account's identity
//! keys, and creating an account as the operator. Admin token only.

use super::admin::require_admin;
use super::moderation::{audit, ClientIp, SubjectRef, Who};
use super::*;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.getAccountKeys", get(get_account_keys))
        .route("/xrpc/vlpds.admin.createAccount", post(create_account))
}

#[derive(Deserialize)]
struct KeysQ {
    did: String,
    /// Drop the cached DID document first.
    #[serde(default)]
    refresh: bool,
}

/// The DID document's verification methods, from the resolver's cache (a
/// resolve on a miss), and for a did:plc the directory's rotation keys
/// (one request to the directory: only when an operator opens this).
async fn get_account_keys(State(app): AppState, Auth(creds): Auth, Query(q): Query<KeysQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let did = q.did.as_str();
    let acct =
        internal::account_anywhere(&app, did).await.map_err(|_| XrpcError::bad("NotFound", "account not found"))?;
    if q.refresh {
        app.did_resolver.invalidate(did);
    }
    let mut out = json!({
        "did": did,
        "signingKey": acct.signing_pubkey,
        "pendingSigningKey": acct.pending_signing_key.as_ref().map(|p| p.pubkey.clone()),
    });
    match app.did_resolver.resolve(did).await {
        Ok(doc) => {
            let methods: Vec<J> = doc["verificationMethod"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|m| {
                    let key = m["publicKeyMultibase"].as_str();
                    json!({
                        "id": m["id"],
                        "type": m["type"],
                        "controller": m["controller"],
                        "publicKeyMultibase": key,
                        "matchesAccount": key == Some(acct.signing_pubkey.as_str()),
                    })
                })
                .collect();
            out["verificationMethods"] = json!(methods);
            out["alsoKnownAs"] = doc["alsoKnownAs"].clone();
            out["pds"] = json!(vlatproto::did_resolver::service_endpoint(&doc, "#atproto_pds"));
        }
        Err(e) => out["didDocError"] = json!(e.to_string()),
    }
    if did.starts_with("did:plc:") {
        match &app.plc {
            Some(plc) => match plc.client.document_data(did).await {
                Ok(data) => {
                    let recovery = plc.recovery_did_key();
                    let keys: Vec<J> = crate::plc::rotation_keys(&data)
                        .into_iter()
                        .map(|k| {
                            let role = if plc.is_server_key(&k) {
                                "server"
                            } else if recovery == Some(k.as_str()) {
                                "operator_recovery"
                            } else {
                                "other"
                            };
                            json!({"didKey": k, "role": role})
                        })
                        .collect();
                    out["rotationKeys"] = json!(keys);
                }
                Err(e) => out["rotationKeysError"] = json!(e.to_string()),
            },
            None => out["rotationKeysError"] = json!("this server doesn't register DIDs with a PLC directory"),
        }
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateIn {
    handle: String,
    email: String,
    /// None: one is generated and returned once.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    actor: Option<String>,
}

/// As createAccount (the same checks, claims and DID registration), with no
/// invite code needed. Audited as `account.create`.
async fn create_account(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<CreateIn>,
) -> XResult<Json<J>> {
    use rand::Rng;
    require_admin(&creds)?;
    let reason = inp.reason.as_deref().map(str::trim).filter(|r| !r.is_empty()).map(String::from);
    if reason.as_ref().is_some_and(|r| r.chars().count() > 2000) {
        return Err(XrpcError::bad("InvalidRequest", "reason: longer than 2000 characters"));
    }
    let generated = inp.password.as_deref().is_none_or(|p| p.is_empty()).then(|| {
        rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(24).map(char::from).collect::<String>()
    });
    let password = generated.clone().or(inp.password);
    let acct = super::server::create_account_by_operator(
        &app,
        super::server::CreateAccountIn { handle: inp.handle, email: Some(inp.email), password, ..Default::default() },
    )
    .await?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let detail = json!({"handle": acct.handle, "generatedPassword": generated.is_some()});
    let e = audit(
        &app,
        &who,
        "account.create",
        Some(&SubjectRef::account(&acct.did)),
        reason.as_deref(),
        None,
        Some(detail),
    )
    .await?;
    let mut out = json!({"did": acct.did, "handle": acct.handle, "auditId": e.id});
    if let Some(p) = generated {
        out["password"] = json!(p);
    }
    Ok(Json(out))
}
