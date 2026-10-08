//! `app.bsky.notification.{registerPush,unregisterPush}` (reference
//! api/app/bsky/notification/*.ts). These name their push service in the
//! body (`serviceDid`), not in an atproto-proxy header, so they are served
//! here instead of by the generic proxy:
//! - OAuth scope check: `rpc:{lxm}?aud={serviceDid}#bsky_notif`.
//! - The forwarded call carries a service-auth JWT signed with the
//!   account's repo key (the proxy's hedged, verify-after-sign signer):
//!   iss = account DID, aud = the bare `serviceDid` (as the reference's
//!   `serviceAuthHeaders(did, serviceDid, lxm)`), lxm = the method.
//! - Target: the configured AppView's URL when `serviceDid` is its DID;
//!   otherwise the `#bsky_notif` (`BskyNotificationService`) endpoint of
//!   `serviceDid`'s DID document, called through the SSRF-guarded client.

use super::*;

const REGISTER_PUSH: &str = "app.bsky.notification.registerPush";
const UNREGISTER_PUSH: &str = "app.bsky.notification.unregisterPush";

pub(super) async fn register_push(State(app): AppState, Auth(creds): Auth, body: AxBytes) -> XResult<Response> {
    push(&app, &creds, REGISTER_PUSH, &body).await
}

pub(super) async fn unregister_push(State(app): AppState, Auth(creds): Auth, body: AxBytes) -> XResult<Response> {
    push(&app, &creds, UNREGISTER_PUSH, &body).await
}

fn bad(message: impl Into<String>) -> XrpcError {
    XrpcError::bad("InvalidRequest", message)
}

/// The lexicon's required input (both methods share it).
fn check_input(input: &J) -> XResult<&str> {
    if !input.is_object() {
        return Err(bad("Input must be an object"));
    }
    for k in ["serviceDid", "token", "platform", "appId"] {
        if !input.get(k).is_some_and(|v| v.is_string()) {
            return Err(bad(format!("Input must have the property \"{k}\"")));
        }
    }
    if !matches!(input["platform"].as_str(), Some("ios" | "android" | "web")) {
        return Err(bad("Input/platform must be one of (ios|android|web)"));
    }
    if input.get("ageRestricted").is_some_and(|v| !v.is_boolean()) {
        return Err(bad("Input/ageRestricted must be a boolean"));
    }
    let service_did = input["serviceDid"].as_str().unwrap_or_default();
    if !vlatproto::syntax::valid_did(service_did) {
        return Err(bad("Input/serviceDid must be a valid did"));
    }
    Ok(service_did)
}

async fn push(app: &App, creds: &Credentials, lxm: &'static str, body: &[u8]) -> XResult<Response> {
    let did = user_did(creds)?.to_string();
    let input: J = serde_json::from_slice(body).map_err(|_| bad("Request body must be a JSON object"))?;
    let service_did = check_input(&input)?;
    creds.need_rpc(lxm, &format!("{service_did}#bsky_notif"))?;
    let acct = check_takedown(app, &did, false).await?;
    let target = push_target(app, service_did, lxm).await?;
    let body = Bytes::from(serde_json::to_vec(&input).map_err(XrpcError::from_err)?);
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    headers.insert(header::CONTENT_LENGTH, body.len().into());
    let path = format!("/xrpc/{lxm}");
    forward(
        app,
        &target,
        Forward {
            method: Method::POST,
            path_and_query: &path,
            headers: &headers,
            body: Some(Body::from(body)),
            iss: Some(&did),
            lxm,
            aud: None,
            accept_encoding: None,
        },
        Some(&acct),
    )
    .await
}

/// The configured AppView when it is `service_did`, else the DID
/// document's notification service (untrusted: guarded client).
async fn push_target<'a>(app: &'a App, service_did: &str, lxm: &str) -> XResult<Target<'a>> {
    let Some((av_url, av_did)) = &app.config.appview else {
        // the reference registers these only alongside an AppView
        return Err(bad(format!("No service configured for {lxm}")));
    };
    if av_did == service_did {
        return Ok(Target {
            url: Cow::Borrowed(av_url),
            did: Cow::Borrowed(av_did),
            service_id: Cow::Borrowed("bsky_notif"),
            trusted: true,
        });
    }
    let doc = resolve_did(app, service_did)
        .await
        .map_err(|_| bad(format!("could not resolve did document: {service_did}")))?;
    let url = notif_endpoint(&doc)
        .ok_or_else(|| bad(format!("invalid notification service details in did document: {service_did}")))?;
    Ok(Target {
        url: Cow::Owned(url),
        did: Cow::Owned(service_did.to_string()),
        service_id: Cow::Borrowed("bsky_notif"),
        trusted: false,
    })
}

/// Reference `getNotifEndpoint`: service `#bsky_notif` of type
/// `BskyNotificationService` with an http(s) URL.
fn notif_endpoint(doc: &J) -> Option<String> {
    let did = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let full = format!("{did}#bsky_notif");
    let svc = doc
        .get("service")?
        .as_array()?
        .iter()
        .find(|s| s.get("id").and_then(|v| v.as_str()).is_some_and(|id| id == "#bsky_notif" || id == full))?;
    if svc.get("type").and_then(|v| v.as_str()) != Some("BskyNotificationService") {
        return None;
    }
    did_resolver::service_endpoint(doc, "bsky_notif")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notif_endpoint_needs_id_type_and_url() {
        let doc = |svc: J| json!({"id": "did:web:push.example", "service": [svc]});
        let ok =
            json!({"id": "#bsky_notif", "type": "BskyNotificationService", "serviceEndpoint": "https://push.example"});
        assert_eq!(notif_endpoint(&doc(ok)).as_deref(), Some("https://push.example"));
        let full = json!({"id": "did:web:push.example#bsky_notif", "type": "BskyNotificationService", "serviceEndpoint": "https://push.example"});
        assert!(notif_endpoint(&doc(full)).is_some());
        let wrong_type = json!({"id": "#bsky_notif", "type": "Other", "serviceEndpoint": "https://push.example"});
        assert!(notif_endpoint(&doc(wrong_type)).is_none());
        let bad_url =
            json!({"id": "#bsky_notif", "type": "BskyNotificationService", "serviceEndpoint": "ftp://push.example"});
        assert!(notif_endpoint(&doc(bad_url)).is_none());
        let other_id = json!({"id": "#bsky_appview", "type": "BskyNotificationService", "serviceEndpoint": "https://push.example"});
        assert!(notif_endpoint(&doc(other_id)).is_none());
    }

    #[test]
    fn input_checks() {
        let ok = json!({"serviceDid": "did:web:push.example", "token": "t", "platform": "ios", "appId": "xyz.blueskyweb.app"});
        assert_eq!(check_input(&ok).ok(), Some("did:web:push.example"));
        let mut v = ok.clone();
        v["platform"] = json!("windows");
        assert!(check_input(&v).is_err());
        let mut v = ok.clone();
        v["serviceDid"] = json!("not a did");
        assert!(check_input(&v).is_err());
        let mut v = ok;
        v.as_object_mut().unwrap().remove("token");
        assert!(check_input(&v).is_err());
    }
}
