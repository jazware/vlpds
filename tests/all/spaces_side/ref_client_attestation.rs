//! Ported from the reference's `tests/client-attestation.test.ts`
//! (5b95b2f2), a unit test of `ClientAttestationVerifier` against an
//! injected fetch, plus the "client attestation" cases of
//! `space/policy.test.ts`. vlpds verifies an attestation inside
//! getSpaceCredential, so each case is a credential mint for a space whose
//! `allowedApps` lists a [`MockClientApp`] served over loopback HTTP.
//!
//! Every refusal is a 4xx: the reference pins "Invalid client attestation"
//! and friends by message, which vlpds isn't held to.

use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use vlpds::space::token::space_host_aud;

struct Fixture {
    net: Net,
    alice: SpaceClient,
    carol: SpaceClient,
    app: MockClientApp,
    space: String,
}

impl Fixture {
    async fn new(keys: Keys) -> Fixture {
        let net = Net::new(1).await;
        let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 1).await);
        let app = MockClientApp::spawn(keys).await;
        let space = net
            .create_space(
                &alice,
                SpaceOpts {
                    policy: Some(memberspace(json!({"publicRead": true, "allowedApps": [app.client_id]}))),
                    ..Default::default()
                },
            )
            .await;
        Fixture { net, alice, carol, app, space }
    }

    fn aud(&self) -> String {
        space_host_aud(&self.alice.did)
    }

    /// A good attestation mints, so a refusal that follows is about what
    /// the test changed.
    async fn control(&self) {
        self.mint(&self.app.attest(&self.aud(), Attest::default())).await.ok();
    }

    async fn mint(&self, attestation: &str) -> Resp {
        let token = delegation_token(&self.carol, &self.space).await;
        self.net.mint_credential(&self.space, &token, Some(attestation)).await.0
    }
}

/// "accepts an attestation signed by a key in the client jwks"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepts_an_attestation_signed_by_a_key_in_the_client_jwks() {
    let f = Fixture::new(Keys::Inline).await;
    f.mint(&f.app.attest(&f.aud(), Attest::default())).await.ok();
}

/// "accepts an attestation when the client publishes a jwks_uri"
/// (policy: "mints for an allow-listed app that signs with its
/// published key")
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepts_an_attestation_when_the_client_publishes_a_jwks_uri() {
    let f = Fixture::new(Keys::Uri).await;
    f.mint(&f.app.attest(&f.aud(), Attest::default())).await.ok();
}

/// "refuses a replayed attestation, but not a second fresh one"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_replayed_attestation_but_not_a_fresh_one() {
    let f = Fixture::new(Keys::Uri).await;
    let replayed = f.app.attest(&f.aud(), Attest::default());
    f.mint(&replayed).await.ok();
    f.mint(&replayed).await.client_err();
    f.mint(&f.app.attest(&f.aud(), Attest::default())).await.ok();
}

/// "refuses an attestation with no jti to consume"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_attestation_with_no_jti() {
    let f = Fixture::new(Keys::Uri).await;
    f.control().await;
    f.mint(&f.app.attest(&f.aud(), Attest { jti: Some(None), ..Default::default() })).await.client_err();
}

/// "refuses an attestation signed by a key the client does not publish"
/// (policy: "refuses an attestation signed by a key the app does not
/// publish")
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_attestation_signed_by_an_unpublished_key() {
    let f = Fixture::new(Keys::Uri).await;
    f.control().await;
    let attacker = new_p256();
    f.mint(&f.app.attest(&f.aud(), Attest { sign_with: Some(&attacker), ..Default::default() })).await.client_err();
}

/// "refuses an attestation addressed to another space host" (policy:
/// "refuses an attestation addressed to another authority")
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_attestation_addressed_to_another_space_host() {
    let f = Fixture::new(Keys::Uri).await;
    f.control().await;
    f.mint(&f.app.attest(&space_host_aud(&f.carol.did), Attest::default())).await.client_err();
}

/// "refuses an expired attestation" (both suites)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_expired_attestation() {
    let f = Fixture::new(Keys::Uri).await;
    f.control().await;
    f.mint(&f.app.attest(&f.aud(), Attest { expires_in: Some(-120), ..Default::default() })).await.client_err();
}

/// Divergence: attestations live at most 300 s (single-use token cap).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_attestation_living_past_300_seconds() {
    let f = Fixture::new(Keys::Uri).await;
    f.control().await;
    f.mint(&f.app.attest(&f.aud(), Attest { expires_in: Some(600), ..Default::default() })).await.client_err();
}

/// "refuses an attestation whose iss and sub disagree"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_attestation_whose_iss_and_sub_disagree() {
    let f = Fixture::new(Keys::Uri).await;
    f.control().await;
    f.mint(&f.app.attest(&f.aud(), Attest { sub: Some("https://other.example/x"), ..Default::default() }))
        .await
        .client_err();
}

/// "refuses when the client publishes no keys"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_when_the_client_publishes_no_keys() {
    let f = Fixture::new(Keys::None).await;
    f.mint(&f.app.attest(&f.aud(), Attest::default())).await.client_err();
}

/// "refuses when the client metadata cannot be resolved"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_when_the_client_metadata_cannot_be_resolved() {
    let f = Fixture::new(Keys::Uri).await;
    f.app.serve_metadata(false);
    f.mint(&f.app.attest(&f.aud(), Attest::default())).await.client_err();
}

/// "refuses when the jwks_uri cannot be resolved"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_when_the_jwks_uri_cannot_be_resolved() {
    let f = Fixture::new(Keys::UriMissing).await;
    f.mint(&f.app.attest(&f.aud(), Attest::default())).await.client_err();
}

/// policy client attestation: "refuses an attestation from an app that
/// is not allow-listed"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_attestation_from_an_app_that_is_not_allow_listed() {
    let f = Fixture::new(Keys::Uri).await;
    f.control().await;
    let other = MockClientApp::spawn(Keys::Uri).await;
    f.mint(&other.attest(&f.aud(), Attest::default())).await.err(400, "AppNotAuthorized");
}

/// policy client attestation: "mints for an allow-listed app without a
/// delegation token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mints_for_an_allow_listed_app_without_a_delegation_token() {
    let f = Fixture::new(Keys::Uri).await;
    let attestation = f.app.attest(&f.aud(), Attest::default());
    f.net.public_credential(&f.space, Some(&attestation)).await.0.ok();
}
