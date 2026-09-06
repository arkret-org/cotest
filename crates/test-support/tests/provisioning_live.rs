//! Live check for the Rust provisioning module.
//!
//! `#[ignore]` because it needs a running Coauth and Soland; it is not a unit
//! test with a mock behind it. Run it against a harness started with
//! `-KeepServices`, or from a scenario that owns the deployment:
//!
//! ```text
//! cargo test -p cotest-test-support --test provisioning_live -- --ignored --nocapture
//! ```
//!
//! Environment is **required, not optional**: a missing variable panics rather
//! than skipping. A provisioning check that quietly does nothing is worse than
//! no check, because the suite still reports a pass.

use cotest_test_support::provisioning::{
    DeploymentEndpoints, MockEmailInbox, UnboundAccount, authorize_with_current_account,
    describe_station, provision_unbound_account,
};

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} is required for the live provisioning check. Start the harness \
             (scripts/run-joint-e2e.ps1 -RunProfile joint-api -StartCoauth -StartMocks \
             -KeepServices) and export the variables it prints."
        )
    })
}

/// Build a client that trusts the run-scoped CA, and nothing extra.
///
/// The harness terminates TLS with a per-run certificate authority, so a client
/// that skipped verification would also pass against a misconfigured
/// deployment. `COTEST_RUN_SCOPED_CA_PEM` is what the runner exports for
/// exactly this.
fn http_client() -> reqwest::Client {
    let ca_pem = required_env("COTEST_RUN_SCOPED_CA_PEM");
    let pem = std::fs::read(&ca_pem)
        .unwrap_or_else(|error| panic!("read run-scoped CA {ca_pem}: {error}"));
    let certificate = reqwest::Certificate::from_pem(&pem)
        .unwrap_or_else(|error| panic!("parse run-scoped CA {ca_pem}: {error}"));
    reqwest::Client::builder()
        .add_root_certificate(certificate)
        // Coauth carries the authenticated account session in a cookie, and the
        // gate handoff authorizes against it.
        .cookie_store(true)
        // Redirects are not followed on purpose. The authorize step answers 302
        // into the approval page and the grant id is in its `Location`; a client
        // that follows it loses the one value that step produces, and does so
        // silently.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build HTTP client")
}

fn endpoints() -> DeploymentEndpoints {
    DeploymentEndpoints {
        coauth_base_url: required_env("COTEST_COAUTH_BASE_URL"),
        soland_base_url: required_env("COTEST_SOLAND_BASE_URL"),
        mock_email: std::env::var("COTEST_MOCK_EMAIL_BASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|base_url| MockEmailInbox { base_url }),
    }
}

#[tokio::test]
#[ignore = "requires a running Coauth and Soland; see the module docs"]
async fn station_description_supplies_the_audience_a_grant_binds_to() {
    let http = http_client();
    let endpoints = endpoints();
    let facts = describe_station(&http, &endpoints)
        .await
        .expect("describe the Station under test");

    // These are the two values the rest of the chain is keyed on, so an empty
    // or shape-only answer has to fail here rather than three steps later.
    assert!(
        !facts.trust_domain.trim().is_empty(),
        "Station published an empty trust_domain"
    );
    assert!(
        facts.service_id.starts_with("ak:did_core:"),
        "Station service_id is not a DID core id: {}",
        facts.service_id
    );
}

#[tokio::test]
#[ignore = "requires a running Coauth and Soland; see the module docs"]
async fn an_unbound_account_registers_and_authenticates() {
    let http = http_client();
    let endpoints = endpoints();
    let slug = format!(
        "rust-prov-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    );
    let account = UnboundAccount {
        email: format!("{slug}@example.test"),
        display_name: format!("Rust provisioning {slug}"),
        handle: slug,
        password: "1amTester!".to_owned(),
    };

    provision_unbound_account(&http, &endpoints, &account)
        .await
        .expect("register and authenticate an unbound Coauth account");

    // Registering the same handle twice must be refused. Without this the test
    // would pass against a service that accepted anything, which is the failure
    // mode a "did it return 200" assertion cannot see.
    let repeated = provision_unbound_account(&http, &endpoints, &account).await;
    assert!(
        repeated.is_err(),
        "Coauth accepted a second registration for the same handle"
    );
}

#[tokio::test]
#[ignore = "requires a running Coauth and Soland; see the module docs"]
async fn an_authenticated_account_completes_the_authorization_code_flow() {
    let http = http_client();
    let endpoints = endpoints();
    let client_id = required_env("COTEST_OIDC_CLIENT_ID");
    let slug = format!(
        "rust-oauth-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    );
    let account = UnboundAccount {
        email: format!("{slug}@example.test"),
        display_name: format!("Rust OAuth {slug}"),
        handle: slug,
        password: "1amTester!".to_owned(),
    };
    provision_unbound_account(&http, &endpoints, &account)
        .await
        .expect("register and authenticate an unbound Coauth account");

    let authorization =
        authorize_with_current_account(&http, &endpoints.coauth_base_url, &client_id)
            .await
            .expect("complete the authorization-code flow as the logged-in account");

    assert!(
        !authorization.authorization_code.trim().is_empty(),
        "authorization returned an empty code"
    );
    assert_eq!(
        authorization.client_id, client_id,
        "authorization came back for a different client"
    );
    // PKCE is only meaningful if the verifier is not the challenge; a flow that
    // sent the verifier straight through would still return a code.
    assert_ne!(
        authorization.code_verifier, authorization.state,
        "code_verifier and state must not be the same value"
    );
}
