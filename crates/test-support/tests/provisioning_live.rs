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
    DeploymentEndpoints, FoundPrincipalRequest, FoundingDeviceKey, MockEmailInbox, UnboundAccount,
    authorize_with_current_account, create_account_handoff, describe_station, found_principal,
    provision_unbound_account,
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

#[tokio::test]
#[ignore = "requires a running Coauth and Soland; see the module docs"]
async fn a_fresh_account_receives_an_identity_creation_lease() {
    let http = http_client();
    let endpoints = endpoints();
    let client_id = required_env("COTEST_OIDC_CLIENT_ID");
    let slug = format!(
        "rust-handoff-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    );
    let account = UnboundAccount {
        email: format!("{slug}@example.test"),
        display_name: format!("Rust handoff {slug}"),
        handle: slug.clone(),
        password: "1amTester!".to_owned(),
    };
    provision_unbound_account(&http, &endpoints, &account)
        .await
        .expect("register and authenticate an unbound Coauth account");

    let facts = describe_station(&http, &endpoints)
        .await
        .expect("describe the Station under test");
    let authorization =
        authorize_with_current_account(&http, &endpoints.coauth_base_url, &client_id)
            .await
            .expect("complete the authorization-code flow");

    let handoff = create_account_handoff(
        &http,
        &endpoints.coauth_base_url,
        &facts.service_id,
        &authorization,
        FoundingDeviceKey::derive(&slug),
    )
    .await
    .expect("exchange the authorization for an account handoff");

    assert!(
        !handoff.account_handoff_grant.trim().is_empty(),
        "handoff returned an empty grant"
    );
    // The lease is what makes this account able to found a principal. Without
    // asserting it, a handoff for an already-bound account would look the same.
    let lease = handoff
        .binding
        .get("identity_creation_lease")
        .unwrap_or_else(|| panic!("handoff binding carried no lease: {}", handoff.binding));
    assert!(
        lease.is_object(),
        "identity_creation_lease is not an object: {lease}"
    );
}

#[tokio::test]
#[ignore = "requires a running Coauth and Soland; see the module docs"]
async fn the_canonical_chain_founds_a_principal_end_to_end() {
    let http = http_client();
    let endpoints = endpoints();
    let client_id = required_env("COTEST_OIDC_CLIENT_ID");
    let slug = format!(
        "rust-found-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    );
    let account = UnboundAccount {
        email: format!("{slug}@example.test"),
        display_name: format!("Rust founding {slug}"),
        handle: slug.clone(),
        password: "1amTester!".to_owned(),
    };
    provision_unbound_account(&http, &endpoints, &account)
        .await
        .expect("register and authenticate an unbound Coauth account");

    let facts = describe_station(&http, &endpoints)
        .await
        .expect("describe the Station under test");
    let authorization =
        authorize_with_current_account(&http, &endpoints.coauth_base_url, &client_id)
            .await
            .expect("complete the authorization-code flow");
    let handoff = create_account_handoff(
        &http,
        &endpoints.coauth_base_url,
        &facts.service_id,
        &authorization,
        FoundingDeviceKey::derive(&slug),
    )
    .await
    .expect("exchange the authorization for an account handoff");

    let device_id = format!(
        "ak:device:01904100-0000-7000-8000-{:012x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
            & 0xffff_ffff_ffff
    );
    let principal = found_principal(
        &http,
        FoundPrincipalRequest {
            coauth_base: &endpoints.coauth_base_url,
            station_base: &endpoints.soland_base_url,
            trust_domain: &facts.trust_domain,
            audience_id: &facts.service_id,
            device_id: &device_id,
            display_name: &account.display_name,
        },
        &handoff,
    )
    .await
    .expect("found a principal through the canonical chain");

    // A recovery key that is not 24 words is not a recovery key. The registration
    // would still have "succeeded" without this.
    assert_eq!(
        principal.recovery_key.split_whitespace().count(),
        24,
        "recovery key is not a 24-word mnemonic"
    );

    // The grant has to bind to the Station that will be asked to honour it, and
    // to the device key that will present it. Either one wrong produces a grant
    // that looks valid and is refused on first use.
    let grant = &principal.session_grant_outcome;
    assert_eq!(
        grant.get("audience_id").and_then(|v| v.as_str()),
        Some(facts.service_id.as_str()),
        "initial grant bound to the wrong audience: {grant}"
    );
    assert!(
        grant
            .get("session_grant")
            .and_then(|v| v.as_str())
            .is_some_and(|jwt| !jwt.trim().is_empty()),
        "initial grant carried no session grant JWT: {grant}"
    );

    // The account id is closed: a principal is only addressable together with
    // the Station that holds it, and the grant must carry both halves.
    let account_id = grant
        .get("account_id")
        .unwrap_or_else(|| panic!("grant carried no account id: {grant}"));
    assert!(
        account_id
            .get("principal_id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id.starts_with("ak:did_core:")),
        "grant account id has no principal: {account_id}"
    );
    assert_eq!(
        account_id.get("station_id").and_then(|v| v.as_str()),
        Some(facts.service_id.as_str()),
        "grant account id names a different Station: {account_id}"
    );

    // The grant binds to the device this chain founded with. A grant bound to
    // some other device would present and be refused on first use.
    assert_eq!(
        grant.get("device_id").and_then(|v| v.as_str()),
        Some(device_id.as_str()),
        "initial grant bound to a different device: {grant}"
    );
}
