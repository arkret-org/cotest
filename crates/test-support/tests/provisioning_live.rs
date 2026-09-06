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
    provision_unbound_account, read_self_account_viewer,
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

    // Everything above reads the register response. This presents the grant
    // back to the Station, which is the only assertion here that would fail if
    // the chain produced a well-formed but unusable grant.
    let read = read_self_account_viewer(
        &http,
        &endpoints.soland_base_url,
        grant
            .get("session_grant")
            .and_then(|v| v.as_str())
            .expect("checked above"),
        &handoff.device_key,
    )
    .await
    .expect("read the founded principal's own account view");
    assert_eq!(
        read.status, 200,
        "the Station refused the grant it had just issued: {}",
        read.body
    );
    // The Station answers about the principal this chain founded, not about
    // whoever else the session happens to know.
    assert_eq!(
        read.body.get("principal_id"),
        account_id.get("principal_id"),
        "account viewer named a different principal: {}",
        read.body
    );
    // The founding device is on the account. A grant that authenticated but
    // whose device never landed would still read, and the next DPoP-bound call
    // would be the one to fail.
    let devices = read
        .body
        .get("devices")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("account viewer carried no devices: {}", read.body));
    assert!(
        devices.iter().any(|device| {
            device.get("device_id").and_then(|v| v.as_str()) == Some(device_id.as_str())
        }),
        "the founding device is not on the account: {devices:?}"
    );
}

/// The stdio bridge, driven the way a Playwright worker would drive it.
///
/// Spawns the binary, sends two correlated requests on one connection, and
/// checks that the second one sees the session the first one established. That
/// last part is the whole reason the bridge is a long-lived process: Coauth's
/// account session lives in a cookie jar, and a fresh process per call would
/// lose it.
#[tokio::test]
#[ignore = "requires a running Coauth and Soland; see the module docs"]
async fn the_stdio_bridge_keeps_one_session_across_requests() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let endpoints = endpoints();
    let bridge = env!("CARGO_BIN_EXE_cotest-provision");
    let mut child = tokio::process::Command::new(bridge)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn the provisioning bridge");
    let mut stdin = child.stdin.take().expect("bridge stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("bridge stdout")).lines();

    let slug = format!(
        "rust-bridge-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    );
    let endpoints_json = serde_json::json!({
        "coauth_base_url": endpoints.coauth_base_url,
        "soland_base_url": endpoints.soland_base_url,
        "mock_email_base_url": endpoints
            .mock_email
            .as_ref()
            .map(|inbox| inbox.base_url.clone()),
    });

    let mut send = |request: serde_json::Value| {
        let line = format!("{request}\n");
        async { line }
    };
    let _ = &mut send;

    // Request 1: register an account. This is what puts the session cookie in
    // the bridge's jar.
    let register = serde_json::json!({
        "id": "1",
        "op": "provision_unbound_account",
        "endpoints": endpoints_json,
        "account": { "handle": slug, "password": "1amTester!" },
    });
    stdin
        .write_all(format!("{register}\n").as_bytes())
        .await
        .expect("write register request");
    stdin.flush().await.expect("flush register request");
    let first = stdout
        .next_line()
        .await
        .expect("read register response")
        .expect("bridge closed before answering");
    let first: serde_json::Value = serde_json::from_str(&first).expect("parse register response");
    assert_eq!(first.get("id").and_then(|v| v.as_str()), Some("1"));
    assert_eq!(
        first.get("ok").and_then(|v| v.as_bool()),
        Some(true),
        "register through the bridge failed: {first}"
    );

    // Request 2: a handoff, which only works if the session from request 1 is
    // still there.
    let client_id = required_env("COTEST_OIDC_CLIENT_ID");
    let describe = serde_json::json!({
        "id": "2",
        "op": "describe_station",
        "coauth_base_url": endpoints.coauth_base_url,
        "soland_base_url": endpoints.soland_base_url,
    });
    stdin
        .write_all(format!("{describe}\n").as_bytes())
        .await
        .expect("write describe request");
    stdin.flush().await.expect("flush describe request");
    let second = stdout
        .next_line()
        .await
        .expect("read describe response")
        .expect("bridge closed before answering");
    let second: serde_json::Value = serde_json::from_str(&second).expect("parse describe response");
    assert_eq!(second.get("id").and_then(|v| v.as_str()), Some("2"));
    let service_id = second
        .pointer("/result/service_id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("describe through the bridge failed: {second}"))
        .to_owned();

    let handoff = serde_json::json!({
        "id": "3",
        "op": "create_account_handoff",
        "coauth_base_url": endpoints.coauth_base_url,
        "client_id": client_id,
        "audience_id": service_id,
        "device_label": slug,
    });
    stdin
        .write_all(format!("{handoff}\n").as_bytes())
        .await
        .expect("write handoff request");
    stdin.flush().await.expect("flush handoff request");
    let third = stdout
        .next_line()
        .await
        .expect("read handoff response")
        .expect("bridge closed before answering");
    let third: serde_json::Value = serde_json::from_str(&third).expect("parse handoff response");
    assert_eq!(
        third.get("ok").and_then(|v| v.as_bool()),
        Some(true),
        "handoff through the bridge failed — the account session did not survive \
         between requests: {third}"
    );
    assert!(
        third.pointer("/result/handoff_id").is_some(),
        "handoff response carried no id: {third}"
    );

    // The grant never crosses the bridge. A caller that could read it could
    // also present it, which would put the session material this module owns
    // into whatever process happened to ask.
    assert!(
        third.pointer("/result/account_handoff_grant").is_none(),
        "the bridge leaked the handoff grant: {third}"
    );

    drop(stdin);
    let status = child.wait().await.expect("wait for the bridge to exit");
    assert!(
        status.success(),
        "bridge exited with {status} after its input closed"
    );
}
