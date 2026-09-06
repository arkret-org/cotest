//! `ArkretServer::canonical_client` against a live Coauth and Soland.
//!
//! The Rust harness has three ways to hold a principal, and until this file
//! existed only two of them were exercised: `demo_client` and `register_client`
//! take a development session, and the canonical entry point was compiled but
//! never run. A constructor that has never founded anything is not an entry
//! point, it is a claim.
//!
//! `#[ignore]` because it needs the deployment. `run-joint-e2e.ps1` runs it in
//! the same place it runs `provisioning_live`: inside the lane that owns the
//! services, because `-KeepServices` does not outlive a background runner and
//! there is no way to hand a running deployment to a separate `cargo test`.
//!
//! Environment is required, not optional. A missing variable panics rather than
//! skipping: a canonical-provisioning check that quietly does nothing is worse
//! than no check, because the run still reports a pass.

#![cfg(not(target_arch = "wasm32"))]

use anyhow::Result;
use cotest::harness::{ArkretServer, CanonicalClientRequest, ClientSession};
use cotest_test_support::provisioning::{DeploymentEndpoints, MockEmailInbox};

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is required; run this through scripts/run-joint-e2e.ps1")
    })
}

/// A client that trusts the run-scoped CA, and nothing extra.
///
/// The harness terminates TLS with a per-run certificate authority, so a client
/// that skipped verification would also pass against a misconfigured
/// deployment. The cookie jar is not optional either: Coauth's account session
/// lives in a cookie and the gate handoff authorizes against it.
fn provisioning_http() -> reqwest::Client {
    let ca_pem = required_env("COTEST_RUN_SCOPED_CA_PEM");
    let pem = std::fs::read(&ca_pem).unwrap_or_else(|error| {
        panic!("read run-scoped CA {ca_pem}: {error}");
    });
    let certificate = reqwest::Certificate::from_pem(&pem)
        .unwrap_or_else(|error| panic!("parse run-scoped CA {ca_pem}: {error}"));
    reqwest::Client::builder()
        .add_root_certificate(certificate)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build the provisioning HTTP client")
}

fn endpoints() -> DeploymentEndpoints {
    DeploymentEndpoints {
        coauth_base_url: required_env("COTEST_COAUTH_BASE_URL"),
        soland_base_url: required_env("COTEST_SOLAND_BASE_URL"),
        mock_email: std::env::var("COTEST_MOCK_EMAIL_BASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .map(|base_url| MockEmailInbox { base_url }),
    }
}

fn slug(prefix: &str) -> String {
    format!(
        "{prefix}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    )
}

#[tokio::test]
#[ignore = "requires a running Coauth and Soland; see the module docs"]
async fn the_harness_builds_a_client_from_the_canonical_chain() -> Result<()> {
    let endpoints = endpoints();
    let http = provisioning_http();
    let client_id = required_env("COTEST_OIDC_CLIENT_ID");
    let server = ArkretServer::attach(
        &endpoints.soland_base_url,
        &required_env("COTEST_SOLAND_NOTARY_SIGNING_KEY"),
        Some(std::path::Path::new(&required_env(
            "COTEST_RUN_SCOPED_CA_PEM",
        ))),
    )
    .await?;

    let handle = slug("rust-canonical").to_lowercase();
    let device_id = format!(
        "ak:device:01904100-0000-7000-8000-{:012x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
            & 0xffff_ffff_ffff
    );
    let client = server
        .canonical_client(CanonicalClientRequest {
            http: &http,
            endpoints: &endpoints,
            oidc_client_id: &client_id,
            handle: &handle,
            password: "1amTester!",
            device_id: &device_id,
            display_name: &format!("Rust canonical {handle}"),
        })
        .await?;

    // The session is canonical, not a bearer wearing the name. A scenario that
    // reached for `dev_bearer` here would get `None`, which is the whole point
    // of the two kinds being distinguishable.
    assert!(
        matches!(client.session(), ClientSession::Canonical { .. }),
        "canonical_client returned a development session"
    );
    assert!(
        client.dev_bearer().is_none(),
        "a canonical session must not present a bearer"
    );
    assert!(
        client.actor.starts_with("ak:did_core:"),
        "client actor is not a projected principal id: {}",
        client.actor
    );
    assert_eq!(client.device_id, device_id, "client bound another device");

    // The assertion that needed a live deployment: the client's own request
    // path presents the grant, and the Station honours it. Everything above
    // reads values the chain returned; this is the first thing that would fail
    // if the DPoP proof were minted over the wrong URL, signed by the wrong
    // key, or sent without the grant it is bound to.
    let response = client.get("/_arkret/self/account/viewer").send().await?;
    let status = response.status();
    let body = response.text().await?;
    assert_eq!(
        status.as_u16(),
        200,
        "the Station refused the canonical client's own grant: {body}"
    );
    let viewer: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        viewer.get("principal_id").and_then(|value| value.as_str()),
        Some(client.actor.as_str()),
        "account viewer named a different principal: {body}"
    );
    // The founding device landed on the account. A grant that authenticated
    // while its device never registered would read fine here and fail on the
    // next device-bound call.
    let devices = viewer
        .get("devices")
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("account viewer carried no devices: {body}"));
    assert!(
        devices.iter().any(|device| {
            device.get("device_id").and_then(|value| value.as_str()) == Some(device_id.as_str())
        }),
        "the founding device is not on the account: {devices:?}"
    );
    Ok(())
}
