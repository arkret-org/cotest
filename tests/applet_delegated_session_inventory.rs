//! Exact Applet delegated-session inventory contract and live issuer boundary.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use arkret_identifiers::SessionGrantId;
use arkret_models_collaboration::account_lifecycle::{
    AppletDelegatedSessionInventoryOutcome, AppletDelegatedSessionInventoryRequestBody,
};
use arkret_signatures::http_signature::{
    ContentDigest, ContentDigestAlgorithm, HttpSignatureScenario, SignedRequestParts,
    sign_http_message_for_scenario,
};
use cotest::scenarios::_helpers::joint_service_bootstrap::{JointServiceConfig, try_bootstrap};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use serial_test::serial;
use sha2::{Digest, Sha256};

const OPERATION: &str = "ak.gate.account.read.applet_delegated_session_inventory.v1";
const PATH: &str = "/_arkret/gate/account/session-grants/applet-inventory";
const STATION_NAME: &str = "applet-inventory-live";

fn fixture() -> Result<Value> {
    let path = arkret_schema_conformance::default_spec_artifacts_dir()
        .context("arkret-spec artifacts directory is unavailable")?
        .join("fixtures/applet-revoke-saga-fixture.json");
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

#[test]
fn empty_inventory_witness_and_aba_are_bound_to_the_closed_sdk_carrier() -> Result<()> {
    let fixture = fixture()?;
    let kat = &fixture["preview_plan_digest_kat"]["delegated_session_inventory_kat"];
    let request: AppletDelegatedSessionInventoryRequestBody =
        serde_json::from_value(kat["request"].clone())?;
    let outcome: AppletDelegatedSessionInventoryOutcome =
        serde_json::from_value(kat["outcome"].clone())?;
    request.validate_shape()?;
    outcome.validate_against(&request)?;
    ensure!(outcome.active_session_grant_ids.is_empty());
    ensure!(
        outcome.snapshot_digest.to_string()
            == fixture["preview_plan_digest_kat"]["revoke_plan"]
                ["delegated_session_snapshot_digest"]
                .as_str()
                .context("plan omitted the empty-set witness")?
    );

    let mut after_aba = outcome.clone();
    after_aba.inventory_revision = kat["aba_reject"]["after_add_and_remove_revision"]
        .as_u64()
        .context("ABA vector omitted the successor revision")?;
    ensure!(
        after_aba.active_session_grant_ids == outcome.active_session_grant_ids,
        "ABA vector must return to the same active set"
    );
    ensure!(after_aba.validate_against(&request).is_err());

    let mut altered_selector = request.clone();
    altered_selector.capability_grant_refs.clear();
    ensure!(outcome.validate_against(&altered_selector).is_err());

    let mut missing_witness = kat["outcome"].clone();
    missing_witness
        .as_object_mut()
        .context("inventory outcome must be an object")?
        .remove("snapshot_digest");
    ensure!(
        serde_json::from_value::<AppletDelegatedSessionInventoryOutcome>(missing_witness).is_err(),
        "an empty list without a witness cannot be authoritative"
    );

    let mut nonempty = outcome.clone();
    nonempty.inventory_revision = 2;
    nonempty.active_session_grant_ids = vec![
        SessionGrantId::from_issuance_digest([1; 32]),
        SessionGrantId::from_issuance_digest([2; 32]),
    ];
    nonempty.active_session_grant_ids.sort();
    nonempty.snapshot_digest = nonempty.compute_snapshot_digest()?;
    nonempty.validate_against(&request)?;
    nonempty.active_session_grant_ids.reverse();
    nonempty.snapshot_digest = nonempty.compute_snapshot_digest()?;
    ensure!(nonempty.validate_against(&request).is_err());
    let repeated = nonempty.active_session_grant_ids[1].clone();
    nonempty.active_session_grant_ids[0] = repeated;
    nonempty.snapshot_digest = nonempty.compute_snapshot_digest()?;
    ensure!(nonempty.validate_against(&request).is_err());
    Ok(())
}

/// Boots real Soland, Coauth and PostgreSQL; a service-signed empty inventory
/// must be accepted, while the same body without the signature must be hidden.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires built Soland and Coauth binaries plus Docker or COTEST_COAUTH_DATABASE_URL"]
#[serial]
async fn live_signed_inventory_uses_coauth_issuer_and_unsigned_read_has_no_effect() -> Result<()> {
    let stack = try_bootstrap(JointServiceConfig::new(STATION_NAME)).await?;
    let coauth = stack.coauth.as_ref().context(
        "live inventory requires real Coauth and PostgreSQL; build both binaries and provide Docker or COTEST_COAUTH_DATABASE_URL",
    )?;
    let fixture = fixture()?;
    let kat = &fixture["preview_plan_digest_kat"]["delegated_session_inventory_kat"];
    let request: AppletDelegatedSessionInventoryRequestBody =
        serde_json::from_value(kat["request"].clone())?;
    request.validate_shape()?;
    let body = arkret_canonical::canonical_json_bytes(&request)?;
    let target = format!("{}{}", coauth.base_url().trim_end_matches('/'), PATH);
    let url = url::Url::parse(&target)?;
    let authority = url.host_str().context("Coauth URL has no host")?.to_owned();
    let authority = url
        .port()
        .map_or(authority.clone(), |port| format!("{authority}:{port}"));
    let digest = ContentDigest::compute(&body, ContentDigestAlgorithm::Sha256).wire_value;
    let source = stack.soland.service_id().to_string();
    let headers = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("content-digest".to_owned(), digest.clone()),
        ("arkret-operation".to_owned(), OPERATION.to_owned()),
        ("source-service-id".to_owned(), source.clone()),
        ("destination-service-id".to_owned(), source),
        (
            "source-trust-domain".to_owned(),
            stack.soland.trust_domain().to_string(),
        ),
        (
            "destination-trust-domain".to_owned(),
            stack.soland.trust_domain().to_string(),
        ),
    ];
    let signing_digest = Sha256::digest(format!("cotest:notary:{STATION_NAME}").as_bytes());
    let mut signing_seed = [0_u8; 32];
    signing_seed.copy_from_slice(&signing_digest);
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let signed = sign_http_message_for_scenario(
        &SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: target.clone(),
            authority,
            path: PATH.to_owned(),
            headers: headers.clone(),
            body_digest: Some(digest),
        },
        HttpSignatureScenario::ServiceToServiceV1,
        &[
            "content-digest",
            "source-trust-domain",
            "destination-trust-domain",
        ],
        "sig1",
        &format!("{}#federation-fanout-key", stack.soland.service_did()),
        chrono::Utc::now().timestamp(),
        &signing_key,
    )?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    wait_for_coauth_service_identity(&http, coauth.base_url()).await?;
    let mut unsigned = http.post(&target).body(body.clone());
    for (name, value) in &headers {
        unsigned = unsigned.header(name, value);
    }
    let unsigned_response = unsigned.send().await?;
    ensure!(
        unsigned_response.status() == reqwest::StatusCode::NOT_FOUND,
        "unsigned delegated-session inventory must be hidden with 404, got {}",
        unsigned_response.status()
    );

    let mut tampered = serde_json::to_value(&request)?;
    tampered["registration_epoch"] = serde_json::json!(format!("sha256:{}", "2".repeat(64)));
    let tampered_body = arkret_canonical::canonical_json_bytes(&tampered)?;
    let mut tampered_request = http.post(&target).body(tampered_body);
    for (name, value) in &headers {
        tampered_request = tampered_request.header(name, value);
    }
    let tampered_response = tampered_request
        .header("signature-input", &signed.signature_input_header)
        .header("signature", &signed.signature_header)
        .send()
        .await?;
    ensure!(
        tampered_response.status() == reqwest::StatusCode::NOT_FOUND,
        "changed signed selector must be hidden with 404, got {}",
        tampered_response.status()
    );

    let mut signed_request = http.post(&target).body(body);
    for (name, value) in &headers {
        signed_request = signed_request.header(name, value);
    }
    let response = signed_request
        .header("signature-input", &signed.signature_input_header)
        .header("signature", &signed.signature_header)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status.is_success(),
        "Coauth rejected signed inventory with {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    let outcome: AppletDelegatedSessionInventoryOutcome = serde_json::from_slice(&bytes)?;
    outcome.validate_against(&request)?;
    ensure_eq_empty_fixture(&outcome, kat)?;

    let mut db = postgres::Client::connect(&coauth.pg.connect_url, postgres::NoTls)?;
    let states: i64 = db
        .query_one(
            "SELECT count(*) FROM oauth_applet_session_inventory_states",
            &[],
        )?
        .get(0);
    let operations: i64 = db
        .query_one("SELECT count(*) FROM oauth_session_grant_operations", &[])?
        .get(0);
    ensure!(
        states == 0 && operations == 0,
        "inventory reads mutated the issuer ledger"
    );
    Ok(())
}

async fn wait_for_coauth_service_identity(http: &reqwest::Client, base_url: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let url = format!("{}/_arkret/describe", base_url.trim_end_matches('/'));
    loop {
        let response = http.get(&url).send().await?;
        if response.status().is_success() {
            let describe: Value = response.json().await?;
            if describe
                .get("service_id")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty())
            {
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < deadline,
            "Coauth service identity was not ready within 60 seconds"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn ensure_eq_empty_fixture(
    actual: &AppletDelegatedSessionInventoryOutcome,
    kat: &Value,
) -> Result<()> {
    let expected: AppletDelegatedSessionInventoryOutcome =
        serde_json::from_value(kat["outcome"].clone())?;
    ensure!(
        actual == &expected,
        "live empty inventory differs from the normative witness"
    );
    Ok(())
}
