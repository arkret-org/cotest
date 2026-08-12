//! Real identity deployment smoke: production Starid Provider, Soland,
//! Coauth, and the Inkson-linked SDK client path.

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::SigningKey;
use reqwest::{Client, StatusCode, Url};
use serde_json::{Value, json};

use crate::harness::{CanonicalJsonBody, device_message_send_request, encrypted_envelope};
use crate::scenarios::_helpers::four_service_bootstrap::{
    FourServiceConfig, FourServiceStack, identity_deployment_required,
};

pub async fn identity_deployment_smoke_run() -> Result<()> {
    let mut config = FourServiceConfig::new("identity-deployment-smoke");
    config.wire_directory_ingest = false;
    let registration_bearer = config.external_webvh_registration_bearer.clone();
    let mut stack = identity_deployment_required(config).await?;
    stack.assert_healthy().await?;

    let starid_base = stack
        .starid_base_url()
        .context("identity deployment omitted Starid")?
        .trim_end_matches('/')
        .to_owned();
    let soland_base = stack.soland_base_url().trim_end_matches('/').to_owned();
    let coauth_base = stack
        .coauth_base_url()
        .context("identity deployment omitted Coauth")?
        .trim_end_matches('/')
        .to_owned();
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    assert_provider_discovery(&client, &starid_base, &soland_base).await?;
    assert_service_identity_registration_auth(
        &client,
        &starid_base,
        &soland_base,
        &registration_bearer,
    )
    .await?;
    assert_coauth_service_identity(&client, &coauth_base).await?;
    assert_witness_and_freshness(&client, &starid_base, &soland_base).await?;
    assert_starid_outage_does_not_gate_ordinary_human_flows(&client, &mut stack, &starid_base).await
}

async fn assert_starid_outage_does_not_gate_ordinary_human_flows(
    client: &Client,
    stack: &mut FourServiceStack,
    starid_base: &str,
) -> Result<()> {
    stack
        .starid
        .as_mut()
        .context("identity deployment omitted Starid")?
        .kill_and_wait()?;
    if client
        .get(format!("{starid_base}/_arkret/describe"))
        .send()
        .await
        .is_ok()
    {
        bail!("Starid remained reachable after the outage was injected");
    }

    let actor = "did:web:alice.example";
    let device_id = "ak:device:01904100-0000-7000-8000-00000000d110";
    let alice = stack.soland.demo_client(actor, device_id).await?;

    let realm_id = alice.create_realm("Starid Outage Ordinary Flow").await?;
    alice
        .grant_self_realm_actions(&realm_id, &["ak.policy.manage"])
        .await?;
    let strand_id = alice.default_strand_id(&realm_id)?;
    alice
        .send_message(
            &realm_id,
            &strand_id,
            "ordinary PCR-bound Event while Starid is unavailable",
        )
        .await?;

    let mls_device_message = device_message_send_request(
        actor,
        device_id,
        "ak:device_message:0196419b-0000-7000-8000-00000000d110",
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "opaque-starid-outage-ciphertext"),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )?;
    require_success(
        alice
            .post("/_arkret/self/device_messages")
            .header("Idempotency-Key", "identity-deployment-starid-outage-mls")
            .canonical_json(&mls_device_message)?
            .send()
            .await?,
        "MLS device message while Starid is unavailable",
    )
    .await?;

    // Run lifecycle last because deactivation intentionally revokes this
    // session and device. The handler is deployment-local and must not turn
    // Starid availability into a blanket prerequisite.
    require_success(
        alice
            .post("/_soland/self/account/deactivate")
            .send()
            .await?,
        "human account lifecycle while Starid is unavailable",
    )
    .await
}

async fn assert_provider_discovery(
    client: &Client,
    starid_base: &str,
    soland_base: &str,
) -> Result<()> {
    let starid = get_json(client, &format!("{starid_base}/_arkret/describe")).await?;
    if starid
        .pointer("/auth_metadata/mode")
        .and_then(Value::as_str)
        != Some("production")
        || starid.get("development_mode").and_then(Value::as_bool) != Some(false)
    {
        bail!("Starid discovery did not report production posture");
    }

    let soland = get_json(
        client,
        &format!("{soland_base}/_arkret/root/identity/describe"),
    )
    .await?;
    let descriptor = &soland["did_webvh"];
    if descriptor["default_provider_id"] != "external.webvh" {
        bail!("Soland did not select the external WebVH Provider");
    }
    let external = descriptor["providers"]
        .as_array()
        .and_then(|providers| {
            providers
                .iter()
                .find(|provider| provider["id"] == "external.webvh")
        })
        .context("Soland discovery omitted external.webvh")?;
    if external["active"] != true
        || external["freshness_probe"] != "/_arkret/describe"
        || external["base_url"] != starid_base
    {
        bail!("Soland external WebVH discovery is inactive or points at the wrong Provider");
    }

    let health = get_json(client, &format!("{soland_base}/health")).await?;
    if health
        .pointer("/checks/service_identity/state")
        .and_then(Value::as_str)
        != Some("ready")
        || health
            .pointer("/checks/service_identity/provider_endpoint")
            .and_then(Value::as_str)
            .map(|value| value.trim_end_matches('/'))
            != Some(starid_base)
    {
        bail!("Soland service identity was not bootstrapped by the external Provider");
    }
    Ok(())
}

async fn assert_service_identity_registration_auth(
    client: &Client,
    starid_base: &str,
    soland_base: &str,
    bearer: &str,
) -> Result<()> {
    let endpoint = format!(
        "{starid_base}{}",
        arkret_models_identity::service_identity::SERVICE_REGISTRATION_GET_PATH
    );
    let canonical_soland_base = format!("{soland_base}/");
    let query = [
        ("service_kind", "principal_server"),
        ("public_base", canonical_soland_base.as_str()),
    ];
    let unauthenticated = client.get(&endpoint).query(&query).send().await?;
    if unauthenticated.status() != StatusCode::UNAUTHORIZED {
        bail!(
            "Starid service registration lookup did not require authentication: {}",
            unauthenticated.status()
        );
    }
    let authenticated = client
        .get(endpoint)
        .query(&query)
        .bearer_auth(bearer)
        .send()
        .await?;
    let status = authenticated.status();
    let body = authenticated.text().await?;
    if !status.is_success() {
        bail!("authenticated service registration lookup failed: {status} {body}");
    }
    let outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome =
        serde_json::from_str(&body).context("decode service registration outcome")?;
    if outcome
        .registration_receipt
        .registration_key
        .public_base()
        .as_str()
        .trim_end_matches('/')
        != soland_base
    {
        bail!("Starid registration receipt is bound to a different Soland base URL");
    }
    Ok(())
}

async fn assert_coauth_service_identity(client: &Client, coauth_base: &str) -> Result<()> {
    let describe = get_json(client, &format!("{coauth_base}/_arkret/describe")).await?;
    let service_id = describe
        .get("service_id")
        .and_then(Value::as_str)
        .context("Coauth discovery omitted service_id")?;
    arkret_identifiers::DidCoreId::new(service_id.to_owned())
        .map_err(|error| anyhow!("Coauth service_id is invalid: {error}"))?;
    Ok(())
}

async fn assert_witness_and_freshness(
    client: &Client,
    starid_base: &str,
    soland_base: &str,
) -> Result<()> {
    let provider_endpoint = Url::parse(&format!("{starid_base}/"))?;
    let principal_endpoint = Url::parse(&format!("{soland_base}/"))?;
    let witness_seed = [61u8; 32];
    let witness_multikey = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&witness_seed)
            .verifying_key()
            .to_bytes(),
    );
    let witness_did = format!("did:key:{witness_multikey}");
    let witness_policy = arkret_models_identity::DidWebvhWitnessPolicy {
        threshold: 1,
        witnesses: vec![witness_did.clone()],
    };
    let next_root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[62u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let prepared = arkret_signatures::webvh::prepare_portable_principal_inception(
        &arkret_signatures::webvh::PrincipalInceptionInput {
            provider_endpoint: &provider_endpoint,
            principal_endpoint: &principal_endpoint,
            local_id: "identity-deployment-smoke",
            also_known_as: &[],
            version_time: chrono::Utc::now(),
            root_seed: &[63u8; 32],
            next_root_public_key_multibase: &next_root,
            witness_policy: Some(&witness_policy),
        },
    )?;
    let submit = client
        .post(format!(
            "{starid_base}/_arkret/root/identity/submit-did-operation"
        ))
        .json(&prepared.submit_body)
        .send()
        .await?;
    require_success(submit, "standard witnessed DID inception").await?;

    let before = witness_receipts(client, starid_base, &prepared.did).await?;
    if before["threshold_met"] != false {
        bail!("freshness precondition did not report an unmet witness threshold");
    }

    let witness_path = format!("{starid_base}/_starid/webvh/dids/witness");
    let bad_seed = [64u8; 32];
    let bad = witness_request(&bad_seed, &prepared.did, &prepared.version_id);
    require_error_code(
        client.post(&witness_path).json(&bad).send().await?,
        StatusCode::FORBIDDEN,
        "witness_not_authorized",
    )
    .await?;

    let wrong_subject = format!("{}-wrong", prepared.did);
    let wrong = witness_request(&witness_seed, &wrong_subject, &prepared.version_id);
    require_status(
        client.post(&witness_path).json(&wrong).send().await?,
        StatusCode::NOT_FOUND,
        "wrong witness subject",
    )
    .await?;

    let stale_version = format!("{}-stale", prepared.version_id);
    let stale = witness_request(&witness_seed, &prepared.did, &stale_version);
    require_error_code(
        client.post(&witness_path).json(&stale).send().await?,
        StatusCode::CONFLICT,
        "stale_version",
    )
    .await?;

    let valid = witness_request(&witness_seed, &prepared.did, &prepared.version_id);
    require_success(
        client.post(&witness_path).json(&valid).send().await?,
        "valid witness attestation",
    )
    .await?;
    require_error_code(
        client.post(&witness_path).json(&valid).send().await?,
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await?;

    let after = witness_receipts(client, starid_base, &prepared.did).await?;
    if after["threshold_met"] != true {
        bail!("freshness refresh did not observe the newly accepted witness evidence");
    }

    let did = arkret_identifiers::DidFullId::new(prepared.did.clone())?;
    // This is an explicitly owned loopback Provider. The public resolver URL
    // helpers correctly reject loopback authorities as an SSRF boundary, so
    // construct only this test-owned method-native path after checking that
    // the DID authority is exactly loopback.
    let log_url = owned_loopback_webvh_url(&did, "did.jsonl")?;
    let witness_url = owned_loopback_webvh_url(&did, "did-witness.json")?;
    let log = client
        .get(log_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let witness = client
        .get(witness_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    arkret::identity::verify_did_webvh_v1_chain_and_witness_bytes(&did, &log, Some(&witness))
        .context("verify standard did.jsonl + did-witness.json evidence")?;

    let resolved = client
        .post(format!("{soland_base}/_arkret/root/identity/resolve"))
        .json(&arkret_models_identity::IdentityResolveRequestBody {
            did,
            requested_evidence_kinds: Vec::new(),
        })
        .send()
        .await?;
    require_success(resolved, "Soland external witnessed DID resolution").await
}

fn witness_request(seed: &[u8; 32], did: &str, version_id: &str) -> Value {
    json!({
        "did": did,
        "version_id": version_id,
        "proof": arkret_signatures::webvh::sign_did_webvh_witness_proof(version_id, seed),
    })
}

async fn witness_receipts(client: &Client, starid_base: &str, did: &str) -> Result<Value> {
    let response = client
        .get(format!("{starid_base}/_arkret/root/identity/receipts"))
        .query(&[("did", did)])
        .send()
        .await?;
    response
        .error_for_status()?
        .json()
        .await
        .map_err(Into::into)
}

fn owned_loopback_webvh_url(did: &arkret_identifiers::DidFullId, leaf: &str) -> Result<Url> {
    let (_, host, port, path) =
        arkret::identity::did_webvh_parts(did).context("parse test-owned did:webvh authority")?;
    if host != "127.0.0.1" {
        bail!("identity deployment smoke DID escaped loopback: {host}");
    }
    let port = port.context("identity deployment smoke DID omitted its loopback port")?;
    let path = if path.is_empty() {
        format!(".well-known/{leaf}")
    } else {
        format!("{}/{leaf}", path.join("/"))
    };
    Ok(Url::parse(&format!("http://{host}:{port}/{path}"))?)
}

async fn get_json(client: &Client, url: &str) -> Result<Value> {
    Ok(client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn require_success(response: reqwest::Response, operation: &str) -> Result<()> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("{operation} failed: {status} {body}");
    }
    Ok(())
}

async fn require_status(
    response: reqwest::Response,
    expected: StatusCode,
    operation: &str,
) -> Result<()> {
    let status = response.status();
    let body = response.text().await?;
    if status != expected {
        bail!("{operation} returned {status}, expected {expected}: {body}");
    }
    Ok(())
}

async fn require_error_code(
    response: reqwest::Response,
    expected_status: StatusCode,
    expected_code: &str,
) -> Result<()> {
    let status = response.status();
    let body: Value = response.json().await?;
    if status != expected_status
        || body.pointer("/error/code").and_then(Value::as_str) != Some(expected_code)
    {
        bail!(
            "fail-closed assertion expected {expected_status}/{expected_code}, got {status}: {body}"
        );
    }
    Ok(())
}
