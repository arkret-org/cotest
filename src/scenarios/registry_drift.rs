//! Current catalogs and live wire rejection/scanning, migrated from Playwright.

use anyhow::{Context, Result, ensure};
use arkret_wire::{CommitStreamRef, RealmId};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::conformance::forbidden_wire::ForbiddenWireScanner;
use crate::harness::{TestActorClient, expect_json, expect_response, message_create_text_payload};

pub fn artifact(relative: &str) -> Result<Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../arkret-spec/spec/v1/artifacts")
        .join(relative);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn profile_claims<'a>(value: &'a Value, path: &mut Vec<String>, claims: &mut Vec<&'a str>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                path.push(key.clone());
                if (key == "profile_id"
                    || key == "id"
                        && path
                            .iter()
                            .any(|part| part.to_lowercase().contains("profile")))
                    && let Some(id) = child.as_str()
                {
                    claims.push(id);
                }
                profile_claims(child, path, claims);
                path.pop();
            }
        }
        Value::Array(values) => {
            for child in values {
                profile_claims(child, path, claims);
            }
        }
        _ => {}
    }
}

fn string_leaves(value: &Value) -> Vec<&str> {
    match value {
        Value::String(value) => vec![value],
        Value::Object(object) => object.values().flat_map(string_leaves).collect(),
        Value::Array(array) => array.iter().flat_map(string_leaves).collect(),
        _ => vec![],
    }
}

async fn scan(client: &TestActorClient, realm: &RealmId) -> Result<arkret_wire::StreamScanOutcome> {
    let outcome = client
        .sdk()
        .scan_commit_stream_tail(
            realm.clone(),
            CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            None,
            1000,
        )
        .await?;
    ensure!(!outcome.truncated, "registry probe unexpectedly truncated");
    Ok(outcome)
}

pub async fn registry_drift_with_client(client: &TestActorClient) -> Result<()> {
    let profiles = artifact("profiles/conformance-profiles.json")?;
    let operations = artifact("registry/operation-registry.json")?;
    let kinds = artifact("registry/event-kind-registry.json")?;
    let wire = artifact("registry/forbidden-wire-fields.json")?;
    let terms = artifact("registry/forbidden-model-terms.json")?;
    let scanner = ForbiddenWireScanner::new(wire.clone(), kinds.clone())?;
    let describe = serde_json::to_value(client.sdk().describe().await?)?;
    let roles = profiles["profile_roles"]
        .as_object()
        .context("canonical profile roles")?;
    ensure!(!roles.is_empty(), "empty profile catalog");
    let mut claims = vec![];
    for field in ["supported_profiles", "verified_profiles"] {
        for entry in describe[field]
            .as_array()
            .context("describe profile claims")?
        {
            if let Some(id) = entry
                .as_str()
                .or_else(|| entry["id"].as_str())
                .or_else(|| entry["profile_id"].as_str())
            {
                claims.push(id);
            }
        }
    }
    profile_claims(&describe, &mut vec![], &mut claims);
    for id in claims {
        ensure!(roles.contains_key(id), "unregistered profile {id}");
    }
    let bundles = operations["operation_bundles"]
        .as_array()
        .context("operation bundles")?;
    let canonical = operations["operations"]
        .as_array()
        .context("canonical operations")?;
    let claimed = describe["supported_operation_bundles"]
        .as_array()
        .context("describe must expose operation bundles")?;
    ensure!(
        !canonical.is_empty() && !claimed.is_empty(),
        "empty operation catalog/claim"
    );
    let mut claimed_count = 0;
    for id in claimed {
        let bundle = bundles
            .iter()
            .find(|row| row["operation_bundle_id"] == *id)
            .context("unregistered operation bundle")?;
        for member in bundle["members"].as_array().context("bundle members")? {
            ensure!(
                canonical
                    .iter()
                    .any(|row| row["operation_id"] == member["operation_id"]),
                "unregistered claimed operation"
            );
            claimed_count += 1;
        }
    }
    ensure!(claimed_count > 0, "empty expanded operation claim");

    let realm = client.create_realm("registry probe").await?;
    let strand = client.default_strand_id(&realm)?;
    let event = client
        .author_event(
            &realm,
            "ak.message.create",
            message_create_text_payload(&strand, "registry probe")?,
        )
        .await?;
    let submission = crate::publication::initial_submission(event.clone(), "")?;
    let receipt = expect_json(
        client.post("/_arkret/self/events").json(&submission),
        StatusCode::OK,
    )
    .await?;
    let event_value = serde_json::to_value(&event)?;
    ensure!(
        event_value["producer_proof"]["kind"] == "detached_jws"
            && event_value["producer_proof"]["verification_method"]
                == format!("{}#{}", client.actor, client.device_id),
        "ordinary device producer proof mismatch"
    );
    ensure!(
        event_value.get("auth_context").is_none() && event_value.get("data_basis").is_none(),
        "retired Event authoring members"
    );
    ensure!(
        scanner.scan_event(&event_value)?.is_empty(),
        "submitted Event has forbidden wire fields"
    );
    ensure!(
        scanner
            .scan(
                &receipt,
                "http_response",
                "service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome"
            )?
            .is_empty(),
        "receipt has forbidden wire fields"
    );
    let realm = RealmId::new(realm)?;
    let before = scan(client, &realm).await?;
    let removed = wire["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| {
            entry["context"] == "event_kind"
                && entry["rejection_level"] == "hard_reject"
                && entry["allowed_contexts"]
                    .as_array()
                    .is_some_and(|contexts| contexts.contains(&json!("negative_test")))
        })
        .context("registered removed Event kind")?;
    ensure!(
        !kinds["event_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["event_kind"] == removed["id"]),
        "negative kind is still registered"
    );
    // Keep the negative probe content-addressed and genuinely device-signed:
    // an old EventId would only exercise the digest gate before kind rejection.
    let mut unsigned = event.digest_payload()?;
    unsigned["kind"] = removed["id"].clone();
    let suite = event.event_id.event_digest().digest_suite()?;
    let bytes = arkret_canonical::canonical_json_bytes(&unsigned)?;
    let digest = arkret_wire::Hash::new(arkret_canonical::digest(suite, &bytes))?;
    let event_id = arkret_wire::EventId::from_event_digest(&digest)?;
    let principal = client
        .principal
        .as_ref()
        .context("negative probe needs its actual accepted device")?;
    let mut proof = event
        .producer_proof
        .clone()
        .context("negative producer proof")?;
    proof.event_digest = digest;
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &proof.canonical_binding_bytes(&event.actor_id)?,
        &principal.device_signing_key,
    )
    .map_err(anyhow::Error::msg)?;
    arkret_signatures::proof::verify_ed25519_detached_jws_proof_with_digest_suite(
        &proof,
        &bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: principal
                .device_signing_key
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
        suite,
    )?;
    let proof = serde_json::to_value(proof)?;
    let rejected = arkret_test_kit::wire_negative_from_sdk(&submission, |value| {
        value["event"]["kind"] = removed["id"].clone();
        value["event"]["event_id"] = json!(event_id);
        value["event"]["producer_proof"] = proof;
    })?;
    let refused = expect_response(
        client.post("/_arkret/self/events").json(&rejected),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    let problem = refused.json()?;
    let code = problem["type"]
        .as_str()
        .context("HTTP Problem type")?
        .rsplit('/')
        .next()
        .unwrap();
    ensure!(
        ["schema_violation", "unknown_event_kind"].contains(&code),
        "removed Event kind returned another error"
    );
    ensure!(
        scan(client, &realm).await? == before,
        "removed Event kind changed the accepted stream"
    );

    let mut surfaces = vec![
        ("server.describe", describe),
        ("events.submit.receipt", receipt),
        ("events.reject.problem", problem),
        ("streams.scan", serde_json::to_value(before)?),
    ];
    for (name, path) in [
        ("health", "/health"),
        ("directory.describe", "/_arkret/find/directory/describe"),
        ("account.viewer", "/_arkret/self/account/viewer"),
    ] {
        surfaces.push((name, expect_json(client.get(path), StatusCode::OK).await?));
    }
    let forbidden = terms["entries"]
        .as_array()
        .context("forbidden model terms")?
        .iter()
        .filter(|entry| entry["rejection_level"] == "hard_reject")
        .map(|entry| {
            entry["term"]
                .as_str()
                .or_else(|| entry["id"].as_str())
                .context("forbidden model term")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!forbidden.is_empty(), "empty model-term rejection set");
    for term in &forbidden {
        let ascii_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let leading = if term.chars().next().is_some_and(ascii_word) {
            r"(?-u:\b)"
        } else {
            ""
        };
        let trailing = if term.chars().last().is_some_and(ascii_word) {
            r"(?-u:\b)"
        } else {
            ""
        };
        let matcher = regex::Regex::new(&format!("{leading}{}{trailing}", regex::escape(term)))?;
        for (name, value) in &surfaces {
            ensure!(
                !string_leaves(value)
                    .into_iter()
                    .any(|text| matcher.is_match(text)),
                "forbidden model term {term} on {name}"
            );
        }
    }
    println!(
        "{}",
        json!({"phase":"registry_drift", "surfaces":surfaces.len(), "claimed_operations":claimed_count,
        "forbidden_model_terms":forbidden.len(), "removed_kind_zero_writes":true})
    );
    Ok(())
}

pub async fn registry_drift_runs_against_station() -> Result<()> {
    let server = super::identity_test_support::spawn_with_harness_account_authority(
        "registry-api-migration",
        &[],
    )
    .await?;
    let did = super::identity_test_support::actor_did_for_service_did(
        server.service_did(),
        "registry-api-owner",
    )?;
    let client = server
        .standard_client(&did, "ak:device:01904100-0000-7000-8000-00000000e602")
        .await?;
    registry_drift_with_client(&client).await
}

pub async fn canonical_registry_drift_api_migration() -> Result<()> {
    let fixture = super::_helpers::canonical_api::fixture("registry").await?;
    registry_drift_with_client(&fixture.client).await
}
