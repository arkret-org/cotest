//! Same-SCID relocation against independent, durable HTTPS Stations.

use anyhow::{Result, ensure};
use arkret_models_identity::{DidOperationSubmitRequestBody, IdentityResolveRequestBody};
use arkret_signatures::webvh::{
    PrincipalInceptionInput, PrincipalRotationInput, WebvhRelocationInput,
    prepare_principal_inception, prepare_principal_portability_update, prepare_principal_rotation,
    prepare_webvh_relocation,
};
use chrono::{Duration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, CanonicalJsonBody, expect_api_error, expect_json, expect_text};

fn public(seed: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .as_bytes(),
    )
}

fn resign_successor(
    body: &mut DidOperationSubmitRequestBody,
    previous: &Value,
    seed: &[u8; 32],
) -> Result<()> {
    let mut entry = serde_json::to_value(&body.operation)?;
    entry.as_object_mut().unwrap().remove("proof");
    let previous_version = previous["versionId"].as_str().unwrap();
    entry["versionId"] = json!(previous_version);
    let hash = arkret_signatures::webvh::webvh_entry_hash_multibase(&entry, previous_version)?;
    entry["versionId"] = json!(format!("{}-{hash}", body.seq.unwrap()));
    let key = public(seed);
    let proof = arkret_signatures::build_eddsa_jcs_2022_proof(
        &entry,
        &ed25519_dalek::SigningKey::from_bytes(seed),
        &format!("did:key:{key}#{key}"),
        arkret_signatures::DataIntegrityProofPurpose::AssertionMethod,
    )?;
    entry["proof"] = json!([proof]);
    body.operation = serde_json::from_value(entry)?;
    Ok(())
}

async fn submit(
    server: &ArkretServer,
    body: &DidOperationSubmitRequestBody,
    status: &str,
) -> Result<Value> {
    let outcome = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/submit-did-operation"))
            .canonical_json(body)?,
        StatusCode::OK,
    )
    .await?;
    ensure!(
        outcome["status"] == status,
        "unexpected submit outcome: {outcome}"
    );
    Ok(outcome)
}

async fn assert_current(
    server: &ArkretServer,
    aliases: &[String],
    entries: &[Value],
) -> Result<()> {
    let current = &entries.last().unwrap()["state"];
    for alias in aliases {
        let value = expect_json(
            server
                .http()
                .post(server.url("/_arkret/root/identity/resolve"))
                .canonical_json(&IdentityResolveRequestBody {
                    did: alias.parse()?,
                    requested_evidence_kinds: vec![],
                })?,
            StatusCode::OK,
        )
        .await?;
        ensure!(
            value["did_document"] == *current && value["seq"] == entries.len(),
            "alias did not reach the canonical head: {value}"
        );
    }
    let log_url = server.url("/webvh/portable/did.jsonl");
    let hosted_alias = entries.iter().any(|entry| {
        entry
            .pointer("/state/id")
            .and_then(Value::as_str)
            .and_then(|did| did.parse::<arkret_wire::Did>().ok())
            .and_then(|did| arkret_identity::DidWebvhResolver::log_url(&did).ok())
            .is_some_and(|url| url == log_url)
    });
    if !hosted_alias {
        let response = server.http().get(log_url).send().await?;
        ensure!(
            response.status() == StatusCode::NOT_FOUND,
            "foreign same-name history was served as a hosted alias"
        );
        return Ok(());
    }
    let body = expect_text(server.http().get(log_url), StatusCode::OK).await?;
    let mut expected = String::new();
    for entry in entries {
        expected.push_str(&String::from_utf8(arkret_canonical::canonical_json_bytes(
            entry,
        )?)?);
        expected.push('\n');
    }
    ensure!(
        body == expected,
        "hosted log changed or omitted a native original"
    );
    Ok(())
}

pub async fn relocation_survives_three_hosts_offline_recovery_and_restart() -> Result<()> {
    let hosting = [("COLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED", "1")];
    let mut a = ArkretServer::spawn_with_env("webvh-relocation-a", &hosting).await?;
    let mut b = ArkretServer::spawn_with_env("webvh-relocation-b", &hosting).await?;
    let mut c = ArkretServer::spawn_with_env("webvh-relocation-c", &hosting).await?;
    let services = [
        a.service_id().to_owned(),
        b.service_id().to_owned(),
        c.service_id().to_owned(),
    ];
    let at = Utc::now() - Duration::minutes(10);
    let a_url = a.base_url();
    let inception = prepare_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &a_url,
        principal_endpoint: &a_url,
        local_id: "portable",
        also_known_as: &[],
        version_time: at,
        root_seed: &[161; 32],
        next_root_public_key_multibase: &public(&[162; 32]),
        witness_policy: None,
    })?;
    for server in [&a, &b] {
        submit(server, &inception.submit_body, "accepted").await?;
    }
    let mut entries = vec![inception.log_entry.clone()];
    // An otherwise correctly signed move cannot enable its own permission.
    let mut late = prepare_principal_rotation(&PrincipalRotationInput {
        did: &inception.did,
        local_id: "portable",
        previous_entries: &entries,
        version_time: at + Duration::seconds(1),
        current_root_seed: &[162; 32],
        next_root_public_key_multibase: &public(&[163; 32]),
        state: &inception.log_entry["state"],
    })?
    .submit_body;
    let unknown_alias = inception
        .did
        .replace(":webvh:portable", ":webvh:late-portable");
    late.did = unknown_alias.parse()?;
    let mut late_state: Value = serde_json::from_str(
        &serde_json::to_string(&inception.log_entry["state"])?
            .replace(&inception.did, &unknown_alias),
    )?;
    late_state["alsoKnownAs"] = json!([inception.did]);
    late.operation.insert("state".into(), late_state);
    late.operation.get_mut("parameters").unwrap()["portable"] = json!(true);
    resign_successor(&mut late, &inception.log_entry, &[162; 32])?;
    arkret_identity::verify_did_webvh_entry_controller_proofs(&serde_json::to_value(
        &late.operation,
    )?)?;
    let refusal = expect_api_error(
        a.http()
            .post(a.url("/_arkret/root/identity/submit-did-operation"))
            .canonical_json(&late)?,
        StatusCode::CONFLICT,
        "did_method_successor_invalid",
    )
    .await?;
    ensure!(
        refusal.detail.contains("predecessor") && refusal.detail.contains("portable"),
        "relocation was refused for a different reason: {refusal:?}"
    );
    let still_original = expect_json(
        a.http()
            .post(a.url("/_arkret/root/identity/resolve"))
            .canonical_json(&IdentityResolveRequestBody {
                did: inception.did.parse()?,
                requested_evidence_kinds: vec![],
            })?,
        StatusCode::OK,
    )
    .await?;
    ensure!(
        still_original["seq"] == 1,
        "refused relocation changed the accepted head"
    );
    // Portability may be enabled by an earlier valid same-DID successor.
    let enabled = prepare_principal_portability_update(
        &PrincipalRotationInput {
            did: &inception.did,
            local_id: "portable",
            previous_entries: &entries,
            version_time: at + Duration::seconds(1),
            current_root_seed: &[162; 32],
            next_root_public_key_multibase: &public(&[163; 32]),
            state: &inception.log_entry["state"],
        },
        true,
    )?;
    expect_api_error(
        c.http()
            .post(c.url("/_arkret/root/identity/submit-did-operation"))
            .canonical_json(&enabled.submit_body)?,
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await?;
    submit(&c, &inception.submit_body, "accepted").await?;
    for server in [&a, &b, &c] {
        submit(server, &enabled.submit_body, "accepted").await?;
    }
    entries.push(enabled.log_entry.clone());
    let scid = inception.did.split(':').nth(2).unwrap();
    let target = |server: &ArkretServer| -> Result<String> {
        let base = server.base_url();
        let (authority, _) =
            arkret_signatures::webvh::webvh_authority_pair(base.host_str().unwrap(), base.port());
        Ok(format!("did:webvh:{scid}:{authority}:webvh:portable"))
    };
    let b_did = target(&b)?;
    let c_did = target(&c)?;
    let mut aliases = vec![inception.did.clone()];
    let mut current = inception.did.clone();
    let mut missed = Vec::new();
    a.stop_external_process().await?;
    for (index, target) in [&b_did, &c_did].into_iter().enumerate() {
        let mut state: Value = serde_json::from_str(
            &serde_json::to_string(&entries.last().unwrap()["state"])?.replace(&current, target),
        )?;
        state["alsoKnownAs"] = json!([current]);
        let moved = prepare_webvh_relocation(&WebvhRelocationInput {
            current_did: &current,
            target_did: target,
            previous_entries: &entries,
            version_time: at + Duration::seconds(index as i64 + 2),
            current_update_seed: &[163 + index as u8; 32],
            next_update_public_key_multibase: &public(&[164 + index as u8; 32]),
            state: &state,
        })?;
        // Each Station has its own history and CAS; the old host can be offline
        // while the new host accepts the holder's next original.
        submit(&b, &moved.submit_body, "accepted").await?;
        submit(&c, &moved.submit_body, "accepted").await?;
        missed.push(moved.submit_body);
        entries.push(moved.log_entry.clone());
        aliases.push(target.clone());
        current = target.clone();
        for server in [&b, &c] {
            assert_current(server, &aliases, &entries).await?;
        }
    }
    a.start_external_process().await?;
    expect_api_error(
        a.http()
            .post(a.url("/_arkret/root/identity/submit-did-operation"))
            .canonical_json(missed.last().unwrap())?,
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await?;
    for original in &missed {
        submit(&a, original, "accepted").await?;
        submit(&a, original, "duplicate").await?;
    }
    assert_current(&a, &aliases, &entries).await?;
    for server in [&mut a, &mut b, &mut c] {
        server.restart_external_process().await?;
        assert_current(server, &aliases, &entries).await?;
    }
    ensure!(
        [
            a.service_id().to_owned(),
            b.service_id().to_owned(),
            c.service_id().to_owned()
        ] == services,
        "hosting changed a Station identity"
    );
    // A rival successor from the old cut cannot replace the accepted branch.
    let mut fork = enabled.submit_body.clone();
    fork.operation
        .insert("state".into(), json!({"id": inception.did}));
    expect_api_error(
        a.http()
            .post(a.url("/_arkret/root/identity/submit-did-operation"))
            .canonical_json(&fork)?,
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await?;
    assert_current(&a, &aliases, &entries).await?;
    let witness_policy = arkret_models_identity::DidWebvhWitnessPolicy {
        threshold: 1,
        witnesses: vec![format!("did:key:{}", public(&[170; 32]))],
    };
    let unwitnessed = prepare_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &a_url,
        principal_endpoint: &a_url,
        local_id: "unwitnessed",
        also_known_as: &[],
        version_time: at,
        root_seed: &[171; 32],
        next_root_public_key_multibase: &public(&[172; 32]),
        witness_policy: Some(&witness_policy),
    })?;
    let witness_refusal = expect_api_error(
        a.http()
            .post(a.url("/_arkret/root/identity/submit-did-operation"))
            .canonical_json(&unwitnessed.submit_body)?,
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;
    ensure!(
        witness_refusal
            .extensions
            .get("reason_code")
            .and_then(Value::as_str)
            == Some("webvh_witness_threshold_not_met"),
        "wrong witness refusal: {witness_refusal:?}"
    );
    assert_current(&a, &aliases, &entries).await?;
    Ok(())
}
