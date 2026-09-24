use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::harness::{expect_json, expect_status};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority,
};

pub async fn narrow_snapshot_head_discloses_only_complete_creator_cut() -> Result<()> {
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let origin = coauth.origin();
    let introspection = coauth.url();
    let server = spawn_with_harness_account_authority(
        "snapshot-head-disclosure",
        &[
            ("SOLAND_ACCOUNT_AUTHORITY_URL", origin.as_str()),
            ("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid"),
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
                introspection.as_str(),
            ),
        ],
    )
    .await?;
    let actor_id = actor_did_for_service_did(server.service_did(), "snapshot-alice")?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let principal = client.principal.as_ref().context("founding principal")?;
    let grant = mock_session_grant_jwt(
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        server.service_id().as_str(),
    );
    coauth.bind_founding_device_grant(
        &grant,
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        principal.founding_authorize_event_id.as_str(),
        &principal.device_signing_key.verifying_key(),
    )?;
    let author = server.client_with_founding_device_grant(principal, grant)?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Snapshot disclosure",
            "summary": "Snapshot disclosure",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm_id = bootstrap["realm_id"].as_str().context("realm_id")?;
    ensure!(
        bootstrap["event_response"]["commits"]
            .as_array()
            .is_some_and(|commits| commits.len() == 7),
        "baseline bootstrap must accept exactly seven Events: {bootstrap}"
    );
    let head_path = "/_arkret/self/realm-state-snapshot/head";
    let genesis_snapshot = expect_json(
        author.get(head_path).query(&[("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let genesis_typed: arkret_wire::RealmStateSnapshot =
        serde_json::from_value(genesis_snapshot.clone())
            .context("seven-Commit head must be a signed wire snapshot")?;
    ensure!(
        genesis_typed.visible_stream_heads.len() == 1
            && genesis_typed.visible_stream_heads[0].stream_position == 6
            && genesis_typed.current_state_entries.len() == 8,
        "seven-Commit creator cut is incomplete: {genesis_snapshot}"
    );
    verify_test_notary_snapshot(&genesis_typed)?;
    author.create_default_strand(realm_id).await?;
    let snapshot = expect_json(
        author.get(head_path).query(&[("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let typed: arkret_wire::RealmStateSnapshot = serde_json::from_value(snapshot.clone())
        .context("head must be the complete signed wire snapshot")?;
    ensure!(
        typed.realm_id.as_str() == realm_id,
        "wrong Realm in snapshot: {snapshot}"
    );
    ensure!(
        typed.visible_stream_heads[0].stream_position == 8,
        "creator cut must include bootstrap, Strand create, and default-Strand Commit: {snapshot}"
    );
    ensure!(
        typed.current_state_entries.len() == 10,
        "creator cut must disclose all ten typed current results: {snapshot}"
    );
    ensure!(
        snapshot["visible_stream_heads"]
            .as_array()
            .is_some_and(|heads| heads.len() == 1),
        "single-stream creator cut omitted or added a stream head: {snapshot}"
    );
    ensure!(
        snapshot["retention_and_history_floor"]["stream_floors"]
            .as_array()
            .is_some_and(|floors| floors.len() == 1),
        "creator cut omitted its history floor: {snapshot}"
    );
    ensure!(
        snapshot["signature"].is_object(),
        "unsigned snapshot: {snapshot}"
    );
    verify_test_notary_snapshot(&typed)?;

    let with_plaintext = author
        .create_realm_with(json!({
            "title": "Extra current family",
            "summary": "Extra current family",
            "public": false,
            "plaintext_visible_services": [server.service_id()]
        }))
        .await?;
    let with_plaintext_id = with_plaintext["realm_id"]
        .as_str()
        .context("plaintext Realm id")?;
    ensure!(
        with_plaintext["event_response"]["commits"]
            .as_array()
            .is_some_and(|commits| commits.len() == 8),
        "facet bootstrap must accept eight Events before the Strand pair: {with_plaintext}"
    );
    expect_status(
        author
            .get(head_path)
            .query(&[("realm_id", with_plaintext_id)]),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    Ok(())
}

fn verify_test_notary_snapshot(snapshot: &arkret_wire::RealmStateSnapshot) -> Result<()> {
    let seed: [u8; 32] = Sha256::digest(b"cotest:notary:snapshot-head-disclosure").into();
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let unsigned = arkret_canonical::unsigned_value(snapshot, &["signature"])?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &public_key,
    )
    .context("Snapshot detached signature does not verify against the test Station notary")?;
    let mut identity = serde_json::to_value(snapshot)?;
    let object = identity
        .as_object_mut()
        .context("Snapshot identity object")?;
    object.remove("signature");
    object.remove("snapshot_id");
    let derived = arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity)?,
    ));
    ensure!(
        snapshot.snapshot_id == derived,
        "Snapshot ID does not address its canonical identity body"
    );
    Ok(())
}
