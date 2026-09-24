use anyhow::{Context as _, Result, anyhow};
use arkret_identifiers::{BackupId, BackupSeriesId, DeviceId, Did, project_did_to_core_id};
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData,
    KeyBackupDomainSeparation, KeyBackupEncryption, KeyBackupRecipientMethod,
    KeyBackupSignatureAlgorithm, SecretStorageContentIndex, SecretStorageItemKind,
};
use arkret_wire::{Base64UrlString, Hash};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{ArkretServer, TestActorClient, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

const BACKUP_ID: &str = "ak:backup:01975510-0000-7000-8000-0000000000d3";
const DEVICE_A: &str = "ak:device:01975510-0000-7000-8000-0000000000a1";
const DEVICE_B: &str = "ak:device:01975510-0000-7000-8000-0000000000b2";

pub async fn key_backup_put_get_negative_run() -> Result<()> {
    let server_instance =
        spawn_with_harness_account_authority("d3-key-backup-negative", &[]).await?;
    let server = &server_instance;
    let alice_did = actor_did_for_service_did(server.service_did(), "alice-d3")?;
    let alice = server
        .register_client(&alice_did, "@alice-d3", DEVICE_A)
        .await?;
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-d3")?;
    let bob = server
        .register_client(
            &bob_did,
            "@bob-d3",
            "ak:device:01904100-0000-7000-8000-000000000bd3",
        )
        .await?;

    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .json(&backup_body(
                server.service_id(),
                &alice,
                DEVICE_A,
                BACKUP_ID,
            )?),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    let missing_ciphertext_baseline =
        backup_body(server.service_id(), &alice, DEVICE_A, BACKUP_ID)?;
    let missing_ciphertext =
        arkret_test_kit::wire_negative_from_sdk(&missing_ciphertext_baseline, |value| {
            value
                .as_object_mut()
                .expect("SDK key backup is an object")
                .remove("ciphertext");
        })?;
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "missing-ciphertext")
            .json(&missing_ciphertext),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    for (case, mutate) in [
        ("missing-contents", remove_contents as fn(&mut Value)),
        ("empty-contents", empty_contents),
        ("indexed-secret-generation", indexed_secret_generation),
    ] {
        let baseline = backup_body(server.service_id(), &alice, DEVICE_A, BACKUP_ID)?;
        let body = arkret_test_kit::wire_negative_from_sdk(&baseline, mutate)?;
        expect_backup_error(
            alice
                .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
                .header("Idempotency-Key", case)
                .json(&body),
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
        )
        .await
        .with_context(|| format!("key backup contents case {case}"))?;
    }

    let body_id_mismatch = backup_body(
        server.service_id(),
        &alice,
        DEVICE_A,
        "ak:backup:01975510-0000-7000-8000-0000000000ff",
    )?;
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "body-id-mismatch")
            .json(&body_id_mismatch),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    let wrong_actor = backup_body(server.service_id(), &bob, DEVICE_A, BACKUP_ID)?;
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "wrong-actor")
            .json(&wrong_actor),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let accepted_body = backup_body(server.service_id(), &alice, DEVICE_A, BACKUP_ID)?;
    let accepted = expect_json(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "accepted-replay")
            .json(&accepted_body),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(accepted["backup_id"], BACKUP_ID);
    assert_eq!(accepted["status"], "accepted");

    let replayed = expect_json(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "accepted-replay")
            .json(&accepted_body),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(replayed, accepted, "same key and body must replay exactly");

    let mut conflicting = accepted_body.clone();
    conflicting.plaintext_commitment = Some(Hash::new(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )?);
    let signing_key = &alice
        .principal
        .as_ref()
        .context("client has a provisioned principal")?
        .device_signing_key;
    let signature = ed25519_dalek::Signer::sign(signing_key, &conflicting.signing_payload_bytes()?);
    conflicting.auth_data.signature = Base64UrlString::new(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        signature.to_bytes(),
    ))
    .map_err(|error| anyhow!(error))?;
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "accepted-replay")
            .json(&conflicting),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    let bob_backups = expect_json(bob.get("/_arkret/self/keys/backups"), StatusCode::OK).await?;
    assert!(
        bob_backups["backups"]
            .as_array()
            .expect("key backup list backups")
            .iter()
            .all(|backup| backup["backup_id"] != BACKUP_ID),
        "key backup list leaked another actor's backup: {bob_backups}"
    );

    reject_wrong_device_on_put(server, &alice).await?;
    reject_digest_mismatch_on_put(server, &alice).await?;

    Ok(())
}

async fn reject_wrong_device_on_put(server: &ArkretServer, alice: &TestActorClient) -> Result<()> {
    let id = "ak:backup:01975510-0000-7000-8000-0000000000d4";
    let body = backup_body(server.service_id(), alice, DEVICE_B, id)?;
    expect_backup_error(
        server
            .http()
            .put(server.url(&format!("/_arkret/self/keys/backups/{id}")))
            .bearer_auth(alice.expect_dev_bearer())
            .header("Idempotency-Key", "wrong-device")
            .json(&body),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await
}

async fn reject_digest_mismatch_on_put(
    server: &ArkretServer,
    alice: &TestActorClient,
) -> Result<()> {
    let id = "ak:backup:01975510-0000-7000-8000-0000000000d5";
    let baseline = backup_body(server.service_id(), alice, DEVICE_A, id)?;
    let body = arkret_test_kit::wire_negative_from_sdk(&baseline, |value| {
        value["ciphertext"] = Value::String("tampered-ciphertext".to_owned());
        value["ciphertext_digest"] = Value::String(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        );
    })?;
    expect_backup_error(
        server
            .http()
            .put(server.url(&format!("/_arkret/self/keys/backups/{id}")))
            .bearer_auth(alice.expect_dev_bearer())
            .header("Idempotency-Key", "digest-mismatch")
            .json(&body),
        StatusCode::BAD_REQUEST,
        "digest_mismatch",
    )
    .await
}

fn backup_body(
    station_id: &arkret_wire::DidCoreId,
    actor: &TestActorClient,
    device_id: &str,
    backup_id: &str,
) -> Result<KeyBackup> {
    let created_at = ts("2026-05-18T00:00:00.000Z")?;
    let actor_id = project_did_to_core_id(&Did::new(actor.actor.clone())?)?;
    let principal = actor
        .principal
        .as_ref()
        .context("client has a provisioned principal")?;
    let (signing_seed, verification_method) =
        crate::harness::event_signing_identity_for_device(&actor.actor, device_id);
    let mut backup = KeyBackup {
        backup_id: BackupId::new(backup_id.to_owned())?,
        actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id.clone(),
            station_id.clone(),
        )),
        device_id: Some(DeviceId::new(device_id.to_owned())?),
        backup_kind: BackupKind::SecretStorage,
        mixed_secret_storage: false,
        backup_version: "kb_1".to_owned(),
        created_at,
        updated_at: None,
        expires_at: None,
        encryption: KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::SecretStorageKey,
            recipient_key_ref: Some("mls_group_secrets_backup_key".to_owned()),
            kdf: None,
            aead: KeyBackupAead {
                name: KeyBackupAeadName::Xchacha20Poly1305,
                aead_profile: Some("ak.aead.xchacha20_poly1305.v1".to_owned()),
                nonce_salt: None,
                nonce: Some(
                    Base64UrlString::new("cotest-d3-nonce").map_err(|error| anyhow!(error))?,
                ),
                enc: None,
                extra: Default::default(),
            },
            key_commitment: None,
            hpke_suite: None,
            extra: Default::default(),
        },
        domain_separation: KeyBackupDomainSeparation {
            subdomain: "test".to_owned(),
            aead_aad_extensions: Default::default(),
        },
        contents: vec![SecretStorageContentIndex {
            item_kind: SecretStorageItemKind::MlsGroupSecretsBackupKey,
            secret_id: "mls_group_secrets_backup_key".to_owned(),
        }],
        ciphertext: Base64UrlString::new("cotest-d3-ciphertext").map_err(|error| anyhow!(error))?,
        ciphertext_digest: Hash::new(
            "sha256:099bf8f3386d21514c1fbd8282454fb2485018aa4cc3ede46d7f1fa6c3287d40",
        )?,
        plaintext_commitment: None,
        auth_data: KeyBackupAuthData {
            device_id: DeviceId::new(device_id.to_owned())?,
            verification_method,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new("AA").map_err(|error| anyhow!(error))?,
            device_authorize_event_id: principal.founding_authorize_event_id.clone(),
        },
        retention: None,
        series_id: BackupSeriesId::new(backup_id.replacen("ak:backup:", "ak:backup_series:", 1))?,
        series_seq: 0,
        supersedes_id: None,
        supersedes_digest: None,
        source_commit_ref: None,
        recovery_policy_ref: None,
        extra: Default::default(),
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
    let signature = ed25519_dalek::Signer::sign(&signing_key, &backup.signing_payload_bytes()?);
    backup.auth_data.signature = Base64UrlString::new(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        signature.to_bytes(),
    ))
    .map_err(|error| anyhow!(error))?;
    Ok(backup)
}

fn ts(value: &str) -> Result<DateTime<Utc>> {
    arkret_canonical::parse_timestamp_canonical(value)
        .with_context(|| format!("invalid timestamp {value}"))
}

async fn expect_backup_error(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
    errcode: &str,
) -> Result<()> {
    expect_api_error(builder, status, errcode).await?;
    Ok(())
}

fn remove_contents(value: &mut Value) {
    value
        .as_object_mut()
        .expect("SDK key backup is an object")
        .remove("contents");
}

fn empty_contents(value: &mut Value) {
    value["contents"] = Value::Array(Vec::new());
}

fn indexed_secret_generation(value: &mut Value) {
    value["contents"][0]["secret_generation"] = Value::from(1);
}
