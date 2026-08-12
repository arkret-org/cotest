use anyhow::{Context as _, Result, anyhow, bail};
use arkret_identifiers::{
    BackupId, BackupSeriesId, DeviceId, DidFullId, EventId, project_full_id_to_core_id,
};
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupContentItem,
    KeyBackupDomainSeparation, KeyBackupDomainSeparationAad, KeyBackupEncryption,
    KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm, UnsignedKeyBackup,
    UnsignedKeyBackupAuthData,
};
use arkret_wire::{Base64UrlString, DidUrl};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{
    ArkretServer, TestServerGroup, expect_json, expect_response, wire_negative_from_sdk,
};

const BACKUP_ID: &str = "ak:backup:01975510-0000-7000-8000-0000000000d3";
const DEVICE_A: &str = "ak:device:01975510-0000-7000-8000-0000000000a1";
const DEVICE_B: &str = "ak:device:01975510-0000-7000-8000-0000000000b2";

pub async fn key_backup_put_get_negative_run() -> Result<()> {
    let group = TestServerGroup::single("d3-key-backup-negative").await?;
    let server = group.server(0);
    let alice = server
        .register_client("did:web:alice-d3.example", "@alice-d3", DEVICE_A)
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-d3.example",
            "@bob-d3",
            "ak:device:01904100-0000-7000-8000-000000000bd3",
        )
        .await?;

    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .json(&backup_body(&alice.actor, DEVICE_A, BACKUP_ID)?),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let missing_ciphertext_baseline = backup_body(&alice.actor, DEVICE_A, BACKUP_ID)?;
    let missing_ciphertext = wire_negative_from_sdk(&missing_ciphertext_baseline, |value| {
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

    let body_id_mismatch = backup_body(
        &alice.actor,
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

    let wrong_actor = backup_body(&bob.actor, DEVICE_A, BACKUP_ID)?;
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "wrong-actor")
            .json(&wrong_actor),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let accepted_body = backup_body(&alice.actor, DEVICE_A, BACKUP_ID)?;
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

    let conflicting = wire_negative_from_sdk(&accepted_body, |value| {
        value["plaintext_commitment"] = Value::String(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        );
    })?;
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "accepted-replay")
            .json(&conflicting),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    let accepted_value = serde_json::to_value(&accepted_body)?;
    let signed_fields = accepted_value
        .pointer("/auth_data/signed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("key backup auth_data.signed_fields is missing"))?;
    assert!(
        signed_fields
            .iter()
            .all(|field| field.as_str() != Some("idempotency_key")),
        "Idempotency-Key is an HTTP replay header, not part of the backup content signature"
    );

    let bob_backups = expect_json(bob.get("/_arkret/self/keys/backups"), StatusCode::OK).await?;
    assert!(
        bob_backups["backups"]
            .as_array()
            .expect("key backup list backups")
            .iter()
            .all(|backup| backup["backup_id"] != BACKUP_ID),
        "key backup list leaked another actor's backup: {bob_backups}"
    );

    if strict_device_digest_negatives_enabled() {
        reject_wrong_device_on_put(server, &alice.token, &alice.actor).await?;
        reject_digest_mismatch_on_put(server, &alice.token, &alice.actor).await?;
    }

    Ok(())
}

async fn reject_wrong_device_on_put(server: &ArkretServer, token: &str, actor: &str) -> Result<()> {
    let id = "ak:backup:01975510-0000-7000-8000-0000000000d4";
    let body = backup_body(actor, DEVICE_B, id)?;
    expect_backup_error(
        server
            .http()
            .put(server.url(&format!("/_arkret/self/keys/backups/{id}")))
            .bearer_auth(token)
            .header("Idempotency-Key", "wrong-device")
            .json(&body),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await
}

async fn reject_digest_mismatch_on_put(
    server: &ArkretServer,
    token: &str,
    actor: &str,
) -> Result<()> {
    let id = "ak:backup:01975510-0000-7000-8000-0000000000d5";
    let baseline = backup_body(actor, DEVICE_A, id)?;
    let body = wire_negative_from_sdk(&baseline, |value| {
        value["ciphertext"] = Value::String("tampered-ciphertext".to_owned());
        value["ciphertext_digest"] = Value::String(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        );
    })?;
    expect_backup_error(
        server
            .http()
            .put(server.url(&format!("/_arkret/self/keys/backups/{id}")))
            .bearer_auth(token)
            .header("Idempotency-Key", "digest-mismatch")
            .json(&body),
        StatusCode::BAD_REQUEST,
        "digest_mismatch",
    )
    .await
}

fn backup_body(actor: &str, device_id: &str, backup_id: &str) -> Result<KeyBackup> {
    let created_at = ts("2026-05-18T00:00:00.000Z")?;
    let actor_id = project_full_id_to_core_id(&DidFullId::new(actor.to_owned())?)?;
    let backup = KeyBackup {
        backup_id: BackupId::new(backup_id.to_owned())?,
        actor_id: actor_id.clone(),
        device_id: Some(DeviceId::new(device_id.to_owned())?),
        backup_kind: BackupKind::MlsHistory,
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
            hkdf_info: "arkret-key-backup/mls_history/test/v1".to_owned(),
            subdomain: "test".to_owned(),
            aead_aad: KeyBackupDomainSeparationAad {
                schema: "ak.schema.key_backup.v1".to_owned(),
                actor_id,
                device_id: Some(device_id.to_owned()),
                backup_kind: BackupKind::MlsHistory,
                backup_version: "kb_1".to_owned(),
                created_at,
                item_kinds: vec!["mls_group_state".to_owned()],
                managed_principal_bindings: Vec::new(),
                recipient_method: Some(KeyBackupRecipientMethod::SecretStorageKey),
                recipient_key_ref: Some("mls_group_secrets_backup_key".to_owned()),
                extra: Default::default(),
            },
            extra: Default::default(),
        },
        contents: vec![KeyBackupContentItem {
            item_kind: "mls_group_state".to_owned(),
            realm_id: None,
            managed_principal_binding: None,
            mls_group_id: Some("group_d3".to_owned()),
            epoch: Some(0),
            first_event_id: None,
            last_event_id: None,
            secret_id: None,
            secret_version: None,
            extra: Default::default(),
        }],
        ciphertext: "cotest-d3-ciphertext".to_owned(),
        ciphertext_digest:
            "sha256:099bf8f3386d21514c1fbd8282454fb2485018aa4cc3ede46d7f1fa6c3287d40".to_owned(),
        plaintext_commitment: None,
        auth_data: None,
        retention: None,
        series_id: BackupSeriesId::new(backup_id.replacen("ak:backup:", "ak:backup_series:", 1))?,
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref: None,
        recovery_policy_ref: None,
        extra: Default::default(),
    };
    let auth_data = UnsignedKeyBackupAuthData::new(
        DeviceId::new(device_id.to_owned())?,
        DidUrl::new(format!("{actor}#device")).map_err(|error| anyhow!(error))?,
        KeyBackupSignatureAlgorithm::Ed25519,
        EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")?,
    )?;
    UnsignedKeyBackup::new(backup, auth_data)?
        .attach_signature(Base64UrlString::new("c2lnbmF0dXJl").map_err(|error| anyhow!(error))?)
        .map_err(anyhow::Error::from)
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
    let response = expect_response(builder, status).await?;
    let body = response.json()?;
    let actual = body
        .pointer("/error/errcode")
        .or_else(|| body.pointer("/error/code"))
        .or_else(|| body.get("errcode"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actual != errcode {
        bail!("expected errcode {errcode}, got {actual:?}. body: {body}");
    }
    Ok(())
}

fn strict_device_digest_negatives_enabled() -> bool {
    std::env::var("COTEST_STRICT_KEY_BACKUP_DEVICE_DIGEST")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
}
