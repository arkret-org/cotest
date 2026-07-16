use anyhow::{Context as _, Result, anyhow, bail};
use arkret_core::{
    BackupClass, BackupId, BackupSeriesId, Base64UrlString, DeviceId, Did, DidUrl, KeyBackup,
    KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData, KeyBackupContentItem,
    KeyBackupDomainSeparation, KeyBackupDomainSeparationAad, KeyBackupEncryption,
    KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm,
};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{ArkretServer, TestServerGroup, expect_json, expect_response};

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

    let mut missing_ciphertext = backup_body(&alice.actor, DEVICE_A, BACKUP_ID)?;
    missing_ciphertext
        .as_object_mut()
        .ok_or_else(|| anyhow!("backup body was not an object"))?
        .remove("ciphertext");
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
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
            .json(&body_id_mismatch),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    let wrong_actor = backup_body(&bob.actor, DEVICE_A, BACKUP_ID)?;
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .json(&wrong_actor),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let accepted = expect_json(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .json(&backup_body(&alice.actor, DEVICE_A, BACKUP_ID)?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(accepted["backup_id"], BACKUP_ID);
    assert_eq!(accepted["status"], "accepted");

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
    let mut body = backup_body(actor, DEVICE_A, id)?;
    body["ciphertext"] = Value::String("tampered-ciphertext".to_owned());
    body["ciphertext_digest"] = Value::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
    );
    expect_backup_error(
        server
            .http()
            .put(server.url(&format!("/_arkret/self/keys/backups/{id}")))
            .bearer_auth(token)
            .json(&body),
        StatusCode::BAD_REQUEST,
        "digest_mismatch",
    )
    .await
}

fn backup_body(actor: &str, device_id: &str, backup_id: &str) -> Result<Value> {
    let created_at = ts("2026-05-18T00:00:00Z")?;
    let backup = KeyBackup {
        backup_id: BackupId::new(backup_id.to_owned())?,
        actor_id: Did::new(actor.to_owned())?,
        device_id: Some(DeviceId::new(device_id.to_owned())?),
        backup_class: BackupClass::MlsHistory,
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
                actor_id: Did::new(actor.to_owned())?,
                device_id: Some(device_id.to_owned()),
                backup_class: BackupClass::MlsHistory,
                backup_version: "kb_1".to_owned(),
                created_at,
                item_types: vec!["mls_group_state".to_owned()],
                managed_principal_bindings: Vec::new(),
                recipient_method: None,
                recipient_key_ref: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        },
        contents: vec![KeyBackupContentItem {
            item_type: "mls_group_state".to_owned(),
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
            "sha256:2108421084217842908421084210842121084210842178429084210842108421".to_owned(),
        plaintext_commitment: None,
        auth_data: Some(KeyBackupAuthData {
            device_id: DeviceId::new(device_id.to_owned())?,
            verification_method: DidUrl::new(format!("{actor}#device"))
                .map_err(|error| anyhow!(error))?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new("c2lnbmF0dXJl").map_err(|error| anyhow!(error))?,
            ssk_generation: std::num::NonZeroU64::new(1),
            device_authorize_event_id: None,
            signed_fields: key_backup_signed_fields(),
            extra: Default::default(),
        }),
        retention: None,
        series_id: BackupSeriesId::new(backup_id.replacen("ak:backup:", "ak:backup_series:", 1))?,
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref: None,
        recovery_policy_ref: None,
        extra: Default::default(),
    };
    Ok(serde_json::to_value(backup)?)
}

fn key_backup_signed_fields() -> Vec<String> {
    [
        "backup_id",
        "actor_id",
        "backup_class",
        "backup_version",
        "series_id",
        "series_seq",
        "supersedes",
        "encryption",
        "domain_separation",
        "contents",
        "ciphertext_digest",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn ts(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid timestamp {value}"))
        .map(|dt| dt.with_timezone(&Utc))
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
