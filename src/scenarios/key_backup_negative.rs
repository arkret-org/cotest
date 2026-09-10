use anyhow::{Context as _, Result, anyhow};
use arkret_identifiers::{
    BackupId, BackupSeriesId, DeviceId, Did, EventId, project_did_to_core_id,
};
use arkret_models_crypto::{
    BackupKind, HistorySecretRangeIndex, HistorySecretRangesItemKind, KeyBackup, KeyBackupAead,
    KeyBackupAeadName, KeyBackupContentIndex, KeyBackupDomainSeparation, KeyBackupEncryption,
    KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm, UnsignedKeyBackup,
    UnsignedKeyBackupAuthData,
};
use arkret_wire::{Base64UrlString, DidUrl, EpochRange, HistoryEffectiveScope, RealmId, ScopeRef};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{ArkretServer, TestServerGroup, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

const BACKUP_ID: &str = "ak:backup:01975510-0000-7000-8000-0000000000d3";
const DEVICE_A: &str = "ak:device:01975510-0000-7000-8000-0000000000a1";
const DEVICE_B: &str = "ak:device:01975510-0000-7000-8000-0000000000b2";

pub async fn key_backup_put_get_negative_run() -> Result<()> {
    let group = TestServerGroup::single("d3-key-backup-negative").await?;
    let server = group.server(0);
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
                &alice.actor,
                DEVICE_A,
                BACKUP_ID,
            )?),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    let missing_ciphertext_baseline =
        backup_body(server.service_id(), &alice.actor, DEVICE_A, BACKUP_ID)?;
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

    let body_id_mismatch = backup_body(
        server.service_id(),
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

    let wrong_actor = backup_body(server.service_id(), &bob.actor, DEVICE_A, BACKUP_ID)?;
    expect_backup_error(
        alice
            .put(&format!("/_arkret/self/keys/backups/{BACKUP_ID}"))
            .header("Idempotency-Key", "wrong-actor")
            .json(&wrong_actor),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let accepted_body = backup_body(server.service_id(), &alice.actor, DEVICE_A, BACKUP_ID)?;
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

    let conflicting = arkret_test_kit::wire_negative_from_sdk(&accepted_body, |value| {
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
        reject_wrong_device_on_put(server, alice.expect_dev_bearer(), &alice.actor).await?;
        reject_digest_mismatch_on_put(server, alice.expect_dev_bearer(), &alice.actor).await?;
    }

    Ok(())
}

async fn reject_wrong_device_on_put(server: &ArkretServer, token: &str, actor: &str) -> Result<()> {
    let id = "ak:backup:01975510-0000-7000-8000-0000000000d4";
    let body = backup_body(server.service_id(), actor, DEVICE_B, id)?;
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
    let baseline = backup_body(server.service_id(), actor, DEVICE_A, id)?;
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
            .bearer_auth(token)
            .header("Idempotency-Key", "digest-mismatch")
            .json(&body),
        StatusCode::BAD_REQUEST,
        "digest_mismatch",
    )
    .await
}

fn backup_body(
    station_id: &arkret_wire::DidCoreId,
    actor: &str,
    device_id: &str,
    backup_id: &str,
) -> Result<KeyBackup> {
    let created_at = ts("2026-05-18T00:00:00.000Z")?;
    let actor_id = project_did_to_core_id(&Did::new(actor.to_owned())?)?;
    let effective_scope = ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:Aa1JCF6pnQnSgl8DnT6vNtPcFGPCxLnEY130o2lmyDSh".to_owned())?,
    };
    let history_scope = HistoryEffectiveScope::try_from(effective_scope)?;
    let backup = KeyBackup {
        backup_id: BackupId::new(backup_id.to_owned())?,
        actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id.clone(),
            station_id.clone(),
        )),
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
            subdomain: "test".to_owned(),
            aead_aad_extensions: Default::default(),
        },
        contents: vec![KeyBackupContentIndex::HistorySecretRanges(
            HistorySecretRangeIndex {
                item_kind: HistorySecretRangesItemKind::Value,
                effective_scope: history_scope,
                ranges: vec![EpochRange {
                    from_epoch: 0,
                    to_epoch: 0,
                }],
                extra: Default::default(),
            },
        )],
        ciphertext: "cotest-d3-ciphertext".to_owned(),
        ciphertext_digest:
            "sha256:099bf8f3386d21514c1fbd8282454fb2485018aa4cc3ede46d7f1fa6c3287d40".to_owned(),
        plaintext_commitment: None,
        auth_data: None,
        retention: None,
        series_id: BackupSeriesId::new(backup_id.replacen("ak:backup:", "ak:backup_series:", 1))?,
        series_seq: 0,
        supersedes_id: None,
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
    expect_api_error(builder, status, errcode).await?;
    Ok(())
}

fn strict_device_digest_negatives_enabled() -> bool {
    std::env::var("COTEST_STRICT_KEY_BACKUP_DEVICE_DIGEST")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
}
