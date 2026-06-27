use std::collections::BTreeMap;

use anyhow::{Context as _, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use cokret_core::multibase::ed25519_pubkey_to_did_key_multibase;
use cokret_core::{
    BackupClass, BackupId, BackupSeriesId, DeviceId, Did, KeyBackup, KeyBackupAead,
    KeyBackupAuthData, KeyBackupContentItem, KeyBackupDomainSeparation,
    KeyBackupDomainSeparationAad, KeyBackupEncryption, KeyBackupRecipientMethod,
    KeyBackupSignatureAlgorithm, PolicyId, RecoveryPolicy, RecoveryPolicyAuthData,
    RecoveryPolicyRef, RecoveryProofKind, TypedTrustDomainId,
};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{TestServerGroup, expect_json, expect_response};

const DEVICE_A: &str = "ck:device:01975510-0000-7000-8000-0000000000a1";
const POLICY_ID: &str = "ck:policy:01975510-0000-7000-8000-0000000000a1";
const DID_RECOVERY_BACKUP_ID: &str = "ck:backup:01975510-0000-7000-8000-0000000000a2";

pub async fn key_backup_recovery_account_state_run() -> Result<()> {
    let signing = SigningKey::from_bytes(&[81u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);

    let group = TestServerGroup::single("key-backup-recovery-account-state").await?;
    let server = group.server(0);
    let alice = server.demo_client(&principal_id, DEVICE_A).await?;

    let initial_policy = expect_json(
        alice.get("/_cokret/root/identity/recovery-policy"),
        StatusCode::OK,
    )
    .await?;
    assert!(
        initial_policy["active_policy"].is_null(),
        "fresh account must not claim an active recovery policy: {initial_policy}"
    );

    let empty_did_recovery = list_backups_by_class(&alice, "did_recovery").await?;
    assert!(
        !account_recovery_configured(&initial_policy["active_policy"], &empty_did_recovery),
        "active_policy=null plus zero did_recovery backups must be recovery-incomplete"
    );

    let rejected = expect_api_error_code(
        alice
            .put(&format!(
                "/_cokret/self/keys/backups/{DID_RECOVERY_BACKUP_ID}"
            ))
            .json(&did_recovery_backup_body(&principal_id, POLICY_ID)?),
        StatusCode::CONFLICT,
        "recovery_policy_mismatch",
    )
    .await?;
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("recovery policy"),
        "did_recovery rejection should point at the missing active policy: {rejected}"
    );

    let rejected_policy = expect_api_error_code(
        alice
            .post("/_cokret/root/identity/recovery-policy")
            .json(&unsigned_recovery_policy(
                &principal_id,
                &verification_method,
            )?),
        StatusCode::UNAUTHORIZED,
        "proof_invalid",
    )
    .await?;
    assert!(
        rejected_policy["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("freshness"),
        "live policy publish must fail closed without DID freshness evidence: {rejected_policy}"
    );

    let secret_storage = list_backups_by_class(&alice, "secret_storage").await?;
    assert!(
        secret_storage.is_empty(),
        "backup_class filter must not return did_recovery rows for secret_storage"
    );

    Ok(())
}

fn account_recovery_configured(active_policy: &Value, backups: &[Value]) -> bool {
    !active_policy.is_null()
        && backups.iter().any(|backup| {
            backup.get("backup_class").and_then(Value::as_str) == Some("did_recovery")
        })
}

async fn list_backups_by_class(
    alice: &crate::harness::TestActorClient,
    backup_class: &str,
) -> Result<Vec<Value>> {
    let body = expect_json(
        alice.get(&format!(
            "/_cokret/self/keys/backups?backup_class={backup_class}"
        )),
        StatusCode::OK,
    )
    .await?;
    body["backups"]
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("key-backup list did not return backups[]: {body}"))
}

fn did_key_principal(signing: &SigningKey) -> (String, String) {
    let multibase = ed25519_pubkey_to_did_key_multibase(signing.verifying_key().as_bytes());
    let principal_id = format!("did:key:{multibase}");
    let verification_method = format!("{principal_id}#{multibase}");
    (principal_id, verification_method)
}

fn unsigned_recovery_policy(
    principal_id: &str,
    verification_method: &str,
) -> Result<RecoveryPolicy> {
    Ok(RecoveryPolicy {
        schema: "ck.schema.recovery_policy.v1".to_owned(),
        policy_id: PolicyId::new(POLICY_ID.to_owned())?,
        principal_id: Did::new(principal_id.to_owned())?,
        version: 1,
        supersedes: None,
        trust_domain: TypedTrustDomainId::new("ck:trust_domain:soland.local".to_owned())?,
        allowed_proof_kinds: vec![RecoveryProofKind::PrincipalSigning],
        threshold: None,
        device_quorum: None,
        recovery_keys: None,
        trusted_recovery_services: None,
        approval_requirement: None,
        audit: None,
        issued_at: ts("2026-05-30T00:00:00Z")?,
        not_before: None,
        expires_at: Some(ts("2026-06-30T00:00:00Z")?),
        auth_data: RecoveryPolicyAuthData {
            verification_method: verification_method.to_owned(),
            signature_algorithm: "EdDSA".to_owned(),
            signature: "c2lnbmF0dXJl".to_owned(),
            signed_fields: [
                "schema",
                "policy_id",
                "principal_id",
                "version",
                "trust_domain",
                "allowed_proof_kinds",
                "supersedes",
                "issued_at",
                "expires_at",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        },
        extra: BTreeMap::new(),
    })
}

fn did_recovery_backup_body(principal_id: &str, policy_id: &str) -> Result<KeyBackup> {
    let created_at = ts("2026-05-30T00:00:00Z")?;
    Ok(KeyBackup {
        backup_id: BackupId::new(DID_RECOVERY_BACKUP_ID.to_owned())?,
        actor_id: Did::new(principal_id.to_owned())?,
        device_id: Some(DeviceId::new(DEVICE_A.to_owned())?),
        backup_class: BackupClass::DidRecovery,
        mixed_secret_storage: false,
        backup_version: "kb_1".to_owned(),
        created_at,
        updated_at: None,
        expires_at: None,
        encryption: KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::RecoveryPublicKey,
            recipient_key_ref: Some("did:key:z6MkrecoveryKey#z6MkrecoveryKey".to_owned()),
            kdf: None,
            aead: KeyBackupAead {
                name: "hpke_base_x25519_hkdf_sha256_chacha20poly1305".to_owned(),
                aead_profile: Some("ck.hpke.x25519_hkdf_sha256_chacha20_poly1305.v1".to_owned()),
                nonce_salt: None,
                nonce: None,
                enc: Some("Y290ZXN0LWVuYw".to_owned()),
                extra: BTreeMap::new(),
            },
            key_commitment: None,
            hpke_suite: None,
            extra: BTreeMap::new(),
        },
        domain_separation: KeyBackupDomainSeparation {
            hkdf_info: "cokret-key-backup/did_recovery/recovery_policy/v1".to_owned(),
            subdomain: "recovery_policy".to_owned(),
            aead_aad: KeyBackupDomainSeparationAad {
                schema: "ck.schema.key_backup.v1".to_owned(),
                actor_id: Did::new(principal_id.to_owned())?,
                device_id: DEVICE_A.to_owned(),
                backup_class: BackupClass::DidRecovery,
                backup_version: "kb_1".to_owned(),
                created_at,
                item_types: vec!["recovery_secret".to_owned()],
                recipient_method: None,
                recipient_key_ref: None,
                extra: BTreeMap::new(),
            },
            extra: BTreeMap::new(),
        },
        contents: vec![KeyBackupContentItem {
            item_type: "recovery_secret".to_owned(),
            realm_id: None,
            mls_group_id: None,
            epoch: None,
            first_event_id: None,
            last_event_id: None,
            secret_id: None,
            secret_version: None,
            extra: BTreeMap::new(),
        }],
        ciphertext: "cotest-did-recovery-ciphertext".to_owned(),
        ciphertext_digest:
            "sha256:2108421084217842908421084210842121084210842178429084210842108421".to_owned(),
        plaintext_commitment: None,
        auth_data: Some(KeyBackupAuthData {
            device_id: DeviceId::new(DEVICE_A.to_owned())?,
            verification_method: "did:key:z6Mkdevice#z6Mkdevice".to_owned(),
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: "c2lnbmF0dXJl".to_owned(),
            ssk_generation: Some(1),
            device_authorize_event_id: None,
            signed_fields: [
                "backup_id",
                "actor_id",
                "backup_class",
                "backup_version",
                "series_id",
                "series_seq",
                "encryption",
                "domain_separation",
                "contents",
                "ciphertext_digest",
                "recovery_policy_ref",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            extra: BTreeMap::new(),
        }),
        retention: None,
        series_id: BackupSeriesId::new(
            "ck:backup_series:01975510-0000-7000-8000-0000000000a2".to_owned(),
        )?,
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref: None,
        recovery_policy_ref: Some(RecoveryPolicyRef {
            policy_id: PolicyId::new(policy_id.to_owned())?,
            policy_version: 1,
        }),
        extra: BTreeMap::new(),
    })
}

fn ts(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid timestamp {value}"))
        .map(|dt| dt.with_timezone(&Utc))
}

async fn expect_api_error_code(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
    errcode: &str,
) -> Result<Value> {
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
    Ok(body)
}
