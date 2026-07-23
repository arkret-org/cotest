use anyhow::{Context as _, Result, anyhow, bail};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_identifiers::{BackupId, BackupSeriesId, DeviceId, Did, PolicyId, TypedTrustDomainId};
use arkret_models_crypto::{
    BackupClass, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData,
    KeyBackupContentItem, KeyBackupDomainSeparation, KeyBackupDomainSeparationAad,
    KeyBackupEncryption, KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm, RecoveryPolicy,
    RecoveryPolicyAuthData, RecoveryPolicyRef, RecoveryProofKind,
};
use arkret_wire::{Base64UrlString, DidUrl};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{TestServerGroup, expect_json, expect_response};

const DEVICE_A: &str = "ak:device:01975510-0000-7000-8000-0000000000a1";
const POLICY_ID: &str = "ak:policy:01975510-0000-7000-8000-0000000000a1";
const DID_RECOVERY_BACKUP_ID: &str = "ak:backup:01975510-0000-7000-8000-0000000000a2";

pub async fn key_backup_recovery_account_state_run() -> Result<()> {
    let signing = SigningKey::from_bytes(&[81u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);

    let group = TestServerGroup::single("key-backup-recovery-account-state").await?;
    let server = group.server(0);
    let alice = server.demo_client(&principal_id, DEVICE_A).await?;

    let initial_policy = expect_json(
        alice.get("/_arkret/root/identity/recovery-policy"),
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
                "/_arkret/self/keys/backups/{DID_RECOVERY_BACKUP_ID}"
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
            .post("/_arkret/root/identity/recovery-policy")
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
            "/_arkret/self/keys/backups?backup_class={backup_class}"
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
        schema: "ak.schema.recovery_policy.v1".to_owned(),
        policy_id: PolicyId::new(POLICY_ID.to_owned())?,
        principal_id: Did::new(principal_id.to_owned())?,
        version: 1,
        supersedes: None,
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:soland.local".to_owned())?,
        allowed_proof_kinds: vec![RecoveryProofKind::PrincipalSigning],
        threshold: None,
        device_quorum: None,
        recovery_keys: None,
        recovery_key_agreements: None,
        trusted_recovery_services: None,
        approval_requirement: None,
        audit: None,
        issued_at: ts("2026-05-30T00:00:00.000Z")?,
        not_before: None,
        expires_at: Some(ts("2026-06-30T00:00:00.000Z")?),
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
        extra: Default::default(),
    })
}

fn did_recovery_backup_body(principal_id: &str, policy_id: &str) -> Result<KeyBackup> {
    let created_at = ts("2026-05-30T00:00:00.000Z")?;
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
            // hpke-suite-registry.json: absent `hpke_suite` denotes the
            // default-MUST row ak.hpke_x25519_aead_chacha20poly1305.v1, and
            // aead.name MUST equal that suite's AEAD (`chacha20_poly1305`) —
            // the SDK rejects a mismatch at parse time (schema_violation).
            aead: KeyBackupAead {
                name: KeyBackupAeadName::Chacha20Poly1305,
                aead_profile: Some("ak.aead.chacha20_poly1305.v1".to_owned()),
                nonce_salt: None,
                nonce: None,
                enc: Some(Base64UrlString::new("Y290ZXN0LWVuYw").map_err(|error| anyhow!(error))?),
                extra: Default::default(),
            },
            key_commitment: None,
            hpke_suite: None,
            extra: Default::default(),
        },
        domain_separation: KeyBackupDomainSeparation {
            hkdf_info: "arkret-key-backup/did_recovery/recovery_policy/v1".to_owned(),
            subdomain: "recovery_policy".to_owned(),
            aead_aad: KeyBackupDomainSeparationAad {
                schema: "ak.schema.key_backup.v1".to_owned(),
                actor_id: Did::new(principal_id.to_owned())?,
                device_id: Some(DEVICE_A.to_owned()),
                backup_class: BackupClass::DidRecovery,
                backup_version: "kb_1".to_owned(),
                created_at,
                item_types: vec!["recovery_secret".to_owned()],
                managed_principal_bindings: Vec::new(),
                recipient_method: None,
                recipient_key_ref: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        },
        contents: vec![KeyBackupContentItem {
            item_type: "recovery_secret".to_owned(),
            realm_id: None,
            managed_principal_binding: None,
            mls_group_id: None,
            epoch: None,
            first_event_id: None,
            last_event_id: None,
            secret_id: None,
            secret_version: None,
            extra: Default::default(),
        }],
        ciphertext: "cotest-did-recovery-ciphertext".to_owned(),
        ciphertext_digest:
            "sha256:2108421084217842908421084210842121084210842178429084210842108421".to_owned(),
        plaintext_commitment: None,
        auth_data: Some(KeyBackupAuthData {
            device_id: DeviceId::new(DEVICE_A.to_owned())?,
            verification_method: DidUrl::new("did:key:z6Mkdevice#z6Mkdevice")
                .map_err(|error| anyhow!(error))?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new("c2lnbmF0dXJl").map_err(|error| anyhow!(error))?,
            ssk_generation: std::num::NonZeroU64::new(1),
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
            extra: Default::default(),
        }),
        retention: None,
        series_id: BackupSeriesId::new(
            "ak:backup_series:01975510-0000-7000-8000-0000000000a2".to_owned(),
        )?,
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref: None,
        recovery_policy_ref: Some(RecoveryPolicyRef {
            policy_id: PolicyId::new(policy_id.to_owned())?,
            policy_version: 1,
        }),
        extra: Default::default(),
    })
}

fn ts(value: &str) -> Result<DateTime<Utc>> {
    arkret_canonical::parse_timestamp_canonical(value)
        .with_context(|| format!("invalid timestamp {value}"))
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
