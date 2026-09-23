//! Phase 3 — key-backup surfaces: PUT / list / operations / unlock.
//!
//! Stores Alice's MLS-history backup, enumerates the collection, walks the
//! advertised key-backup operations, and exercises the unlock-proof gate.
//!
//! Surface split (G3 namespace audit):
//! - `PUT/DELETE /_arkret/self/keys/backups/*`, `GET /_arkret/self/keys/backups`, and `POST
//!   /_arkret/self/keys/backups/{id}/unlock` — protocol face.
//! - `GET /_arkret/describe` — advertises the key-backup operation ids.
//!
//! Full-ciphertext reads are gated by spec `identity/key-management.md`
//! §7.7.1: every `POST /_arkret/self/keys/backups/{id}/unlock` MUST carry a
//! body `{proof: ak.schema.key_backup_unlock_proof.v1}` bound to the envelope;
//! a bearer token without that body proof MUST be refused.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, anyhow};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_identifiers::{
    BackupId, BackupSeriesId, DeviceId, Did, DidCoreId, EventId, project_did_to_core_id,
};
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData,
    KeyBackupDomainSeparation, KeyBackupEncryption, KeyBackupRecipientMethod, KeyBackupRetention,
    KeyBackupSignatureAlgorithm, KeyBackupUnlockAuthority, KeyBackupUnlockProof,
    KeyBackupUnlockProofAuthData, KeysBackupsIssueUnlockChallengeRequestBody,
    KeysBackupsUnlockChallenge, KeysBackupsUnlockRequestBody, SecretStorageContentIndex,
    SecretStorageItemKind,
};
use arkret_wire::{AccountId, Base64UrlString, DidUrl, Hash};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;

use crate::harness::{ArkretServer, expect_json};

pub const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-000000000000";

/// Must match the device id minted by the typed bootstrap in
/// [`super::events_keys_device_blob_push_and_moderation_surfaces_work`]: the
/// unlock proof binds `requesting_device_id` to the authenticated session
/// device.
const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const SERIES_ID: &str = "ak:backup_series:01964137-0000-7000-8000-000000000000";
/// Typed device id carried inside the envelope (`auth_data.device_id` must be
/// a `ak:device:` typed id; it is not required to equal the session device).
const ENVELOPE_DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000000";
const CIPHERTEXT_DIGEST: &str =
    "sha256:305531dcc50ebca31cf1d5b31e9fc76ed51f66b3b6dd5a030c6539ae6532f979";

/// Deterministic Ed25519 device key shared by the envelope `auth_data`
/// signature and the unlock-proof transcript signature.
fn device_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

pub async fn run(server: &ArkretServer, token: &str, actor_id: &str) -> Result<()> {
    put_backup(server, token, actor_id).await?;
    list_backups(server, token).await?;
    describe_backup_operations(server).await?;
    unlock_backup_requires_body_proof(server, token, actor_id).await?;
    current_device_unlock_rejects_wrong_device_before_signature_trust(server, token, actor_id)
        .await?;
    Ok(())
}

async fn put_backup(server: &ArkretServer, token: &str, actor_id: &str) -> Result<()> {
    let backup_put = expect_json(
        server
            .http()
            .put(server.url(&format!("/_arkret/self/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-payloads-key-backup-put")
            .json(&signed_backup_envelope(actor_id, server.service_id())?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_put["status"], "accepted");
    assert_eq!(backup_put["backup_id"], BACKUP_ID);
    Ok(())
}

/// Build the `ak.schema.key_backup.v1` envelope including the §7.4.1
/// `auth_data` device-signature block. The device authorization Event is the
/// trust anchor for this signature.
fn signed_backup_envelope(actor_id: &str, station_id: &DidCoreId) -> Result<KeyBackup> {
    let signing_key = device_signing_key();
    let multibase = ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    let verification_method = format!("did:key:{multibase}#{multibase}");
    let created_at = ts("2026-04-26T00:00:00.000Z")?;
    let mut envelope = KeyBackup {
        backup_id: backup_id(BACKUP_ID)?,
        actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            did(actor_id)?,
            station_id.clone(),
        )),
        device_id: Some(device_id(ENVELOPE_DEVICE_ID)?),
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
                nonce: Some(Base64UrlString::new("nonce").map_err(|error| anyhow!(error))?),
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
        ciphertext: Base64UrlString::new("Y2lwaGVydGV4dA").map_err(|error| anyhow!(error))?,
        ciphertext_digest: Hash::new(CIPHERTEXT_DIGEST)?,
        plaintext_commitment: None,
        auth_data: KeyBackupAuthData {
            device_id: device_id(ENVELOPE_DEVICE_ID)?,
            verification_method: DidUrl::new(verification_method)
                .map_err(|error| anyhow!(error))?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new("AA").map_err(|error| anyhow!(error))?,
            device_authorize_event_id: EventId::new(
                "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            )?,
        },
        retention: Some(KeyBackupRetention {
            delete_after: Some(ts("2020-01-01T00:00:00.000Z")?),
            legal_hold: Some(false),
            extra: BTreeMap::new(),
        }),
        series_id: backup_series_id(SERIES_ID)?,
        series_seq: 0,
        supersedes_id: None,
        supersedes_digest: None,
        source_commit_ref: None,
        recovery_policy_ref: None,
        extra: Default::default(),
    };
    let signature = signing_key.sign(&envelope.signing_payload_bytes()?);
    envelope.auth_data.signature =
        Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
            .map_err(|error| anyhow!(error))?;
    Ok(envelope)
}

async fn list_backups(server: &ArkretServer, token: &str) -> Result<()> {
    let backup_list = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/keys/backups"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert!(!backup_list["backups"].as_array().unwrap().is_empty());
    Ok(())
}

async fn describe_backup_operations(server: &ArkretServer) -> Result<()> {
    let description = expect_json(
        server.http().get(server.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    let description: arkret_models_discovery::ServiceDescribe =
        serde_json::from_value(description)?;
    for operation_id in [
        "ak.self.keys.backups.resource.replace.v1",
        "ak.self.keys.backups.read.list.v1",
        "ak.self.keys.backups.command.unlock.v1",
        "ak.self.keys.backups.command.issue_unlock_challenge.v1",
        "ak.self.keys.backups.resource.delete.v1",
    ] {
        assert!(
            description.supports_operation(
                arkret_wire::ServiceOperationId::from_wire(operation_id)
                    .expect("backup operation must be registered")
            ),
            "describe did not advertise {operation_id}: {description:?}"
        );
    }
    Ok(())
}

/// Spec §7.7.1 / §7.8 — a bearer token alone MUST NOT release the full
/// ciphertext: unlock is refused without a body proof.
async fn unlock_backup_requires_body_proof(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    let baseline = KeysBackupsUnlockRequestBody {
        proof: unlock_proof(server, token, actor_id).await?,
    };
    crate::harness::expect_api_error(
        server
            .http()
            .post(server.url(&format!("/_arkret/self/keys/backups/{BACKUP_ID}/unlock")))
            .bearer_auth(token)
            .json(&arkret_test_kit::wire_negative_from_sdk(
                &baseline,
                |value| {
                    value
                        .as_object_mut()
                        .expect("SDK body is an object")
                        .remove("proof");
                },
            )?),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;
    Ok(())
}

async fn current_device_unlock_rejects_wrong_device_before_signature_trust(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    // The proof uses the deterministic backup-envelope key, not the
    // authenticated session's current device key. Device binding is the first
    // authorization gate, so the request must fail before evaluating whether
    // that unrelated signature is otherwise well formed.
    crate::harness::expect_api_error(
        server
            .http()
            .post(server.url(&format!("/_arkret/self/keys/backups/{BACKUP_ID}/unlock")))
            .bearer_auth(token)
            .json(&KeysBackupsUnlockRequestBody {
                proof: unlock_proof(server, token, actor_id).await?,
            }),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    Ok(())
}

/// Build a `ak.schema.key_backup_unlock_proof.v1` body value: a canonical
/// JSON transcript bound to the stored envelope, signed by an Ed25519 device
/// key whose `verification_method` resolves via `did:key`.
///
/// Ordinary device proofs use the exact Station-issued challenge and never
/// claim a synthetic recovery session or a second proof digest.
async fn unlock_proof(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<KeyBackupUnlockProof> {
    let request = KeysBackupsIssueUnlockChallengeRequestBody {
        request_id: Base64UrlString::new("cHJvdG9jb2wtdW5sb2NrLXJlcXVlc3Q")
            .map_err(|error| anyhow!(error))?,
    };
    let challenge: KeysBackupsUnlockChallenge = serde_json::from_value(
        expect_json(
            server
                .http()
                .post(server.url(&format!(
                    "/_arkret/self/keys/backups/{BACKUP_ID}/unlock-challenge"
                )))
                .bearer_auth(token)
                .json(&request),
            StatusCode::OK,
        )
        .await?,
    )?;
    anyhow::ensure!(
        challenge.account_id == AccountId::new(did(actor_id)?, server.service_id().clone()),
        "unlock challenge account mismatch"
    );
    anyhow::ensure!(
        challenge.requesting_device_id.as_str() == DEVICE_ID
            && challenge.backup_id.as_str() == BACKUP_ID,
        "unlock challenge target mismatch"
    );
    let signing_key = device_signing_key();
    let multibase = ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    let verification_method = format!("did:key:{multibase}#{multibase}");
    let mut proof = KeyBackupUnlockProof {
        schema: KeyBackupUnlockProof::SCHEMA.to_owned(),
        authority: KeyBackupUnlockAuthority::CurrentDevice {
            challenge_id: challenge.challenge_id,
            nonce: challenge.nonce,
        },
        account_id: challenge.account_id,
        requesting_device_id: challenge.requesting_device_id,
        backup_id: challenge.backup_id,
        backup_kind: BackupKind::SecretStorage,
        series_id: challenge.series_id,
        ciphertext_digest: challenge.ciphertext_digest,
        challenge: challenge.challenge,
        service_id: challenge.service_id,
        audience: challenge.audience,
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        auth_data: KeyBackupUnlockProofAuthData {
            verification_method: DidUrl::new(verification_method)
                .map_err(|error| anyhow!(error))?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new("AA").map_err(|error| anyhow!(error))?,
        },
    };
    let signature = signing_key.sign(&proof.signing_payload_bytes()?);
    proof.auth_data.signature = Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
        .map_err(|error| anyhow!(error))?;
    Ok(proof)
}

fn ts(value: &str) -> Result<DateTime<Utc>> {
    arkret_canonical::parse_timestamp_canonical(value)
        .with_context(|| format!("invalid timestamp {value}"))
}

fn did(value: &str) -> Result<DidCoreId> {
    Ok(project_did_to_core_id(&Did::new(value.to_owned())?)?)
}

fn device_id(value: &str) -> Result<DeviceId> {
    Ok(DeviceId::new(value.to_owned())?)
}

fn backup_id(value: &str) -> Result<BackupId> {
    Ok(BackupId::new(value.to_owned())?)
}

fn backup_series_id(value: &str) -> Result<BackupSeriesId> {
    Ok(BackupSeriesId::new(value.to_owned())?)
}
