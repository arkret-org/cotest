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
    BackupId, BackupSeriesId, DeviceId, Did, EventId, Hash, RecoverySessionId,
};
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupContentItem,
    KeyBackupDomainSeparation, KeyBackupDomainSeparationAad, KeyBackupEncryption,
    KeyBackupRecipientMethod, KeyBackupRetention, KeyBackupSignatureAlgorithm,
    KeyBackupUnlockProof, KeysBackupsUnlockRequestBody, ProofKind, UnsignedKeyBackup,
    UnsignedKeyBackupAuthData, UnsignedKeyBackupUnlockProof, UnsignedKeyBackupUnlockProofAuthData,
};
use arkret_wire::{Base64UrlString, DidUrl};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;

use crate::harness::{ArkretServer, expect_json, wire_negative_from_sdk};

pub const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-000000000000";

/// Must match the device id minted by `dev_login` in
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
    principal_signing_unlock_reaches_trust_anchor(server, token, actor_id).await?;
    Ok(())
}

async fn put_backup(server: &ArkretServer, token: &str, actor_id: &str) -> Result<()> {
    let backup_put = expect_json(
        server
            .http()
            .put(server.url(&format!("/_arkret/self/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-payloads-key-backup-put")
            .json(&signed_backup_envelope(actor_id)?),
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
fn signed_backup_envelope(actor_id: &str) -> Result<KeyBackup> {
    let signing_key = device_signing_key();
    let multibase = ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    let verification_method = format!("did:key:{multibase}#{multibase}");
    let created_at = ts("2026-04-26T00:00:00.000Z")?;
    let envelope = KeyBackup {
        backup_id: backup_id(BACKUP_ID)?,
        actor_id: did(actor_id)?,
        device_id: Some(device_id(ENVELOPE_DEVICE_ID)?),
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
                nonce: Some(Base64UrlString::new("nonce").map_err(|error| anyhow!(error))?),
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
                actor_id: did(actor_id)?,
                device_id: Some(ENVELOPE_DEVICE_ID.to_owned()),
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
            mls_group_id: Some("group_default".to_owned()),
            epoch: Some(0),
            first_event_id: None,
            last_event_id: None,
            secret_id: None,
            secret_version: None,
            extra: Default::default(),
        }],
        ciphertext: "Y2lwaGVydGV4dA".to_owned(),
        ciphertext_digest: CIPHERTEXT_DIGEST.to_owned(),
        plaintext_commitment: None,
        auth_data: None,
        retention: Some(KeyBackupRetention {
            delete_after: Some(ts("2020-01-01T00:00:00.000Z")?),
            legal_hold: Some(false),
            extra: BTreeMap::new(),
        }),
        series_id: backup_series_id(SERIES_ID)?,
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref: None,
        recovery_policy_ref: None,
        extra: Default::default(),
    };
    let auth_data = UnsignedKeyBackupAuthData::new(
        device_id(ENVELOPE_DEVICE_ID)?,
        DidUrl::new(verification_method).map_err(|error| anyhow!(error))?,
        KeyBackupSignatureAlgorithm::Ed25519,
        EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")?,
    )?;
    let unsigned = UnsignedKeyBackup::new(envelope, auth_data)?;
    let signature = signing_key.sign(&unsigned.signing_payload_bytes()?);
    unsigned
        .attach_signature(
            Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
                .map_err(|error| anyhow!(error))?,
        )
        .map_err(anyhow::Error::from)
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
    let operations = description["supported_operations"]
        .as_array()
        .expect("supported operation list");
    for operation_id in [
        "ak.self.keys.backups.resource.replace",
        "ak.self.keys.backups.read.list",
        "ak.self.keys.backups.command.unlock",
        "ak.self.keys.backups.resource.delete",
    ] {
        assert!(
            operations
                .iter()
                .any(|operation| operation.as_str() == Some(operation_id)),
            "describe did not advertise {operation_id}: {description}"
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
        proof: unlock_proof(actor_id)?,
    };
    let body = expect_json(
        server
            .http()
            .post(server.url(&format!("/_arkret/self/keys/backups/{BACKUP_ID}/unlock")))
            .bearer_auth(token)
            .json(&wire_negative_from_sdk(&baseline, |value| {
                value
                    .as_object_mut()
                    .expect("SDK body is an object")
                    .remove("proof");
            })?),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    assert_eq!(body["error"]["code"], "schema_violation");
    Ok(())
}

async fn principal_signing_unlock_reaches_trust_anchor(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    let unlock = expect_json(
        server
            .http()
            .post(server.url(&format!("/_arkret/self/keys/backups/{BACKUP_ID}/unlock")))
            .bearer_auth(token)
            .json(&KeysBackupsUnlockRequestBody {
                proof: unlock_proof(actor_id)?,
            }),
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    assert_eq!(unlock["error"]["code"], "untrusted_backup_signature");
    Ok(())
}

/// Build a `ak.schema.key_backup_unlock_proof.v1` body value: a canonical
/// JSON transcript bound to the stored envelope, signed by an Ed25519 device
/// key whose `verification_method` resolves via `did:key`.
///
/// No durable recovery-session record exists for this synthetic session id.
/// `principal_signing` is the compatibility proof kind that may still reach
/// the trust-anchor check without a bound recovery ceremony.
fn unlock_proof(actor_id: &str) -> Result<KeyBackupUnlockProof> {
    let signing_key = device_signing_key();
    let multibase = ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    let verification_method = format!("did:key:{multibase}#{multibase}");
    let auth_data = UnsignedKeyBackupUnlockProofAuthData::new(
        DidUrl::new(verification_method).map_err(|error| anyhow!(error))?,
        KeyBackupSignatureAlgorithm::Ed25519,
    )?;
    let unsigned = UnsignedKeyBackupUnlockProof::new(
        RecoverySessionId::new("ak:recovery_session:01964137-0000-7000-8000-0000000000aa")?,
        did(actor_id)?,
        DeviceId::new(DEVICE_ID.to_owned())?,
        backup_id(BACKUP_ID)?,
        BackupKind::MlsHistory,
        backup_series_id(SERIES_ID)?,
        Hash::new(CIPHERTEXT_DIGEST)?,
        ProofKind::PrincipalSigning,
        Hash::new("sha256:84a51084210842108421084210842108421084210842108421084210842108aa")?,
        None,
        ts("2026-04-26T00:00:00.000Z")?,
        auth_data,
    )?;
    let signature = signing_key.sign(&unsigned.signing_payload_bytes()?);
    unsigned
        .attach_signature(
            Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
                .map_err(|error| anyhow!(error))?,
        )
        .map_err(anyhow::Error::from)
}

fn ts(value: &str) -> Result<DateTime<Utc>> {
    arkret_canonical::parse_timestamp_canonical(value)
        .with_context(|| format!("invalid timestamp {value}"))
}

fn did(value: &str) -> Result<Did> {
    Ok(Did::new(value.to_owned())?)
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
