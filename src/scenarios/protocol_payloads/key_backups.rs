//! Phase 3 — key-backup surfaces: PUT / list / describe / unlock.
//!
//! Stores Alice's MLS-history backup, enumerates the collection, walks the
//! key-backup descriptor, and exercises the unlock-proof gate.
//!
//! Surface split (G3 namespace audit):
//! - `PUT/DELETE /_cokret/self/keys/backups/*`, `GET /_cokret/self/keys/backups`, and `POST
//!   /_cokret/self/keys/backups/{id}/unlock` — protocol face.
//! - `GET /_soland/self/keys/backups/describe` — the describe contract is a deployment/product
//!   surface and is only mounted on the `/_soland` face
//!   (`soland/src/routing/identity/key_backup.rs::legacy_router`).
//!
//! Full-ciphertext reads are gated by spec `identity/key-management.md`
//! §7.7.1: every `POST /_cokret/self/keys/backups/{id}/unlock` MUST carry a
//! body `{proof: ck.schema.key_backup_unlock_proof.v1}` bound to the envelope;
//! a bearer token without that body proof MUST be refused.

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_core::canonical::canonical_json_bytes;
use cokret_core::multibase::ed25519_pubkey_to_did_key_multibase;
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_json};

pub const BACKUP_ID: &str = "ck:backup:01964137-0000-7000-8000-000000000000";

const ACTOR_ID: &str = "did:web:alice.example";
/// Must match the device id minted by `dev_login` in
/// [`super::events_keys_device_blob_push_and_moderation_surfaces_work`]: the
/// unlock proof binds `requesting_device_id` to the authenticated session
/// device.
const DEVICE_ID: &str = "ck:device:01904100-0000-7000-8000-0000000000a1";
const SERIES_ID: &str = "ck:backup_series:01964137-0000-7000-8000-000000000000";
/// Typed device id carried inside the envelope (`auth_data.device_id` must be
/// a `ck:device:` typed id; it is not required to equal the session device).
const ENVELOPE_DEVICE_ID: &str = "ck:device:01964137-0000-7000-8000-000000000000";
const CIPHERTEXT_DIGEST: &str =
    "sha256:2108421084217842908421084210842121084210842178429084210842108421";

/// Deterministic Ed25519 device key shared by the envelope `auth_data`
/// signature and the unlock-proof transcript signature.
fn device_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

pub async fn run(server: &CokretServer, token: &str) -> Result<()> {
    put_backup(server, token).await?;
    list_backups(server, token).await?;
    describe_backup_surfaces(server, token).await?;
    unlock_backup_requires_body_proof(server, token).await?;
    unlock_backup_reaches_trust_anchor(server, token).await?;
    Ok(())
}

async fn put_backup(server: &CokretServer, token: &str) -> Result<()> {
    let backup_put = expect_json(
        server
            .http()
            .put(server.url(&format!("/_cokret/self/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .json(&signed_backup_envelope()?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_put["status"], "accepted");
    assert_eq!(backup_put["backup_id"], BACKUP_ID);
    Ok(())
}

/// Build the `ck.schema.key_backup.v1` envelope including the §7.4.1
/// `auth_data` device-signature block (device key signs the canonical
/// envelope minus `auth_data.signature`; `ssk_generation` binds the
/// cross-signing generation).
fn signed_backup_envelope() -> Result<serde_json::Value> {
    let signing_key = device_signing_key();
    let multibase = ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    let verification_method = format!("did:key:{multibase}#{multibase}");
    let mut envelope = json!({
        "backup_id": BACKUP_ID,
        "actor_id": ACTOR_ID,
        "device_id": ENVELOPE_DEVICE_ID,
        "series_id": SERIES_ID,
        "series_seq": 0,
        "backup_class": "mls_history",
        "backup_version": "kb_1",
        "created_at": "2026-04-26T00:00:00Z",
        "encryption": {
            "recipient_method": "secret_storage_key",
            "recipient_key_ref": "mls_group_secrets_backup_key",
            "aead": {"name": "xchacha20_poly1305", "aead_profile": "ck.aead.xchacha20_poly1305.v1", "nonce": "nonce"}
        },
        "contents": [
            {
                "item_type": "mls_group_state",
                "mls_group_id": "group_default",
                "epoch": 0
            }
        ],
        "retention": {
            "delete_after": "2020-01-01T00:00:00Z",
            "legal_hold": false
        },
        "ciphertext": "ciphertext",
        "ciphertext_digest": CIPHERTEXT_DIGEST,
        "domain_separation": {
            "hkdf_info": "cokret-key-backup/mls_history/test/v1",
            "subdomain": "test",
            "aead_aad": {
                "schema": "ck.schema.key_backup.v1",
                "actor_id": ACTOR_ID,
                "device_id": ENVELOPE_DEVICE_ID,
                "backup_class": "mls_history",
                "backup_version": "kb_1",
                "created_at": "2026-04-26T00:00:00Z",
                "item_types": ["mls_group_state"]
            }
        },
        "auth_data": {
            "device_id": ENVELOPE_DEVICE_ID,
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "ssk_generation": 1,
            "signed_fields": [
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
                "ciphertext_digest"
            ]
        }
    });
    let canonical = canonical_json_bytes(&envelope)?;
    let signature = signing_key.sign(&canonical);
    envelope["auth_data"]["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    Ok(envelope)
}

async fn list_backups(server: &CokretServer, token: &str) -> Result<()> {
    let backup_list = expect_json(
        server
            .http()
            .get(server.url("/_cokret/self/keys/backups"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert!(!backup_list["backups"].as_array().unwrap().is_empty());
    Ok(())
}

async fn describe_backup_surfaces(server: &CokretServer, token: &str) -> Result<()> {
    // The key-backups describe contract is mounted on the `/_soland`
    // deployment face only; `/_cokret/self/keys/backups/describe` would be
    // swallowed by the `{backup_id}` GET route and 404.
    let key_backups_describe = expect_json(
        server
            .http()
            .get(server.url("/_soland/self/keys/backups/describe"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        key_backups_describe["contract"],
        "cokret.rest.key_backups_describe.v1"
    );
    assert_eq!(key_backups_describe["schema"], "ck.schema.key_backup.v1");
    assert_eq!(
        key_backups_describe["operations"][0],
        "ck.self.keys.backups.resource.replace"
    );
    Ok(())
}

/// Spec §7.7.1 / §7.8 — a bearer token alone MUST NOT release the full
/// ciphertext: unlock is refused without a body proof.
async fn unlock_backup_requires_body_proof(server: &CokretServer, token: &str) -> Result<()> {
    let body = expect_json(
        server
            .http()
            .post(server.url(&format!("/_cokret/self/keys/backups/{BACKUP_ID}/unlock")))
            .bearer_auth(token)
            .json(&json!({})),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    assert_eq!(body["error"]["code"], "bad_request");
    Ok(())
}

async fn unlock_backup_reaches_trust_anchor(server: &CokretServer, token: &str) -> Result<()> {
    let unlock = expect_json(
        server
            .http()
            .post(server.url(&format!("/_cokret/self/keys/backups/{BACKUP_ID}/unlock")))
            .bearer_auth(token)
            .json(&json!({ "proof": unlock_proof()? })),
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    assert_eq!(unlock["error"]["code"], "untrusted_backup_signature");
    Ok(())
}

/// Build a `ck.schema.key_backup_unlock_proof.v1` body value: a canonical
/// JSON transcript bound to the stored envelope, signed by an Ed25519 device
/// key whose `verification_method` resolves via `did:key`.
///
/// No durable recovery-session record exists for this synthetic session id,
/// so soland's session-binding check is skipped (device-signed decrypt proof
/// path); the shape, envelope binding, and signature are still verified.
fn unlock_proof() -> Result<serde_json::Value> {
    let signing_key = device_signing_key();
    let multibase = ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    let verification_method = format!("did:key:{multibase}#{multibase}");
    let mut proof = json!({
        "schema": "ck.schema.key_backup_unlock_proof.v1",
        "recovery_session_id": "ck:recovery_session:01964137-0000-7000-8000-0000000000aa",
        "principal_id": ACTOR_ID,
        "requesting_device_id": DEVICE_ID,
        "backup_id": BACKUP_ID,
        "backup_class": "mls_history",
        "series_id": SERIES_ID,
        "ciphertext_digest": CIPHERTEXT_DIGEST,
        "proof_kind": "recovery_unlock",
        "proof_digest": "sha256:84a51084210842108421084210842108421084210842108421084210842108aa",
        "issued_at": "2026-04-26T00:00:00Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signed_fields": [
                "schema",
                "recovery_session_id",
                "principal_id",
                "requesting_device_id",
                "backup_id",
                "backup_class",
                "series_id",
                "ciphertext_digest",
                "proof_kind",
                "proof_digest",
                "issued_at"
            ]
        }
    });
    // soland verifies the signature over canonical JSON of the proof with
    // `auth_data.signature` removed — sign first, then attach.
    let canonical = canonical_json_bytes(&proof)?;
    let signature = signing_key.sign(&canonical);
    proof["auth_data"]["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    Ok(proof)
}
