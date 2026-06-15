use anyhow::{Result, anyhow, bail};
use cokret_core::multibase::ed25519_pubkey_to_did_key_multibase;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

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
            .json(&did_recovery_backup_body(&principal_id, POLICY_ID)),
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
            )),
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

fn unsigned_recovery_policy(principal_id: &str, verification_method: &str) -> Value {
    json!({
        "schema": "ck.schema.recovery_policy.v1",
        "policy_id": POLICY_ID,
        "principal_id": principal_id,
        "version": 1,
        "trust_domain": "ck:trust_domain:soland.local",
        "allowed_proof_kinds": ["principal_signing"],
        "supersedes": null,
        "issued_at": "2026-05-30T00:00:00Z",
        "expires_at": "2026-06-30T00:00:00Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "EdDSA",
            "signed_fields": [
                "schema",
                "policy_id",
                "principal_id",
                "version",
                "trust_domain",
                "allowed_proof_kinds",
                "supersedes",
                "issued_at",
                "expires_at"
            ],
            "signature": "c2lnbmF0dXJl"
        }
    })
}

fn did_recovery_backup_body(principal_id: &str, policy_id: &str) -> Value {
    json!({
        "backup_id": DID_RECOVERY_BACKUP_ID,
        "actor_id": principal_id,
        "device_id": DEVICE_A,
        "series_id": "ck:backup_series:01975510-0000-7000-8000-0000000000a2",
        "series_seq": 0,
        "backup_class": "did_recovery",
        "backup_version": "kb_1",
        "created_at": "2026-05-30T00:00:00Z",
        "recovery_policy_ref": { "policy_id": policy_id, "policy_version": 1 },
        "encryption": {
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": "did:key:z6MkrecoveryKey#z6MkrecoveryKey",
            "aead": {
                "name": "hpke_base_x25519_hkdf_sha256_chacha20poly1305",
                "aead_profile": "ck.hpke.x25519_hkdf_sha256_chacha20_poly1305.v1",
                "enc": "Y290ZXN0LWVuYw"
            }
        },
        "domain_separation": {
            "hkdf_info": "cokret-key-backup/did_recovery/recovery_policy/v1",
            "subdomain": "recovery_policy",
            "aead_aad": {
                "schema": "ck.schema.key_backup.v1",
                "actor_id": principal_id,
                "device_id": DEVICE_A,
                "backup_class": "did_recovery",
                "backup_version": "kb_1",
                "created_at": "2026-05-30T00:00:00Z",
                "item_types": ["recovery_secret"]
            }
        },
        "contents": [
            {
                "item_type": "recovery_secret"
            }
        ],
        "ciphertext": "cotest-did-recovery-ciphertext",
        "ciphertext_digest": "sha256:2108421084217842908421084210842121084210842178429084210842108421",
        "auth_data": {
            "device_id": DEVICE_A,
            "verification_method": "did:key:z6Mkdevice#z6Mkdevice",
            "signature_algorithm": "Ed25519",
            "ssk_generation": 1,
            "signed_fields": [
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
                "recovery_policy_ref"
            ],
            "signature": "c2lnbmF0dXJl"
        }
    })
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
