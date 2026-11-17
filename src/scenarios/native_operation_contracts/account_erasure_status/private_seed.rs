//! Real holder-signed encrypted private state; no direct authority writes.

use arkret_crypto::backup::{
    KeyBackupAuthorizationBinding, build_key_backup_envelope, derive_vault_kek,
};
use arkret_models_collaboration::events_payloads::account_data::{
    AccountDataBody, AccountDataSetPayload,
};
use arkret_models_crypto::{
    BackupKind, KeyBackupSignatureAlgorithm, SecretStorageItemKind, SecretStorageSecret,
};
use ed25519_dalek::Signer as _;

use super::*;

fn entropy() -> Result<[u8; 32]> {
    let mut value = [0u8; 32];
    getrandom::fill(&mut value).context("obtain native erasure private entropy")?;
    Ok(value)
}

pub(super) async fn seed(source: &Deployment) -> Result<Value> {
    let principal = source
        .controller
        .principal
        .as_ref()
        .context("actual founding Device")?;
    let route =
        super::super::actor_private::exercise(&source.station, &source.controller, &source.account)
            .await?;
    let secret = zeroize::Zeroizing::new(entropy()?);
    let passphrase =
        zeroize::Zeroizing::new(arkret_crypto::backup::format_backup_passphrase(&entropy()?));
    let kek = derive_vault_kek(passphrase.as_bytes())?;
    let method = arkret_wire::DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let envelope = build_key_backup_envelope(
        arkret_identifiers::new_prefixed_uuid7("ak:backup:").parse()?,
        arkret_wire::ActorId::account(source.account.clone()),
        Some(principal.device_id.clone()),
        BackupKind::SecretStorage,
        "kb_1",
        "mls_group_secrets",
        &kek,
        vec![SecretStorageSecret {
            item_kind: SecretStorageItemKind::MlsGroupSecretsBackupKey,
            secret_id: "mls_group_secrets_backup_key".into(),
            secret_base64url: arkret_wire::Base64UrlString::new(
                arkret_canonical::base64url_encode(secret.as_ref()),
            )
            .map_err(anyhow::Error::msg)?,
            secret_generation: None,
            extra: Default::default(),
        }],
        &KeyBackupAuthorizationBinding {
            device_id: principal.device_id.clone(),
            verification_method: method,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            device_authorize_event_id: principal.founding_authorize_event_id.clone(),
        },
        &|bytes| Ok(principal.device_signing_key.sign(bytes).to_bytes().to_vec()),
    )?;
    envelope.validate()?;
    let accepted = expect_json(
        source
            .controller
            .put(&format!(
                "/_arkret/self/keys/backups/{}",
                envelope.backup_id
            ))
            .header(
                "Idempotency-Key",
                arkret_identifiers::new_prefixed_uuid7("ak:request:"),
            )
            .json(&envelope),
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        accepted["status"] == "accepted",
        "native erasure backup was not accepted"
    );
    let actor = arkret_wire::ActorId::account(source.account.clone());
    let key = arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST;
    let encrypted = arkret_crypto::account_data_crypto::seal_account_data_value(
        &entropy()?,
        &actor,
        key,
        &json!({"entries":[]}),
    )?;
    let payload = AccountDataSetPayload {
        key: arkret_wire::NonEmptyString::new(key).map_err(anyhow::Error::msg)?,
        expected_server_revision: 0,
        body: AccountDataBody::Value(serde_json::to_value(encrypted)?),
        encrypted_payload: None,
        tombstone: false,
        updated_at: None,
        source_pending_event_id: None,
    };
    payload.validate()?;
    let event = source
        .controller
        .author_event(
            principal.pcr_realm_id.as_str(),
            arkret_wire::EventKind::AccountDataSet.as_str(),
            json!(payload),
        )
        .await?;
    let request = arkret_models_identity::AccountDataReplaceRequestBody {
        set_event: arkret_wire::EventAdmissionSubmission::new(event.clone()),
    };
    let data = expect_json(
        source
            .controller
            .put(&format!("/_arkret/self/account-data/{key}"))
            .json(&request),
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        data["revision"] == 1,
        "native private cell did not commit its first CAS"
    );
    Ok(
        json!({"backup":envelope,"backup_acceptance":accepted,"private_route":route,"private_data_event":event,"private_data":data,
        "gateway_boundary":{"active_targets":[],"claim":"revoked route private-copy erasure only; no active Gateway stop-delivery claim"}}),
    )
}
