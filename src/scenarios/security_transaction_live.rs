use anyhow::Result;
use arkret_models_crypto::{
    BackupKind, BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
    KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData, KeyBackupDomainSeparation,
    KeyBackupEncryption, KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm,
    PreparedEventBatchRequest, PreparedEventUnit, SecretStorageContentIndex, SecretStorageItemKind,
    SecurityRotationTransactionCreateRequest, SecurityTransactionCreateRequest,
};
use arkret_wire::{
    AccountId, ActorId, BackupId, BackupSeriesId, Base64UrlString, DeviceId, Did, DidCoreId,
    DidUrl, Event, EventId, Hash, ScopeRef,
};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestServerGroup, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

const DEVICE: &str = "ak:device:01975510-0000-7000-8000-0000000000b1";
const TRANSACTION: &str = "ak:transaction:01975510-0000-7000-8000-0000000000b2";

pub async fn security_transaction_create_is_durable_on_live_soland() -> Result<()> {
    let group = TestServerGroup::single("security-transaction-live-create").await?;
    let server = group.server(0);
    let actor = actor_did_for_service_did(server.service_did(), "security-transaction")?;
    let client = server.demo_client(&actor, DEVICE).await?;
    let pcr_realm = client
        .principal
        .as_ref()
        .map(|principal| principal.pcr_realm_id.as_str().to_owned())
        .ok_or_else(|| anyhow::anyhow!("client carries its provisioned principal"))?;
    let signing_seed = client
        .principal
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("client has no provisioned principal"))?
        .device_signing_key
        .to_bytes();
    let request = rotation_create_request(
        &actor,
        server.service_id().as_str(),
        &pcr_realm,
        &client.device_id,
        signing_seed,
        &client
            .principal
            .as_ref()
            .unwrap()
            .founding_authorize_event_id,
    )?;

    let first = expect_json(
        client
            .post("/_arkret/self/security-transactions")
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    let exact = expect_json(
        client
            .post("/_arkret/self/security-transactions")
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        first, exact,
        "exact create replay changed the first outcome"
    );
    assert_eq!(first["transaction_id"], TRANSACTION);

    let mut conflicting = request.clone();
    let SecurityTransactionCreateRequest::SecurityRotation(rotation) = &mut conflicting else {
        unreachable!("rotation request")
    };
    rotation.expires_at += chrono::Duration::seconds(1);
    let error = expect_api_error(
        client
            .post("/_arkret/self/security-transactions")
            .json(&conflicting),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;
    assert_eq!(error.code(), "duplicate_conflict");

    let fetched = expect_json(
        client.get(&format!(
            "/_arkret/self/security-transactions/{TRANSACTION}"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        fetched, first,
        "authoritative GET changed the accepted create outcome"
    );
    Ok(())
}

fn rotation_create_request(
    actor: &str,
    station_id: &str,
    pcr_realm: &str,
    device_id: &str,
    signing_seed: [u8; 32],
    device_authorize_event_id: &EventId,
) -> Result<SecurityTransactionCreateRequest> {
    let principal = Did::new(actor.to_owned())?;
    let principal_id = arkret_wire::project_did_to_core_id(&principal)?;
    let transaction_id = arkret_wire::TransactionId::new(TRANSACTION.to_owned())?;
    let revoke_submission = event_submission(
        &principal,
        station_id,
        pcr_realm,
        "ak.device.revoke",
        signing_seed,
        device_id,
    )?;
    let revoke_unit = event_unit(revoke_submission)?;
    let rotations = [(BackupRotationKind::SecretStorage, "c")]
        .into_iter()
        .map(|(kind, suffix)| {
            rotation_plan(
                &principal,
                station_id,
                pcr_realm,
                kind,
                suffix,
                signing_seed,
                device_id,
                device_authorize_event_id,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SecurityTransactionCreateRequest::SecurityRotation(
        SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            transaction_id,
            arkret_wire::AccountId::new(principal_id, DidCoreId::new(station_id.to_owned())?),
            arkret_wire::DeviceId::new(device_id.to_owned())?,
            Utc::now() + chrono::Duration::hours(1),
            revoke_unit,
            hash('e')?,
            rotations,
        )?,
    ))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Rotation fixture binds all atomic key and identity inputs"
)]
fn rotation_plan(
    principal: &Did,
    station_id: &str,
    pcr_realm: &str,
    kind: BackupRotationKind,
    suffix: &str,
    signing_seed: [u8; 32],
    device_id: &str,
    device_authorize_event_id: &EventId,
) -> Result<BackupRotationPlan> {
    let active_series_submission = event_submission(
        principal,
        station_id,
        pcr_realm,
        "ak.key_backup.active_series",
        signing_seed,
        device_id,
    )?;
    let active_series_event_id = active_series_submission.event_id.clone();
    let mut binding = BackupRotationBinding {
        backup_kind: kind,
        previous_series_id: BackupSeriesId::new(format!(
            "ak:backup_series:01975510-0000-7000-8000-0000000000{suffix}1"
        ))?,
        new_series_id: BackupSeriesId::new(format!(
            "ak:backup_series:01975510-0000-7000-8000-0000000000{suffix}2"
        ))?,
        new_backups: vec![BackupObjectRef {
            backup_id: BackupId::new(format!(
                "ak:backup:01975510-0000-7000-8000-0000000000{suffix}3"
            ))?,
            ciphertext_digest: hash('7')?,
        }],
        active_series_event_id,
        old_backups: vec![BackupObjectRef {
            backup_id: BackupId::new(format!(
                "ak:backup:01975510-0000-7000-8000-0000000000{suffix}5"
            ))?,
            ciphertext_digest: hash('9')?,
        }],
    };
    let ciphertext = b"rotation-create-backup";
    let principal_id = arkret_wire::project_did_to_core_id(principal)?;
    let device_id = DeviceId::new(device_id.to_owned())?;
    let mut envelope = KeyBackup {
        backup_id: binding.new_backups[0].backup_id.clone(),
        actor_id: ActorId::account(AccountId::new(
            principal_id,
            DidCoreId::new(station_id.to_owned())?,
        )),
        device_id: Some(device_id.clone()),
        backup_kind: BackupKind::SecretStorage,
        mixed_secret_storage: false,
        backup_version: "kb_1".to_owned(),
        created_at: arkret::canonical::normalize_timestamp_canonical(Utc::now()),
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
                nonce: Some(Base64UrlString::new("nonce").map_err(anyhow::Error::msg)?),
                enc: None,
                extra: Default::default(),
            },
            key_commitment: None,
            hpke_suite: None,
            extra: Default::default(),
        },
        domain_separation: KeyBackupDomainSeparation {
            subdomain: "rotation".to_owned(),
            aead_aad_extensions: Default::default(),
        },
        contents: vec![SecretStorageContentIndex {
            item_kind: SecretStorageItemKind::MlsGroupSecretsBackupKey,
            secret_id: "mls_group_secrets_backup_key".to_owned(),
        }],
        ciphertext: Base64UrlString::new(arkret_canonical::base64url_encode(ciphertext))
            .map_err(anyhow::Error::msg)?,
        ciphertext_digest: Hash::new(arkret_canonical::sha256_digest(ciphertext))?,
        plaintext_commitment: None,
        auth_data: KeyBackupAuthData {
            device_id: device_id.clone(),
            verification_method: DidUrl::new(format!("{principal}#{device_id}"))
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
            device_authorize_event_id: device_authorize_event_id.clone(),
        },
        retention: None,
        series_id: binding.new_series_id.clone(),
        series_seq: 0,
        supersedes_id: None,
        supersedes_digest: None,
        source_commit_ref: None,
        recovery_policy_ref: None,
        extra: Default::default(),
    };
    let signature = SigningKey::from_bytes(&signing_seed).sign(&envelope.signing_payload_bytes()?);
    envelope.auth_data.signature =
        Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
            .map_err(anyhow::Error::msg)?;
    binding.new_backups[0].ciphertext_digest = envelope.ciphertext_digest.clone();
    Ok(BackupRotationPlan {
        binding,
        new_backup_envelopes: vec![envelope],
        active_series_unit: event_unit(active_series_submission)?,
    })
}

fn event_unit(event: Event) -> Result<PreparedEventUnit> {
    Ok(PreparedEventUnit::new(
        arkret_canonical::DigestSuite::Sha256,
        PreparedEventBatchRequest {
            events: vec![event],
        },
    )?)
}

fn event_submission(
    principal: &Did,
    station_id: &str,
    pcr_realm: &str,
    kind: &str,
    signing_seed: [u8; 32],
    device_id: &str,
) -> Result<Event> {
    let realm_id = arkret_wire::RealmId::new(pcr_realm.to_owned())?;
    let now = Utc::now();
    let event = arkret_wire::test_support::raw_event_at(
        kind,
        ScopeRef::Realm { realm_id },
        arkret_identifiers::project_did_to_core_id(principal)?,
        DidCoreId::new(station_id.to_owned())?,
        json!({"fixture": true}),
        now,
    )?;
    let verification_method = crate::fixture_did_url(format!("{principal}#{device_id}"));
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        signing_seed,
        principal.clone(),
        verification_method,
    );
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )?;
    Ok(event.into_event())
}
fn hash(byte: char) -> Result<Hash> {
    Ok(Hash::new(format!(
        "sha256:{}",
        byte.to_string().repeat(64)
    ))?)
}
