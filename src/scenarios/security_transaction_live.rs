use anyhow::Result;
use arkret_models_crypto::{
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
    PreparedEventBatchRequest, PreparedEventUnit, SecurityRotationTransactionCreateRequest,
    SecurityTransactionCreateRequest,
};
use arkret_wire::{
    BackupId, BackupSeriesId, CanonicalPublicMaterial, Did, DidCoreId, Event, Hash, ScopeRef,
};
use chrono::Utc;
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

fn rotation_plan(
    principal: &Did,
    station_id: &str,
    pcr_realm: &str,
    kind: BackupRotationKind,
    suffix: &str,
    signing_seed: [u8; 32],
    device_id: &str,
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
    let binding = BackupRotationBinding {
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
    let backup_kind = "secret_storage";
    let principal_id = arkret_wire::project_did_to_core_id(principal)?;
    let material = CanonicalPublicMaterial::canonical_json(json!({
        "backups": [{
            "actor_id": principal_id,
            "backup_id": binding.new_backups[0].backup_id,
            "backup_kind": backup_kind,
            "ciphertext_digest": binding.new_backups[0].ciphertext_digest,
            "series_id": binding.new_series_id,
        }]
    }))?;
    Ok(BackupRotationPlan {
        active_series_unit: event_unit(active_series_submission)?,
        encrypted_backup_material: material,
        binding,
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
