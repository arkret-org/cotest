use anyhow::Result;
use arkret_wire::{
    BackupId, BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
    BackupSeriesId, CanonicalPublicMaterial, Did, Event, EventId, EventInitialSubmission,
    EventsSubmitBatchRequestBody, Hash, Hlc, ReceiptId, RecoverySessionId,
    RecoveryTransactionCreateRequest, RiskTier, ScopeRef, SealId,
    SecurityRotationTransactionCreateRequest, SecurityTransactionCreateRequest,
};
use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_api_error, expect_json};

const ACTOR: &str = "did:web:security-transaction-live.example";
const DEVICE: &str = "ak:device:01975510-0000-7000-8000-0000000000b1";
const TRANSACTION: &str = "ak:transaction:01975510-0000-7000-8000-0000000000b2";
const RECOVERY_TRANSACTION: &str = "ak:transaction:01975510-0000-7000-8000-0000000000f2";

pub async fn security_transaction_create_is_durable_on_live_soland() -> Result<()> {
    let group = TestServerGroup::single("security-transaction-live-create").await?;
    let server = group.server(0);
    let client = server.demo_client(ACTOR, DEVICE).await?;
    let request = rotation_create_request(server.service_id())?;

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
    assert_eq!(first["state"], "pending");

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
    assert_eq!(error["error"]["code"], "duplicate_conflict");

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

pub async fn recovery_transaction_rejects_unknown_session_on_live_soland() -> Result<()> {
    let group = TestServerGroup::single("recovery-transaction-live-create").await?;
    let server = group.server(0);
    let client = server.demo_client(ACTOR, DEVICE).await?;
    let request = cross_signing_recovery_create_request(server.service_id())?;

    let first = expect_api_error(
        client
            .post("/_arkret/self/security-transactions")
            .json(&request),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    let exact = expect_api_error(
        client
            .post("/_arkret/self/security-transactions")
            .json(&request),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    assert_eq!(first["error"], exact["error"]);
    assert!(
        first["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("recovery_session_id"))
    );
    expect_api_error(
        client.get(&format!(
            "/_arkret/self/security-transactions/{RECOVERY_TRANSACTION}"
        )),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    Ok(())
}

fn cross_signing_recovery_create_request(
    service_id: &str,
) -> Result<SecurityTransactionCreateRequest> {
    cross_signing_recovery_create_request_for(
        service_id,
        ACTOR,
        DEVICE,
        "ak:recovery_session:01975510-0000-7000-8000-0000000000f7",
        hash('2')?,
        1,
    )
}

pub fn cross_signing_recovery_create_request_for(
    service_id: &str,
    principal_id: &str,
    device_id: &str,
    recovery_session_id: &str,
    proof_digest: Hash,
    generation: u64,
) -> Result<SecurityTransactionCreateRequest> {
    let coordinator = Did::new(service_id.to_owned())?;
    let principal = Did::new(principal_id.to_owned())?;
    let authorize_event_id =
        EventId::new("ak:event:01975510-0000-8000-8000-0000000000f3".to_owned())?;
    let list_event_id = EventId::new("ak:event:01975510-0000-8000-8000-0000000000f4".to_owned())?;
    let request = EventsSubmitBatchRequestBody {
        events: vec![
            event_submission(&principal, authorize_event_id, "ak.device.authorize", "f5")?,
            event_submission(&principal, list_event_id, "ak.device.list_update", "f6")?,
        ],
    };
    Ok(SecurityTransactionCreateRequest::Recovery(
        RecoveryTransactionCreateRequest::from_cross_signing_prepared(
            arkret_wire::TransactionId::new(RECOVERY_TRANSACTION.to_owned())?,
            principal,
            Utc::now() + chrono::Duration::hours(1),
            RecoverySessionId::new(recovery_session_id.to_owned())?,
            arkret_wire::DeviceId::new(device_id.to_owned())?,
            ReceiptId::new("ak:receipt:01975510-0000-7000-8000-0000000000f8".to_owned())?,
            hash('1')?,
            proof_digest,
            generation,
            generation,
            arkret_wire::security_transaction::PreparedEventSubmissionBatch::new(
                coordinator,
                request,
            )?,
        )?,
    ))
}

fn rotation_create_request(service_id: &str) -> Result<SecurityTransactionCreateRequest> {
    let coordinator = Did::new(service_id.to_owned())?;
    let principal = Did::new(ACTOR.to_owned())?;
    let transaction_id = arkret_wire::TransactionId::new(TRANSACTION.to_owned())?;
    let revoke_event_id = EventId::new("ak:event:01975510-0000-8000-8000-0000000000b3".to_owned())?;
    let rotations = [
        (BackupRotationKind::SecretStorage, "c"),
        (BackupRotationKind::MlsHistory, "d"),
    ]
    .into_iter()
    .map(|(kind, suffix)| rotation_plan(&coordinator, &principal, kind, suffix))
    .collect::<Result<Vec<_>>>()?;
    Ok(SecurityTransactionCreateRequest::SecurityRotation(
        SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            transaction_id,
            principal.clone(),
            Utc::now() + chrono::Duration::hours(1),
            revoke_event_id.clone(),
            event_unit(
                &coordinator,
                &principal,
                revoke_event_id,
                "ak.device.revoke",
            )?,
            hash('e')?,
            rotations,
        )?,
    ))
}

fn rotation_plan(
    coordinator: &Did,
    principal: &Did,
    kind: BackupRotationKind,
    suffix: &str,
) -> Result<BackupRotationPlan> {
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
        active_series_event_id: EventId::new(format!(
            "ak:event:01975510-0000-8000-8000-0000000000{suffix}4"
        ))?,
        old_backups: vec![BackupObjectRef {
            backup_id: BackupId::new(format!(
                "ak:backup:01975510-0000-7000-8000-0000000000{suffix}5"
            ))?,
            ciphertext_digest: hash('9')?,
        }],
    };
    let backup_kind = match kind {
        BackupRotationKind::SecretStorage => "secret_storage",
        BackupRotationKind::MlsHistory => "mls_history",
    };
    let material = CanonicalPublicMaterial::canonical_json(Value::Array(vec![json!({
        "actor_id": principal,
        "backup_id": binding.new_backups[0].backup_id,
        "backup_kind": backup_kind,
        "ciphertext_digest": binding.new_backups[0].ciphertext_digest,
        "series_id": binding.new_series_id,
    })]))?;
    Ok(BackupRotationPlan {
        active_series_unit: event_unit(
            coordinator,
            principal,
            binding.active_series_event_id.clone(),
            "ak.key_backup.active_series",
        )?,
        encrypted_backup_material: material,
        binding,
    })
}

fn event_unit(
    coordinator: &Did,
    principal: &Did,
    event_id: EventId,
    kind: &str,
) -> Result<arkret_wire::PreparedEventUnit> {
    let request = EventsSubmitBatchRequestBody {
        events: vec![event_submission(principal, event_id, kind, "e1")?],
    };
    Ok(arkret_wire::PreparedEventUnit::new(
        coordinator.clone(),
        serde_json::to_value(request)?,
    )?)
}

fn event_submission(
    principal: &Did,
    event_id: EventId,
    kind: &str,
    _lease_suffix: &str,
) -> Result<EventInitialSubmission> {
    let realm_id = arkret_wire::RealmId::new(
        arkret_models_identity::did_document::principal_control_realm_id(principal),
    )?;
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let now = Utc::now();
    let mut event = Event::new_with_id_at(
        event_id,
        kind,
        scope_ref.clone(),
        principal.clone(),
        1,
        Hlc::new("01970e589d21-0004-c07e57aa".to_owned())?,
        json!({"fixture": true}),
        now,
    )?;
    event.seal_basis = Some(arkret_wire::SealBasis {
        leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64)))?],
    });
    let event_digest = Hash::new(event.event_digest()?)?;
    event.proofs.push(arkret_wire::Proof {
        kind: "DataIntegrityProof".to_owned(),
        // `zh/identity/did-usage-and-verification.md` §2.2: a
        // `verification_method` is a DID URL, never a bare DID. This fixture
        // used `principal` itself, which no receiver could resolve to a key.
        verification_method: crate::fixture_did_url(format!("{principal}#cotest")),
        event_digest,
        created_at: now,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZDI1NTE5In0..c2lnbmF0dXJl".to_owned(),
    });
    let authorization_lease =
        crate::publication::authorization_lease_for(&event, "ak.realm.admin", RiskTier::High)?;
    let mut submission = crate::publication::initial_submission(event, "ak.realm.admin")?;
    submission.authorization_lease = Some(authorization_lease);
    Ok(submission)
}

fn hash(byte: char) -> Result<Hash> {
    Ok(Hash::new(format!(
        "sha256:{}",
        byte.to_string().repeat(64)
    ))?)
}
