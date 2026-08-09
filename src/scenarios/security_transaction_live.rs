use anyhow::Result;
use arkret_wire::{
    BackupId, BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
    BackupSeriesId, CanonicalPublicMaterial, Did, Event, EventInitialSubmission,
    EventsSubmitBatchRequestBody, Hash, Hlc, RiskTier, ScopeRef, SealId,
    SecurityRotationTransactionCreateRequest, SecurityTransactionCreateRequest,
};
use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_api_error, expect_json};

const ACTOR: &str = "did:web:security-transaction-live.example";
const DEVICE: &str = "ak:device:01975510-0000-7000-8000-0000000000b1";
const TRANSACTION: &str = "ak:transaction:01975510-0000-7000-8000-0000000000b2";

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

fn rotation_create_request(service_id: &str) -> Result<SecurityTransactionCreateRequest> {
    let coordinator = Did::new(service_id.to_owned())?;
    let principal = Did::new(ACTOR.to_owned())?;
    let transaction_id = arkret_wire::TransactionId::new(TRANSACTION.to_owned())?;
    let revoke_submission = event_submission(&principal, "ak.device.revoke")?;
    let revoke_event_id = revoke_submission.event.event_id.clone();
    let revoke_unit = event_unit(&coordinator, revoke_submission)?;
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
            revoke_event_id,
            revoke_unit,
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
    let active_series_submission = event_submission(principal, "ak.key_backup.active_series")?;
    let active_series_event_id = active_series_submission.event.event_id.clone();
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
        active_series_unit: event_unit(coordinator, active_series_submission)?,
        encrypted_backup_material: material,
        binding,
    })
}

fn event_unit(
    coordinator: &Did,
    submission: EventInitialSubmission,
) -> Result<arkret_wire::PreparedEventUnit> {
    let request = EventsSubmitBatchRequestBody {
        events: vec![submission],
    };
    Ok(arkret_wire::PreparedEventUnit::new(
        coordinator.clone(),
        serde_json::to_value(request)?,
    )?)
}

fn event_submission(principal: &Did, kind: &str) -> Result<EventInitialSubmission> {
    let realm_id = arkret_wire::RealmId::new(
        arkret_models_identity::did_document::principal_control_realm_id(principal),
    )?;
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let now = Utc::now();
    let mut event = arkret_wire::test_support::raw_event_at(
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
