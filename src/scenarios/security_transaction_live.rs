use anyhow::Result;
use arkret_wire::{
    AUTHORITY_SET_POLICY_SCHEMA, AuthoritySetPolicy, AuthoritySetPolicyKind,
    AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind, AuthorizationLease,
    AuthorizationLeaseId, BackupId, BackupObjectRef, BackupRotationBinding, BackupRotationKind,
    BackupRotationPlan, BackupSeriesId, CanonicalPublicMaterial, Did, Event, EventId,
    EventInitialSubmission, EventsSubmitBatchRequestBody, Hash, Hlc, LeaseBasisRef, RiskTier,
    ScopeRef, SealId, SecurityRotationTransactionCreateRequest, SecurityTransactionCreateRequest,
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
    let revoke_event_id = EventId::new("ak:event:01975510-0000-7000-8000-0000000000b3".to_owned())?;
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
            "ak:event:01975510-0000-7000-8000-0000000000{suffix}4"
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
    let realm_id = arkret_wire::RealmId::new(
        arkret_models_identity::did_document::principal_control_realm_id(principal),
    )?;
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let now = Utc::now();
    let event = Event::new_with_id_at(
        event_id,
        kind,
        scope_ref.clone(),
        principal.clone(),
        1,
        Hlc::new("01970e589d21-0004-c07e57aa".to_owned())?,
        json!({"fixture": true}),
        now,
    )?;
    let authority_set_policy = AuthoritySetPolicy {
        schema: AUTHORITY_SET_POLICY_SCHEMA.to_owned(),
        authority_set_id: "ak.authority_set.security_transaction_live.v1".to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: "ak:event:01975510-0000-7000-8000-0000000000aa".to_owned(),
            source_digest: hash('a')?,
            generation_ref: "1".to_owned(),
        },
        authorization_rules: Vec::new(),
    };
    let request = EventsSubmitBatchRequestBody {
        events: vec![EventInitialSubmission {
            event,
            authorization_lease: AuthorizationLease {
                authorization_lease_id: AuthorizationLeaseId::new(format!(
                    "ak:authorization_lease:01975510-0000-7000-8000-0000000000{}",
                    if kind == "ak.device.revoke" {
                        "e1"
                    } else {
                        "e2"
                    }
                ))?,
                basis_ref: LeaseBasisRef::Seal(SealId::new(format!(
                    "ak:seal:sha256:{}",
                    "b".repeat(64)
                ))?),
                actor_id: principal.clone(),
                device_id: arkret_wire::DeviceId::new(DEVICE.to_owned())?,
                scope_ref,
                action: "ak.realm.admin".to_owned(),
                authorization_rule_id: "fixture".to_owned(),
                risk_tier: RiskTier::High,
                issued_at: now,
                expires_at: now + chrono::Duration::hours(1),
                authority_set_ref: AuthoritySetRef {
                    authority_set_id: authority_set_policy.authority_set_id.clone(),
                    authority_set_digest: hash('c')?,
                },
                authority_set_policy,
                proofs: Vec::new(),
            },
            cba_proof_bundles: Vec::new(),
            control_proposal_receipt: None,
        }],
    };
    Ok(arkret_wire::PreparedEventUnit::new(
        coordinator.clone(),
        serde_json::to_value(request)?,
    )?)
}

fn hash(byte: char) -> Result<Hash> {
    Ok(Hash::new(format!(
        "sha256:{}",
        byte.to_string().repeat(64)
    ))?)
}
