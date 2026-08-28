use anyhow::Result;
use arkret_wire::{
    BackupId, BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
    BackupSeriesId, CanonicalPublicMaterial, Did, DidCoreId, EventInitialSubmission,
    EventsSubmitBatchRequestBody, Hash, Hlc, RiskTier, ScopeRef, SealId,
    SecurityRotationTransactionCreateRequest, SecurityTransactionCreateRequest,
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
    let request = rotation_create_request(&actor, &pcr_realm)?;

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
    pcr_realm: &str,
) -> Result<SecurityTransactionCreateRequest> {
    let principal = Did::new(actor.to_owned())?;
    let principal_id = arkret_wire::project_did_to_core_id(&principal)?;
    let transaction_id = arkret_wire::TransactionId::new(TRANSACTION.to_owned())?;
    let revoke_submission = event_submission(&principal, pcr_realm, "ak.device.revoke")?;
    let revoke_unit = event_unit(revoke_submission)?;
    let rotations = [
        (BackupRotationKind::SecretStorage, "c"),
        (BackupRotationKind::MlsHistory, "d"),
    ]
    .into_iter()
    .map(|(kind, suffix)| rotation_plan(&principal, pcr_realm, kind, suffix))
    .collect::<Result<Vec<_>>>()?;
    Ok(SecurityTransactionCreateRequest::SecurityRotation(
        SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            transaction_id,
            principal_id,
            Utc::now() + chrono::Duration::hours(1),
            revoke_unit,
            hash('e')?,
            rotations,
        )?,
    ))
}

fn rotation_plan(
    principal: &Did,
    pcr_realm: &str,
    kind: BackupRotationKind,
    suffix: &str,
) -> Result<BackupRotationPlan> {
    let active_series_submission =
        event_submission(principal, pcr_realm, "ak.key_backup.active_series")?;
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

fn event_unit(submission: EventInitialSubmission) -> Result<arkret_wire::PreparedEventUnit> {
    let request = EventsSubmitBatchRequestBody {
        events: vec![submission],
    };
    Ok(arkret_wire::PreparedEventUnit::new(
        arkret_canonical::DigestSuite::Sha256,
        request,
    )?)
}

fn event_submission(
    principal: &Did,
    pcr_realm: &str,
    kind: &str,
) -> Result<EventInitialSubmission> {
    // The live fixture uses an already accepted event-derived PCR coordinate;
    // it must never reconstruct one from the principal DID.
    let realm_id = arkret_wire::RealmId::new(pcr_realm.to_owned())?;
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let now = Utc::now();
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        scope_ref.clone(),
        arkret_identifiers::project_did_to_core_id(principal)?,
        DidCoreId::new("ak:did_core:web:principal.example")?,
        1,
        Hlc::new("01970e589d21-0004-c07e57aa".to_owned())?,
        json!({"fixture": true}),
        now,
    )?;
    event.seal_basis = Some(arkret_wire::SealBasis {
        leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64)))?],
    });
    let event_digest =
        Hash::new(event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?)?;
    let (signer_evidence_ref, signer_evidence_digest) =
        crate::fixture_signer_evidence_pair(principal.as_str());
    event.proofs.push(
        arkret_wire::ProducerEventProof {
            kind: "DataIntegrityProof".to_owned(),
            // `zh/identity/did-usage-and-verification.md` §2.2: a
            // `verification_method` is a DID URL, never a bare DID. This fixture
            // used `principal` itself, which no receiver could resolve to a key.
            verification_method: crate::harness::default_event_verification_method(
                principal.as_str(),
            ),
            event_digest,
            signer_resolution_evidence_ref: Some(signer_evidence_ref),
            signer_resolution_evidence_digest: Some(signer_evidence_digest),
            created_at: now,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZDI1NTE5In0..c2lnbmF0dXJl".to_owned(),
        }
        .into(),
    );
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
