use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{
    AccountId, ActorId, Did, DidCoreId, DidKey, DidUrl, Event, EventProof, Hash, Hlc,
    ProducerEventProof, RealmId, ScopeRef, StationAdmissionProof, StationAdmissionProofKind,
    StrandId, event_spec, project_did_to_core_id,
};
use chrono::{TimeZone as _, Utc};

fn core(did: &str) -> DidCoreId {
    project_did_to_core_id(&Did::new(did.to_owned()).unwrap()).unwrap()
}

fn producer_event() -> Event {
    let actor_id = core("did:web:alice.example");
    let station_id = core("did:web:principal.example");
    let payload = MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        "discussion",
        ContentBlock::text("authority simplification"),
    );
    let event = TypedEventDraft::<event_spec::MessageCreate>::new(
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir")
                .unwrap(),
        },
        ActorId::account(AccountId::new(actor_id, station_id)),
        payload,
    )
    .unwrap()
    .author_with_digest_suite(
        7,
        Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 13, 1, 2, 3).single().unwrap(),
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let mut event = event;
    event.attach_proof(
        ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
            event_digest: digest,
            signer_resolution_evidence_ref: None,
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "header..signature".to_owned(),
        }
        .into(),
    );
    event.into_event()
}

fn accept(mut event: Event) -> Event {
    let EventProof::Producer(producer) = &event.proofs[0] else {
        unreachable!("fixture starts with a producer proof")
    };
    let signer_resolution_evidence_ref =
        cotest::fixture_signer_evidence_ref("authority-simplification-admission");
    event.proofs.push(
        StationAdmissionProof {
            kind: StationAdmissionProofKind::StationAdmission,
            verification_method: DidUrl::new("did:web:principal.example#admission-1").unwrap(),
            event_digest: producer.event_digest.clone(),
            producer_proof_digest: StationAdmissionProof::producer_proof_digest(producer).unwrap(),
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key_did: DidKey::new("did:key:z6MkhFixtureDeviceKey").unwrap(),
            producer_signer_resolution_evidence_ref: None,
            signer_resolution_evidence_ref,
            accepted_at: event.created_at,
            jws: "header..admission-signature".to_owned(),
        }
        .into(),
    );
    event
}

#[test]
fn authority_pair_distinguishes_same_principal_at_different_servers() {
    let principal = core("did:web:alice.example");
    let left = AccountId::new(principal.clone(), core("did:web:principal-a.example"));
    let right = AccountId::new(principal, core("did:web:principal-b.example"));
    assert_ne!(left, right);
}

#[test]
fn accepted_event_requires_exact_origin_and_producer_binding() {
    let accepted = accept(producer_event());
    accepted
        .validate_station_admission_binding(arkret_canonical::DigestSuite::Sha256)
        .unwrap();

    let mut wrong_origin = accepted.clone();
    wrong_origin.actor_id = ActorId::account(AccountId::new(
        core("did:web:alice.example"),
        core("did:web:replica.example"),
    ));
    assert!(
        wrong_origin
            .validate_station_admission_binding(arkret_canonical::DigestSuite::Sha256)
            .is_err()
    );

    let mut wrong_producer_digest = accepted.clone();
    let EventProof::StationAdmission(admission) = &mut wrong_producer_digest.proofs[1] else {
        unreachable!()
    };
    admission.producer_proof_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    assert!(
        wrong_producer_digest
            .validate_station_admission_binding(arkret_canonical::DigestSuite::Sha256)
            .is_err()
    );

    let mut replica_resigned = accepted;
    replica_resigned
        .proofs
        .push(replica_resigned.proofs[1].clone());
    assert!(
        replica_resigned
            .validate_station_admission_binding(arkret_canonical::DigestSuite::Sha256)
            .is_err()
    );
}

#[test]
fn deleted_event_wire_members_are_hard_rejected() {
    let event = accept(producer_event());
    let mut value = serde_json::to_value(&event).unwrap();
    value["accepted_by"] = serde_json::json!(event.actor_id.route_service_id());
    assert!(serde_json::from_value::<Event>(value).is_err());

    let mut missing_origin = serde_json::to_value(event).unwrap();
    missing_origin.as_object_mut().unwrap().remove("actor_id");
    assert!(serde_json::from_value::<Event>(missing_origin).is_err());
}
