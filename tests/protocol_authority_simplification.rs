use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_schema::EventSchemaExt as _;
use arkret_wire::{
    AccountId, ActorId, AuthContext, Did, DidCoreId, DidUrl, Event, Hash, Hlc, ProducerEventProof,
    RealmId, ScopeRef, SealId, StrandId, event_spec, project_did_to_core_id,
};
use chrono::{TimeZone as _, Utc};

fn core(did: &str) -> DidCoreId {
    project_did_to_core_id(&Did::new(did.to_owned()).unwrap()).unwrap()
}

fn authority_ref(byte: char) -> SealId {
    SealId::new(format!("ak:seal:sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn producer_event() -> Event {
    let actor_id = core("did:web:alice.example");
    let station_id = core("did:web:principal.example");
    let payload = MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        "discussion",
        ContentBlock::text("authority simplification"),
    );
    let auth_context = AuthContext {
        key_id: arkret_wire::OpaqueLocalId::new("device-1").unwrap(),
        key_epoch: 7,
        credential_epoch: None,
        authority_refs: vec![authority_ref('1'), authority_ref('2')],
    };
    let mut event = TypedEventDraft::<event_spec::MessageCreate>::new(
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir")
                .unwrap(),
        },
        ActorId::account(AccountId::new(actor_id, station_id)),
        payload,
    )
    .unwrap()
    .with_auth_context(auth_context)
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
    event.attach_proof(ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
        event_digest: digest,
        signer_resolution_evidence_ref: Some(cotest::fixture_signer_evidence_ref(
            "authority-simplification-producer",
        )),
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "header..signature".to_owned(),
    });
    event.into_event()
}

#[test]
fn authority_pair_distinguishes_same_principal_at_different_servers() {
    let principal = core("did:web:alice.example");
    let left = AccountId::new(principal.clone(), core("did:web:principal-a.example"));
    let right = AccountId::new(principal, core("did:web:principal-b.example"));
    assert_ne!(left, right);
}

#[test]
fn ordinary_event_is_producer_only_and_portably_authorized() {
    let event = producer_event();
    assert_eq!(event.proofs.len(), 1);
    assert!(event.seal_basis.is_none());
    event.validate_for_submit().unwrap();
    let wire = serde_json::to_value(&event).unwrap();
    assert!(wire.get("seal_basis").is_none());
    assert!(wire.get("seal_ref").is_none());
    assert!(
        wire["proofs"][0]
            .get("signer_resolution_evidence_ref")
            .is_some()
    );
    assert!(wire["proofs"][0].get("expires_at").is_none());
    event
        .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();

    let mut missing_evidence = event.clone();
    missing_evidence.proofs[0].signer_resolution_evidence_ref = None;
    // The proof-only pass verifies the digest binding and intentionally has no
    // submit-context policy. The complete SDK submit gate owns the ordinary
    // Event requirement for portable signer evidence.
    missing_evidence
        .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    assert!(missing_evidence.validate_for_submit().is_err());

    let mut unsorted_authority = event;
    unsorted_authority
        .auth_context
        .as_mut()
        .unwrap()
        .authority_refs
        .reverse();
    assert!(unsorted_authority.validate_for_submit().is_err());
}

#[test]
fn deleted_event_wire_members_are_hard_rejected() {
    let event = producer_event();
    for removed in [
        "accepted_by",
        "seal_ref",
        "station_admission",
        "origin_station_admission",
    ] {
        let mut value = serde_json::to_value(&event).unwrap();
        value[removed] = serde_json::json!(event.actor_id.route_service_id());
        assert!(serde_json::from_value::<Event>(value).is_err(), "{removed}");
    }
}
