use arkret_canonical::{DigestSuite, canonical_json_bytes};
use arkret_event_draft::{EventPayloadExt, TypedEventDraft, ValidatedExtensionPayload};
use arkret_models_collaboration::events_payloads::{
    ContentBlock, MessageCreatePayload, StatePayload,
};
use arkret_wire::{
    ConfidentialityClass, DidCoreId, DidFullId, Event, EventKind, ExtensionManifest, Hash, Hlc,
    ManifestResourceLimits, ProtocolLayerKind, RealmId, RegistryContentRef, ScopeRef, StrandId,
    WireError, event_spec,
};
use chrono::{TimeZone as _, Utc};

const REALM_ID: &str = "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir";
const ACTOR_FULL_ID: &str = "did:webvh:z6mkfixture:alice.example";
const ACTOR_ID: &str = "ak:did_core:webvh:z6mkfixture";
const STRAND_ID: &str = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
const HLC: &str = "01970e589d21-0001-a13f9c2e";

fn scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: RealmId::new(REALM_ID).unwrap(),
    }
}

fn actor() -> DidCoreId {
    let projected =
        arkret_wire::project_full_id_to_core_id(&DidFullId::new(ACTOR_FULL_ID).unwrap()).unwrap();
    assert_eq!(projected.as_str(), ACTOR_ID);
    DidCoreId::from(projected)
}

fn principal_server() -> DidCoreId {
    DidCoreId::new("ak:did_core:web:principal.example").unwrap()
}

fn created_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 9, 1, 2, 3).single().unwrap()
}

fn message_event() -> Event {
    let payload = MessageCreatePayload::with_content(
        StrandId::new(STRAND_ID).unwrap(),
        "main",
        ContentBlock::text("typed authoring KAT"),
    );
    TypedEventDraft::<event_spec::MessageCreate>::new(scope(), actor(), principal_server(), payload)
        .unwrap()
        .author_with_digest_suite(7, Hlc::new(HLC).unwrap(), created_at(), DigestSuite::Sha256)
        .unwrap()
        .into_event()
}

#[test]
fn typed_event_cross_family_canonical_kats_are_fixed() {
    let message = message_event();
    let policy = TypedEventDraft::<event_spec::RealmPolicy>::new(
        scope(),
        actor(),
        principal_server(),
        StatePayload {
            value: None,
            state: Some("active".to_owned()),
            reason: None,
        },
    )
    .unwrap()
    .author_with_digest_suite(7, Hlc::new(HLC).unwrap(), created_at(), DigestSuite::Sha256)
    .unwrap();

    let message_bytes = canonical_json_bytes(&message.digest_payload().unwrap()).unwrap();
    let policy_bytes = canonical_json_bytes(&policy.digest_payload().unwrap()).unwrap();
    assert_eq!(
        message_bytes,
        br#"{"actor_id":"ak:did_core:webvh:z6mkfixture","actor_seq":7,"created_at":"2026-08-09T01:02:03.000Z","hlc":"01970e589d21-0001-a13f9c2e","kind":"ak.message.create","payload":{"content":{"body":"typed authoring KAT","kind":"ak.content.text"},"strand_id":"ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9","track_name":"main"},"prev_refs":[],"principal_server_id":"ak:did_core:web:principal.example","realm_id":"ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir","refs":[],"scope_ref":{"kind":"realm","realm_id":"ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir"}}"#
    );
    assert_eq!(
        policy_bytes,
        br#"{"actor_id":"ak:did_core:webvh:z6mkfixture","actor_seq":7,"created_at":"2026-08-09T01:02:03.000Z","hlc":"01970e589d21-0001-a13f9c2e","kind":"ak.realm.policy","payload":{"state":"active"},"prev_refs":[],"principal_server_id":"ak:did_core:web:principal.example","realm_id":"ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir","refs":[],"scope_ref":{"kind":"realm","realm_id":"ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir"}}"#
    );
    assert_eq!(
        message.event_id.as_str(),
        "ak:event:AcBKdR9sldDdj1xmna9xcGIbbQx9pUCqKOptx0IeMXGD"
    );
    assert_eq!(
        policy.event_id.as_str(),
        "ak:event:ART2Dcr_wvitix1HGiC-e3VR5ByWLCwGRUmRknLtQO1k"
    );
    assert_ne!(message_bytes, policy_bytes);
}

#[test]
fn checked_accessor_separates_kind_mismatch_from_payload_invalid() {
    let message = message_event();
    assert!(matches!(
        message.typed_payload::<event_spec::RealmPolicy>(),
        Err(WireError::PayloadKindMismatch { .. })
    ));

    let mut wrong_family_wire = serde_json::to_value(&message).unwrap();
    wrong_family_wire["kind"] = serde_json::json!(event_spec::RealmPolicy::KIND_STR);
    let wrong_family: Event = serde_json::from_value(wrong_family_wire).unwrap();
    assert!(matches!(
        wrong_family.typed_payload::<event_spec::RealmPolicy>(),
        Err(WireError::PayloadInvalid { .. })
    ));
}

#[test]
fn typed_authored_event_round_trips_at_the_wire_boundary() {
    let event = message_event();
    let wire = serde_json::to_vec(&event).unwrap();
    let decoded: Event = serde_json::from_slice(&wire).unwrap();
    assert_eq!(decoded, event);
    decoded
        .verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
}

#[test]
fn extension_authoring_keeps_unknown_kinds_open_but_manifest_bound() {
    let schema_ref = RegistryContentRef {
        registry_id: "ak.schema.example.note.v1".to_owned(),
        digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
        retrieval_url: None,
    };
    let manifest = ExtensionManifest {
        manifest_id: "ak.manifest.example.v1".to_owned(),
        extension_id: "ak.extension.example.v1".to_owned(),
        namespace: "ak.example".to_owned(),
        protocol_layer_kind: ProtocolLayerKind::Extension,
        manifest_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        publisher_id: DidCoreId::new("ak:did_core:web:publisher.example").unwrap(),
        published_at: created_at(),
        dependency_refs: Vec::new(),
        payload_schema_refs: vec![schema_ref.clone()],
        reducer_contract_refs: Vec::new(),
        required_actions: Vec::new(),
        confidentiality_class: ConfidentialityClass::PlaintextAllowed,
        transport_rail_ids: Vec::new(),
        recovery_profile_ref: None,
        federation_profile_ref: None,
        conformance_vector_refs: Vec::new(),
        resource_limits: ManifestResourceLimits::default(),
        proofs: Vec::new(),
    };
    let validator = |_: &RegistryContentRef, payload: &serde_json::Value| {
        payload
            .get("text")
            .and_then(serde_json::Value::as_str)
            .map(|_| ())
            .ok_or_else(|| WireError::Protocol("example note requires text".to_owned()))
    };
    let validated = ValidatedExtensionPayload::validate(
        EventKind::from_wire("ak.example.note"),
        serde_json::json!({"text": "hello", "provider_extension": {"x": 1}}),
        &manifest,
        &schema_ref,
        &validator,
    )
    .unwrap();
    let event = validated
        .author(
            scope(),
            actor(),
            principal_server(),
            7,
            Hlc::new(HLC).unwrap(),
            created_at(),
            DigestSuite::Sha256,
        )
        .unwrap();
    assert_eq!(event.kind, EventKind::Unknown("ak.example.note".to_owned()));
    assert_eq!(event.payload["provider_extension"]["x"], 1);

    assert!(
        ValidatedExtensionPayload::validate(
            EventKind::MessageCreate,
            serde_json::json!({"text": "hello"}),
            &manifest,
            &schema_ref,
            &validator,
        )
        .is_err()
    );
    assert!(
        ValidatedExtensionPayload::validate(
            EventKind::from_wire("ak.other.note"),
            serde_json::json!({"text": "hello"}),
            &manifest,
            &schema_ref,
            &validator,
        )
        .is_err()
    );
}
