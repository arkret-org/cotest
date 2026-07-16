use std::collections::BTreeSet;

use arkret_core::events::{EventKind, EventProductClass, EventRegistryCategory};
use arkret_core::{
    CapabilityActionId, DIGEST_SUITES, EXPORTER_LABELS, ErrorCode, ExporterLabelId, HPKE_SUITES,
    MLS_CIPHERSUITES, PROOF_CONTEXTS, ProofContextId, RELATION_KIND_DESCRIPTORS, RelationKind,
    SERVICE_OPERATION_DESCRIPTORS, SERVICE_TYPE_DESCRIPTORS, SIGNATURE_ALGORITHMS,
    ServiceOperationId, ServiceType,
};
use arkret_schema::{
    REGISTERED_ACCOUNT_DATA_PATTERNS, REGISTERED_CAPABILITY_ACTIONS, REGISTERED_ID_KINDS,
    REGISTERED_SCHEMA_IDS, REGISTERED_SPECIAL_FORM_ID_KINDS, account_data_pattern,
};

#[test]
fn generated_registry_sets_are_complete_and_unique() {
    assert_eq!(EventKind::ALL.len(), 188);
    assert_eq!(ServiceOperationId::ALL.len(), 185);
    assert_eq!(ErrorCode::ALL.len(), 234);
    assert_eq!(REGISTERED_ID_KINDS.len(), 48);
    assert_eq!(REGISTERED_SPECIAL_FORM_ID_KINDS.len(), 9);
    assert_eq!(REGISTERED_CAPABILITY_ACTIONS.len(), 152);
    assert_eq!(CapabilityActionId::ALL.len(), 152);
    assert_eq!(REGISTERED_SCHEMA_IDS.len(), 120);

    let routes = SERVICE_OPERATION_DESCRIPTORS
        .iter()
        .map(|row| (row.http_method, row.http_path))
        .collect::<BTreeSet<_>>();
    assert_eq!(routes.len(), SERVICE_OPERATION_DESCRIPTORS.len());
    assert!(ErrorCode::ALL.iter().all(|code| code.http_status() >= 100));
}

#[test]
fn open_value_spaces_round_trip_without_changing_registry_facts() {
    let unknown = EventKind::from_wire("vendor.example.future");
    assert_eq!(unknown.as_str(), "vendor.example.future");
    assert_eq!(
        unknown.product_class(),
        EventProductClass::Custom("vendor.example.future".to_owned())
    );

    let pin = EventKind::PinAdd;
    assert_eq!(
        pin.registry_category(),
        Some(EventRegistryCategory::Discussion)
    );
    assert_eq!(pin.product_class(), EventProductClass::Pin);
}

#[test]
fn generated_metadata_keeps_product_and_security_domains_separate() {
    assert!(ServiceType::PrincipalServer.valid_in("service_describe"));
    assert!(!ServiceType::MimiProviderFacade.valid_in("service_describe"));
    assert_eq!(SERVICE_TYPE_DESCRIPTORS.len(), ServiceType::ALL.len());
    assert_eq!(RELATION_KIND_DESCRIPTORS.len(), 16);
    assert_eq!(
        RelationKind::from_wire("vendor.example.relation").as_str(),
        "vendor.example.relation"
    );

    assert_eq!(PROOF_CONTEXTS.len(), 24);
    assert_eq!(EXPORTER_LABELS.len(), 8);
    assert_eq!(ProofContextId::ALL.len(), PROOF_CONTEXTS.len());
    assert_eq!(ExporterLabelId::ALL.len(), EXPORTER_LABELS.len());
    assert_eq!(
        ProofContextId::from_wire(ProofContextId::EventProofV1.as_str()),
        Some(ProofContextId::EventProofV1)
    );
    assert_eq!(
        ExporterLabelId::from_wire(ExporterLabelId::RtcRecordingKeyV1.as_str()),
        Some(ExporterLabelId::RtcRecordingKeyV1)
    );
    assert!(PROOF_CONTEXTS.iter().all(|context| {
        EXPORTER_LABELS
            .iter()
            .all(|label| context.context != label.label)
    }));
    assert!(!DIGEST_SUITES.is_empty());
    assert!(!SIGNATURE_ALGORITHMS.is_empty());
    assert!(!HPKE_SUITES.is_empty());
    assert!(!MLS_CIPHERSUITES.is_empty());
}

#[test]
fn unknown_remote_error_code_remains_round_trippable_wire_data() {
    let detail = arkret_core::ErrorDetail {
        code: "vendor.example.future_error".to_owned(),
        message: "future peer error".to_owned(),
        retry_after_ms: None,
        details: Default::default(),
    };
    assert_eq!(detail.error_code(), None);
    let encoded = serde_json::to_value(&detail).expect("serialize open remote error");
    let decoded: arkret_core::ErrorDetail =
        serde_json::from_value(encoded).expect("deserialize open remote error");
    assert_eq!(decoded.code, "vendor.example.future_error");
}

#[test]
fn account_data_patterns_match_dynamic_keys() {
    assert_eq!(REGISTERED_ACCOUNT_DATA_PATTERNS.len(), 22);
    assert_eq!(
        account_data_pattern("ak.reminders.v1:0190example")
            .expect("dynamic reminder key")
            .key_pattern,
        "ak.reminders.v1:<id>"
    );
    assert!(account_data_pattern("ak.reminders.v1:").is_none());
    assert!(account_data_pattern("vendor.account.data").is_none());
}
