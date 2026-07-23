use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use arkret_schema::{
    REGISTERED_ACCOUNT_DATA_PATTERNS, REGISTERED_CAPABILITY_ACTIONS, REGISTERED_ID_KINDS,
    REGISTERED_SCHEMA_IDS, REGISTERED_SPECIAL_FORM_ID_KINDS, account_data_pattern,
};
use arkret_wire::events::{EventKind, EventProductClass, EventRegistryCategory};
use arkret_wire::{
    CapabilityActionId, DIGEST_SUITES, EXPORTER_LABELS, ErrorCode, ExporterLabelId, HPKE_SUITES,
    MLS_CIPHERSUITES, PROOF_CONTEXTS, ProofContextId, RELATION_KIND_DESCRIPTORS, RelationKind,
    SERVICE_OPERATION_DESCRIPTORS, SERVICE_TYPE_DESCRIPTORS, SIGNATURE_ALGORITHMS,
    ServiceOperationId, ServiceType,
};
use serde_json::Value;

#[test]
fn generated_registry_sets_are_complete_and_unique() {
    assert_generated_set(
        "event kinds",
        EventKind::ALL.iter().map(EventKind::as_str),
        "event-kind-registry.json",
        "event_kinds",
        "event_kind",
    );
    assert_generated_set(
        "operations",
        ServiceOperationId::ALL.iter().map(|id| id.as_str()),
        "operation-registry.json",
        "operations",
        "operation_id",
    );
    assert_generated_set(
        "error codes",
        ErrorCode::ALL.iter().map(|code| code.as_str()),
        "error-code-registry.json",
        "codes",
        "code",
    );
    assert_generated_set(
        "id kinds",
        REGISTERED_ID_KINDS.iter().map(|row| row.kind),
        "id-kind-registry.json",
        "id_kinds",
        "kind",
    );
    assert_generated_set(
        "special-form id kinds",
        REGISTERED_SPECIAL_FORM_ID_KINDS.iter().map(|row| row.kind),
        "id-kind-registry.json",
        "special_forms",
        "kind",
    );
    assert_generated_set(
        "capability actions",
        REGISTERED_CAPABILITY_ACTIONS
            .iter()
            .map(|row| row.action.as_str()),
        "capability-action-registry.json",
        "actions",
        "action",
    );
    assert_generated_set(
        "capability action ids",
        CapabilityActionId::ALL.iter().map(|action| action.as_str()),
        "capability-action-registry.json",
        "actions",
        "action",
    );
    assert_generated_set(
        "schema ids",
        REGISTERED_SCHEMA_IDS.iter().map(|row| row.schema_id),
        "schema-registry.json",
        "schemas",
        "schema_id",
    );

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
    assert_generated_set(
        "service types",
        SERVICE_TYPE_DESCRIPTORS
            .iter()
            .map(|row| row.service_type.as_str()),
        "service-type-registry.json",
        "service_types",
        "canonical_id",
    );
    assert_generated_set(
        "relation kinds",
        RELATION_KIND_DESCRIPTORS.iter().map(|row| row.canonical_id),
        "relation-kind-registry.json",
        "relation_kinds",
        "canonical_id",
    );
    assert_eq!(
        RelationKind::from_wire("vendor.example.relation").as_str(),
        "vendor.example.relation"
    );

    assert_generated_set(
        "proof contexts",
        PROOF_CONTEXTS.iter().map(|row| row.context),
        "proof-context-registry.json",
        "contexts",
        "context",
    );
    assert_generated_set(
        "exporter labels",
        EXPORTER_LABELS.iter().map(|row| row.label),
        "exporter-label-registry.json",
        "labels",
        "label",
    );
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
    assert_generated_set(
        "digest suites",
        DIGEST_SUITES.iter().map(|row| row.canonical_id),
        "digest-suite-registry.json",
        "suites",
        "canonical_id",
    );
    assert_generated_set(
        "signature algorithms",
        SIGNATURE_ALGORITHMS.iter().map(|row| row.canonical_id),
        "signature-alg-registry.json",
        "algorithms",
        "canonical_id",
    );
    assert_generated_set(
        "HPKE suites",
        HPKE_SUITES.iter().map(|row| row.canonical_id),
        "hpke-suite-registry.json",
        "suites",
        "canonical_id",
    );
    assert_generated_set(
        "MLS ciphersuites",
        MLS_CIPHERSUITES.iter().map(|row| row.canonical_id),
        "mls-ciphersuite-registry.json",
        "ciphersuites",
        "canonical_id",
    );
}

#[test]
fn unknown_remote_error_code_remains_round_trippable_wire_data() {
    let detail = arkret_wire::ErrorDetail {
        code: "vendor.example.future_error".to_owned(),
        message: "future peer error".to_owned(),
        retry_after_ms: None,
        details: Default::default(),
    };
    assert_eq!(detail.error_code(), None);
    let encoded = serde_json::to_value(&detail).expect("serialize open remote error");
    let decoded: arkret_wire::ErrorDetail =
        serde_json::from_value(encoded).expect("deserialize open remote error");
    assert_eq!(decoded.code, "vendor.example.future_error");
}

#[test]
fn account_data_patterns_match_dynamic_keys() {
    assert_generated_set(
        "account-data patterns",
        REGISTERED_ACCOUNT_DATA_PATTERNS
            .iter()
            .map(|row| row.key_pattern),
        "account-data-type-registry.json",
        "account_data_types",
        "key_pattern",
    );
    assert_eq!(
        account_data_pattern("ak.reminders.v1:0190example")
            .expect("dynamic reminder key")
            .key_pattern,
        "ak.reminders.v1:<id>"
    );
    assert!(account_data_pattern("ak.reminders.v1:").is_none());
    assert!(account_data_pattern("vendor.account.data").is_none());
}

fn assert_generated_set<'a>(
    label: &str,
    actual: impl IntoIterator<Item = &'a str>,
    artifact_file: &str,
    rows_field: &str,
    value_field: &str,
) {
    let actual_values = actual.into_iter().map(str::to_owned).collect::<Vec<_>>();
    let actual_set = actual_values.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        actual_set.len(),
        actual_values.len(),
        "generated {label} contain duplicates"
    );

    let artifact: Value = serde_json::from_slice(
        &fs::read(spec_registry_root().join(artifact_file))
            .unwrap_or_else(|error| panic!("read {artifact_file}: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse {artifact_file}: {error}"));
    let expected_values = artifact[rows_field]
        .as_array()
        .unwrap_or_else(|| panic!("{artifact_file} lacks {rows_field} array"))
        .iter()
        .map(|row| {
            row[value_field]
                .as_str()
                .unwrap_or_else(|| panic!("{artifact_file} {rows_field} row lacks {value_field}"))
                .to_owned()
        })
        .collect::<Vec<_>>();
    let expected_set = expected_values.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        expected_set.len(),
        expected_values.len(),
        "Spec {label} contain duplicates"
    );
    assert_eq!(
        actual_set, expected_set,
        "generated {label} drifted from Spec"
    );
}

fn spec_registry_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cotest has a workspace parent")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join("registry")
}
