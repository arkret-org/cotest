use std::fs;
use std::path::Path;

use anyhow::Result;
use cotest::conformance::{
    VectorRegistryGateMode, VectorRegistryGateStatus, build_vector_registry_gate_report_from_paths,
    validate_vector_registry_gate, validate_vector_registry_gate_report,
    validate_vector_registry_gate_report_with_mode,
};
use serde_json::{Value, json};

#[test]
fn active_vector_with_missing_artifact_evidence_fails() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("spec").join("v1").join("artifacts");
    let registry_path = artifacts_root.join("registry").join("vector-registry.json");

    write_json(
        &artifacts_root.join("fixtures").join("gate-fixture.json"),
        &json!({
            "vectors": [
                {
                    "vector_id": "ck.vector.other.v1",
                    "expected_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                }
            ]
        }),
    )?;
    write_json(
        &registry_path,
        &json!({
            "vectors": [
                {
                    "vector_id": "ck.vector.missing.v1",
                    "status": "active",
                    "domain": "gate",
                    "source_refs": ["spec/v1/artifacts/fixtures/gate-fixture.json"]
                }
            ]
        }),
    )?;

    let report = build_vector_registry_gate_report_from_paths(&registry_path, &artifacts_root)?;
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].gate_status,
        VectorRegistryGateStatus::Failed
    );

    let error = validate_vector_registry_gate_report(&report)
        .expect_err("missing active vector evidence must fail")
        .to_string();
    assert!(error.contains("ck.vector.missing.v1"));
    Ok(())
}

#[test]
fn active_doc_only_vector_is_lenient_only() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("spec").join("v1").join("artifacts");
    let registry_path = artifacts_root.join("registry").join("vector-registry.json");

    write_json(
        &registry_path,
        &json!({
            "vectors": [
                {
                    "vector_id": "ck.vector.doc_only.v1",
                    "status": "active",
                    "domain": "gate",
                    "source_refs": ["spec/v1/zh/conformance/conformance-vectors.md"]
                }
            ]
        }),
    )?;

    let report = build_vector_registry_gate_report_from_paths(&registry_path, &artifacts_root)?;
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].gate_status,
        VectorRegistryGateStatus::ActiveDocOnly
    );
    assert_eq!(report.active_doc_only_entries().count(), 1);
    assert_eq!(report.non_gating_entries().count(), 1);

    validate_vector_registry_gate_report_with_mode(&report, VectorRegistryGateMode::Lenient)?;
    let error =
        validate_vector_registry_gate_report_with_mode(&report, VectorRegistryGateMode::Strict)
            .expect_err("strict mode must fail active doc-only vectors")
            .to_string();
    assert!(error.contains("ck.vector.doc_only.v1"));
    assert!(error.contains("active doc-only"));
    Ok(())
}

#[test]
fn fixture_backed_active_vector_is_certification_gate() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("spec").join("v1").join("artifacts");
    let registry_path = artifacts_root.join("registry").join("vector-registry.json");
    let expected_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    write_json(
        &artifacts_root.join("fixtures").join("gate-fixture.json"),
        &json!({
            "vectors": [
                {
                    "name": "ck.vector.fixture_backed.v1",
                    "expected_state_digest": expected_digest
                }
            ]
        }),
    )?;
    write_json(
        &registry_path,
        &json!({
            "vectors": [
                {
                    "vector_id": "ck.vector.fixture_backed.v1",
                    "status": "active",
                    "domain": "gate",
                    "source_refs": ["spec/v1/artifacts/fixtures/gate-fixture.json"]
                }
            ]
        }),
    )?;

    let report = build_vector_registry_gate_report_from_paths(&registry_path, &artifacts_root)?;
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].gate_status,
        VectorRegistryGateStatus::FixtureBacked
    );
    assert_eq!(report.fixture_backed_entries().count(), 1);
    assert_eq!(report.gated_entries().count(), 1);
    assert!(
        report.entries[0]
            .evidence_refs
            .iter()
            .any(|evidence| evidence.contains(expected_digest)),
        "fixture-backed evidence should surface expected_digest metadata"
    );
    validate_vector_registry_gate_report_with_mode(&report, VectorRegistryGateMode::Strict)?;
    Ok(())
}

#[test]
fn reserved_vector_is_not_a_certification_gate() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("spec").join("v1").join("artifacts");
    let registry_path = artifacts_root.join("registry").join("vector-registry.json");

    write_json(
        &registry_path,
        &json!({
            "vectors": [
                {
                    "vector_id": "ck.vector.reserved.v1",
                    "status": "reserved",
                    "domain": "gate",
                    "description": "Reserved until a machine fixture is published.",
                    "source_refs": ["spec/v1/zh/conformance/conformance-vectors.md"]
                }
            ]
        }),
    )?;

    let report = build_vector_registry_gate_report_from_paths(&registry_path, &artifacts_root)?;
    validate_vector_registry_gate_report(&report)?;
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].gate_status,
        VectorRegistryGateStatus::Reserved
    );
    assert_eq!(report.gated_entries().count(), 0);
    Ok(())
}

#[test]
fn unsupported_vector_with_reason_is_not_a_certification_gate() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("spec").join("v1").join("artifacts");
    let registry_path = artifacts_root.join("registry").join("vector-registry.json");

    write_json(
        &registry_path,
        &json!({
            "vectors": [
                {
                    "vector_id": "ck.vector.unsupported.v1",
                    "status": "unsupported",
                    "domain": "gate",
                    "description": "Unsupported until the corresponding feature profile exists.",
                    "source_refs": ["spec/v1/zh/conformance/conformance-vectors.md"]
                }
            ]
        }),
    )?;

    let report = build_vector_registry_gate_report_from_paths(&registry_path, &artifacts_root)?;
    validate_vector_registry_gate_report_with_mode(&report, VectorRegistryGateMode::Strict)?;
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].gate_status,
        VectorRegistryGateStatus::Unsupported
    );
    assert_eq!(report.gated_entries().count(), 0);
    assert!(report.entries[0].reason.is_some());
    Ok(())
}

#[test]
fn current_spec_vector_registry_artifact_gate_validates() -> Result<()> {
    let report = validate_vector_registry_gate()?;
    assert!(
        report.fixture_backed_entries().count() > 0,
        "real registry must expose at least one artifact-backed vector"
    );
    assert!(
        report.active_doc_only_entries().count() > 0,
        "real registry currently has active doc-only vectors; strict mode must fail until they gain fixtures or become reserved/unsupported"
    );
    assert!(
        report.non_gating_entries().any(|entry| matches!(
            entry.gate_status,
            VectorRegistryGateStatus::Reserved | VectorRegistryGateStatus::Unsupported
        ) && entry.reason.is_some()),
        "real registry should record reserved or unsupported rows with a reason"
    );
    Ok(())
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
