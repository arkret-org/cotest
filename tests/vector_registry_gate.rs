use std::fs;
use std::path::Path;

use anyhow::Result;
use cotest::conformance::{
    VectorRegistryGateStatus, build_vector_registry_gate_report_from_paths,
    validate_vector_registry_gate, validate_vector_registry_gate_report,
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
fn current_spec_vector_registry_artifact_gate_validates() -> Result<()> {
    let report = validate_vector_registry_gate()?;
    assert!(
        report.gated_entries().count() > 0,
        "real registry must expose at least one artifact-backed vector"
    );
    assert!(
        report.non_gating_entries().count() > 0,
        "real registry should record non-gating reserved or unsupported rows"
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
