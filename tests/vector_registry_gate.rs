use std::fs;
use std::path::Path;

use anyhow::Result;
use cotest::conformance::{
    VectorRegistryGateMode, VectorRegistryGateStatus, build_vector_registry_gate_report_from_paths,
    validate_vector_registry_gate, validate_vector_registry_gate_report,
    validate_vector_registry_gate_report_with_mode,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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
    write_fixture_digest_report(
        &artifacts_root,
        &["spec/v1/artifacts/fixtures/gate-fixture.json"],
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
    write_fixture_digest_report(
        &artifacts_root,
        &["spec/v1/artifacts/fixtures/gate-fixture.json"],
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
fn fixture_backed_active_vector_with_digest_drift_fails() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("spec").join("v1").join("artifacts");
    let registry_path = artifacts_root.join("registry").join("vector-registry.json");

    write_json(
        &artifacts_root.join("fixtures").join("gate-fixture.json"),
        &json!({
            "vectors": [
                {
                    "vector_id": "ck.vector.fixture_backed.v1",
                    "expected_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                }
            ]
        }),
    )?;
    write_json(
        &artifacts_root.join("reports").join("fixture-digests.json"),
        &json!({
            "schema": "arkret.fixture-digests.v1",
            "hash": "sha256",
            "fixtures_root": "spec/v1/artifacts/fixtures",
            "files": [{
                "path": "spec/v1/artifacts/fixtures/gate-fixture.json",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            }]
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
    assert_eq!(
        report.entries[0].gate_status,
        VectorRegistryGateStatus::Failed
    );
    let error =
        validate_vector_registry_gate_report_with_mode(&report, VectorRegistryGateMode::Lenient)
            .expect_err("digest drift must fail even in lenient mode")
            .to_string();
    assert!(error.contains("fixture digest drift"));
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
    validate_vector_registry_gate_report_with_mode(&report, VectorRegistryGateMode::Strict)?;
    assert!(
        report.fixture_backed_entries().count() > 0,
        "real registry must expose at least one artifact-backed vector"
    );
    assert_eq!(
        report.active_doc_only_entries().count(),
        0,
        "real registry must not retain active doc-only vectors"
    );
    // The current spec registry may set every row to active (no reserved /
    // unsupported rows). That is allowed; we only require that *if* any such
    // row exists, it carries a reason. This is a conditional invariant rather
    // than a hard requirement that reserved/unsupported rows be present.
    assert!(
        report
            .non_gating_entries()
            .filter(|entry| matches!(
                entry.gate_status,
                VectorRegistryGateStatus::Reserved | VectorRegistryGateStatus::Unsupported
            ))
            .all(|entry| entry.reason.is_some()),
        "any reserved or unsupported row must record a reason"
    );
    for (vector_id, expected_fixture_ref) in [
        (
            "ck.vector.capability.approval_constraint.v1",
            "spec/v1/artifacts/fixtures/capability-fixture.json",
        ),
        (
            "ck.vector.redaction.preserve_fields.v1",
            "spec/v1/artifacts/fixtures/redaction-fixture.json",
        ),
        (
            "ck.vector.redaction.snapshot_pruning_stub.v1",
            "spec/v1/artifacts/fixtures/redaction-fixture.json",
        ),
    ] {
        let entry = report
            .entries
            .iter()
            .find(|entry| entry.vector_id == vector_id)
            .unwrap_or_else(|| panic!("{vector_id} must be registered"));
        assert_eq!(entry.gate_status, VectorRegistryGateStatus::FixtureBacked);
        assert!(
            entry
                .fixture_refs
                .iter()
                .any(|fixture_ref| fixture_ref == expected_fixture_ref),
            "{vector_id} must stay backed by {expected_fixture_ref}"
        );
    }
    Ok(())
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn write_fixture_digest_report(artifacts_root: &Path, fixture_refs: &[&str]) -> Result<()> {
    let files = fixture_refs
        .iter()
        .map(|fixture_ref| {
            let relative = fixture_ref
                .strip_prefix("spec/v1/artifacts/")
                .expect("fixture ref must be artifact-relative");
            let path = relative
                .split('/')
                .fold(artifacts_root.to_owned(), |path, segment| {
                    path.join(segment)
                });
            let bytes = fs::read(path)?;
            Ok(json!({
                "path": fixture_ref,
                "sha256": sha256_hex(&bytes),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    write_json(
        &artifacts_root.join("reports").join("fixture-digests.json"),
        &json!({
            "schema": "arkret.fixture-digests.v1",
            "hash": "sha256",
            "fixtures_root": "spec/v1/artifacts/fixtures",
            "files": files,
        }),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
