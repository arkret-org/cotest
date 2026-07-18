use std::fs;
use std::path::Path;

use anyhow::Result;
use cotest::conformance::{
    VectorRegistryGateMode, VectorRegistryGateStatus, build_vector_registry_gate_report_from_paths,
    fixture_digest_hex, validate_vector_registry_gate, validate_vector_registry_gate_report,
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
                    "vector_id": "ak.vector.other.v1",
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
                    "vector_id": "ak.vector.missing.v1",
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
    assert!(error.contains("ak.vector.missing.v1"));
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
                    "vector_id": "ak.vector.doc_only.v1",
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
    assert!(error.contains("ak.vector.doc_only.v1"));
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
                    "name": "ak.vector.fixture_backed.v1",
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
                    "vector_id": "ak.vector.fixture_backed.v1",
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
                    "vector_id": "ak.vector.fixture_backed.v1",
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
                    "vector_id": "ak.vector.fixture_backed.v1",
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
fn fixture_digest_normalizes_lf_crlf_and_cr() {
    let lf = b"{\n  \"vector_id\": \"ak.vector.fixture_backed.v1\"\n}\n";
    let crlf = b"{\r\n  \"vector_id\": \"ak.vector.fixture_backed.v1\"\r\n}\r\n";
    let cr = b"{\r  \"vector_id\": \"ak.vector.fixture_backed.v1\"\r}\r";

    assert_eq!(fixture_digest_hex(lf), fixture_digest_hex(crlf));
    assert_eq!(fixture_digest_hex(lf), fixture_digest_hex(cr));
    assert_ne!(fixture_digest_hex(lf), fixture_digest_hex(b"different\n"));
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
                    "vector_id": "ak.vector.reserved.v1",
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
                    "vector_id": "ak.vector.unsupported.v1",
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
            "ak.vector.capability.approval_constraint.v1",
            "spec/v1/artifacts/fixtures/capability-fixture.json",
        ),
        (
            "ak.vector.redaction.preserve_fields.v1",
            "spec/v1/artifacts/fixtures/redaction-fixture.json",
        ),
        (
            "ak.vector.redaction.snapshot_pruning_stub.v1",
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

#[test]
fn runner_kind_registry_is_closed_and_fully_owned() -> Result<()> {
    let artifacts = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts");
    let registry: Value = serde_json::from_slice(&fs::read(
        artifacts.join("registry").join("runner-kind-registry.json"),
    )?)?;
    let rows = registry["runner_kinds"]
        .as_array()
        .expect("runner_kinds must be an array");
    let registered = rows
        .iter()
        .map(|row| {
            let kind = row["kind"].as_str().expect("runner kind must be a string");
            assert!(
                row["owner"].as_str().is_some_and(|value| !value.is_empty()),
                "runner kind {kind} must have an owner"
            );
            assert!(
                row["execution_contract"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
                "runner kind {kind} must have an execution contract"
            );
            kind.to_owned()
        })
        .collect::<std::collections::BTreeSet<_>>();
    let supported = [
        "named_suite",
        "registry_coverage",
        "json_schema_and_semantic_cases",
        "json_schema_validation_cases",
        "did_method_adapter_cases",
        "known_answer_tests",
        "identity_root_anchor_state_machine",
        "profile_discovery_coverage",
        "generated_limit_cases",
        "arkret_private_kdf_and_durability",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(registered, supported, "runner dispatcher closure drifted");

    for entry in fs::read_dir(artifacts.join("fixtures"))? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let fixture: Value = serde_json::from_slice(&fs::read(&path)?)?;
        if let Some(kind) = fixture.pointer("/runner/kind").and_then(Value::as_str) {
            assert!(
                registered.contains(kind),
                "{} declares unknown runner kind {kind}",
                path.display()
            );
        }
    }

    assert!(
        !registered.contains("unknown_runner_kind"),
        "unknown runner kinds must fail closed"
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
                "sha256": fixture_digest_hex(&bytes),
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
