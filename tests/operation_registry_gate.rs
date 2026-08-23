use std::fs;
use std::path::Path;

use anyhow::Result;
use cotest::conformance::{
    OperationRegistryGatePaths, OperationRegistryGateStatus, OperationSourceRoot,
    build_operation_registry_gate_report, build_operation_registry_gate_report_from_paths,
    validate_operation_registry_gate_report,
};
use serde_json::{Value, json};

#[test]
fn openapi_operation_id_drift_fails() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let product_private_path = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[(
            "ak.server.read.describe",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.wrong")],
    )?;
    write_json(
        &product_private_path,
        &json!({"schema": "cotest.operation-product-private-paths.v1", "allowed": []}),
    )?;
    write_source(
        &source_dir,
        "src/api.rs",
        r#"client.get_json("_arkret/describe")"#,
    )?;

    let report = build_operation_registry_gate_report_from_paths(paths(
        &artifacts_root,
        &product_private_path,
        source_root("sdk", &source_dir, "src/api.rs"),
    ))?;
    let error = validate_operation_registry_gate_report(&report)
        .expect_err("OpenAPI operationId drift must fail")
        .to_string();
    assert!(error.contains("operationId drift"));
    assert!(error.contains("ak.server.read.wrong"));
    Ok(())
}

#[test]
fn unregistered_source_path_without_product_private_classification_fails() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let product_private_path = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[(
            "ak.server.read.describe",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.describe")],
    )?;
    write_json(
        &product_private_path,
        &json!({"schema": "cotest.operation-product-private-paths.v1", "allowed": []}),
    )?;
    write_source(
        &source_dir,
        "src/api.rs",
        r#"client.post_json("_arkret/self/private-control", &body)"#,
    )?;

    let report = build_operation_registry_gate_report_from_paths(paths(
        &artifacts_root,
        &product_private_path,
        source_root("inkson", &source_dir, "src/api.rs"),
    ))?;
    assert_eq!(report.failed_entries().count(), 1);
    let error = validate_operation_registry_gate_report(&report)
        .expect_err("unregistered source path must fail")
        .to_string();
    assert!(error.contains("/_arkret/self/private-control"));
    assert!(error.contains("product-private"));
    Ok(())
}

#[test]
fn product_private_source_path_is_explicitly_allowed() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let product_private_path = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[(
            "ak.server.read.describe",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.describe")],
    )?;
    write_json(
        &product_private_path,
        &json!({
            "schema": "cotest.operation-product-private-paths.v1",
            "allowed": [{
                "source": "soland",
                "method": "POST",
                "path": "/_arkret/self/private-control",
                "classification": "product-private",
                "reason": "deployment-local control surface"
            }]
        }),
    )?;
    write_source(
        &source_dir,
        "src/api.rs",
        r#"Router::with_path("_arkret/self/private-control").post(handler)"#,
    )?;

    let report = build_operation_registry_gate_report_from_paths(paths(
        &artifacts_root,
        &product_private_path,
        source_root("soland", &source_dir, "src/api.rs"),
    ))?;
    validate_operation_registry_gate_report(&report)?;
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.path == "/_arkret/self/private-control")
        .expect("source path should be observed");
    assert_eq!(
        entry.gate_status,
        OperationRegistryGateStatus::ProductPrivate
    );
    assert!(
        entry
            .reason
            .as_deref()
            .is_some_and(|reason| !reason.is_empty())
    );
    Ok(())
}

#[test]
fn cotest_spec_files_are_scanned() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let product_private_path = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[(
            "ak.server.read.describe",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.describe")],
    )?;
    write_json(
        &product_private_path,
        &json!({"schema": "cotest.operation-product-private-paths.v1", "allowed": []}),
    )?;
    write_source(
        &source_dir,
        "e2e/tests/self-gate.spec.ts",
        r#"await request.post(`${base}/_arkret/self/private-test`, { data: {} });"#,
    )?;

    let report = build_operation_registry_gate_report_from_paths(paths(
        &artifacts_root,
        &product_private_path,
        OperationSourceRoot::new("cotest", &source_dir).with_dir("e2e/tests"),
    ))?;
    let error = validate_operation_registry_gate_report(&report)
        .expect_err("cotest .spec.ts paths must be scanned")
        .to_string();
    assert!(error.contains("cotest POST /_arkret/self/private-test"));
    Ok(())
}

#[test]
fn rust_cfg_test_items_are_not_treated_as_production_operations() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let product_private_path = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[
            (
                "ak.server.read.describe",
                "GET /_arkret/describe",
                "typed_response",
                None,
                None,
            ),
            (
                "ak.server.read.health",
                "GET /_arkret/health",
                "typed_response",
                None,
                None,
            ),
        ],
        &[
            ("GET", "/_arkret/describe", "ak.server.read.describe"),
            ("GET", "/_arkret/health", "ak.server.read.health"),
        ],
    )?;
    write_json(
        &product_private_path,
        &json!({"schema": "cotest.operation-product-private-paths.v1", "allowed": []}),
    )?;
    write_source(
        &source_dir,
        "src/api.rs",
        r#"
fn production_call() {
    client.get_json("/_arkret/describe");
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_an_unregistered_test_vector() {
        assert_rejected("POST", "/_arkret/self/test-only-invalid");
    }
}

#[cfg(test)]
fn one_line_test_item() { assert_rejected("POST", "/_arkret/self/also-test-only"); }

fn production_call_after_test_item() {
    client.get_json("/_arkret/health");
}
"#,
    )?;

    let report = build_operation_registry_gate_report_from_paths(paths(
        &artifacts_root,
        &product_private_path,
        source_root("soland", &source_dir, "src/api.rs"),
    ))?;
    validate_operation_registry_gate_report(&report)?;
    assert!(report.entries.iter().all(|entry| !matches!(
        entry.path.as_str(),
        "/_arkret/self/test-only-invalid" | "/_arkret/self/also-test-only"
    )));
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.path == "/_arkret/health")
    );
    Ok(())
}

#[test]
fn current_workspace_operation_registry_gate_passes() -> Result<()> {
    let report = build_operation_registry_gate_report()?;
    assert!(
        report.registry_operation_count > 100,
        "real operation registry should expose the generated protocol catalog"
    );
    assert!(
        report.registered_entries().count() > 20,
        "source scans should find registered soland/SDK/inkson operations"
    );
    validate_operation_registry_gate_report(&report)?;
    assert_eq!(report.failed_entries().count(), 0);
    Ok(())
}

fn paths(
    artifacts_root: &Path,
    product_private_path: &Path,
    source_root: OperationSourceRoot,
) -> OperationRegistryGatePaths {
    OperationRegistryGatePaths {
        artifacts_root: artifacts_root.to_owned(),
        product_private_path: product_private_path.to_owned(),
        source_roots: vec![source_root],
    }
}

fn source_root(source: &str, root: &Path, include_file: &str) -> OperationSourceRoot {
    OperationSourceRoot::new(source, root).with_file(include_file)
}

fn write_source(root: &Path, relative: &str, source: &str) -> Result<()> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, source)?;
    Ok(())
}

type RegistryOperationFixture<'a> = (&'a str, &'a str, &'a str, Option<&'a str>, Option<&'a str>);

fn write_minimal_artifacts(
    artifacts_root: &Path,
    registry_operations: &[RegistryOperationFixture<'_>],
    openapi_operations: &[(&str, &str, &str)],
) -> Result<()> {
    let registry_rows = registry_operations
        .iter()
        .map(
            |(operation_id, http, success_shape_kind, request_schema_ref, response_schema_ref)| {
                let mut row = json!({
                    "operation_id": operation_id,
                    "http": http,
                    "success_shape_kind": success_shape_kind
                });
                if let Some(request_schema_ref) = request_schema_ref {
                    row["request_schema_ref"] = json!(request_schema_ref);
                }
                if let Some(response_schema_ref) = response_schema_ref {
                    row["response_schema_ref"] = json!(response_schema_ref);
                }
                row
            },
        )
        .collect::<Vec<_>>();
    write_json(
        &artifacts_root
            .join("registry")
            .join("operation-registry.json"),
        &json!({
            "version": "test",
            "operations": registry_rows
        }),
    )?;
    write_json(
        &artifacts_root
            .join("registry")
            .join("event-kind-registry.json"),
        &json!({
            "version": "test",
            "event_kinds": [],
            "actor_private_contracts": {
                "cell_families": {},
                "event_writes": {}
            }
        }),
    )?;

    let mut paths = serde_json::Map::new();
    for (method, path, operation_id) in openapi_operations {
        let item = paths
            .entry((*path).to_owned())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        item.as_object_mut().expect("path item is object").insert(
            method.to_ascii_lowercase(),
            json!({"operationId": operation_id, "responses": {"200": {"description": "ok"}}}),
        );
    }
    write_json(
        &artifacts_root
            .join("openapi")
            .join("arkret-service-api.openapi.yaml"),
        &json!({"openapi": "3.1.0", "paths": Value::Object(paths)}),
    )?;

    write_json(
        &artifacts_root
            .join("reports")
            .join("operation-completeness-report.json"),
        &json!({
            "version": "test",
            "operations": registry_operations
                .iter()
                .map(|(operation_id, http, _, _, _)| json!({
                    "operation_id": operation_id,
                    "http": http
                }))
                .collect::<Vec<_>>()
        }),
    )?;

    write_json(
        &artifacts_root
            .join("reports")
            .join("operation-schema-index.json"),
        &json!({
            "version": "test",
            "operations": registry_operations
                .iter()
                .filter(|(_, _, _, request_schema_ref, response_schema_ref)| {
                    request_schema_ref.is_some() || response_schema_ref.is_some()
                })
                .map(|(operation_id, _, success_shape_kind, _, _)| json!({
                    "operation_id": operation_id,
                    "success_shape_kind": success_shape_kind
                }))
                .collect::<Vec<_>>()
        }),
    )
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
