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
            "ck.server.query.describe",
            "GET /_cokret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_cokret/describe", "ck.server.query.wrong")],
    )?;
    write_json(
        &product_private_path,
        &json!({"schema": "cotest.operation-product-private-paths.v1", "allowed": []}),
    )?;
    write_source(
        &source_dir,
        "src/api.rs",
        r#"client.get_json("_cokret/describe")"#,
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
    assert!(error.contains("ck.server.query.wrong"));
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
            "ck.server.query.describe",
            "GET /_cokret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_cokret/describe", "ck.server.query.describe")],
    )?;
    write_json(
        &product_private_path,
        &json!({"schema": "cotest.operation-product-private-paths.v1", "allowed": []}),
    )?;
    write_source(
        &source_dir,
        "src/api.rs",
        r#"client.post_json("_cokret/self/private-control", &body)"#,
    )?;

    let report = build_operation_registry_gate_report_from_paths(paths(
        &artifacts_root,
        &product_private_path,
        source_root("yougen", &source_dir, "src/api.rs"),
    ))?;
    assert_eq!(report.failed_entries().count(), 1);
    let error = validate_operation_registry_gate_report(&report)
        .expect_err("unregistered source path must fail")
        .to_string();
    assert!(error.contains("/_cokret/self/private-control"));
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
            "ck.server.query.describe",
            "GET /_cokret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_cokret/describe", "ck.server.query.describe")],
    )?;
    write_json(
        &product_private_path,
        &json!({
            "schema": "cotest.operation-product-private-paths.v1",
            "allowed": [{
                "source": "soland",
                "method": "POST",
                "path": "/_cokret/self/private-control",
                "classification": "product-private",
                "reason": "deployment-local control surface"
            }]
        }),
    )?;
    write_source(
        &source_dir,
        "src/api.rs",
        r#"Router::with_path("_cokret/self/private-control").post(handler)"#,
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
        .find(|entry| entry.path == "/_cokret/self/private-control")
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
fn current_workspace_operation_registry_gate_passes() -> Result<()> {
    let report = build_operation_registry_gate_report()?;
    assert!(
        report.registry_operation_count > 100,
        "real operation registry should expose the generated protocol catalog"
    );
    assert!(
        report.registered_entries().count() > 20,
        "source scans should find registered soland/SDK/yougen operations"
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

fn write_minimal_artifacts(
    artifacts_root: &Path,
    registry_operations: &[(&str, &str, &str, Option<&str>, Option<&str>)],
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
            .join("cokret-service-api.openapi.yaml"),
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
