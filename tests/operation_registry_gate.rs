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
fn operation_selector_is_exact_versioned_and_route_bound() {
    let operation = arkret_wire::ServiceOperationId::from_wire("ak.server.read.describe.v1")
        .expect("registered current-v1 selector must resolve");
    assert_eq!(operation.as_str(), "ak.server.read.describe.v1");
    assert!(operation.matches_http_request("GET", "/_arkret/describe"));
    assert!(!operation.matches_http_request("POST", "/_arkret/describe"));
    assert!(!operation.matches_http_request("GET", "/_arkret/self/events"));
    assert!(arkret_wire::ServiceOperationId::from_wire("ak.server.read.describe").is_none());
    assert!(arkret_wire::ServiceOperationId::from_wire("ak.server.read.unknown.v1").is_none());
}

#[test]
fn openapi_operation_id_drift_fails() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let product_private_path = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[(
            "ak.server.read.describe.v1",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.wrong")],
    )?;
    write_json(&product_private_path, &json!({"allowed": []}))?;
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
            "ak.server.read.describe.v1",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.describe.v1")],
    )?;
    write_json(&product_private_path, &json!({"allowed": []}))?;
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
            "ak.server.read.describe.v1",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.describe.v1")],
    )?;
    write_json(
        &product_private_path,
        &json!({
            "allowed": [{
                "source": "coland",
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
        source_root("coland", &source_dir, "src/api.rs"),
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
            "ak.server.read.describe.v1",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.describe.v1")],
    )?;
    write_json(&product_private_path, &json!({"allowed": []}))?;
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
                "ak.server.read.describe.v1",
                "GET /_arkret/describe",
                "typed_response",
                None,
                None,
            ),
            (
                "ak.server.read.health.v1",
                "GET /_arkret/health",
                "typed_response",
                None,
                None,
            ),
        ],
        &[
            ("GET", "/_arkret/describe", "ak.server.read.describe.v1"),
            ("GET", "/_arkret/health", "ak.server.read.health.v1"),
        ],
    )?;
    write_json(&product_private_path, &json!({"allowed": []}))?;
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
        source_root("coland", &source_dir, "src/api.rs"),
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
        "source scans should find registered coland/SDK/inkson operations"
    );
    validate_operation_registry_gate_report(&report)?;
    assert_eq!(report.failed_entries().count(), 0);
    Ok(())
}

#[test]
fn negative_routes_are_scoped_to_one_test_file_method_and_path() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let classifications = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[(
            "ak.server.read.describe.v1",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.describe.v1")],
    )?;
    write_json(
        &classifications,
        &json!({
            "allowed": [],
            "negative_test_paths": [{
                "source": "cotest", "source_file": "src/scenarios/retired.rs",
                "method": "GET", "path": "/_arkret/self/retired",
                "reason": "The exact test asserts that this retired route returns 404."
            }]
        }),
    )?;
    write_source(
        &source_dir,
        "src/scenarios/retired.rs",
        r#"client.get_json("_arkret/self/retired")"#,
    )?;
    for (source, file, call, allowed) in [
        (
            "cotest",
            "src/scenarios/retired.rs",
            r#"client.get_json("_arkret/self/retired")"#,
            true,
        ),
        (
            "coland",
            "src/scenarios/retired.rs",
            r#"client.get_json("_arkret/self/retired")"#,
            false,
        ),
        (
            "cotest",
            "src/scenarios/elsewhere.rs",
            r#"client.get_json("_arkret/self/retired")"#,
            false,
        ),
        (
            "cotest",
            "src/scenarios/retired.rs",
            r#"client.post_json("_arkret/self/retired", &body)"#,
            false,
        ),
        (
            "cotest",
            "src/scenarios/retired.rs",
            r#"client.get_json("_arkret/self/other-retired")"#,
            false,
        ),
    ] {
        write_source(&source_dir, file, call)?;
        let report = build_operation_registry_gate_report_from_paths(paths(
            &artifacts_root,
            &classifications,
            source_root(source, &source_dir, file),
        ))?;
        assert_eq!(
            validate_operation_registry_gate_report(&report).is_ok(),
            allowed
        );
        if allowed {
            assert!(
                report
                    .entries
                    .iter()
                    .any(|entry| entry.gate_status == OperationRegistryGateStatus::NegativeTest)
            );
            assert!(
                report
                    .entries
                    .iter()
                    .all(|entry| entry.operation_id.is_none())
            );
        }
    }
    Ok(())
}

#[test]
fn metadata_values_and_url_assertions_do_not_borrow_request_methods() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let classifications = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[
            (
                "ak.self.blob.presign.v1",
                "POST /_arkret/self/blob/presign",
                "typed_response",
                None,
                None,
            ),
            (
                "ak.self.blob.resource.get.v1",
                "GET /_arkret/self/blob/get",
                "typed_response",
                None,
                None,
            ),
        ],
        &[
            (
                "POST",
                "/_arkret/self/blob/presign",
                "ak.self.blob.presign.v1",
            ),
            (
                "GET",
                "/_arkret/self/blob/get",
                "ak.self.blob.resource.get.v1",
            ),
        ],
    )?;
    write_json(&classifications, &json!({"allowed": []}))?;
    for (label, snippet, expected_paths, expected_failures) in [
        (
            "Describe base field construction",
            r#"let gate_account_base_url = format!("{account_origin}/_arkret/gate/account"); Some(AccountAuthority { gate_account_base_url, extra: Default::default() });"#,
            0,
            0,
        ),
        (
            "principal registration fixture field value",
            r#"let fixture = principal_registration_fixture(json!({"gate_account_base_url": format!("{}/_arkret/gate/account", deployment.coauth.base_url())}))?;"#,
            0,
            0,
        ),
        (
            "Describe exact metadata comparison",
            "ensure!(\n metadata[\"account_authority\"][\"gate_account_base_url\"]\n == format!(\"{origin}/_arkret/gate/account\"),\n \"gate origin mismatch\");",
            0,
            0,
        ),
        (
            "presign POST followed by URL.path GET assertion",
            "let value = expect_json(controller.post(\"/_arkret/self/blob/presign\").json(&request), OK).await?;\nlet issued = issued(value)?;\nlet url = issued.url.parse()?; ensure!(url.path() == \"/_arkret/self/blob/get\", \"path\");",
            2,
            0,
        ),
        (
            "an actual POST to the GET resource stays invalid",
            r#"client.post("/_arkret/self/blob/get");"#,
            1,
            1,
        ),
        (
            "same-line metadata cannot exempt a real unknown POST",
            r#"let gate_account_base_url = format!("{origin}/_arkret/gate/account"); client.post("/_arkret/unknown"); Some(AccountAuthority { gate_account_base_url, extra: Default::default() });"#,
            1,
            1,
        ),
        (
            "next-line metadata cannot exempt a real unknown POST",
            "let gate_account_base_url = format!(\"{origin}/_arkret/gate/account\");\nclient.post(\"/_arkret/unknown\");\nSome(AccountAuthority { gate_account_base_url, extra: Default::default() });",
            1,
            1,
        ),
        (
            "a nearby field name cannot exempt a request argument",
            r#"let field = "gate_account_base_url"; client.post(format!("{origin}/_arkret/gate/account"));"#,
            1,
            1,
        ),
        (
            "metadata beside a request in the same JSON expression",
            r#"json!({"gate_account_base_url":format!("{origin}/_arkret/gate/account"), "result":client.post("/_arkret/unknown")});"#,
            1,
            1,
        ),
        (
            "a metadata-named variable used as a bare request URL is not exempt",
            "let gate_account_base_url = format!(\"{origin}/_arkret/gate/account\");\nclient.post(&gate_account_base_url);",
            1,
            1,
        ),
        (
            "a same-line metadata-named variable request is not exempt",
            r#"let gate_account_base_url = format!("{origin}/_arkret/gate/account"); client.post(gate_account_base_url.clone());"#,
            1,
            1,
        ),
        (
            "a multiline canonical_post metadata-variable URL is not exempt",
            "let gate_account_base_url = format!(\"{origin}/_arkret/gate/account\");\ncanonical_post(\n &client,\n &gate_account_base_url,\n &body);",
            1,
            1,
        ),
        (
            "an unused metadata-named variable is not sufficient evidence",
            r#"let gate_account_base_url = format!("{origin}/_arkret/gate/account");"#,
            1,
            1,
        ),
        (
            "a real field consumer plus another request use is not exempt",
            r#"let gate_account_base_url = format!("{origin}/_arkret/gate/account"); client.post(&gate_account_base_url); Some(AccountAuthority { gate_account_base_url, extra: Default::default() });"#,
            1,
            1,
        ),
        (
            "a metadata JSON value cannot hide a nested bare POST",
            r#"json!({"gate_account_base_url": client.post(format!("{origin}/_arkret/gate/account"))});"#,
            1,
            1,
        ),
        (
            "a typed field expression call argument is not shorthand",
            r#"let gate_account_base_url = format!("{origin}/_arkret/gate/account"); Some(AccountAuthority { issuer: canonical_post(&client, gate_account_base_url, body)?.build()?.url().clone(), extra: Default::default() });"#,
            1,
            1,
        ),
        (
            "a typed named field value is not shorthand",
            r#"let gate_account_base_url = format!("{origin}/_arkret/gate/account"); Some(AccountAuthority { origin: gate_account_base_url, extra: Default::default() });"#,
            1,
            1,
        ),
        (
            "a typed field array expression is not shorthand",
            r#"let gate_account_base_url = format!("{origin}/_arkret/gate/account"); Some(AccountAuthority { origin: [first, gate_account_base_url, last], extra: Default::default() });"#,
            1,
            1,
        ),
        (
            "a quote in a block comment cannot hide an actual request use",
            "let gate_account_base_url = format!(\"{origin}/_arkret/gate/account\");\n/* \"*/ client.post(&gate_account_base_url); let s = \"*/\";\nSome(AccountAuthority { gate_account_base_url, extra: Default::default() });",
            1,
            1,
        ),
        (
            "a metadata descendant is not the Describe base value",
            r#"let gate_account_base_url = format!("{origin}/_arkret/gate/account/unknown");"#,
            1,
            1,
        ),
    ] {
        let file = "src/scenarios/probe.rs";
        write_source(&source_dir, file, snippet)?;
        let report = build_operation_registry_gate_report_from_paths(paths(
            &artifacts_root,
            &classifications,
            source_root("cotest", &source_dir, file),
        ))?;
        assert_eq!(report.entries.len(), expected_paths, "{label}");
        assert_eq!(
            report.failed_entries().count(),
            expected_failures,
            "{label}"
        );
        assert_eq!(
            validate_operation_registry_gate_report(&report).is_ok(),
            expected_failures == 0,
            "{label}"
        );
        if label == "presign POST followed by URL.path GET assertion" {
            let assertion = report
                .entries
                .iter()
                .find(|entry| entry.path == "/_arkret/self/blob/get")
                .expect("the URL assertion still checks the registered path");
            assert_eq!(assertion.method, None);
        }
        if label.contains("unknown POST")
            || label == "an actual POST to the GET resource stays invalid"
        {
            assert_eq!(
                report.failed_entries().next().unwrap().method.as_deref(),
                Some("POST"),
                "{label}"
            );
        }
    }
    Ok(())
}

#[test]
fn canonical_post_retired_erase_requires_the_exact_negative_route_triple() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let artifacts_root = temp.path().join("artifacts");
    let classifications = temp.path().join("operation-product-private-paths.json");
    let source_dir = temp.path().join("source");
    write_minimal_artifacts(
        &artifacts_root,
        &[(
            "ak.server.read.describe.v1",
            "GET /_arkret/describe",
            "typed_response",
            None,
            None,
        )],
        &[("GET", "/_arkret/describe", "ak.server.read.describe.v1")],
    )?;
    write_json(
        &classifications,
        &json!({
            "allowed": [],
            "negative_test_paths": [{
                "source": "cotest", "source_file": "src/scenarios/security_rotation_live.rs",
                "method": "POST", "path": "/_arkret/self/keys/backup-series/erase",
                "reason": "This exact retired erase probe asserts 404/unrecognized_endpoint and an unchanged listing."
            }]
        }),
    )?;
    for (source, file, method, path, allowed) in [
        (
            "cotest",
            "src/scenarios/security_rotation_live.rs",
            "post",
            "erase",
            true,
        ),
        (
            "coland",
            "src/scenarios/security_rotation_live.rs",
            "post",
            "erase",
            false,
        ),
        (
            "cotest",
            "src/scenarios/elsewhere.rs",
            "post",
            "erase",
            false,
        ),
        (
            "cotest",
            "src/scenarios/security_rotation_live.rs",
            "get",
            "erase",
            false,
        ),
        (
            "cotest",
            "src/scenarios/security_rotation_live.rs",
            "post",
            "other",
            false,
        ),
    ] {
        let snippet = format!(
            "let foreign = canonical_{method}(\n &client_a,\n \"/_arkret/self/keys/backup-series/{path}\",\n &json!({{}}),\n)?.send().await?;"
        );
        write_source(&source_dir, file, &snippet)?;
        let report = build_operation_registry_gate_report_from_paths(paths(
            &artifacts_root,
            &classifications,
            source_root(source, &source_dir, file),
        ))?;
        assert_eq!(report.entries.len(), 1);
        assert_eq!(
            report.entries[0].method.as_deref(),
            Some(if method == "post" { "POST" } else { "GET" })
        );
        assert_eq!(
            validate_operation_registry_gate_report(&report).is_ok(),
            allowed
        );
        assert_eq!(
            report.entries[0].gate_status == OperationRegistryGateStatus::NegativeTest,
            allowed
        );
        assert!(report.entries[0].operation_id.is_none());
    }
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
        let endpoint_id = operation_id
            .rsplit_once(".v")
            .filter(|(_, version)| {
                !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
            })
            .map_or(*operation_id, |(endpoint_id, _)| endpoint_id);
        let item = paths
            .entry((*path).to_owned())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        item.as_object_mut().expect("path item is object").insert(
            method.to_ascii_lowercase(),
            json!({"operationId": endpoint_id, "responses": {"200": {"description": "ok"}}}),
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
