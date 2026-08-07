use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use arkret_policy::authz::ResourceSelector;
use serde::Deserialize;
use serde_json::{Value, json};

const OPERATION_REGISTRY: &str = "registry/operation-registry.json";
const OPERATION_SCHEMA_INDEX: &str = "reports/operation-schema-index.json";

#[derive(Debug, Deserialize)]
struct OperationRegistry {
    operations: Vec<RegistryOperation>,
}

#[derive(Debug, Deserialize)]
struct RegistryOperation {
    operation_id: String,
    http: String,
    success_shape_kind: String,
}

#[derive(Debug, Deserialize)]
struct OperationSchemaIndex {
    operations: Vec<SchemaIndexOperation>,
}

#[derive(Debug, Deserialize)]
struct SchemaIndexOperation {
    operation_id: String,
    success_shape_kind: String,
    response: Option<ObjectShape>,
}

#[derive(Debug, Deserialize)]
struct ObjectShape {
    schema_ref: Option<String>,
    schema_kind: Option<String>,
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    properties: Vec<String>,
    closed: bool,
}

#[test]
fn resource_selector_rejects_legacy_schema_id_fields() {
    let realm_id = "ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_";
    let schema_ref = "ak.schema.strand.v1";

    let canonical = ResourceSelector::from_spec_value(&json!({
        "kind": "schema",
        "realm_id": realm_id,
        "schema_ref": schema_ref
    }))
    .expect("canonical schema_ref selector must parse");
    let encoded = canonical.to_spec_value();
    assert_eq!(encoded.get("schema_ref"), Some(&json!(schema_ref)));
    assert_eq!(encoded.get("schema_id"), None);

    for legacy in [
        json!({
            "kind": "schema",
            "realm_id": realm_id,
            "schema_id": schema_ref
        }),
        json!({
            "kind": "schema",
            "realm_id": realm_id,
            "schema_ref": schema_ref,
            "schema_id": schema_ref
        }),
    ] {
        let error = ResourceSelector::from_spec_value(&legacy)
            .expect_err("schema_id must never be accepted as an alias")
            .to_string();
        assert!(
            error.contains("schema_id"),
            "legacy-field rejection should identify schema_id, got: {error}"
        );
    }
}

#[test]
fn simple_mutations_reject_legacy_success_discriminators() -> Result<()> {
    let registry: OperationRegistry = load_artifact(OPERATION_REGISTRY)?;
    let schema_index: OperationSchemaIndex = load_artifact(OPERATION_SCHEMA_INDEX)?;
    let registry_by_id = registry
        .operations
        .into_iter()
        .map(|operation| (operation.operation_id.clone(), operation))
        .collect::<BTreeMap<_, _>>();

    let mut checked_simple_mutations = 0usize;
    for operation in &schema_index.operations {
        let Some(shape) = operation.response.as_ref() else {
            continue;
        };
        if shape.schema_kind.as_deref() != Some("object")
            || !shape.required.iter().any(|field| field == "ok")
        {
            continue;
        }

        let registry_operation = registry_by_id.get(&operation.operation_id).ok_or_else(|| {
            anyhow!(
                "schema index operation {} is absent from the registry",
                operation.operation_id
            )
        })?;
        if registry_operation.success_shape_kind != operation.success_shape_kind {
            bail!(
                "{} success_shape_kind drift: registry={}, schema_index={}",
                operation.operation_id,
                registry_operation.success_shape_kind,
                operation.success_shape_kind
            );
        }
        if registry_operation.http.starts_with("GET ")
            || registry_operation.http.starts_with("HEAD ")
        {
            continue;
        }

        let canonical_fields = shape
            .required
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert!(
            accepts_top_level_fields(shape, &canonical_fields),
            "{} canonical required fields must satisfy {}",
            operation.operation_id,
            shape
                .schema_ref
                .as_deref()
                .unwrap_or("inline response shape")
        );

        for alias in ["deleted", "accepted"] {
            let alias_instead_of_ok = shape
                .required
                .iter()
                .map(String::as_str)
                .filter(|field| *field != "ok")
                .chain(std::iter::once(alias))
                .collect::<Vec<_>>();
            assert!(
                !accepts_top_level_fields(shape, &alias_instead_of_ok),
                "{} must reject legacy {alias} in place of ok",
                operation.operation_id
            );
        }

        if !shape.properties.iter().any(|field| field == "deleted")
            && !shape.properties.iter().any(|field| field == "accepted")
        {
            for alias in ["deleted", "accepted"] {
                let dual_write = canonical_fields
                    .iter()
                    .copied()
                    .chain(std::iter::once(alias))
                    .collect::<Vec<_>>();
                assert!(
                    !accepts_top_level_fields(shape, &dual_write),
                    "{} closed simple-mutation response must reject undeclared {alias}",
                    operation.operation_id
                );
            }
            checked_simple_mutations += 1;
        }
    }

    assert!(
        checked_simple_mutations >= 20,
        "expected broad simple-mutation coverage, checked {checked_simple_mutations} operations"
    );

    assert_typed_business_value_allowed(
        &schema_index,
        "ak.self.events.command.submit",
        &json!({"status": "accepted", "accepted": []}),
    )?;
    assert_typed_business_value_allowed(
        &schema_index,
        "ak.self.keys.backups.resource.delete",
        &json!({
            "deleted": true,
            "backup_id": "ak:backup:01964137-0000-7000-8000-000000000000"
        }),
    )?;
    Ok(())
}

fn accepts_top_level_fields(shape: &ObjectShape, fields: &[&str]) -> bool {
    let fields = fields.iter().copied().collect::<BTreeSet<_>>();
    let has_required = shape
        .required
        .iter()
        .all(|required| fields.contains(required.as_str()));
    let has_only_declared = !shape.closed
        || fields
            .iter()
            .all(|field| shape.properties.iter().any(|property| property == field));
    has_required && has_only_declared
}

fn assert_typed_business_value_allowed(
    schema_index: &OperationSchemaIndex,
    operation_id: &str,
    value: &Value,
) -> Result<()> {
    let operation = schema_index
        .operations
        .iter()
        .find(|operation| operation.operation_id == operation_id)
        .ok_or_else(|| anyhow!("schema index missing typed operation {operation_id}"))?;
    if operation.success_shape_kind != "typed_response" {
        bail!(
            "{operation_id} should remain typed_response, got {}",
            operation.success_shape_kind
        );
    }
    let shape = operation
        .response
        .as_ref()
        .ok_or_else(|| anyhow!("typed operation {operation_id} is missing a response shape"))?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("typed response fixture for {operation_id} must be an object"))?;
    let fields = object.keys().map(String::as_str).collect::<Vec<_>>();
    assert!(
        accepts_top_level_fields(shape, &fields),
        "typed business fields for {operation_id} must remain distinct from rejected legacy fields"
    );
    if let Some(accepted) = object.get("accepted") {
        assert!(
            accepted.is_array(),
            "typed accepted business field for {operation_id} must remain an array"
        );
    }
    Ok(())
}

fn load_artifact<T>(relative: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let path = spec_artifacts_root().join(relative);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read spec artifact {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse spec artifact {}", path.display()))
}

fn spec_artifacts_root() -> PathBuf {
    std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("arkret-spec")
                .join("spec")
                .join("v1")
                .join("artifacts")
        })
}
