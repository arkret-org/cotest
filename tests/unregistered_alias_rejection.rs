use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use arkret_wire::WireResourceSelector;
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
fn resource_selector_rejects_unregistered_schema_id_fields() {
    let realm_id = "ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_";
    let schema_ref = "ak.schema.strand.v1";

    let canonical: WireResourceSelector = serde_json::from_value(json!({
        "kind": "schema",
        "realm_id": realm_id,
        "schema_ref": schema_ref
    }))
    .expect("canonical schema_ref selector must parse");
    let encoded = serde_json::to_value(canonical).expect("selector must serialize");
    assert_eq!(encoded.get("schema_ref"), Some(&json!(schema_ref)));
    assert_eq!(encoded.get("schema_id"), None);

    for unregistered in [
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
        let error = serde_json::from_value::<WireResourceSelector>(unregistered)
            .expect_err("schema_id must never be accepted as an alias")
            .to_string();
        assert!(
            error.contains("schema_id"),
            "unregistered-field rejection should identify schema_id, got: {error}"
        );
    }
}

#[test]
fn simple_mutations_reject_unregistered_success_discriminators() -> Result<()> {
    let registry: OperationRegistry = load_artifact(OPERATION_REGISTRY)?;
    let schema_index: OperationSchemaIndex = load_artifact(OPERATION_SCHEMA_INDEX)?;
    let registry_by_id = registry
        .operations
        .into_iter()
        .map(|operation| (operation.operation_id.clone(), operation))
        .collect::<BTreeMap<_, _>>();

    let mut checked_success_objects = 0usize;
    for operation in &schema_index.operations {
        let Some(shape) = operation.response.as_ref() else {
            continue;
        };
        if shape.schema_kind.as_deref() != Some("object") {
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
        assert!(
            !shape.required.iter().any(|field| field == "ok")
                && !shape.properties.iter().any(|field| field == "ok"),
            "{} must not retain the retired generic success discriminator `ok`",
            operation.operation_id
        );

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

        if shape.closed {
            let with_retired_ok = canonical_fields
                .iter()
                .copied()
                .chain(std::iter::once("ok"))
                .collect::<Vec<_>>();
            assert!(
                !accepts_top_level_fields(shape, &with_retired_ok),
                "{} closed response must reject retired `ok`",
                operation.operation_id
            );
        }
        checked_success_objects += 1;
    }

    assert!(
        checked_success_objects >= 50,
        "expected broad success-object coverage, checked {checked_success_objects} operations"
    );

    // The self Event submit answers with the closed AuthoritySubmitOutcome
    // schema resource, and the backups delete succeeds empty
    // (key-management.md 7.8/7.8.1: a byte-identical retry returns the same
    // empty body), so the typed-response half of this contract is carried by
    // a mutation that does return business fields.
    assert_typed_business_value_allowed(
        &schema_index,
        "ak.self.keys.keypackages.command.revoke.v1",
        &json!({"revoked": [], "failures": []}),
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
        "typed business fields for {operation_id} must remain distinct from rejected unregistered fields"
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
