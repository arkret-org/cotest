use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;

use anyhow::{Result, anyhow, bail};
use jsonschema::{Registry, Resource};
use serde_json::{Value, json};

use super::{load_artifact_json, required_str, spec_artifacts_root};

const SCHEMA_DIR: &str = "schemas";
const SCHEMA_ID_PREFIX: &str = "https://cokret.org/artifacts/";

pub fn run_schema_validation_suite() -> Result<()> {
    let root = spec_artifacts_root();
    let schema_registry = load_artifact_json("registry/schema-registry.json")?;
    let registry_entries = schema_registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("schema-registry missing schemas"))?;

    let schemas_dir = root.join(SCHEMA_DIR);
    let mut resources: Vec<(String, Value)> = Vec::new();
    for entry in fs::read_dir(&schemas_dir)? {
        let path = entry?.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let raw = fs::read_to_string(&path)?;
        let value: Value = serde_json::from_str(&raw)
            .map_err(|err| anyhow!("schema file {} invalid JSON: {err}", path.display()))?;
        let id = value
            .get("$id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("schema file {} missing $id", path.display()))?
            .to_owned();
        if !id.starts_with(SCHEMA_ID_PREFIX) {
            bail!("schema $id {id} does not use prefix {SCHEMA_ID_PREFIX}");
        }
        resources.push((id, value));
    }

    let mut builder = Registry::new();
    for (id, value) in &resources {
        builder = builder
            .add(id.as_str(), Resource::from_contents(value.clone()))
            .map_err(|err| anyhow!("registry add {id} failed: {err}"))?;
    }
    let registry = builder
        .prepare()
        .map_err(|err| anyhow!("registry prepare failed: {err}"))?;

    let mut schemas_validated = 0usize;
    let mut id_consistency_checks = 0usize;
    let mut const_consistency_checks = 0usize;
    let mut required_negative_vectors = 0usize;
    let mut nonobject_negative_vectors = 0usize;
    let mut enum_negative_vectors = 0usize;
    let mut typed_id_negative_vectors = 0usize;
    let mut compiled_property_validators = 0usize;
    let mut seen_ids = BTreeSet::new();

    for entry in registry_entries {
        let schema_id = required_str(entry, "schema_id")?;
        let file = required_str(entry, "file")?;
        let path = root.join(file);
        let raw = fs::read_to_string(&path)
            .map_err(|err| anyhow!("read schema {schema_id} from {}: {err}", path.display()))?;
        let schema_value: Value = serde_json::from_str(&raw)
            .map_err(|err| anyhow!("schema {schema_id} invalid JSON: {err}"))?;

        let actual_id = schema_value
            .get("$id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("schema {schema_id} missing $id"))?;
        let expected_id = format!("{SCHEMA_ID_PREFIX}{file}");
        if actual_id != expected_id {
            bail!("schema {schema_id} $id drift: expected {expected_id}, got {actual_id}");
        }
        if !seen_ids.insert(actual_id.to_owned()) {
            bail!("duplicate schema $id {actual_id}");
        }
        id_consistency_checks += 1;

        if let Some(schema_const) = schema_value
            .pointer("/properties/schema/const")
            .and_then(Value::as_str)
        {
            if schema_const != schema_id {
                bail!(
                    "schema {schema_id} declares properties.schema.const={schema_const} (mismatch)"
                );
            }
            const_consistency_checks += 1;
        }

        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&schema_value)
            .map_err(|err| anyhow!("compile {schema_id} failed: {err}"))?;

        if schema_value.get("type").and_then(Value::as_str) == Some("object") {
            for non_object in [json!(null), json!(42), json!("string"), json!([])] {
                if validator.is_valid(&non_object) {
                    bail!(
                        "schema {schema_id} accepted non-object payload {}",
                        non_object
                    );
                }
                nonobject_negative_vectors += 1;
            }
        }

        if let Some(required) = schema_value.get("required").and_then(Value::as_array) {
            if !required.is_empty() && validator.is_valid(&json!({})) {
                bail!(
                    "schema {schema_id} accepted empty {{}} despite {} required fields",
                    required.len()
                );
            }
            if !required.is_empty() {
                required_negative_vectors += 1;
            }
        }

        let parent_defs = schema_value.get("$defs").cloned();
        if let Some(properties) = schema_value.get("properties").and_then(Value::as_object) {
            for (field, prop) in properties {
                let mut prop_schema = prop.clone();
                if let Value::Object(map) = &mut prop_schema {
                    map.entry("$schema")
                        .or_insert(json!("https://json-schema.org/draft/2020-12/schema"));
                    if let Some(defs) = &parent_defs {
                        map.entry("$defs").or_insert_with(|| defs.clone());
                    }
                }
                let prop_validator = jsonschema::options()
                    .with_registry(&registry)
                    .with_base_uri(actual_id)
                    .build(&prop_schema)
                    .map_err(|err| anyhow!("compile property {schema_id}#{field} failed: {err}"))?;
                compiled_property_validators += 1;

                if let Some(enum_values) = prop.get("enum").and_then(Value::as_array)
                    && !enum_values.is_empty()
                {
                    let bogus = json!("__cotest_invalid_enum__");
                    if prop_validator.is_valid(&bogus) {
                        bail!("schema {schema_id} property {field} accepted invalid enum value");
                    }
                    enum_negative_vectors += 1;
                }

                if let Some(pattern) = prop.get("pattern").and_then(Value::as_str)
                    && pattern.starts_with("^ck:")
                {
                    for bogus in [json!("ck:invalid:!!!"), json!("not-a-typed-id"), json!("")] {
                        if prop_validator.is_valid(&bogus) {
                            bail!(
                                "schema {schema_id} property {field} accepted invalid typed-id {bogus}"
                            );
                        }
                        typed_id_negative_vectors += 1;
                    }
                }
            }
        }

        schemas_validated += 1;
    }

    eprintln!(
        "[cotest schema_validation] schemas={schemas_validated} \
$id_checks={id_consistency_checks} \
const_checks={const_consistency_checks} \
required_negatives={required_negative_vectors} \
nonobject_negatives={nonobject_negative_vectors} \
enum_negatives={enum_negative_vectors} \
typed_id_negatives={typed_id_negative_vectors} \
property_validators={compiled_property_validators}"
    );

    if schemas_validated < 34 {
        bail!(
            "schema validation suite covered only {schemas_validated} schemas; expected = 34 (registry has {})",
            registry_entries.len()
        );
    }
    if id_consistency_checks != schemas_validated {
        bail!(
            "$id consistency coverage drift: {id_consistency_checks} checks across {schemas_validated} schemas"
        );
    }
    if const_consistency_checks < 16 {
        bail!(
            "schema_id ↔ const consistency coverage too low: {const_consistency_checks} (expected ≥ 16)"
        );
    }
    if required_negative_vectors < 30 {
        bail!(
            "required-field negative coverage too low: {required_negative_vectors} (expected ≥ 30)"
        );
    }
    if enum_negative_vectors < 40 {
        bail!("enum negative coverage too low: {enum_negative_vectors} (expected ≥ 40)");
    }
    if typed_id_negative_vectors < 180 {
        bail!(
            "typed-id pattern negative coverage too low: {typed_id_negative_vectors} (expected ≥ 180)"
        );
    }
    if nonobject_negative_vectors < 120 {
        bail!(
            "non-object payload negative coverage too low: {nonobject_negative_vectors} (expected ≥ 120)"
        );
    }
    if compiled_property_validators < 400 {
        bail!(
            "property validator coverage too low: {compiled_property_validators} (expected ≥ 400)"
        );
    }

    Ok(())
}
