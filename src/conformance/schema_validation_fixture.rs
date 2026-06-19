//! Round 4 / A2 — schema-validation-fixture runner.
//!
//! Loads
//! `cokret-spec/spec/v1/artifacts/fixtures/schema-validation-fixture.json`
//! and runs each positive/negative case against the schema referenced by
//! `schema_ref`. `schema_ref` syntax (mirrors the Python lint
//! `check_fixture_schema_validation_cases`):
//!
//! ```text
//! schemas/<name>.schema.json                         -- whole schema
//! schemas/<name>.schema.json#/$defs/<subschema>      -- sub-schema fragment
//! openapi/cokret-service-api.openapi.yaml#/components/schemas/<Name>
//!                                                   -- OpenAPI component
//! ```
//!
//! Positive cases (`expect_valid: true`) MUST pass schema validation;
//! negative cases (`expect_valid: false`) MUST fail. Any drift is a hard
//! cotest failure.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use jsonschema::{Registry, Resource};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{fixture_path, spec_artifacts_root, validate_profile};

/// Canonical fixture filename.
pub const SCHEMA_VALIDATION_FIXTURE: &str = "schema-validation-fixture.json";

/// Canonical conformance profile pin.
pub const SCHEMA_VALIDATION_PROFILE: &str = "ck.profile.privacy_security_vectors.v1";

const SCHEMA_DIR: &str = "schemas";
const SCHEMA_ID_PREFIX: &str = "https://cokret.io/artifacts/";
const OPENAPI_FILE: &str = "openapi/cokret-service-api.openapi.yaml";

#[derive(Clone, Debug, Deserialize)]
pub struct SchemaValidationFixture {
    pub suite: String,
    pub profile: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub schema_validation_cases: Vec<SchemaValidationCase>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SchemaValidationCase {
    pub name: String,
    pub schema_ref: String,
    #[serde(default = "default_true")]
    pub expect_valid: bool,
    pub instance: Value,
}

fn default_true() -> bool {
    true
}

/// Public entry point: load the canonical fixture and run every case.
pub fn run_schema_validation_fixture_suite() -> Result<()> {
    let path = fixture_path(SCHEMA_VALIDATION_FIXTURE);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read schema-validation-fixture {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse schema-validation-fixture {}", path.display()))?;
    validate_profile(&value, SCHEMA_VALIDATION_PROFILE)?;
    let fixture: SchemaValidationFixture = serde_json::from_value(value)
        .with_context(|| format!("decode schema-validation-fixture {}", path.display()))?;
    if fixture.suite != "schema_validation" {
        bail!(
            "schema-validation-fixture suite drifted: expected `schema_validation`, got `{}`",
            fixture.suite
        );
    }
    run_cases(&fixture.schema_validation_cases)
}

/// Run the supplied cases. Public for tests.
pub fn run_cases(cases: &[SchemaValidationCase]) -> Result<()> {
    if cases.is_empty() {
        bail!("schema-validation-fixture has zero cases");
    }
    let env = SchemaEnv::load()?;
    let mut positives = 0usize;
    let mut negatives = 0usize;
    for case in cases {
        let validator = env.compile(&case.schema_ref)?;
        let is_valid = validator.is_valid(&case.instance);
        if case.expect_valid && !is_valid {
            // Pull the first error for diagnostics.
            let detail = validator
                .iter_errors(&case.instance)
                .next()
                .map(|e| format!("{e}"))
                .unwrap_or_else(|| "<no error reported>".to_string());
            bail!(
                "schema_validation_cases[{}]: positive case rejected by `{}`: {detail}",
                case.name,
                case.schema_ref,
            );
        }
        if !case.expect_valid && is_valid {
            bail!(
                "schema_validation_cases[{}]: negative case accepted by `{}` (expected failure)",
                case.name,
                case.schema_ref,
            );
        }
        if case.expect_valid {
            positives += 1;
        } else {
            negatives += 1;
        }
    }
    eprintln!(
        "[cotest schema_validation_fixture] cases={} positive={positives} negative={negatives}",
        cases.len()
    );
    Ok(())
}

/// Lazy schema/registry environment that caches:
/// * the parsed JSON-Schema source documents
/// * the openapi YAML doc (parsed once)
///
/// `jsonschema::Registry` borrows the supplied resources and is
/// builder-only — we cannot stash a prepared Registry into a field and
/// then hand out validators that outlive a builder borrow. Compiling a
/// validator is the cheap path here (≤34 schemas, no network IO), so we
/// rebuild the registry inline per `compile()` call. The resulting
/// `Validator` is owned and outlives the borrowed registry.
pub(crate) struct SchemaEnv {
    resources: Vec<(String, Value)>,
    schemas_by_file: HashMap<String, Value>,
    openapi: Option<Value>,
}

impl SchemaEnv {
    pub(crate) fn load() -> Result<Self> {
        let artifacts_root = spec_artifacts_root();
        let schemas_dir = artifacts_root.join(SCHEMA_DIR);
        let mut resources: Vec<(String, Value)> = Vec::new();
        let mut schemas_by_file: HashMap<String, Value> = HashMap::new();
        for entry in fs::read_dir(&schemas_dir)
            .with_context(|| format!("read schemas dir {}", schemas_dir.display()))?
        {
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
            let rel = format!(
                "{SCHEMA_DIR}/{}",
                path.file_name()
                    .and_then(OsStr::to_str)
                    .ok_or_else(|| anyhow!("schema filename invalid"))?
            );
            schemas_by_file.insert(rel, value.clone());
            resources.push((id, value));
        }

        let openapi_path = artifacts_root.join(OPENAPI_FILE);
        let openapi = if openapi_path.is_file() {
            let raw = fs::read_to_string(&openapi_path)
                .with_context(|| format!("read openapi {}", openapi_path.display()))?;
            let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&raw)?;
            Some(yaml_to_json(&yaml)?)
        } else {
            None
        };

        Ok(Self {
            resources,
            schemas_by_file,
            openapi,
        })
    }

    pub(crate) fn compile(&self, schema_ref: &str) -> Result<jsonschema::Validator> {
        let (schema_value, base_uri) = self.resolve_schema_ref(schema_ref)?;
        let mut builder = Registry::new();
        for (id, value) in &self.resources {
            builder = builder
                .add(id.as_str(), Resource::from_contents(value.clone()))
                .map_err(|err| anyhow!("registry add {id} failed: {err}"))?;
        }
        let registry = builder
            .prepare()
            .map_err(|err| anyhow!("registry prepare failed: {err}"))?;
        let mut opts = jsonschema::options().with_registry(&registry);
        if let Some(base) = base_uri {
            opts = opts.with_base_uri(base);
        }
        opts.build(&schema_value)
            .map_err(|err| anyhow!("compile schema_ref `{schema_ref}` failed: {err}"))
    }

    /// Resolve a `schema_ref` to a JSON Schema value + optional base URI.
    ///
    /// Returns the schema value (already seeded with `$schema` and `$defs`
    /// when appropriate) and a base URI for ref resolution.
    fn resolve_schema_ref(&self, schema_ref: &str) -> Result<(Value, Option<String>)> {
        // Three shapes the fixture uses:
        //  (a) `schemas/<file>.schema.json`
        //  (b) `schemas/<file>.schema.json#/$defs/<name>`
        //  (c) `openapi/cokret-service-api.openapi.yaml#/components/schemas/<Name>`
        if let Some(rest) = schema_ref.strip_prefix("schemas/") {
            let (file_path, fragment) = split_fragment(rest);
            let key = format!("{SCHEMA_DIR}/{file_path}");
            let parent = self
                .schemas_by_file
                .get(&key)
                .ok_or_else(|| anyhow!("schema_ref points at unknown file `{schema_ref}`"))?;
            let base_uri = parent.get("$id").and_then(Value::as_str).map(str::to_owned);
            let mut schema = if let Some(fragment) = fragment {
                let pointer = format!("/{}", fragment.trim_start_matches('/'));
                let value = parent.pointer(&pointer).ok_or_else(|| {
                    anyhow!("schema_ref fragment not found in {schema_ref}: {pointer}")
                })?;
                value.clone()
            } else {
                parent.clone()
            };

            // Seed `$schema` and inherit `$defs` so a fragment compiles
            // standalone but can still resolve sibling defs.
            if let Value::Object(map) = &mut schema {
                map.entry("$schema")
                    .or_insert(json!("https://json-schema.org/draft/2020-12/schema"));
                if let Some(defs) = parent.get("$defs") {
                    map.entry("$defs").or_insert_with(|| defs.clone());
                }
            }
            return Ok((schema, base_uri));
        }
        if let Some(rest) = schema_ref.strip_prefix("openapi/") {
            // We only support OpenAPI refs that target
            // `#/components/schemas/<Name>` — the only form this fixture
            // uses today. If a new form lands, surface a clear error.
            let openapi = self.openapi.as_ref().ok_or_else(|| {
                anyhow!("openapi document not loaded; cannot resolve `{schema_ref}`")
            })?;
            let (file_path, fragment) = split_fragment(rest);
            if file_path != "cokret-service-api.openapi.yaml" {
                bail!("schema_ref points at unknown openapi file: {file_path}");
            }
            let fragment =
                fragment.ok_or_else(|| anyhow!("openapi schema_ref missing component fragment"))?;
            let pointer = format!("/{}", fragment.trim_start_matches('/'));
            let component = openapi
                .pointer(&pointer)
                .ok_or_else(|| anyhow!("openapi component not found: {pointer}"))?;
            // Inline shared component schemas referenced by this component
            // so we don't need a separate openapi-aware registry.
            let inlined = inline_openapi_refs(component, openapi)?;
            let base_uri = Some(format!(
                "{SCHEMA_ID_PREFIX}openapi/cokret-service-api.openapi.yaml"
            ));
            let mut schema = inlined;
            if let Value::Object(map) = &mut schema {
                map.entry("$schema")
                    .or_insert(json!("https://json-schema.org/draft/2020-12/schema"));
            }
            return Ok((schema, base_uri));
        }
        bail!("unsupported schema_ref shape: {schema_ref}")
    }
}

fn split_fragment(input: &str) -> (&str, Option<&str>) {
    match input.find('#') {
        Some(idx) => (&input[..idx], Some(&input[idx + 1..])),
        None => (input, None),
    }
}

fn yaml_to_json(value: &serde_yaml_ng::Value) -> Result<Value> {
    // Round-trip via serde_json to swap representations.
    let s = serde_json::to_string(&value)
        .map_err(|err| anyhow!("yaml to json round-trip failed: {err}"))?;
    serde_json::from_str(&s).map_err(|err| anyhow!("re-decode yaml-as-json failed: {err}"))
}

/// Inline every `{ "$ref": "#/components/schemas/Name" }` reference found
/// inside `value` against `openapi`. The substitution is shallow-deep —
/// we recursively walk arrays/objects but stop expanding after a single
/// substitution cycle to avoid infinite recursion on self-referential
/// components.
fn inline_openapi_refs(value: &Value, openapi: &Value) -> Result<Value> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    inline_openapi_refs_inner(value, openapi, &mut seen, 0)
}

fn inline_openapi_refs_inner(
    value: &Value,
    openapi: &Value,
    seen: &mut std::collections::HashSet<String>,
    depth: usize,
) -> Result<Value> {
    if depth > 16 {
        // Hard ceiling — should never happen for our fixture but protects
        // against pathological future openapi authoring.
        return Ok(value.clone());
    }
    match value {
        Value::Object(map) => {
            if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                if let Some(component_name) = reference.strip_prefix("#/components/schemas/") {
                    if seen.contains(component_name) {
                        // Cycle: leave the reference as-is and let
                        // jsonschema handle it (or fail). For our fixture
                        // there are no cycles, so this path is unused.
                        return Ok(value.clone());
                    }
                    let pointer = format!("/components/schemas/{component_name}");
                    let resolved = openapi
                        .pointer(&pointer)
                        .ok_or_else(|| anyhow!("openapi $ref target missing: {reference}"))?;
                    seen.insert(component_name.to_string());
                    let expanded = inline_openapi_refs_inner(resolved, openapi, seen, depth + 1)?;
                    seen.remove(component_name);
                    return Ok(expanded);
                }
            }
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(
                    k.clone(),
                    inline_openapi_refs_inner(v, openapi, seen, depth + 1)?,
                );
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(inline_openapi_refs_inner(item, openapi, seen, depth + 1)?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_fixture_runs() {
        run_schema_validation_fixture_suite()
            .expect("schema-validation-fixture cases should all match expectations");
    }
}
