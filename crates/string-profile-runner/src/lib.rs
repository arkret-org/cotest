//! Executable Arkret string-profile vectors.
//!
//! Each formal schema fragment is registered in the SDK production
//! [`ProtocolSchemaRegistry`]. A second registry removes only the custom
//! `format` keyword, proving whether each negative belongs to the coarse schema
//! layer or to the normative Unicode/domain profile validator.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_schema::{ProtocolSchemaRegistry, SchemaError};
use serde_json::Value;

pub const STRING_PROFILE_ENTRYPOINT: &str = "ak.suite.encoding.string_profiles.v1";
pub const FIXTURE: &str = "string-profile-fixture.json";
const SCHEMA: &str = "string-profiles.schema.json";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct StringConsumerState {
    accepted_projection: BTreeMap<String, Value>,
    outbound_projection: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorExecutionResult {
    pub vector_id: String,
    pub assertions: usize,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub profile_validator_rejections: usize,
    pub schema_pattern_rejections: usize,
    pub accepted_projection_count: usize,
    pub outbound_projection_count: usize,
    pub rejected_state_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StringProfileExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub vectors: Vec<VectorExecutionResult>,
}

impl StringProfileExecution {
    fn assert_complete_against(&self, fixture: &Value) -> Result<()> {
        let declared = fixture_vectors(fixture)?;
        ensure!(declared.len() == self.vectors.len(), "vector count drifted");
        for (index, (vector, result)) in declared.iter().zip(&self.vectors).enumerate() {
            let vector_id = vector["vector_id"]
                .as_str()
                .with_context(|| format!("{FIXTURE} vector {index} has no vector_id"))?;
            ensure!(
                vector_id == result.vector_id,
                "vector order drift at {index}"
            );
            ensure!(result.assertions > 0, "{vector_id} executed no assertions");
        }
        Ok(())
    }
}

struct StringProfileConsumer {
    format: String,
    full: ProtocolSchemaRegistry,
    shape_only: ProtocolSchemaRegistry,
    state: StringConsumerState,
}

impl StringProfileConsumer {
    fn new(format: &str, schema: &Value, pointer: &str) -> Result<Self> {
        let mut full = ProtocolSchemaRegistry::new();
        full.register_fragment(format, schema.clone(), pointer)
            .with_context(|| format!("register production string format {format}"))?;

        let mut shape = schema
            .pointer(pointer.trim_start_matches('#'))
            .with_context(|| format!("schema pointer {pointer} is absent"))?
            .clone();
        ensure!(
            shape
                .as_object_mut()
                .context("string profile definition must be an object")?
                .remove("format")
                .is_some(),
            "{format} definition has no custom format"
        );
        let mut shape_only = ProtocolSchemaRegistry::new();
        shape_only.register(format, shape);
        Ok(Self {
            format: format.to_owned(),
            full,
            shape_only,
            state: StringConsumerState::default(),
        })
    }

    fn consume(&mut self, key: String, value: &Value) -> Result<()> {
        self.full
            .validate_value(&self.format, value)
            .with_context(|| format!("{} positive failed production validation", self.format))?;
        ensure!(
            self.state
                .accepted_projection
                .insert(key.clone(), value.clone())
                .is_none(),
            "duplicate positive-control key {key}"
        );
        self.state.outbound_projection.push(key);
        Ok(())
    }

    fn reject(&mut self, value: &Value, layer: &str) -> Result<()> {
        let before = self.state.clone();
        let error = self
            .full
            .validate_value(&self.format, value)
            .expect_err("negative value passed production validation");
        ensure!(
            matches!(error, SchemaError::Validation(_)),
            "{} failed outside schema validation: {error}",
            self.format
        );
        match layer {
            "profile_validator" => self
                .shape_only
                .validate_value(&self.format, value)
                .with_context(|| {
                    format!(
                        "{} profile-only negative was already rejected by coarse shape",
                        self.format
                    )
                })?,
            "schema_pattern" => {
                let shape_error = self
                    .shape_only
                    .validate_value(&self.format, value)
                    .expect_err("schema-pattern negative passed coarse shape");
                ensure!(
                    matches!(shape_error, SchemaError::Validation(_)),
                    "{} shape failed outside schema validation: {shape_error}",
                    self.format
                );
            }
            other => anyhow::bail!("unknown rejection layer {other}"),
        }
        ensure!(
            self.state == before,
            "{} rejection changed consumer state",
            self.format
        );
        Ok(())
    }
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_json(relative: &str) -> Result<Value> {
    let path = spec_artifacts_root().join(relative);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read artifact {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse artifact {}", path.display()))
}

fn fixture_vectors(fixture: &Value) -> Result<&Vec<Value>> {
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(STRING_PROFILE_ENTRYPOINT),
        "string profile entrypoint drifted"
    );
    fixture["vectors"]
        .as_array()
        .context("string profile fixture has no vectors")
}

pub fn run_string_profile_suite() -> Result<StringProfileExecution> {
    let fixture = load_json(&format!("fixtures/{FIXTURE}"))?;
    let schema = load_json(&format!("schemas/{SCHEMA}"))?;
    let declared_format_count = schema["$defs"]
        .as_object()
        .context("string profile schema has no $defs")?
        .values()
        .filter(|definition| definition.get("format").is_some())
        .count();
    let vectors = fixture_vectors(&fixture)?;
    ensure!(
        vectors.len() == declared_format_count,
        "fixture does not cover every production custom string format"
    );

    let mut results = Vec::new();
    for vector in vectors {
        let vector_id = vector["vector_id"]
            .as_str()
            .context("string profile vector has no vector_id")?;
        let format = vector["format"]
            .as_str()
            .with_context(|| format!("{vector_id} has no format"))?;
        let schema_ref = vector["schema_ref"]
            .as_str()
            .with_context(|| format!("{vector_id} has no schema_ref"))?;
        let (schema_path, fragment) = schema_ref
            .split_once('#')
            .with_context(|| format!("{vector_id} schema_ref has no fragment"))?;
        ensure!(schema_path == format!("schemas/{SCHEMA}"));
        let pointer = format!("#{fragment}");
        let mut consumer = StringProfileConsumer::new(format, &schema, &pointer)?;

        let accepted = vector["accepted"]
            .as_array()
            .with_context(|| format!("{vector_id} has no accepted values"))?;
        let rejected = vector["rejected"]
            .as_array()
            .with_context(|| format!("{vector_id} has no rejected values"))?;
        ensure!(!accepted.is_empty(), "{vector_id} has no positive control");
        ensure!(!rejected.is_empty(), "{vector_id} has no negative control");

        let mut profile_validator_rejections = 0;
        let mut schema_pattern_rejections = 0;
        let mut assertions = 4;
        for (index, value) in accepted.iter().enumerate() {
            let key = format!("{vector_id}:accepted:{index}");
            consumer.consume(key.clone(), value)?;
            ensure!(
                consumer.state.accepted_projection.get(&key) == Some(value),
                "{vector_id} positive did not reach accepted projection"
            );
            ensure!(
                consumer.state.outbound_projection.last() == Some(&key),
                "{vector_id} positive did not reach outbound projection"
            );
            assertions += 3;
        }
        ensure!(consumer.state.accepted_projection.len() == accepted.len());
        ensure!(consumer.state.outbound_projection.len() == accepted.len());
        assertions += 2;

        for negative in rejected {
            let value = &negative["value"];
            ensure!(
                value.is_string(),
                "{vector_id} negative value is not a string"
            );
            let layer = negative["rejected_by"]
                .as_str()
                .with_context(|| format!("{vector_id} negative has no rejected_by"))?;
            consumer.reject(value, layer)?;
            match layer {
                "profile_validator" => profile_validator_rejections += 1,
                "schema_pattern" => schema_pattern_rejections += 1,
                _ => unreachable!("reject() closed the layer set"),
            }
            assertions += 3;
        }
        ensure!(consumer.state.accepted_projection.len() == accepted.len());
        ensure!(consumer.state.outbound_projection.len() == accepted.len());
        ensure!(
            profile_validator_rejections + schema_pattern_rejections == rejected.len(),
            "{vector_id} did not classify every negative"
        );
        assertions += 3;

        results.push(VectorExecutionResult {
            vector_id: vector_id.to_owned(),
            assertions,
            accepted_count: accepted.len(),
            rejected_count: rejected.len(),
            profile_validator_rejections,
            schema_pattern_rejections,
            accepted_projection_count: consumer.state.accepted_projection.len(),
            outbound_projection_count: consumer.state.outbound_projection.len(),
            rejected_state_unchanged: true,
        });
    }

    let execution = StringProfileExecution {
        entrypoint: STRING_PROFILE_ENTRYPOINT,
        fixture: FIXTURE,
        vectors: results,
    };
    execution.assert_complete_against(&fixture)?;
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eight_profiles_execute_every_positive_and_negative() -> Result<()> {
        let execution = run_string_profile_suite()?;
        assert_eq!(execution.vectors.len(), 8);
        assert!(execution.vectors.iter().all(|vector| vector.assertions > 0));
        assert!(
            execution
                .vectors
                .iter()
                .all(|vector| vector.accepted_count > 0 && vector.rejected_count > 0)
        );
        assert!(
            execution
                .vectors
                .iter()
                .all(|vector| vector.rejected_state_unchanged)
        );
        assert!(execution.vectors.iter().all(|vector| {
            vector.accepted_projection_count == vector.accepted_count
                && vector.outbound_projection_count == vector.accepted_count
        }));
        Ok(())
    }

    #[test]
    fn fixture_contains_both_rejection_layers() -> Result<()> {
        let execution = run_string_profile_suite()?;
        assert!(
            execution
                .vectors
                .iter()
                .map(|vector| vector.profile_validator_rejections)
                .sum::<usize>()
                > 0
        );
        assert!(
            execution
                .vectors
                .iter()
                .map(|vector| vector.schema_pattern_rejections)
                .sum::<usize>()
                > 0
        );
        Ok(())
    }
}
