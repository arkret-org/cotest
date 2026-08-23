//! Canonical fixture builders used by cross-service conformance suites.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CANONICAL_FIXTURE_DEFAULT_KIND: &str = "canonical_json_digest";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalFixtureSuite {
    pub profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub vectors: Vec<CanonicalFixtureVector>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalFixtureVector {
    pub vector_id: String,
    pub kind: String,
    pub input: Value,
    pub expected_canonical_bytes_utf8: String,
    pub expected_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
}

impl CanonicalFixtureVector {
    pub fn from_input(
        vector_id: impl Into<String>,
        kind: impl Into<String>,
        input: impl Serialize,
    ) -> Result<Self> {
        Self::from_input_with_rules(vector_id, kind, input, Vec::<String>::new())
    }

    pub fn from_input_with_rules(
        vector_id: impl Into<String>,
        kind: impl Into<String>,
        input: impl Serialize,
        rules: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let input = serde_json::to_value(input)?;
        let canonical_bytes = arkret_canonical::canonical_json_bytes(&input)?;
        let expected_canonical_bytes_utf8 = String::from_utf8(canonical_bytes.clone())?;
        let expected_digest = arkret_canonical::sha256_digest(&canonical_bytes);
        Ok(Self {
            vector_id: vector_id.into(),
            kind: kind.into(),
            input,
            expected_canonical_bytes_utf8,
            expected_digest,
            rules: rules.into_iter().map(Into::into).collect(),
        })
    }

    pub fn assert_matches_input(&self) -> Result<()> {
        let canonical_bytes = arkret_canonical::canonical_json_bytes(&self.input)?;
        let canonical_bytes_utf8 = String::from_utf8(canonical_bytes.clone())?;
        if canonical_bytes_utf8 != self.expected_canonical_bytes_utf8 {
            bail!("canonical fixture '{}' bytes drifted", self.vector_id);
        }
        let digest = arkret_canonical::sha256_digest(&canonical_bytes);
        if digest != self.expected_digest {
            bail!("canonical fixture '{}' digest drifted", self.vector_id);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalFixtureBuilder {
    profile: String,
    version: Option<String>,
    description: Option<String>,
    vectors: Vec<CanonicalFixtureVector>,
}

impl CanonicalFixtureBuilder {
    pub fn new(profile: impl Into<String>) -> Self {
        Self {
            profile: profile.into(),
            version: None,
            description: None,
            vectors: Vec::new(),
        }
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn push(
        &mut self,
        vector_id: impl Into<String>,
        input: impl Serialize,
    ) -> Result<&mut Self> {
        self.push_kind(vector_id, CANONICAL_FIXTURE_DEFAULT_KIND, input)
    }

    pub fn push_kind(
        &mut self,
        vector_id: impl Into<String>,
        kind: impl Into<String>,
        input: impl Serialize,
    ) -> Result<&mut Self> {
        self.vectors
            .push(CanonicalFixtureVector::from_input(vector_id, kind, input)?);
        Ok(self)
    }

    pub fn push_with_rules(
        &mut self,
        vector_id: impl Into<String>,
        kind: impl Into<String>,
        input: impl Serialize,
        rules: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<&mut Self> {
        self.vectors
            .push(CanonicalFixtureVector::from_input_with_rules(
                vector_id, kind, input, rules,
            )?);
        Ok(self)
    }

    pub fn finish(self) -> CanonicalFixtureSuite {
        CanonicalFixtureSuite {
            profile: self.profile,
            version: self.version,
            description: self.description,
            vectors: self.vectors,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn fixture_builder_emits_spec_fixture_fields() {
        let mut builder =
            CanonicalFixtureBuilder::new("ak.vector_group.encoding.v1").version("2026-06-19");
        builder
            .push_with_rules(
                "ak.vector.encoding.canonical_json.basic.v1",
                "canonical_json_digest",
                json!({ "b": 2, "a": 1 }),
                ["object keys are sorted"],
            )
            .unwrap();
        let suite = builder.finish();
        assert_eq!(suite.profile, "ak.vector_group.encoding.v1");
        assert_eq!(suite.version.as_deref(), Some("2026-06-19"));
        assert_eq!(suite.vectors.len(), 1);
        let vector = &suite.vectors[0];
        assert_eq!(vector.expected_canonical_bytes_utf8, "{\"a\":1,\"b\":2}");
        assert_eq!(
            vector.expected_digest,
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
        vector.assert_matches_input().unwrap();
    }

    #[test]
    fn fixture_builder_rejects_non_canonical_numbers() {
        let err = CanonicalFixtureVector::from_input(
            "ak.vector.encoding.reject_float.v1",
            "canonical_json_digest",
            json!({ "n": 1.5 }),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("non-integer")
                || err.to_string().contains("not a canonical")
                || err.to_string().contains("float")
        );
    }
}
