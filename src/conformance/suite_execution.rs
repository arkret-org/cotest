//! Shared result shape for executable named conformance suites.
//!
//! A successful `Result<()>` only says that a suite did not return an error. It
//! does not prove that every fixture case ran. Named suites which opt in to
//! this result shape must return exactly one result for every declared case;
//! the integration gate checks the bijection by case id.

use anyhow::{Result, bail};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuiteExecutionResult {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}

impl SuiteExecutionResult {
    /// Validate partial production evidence without promoting absent cases to
    /// executed ones. The returned ids remain obligations of the full suite.
    pub fn missing_against_cases(&self, declared: &[Value]) -> Result<Vec<String>> {
        let mut ids = std::collections::BTreeSet::new();
        let mut ordered = Vec::new();
        for case in declared {
            let id = case
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("{} has an unnamed case", self.fixture))?;
            if !ids.insert(id) {
                bail!("{} declares duplicate case id {id}", self.fixture);
            }
            ordered.push(id);
        }
        let mut executed = std::collections::BTreeSet::new();
        for case in &self.cases {
            if !ids.contains(case.case_id.as_str()) || !executed.insert(case.case_id.as_str()) {
                bail!(
                    "{} has an unknown or duplicate execution {}",
                    self.entrypoint,
                    case.case_id
                );
            }
            if case.assertions == 0 {
                bail!(
                    "{} case {} returned no executed assertions",
                    self.entrypoint,
                    case.case_id
                );
            }
        }
        Ok(ordered
            .into_iter()
            .filter(|id| !executed.contains(id))
            .map(str::to_owned)
            .collect())
    }

    pub fn assert_complete_against(&self, fixture: &Value) -> Result<()> {
        let declared = fixture
            .get("cases")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{} has no cases[]", self.fixture))?;
        self.assert_complete_against_cases(declared)
    }

    pub fn assert_complete_against_cases(&self, declared: &[Value]) -> Result<()> {
        if declared.len() != self.cases.len() {
            bail!(
                "{} declared {} cases but runner returned {} case results",
                self.entrypoint,
                declared.len(),
                self.cases.len()
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        for (index, (case, result)) in declared.iter().zip(&self.cases).enumerate() {
            let declared_id = case
                .get("case_id")
                .or_else(|| case.get("case"))
                .or_else(|| case.get("name"))
                .or_else(|| case.get("vector_id"))
                .or_else(|| case.get("field"))
                .and_then(Value::as_str)
                .or_else(|| case.as_str())
                .ok_or_else(|| anyhow::anyhow!("{} cases[{index}] has no id", self.fixture))?;
            if !ids.insert(declared_id) {
                bail!("{} declares duplicate case id {declared_id}", self.fixture);
            }
            if declared_id != result.case_id {
                bail!(
                    "{} cases[{index}] is {declared_id}, runner returned {}",
                    self.entrypoint,
                    result.case_id
                );
            }
            if result.assertions == 0 {
                bail!(
                    "{} case {declared_id} returned no executed assertions",
                    self.entrypoint
                );
            }
        }
        Ok(())
    }
}

/// The fixture's cases paired with their variants, checked against the
/// executed script: every case and variant name must match in order, so a
/// renamed, added or dropped variant fails instead of being skipped.
pub(crate) fn scripted_cases<'a>(
    fixture: &'a Value,
    script: &[(&str, &[&str])],
) -> Result<Vec<(&'a str, &'a [Value])>> {
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("fixture has no cases[]"))?;
    if cases.len() != script.len() {
        bail!(
            "fixture carries {} cases, the runner executes {}",
            cases.len(),
            script.len()
        );
    }
    let mut scripted = Vec::with_capacity(cases.len());
    for (case, (case_name, variant_names)) in cases.iter().zip(script) {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("a fixture case has no name"))?;
        if name != *case_name {
            bail!("fixture case {name} is not the executed case {case_name}");
        }
        let variants = case
            .get("variants")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{name} has no variants[]"))?;
        let declared = variants
            .iter()
            .map(|variant| variant.get("name").and_then(Value::as_str))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow::anyhow!("{name}: a variant has no name"))?;
        if declared != *variant_names {
            bail!("{name}: variants drifted from the executed script: {declared:?}");
        }
        scripted.push((name, variants.as_slice()));
    }
    Ok(scripted)
}

/// The fixture's decision points are exactly `expected_ids`, each with a
/// requirement and at least one accepting (`accept` or `replay`) and one
/// refusing (`reject`) decision named by JSON pointer: a variant, or one
/// decision object inside a variant's expectation.
pub(crate) fn verify_decision_point_evidence(fixture: &Value, expected_ids: &[&str]) -> Result<()> {
    let points = fixture
        .get("decision_points")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("fixture has no decision_points[]"))?;
    let mut ids = Vec::with_capacity(points.len());
    for point in points {
        let id = point
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("a decision point has no id"))?;
        if point
            .get("requirement")
            .and_then(Value::as_str)
            .is_none_or(|text| text.trim().is_empty())
        {
            bail!("{id}: empty requirement");
        }
        for (side, allowed) in [
            ("accept", &["accept", "replay"][..]),
            ("reject", &["reject"]),
        ] {
            let pointers = point
                .get(side)
                .and_then(Value::as_array)
                .filter(|pointers| !pointers.is_empty())
                .ok_or_else(|| anyhow::anyhow!("{id}: no {side} evidence"))?;
            for pointer in pointers {
                let pointer = pointer
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("{id}: {side} pointer is not a string"))?;
                // A pointer names a variant, whose `expected.decision` is its
                // evidence, or one decision inside a variant's expectation.
                let decision = fixture
                    .pointer(pointer)
                    .and_then(|node| node.get("expected").or(Some(node)))
                    .and_then(|expected| expected.get("decision"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow::anyhow!("{id}: unresolved evidence pointer {pointer}")
                    })?;
                if !allowed.contains(&decision) {
                    bail!("{id}: {pointer} is {decision}, not {side} evidence");
                }
            }
        }
        ids.push(id);
    }
    if ids != expected_ids {
        bail!("decision points drifted: {ids:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn duplicate_case_ids_cannot_claim_complete_execution() {
        let fixture = json!({"cases": [{"name": "first"}, {"name": "first"}]});
        let result = SuiteExecutionResult {
            entrypoint: "ak.suite.test.v1",
            fixture: "test.json",
            cases: vec![
                CaseExecutionResult {
                    case_id: "first".into(),
                    assertions: 1
                };
                2
            ],
        };
        assert!(result.assert_complete_against(&fixture).is_err());
    }

    #[test]
    fn missing_or_assertion_free_case_result_is_rejected() {
        let fixture = json!({"cases": [{"name": "first"}, {"name": "second"}]});
        let missing = SuiteExecutionResult {
            entrypoint: "ak.suite.test.v1",
            fixture: "test.json",
            cases: vec![CaseExecutionResult {
                case_id: "first".to_owned(),
                assertions: 1,
            }],
        };
        assert!(missing.assert_complete_against(&fixture).is_err());

        let assertion_free = SuiteExecutionResult {
            entrypoint: "ak.suite.test.v1",
            fixture: "test.json",
            cases: vec![
                CaseExecutionResult {
                    case_id: "first".to_owned(),
                    assertions: 1,
                },
                CaseExecutionResult {
                    case_id: "second".to_owned(),
                    assertions: 0,
                },
            ],
        };
        assert!(assertion_free.assert_complete_against(&fixture).is_err());
    }
}
