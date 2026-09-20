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
        for (index, (case, result)) in declared.iter().zip(&self.cases).enumerate() {
            let declared_id = case
                .get("case_id")
                .or_else(|| case.get("name"))
                .or_else(|| case.get("vector_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("{} cases[{index}] has no id", self.fixture))?;
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
