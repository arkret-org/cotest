//! C.8 — Unified mock ↔ live parity framework.
//!
//! Different cotest scenarios (yougen, soland reducers, teabay directory,
//! floria push) all want the same thing: a fixed vector list whose mock and
//! live runs must produce *identical* output bytes (canonical JSON, or
//! an opaque transcript). Today each scenario reimplements the same
//! `for vector in fixtures { compare(mock, live) }` loop with its own
//! diff formatting and skip semantics. This module pins one shape so new
//! scenarios get diff output + skip handling for free.
//!
//! ## Trait
//!
//! Implement [`MockLiveParity`] on a per-scenario type. The harness
//! supplies the fixtures, the mock runner, and the live runner; the
//! framework drives the loop and produces a single [`ParityReport`].
//!
//! ```ignore
//! struct YougenParity;
//! impl MockLiveParity for YougenParity {
//!     fn fixtures(&self) -> Vec<TestVector> { /* ... */ }
//!     fn run_mock(&self, v: &TestVector) -> Result<Output> { /* ... */ }
//!     fn run_live(&self, v: &TestVector) -> Result<Output> { /* ... */ }
//! }
//! let report = run_parity_suite(&YougenParity);
//! report.assert_all_passed()?;
//! ```
//!
//! ## Live-leg skip semantics
//!
//! Live runners return `Output::Skipped { reason }` when the corresponding
//! sibling binary or env var is missing — matching the convention used by
//! every other `#[ignore]` test in cotest (silent skip rather than hard
//! failure when the live stack is unreachable). Skipped vectors are
//! reported separately and do NOT fail the suite.

use anyhow::Result;
use serde_json::Value;

/// One fixture row driving a parity check.
///
/// `name` is the human-readable identifier shown in failure diffs.
/// `payload` is the canonical input the scenario hands to both runners;
/// shape is intentionally `serde_json::Value` so the framework stays
/// generic over scenario-specific request DTOs.
#[derive(Clone, Debug)]
pub struct TestVector {
    pub name: String,
    pub payload: Value,
}

impl TestVector {
    pub fn new(name: impl Into<String>, payload: Value) -> Self {
        Self {
            name: name.into(),
            payload,
        }
    }
}

/// Output of either runner. `Json` is the common case (canonical
/// comparison via `serde_json::to_string`); `Transcript` carries an
/// opaque pre-rendered string for scenarios that want to compare a
/// curated event log instead of the raw response body. `Skipped` is the
/// soft-skip signal — a live runner returns it when prereqs are missing
/// so the suite reports `skipped` rather than `failed`.
#[derive(Clone, Debug)]
pub enum Output {
    Json(Value),
    Transcript(String),
    Skipped { reason: String },
}

impl Output {
    fn render(&self) -> Result<String> {
        match self {
            Output::Json(v) => canonical_string(v),
            Output::Transcript(s) => Ok(s.clone()),
            Output::Skipped { reason } => Ok(format!("<skipped: {reason}>")),
        }
    }
}

/// One row in the parity report — pinned per fixture.
#[derive(Clone, Debug)]
pub enum VectorOutcome {
    Match,
    Skipped { reason: String },
    Mismatch { diff: String },
    MockError { error: String },
    LiveError { error: String },
}

impl VectorOutcome {
    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            VectorOutcome::Mismatch { .. }
                | VectorOutcome::MockError { .. }
                | VectorOutcome::LiveError { .. }
        )
    }
}

/// Aggregate report for one parity suite run.
#[derive(Clone, Debug, Default)]
pub struct ParityReport {
    pub entries: Vec<(String, VectorOutcome)>,
}

impl ParityReport {
    pub fn passed(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, o)| matches!(o, VectorOutcome::Match))
            .count()
    }

    pub fn skipped(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, o)| matches!(o, VectorOutcome::Skipped { .. }))
            .count()
    }

    pub fn failed(&self) -> usize {
        self.entries.iter().filter(|(_, o)| o.is_failure()).count()
    }

    /// Convenience: return `Err` with a multi-vector summary if any vector
    /// failed. Skipped vectors do NOT fail the suite — they are surfaced
    /// in the message body so callers can grep for them in CI logs.
    pub fn assert_all_passed(&self) -> Result<()> {
        let failed: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, o)| o.is_failure())
            .collect();
        if failed.is_empty() {
            return Ok(());
        }
        let mut summary = String::from("mock/live parity failures:\n");
        for (name, outcome) in failed {
            summary.push_str(&format!("  - {name}: {outcome:?}\n"));
        }
        anyhow::bail!(summary);
    }
}

/// Implement on a per-scenario harness type. The framework drives
/// `fixtures()` once at the start, then for each vector calls
/// `run_mock()` and `run_live()` and compares the rendered outputs.
pub trait MockLiveParity {
    fn fixtures(&self) -> Vec<TestVector>;
    fn run_mock(&self, vector: &TestVector) -> Result<Output>;
    fn run_live(&self, vector: &TestVector) -> Result<Output>;
}

/// Drive the parity loop over every fixture. Never panics; per-vector
/// errors surface as `VectorOutcome::MockError` / `LiveError` so a
/// single broken scenario doesn't mask the rest.
pub fn run_parity_suite<P: MockLiveParity>(parity: &P) -> ParityReport {
    let mut report = ParityReport::default();
    for vector in parity.fixtures() {
        let outcome = compare_one(parity, &vector);
        report.entries.push((vector.name.clone(), outcome));
    }
    report
}

fn compare_one<P: MockLiveParity>(parity: &P, vector: &TestVector) -> VectorOutcome {
    let mock = match parity.run_mock(vector) {
        Ok(out) => out,
        Err(e) => {
            return VectorOutcome::MockError {
                error: e.to_string(),
            };
        }
    };
    let live = match parity.run_live(vector) {
        Ok(out) => out,
        Err(e) => {
            return VectorOutcome::LiveError {
                error: e.to_string(),
            };
        }
    };

    // Skip semantics: if either side reports `Skipped`, treat the whole
    // vector as skipped and surface the reason (live-side wins when both
    // skip — the mock skipping is unusual but possible for vectors that
    // require a feature flag the mock harness doesn't model).
    if let Output::Skipped { reason } = &live {
        return VectorOutcome::Skipped {
            reason: reason.clone(),
        };
    }
    if let Output::Skipped { reason } = &mock {
        return VectorOutcome::Skipped {
            reason: reason.clone(),
        };
    }

    let mock_text = match mock.render() {
        Ok(t) => t,
        Err(e) => {
            return VectorOutcome::MockError {
                error: format!("render: {e}"),
            };
        }
    };
    let live_text = match live.render() {
        Ok(t) => t,
        Err(e) => {
            return VectorOutcome::LiveError {
                error: format!("render: {e}"),
            };
        }
    };

    if mock_text == live_text {
        VectorOutcome::Match
    } else {
        VectorOutcome::Mismatch {
            diff: diff_lines(&mock_text, &live_text),
        }
    }
}

/// Canonical JSON for deterministic comparison — same shape as the helper
/// in `cotest::conformance::canonical_json` but operates on owned `Value`.
fn canonical_string(value: &Value) -> Result<String> {
    use std::collections::BTreeMap;
    fn walk(v: &Value, out: &mut String) -> Result<()> {
        match v {
            Value::Object(map) => {
                let ordered: BTreeMap<_, _> = map.iter().collect();
                out.push('{');
                for (i, (k, vv)) in ordered.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k)?);
                    out.push(':');
                    walk(vv, out)?;
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    walk(item, out)?;
                }
                out.push(']');
            }
            _ => out.push_str(&serde_json::to_string(v)?),
        }
        Ok(())
    }
    let mut s = String::new();
    walk(value, &mut s)?;
    Ok(s)
}

/// Tiny line-oriented diff helper. Not a Myers diff — just per-line
/// `mock:` vs `live:` so the CI failure log is readable. Scenarios that
/// want richer diffs can render their own `Transcript` strings.
fn diff_lines(mock: &str, live: &str) -> String {
    let mock_lines: Vec<&str> = mock.lines().collect();
    let live_lines: Vec<&str> = live.lines().collect();
    let max = mock_lines.len().max(live_lines.len());
    let mut out = String::new();
    for i in 0..max {
        let m = mock_lines.get(i).copied().unwrap_or("<missing>");
        let l = live_lines.get(i).copied().unwrap_or("<missing>");
        if m != l {
            out.push_str(&format!("  mock[{i}]: {m}\n"));
            out.push_str(&format!("  live[{i}]: {l}\n"));
        }
    }
    if out.is_empty() {
        // Shouldn't normally happen — the caller only calls us on mismatch
        // — but fall back to showing the full bodies so the report stays
        // diagnostic even if the line splitter agrees while the strings
        // differ on the trailing newline.
        out.push_str(&format!("  mock: {mock}\n  live: {live}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Toy {
        same: bool,
        skip_live: bool,
    }
    impl MockLiveParity for Toy {
        fn fixtures(&self) -> Vec<TestVector> {
            vec![TestVector::new("only", serde_json::json!({"k": 1}))]
        }
        fn run_mock(&self, _v: &TestVector) -> Result<Output> {
            Ok(Output::Json(serde_json::json!({"out": 1})))
        }
        fn run_live(&self, _v: &TestVector) -> Result<Output> {
            if self.skip_live {
                return Ok(Output::Skipped {
                    reason: "no binary".to_owned(),
                });
            }
            Ok(Output::Json(
                serde_json::json!({"out": if self.same { 1 } else { 2 }}),
            ))
        }
    }

    #[test]
    fn matching_outputs_pass() {
        let report = run_parity_suite(&Toy {
            same: true,
            skip_live: false,
        });
        assert_eq!(report.passed(), 1);
        assert_eq!(report.failed(), 0);
        report
            .assert_all_passed()
            .expect("matching parity must pass");
    }

    #[test]
    fn mismatched_outputs_fail() {
        let report = run_parity_suite(&Toy {
            same: false,
            skip_live: false,
        });
        assert_eq!(report.passed(), 0);
        assert_eq!(report.failed(), 1);
        assert!(report.assert_all_passed().is_err());
    }

    #[test]
    fn skipped_live_leg_is_not_a_failure() {
        let report = run_parity_suite(&Toy {
            same: false,
            skip_live: true,
        });
        assert_eq!(report.skipped(), 1);
        assert_eq!(report.failed(), 0);
        report
            .assert_all_passed()
            .expect("live-skip must not fail the suite");
    }
}
