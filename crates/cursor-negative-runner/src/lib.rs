//! Executable negative cursor admission vectors.
//!
//! Every fixture token is submitted to the production issuing-service
//! [`Cursor::decode_at`] boundary. State counters sit behind that boundary so
//! a rejection cannot be mistaken for a successful no-op.

use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use arkret_hlc::{Cursor, CursorPurpose};
use serde_json::Value;

pub const CURSOR_NEGATIVE_ENTRYPOINT: &str = "ak.suite.encoding.cursor_negative.v1";
pub const FIXTURE: &str = "cursor-negative-fixture.json";
const VECTOR_ID: &str = "ak.vector.encoding.reject_invalid_cursor.core.v1";
const RECEIVER_NOW: &str = "2026-09-20T00:00:00.000Z";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CursorStateEffects {
    pub subscription_position_advances: usize,
    pub barrier_wait_releases: usize,
    pub recovery_state_advances: usize,
}

impl CursorStateEffects {
    fn is_zero(self) -> bool {
        self == Self::default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CursorSurface {
    Subscription,
    Barrier,
    Recovery,
}

impl CursorSurface {
    const ALL: [Self; 3] = [Self::Subscription, Self::Barrier, Self::Recovery];

    fn required_purpose(self) -> CursorPurpose {
        match self {
            Self::Barrier => CursorPurpose::Barrier,
            Self::Subscription | Self::Recovery => CursorPurpose::Stream,
        }
    }

    fn commit(self, effects: &mut CursorStateEffects) {
        match self {
            Self::Subscription => effects.subscription_position_advances += 1,
            Self::Barrier => effects.barrier_wait_releases += 1,
            Self::Recovery => effects.recovery_state_advances += 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdmissionObservation {
    accepted: bool,
    reason: Option<&'static str>,
    diagnostic: Option<String>,
    effects: CursorStateEffects,
}

struct CursorAdmissionConsumer {
    now_ms: i64,
}

impl CursorAdmissionConsumer {
    fn fixed_receiver_clock() -> Result<Self> {
        Ok(Self {
            now_ms: arkret_canonical::parse_timestamp_canonical(RECEIVER_NOW)?.timestamp_millis(),
        })
    }

    fn submit(&self, token: &str, surface: CursorSurface) -> Result<AdmissionObservation> {
        let mut effects = CursorStateEffects::default();
        match Cursor::decode_at(token, self.now_ms) {
            Ok(cursor) => {
                ensure!(
                    cursor.purpose == surface.required_purpose(),
                    "accepted cursor purpose does not match {surface:?}"
                );
                surface.commit(&mut effects);
                Ok(AdmissionObservation {
                    accepted: true,
                    reason: None,
                    diagnostic: None,
                    effects,
                })
            }
            Err(error) => {
                let diagnostic = error.to_string();
                let reason = if diagnostic.contains("cursor has expired") {
                    "cursor_expired"
                } else {
                    "invalid_cursor"
                };
                Ok(AdmissionObservation {
                    accepted: false,
                    reason: Some(reason),
                    diagnostic: Some(diagnostic),
                    effects,
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub reason: String,
    pub diagnostic: String,
    pub attempts: usize,
    pub effects: CursorStateEffects,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorNegativeExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub positive_control_assertions: usize,
    pub cases: Vec<CaseExecutionResult>,
}

impl CursorNegativeExecution {
    fn assert_complete_against(&self, fixture: &Value) -> Result<()> {
        let declared = fixture_cases(fixture)?;
        ensure!(
            declared.len() == self.cases.len(),
            "{} declared {} cases but runner returned {}",
            self.entrypoint,
            declared.len(),
            self.cases.len()
        );
        for (index, (case, result)) in declared.iter().zip(&self.cases).enumerate() {
            let case_id = case["name"]
                .as_str()
                .with_context(|| format!("{FIXTURE} case {index} has no name"))?;
            ensure!(case_id == result.case_id, "case order drift at {index}");
            ensure!(result.assertions > 0, "{case_id} executed no assertions");
        }
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

fn load_fixture() -> Result<Value> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read fixture {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse fixture {}", path.display()))
}

fn fixture_cases(fixture: &Value) -> Result<&Vec<Value>> {
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(CURSOR_NEGATIVE_ENTRYPOINT),
        "cursor negative entrypoint drifted"
    );
    ensure!(
        fixture
            .pointer("/vectors/0/vector_id")
            .and_then(Value::as_str)
            == Some(VECTOR_ID),
        "cursor negative vector id drifted"
    );
    fixture
        .pointer("/vectors/0/cases")
        .and_then(Value::as_array)
        .context("cursor negative fixture has no vectors[0].cases")
}

fn expected_diagnostic_fragment(case_id: &str) -> Result<&'static str> {
    match case_id {
        "oversized_token" => Ok("cursor token too large"),
        "invalid_base64url" => Ok("invalid Base64URL encoding"),
        "malformed_json"
        | "duplicate_json_key"
        | "non_nfc_string"
        | "inline_positions_rejected"
        | "unknown_public_field_rejected"
        | "non_canonical_timestamp"
        | "missing_millisecond_fraction" => Ok("invalid cursor JSON"),
        "unsupported_version" => Ok("unsupported cursor version"),
        "handle_too_short" => Ok("invalid cursor handle"),
        "negative_ttl" => Ok("issued_at` is after `expires_at"),
        "stream_ttl_exceeds_cap" | "barrier_ttl_exceeds_cap" => Ok("hard upper bound"),
        "expired" => Ok("cursor has expired"),
        other => bail!("unexecuted cursor negative case {other}"),
    }
}

fn add_effects(total: &mut CursorStateEffects, current: CursorStateEffects) {
    total.subscription_position_advances += current.subscription_position_advances;
    total.barrier_wait_releases += current.barrier_wait_releases;
    total.recovery_state_advances += current.recovery_state_advances;
}

fn run_positive_control(consumer: &CursorAdmissionConsumer) -> Result<usize> {
    let issued_at = arkret_canonical::parse_timestamp_canonical(RECEIVER_NOW)?;
    let stream =
        Cursor::new_at(issued_at, 3_600_000)?.with_stateful_handle("abcdefghijklmnopqrstuv");
    let stream_token = stream.encode()?;
    let barrier_token = stream.with_barrier().encode()?;
    let mut effects = CursorStateEffects::default();
    for (token, surface) in [
        (stream_token.as_str(), CursorSurface::Subscription),
        (barrier_token.as_str(), CursorSurface::Barrier),
        (stream_token.as_str(), CursorSurface::Recovery),
    ] {
        let observation = consumer.submit(token, surface)?;
        ensure!(
            observation.accepted,
            "positive cursor rejected on {surface:?}"
        );
        ensure!(
            observation.reason.is_none(),
            "positive cursor returned reason"
        );
        ensure!(
            observation.diagnostic.is_none(),
            "positive cursor returned diagnostic"
        );
        add_effects(&mut effects, observation.effects);
    }
    ensure!(effects.subscription_position_advances == 1);
    ensure!(effects.barrier_wait_releases == 1);
    ensure!(effects.recovery_state_advances == 1);
    Ok(12)
}

pub fn run_cursor_negative_suite() -> Result<CursorNegativeExecution> {
    let fixture = load_fixture()?;
    let consumer = CursorAdmissionConsumer::fixed_receiver_clock()?;
    let positive_control_assertions = run_positive_control(&consumer)?;
    let mut results = Vec::new();

    for case in fixture_cases(&fixture)? {
        let case_id = case["name"].as_str().context("cursor case has no name")?;
        let token = case["input_cursor"]
            .as_str()
            .with_context(|| format!("{case_id} has no input_cursor"))?;
        let expected_reason = case["expected_reason_code"]
            .as_str()
            .with_context(|| format!("{case_id} has no expected_reason_code"))?;
        ensure!(
            matches!(expected_reason, "invalid_cursor" | "cursor_expired"),
            "{case_id} declares unsupported reason {expected_reason}"
        );
        let expected_diagnostic = expected_diagnostic_fragment(case_id)?;

        if case_id == "oversized_token" {
            let encoded = token
                .strip_prefix("ak:cursor:")
                .context("oversized cursor lost prefix")?;
            let encoded_cap = Cursor::MAX_ENCODED_SIZE.div_ceil(3) * 4;
            ensure!(encoded_cap == 5464, "production encoded cap drifted");
            ensure!(encoded.len() == 6000, "formal oversized input drifted");
            ensure!(
                encoded.len() > encoded_cap,
                "formal cursor is not oversized"
            );
            ensure!(
                encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
                "formal oversized cursor is not valid base64url alphabet"
            );
        }

        let mut effects = CursorStateEffects::default();
        let mut first_diagnostic = None;
        let mut assertions = 4;
        for surface in CursorSurface::ALL {
            let observation = consumer.submit(token, surface)?;
            ensure!(!observation.accepted, "{case_id} accepted on {surface:?}");
            ensure!(
                observation.reason == Some(expected_reason),
                "{case_id} returned {:?}, expected {expected_reason}",
                observation.reason
            );
            ensure!(
                observation.effects.is_zero(),
                "{case_id} advanced state on {surface:?}: {:?}",
                observation.effects
            );
            let diagnostic = observation
                .diagnostic
                .context("rejected cursor has no production diagnostic")?;
            ensure!(
                diagnostic.contains(expected_diagnostic),
                "{case_id} hit wrong production branch: {diagnostic}"
            );
            if let Some(first) = &first_diagnostic {
                ensure!(
                    first == &diagnostic,
                    "{case_id} diagnostic changed by surface"
                );
            } else {
                first_diagnostic = Some(diagnostic);
            }
            add_effects(&mut effects, observation.effects);
            assertions += 5;
        }
        ensure!(effects.subscription_position_advances == 0);
        ensure!(effects.barrier_wait_releases == 0);
        ensure!(effects.recovery_state_advances == 0);
        assertions += 3;
        results.push(CaseExecutionResult {
            case_id: case_id.to_owned(),
            assertions,
            reason: expected_reason.to_owned(),
            diagnostic: first_diagnostic.context("cursor case had no attempts")?,
            attempts: CursorSurface::ALL.len(),
            effects,
        });
    }

    let execution = CursorNegativeExecution {
        entrypoint: CURSOR_NEGATIVE_ENTRYPOINT,
        fixture: FIXTURE,
        positive_control_assertions,
        cases: results,
    };
    execution.assert_complete_against(&fixture)?;
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_fifteen_cases_hit_their_production_rejection_branch() -> Result<()> {
        let execution = run_cursor_negative_suite()?;
        assert_eq!(execution.cases.len(), 15);
        assert!(execution.positive_control_assertions > 0);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
        assert!(execution.cases.iter().all(|case| case.attempts == 3));
        assert!(execution.cases.iter().all(|case| case.effects.is_zero()));
        Ok(())
    }

    #[test]
    fn oversized_case_hits_pre_decode_size_branch() -> Result<()> {
        let execution = run_cursor_negative_suite()?;
        let oversized = execution
            .cases
            .iter()
            .find(|case| case.case_id == "oversized_token")
            .context("oversized case did not execute")?;
        assert!(oversized.diagnostic.contains("cursor token too large"));
        assert_eq!(oversized.reason, "invalid_cursor");
        assert!(oversized.effects.is_zero());
        Ok(())
    }

    #[test]
    fn expired_case_is_distinct_from_invalid_cursor() -> Result<()> {
        let execution = run_cursor_negative_suite()?;
        let expired = execution
            .cases
            .iter()
            .find(|case| case.case_id == "expired")
            .context("expired case did not execute")?;
        assert_eq!(expired.reason, "cursor_expired");
        assert!(expired.diagnostic.contains("cursor has expired"));
        assert!(expired.effects.is_zero());
        Ok(())
    }
}
