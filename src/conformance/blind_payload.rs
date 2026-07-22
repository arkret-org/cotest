//! T1.1 — shared push blind-payload sanitizer conformance vectors.
//!
//! These vectors live in `cotest/tests/fixtures/blind_payload_vectors.json`
//! and exercise the SDK sanitizer (`arkret_policy::blind_payload_sanitizer`)
//! that chime and floria both delegate to. They guarantee that any future
//! drift between the three implementations is caught here.

use anyhow::{Result, anyhow, bail};
use arkret_policy::blind_payload_sanitizer::{
    BlindPayloadError, BlindPayloadReasonCode, SanitizerMode, sanitize_blind_payload_with,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::load_local_fixture_value;
use crate::transcripts::record_vector_event;

const FIXTURE_FILE: &str = "blind_payload_vectors.json";

#[derive(Debug, Deserialize)]
struct BlindPayloadFixture {
    suite: String,
    version: u32,
    #[serde(default)]
    description: Option<String>,
    positive_cases: Vec<PositiveCase>,
    negative_cases: Vec<NegativeCase>,
}

#[derive(Debug, Deserialize)]
struct PositiveCase {
    name: String,
    #[serde(default)]
    mode: Option<String>,
    payload: Value,
}

#[derive(Debug, Deserialize)]
struct NegativeCase {
    name: String,
    #[serde(default)]
    mode: Option<String>,
    expected_reason_code: String,
    #[serde(default)]
    expected_field_path: Option<String>,
    payload: Value,
}

fn parse_mode(raw: Option<&str>) -> Result<SanitizerMode> {
    match raw {
        None | Some("default") => Ok(SanitizerMode::Default),
        Some("strict") => Ok(SanitizerMode::Strict),
        Some(other) => bail!("unknown sanitizer mode `{other}`"),
    }
}

fn reason_to_str(code: BlindPayloadReasonCode) -> &'static str {
    code.as_str()
}

/// Thin `Result<()>` wrapper around [`run_blind_payload_sanitizer_suite_counts`]
/// so the suite can be wired into the existing `conformance_test!`
/// integration-test macro (which expects a zero-arg `Result<()>` function).
pub fn run_blind_payload_sanitizer_suite() -> Result<()> {
    run_blind_payload_sanitizer_suite_counts().map(|_| ())
}

/// Run the shared blind-payload sanitizer vectors and return
/// `(positive_count, negative_count)`.
pub fn run_blind_payload_sanitizer_suite_counts() -> Result<(usize, usize)> {
    let value = load_local_fixture_value(FIXTURE_FILE)?;
    let fixture: BlindPayloadFixture = serde_json::from_value(value)
        .map_err(|err| anyhow!("failed to parse {FIXTURE_FILE}: {err}"))?;

    if fixture.suite != "blind_payload_sanitizer" {
        bail!("unexpected fixture suite `{}`", fixture.suite);
    }
    if fixture.version != 1 {
        bail!("unexpected fixture version `{}`", fixture.version);
    }
    let _ = fixture.description; // suppress unused warning while keeping the field.

    let mut positive_count = 0_usize;
    for case in &fixture.positive_cases {
        let mode = parse_mode(case.mode.as_deref())?;
        let outcome = sanitize_blind_payload_with(&case.payload, mode);
        let actual = describe_outcome(&outcome);
        record_vector_event(
            &format!("blind_payload.positive.{}", case.name),
            &case.payload,
            &json!({ "ok": true }),
            &actual,
        );
        if let Err(err) = outcome {
            bail!(
                "positive vector `{}` unexpectedly rejected at `{}` ({}): {}",
                case.name,
                err.field_path,
                err.reason_code,
                err.message,
            );
        }
        positive_count += 1;
    }

    let mut negative_count = 0_usize;
    for case in &fixture.negative_cases {
        let mode = parse_mode(case.mode.as_deref())?;
        let outcome = sanitize_blind_payload_with(&case.payload, mode);
        let actual = describe_outcome(&outcome);
        record_vector_event(
            &format!("blind_payload.negative.{}", case.name),
            &case.payload,
            &json!({
                "ok": false,
                "reason_code": case.expected_reason_code.clone(),
                "field_path": case.expected_field_path.clone(),
            }),
            &actual,
        );
        let err = match outcome {
            Ok(()) => bail!("negative vector `{}` was unexpectedly accepted", case.name),
            Err(err) => err,
        };
        assert_negative_match(
            &case.name,
            &case.expected_reason_code,
            case.expected_field_path.as_deref(),
            &err,
        )?;
        negative_count += 1;
    }

    Ok((positive_count, negative_count))
}

fn describe_outcome(outcome: &Result<(), BlindPayloadError>) -> Value {
    match outcome {
        Ok(()) => json!({ "ok": true }),
        Err(err) => json!({
            "ok": false,
            "reason_code": reason_to_str(err.reason_code),
            "field_path": err.field_path,
            "message": err.message,
        }),
    }
}

fn assert_negative_match(
    name: &str,
    expected_reason_code: &str,
    expected_field_path: Option<&str>,
    err: &BlindPayloadError,
) -> Result<()> {
    let actual_reason = reason_to_str(err.reason_code);
    if actual_reason != expected_reason_code {
        bail!(
            "negative vector `{}` reason_code mismatch: expected `{}`, got `{}` (path=`{}`, message={})",
            name,
            expected_reason_code,
            actual_reason,
            err.field_path,
            err.message,
        );
    }
    if let Some(expected_path) = expected_field_path
        && err.field_path != expected_path
    {
        bail!(
            "negative vector `{}` field_path mismatch: expected `{}`, got `{}`",
            name,
            expected_path,
            err.field_path,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_blind_payload_vectors_pass() {
        let (positive, negative) =
            run_blind_payload_sanitizer_suite_counts().expect("blind payload suite");
        assert!(positive >= 5, "expected ≥ 5 positive cases, got {positive}");
        assert!(
            negative >= 20,
            "expected ≥ 20 negative cases, got {negative}"
        );
    }
}
