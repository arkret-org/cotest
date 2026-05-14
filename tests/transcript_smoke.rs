//! Smoke test for `cotest::transcripts` JSONL writer (C34.5 / Q3).
//!
//! Confirms that when an instrumented conformance suite runs under an active
//! [`init_transcript_writer`] guard, the per-scenario `.jsonl` file:
//!
//! 1. exists at `<target_dir>/<scenario>.jsonl`,
//! 2. contains at least one line per instrumented vector site,
//! 3. each line is valid JSON,
//! 4. each line carries the structured `kind` / `payload` / `expected` /
//!    `actual` / `scenario` fields the consumer contract requires.

use std::fs;

use anyhow::Result;
use serde_json::Value;

use cotest::transcripts::{init_transcript_writer, record_vector_event};

#[test]
fn transcript_writer_emits_jsonl_per_vector() -> Result<()> {
    let dir = std::env::temp_dir().join("cotest-transcript-smoke");
    let _ = fs::remove_dir_all(&dir);

    let scenario = "transcript_smoke_basic";
    let guard = init_transcript_writer(scenario, Some(&dir))?;

    record_vector_event(
        "smoke.basic",
        &serde_json::json!({"input": 1}),
        &serde_json::json!({"out": 2}),
        &serde_json::json!({"out": 2}),
    );
    record_vector_event(
        "smoke.second",
        &serde_json::json!({"input": "x"}),
        &serde_json::json!({"out": "y"}),
        &serde_json::json!({"out": "y"}),
    );

    drop(guard);

    let path = dir.join(format!("{scenario}.jsonl"));
    assert!(path.is_file(), "transcript file not created at {path:?}");
    let raw = fs::read_to_string(&path)?;
    let lines: Vec<&str> = raw.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "expected 2 transcript lines, got {raw:?}");

    for line in &lines {
        let value: Value = serde_json::from_str(line)
            .unwrap_or_else(|err| panic!("transcript line not valid JSON ({err}): {line}"));
        let fields = value
            .get("fields")
            .unwrap_or_else(|| panic!("transcript line missing fields: {line}"));
        for required in ["scenario", "kind", "payload", "expected", "actual"] {
            assert!(
                fields.get(required).is_some(),
                "transcript line missing field {required}: {line}"
            );
        }
        assert_eq!(
            fields.get("scenario").and_then(Value::as_str),
            Some(scenario),
            "scenario field mismatch: {line}",
        );
    }

    Ok(())
}

/// Drives the live conformance redaction suite under a transcript guard and
/// confirms every vector emitted at least one structured event with
/// `kind = "redaction.*"`.
#[test]
fn transcript_writer_captures_redaction_suite_vectors() -> Result<()> {
    let dir = std::env::temp_dir().join("cotest-transcript-smoke-redaction");
    let _ = fs::remove_dir_all(&dir);

    let scenario = "transcript_smoke_redaction";
    let guard = init_transcript_writer(scenario, Some(&dir))?;

    cotest::conformance::run_redaction_fixture_suite()?;

    drop(guard);

    let path = dir.join(format!("{scenario}.jsonl"));
    assert!(path.is_file(), "transcript file not created at {path:?}");
    let raw = fs::read_to_string(&path)?;
    let lines: Vec<&str> = raw.lines().filter(|line| !line.trim().is_empty()).collect();
    assert!(
        lines.len() >= 5,
        "expected ≥ 5 redaction vector events (one per case), got {} from {raw:?}",
        lines.len(),
    );
    for line in &lines {
        let value: Value = serde_json::from_str(line).unwrap_or_else(|err| {
            panic!("redaction transcript line not valid JSON ({err}): {line}")
        });
        let kind = value
            .pointer("/fields/kind")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("redaction transcript line missing fields.kind: {line}"));
        assert!(
            kind.starts_with("redaction."),
            "redaction transcript line carried unexpected kind {kind}: {line}",
        );
    }

    Ok(())
}
