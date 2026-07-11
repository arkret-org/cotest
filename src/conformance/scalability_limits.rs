use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_fixture_value, required_str, validate_profile};

const FIXTURE_FILE: &str = "scalability-limits-fixture.json";
const PROFILE: &str = "ak.profile.core_event_store.v1";

pub fn run_scalability_limits_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE_FILE)?;
    validate_profile(&fixture, PROFILE)?;
    if fixture.pointer("/runner/kind").and_then(Value::as_str) != Some("generated_limit_cases") {
        bail!("scalability fixture runner kind drifted");
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("scalability fixture missing cases[]"))?;
    for case in cases {
        run_case(case)?;
    }
    Ok(())
}

fn run_case(case: &Value) -> Result<()> {
    let name = required_str(case, "name")?;
    let generator = case
        .pointer("/input/generator")
        .or_else(|| case.pointer("/given_state/generator"))
        .ok_or_else(|| anyhow!("{name} missing generator"))?;
    let kind = required_str(generator, "kind")?;
    let actual = match kind {
        "event_refs" => decision(generator, "count", 128)?,
        "canonical_operation_envelope_bytes" => {
            decision(generator, "encoded_size_bytes", 1_048_576)?
        }
        "http_header" => decision(generator, "ascii_char_count", 128)?,
        "http_header_aggregate" => decision(generator, "encoded_size_bytes", 32_768)?,
        "active_circle_count" => decision(generator, "realm_active_circle_count", 999)?,
        "actor_active_mls_circle_memberships" => decision(generator, "count", 255)?,
        other => bail!("{name} uses unknown generated limit kind {other}"),
    };
    let expected = case
        .pointer("/expected/decision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{name} missing expected.decision"))?;
    if actual != expected {
        bail!("{name} decision drifted: expected {expected}, got {actual}");
    }
    Ok(())
}

fn decision(generator: &Value, field: &str, maximum: u64) -> Result<&'static str> {
    let value = generator
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("generated limit case missing integer {field}"))?;
    Ok(if value <= maximum { "accept" } else { "reject" })
}
