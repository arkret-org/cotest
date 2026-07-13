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
        "event_causal_refs" => decision(generator, "count", 128)?,
        "event_refs_by_role" => decision(generator, "count", 64)?,
        "canonical_operation_envelope_bytes" => {
            decision(generator, "encoded_size_bytes", 1_048_576)?
        }
        "http_header" => match required_str(generator, "name")? {
            "Idempotency-Key" => decision(generator, "ascii_char_count", 128)?,
            "X-Arkret-Wait-For" => decision(generator, "encoded_size_bytes", 4_096)?,
            _ => decision(generator, "encoded_size_bytes", 8_192)?,
        },
        "http_header_aggregate" => decision(generator, "encoded_size_bytes", 32_768)?,
        "http_path_query" => decision(generator, "encoded_size_bytes", 8_192)?,
        "operation_batch_items" => decision(generator, "count", 1_000)?,
        "federation_transaction_events" => decision(generator, "count", 500)?,
        "sync_page_candidates" => {
            let count = required_u64(generator, "count")?;
            let returned = count.min(1_000);
            if case
                .pointer("/expected/returned_items")
                .and_then(Value::as_u64)
                != Some(returned)
                || case
                    .pointer("/expected/cursor_present")
                    .and_then(Value::as_bool)
                    != Some(count > returned)
            {
                bail!("{name} sync page cap drifted");
            }
            return Ok(());
        }
        "object_fields_canonical_bytes" => decision(generator, "encoded_size_bytes", 262_144)?,
        "space_parent_chain" => decision(generator, "depth", 8)?,
        "rank_string" => decision(generator, "char_count", 128)?,
        "control_move_preconditions_effects" => decision(generator, "combined_count", 256)?,
        "seal_new_control_moves" => decision(generator, "count", 1_000)?,
        "capability_delegation_chain" => bounded_outcome(generator, "depth", 4, "accept", "deny")?,
        "capability_grant_constraints" => decision(generator, "count", 64)?,
        "resource_selector_ast" => decision(generator, "depth", 16)?,
        "authorization_grant_expansion" => {
            bounded_outcome(generator, "count", 1_024, "accept", "fail_closed")?
        }
        "active_circle_count" => decision(generator, "realm_active_circle_count", 999)?,
        "actor_active_mls_circle_memberships" => decision(generator, "count", 255)?,
        "sibling_forks" if generator["same_actor_sequence"].as_bool() == Some(true) => {
            bounded_outcome(
                generator,
                "count",
                64,
                "accept",
                "quarantine_entire_actor_sequence_height",
            )?
        }
        "sibling_forks" => bounded_outcome(generator, "count", 16, "accept", "quarantine")?,
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
    bounded_outcome(generator, field, maximum, "accept", "reject")
}

fn bounded_outcome(
    generator: &Value,
    field: &str,
    maximum: u64,
    within: &'static str,
    exceeded: &'static str,
) -> Result<&'static str> {
    let value = generator
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("generated limit case missing integer {field}"))?;
    Ok(if value <= maximum { within } else { exceeded })
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("generated limit case missing integer {field}"))
}
