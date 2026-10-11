use anyhow::{Result, anyhow, bail};
use arkret_wire::ProfileId;
use serde_json::Value;

use super::{load_fixture_value, required_str, required_u64, validate_profile};

const FIXTURE_FILE: &str = "scalability-limits-fixture.json";

/// `scalability-constraints.md` section 2.1.1: the complete canonical accepted
/// Event envelope, every active producer proof included and the read-view
/// `unsigned` excluded.
const ACCEPTED_EVENT_ENVELOPE_MAX_BYTES: u64 = 1_048_576;

pub fn run_scalability_limits_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE_FILE)?;
    validate_profile(&fixture, ProfileId::CORE_EVENT_STORE_V1)?;
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
        "event_refs_by_role" => decision(generator, "count", 64)?,
        "patch_path" => validate_patch_path_case(case, generator)?,
        "patch_path_literals" => {
            validate_patch_path_literals(case, generator)?;
            return Ok(());
        }
        "canonical_operation_envelope_bytes" => {
            decision(generator, "encoded_size_bytes", 1_048_576)?
        }
        "accepted_event_envelope_canonical_bytes" => {
            decision(generator, "encoded_size_bytes", 1_048_576)?
        }
        "mls_add_welcome_event_preflight" => {
            if required_str(generator, "carrier")? != "canonical_unpadded_base64url_inline"
                || generator["commit_network_write_started"].as_bool() != Some(false)
            {
                bail!("{name} MLS Welcome preflight input drifted");
            }
            let bytes = required_u64(generator, "accepted_welcome_event_bytes")?;
            let actual = if bytes <= 1_048_576 {
                "continue_commit_generation"
            } else {
                "reject"
            };
            if case.pointer("/expected/decision").and_then(Value::as_str) != Some(actual) {
                bail!("{name} MLS Welcome preflight boundary drifted");
            }
            if actual == "continue_commit_generation"
                && case
                    .pointer("/expected/commit_network_write_allowed")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                bail!("{name} accepted MLS Welcome did not allow commit generation");
            }
            if actual == "reject"
                && (case
                    .pointer("/expected/commit_network_write_started")
                    .and_then(Value::as_bool)
                    != Some(false)
                    || case
                        .pointer("/expected/post_commit_state_installed")
                        .and_then(Value::as_bool)
                        != Some(false))
            {
                bail!("{name} rejected MLS Welcome crossed the preflight boundary");
            }
            return Ok(());
        }
        "event_admission_proof_budget_boundary" => {
            // `scalability-constraints.md` section 2.1.1 fixes the measured
            // object as the accepted envelope *including every active producer
            // proof*. This case exists because the pre-proof envelope fits: a
            // runner that measured the producer's own bytes would accept an
            // Event that is over the limit once the admission proof set it must
            // carry is attached.
            let producer = required_u64(generator, "producer_envelope_bytes")?;
            let accepted = required_u64(generator, "accepted_candidate_bytes")?;
            let proof_kinds = generator
                .get("proof_kinds")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("{name} must name the proofs the candidate carries"))?;
            if proof_kinds.is_empty() {
                bail!("{name} must name at least one proof kind, or it measures nothing");
            }
            if producer > ACCEPTED_EVENT_ENVELOPE_MAX_BYTES {
                bail!(
                    "{name} pre-proof envelope must fit, or the case proves nothing about proofs"
                );
            }
            if accepted <= producer {
                bail!("{name} accepted candidate must exceed the envelope it attaches proofs to");
            }
            let over = accepted > ACCEPTED_EVENT_ENVELOPE_MAX_BYTES;
            let actual = if over { "reject" } else { "accept" };
            if case.pointer("/expected/decision").and_then(Value::as_str) != Some(actual) {
                bail!("{name} admission-proof budget boundary drifted");
            }
            if over {
                if case.pointer("/expected/error_code").and_then(Value::as_str)
                    != Some(arkret_wire::ErrorCode::PAYLOAD_TOO_LARGE)
                {
                    bail!("{name} over-limit Event must reject as payload_too_large");
                }
                // The rejection has to land before anything is written: an
                // oversize Event that is refused *after* a commit starts leaves
                // exactly the half state the limit exists to prevent.
                if case
                    .pointer("/expected/commit_started")
                    .and_then(Value::as_bool)
                    != Some(false)
                    || case
                        .pointer("/expected/state_unchanged")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    bail!("{name} over-limit Event did not reject before any commit");
                }
            }
            return Ok(());
        }
        "event_submit_envelope" => {
            let actual = if generator["unsigned_present"].as_bool() == Some(true) {
                "reject"
            } else {
                "accept"
            };
            if case.pointer("/expected/decision").and_then(Value::as_str) != Some(actual) {
                bail!("{name} submit unsigned exclusion drifted");
            }
            return Ok(());
        }
        "non_streaming_json_operation_canonical_body" => {
            validate_limit_values(generator, "encoded_size_bytes", 8_388_608)?;
            return Ok(());
        }
        "non_streaming_json_http_message_content" => {
            validate_limit_values(generator, "wire_bytes", 16_777_216)?;
            return Ok(());
        }
        "json_wire_amplification" => {
            if required_u64(generator, "wire_bytes")? <= 16_777_216
                || case.pointer("/expected/decision").and_then(Value::as_str) != Some("reject")
            {
                bail!("{name} wire amplification boundary drifted");
            }
            return Ok(());
        }
        "non_streaming_json_request_headers" => {
            if case
                .pointer("/expected/http_status")
                .and_then(Value::as_u64)
                != Some(415)
                || case
                    .pointer("/expected/body_read_started")
                    .and_then(Value::as_bool)
                    != Some(false)
            {
                bail!("{name} Content-Encoding ordering drifted");
            }
            return Ok(());
        }
        "operation_batch_matrix" => {
            let rows = generator
                .get("cases")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("{name} missing operation batch cases"))?;
            if rows.len() != 3
                || rows[0]["count"].as_u64() != Some(1_000)
                || rows[0]["canonical_body_bytes"].as_u64() != Some(8_388_608)
                || rows[1]["canonical_body_bytes"].as_u64() != Some(8_388_609)
                || rows[2]["count"].as_u64() != Some(1_001)
            {
                bail!("{name} batch count/byte conjunction drifted");
            }
            return Ok(());
        }
        "response_page_candidates" => {
            if required_u64(generator, "candidate_count")? != 1_000
                || required_u64(
                    generator,
                    "next_candidate_would_exceed_canonical_body_bytes",
                )? != 8_388_608
            {
                bail!("{name} response page byte stop drifted");
            }
            return Ok(());
        }
        "service_added_event_read_unsigned_canonical_bytes" => {
            validate_limit_values(generator, "encoded_size_bytes", 16_384)?;
            return Ok(());
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
        "resource_selector_ast" => decision(generator, "depth", 8)?,
        "authorization_grant_expansion" => {
            bounded_outcome(generator, "count", 1_024, "accept", "fail_closed")?
        }
        "active_circle_count" => decision(generator, "realm_active_circle_count", 999)?,
        "active_circle_count_by_composition" => {
            composition_decision(generator, &["ordinary_active_circles"], 999)?
        }
        "actor_active_mls_circle_memberships" => decision(generator, "count", 255)?,
        "actor_active_mls_circle_memberships_by_composition" => {
            composition_decision(generator, &["ordinary_mls_circle_memberships"], 255)?
        }
        "relation_chain" => {
            validate_relation_expansion_depth(case, generator)?;
            return Ok(());
        }
        "decoded_canonical_size_matrix" => {
            validate_decoded_canonical_size_matrix(case, generator)?;
            return Ok(());
        }
        "realm_snapshot_maximal_disclosure_projection" => {
            validate_snapshot_inline_capacity(case, generator)?;
            return Ok(());
        }
        "concurrent_realm_snapshot_capacity_candidates" => {
            validate_concurrent_snapshot_capacity(case, generator)?;
            return Ok(());
        }
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

fn validate_patch_path_case(case: &Value, generator: &Value) -> Result<&'static str> {
    let segment_lengths =
        if let Some(lengths) = generator.get("segment_lengths").and_then(Value::as_array) {
            lengths
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| anyhow!("patch_path segment length must be an integer"))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            let count = required_u64(generator, "segment_count")?;
            let length = required_u64(generator, "segment_length")?;
            vec![length; usize::try_from(count)?]
        };
    let alphabet = required_str(generator, "alphabet")?;
    if alphabet.is_empty()
        || !alphabet
            .chars()
            .all(|character| character.is_ascii_lowercase())
    {
        bail!("patch_path generator alphabet is outside the v1 grammar");
    }
    let encoded_size = segment_lengths.iter().sum::<u64>()
        + u64::try_from(segment_lengths.len().saturating_sub(1))?;
    let valid = !segment_lengths.is_empty()
        && segment_lengths.len() <= 16
        && encoded_size <= 1_024
        && segment_lengths
            .iter()
            .all(|length| (1..=64).contains(length));
    if let Some(expected) = case
        .pointer("/expected/segment_count")
        .and_then(Value::as_u64)
        && expected != u64::try_from(segment_lengths.len())?
    {
        bail!("patch_path generated segment count drifted");
    }
    if let Some(expected) = case
        .pointer("/expected/encoded_size_bytes")
        .and_then(Value::as_u64)
        && expected != encoded_size
    {
        bail!("patch_path generated byte length drifted");
    }
    Ok(if valid { "accept" } else { "reject" })
}

fn validate_patch_path_literals(case: &Value, generator: &Value) -> Result<()> {
    let values = generator
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("patch_path_literals generator omits values[]"))?;
    if values.is_empty()
        || values
            .iter()
            .any(|value| value.as_str().is_none_or(valid_v1_patch_path))
    {
        bail!("patch_path_literals contains a valid v1 path or a non-string");
    }
    if case
        .pointer("/expected/decision_for_every_value")
        .and_then(Value::as_str)
        != Some("reject")
        || case
            .pointer("/expected/reason_code")
            .and_then(Value::as_str)
            != Some("patch_path_invalid")
        || case
            .pointer("/expected/parser_fallback")
            .and_then(Value::as_bool)
            != Some(false)
    {
        bail!("patch_path literal rejection contract drifted");
    }
    Ok(())
}

fn valid_v1_patch_path(path: &str) -> bool {
    if path.len() > 1_024 {
        return false;
    }
    let segments = path.split('.').collect::<Vec<_>>();
    !segments.is_empty()
        && segments.len() <= 16
        && segments.iter().all(|segment| {
            let mut characters = segment.chars();
            characters
                .next()
                .is_some_and(|first| first.is_ascii_lowercase())
                && segment.len() <= 64
                && characters.all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
                })
        })
}

fn validate_decoded_canonical_size_matrix(case: &Value, generator: &Value) -> Result<()> {
    const EXPECTED_DIMENSIONS: &[(&str, u64, &str)] = &[
        ("cursor_payload", 65_536, "param_invalid"),
        ("resource_selector", 65_536, "selector_too_complex"),
        (
            "resource_selector.unknown_field_count",
            256,
            "selector_too_complex",
        ),
        ("resource_selector.required_claims", 32, "schema_violation"),
        (
            "resource_selector.required_claims[].trusted_issuers",
            16,
            "schema_violation",
        ),
    ];

    let name = required_str(case, "name")?;
    let dimensions = generator
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{name} missing generated decoded-size cases[]"))?;
    if dimensions.len() != EXPECTED_DIMENSIONS.len() {
        bail!(
            "{name} decoded-size dimension count drifted: expected {}, got {}",
            EXPECTED_DIMENSIONS.len(),
            dimensions.len()
        );
    }
    for dimension in dimensions {
        let field = required_str(dimension, "field")?;
        let (expected_field, expected_limit, expected_error) = EXPECTED_DIMENSIONS
            .iter()
            .find(|(expected_field, ..)| *expected_field == field)
            .ok_or_else(|| anyhow!("{name} has unknown decoded-size dimension {field}"))?;
        let limit = dimension
            .get("limit_bytes")
            .or_else(|| dimension.get("limit"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("{name} dimension {field} has no integer limit"))?;
        if limit != *expected_limit
            || dimension.get("over_error_code").and_then(Value::as_str) != Some(*expected_error)
        {
            bail!("{name} dimension {expected_field} limit or error code drifted");
        }
        let values = dimension
            .get("values")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("{name} dimension {field} missing values[]"))?
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .ok_or_else(|| anyhow!("{name} dimension {field} has a non-integer value"))
            })
            .collect::<Result<Vec<_>>>()?;
        let expected_values = [limit - 1, limit, limit + 1];
        if values.as_slice() != expected_values {
            bail!(
                "{name} dimension {field} must generate limit-1/limit/limit+1: expected {expected_values:?}, got {values:?}"
            );
        }
    }
    if case
        .pointer("/expected/limit_minus_one")
        .and_then(Value::as_str)
        != Some("accept")
        || case.pointer("/expected/limit").and_then(Value::as_str) != Some("accept")
        || case
            .pointer("/expected/limit_plus_one")
            .and_then(Value::as_str)
            != Some("reject_without_partial_parse")
        || case
            .pointer("/expected/unknown_fields_count_toward_canonical_bytes")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("{name} decoded canonical size expectations drifted");
    }
    Ok(())
}

/// Maximum canonical signed inline Realm snapshot body (§4.1 scalability constraints).
const REALM_SNAPSHOT_INLINE_CAPACITY_BYTES: u64 = 8 * 1024 * 1024;

fn validate_snapshot_inline_capacity(case: &Value, generator: &Value) -> Result<()> {
    let name = case["name"].as_str().unwrap_or("snapshot capacity case");
    let bytes = generator["canonical_signed_body_bytes_after_candidate_commit"]
        .as_u64()
        .ok_or_else(|| anyhow!("{name} missing canonical signed body size"))?;
    let expected = &case["expected"];
    if bytes <= REALM_SNAPSHOT_INLINE_CAPACITY_BYTES {
        if expected["decision"] != "accept_when_all_other_admission_checks_pass"
            || expected["paging_or_truncation_used"] != false
        {
            bail!("{name}: a snapshot within capacity must admit whole, without paging");
        }
    } else if expected["decision"] != "reject"
        || expected["error_code"] != "failed_precondition"
        || expected["reason_code"] != arkret_wire::ReasonCode::SNAPSHOT_CAPACITY_EXCEEDED
        || expected["state_unchanged"] != true
        || expected["partial_snapshot_or_hidden_overflow"] != false
    {
        bail!("{name}: an over-capacity candidate must reject atomically");
    }
    Ok(())
}

/// Concurrent candidates that each fit the old cut serialize at one admission
/// boundary: the loser re-checks the current cut and is refused.
fn validate_concurrent_snapshot_capacity(case: &Value, generator: &Value) -> Result<()> {
    let name = case["name"]
        .as_str()
        .unwrap_or("concurrent snapshot capacity case");
    if generator["each_candidate_individually_fits_old_cut"] != true {
        bail!("{name}: candidates must each fit the old cut");
    }
    let combined = generator["combined_canonical_signed_body_bytes"]
        .as_u64()
        .ok_or_else(|| anyhow!("{name} missing combined size"))?;
    let winners = if combined > REALM_SNAPSHOT_INLINE_CAPACITY_BYTES {
        1
    } else {
        2
    };
    let expected = &case["expected"];
    if expected["accepted_winners"].as_u64() != Some(winners)
        || expected["loser_rechecks_current_cut"] != true
        || expected["loser_error_code"] != "failed_precondition"
        || expected["loser_reason_code"] != arkret_wire::ReasonCode::SNAPSHOT_CAPACITY_EXCEEDED
        || expected["final_state_within_limit"] != true
    {
        bail!("{name}: concurrent snapshot candidates did not share one admission boundary");
    }
    Ok(())
}

fn decision(generator: &Value, field: &str, maximum: u64) -> Result<&'static str> {
    bounded_outcome(generator, field, maximum, "accept", "reject")
}

fn validate_limit_values(generator: &Value, field: &str, limit: u64) -> Result<()> {
    let values = generator
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("generated limit matrix missing {field}[]"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| anyhow!("generated limit matrix {field} contains non-integer"))
        })
        .collect::<Result<Vec<_>>>()?;
    let expected = [limit - 1, limit, limit + 1];
    if values.as_slice() != expected {
        bail!("generated limit matrix {field} drifted: expected {expected:?}, got {values:?}");
    }
    Ok(())
}

fn composition_decision(generator: &Value, fields: &[&str], maximum: u64) -> Result<&'static str> {
    let composition = generator
        .get("count_composition")
        .ok_or_else(|| anyhow!("generated composition case missing count_composition"))?;
    let count = fields.iter().try_fold(0_u64, |total, field| {
        total
            .checked_add(required_u64(composition, field)?)
            .ok_or_else(|| anyhow!("generated composition count overflowed"))
    })?;
    Ok(if count <= maximum { "accept" } else { "reject" })
}

/// `ak.vector.scalability.relation_expansion_depth.v1` — a chain at the depth
/// limit expands in full; one level deeper stops *before* reading the extra
/// level and exposes a Lazy Link boundary instead of traversing further.
///
/// The assertion is on the whole expansion outcome, not just the decision
/// string: an implementation that returned `accept_with_truncation` while
/// still walking level 33 would satisfy a decision-only check.
fn validate_relation_expansion_depth(case: &Value, generator: &Value) -> Result<()> {
    const RELATION_EXPANSION_DEPTH_LIMIT: u64 = 32;

    let name = required_str(case, "name")?;
    let depth = required_u64(generator, "depth")?;
    let truncated = depth > RELATION_EXPANSION_DEPTH_LIMIT;
    let expanded_depth = depth.min(RELATION_EXPANSION_DEPTH_LIMIT);
    let decision = if truncated {
        "accept_with_truncation"
    } else {
        "accept"
    };

    let expected = case
        .get("expected")
        .ok_or_else(|| anyhow!("{name} missing expected"))?;
    let expect_str = |field: &str| -> Result<&str> {
        expected
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{name} missing expected.{field}"))
    };

    if expect_str("decision")? != decision {
        bail!(
            "{name} decision drifted: expected {}, got {decision}",
            expect_str("decision")?
        );
    }
    if required_u64(expected, "expanded_depth")? != expanded_depth {
        bail!("{name} expanded_depth drifted: computed {expanded_depth}");
    }
    if expected.get("truncated").and_then(Value::as_bool) != Some(truncated) {
        bail!("{name} truncated flag drifted: computed {truncated}");
    }
    if truncated {
        if expect_str("boundary_projection")? != "lazy_link" {
            bail!("{name} must expose a lazy_link boundary at the truncation point");
        }
        // The bound is "stop before reading", not "read then drop": the first
        // unread level is exactly one past the limit.
        if required_u64(expected, "must_not_read_depth")? != RELATION_EXPANSION_DEPTH_LIMIT + 1 {
            bail!("{name} must_not_read_depth drifted from the first unread level");
        }
    } else if expected.get("boundary_projection").is_some() {
        bail!("{name} declares a truncation boundary on a fully expanded chain");
    }
    Ok(())
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
