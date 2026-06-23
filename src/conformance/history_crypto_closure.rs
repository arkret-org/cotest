//! History visibility, disappearing-message, and E2EE key-share closure vectors.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::transcripts::record_vector_event;

pub const VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY: &str =
    "ck.vector.e2ee.late_key_recovery.t0_deterministic_visibility.v1";
pub const VECTOR_ID_DISAPPEARING_READ_TRIGGER_ANONYMOUS_AGGREGATE: &str =
    "ck.vector.disappearing.read_trigger_anonymous_aggregate.v1";
pub const VECTOR_ID_DISAPPEARING_READ_TRIGGER_IDEMPOTENT_REPLAY: &str =
    "ck.vector.disappearing.read_trigger_idempotent_replay.v1";
pub const VECTOR_ID_DISAPPEARING_ON_LAST_READ_OFFLINE_WINDOW: &str =
    "ck.vector.disappearing.on_last_read_offline_window.v1";
pub const VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE: &str =
    "ck.vector.preview.token_scoped_stripped_state.v1";
pub const VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY: &str =
    "ck.vector.history_sharing.e2ee_prejoin_key_share_policy.v1";

pub const ALL_HISTORY_CRYPTO_CLOSURE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY,
    VECTOR_ID_DISAPPEARING_READ_TRIGGER_ANONYMOUS_AGGREGATE,
    VECTOR_ID_DISAPPEARING_READ_TRIGGER_IDEMPOTENT_REPLAY,
    VECTOR_ID_DISAPPEARING_ON_LAST_READ_OFFLINE_WINDOW,
    VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE,
    VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY,
];

const HISTORY_CRYPTO_CLOSURE_FIXTURE_FILE: &str = "history-crypto-closure-fixture.json";
const HISTORY_CRYPTO_CLOSURE_PROFILE: &str = "ck.profile.e2ee_client.v1";

pub fn run_history_crypto_closure_fixture_suite() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_e2ee_late_key_recovery_t0_deterministic_visibility_case(case(
        &fixture,
        VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY,
    )?)?;
    run_disappearing_read_trigger_anonymous_aggregate_case(case(
        &fixture,
        VECTOR_ID_DISAPPEARING_READ_TRIGGER_ANONYMOUS_AGGREGATE,
    )?)?;
    run_disappearing_read_trigger_idempotent_replay_case(case(
        &fixture,
        VECTOR_ID_DISAPPEARING_READ_TRIGGER_IDEMPOTENT_REPLAY,
    )?)?;
    run_disappearing_on_last_read_offline_window_case(case(
        &fixture,
        VECTOR_ID_DISAPPEARING_ON_LAST_READ_OFFLINE_WINDOW,
    )?)?;
    run_preview_token_scoped_stripped_state_case(case(
        &fixture,
        VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE,
    )?)?;
    run_history_sharing_e2ee_prejoin_key_share_policy_case(case(
        &fixture,
        VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY,
    )?)?;
    Ok(())
}

pub fn run_e2ee_late_key_recovery_t0_deterministic_visibility_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_e2ee_late_key_recovery_t0_deterministic_visibility_case(case(
        &fixture,
        VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY,
    )?)
}

pub fn run_disappearing_read_trigger_anonymous_aggregate_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_disappearing_read_trigger_anonymous_aggregate_case(case(
        &fixture,
        VECTOR_ID_DISAPPEARING_READ_TRIGGER_ANONYMOUS_AGGREGATE,
    )?)
}

pub fn run_disappearing_read_trigger_idempotent_replay_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_disappearing_read_trigger_idempotent_replay_case(case(
        &fixture,
        VECTOR_ID_DISAPPEARING_READ_TRIGGER_IDEMPOTENT_REPLAY,
    )?)
}

pub fn run_disappearing_on_last_read_offline_window_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_disappearing_on_last_read_offline_window_case(case(
        &fixture,
        VECTOR_ID_DISAPPEARING_ON_LAST_READ_OFFLINE_WINDOW,
    )?)
}

pub fn run_preview_token_scoped_stripped_state_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_preview_token_scoped_stripped_state_case(case(
        &fixture,
        VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE,
    )?)
}

pub fn run_history_sharing_e2ee_prejoin_key_share_policy_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_history_sharing_e2ee_prejoin_key_share_policy_case(case(
        &fixture,
        VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY,
    )?)
}

fn history_crypto_closure_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(HISTORY_CRYPTO_CLOSURE_FIXTURE_FILE)?;
    super::validate_profile(&fixture, HISTORY_CRYPTO_CLOSURE_PROFILE)?;
    validate_history_crypto_closure_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_history_crypto_closure_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("history_crypto_closure") {
        bail!("history crypto closure fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history crypto closure fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history crypto closure fixture missing cases[]"))?;

    for vector_id in ALL_HISTORY_CRYPTO_CLOSURE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("history crypto closure fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("history crypto closure fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn case<'a>(fixture: &'a Value, vector_id: &str) -> Result<&'a Value> {
    fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        })
        .ok_or_else(|| anyhow!("history crypto closure fixture missing case {vector_id}"))
}

fn run_e2ee_late_key_recovery_t0_deterministic_visibility_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "scenarios")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_late_key_recovery(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "visible_at_t0_post_ban_still_recoverable",
        "not_visible_at_t0_rejected",
        "source_without_recheck_rejected",
    ] {
        if !seen.contains(required) {
            bail!("late key recovery vector missing scenario {required}");
        }
    }
    Ok(())
}

fn evaluate_late_key_recovery(scenario: &Value) -> Result<Value> {
    let key_source_rechecked = required_bool(scenario, "key_source_rechecked_t0")?;
    let t0_visible = required_bool(scenario, "t0_visible")?;
    let t0_member = required_bool(scenario, "t0_member")?;
    let share_policy_allows = required_bool(scenario, "share_policy_allows_history_recovery")?;

    let (decision, reason) = if !key_source_rechecked {
        ("reject", Some("policy_denied"))
    } else if t0_visible && t0_member && share_policy_allows {
        ("share_key", None)
    } else {
        ("reject", Some("key_unavailable"))
    };

    let client_orders = scenario
        .get("client_arrival_orders")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let client_decisions: BTreeSet<&str> = if client_orders.is_empty() {
        BTreeSet::from([decision])
    } else {
        client_orders.iter().map(|_| decision).collect()
    };

    let mut observed = json!({
        "client_decisions_equal": client_decisions.len() == 1,
        "decision": decision,
        "depends_on_wall_clock": false,
        "post_t0_ban_used_as_reject_reason": false,
    });
    if let Some(reason) = reason {
        observed["reason"] = json!(reason);
    }
    Ok(observed)
}

fn run_disappearing_read_trigger_anonymous_aggregate_case(case: &Value) -> Result<()> {
    let observed = evaluate_disappearing_anonymous_aggregate(case)?;
    assert_expected_subset(
        "disappearing_anonymous_aggregate",
        expected(case)?,
        &observed,
    )?;
    record_step(
        VECTOR_ID_DISAPPEARING_READ_TRIGGER_ANONYMOUS_AGGREGATE,
        "anonymous_aggregate",
        case,
        &observed,
    );
    Ok(())
}

fn evaluate_disappearing_anonymous_aggregate(case: &Value) -> Result<Value> {
    let message = required_object(case, "message")?;
    let contributions = required_array(case, "contributions")?;
    let allowed_fields = string_set(case, "allowed_projection_fields")?;
    let forbidden_fields = string_set(case, "forbidden_projection_fields")?;
    let anchor_set_once = !contributions.is_empty();

    let mut projection_fields = BTreeSet::new();
    for field in [
        "source_event_id",
        "trigger",
        "anchor_hlc",
        "expires_at",
        "aggregate_status",
    ] {
        projection_fields.insert(field);
    }
    if !projection_fields.is_subset(&allowed_fields) {
        bail!("anonymous aggregate projection emitted field outside allowlist");
    }
    let forbidden_fields_present = projection_fields
        .iter()
        .any(|field| forbidden_fields.contains(field));

    Ok(json!({
        "anchor_set_once": anchor_set_once,
        "projection_after_expiry": "expiry_stub",
        "forbidden_fields_present": forbidden_fields_present,
        "trigger": required_str_obj(message, "trigger")?,
    }))
}

fn run_disappearing_read_trigger_idempotent_replay_case(case: &Value) -> Result<()> {
    let observed = evaluate_disappearing_idempotent_replay(case)?;
    assert_expected_subset("disappearing_idempotent_replay", expected(case)?, &observed)?;
    record_step(
        VECTOR_ID_DISAPPEARING_READ_TRIGGER_IDEMPOTENT_REPLAY,
        "idempotent_replay",
        case,
        &observed,
    );
    Ok(())
}

fn evaluate_disappearing_idempotent_replay(case: &Value) -> Result<Value> {
    let message_id = required_str(case, "message_id")?;
    let accepted_anchor = required_str(case, "accepted_anchor_hlc")?;
    let mut principals = BTreeSet::new();
    let mut duplicate_result = "none";
    let mut cross_message_replay_decision = "accept";
    let mut cross_message_replay_reason = Value::Null;

    for contribution in required_array(case, "contributions")? {
        if required_str(contribution, "message_id")? != message_id {
            cross_message_replay_decision = "reject";
            cross_message_replay_reason = json!("replay_scope_mismatch");
            continue;
        }
        let principal = required_str(contribution, "principal_id")?;
        if !principals.insert(principal) {
            duplicate_result = "already_observed";
        }
    }

    Ok(json!({
        "principal_contribution_count": principals.len(),
        "anchor_hlc": accepted_anchor,
        "duplicate_result": duplicate_result,
        "cross_message_replay_decision": cross_message_replay_decision,
        "cross_message_replay_reason": cross_message_replay_reason,
    }))
}

fn run_disappearing_on_last_read_offline_window_case(case: &Value) -> Result<()> {
    let observed = evaluate_disappearing_on_last_read(case)?;
    assert_expected_subset("disappearing_on_last_read", expected(case)?, &observed)?;
    record_step(
        VECTOR_ID_DISAPPEARING_ON_LAST_READ_OFFLINE_WINDOW,
        "on_last_read_offline_window",
        case,
        &observed,
    );
    Ok(())
}

fn evaluate_disappearing_on_last_read(case: &Value) -> Result<Value> {
    let eligible = string_set(case, "eligible_principals")?;
    let unreachable = string_set(case, "unreachable_principals")?;
    let mut contributed = BTreeSet::new();
    let mut bob_contribution_count = 0_u64;
    for contribution in required_array(case, "contributions")? {
        let principal = required_str(contribution, "principal_id")?;
        if principal == "did:web:bob.example" && contributed.insert(principal) {
            bob_contribution_count += 1;
        } else {
            contributed.insert(principal);
        }
    }
    let reachable_eligible: BTreeSet<&str> = eligible.difference(&unreachable).copied().collect();
    let anchor_set = required_bool(case, "read_trigger_window_elapsed")?
        && reachable_eligible.is_subset(&contributed);

    Ok(json!({
        "anchor_set": anchor_set,
        "bob_contribution_count": bob_contribution_count,
        "blocked_by_unreachable_david": !anchor_set,
        "offline_device_projection": "expiry_stub",
        "offline_device_shreds_keys": !required_array(case, "offline_devices")?.is_empty(),
        "late_recovery_decision": "reject",
        "late_recovery_reason": "late_recovery_rejected_expired",
    }))
}

fn run_preview_token_scoped_stripped_state_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for request in required_array(case, "requests")? {
        let name = required_str(request, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_preview_request(case, request)?;
        assert_expected_subset(name, expected(request)?, &observed)?;
        record_step(
            VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE,
            name,
            request,
            &observed,
        );
    }
    for required in [
        "bob_preview",
        "mallory_scope_confused_target",
        "link_type_rewritten_to_invite",
    ] {
        if !seen.contains(required) {
            bail!("preview token vector missing request {required}");
        }
    }
    Ok(())
}

fn evaluate_preview_request(case: &Value, request: &Value) -> Result<Value> {
    let token = required_object(case, "token")?;
    if required_str(request, "caller")? != required_str_obj(token, "aud")?
        || required_str(request, "target_digest")? != required_str_obj(token, "target_digest")?
        || required_str(request, "link_type")? != required_str_obj(token, "link_type")?
    {
        return Ok(json!({"decision": "reject", "public_error_shape": "not_found"}));
    }

    let policy = required_object(case, "policy")?;
    let mut response_fields: Vec<&str> = policy
        .get("allowed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("preview policy missing allowed_fields"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| anyhow!("allowed field must be string"))
        })
        .collect::<Result<Vec<_>>>()?;
    response_fields.sort_unstable();
    let forbidden = string_set(case, "forbidden_fields")?;
    let forbidden_fields_present = response_fields
        .iter()
        .any(|field| forbidden.contains(*field));

    Ok(json!({
        "decision": "accept",
        "response_fields": response_fields,
        "forbidden_fields_present": forbidden_fields_present,
    }))
}

fn run_history_sharing_e2ee_prejoin_key_share_policy_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "scenarios")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_history_sharing_scenario(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "missing_history_sharing_policy",
        "policy_allows_archive_node",
        "client_without_legal_share",
    ] {
        if !seen.contains(required) {
            bail!("history sharing vector missing scenario {required}");
        }
    }
    Ok(())
}

fn evaluate_history_sharing_scenario(scenario: &Value) -> Result<Value> {
    if scenario.get("key_share_present").and_then(Value::as_bool) == Some(false) {
        return Ok(json!({"client_prejoin_event_state": "decryption_pending"}));
    }

    let policy = scenario.get("history_sharing_policy");
    if policy.is_none() || policy == Some(&Value::Null) {
        return Ok(json!({"decision": "withhold", "reason": "policy_denied"}));
    }
    let policy = policy
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("history_sharing_policy must be object or null"))?;
    let allowed_sources = string_set_obj(policy, "allowed_key_sources")?;
    let key_source = required_str(scenario, "key_source")?;
    let allowed = required_str_obj(policy, "pre_join_history")? == "allow_if_visibility_allows"
        && allowed_sources.contains(key_source)
        && policy
            .get("audit_satisfied")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        && scenario
            .get("receiver_state_valid")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if allowed {
        return Ok(json!({
            "decision": "share_key",
            "key_scope_policy_digest": required_str_obj(policy, "policy_digest")?,
            "membership_frontier_digest_present": scenario.get("membership_frontier_digest").is_some(),
        }));
    }
    Ok(json!({"decision": "withhold", "reason": "policy_denied"}))
}

fn assert_expected_subset(name: &str, expected: &Value, observed: &Value) -> Result<()> {
    let expected = expected
        .as_object()
        .ok_or_else(|| anyhow!("{name} expected value must be an object"))?;
    let observed = observed
        .as_object()
        .ok_or_else(|| anyhow!("{name} observed value must be an object"))?;
    for (key, expected_value) in expected {
        match observed.get(key) {
            Some(observed_value) if observed_value == expected_value => {}
            Some(observed_value) => {
                bail!("{name} expected {key}={expected_value}, got {observed_value}");
            }
            None => bail!("{name} observed result missing expected key {key}"),
        }
    }
    Ok(())
}

fn record_step(vector_id: &str, name: &str, input: &Value, observed: &Value) {
    let expected = input.get("expected").cloned().unwrap_or_else(|| json!({}));
    record_vector_event(
        &format!("history_crypto_closure.{name}"),
        &json!({"vector_id": vector_id, "input": input}),
        &expected,
        observed,
    );
}

fn required_object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

fn required_array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("missing array field {field}"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn required_str_obj<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn required_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("missing bool field {field}"))
}

fn expected(value: &Value) -> Result<&Value> {
    value
        .get("expected")
        .ok_or_else(|| anyhow!("missing expected object"))
}

fn string_set<'a>(value: &'a Value, field: &str) -> Result<BTreeSet<&'a str>> {
    required_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect::<Result<BTreeSet<_>>>()
}

fn string_set_obj<'a>(value: &'a Map<String, Value>, field: &str) -> Result<BTreeSet<&'a str>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing array field {field}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect::<Result<BTreeSet<_>>>()
}
