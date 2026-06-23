//! Service-closure fail-closed conformance vectors.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::transcripts::record_vector_event;

pub const VECTOR_ID_INVITE_CONSUMED_TOKEN_RESUBJECT_REJECTED: &str =
    "ck.vector.invite.consumed_token_resubject_rejected.v1";
pub const VECTOR_ID_EPHEMERAL_CAPABILITY_TTL: &str = "ck.vector.ephemeral.capability_ttl.v1";
pub const VECTOR_ID_PROJECTION_PAGINATION_SHAPE: &str = "ck.vector.projection.pagination_shape.v1";
pub const VECTOR_ID_RANGE_COMPLETENESS_WITNESS_DISAGREEMENT: &str =
    "ck.vector.range_completeness.witness_disagreement.v1";
pub const VECTOR_ID_CURSOR_REVOKE_HIGH_ASSURANCE: &str =
    "ck.vector.cursor.revoke_high_assurance.v1";
pub const VECTOR_ID_DEVICE_RECOVERY_LIFECYCLE: &str = "ck.vector.device_recovery.lifecycle.v1";
pub const VECTOR_ID_DEVICE_REVOCATION_SEAL_BINDING: &str =
    "ck.vector.device.revocation_seal_binding.v1";
pub const VECTOR_ID_PUSH_WAKEUP_POLICY: &str = "ck.vector.push.wakeup_policy.v1";

pub const ALL_SERVICE_CLOSURE_HARDENING_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_INVITE_CONSUMED_TOKEN_RESUBJECT_REJECTED,
    VECTOR_ID_EPHEMERAL_CAPABILITY_TTL,
    VECTOR_ID_PROJECTION_PAGINATION_SHAPE,
    VECTOR_ID_RANGE_COMPLETENESS_WITNESS_DISAGREEMENT,
    VECTOR_ID_CURSOR_REVOKE_HIGH_ASSURANCE,
    VECTOR_ID_DEVICE_RECOVERY_LIFECYCLE,
    VECTOR_ID_DEVICE_REVOCATION_SEAL_BINDING,
    VECTOR_ID_PUSH_WAKEUP_POLICY,
];

const SERVICE_CLOSURE_HARDENING_FIXTURE_FILE: &str = "service-closure-hardening-fixture.json";
const SERVICE_CLOSURE_HARDENING_PROFILE: &str = "ck.profile.privacy_security_vectors.v1";

pub fn run_service_closure_hardening_fixture_suite() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_invite_consumed_token_resubject_rejected_case(case(
        &fixture,
        VECTOR_ID_INVITE_CONSUMED_TOKEN_RESUBJECT_REJECTED,
    )?)?;
    run_ephemeral_capability_ttl_case(case(&fixture, VECTOR_ID_EPHEMERAL_CAPABILITY_TTL)?)?;
    run_projection_pagination_shape_case(case(&fixture, VECTOR_ID_PROJECTION_PAGINATION_SHAPE)?)?;
    run_range_completeness_witness_disagreement_case(case(
        &fixture,
        VECTOR_ID_RANGE_COMPLETENESS_WITNESS_DISAGREEMENT,
    )?)?;
    run_cursor_revoke_high_assurance_case(case(&fixture, VECTOR_ID_CURSOR_REVOKE_HIGH_ASSURANCE)?)?;
    run_device_recovery_lifecycle_case(case(&fixture, VECTOR_ID_DEVICE_RECOVERY_LIFECYCLE)?)?;
    run_device_revocation_seal_binding_case(case(
        &fixture,
        VECTOR_ID_DEVICE_REVOCATION_SEAL_BINDING,
    )?)?;
    run_push_wakeup_policy_case(case(&fixture, VECTOR_ID_PUSH_WAKEUP_POLICY)?)?;
    Ok(())
}

pub fn run_invite_consumed_token_resubject_rejected_vector() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_invite_consumed_token_resubject_rejected_case(case(
        &fixture,
        VECTOR_ID_INVITE_CONSUMED_TOKEN_RESUBJECT_REJECTED,
    )?)
}

pub fn run_ephemeral_capability_ttl_vector() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_ephemeral_capability_ttl_case(case(&fixture, VECTOR_ID_EPHEMERAL_CAPABILITY_TTL)?)
}

pub fn run_projection_pagination_shape_vector() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_projection_pagination_shape_case(case(&fixture, VECTOR_ID_PROJECTION_PAGINATION_SHAPE)?)
}

pub fn run_range_completeness_witness_disagreement_vector() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_range_completeness_witness_disagreement_case(case(
        &fixture,
        VECTOR_ID_RANGE_COMPLETENESS_WITNESS_DISAGREEMENT,
    )?)
}

pub fn run_cursor_revoke_high_assurance_vector() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_cursor_revoke_high_assurance_case(case(&fixture, VECTOR_ID_CURSOR_REVOKE_HIGH_ASSURANCE)?)
}

pub fn run_device_recovery_lifecycle_vector() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_device_recovery_lifecycle_case(case(&fixture, VECTOR_ID_DEVICE_RECOVERY_LIFECYCLE)?)
}

pub fn run_device_revocation_seal_binding_vector() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_device_revocation_seal_binding_case(case(
        &fixture,
        VECTOR_ID_DEVICE_REVOCATION_SEAL_BINDING,
    )?)
}

pub fn run_push_wakeup_policy_vector() -> Result<()> {
    let fixture = service_closure_hardening_fixture()?;
    run_push_wakeup_policy_case(case(&fixture, VECTOR_ID_PUSH_WAKEUP_POLICY)?)
}

fn service_closure_hardening_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(SERVICE_CLOSURE_HARDENING_FIXTURE_FILE)?;
    super::validate_profile(&fixture, SERVICE_CLOSURE_HARDENING_PROFILE)?;
    validate_service_closure_hardening_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_service_closure_hardening_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("service_closure_hardening") {
        bail!("service closure hardening fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("service closure hardening fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("service closure hardening fixture missing cases[]"))?;

    for vector_id in ALL_SERVICE_CLOSURE_HARDENING_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("service closure hardening fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("service closure hardening fixture missing asserted case {vector_id}");
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
        .ok_or_else(|| anyhow!("service closure hardening fixture missing case {vector_id}"))
}

fn run_invite_consumed_token_resubject_rejected_case(case: &Value) -> Result<()> {
    let state = case
        .get("state")
        .ok_or_else(|| anyhow!("invite consumed-token vector missing state"))?;
    required_object(case, "state")?;
    let requests = required_array(case, "requests")?;
    let mut seen = BTreeSet::new();
    for request in requests {
        let name = required_str(request, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_invite_binding_request(state, request)?;
        assert_expected_subset(name, expected(request)?, &observed)?;
        record_step(
            VECTOR_ID_INVITE_CONSUMED_TOKEN_RESUBJECT_REJECTED,
            name,
            request,
            &observed,
        );
    }

    for required in ["idempotent_same_subject_replay", "resubject_to_mallory"] {
        if !seen.contains(required) {
            bail!("invite consumed-token vector missing request {required}");
        }
    }

    let reducer_event = case
        .get("reducer_event")
        .ok_or_else(|| anyhow!("invite consumed-token vector missing reducer_event"))?;
    required_object(case, "reducer_event")?;
    let observed = evaluate_invite_reducer_event(state, reducer_event)?;
    assert_expected_subset("reducer_event", expected(reducer_event)?, &observed)?;
    record_step(
        VECTOR_ID_INVITE_CONSUMED_TOKEN_RESUBJECT_REJECTED,
        "reducer_event",
        reducer_event,
        &observed,
    );

    Ok(())
}

fn evaluate_invite_binding_request(state: &Value, request: &Value) -> Result<Value> {
    let same_subject = required_str(state, "subject_id")? == required_str(request, "subject_id")?;
    let same_digest = required_str(state, "binding_proof_digest")?
        == required_str(request, "binding_proof_digest")?;
    if same_subject && same_digest {
        return Ok(json!({
            "decision": "accept",
            "binding_proof": required_str(state, "binding_proof")?,
        }));
    }
    Ok(json!({
        "decision": "reject",
        "audit_reason": "duplicate_conflict",
        "public_error_shape": "not_found_equivalent",
        "new_binding_proof_signed": false,
    }))
}

fn evaluate_invite_reducer_event(state: &Value, event: &Value) -> Result<Value> {
    let resubject = required_str(state, "subject_id")? != required_str(event, "subject_id")?;
    let same_invite = required_str(state, "invite_id")? == required_str(event, "invite_id")?;
    let same_nonce = required_str(state, "claim_nonce")? == required_str(event, "claim_nonce")?;
    if resubject && same_invite && same_nonce {
        Ok(json!({"decision": "reject", "reason": "duplicate_conflict"}))
    } else {
        Ok(json!({"decision": "accept"}))
    }
}

fn run_ephemeral_capability_ttl_case(case: &Value) -> Result<()> {
    let advertised = required_object(case, "advertised_kinds")?;
    let mut seen = BTreeSet::new();
    for step in required_array(case, "steps")? {
        let name = required_str(step, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_ephemeral_step(advertised, step)?;
        assert_expected_subset(name, expected(step)?, &observed)?;
        record_step(VECTOR_ID_EPHEMERAL_CAPABILITY_TTL, name, step, &observed);
    }
    for required in [
        "wrong_capability_action",
        "ttl_above_kind_ceiling",
        "channel_unavailable",
    ] {
        if !seen.contains(required) {
            bail!("ephemeral capability vector missing step {required}");
        }
    }
    Ok(())
}

fn evaluate_ephemeral_step(advertised: &Map<String, Value>, step: &Value) -> Result<Value> {
    let kind = required_str(step, "kind")?;
    let actor_actions = string_set(step, "actor_actions")?;
    let Some(kind_policy) = advertised.get(kind) else {
        return Ok(json!({
            "decision": "reject",
            "reason": "ephemeral_kind_not_permitted",
            "durable_event_written": false,
        }));
    };
    let required_action = required_str(kind_policy, "required_action")?;
    if !actor_actions.contains(required_action) {
        return Ok(json!({
            "decision": "reject",
            "reason": "ephemeral_kind_not_permitted",
            "durable_event_written": false,
        }));
    }
    let ttl_ms = required_u64(step, "ttl_ms")?;
    let max_ttl_ms = required_u64(kind_policy, "max_ttl_ms")?;
    if ttl_ms > max_ttl_ms {
        return Ok(json!({
            "decision": "reject",
            "reason": "ephemeral_ttl_out_of_range",
            "durable_event_written": false,
        }));
    }
    if !required_bool(step, "channel_available")? {
        return Ok(json!({
            "decision": "reject",
            "reason": "ephemeral_channel_unavailable",
            "durable_event_written": false,
            "actor_seq_advanced": false,
            "realm_frontier_advanced": false,
        }));
    }
    Ok(json!({"decision": "accept", "durable_event_written": false}))
}

fn run_projection_pagination_shape_case(case: &Value) -> Result<()> {
    let caller = required_str(case, "caller")?;
    let selector_digest = required_str(case, "selector_digest")?;
    let purpose = required_str(case, "purpose")?;
    let mut seen = BTreeSet::new();
    for response in required_array(case, "responses")? {
        let name = required_str(response, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_projection_response(response, caller, selector_digest, purpose)?;
        assert_expected_subset(name, expected(response)?, &observed)?;
        record_step(
            VECTOR_ID_PROJECTION_PAGINATION_SHAPE,
            name,
            response,
            &observed,
        );
    }
    for required in [
        "first_page",
        "last_page",
        "missing_has_more",
        "malformed_cursor",
        "cross_caller_cursor_reuse",
    ] {
        if !seen.contains(required) {
            bail!("projection pagination vector missing response {required}");
        }
    }
    Ok(())
}

fn evaluate_projection_response(
    response: &Value,
    caller: &str,
    selector_digest: &str,
    purpose: &str,
) -> Result<Value> {
    let Some(has_more) = response.get("has_more").and_then(Value::as_bool) else {
        return Ok(json!({"decision": "reject", "reason": "invalid_response"}));
    };
    if has_more {
        let Some(cursor) = response.get("next_cursor").and_then(Value::as_str) else {
            return Ok(json!({"decision": "reject", "reason": "invalid_response"}));
        };
        if !cursor.starts_with("ck:cursor:") {
            return Ok(json!({"decision": "reject", "reason": "invalid_response"}));
        }
        let binding = required_object(response, "cursor_binding")?;
        if required_str_obj(binding, "caller")? != caller
            || required_str_obj(binding, "selector_digest")? != selector_digest
            || required_str_obj(binding, "purpose")? != purpose
        {
            return Ok(json!({"decision": "reject", "reason": "cursor_integrity_invalid"}));
        }
    }
    Ok(json!({"decision": "accept"}))
}

fn run_range_completeness_witness_disagreement_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for step in required_array(case, "steps")? {
        let name = required_str(step, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_range_completeness_step(step)?;
        assert_expected_subset(name, expected(step)?, &observed)?;
        record_step(
            VECTOR_ID_RANGE_COMPLETENESS_WITNESS_DISAGREEMENT,
            name,
            step,
            &observed,
        );
    }
    for required in [
        "actor_seq_digest_disagreement",
        "range_root_disagreement",
        "high_assurance_single_source_stays_pending",
    ] {
        if !seen.contains(required) {
            bail!("range completeness vector missing step {required}");
        }
    }
    Ok(())
}

fn evaluate_range_completeness_step(step: &Value) -> Result<Value> {
    if let Some(witnesses) = step.get("witnesses").and_then(Value::as_array)
        && witnesses.len() >= 2
        && required_str(&witnesses[0], "realm_id")? == required_str(&witnesses[1], "realm_id")?
        && required_str(&witnesses[0], "actor_id")? == required_str(&witnesses[1], "actor_id")?
        && required_u64(&witnesses[0], "actor_seq")? == required_u64(&witnesses[1], "actor_seq")?
        && required_str(&witnesses[0], "event_digest")?
            != required_str(&witnesses[1], "event_digest")?
    {
        return Ok(json!({
            "decision": "reject",
            "reason": "witness_disagreement",
            "quarantine": true,
        }));
    }
    if let Some(attestations) = step.get("attestations").and_then(Value::as_array)
        && attestations.len() >= 2
        && required_str(&attestations[0], "from_frontier")?
            == required_str(&attestations[1], "from_frontier")?
        && required_str(&attestations[0], "to_frontier")?
            == required_str(&attestations[1], "to_frontier")?
        && required_str(&attestations[0], "range_root")?
            != required_str(&attestations[1], "range_root")?
    {
        return Ok(json!({
            "decision": "reject",
            "reason": "witness_disagreement",
            "quarantine": true,
        }));
    }
    if step.get("security_class").and_then(Value::as_str) == Some("high_assurance")
        && step.get("attestation_mode").and_then(Value::as_str) == Some("single_source")
    {
        return Ok(json!({
            "decision": "pending_stale",
            "high_assurance_frontier_advanced": false,
        }));
    }
    Ok(json!({"decision": "accept"}))
}

fn run_cursor_revoke_high_assurance_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for step in required_array(case, "steps")? {
        let name = required_str(step, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_cursor_step(step)?;
        assert_expected_subset(name, expected(step)?, &observed)?;
        record_step(
            VECTOR_ID_CURSOR_REVOKE_HIGH_ASSURANCE,
            name,
            step,
            &observed,
        );
    }
    for required in ["replay_revoked_cursor", "tampered_unrevoked_cursor"] {
        if !seen.contains(required) {
            bail!("cursor revoke vector missing step {required}");
        }
    }
    Ok(())
}

fn evaluate_cursor_step(step: &Value) -> Result<Value> {
    if !required_bool(step, "integrity_valid")? {
        return Ok(json!({
            "decision": "reject",
            "reason": "cursor_integrity_invalid",
            "revocation_set_exposed": false,
        }));
    }
    if required_bool(step, "revoked")? {
        return Ok(json!({
            "decision": "reject",
            "reason": "cursor_revoked",
            "subscription_position_advanced": false,
        }));
    }
    Ok(json!({"decision": "accept"}))
}

fn run_device_recovery_lifecycle_case(case: &Value) -> Result<()> {
    let current_generation = required_u64(case, "current_ssk_generation")?;
    let mut seen = BTreeSet::new();
    for step in required_array(case, "steps")? {
        let name = required_str(step, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_device_recovery_step(step, current_generation)?;
        assert_expected_subset(name, expected(step)?, &observed)?;
        record_step(VECTOR_ID_DEVICE_RECOVERY_LIFECYCLE, name, step, &observed);
    }
    for required in [
        "stale_ssk_generation",
        "proof_passed_waiting_for_unlock",
        "keypackage_claim_failure_low_watermark",
    ] {
        if !seen.contains(required) {
            bail!("device recovery lifecycle vector missing step {required}");
        }
    }
    Ok(())
}

fn evaluate_device_recovery_step(step: &Value, current_generation: u64) -> Result<Value> {
    if let Some(proof_generation) = step.get("proof_ssk_generation").and_then(Value::as_u64)
        && proof_generation != current_generation
    {
        return Ok(json!({
            "decision": "reject",
            "reason": "device_recovery_ssk_generation_mismatch",
        }));
    }
    if step.get("proof_verified").and_then(Value::as_bool) == Some(true) {
        let unlocked = step
            .get("secret_storage_unlocked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let replayed = step
            .get("mls_welcome_replayed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !unlocked || !replayed {
            return Ok(json!({
                "device_state": "recovery_pending",
                "fully_verified": false,
            }));
        }
    }
    if step.get("available_count").is_some() {
        let available = required_u64(step, "available_count")?;
        let low_watermark = required_u64(step, "low_watermark")?;
        let suggested_publish_count = low_watermark.saturating_sub(available);
        let republished =
            required_str(step, "claimed_package_status_after_failure")? == "published";
        return Ok(json!({
            "available_count": available,
            "low_watermark": low_watermark,
            "suggested_publish_count": suggested_publish_count,
            "claimed_package_republished": republished,
        }));
    }
    Ok(json!({"decision": "accept"}))
}

fn run_device_revocation_seal_binding_case(case: &Value) -> Result<()> {
    required_object(case, "revocation")?;
    let mut seen = BTreeSet::new();
    for step in required_array(case, "steps")? {
        let name = required_str(step, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_device_revocation_step(step)?;
        assert_expected_subset(name, expected(step)?, &observed)?;
        record_step(
            VECTOR_ID_DEVICE_REVOCATION_SEAL_BINDING,
            name,
            step,
            &observed,
        );
    }
    for required in [
        "post_seal_operations",
        "mls_remove_missing_governance_frontier",
        "missing_frontier_for_revoke",
    ] {
        if !seen.contains(required) {
            bail!("device revocation seal-binding vector missing step {required}");
        }
    }
    Ok(())
}

fn evaluate_device_revocation_step(step: &Value) -> Result<Value> {
    if step.get("operation_kinds").is_some() {
        return Ok(json!({"decision": "reject", "reason": "actor_signature_revoked"}));
    }
    if step
        .get("mls_remove_covers_revocation")
        .and_then(Value::as_bool)
        == Some(false)
    {
        return Ok(json!({
            "covered_seals_cell_claims_revocation": false,
            "e2ee_data_gate": "blocked",
            "reason": "epoch_update_required",
        }));
    }
    if step.get("frontier_available").and_then(Value::as_bool) == Some(false)
        || step.get("seal_id_present").and_then(Value::as_bool) == Some(false)
    {
        return Ok(json!({
            "decision": "reject",
            "reason": "failed_precondition",
            "seal_basis_minted": false,
        }));
    }
    Ok(json!({"decision": "accept"}))
}

fn run_push_wakeup_policy_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for step in required_array(case, "steps")? {
        let name = required_str(step, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_push_step(step)?;
        assert_expected_subset(name, expected(step)?, &observed)?;
        record_step(VECTOR_ID_PUSH_WAKEUP_POLICY, name, step, &observed);
    }
    for required in [
        "no_notification_unresolved_mention",
        "client_rule_digest_mismatch",
        "batch_unresolved_events",
    ] {
        if !seen.contains(required) {
            bail!("push wakeup vector missing step {required}");
        }
    }
    Ok(())
}

fn evaluate_push_step(step: &Value) -> Result<Value> {
    if let Some(policy) = step.get("realm_policy").and_then(Value::as_object) {
        if policy.get("wakeup_default").and_then(Value::as_str) == Some("no_notification")
            && policy
                .get("server_can_evaluate_client_rule")
                .and_then(Value::as_bool)
                == Some(false)
        {
            return Ok(json!({"single_event_wakeup_sent": false}));
        }
        if policy.get("wakeup_default").and_then(Value::as_str) == Some("batch_wakeup")
            && required_u64(step, "unresolved_event_count")? > 1
            && required_u64(step, "window_ms")? <= 60000
        {
            return Ok(json!({
                "wakeups_sent": 1,
                "evaluation_locus_unresolved": true,
            }));
        }
    }
    if required_str(step, "registered_client_rule_digest")?
        != required_str(step, "server_client_rule_digest")?
    {
        return Ok(json!({
            "strategy": "conservative",
            "rule_content_guessed": false,
        }));
    }
    Ok(json!({"decision": "accept"}))
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
        &format!("service_closure_hardening.{name}"),
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

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing u64 field {field}"))
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
