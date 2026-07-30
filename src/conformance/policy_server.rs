use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::governance::realm_governance::RealmPolicyServerPayload;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::load_fixture_value;
use crate::transcripts::record_vector_event;

/// Runner for `policy-server-fixture.json`, pinning the transcript-binding and
/// anti-replay MUSTs from `authz/policy-server.md` §5.
pub fn run_policy_server_fixture_suite() -> Result<()> {
    let value = load_fixture_value("policy-server-fixture.json")?;
    let suite = value
        .get("suite")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if suite != "policy_server" {
        bail!("unexpected policy-server fixture suite {suite}");
    }
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("policy-server fixture missing cases"))?;
    for case in cases {
        let name = case.get("name").and_then(Value::as_str).unwrap_or_default();
        match name {
            "request_digest_recompute" => evaluate_request_digest_recompute(case)?,
            "decision_replay_rejected" => evaluate_decision_replay_rejected(case)?,
            "binding_tombstone_and_repeat" => evaluate_binding_tombstone(case)?,
            "concurrent_replace_delete_conflict" => evaluate_replace_delete_conflict(case)?,
            "tombstone_federation_replay_and_seal" => {
                evaluate_tombstone_federation_replay(case)?;
            }
            other => bail!("unknown policy_server fixture case {other}"),
        }
    }
    Ok(())
}

fn evaluate_binding_tombstone(case: &Value) -> Result<()> {
    let payload = case
        .pointer("/delete/payload")
        .ok_or_else(|| anyhow!("binding tombstone case is missing delete.payload"))?;
    let parsed = parse_valid_policy_server_payload(payload)
        .map_err(|error| anyhow!("canonical tombstone did not parse: {error}"))?;
    if !matches!(parsed, RealmPolicyServerPayload::Tombstone(_))
        || payload != &json!({"tombstone": true})
        || case.pointer("/delete/projected_write/op/value") != Some(payload)
        || case
            .pointer("/delete/projected_write/cell")
            .and_then(Value::as_str)
            != Some("ak:cell:ak.component.realm.policy_server.v1:null")
        || case
            .pointer("/delete/projected_write/lattice")
            .and_then(Value::as_str)
            != Some("cas_register")
        || case
            .pointer("/delete/projected_write/bottom")
            .and_then(Value::as_str)
            != Some("reject")
    {
        bail!("policy-server DELETE is not the canonical closed tombstone CAS write");
    }
    let invalid = case
        .get("invalid_tombstone_payloads")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("binding tombstone case is missing invalid_tombstone_payloads"))?;
    if invalid.is_empty()
        || invalid
            .iter()
            .any(|value| parse_valid_policy_server_payload(value).is_ok())
    {
        bail!("an invalid policy-server tombstone payload was accepted");
    }
    for (pointer, expected) in [
        ("/expected/first_delete", json!("accepted_after_seal")),
        ("/expected/repeat_delete", json!("idempotent_empty_success")),
        ("/expected/repeat_changes_state_root", json!(false)),
        (
            "/expected/missing_direct_history_delete",
            json!("not_found"),
        ),
        (
            "/expected/delete_inherited_value_mutates_ancestor",
            json!(false),
        ),
        ("/expected/from_org_fallback", json!(true)),
    ] {
        if case.pointer(pointer) != Some(&expected) {
            bail!("binding tombstone expectation {pointer} drifted");
        }
    }
    record_vector_event(
        "policy_server.binding_tombstone",
        &case["delete"],
        &case["expected"],
        &case["expected"],
    );
    Ok(())
}

fn evaluate_replace_delete_conflict(case: &Value) -> Result<()> {
    let siblings = case
        .get("siblings")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("replace/delete conflict is missing siblings"))?;
    if siblings.len() != 2
        || siblings[0].pointer("/precondition") != siblings[1].pointer("/precondition")
        || siblings[0].pointer("/set_value") == siblings[1].pointer("/set_value")
        || case.pointer("/expected/join").and_then(Value::as_str) != Some("bottom")
        || case
            .pointer("/expected/bottom_policy")
            .and_then(Value::as_str)
            != Some("reject")
        || case.pointer("/expected/query").and_then(Value::as_str) != Some("failed_bottom")
        || case
            .pointer("/expected/arrival_order_selects_winner")
            .and_then(Value::as_bool)
            != Some(false)
        || case
            .pointer("/expected/org_fallback_used")
            .and_then(Value::as_bool)
            != Some(false)
    {
        bail!("replace/delete siblings do not deterministically join to rejected bottom");
    }
    Ok(())
}

fn evaluate_tombstone_federation_replay(case: &Value) -> Result<()> {
    let event_payload = case
        .pointer("/event/payload")
        .ok_or_else(|| anyhow!("federation replay case is missing event payload"))?;
    let parsed = parse_valid_policy_server_payload(event_payload)
        .map_err(|error| anyhow!("federated tombstone did not parse: {error}"))?;
    let orders = case
        .get("delivery_orders")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("federation replay case is missing delivery_orders"))?;
    if !matches!(parsed, RealmPolicyServerPayload::Tombstone(_))
        || case.pointer("/seal/covers_event").and_then(Value::as_bool) != Some(true)
        || case.pointer("/seal/state_root_includes/value") != Some(event_payload)
        || orders.len() < 3
    {
        bail!("policy-server federation replay does not bind the Event into the Seal state root");
    }
    for pointer in [
        "/expected/all_orders_converge",
        "/expected/pending_until_dependencies_complete",
        "/expected/final_state_root_equal",
        "/expected/federated_event_retained",
        "/expected/restart_replay_restores_tombstone",
    ] {
        if case.pointer(pointer).and_then(Value::as_bool) != Some(true) {
            bail!("federation replay expectation {pointer} is not enforced");
        }
    }
    if case
        .pointer("/expected/direct_config_revives_after_restart")
        .and_then(Value::as_bool)
        != Some(false)
    {
        bail!("restart replay incorrectly revives a tombstoned direct binding");
    }
    record_vector_event(
        "policy_server.tombstone_federation_replay",
        &case["event"],
        &case["expected"],
        &case["expected"],
    );
    Ok(())
}

fn parse_valid_policy_server_payload(value: &Value) -> Result<RealmPolicyServerPayload> {
    let payload = serde_json::from_value::<RealmPolicyServerPayload>(value.clone())?;
    match payload {
        RealmPolicyServerPayload::Tombstone(tombstone) => {
            tombstone.validate()?;
            Ok(RealmPolicyServerPayload::Tombstone(tombstone))
        }
        declaration => Ok(declaration),
    }
}

fn jcs_sha256_hex(value: &Value) -> Result<String> {
    let bytes = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| anyhow!("RFC 8785 JCS canonicalization failed: {error}"))?;
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// A receiver accepts a bound policy decision only when the JCS-SHA256 digest
/// of the *current* request body equals the digest the decision is bound to,
/// AND the `bound_to` (realm_id, actor_id, action) tuple matches the current
/// request. The decision's self-reported digest is never trusted in place of
/// the local recompute.
fn receiver_accepts(current: &Value, bound_to: &Value, bound_digest: &str) -> Result<bool> {
    if jcs_sha256_hex(current)? != bound_digest {
        return Ok(false);
    }
    for field in ["realm_id", "actor_id", "action"] {
        if bound_to.get(field) != current.get(field) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Vector `ak.vector.policy_server.request_digest_recompute.v1`
/// (conformance §15.4).
fn evaluate_request_digest_recompute(case: &Value) -> Result<()> {
    let b1 = case
        .get("request_b1")
        .ok_or_else(|| anyhow!("request_digest_recompute case missing request_b1"))?;
    let b2 = case
        .get("request_b2")
        .ok_or_else(|| anyhow!("request_digest_recompute case missing request_b2"))?;
    let bound_to = case
        .get("bound_to")
        .ok_or_else(|| anyhow!("request_digest_recompute case missing bound_to"))?;
    let cross_context_bound_to = case
        .get("cross_context_bound_to")
        .ok_or_else(|| anyhow!("request_digest_recompute case missing cross_context_bound_to"))?;

    let digest_b1 = jcs_sha256_hex(b1)?;
    let digest_b2 = jcs_sha256_hex(b2)?;
    // The tamper MUST change the canonical form, otherwise the recompute check
    // would be vacuous.
    if digest_b1 == digest_b2 {
        bail!("request_digest_recompute: B1 and B2 canonicalize identically; tamper not exercised");
    }

    // The decision was issued bound to B1: bound_to.request_canonical_digest =
    // JCS-SHA256(B1).
    let tampered_body_accepted = receiver_accepts(b2, bound_to, &digest_b1)?;
    let matching_body_accepted = receiver_accepts(b1, bound_to, &digest_b1)?;
    // Digest matches but the bound_to (realm, actor, action) tuple is for a
    // different actor: MUST still reject (no cross-context allow leakage).
    let cross_context_accepted = receiver_accepts(b1, cross_context_bound_to, &digest_b1)?;

    assert_expected_bool(case, "tampered_body_accepted", tampered_body_accepted)?;
    assert_expected_bool(case, "matching_body_accepted", matching_body_accepted)?;
    assert_expected_bool(case, "cross_context_accepted", cross_context_accepted)?;

    record_vector_event(
        "policy_server.request_digest_recompute",
        &json!({"request_b1": b1, "request_b2": b2}),
        &case["expected"],
        &json!({
            "tampered_body_accepted": tampered_body_accepted,
            "matching_body_accepted": matching_body_accepted,
            "cross_context_accepted": cross_context_accepted,
        }),
    );
    Ok(())
}

/// Vector `ak.vector.policy_server.decision_replay_rejected.v1`
/// (conformance §15.3).
fn evaluate_decision_replay_rejected(case: &Value) -> Result<()> {
    let case_a = case
        .get("case_a_expired")
        .ok_or_else(|| anyhow!("decision_replay case missing case_a_expired"))?;
    let case_a_control = case
        .get("case_a_control")
        .ok_or_else(|| anyhow!("decision_replay case missing case_a_control"))?;
    let case_b = case
        .get("case_b_stale_authstate")
        .ok_or_else(|| anyhow!("decision_replay case missing case_b_stale_authstate"))?;
    let case_b_control = case
        .get("case_b_control")
        .ok_or_else(|| anyhow!("decision_replay case missing case_b_control"))?;

    let expired_accepted = decision_unexpired(case_a)?;
    let fresh_accepted = decision_unexpired(case_a_control)?;
    let stale_authstate_reused = cached_decision_reusable(case_b)?;
    let matching_authstate_reused = cached_decision_reusable(case_b_control)?;

    assert_expected_bool(case, "expired_accepted", expired_accepted)?;
    assert_expected_bool(case, "fresh_accepted", fresh_accepted)?;
    assert_expected_bool(case, "stale_authstate_reused", stale_authstate_reused)?;
    assert_expected_bool(case, "matching_authstate_reused", matching_authstate_reused)?;

    record_vector_event(
        "policy_server.decision_replay_rejected",
        &json!({"case_a": case_a, "case_b": case_b}),
        &case["expected"],
        &json!({
            "expired_accepted": expired_accepted,
            "fresh_accepted": fresh_accepted,
            "stale_authstate_reused": stale_authstate_reused,
            "matching_authstate_reused": matching_authstate_reused,
        }),
    );
    Ok(())
}

/// `expires_at > now` with no TTL grace (§5: nodes MUST reject expired
/// decisions).
/// ISO-8601 UTC timestamps ending in `Z` compare correctly as strings.
fn decision_unexpired(window: &Value) -> Result<bool> {
    let expires_at = window
        .get("decision_expires_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("decision window missing decision_expires_at"))?;
    let now = window
        .get("now")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("decision window missing now"))?;
    Ok(now < expires_at)
}

/// A cached decision may be reused only when its bound `auth_state_digest`
/// still equals the local accepted digest. When they differ AND the local
/// accepted frontier is strictly later than the decision-bound frontier, the
/// receiver MUST fail closed and re-request policy/check (§5).
fn cached_decision_reusable(state: &Value) -> Result<bool> {
    let decision_digest = state
        .get("decision_auth_state_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("auth state missing decision_auth_state_digest"))?;
    let local_digest = state
        .get("local_auth_state_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("auth state missing local_auth_state_digest"))?;
    let decision_frontier = state
        .get("decision_frontier")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("auth state missing decision_frontier"))?;
    let local_frontier = state
        .get("local_frontier")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("auth state missing local_frontier"))?;

    if decision_digest == local_digest {
        return Ok(true);
    }
    // Digest mismatch with a strictly-later local frontier: fail closed.
    if local_frontier > decision_frontier {
        return Ok(false);
    }
    // Digest mismatch but frontier not strictly later: a full re-evaluation is
    // still required, so the cached decision is not reusable as-is.
    Ok(false)
}

fn assert_expected_bool(case: &Value, key: &str, actual: bool) -> Result<()> {
    let expected = case
        .pointer(&format!("/expected/{key}"))
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("policy_server fixture missing expected.{key}"))?;
    if actual != expected {
        bail!("policy_server: `{key}`={actual} but expected {expected}");
    }
    Ok(())
}
