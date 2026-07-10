use anyhow::{Result, anyhow, bail};
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
            other => bail!("unknown policy_server fixture case {other}"),
        }
    }
    Ok(())
}

fn jcs_sha256_hex(value: &Value) -> Result<String> {
    let bytes = arkret_core::canonical::canonical_json_bytes(value)
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
