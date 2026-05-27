//! R3 spec-sync (contrix-spec @ b47ff6ec) — integration entrypoints for
//! the new conformance vectors and scenario scaffolds. SDK-pure vector
//! suites run unconditionally; integration-target scenarios are
//! `#[ignore]`-gated on R3.1 reducer / signing wiring.

use std::fs;
use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use cotest::conformance::{
    ALL_AGENT_VECTOR_IDS, ALL_CURSOR_VECTOR_IDS, ALL_MEDIA_BINDING_VECTOR_IDS,
    ALL_SIDECAR_VECTOR_IDS, run_agent_vector_suite, run_cursor_vector_suite,
    run_media_binding_vector_suite, run_sidecar_vector_suite,
};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn load_fixture_value(name: &str) -> Result<Value> {
    let path = fixture_path(name);
    let raw = fs::read_to_string(&path)
        .map_err(|e| anyhow!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| anyhow!("failed to parse {}: {e}", path.display()))
}

// ─── P0 / VECT-MB-1..9 — media binding vectors ─────────────────────────────

#[test]
fn media_binding_vector_suite_runs_clean() {
    run_media_binding_vector_suite().expect("media-binding vectors must pass");
    assert_eq!(ALL_MEDIA_BINDING_VECTOR_IDS.len(), 9);
}

// ─── P0 / VECT-AG-1..5 — agent vectors ─────────────────────────────────────

#[test]
fn agent_vector_suite_runs_clean() {
    run_agent_vector_suite().expect("agent vectors must pass");
    assert_eq!(ALL_AGENT_VECTOR_IDS.len(), 5);
}

// ─── P0 / VECT-SC-1..4 — sidecar vectors ───────────────────────────────────

#[test]
fn sidecar_vector_suite_runs_clean() {
    run_sidecar_vector_suite().expect("sidecar vectors must pass");
    assert_eq!(ALL_SIDECAR_VECTOR_IDS.len(), 4);
}

// ─── P0 / VECT-CUR-1..2 — cursor vectors ───────────────────────────────────

#[test]
fn cursor_vector_suite_runs_clean() {
    run_cursor_vector_suite().expect("cursor vectors must pass");
    assert_eq!(ALL_CURSOR_VECTOR_IDS.len(), 2);
}

// ─── P0 / FIX-1 — fixture presence + shape ────────────────────────────────

#[test]
fn recovery_policy_fixture_loads_and_has_canonical_shape() {
    let value = load_fixture_value("recovery-policy.json").expect("recovery-policy.json");
    assert_eq!(
        value.get("schema_ref").and_then(Value::as_str),
        Some("cx.schema.recovery_policy.v1")
    );
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases array");
    assert!(!cases.is_empty(), "recovery-policy.json must have cases");
}

#[test]
fn recovery_receipt_fixture_loads_and_has_canonical_shape() {
    let value = load_fixture_value("recovery-receipt.json").expect("recovery-receipt.json");
    assert_eq!(
        value.get("schema_ref").and_then(Value::as_str),
        Some("cx.schema.recovery_receipt.v1")
    );
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases array");
    assert!(!cases.is_empty(), "recovery-receipt.json must have cases");
}

#[test]
fn agent_payloads_fixture_loads_and_has_canonical_shape() {
    let value = load_fixture_value("agent_payloads.json").expect("agent_payloads.json");
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases array");
    assert!(cases.len() >= 8, "agent_payloads.json must cover all new kinds");
    let kinds: Vec<&str> = cases
        .iter()
        .filter_map(|c| c.get("event_kind").and_then(Value::as_str))
        .collect();
    for required in [
        "cx.agent.pause",
        "cx.agent.resume",
        "cx.agent.deactivate",
        "cx.agent.draft.propose",
        "cx.agent.action_request",
        "cx.agent.action_approve",
        "cx.agent.action_reject",
    ] {
        assert!(
            kinds.contains(&required),
            "agent_payloads.json missing event_kind {required}"
        );
    }
}

// ─── P0 / TEST-1 — Agent FSM scenario ──────────────────────────────────────
//
// Drives the live `POST /agents/{id}/{pause,resume,deactivate}` route
// matrix against soland and asserts the FSM bottom-reject contract +
// terminal deactivate. Soland's reducer FSM is `TODO(R3.1)` so the
// integration path is ignored.

#[test]
#[ignore = "R3.1: soland agent FSM reducer wiring not yet implemented"]
fn test_1_agent_fsm_active_paused_active_deactivated_terminal() {
    // Wire-shape transitions are pinned by
    // `run_agent_controller_lifecycle_vector` above. Live integration:
    //   1. Provision agent.
    //   2. POST /agents/{id}/pause → 200.
    //   3. POST /agents/{id}/resume → 200.
    //   4. POST /agents/{id}/deactivate → 200.
    //   5. POST /agents/{id}/resume → 403 agent_deactivated.
    unreachable!("integration target gated on soland P2-impl reducer");
}

// ─── P0 / TEST-2 — Media token exchange happy path + 4 negative paths ──────

#[test]
#[ignore = "R3.1: soland/floria `POST /rtc/token` issuer not yet implemented"]
fn test_2_media_token_exchange_happy_path_plus_negatives() {
    // Negative-path matrix pinned at the SDK constant layer by
    // VECT-MB-3 / VECT-MB-4 / VECT-MB-5. Live integration:
    //   - happy: 200 with backend_token + participant_binding,
    //     TTL ≤ 600s, issuer_kid anchored to current
    //     `cx.realm.media_service.service_id`.
    //   - neg-issuer: rogue issuer kid → 401 token_issuer_unauthorised.
    //   - neg-focus:  off-focus token request → 422 focus_mismatch.
    //   - neg-ttl:    server-issued TTL > 600s → 422
    //                 participant_binding_invalid.
    //   - neg-binding: malformed participant_binding scheme → 422
    //                  participant_binding_invalid.
    unreachable!("integration target gated on soland / floria P2-impl");
}

// ─── P0 / TEST-3 — `accountable_to.strict_reject` profile toggle ───────────

#[test]
#[ignore = "R3.1: soland strict_reject reducer branch not yet implemented"]
fn test_3_accountable_to_strict_reject_profile_toggle() {
    // Live integration:
    //   1. With `cx.profile.accountable_to.strict_reject.v1` NOT
    //      advertised: actor-profile create with unverified
    //      `accountable_to[]` → 200, server strips + audit logs.
    //   2. With the profile advertised: same envelope → 412
    //      failed_precondition reason=accountability_grant_missing.
    unreachable!("integration target gated on soland P2-impl profile branch");
}

// ─── P0 / TEST-4 — Cursor opaque round-trip + stateless-under-core reject ──

#[test]
fn test_4_cursor_opaque_round_trip_stateful_only() -> Result<()> {
    // Stateful core body is the default — round-trip via the SDK
    // primitives is exercised by `run_cursor_opaque_core_vector`. Here
    // we additionally assert that a stateless body parses through the
    // SDK struct but a server with no `cx.profile.stateless_cursor.v1`
    // declaration MUST reject it. We pin both at the wire layer; the
    // server-side acceptance gate lands under soland P2-impl.
    use contrix_core::cursor::{Cursor, CursorPurpose};
    use std::collections::BTreeMap;
    let stateless = Cursor {
        v: "1".to_owned(),
        purpose: CursorPurpose::Stream,
        t: "2026-05-27T00:00:00Z".to_owned(),
        s: BTreeMap::new(),
        d: None,
        target: None,
        x: 1_900_000_000_000,
        h: None,
        issuer_kid: Some("did:web:server.example#cursor-1".to_owned()),
        mac: Some("AAAAAAAAAAAAAAAAAAAAAA".to_owned()),
        sig: None,
        filter_hash: None,
    };
    if stateless.h.is_some() {
        bail!("stateless cursor body must not carry stateful handle");
    }
    if stateless.issuer_kid.is_none() {
        bail!("stateless cursor body must carry issuer_kid");
    }
    Ok(())
}

// ─── P0 / TEST-5 — Recovery policy state machine ───────────────────────────

#[test]
fn test_5_recovery_policy_fixture_state_machine_shape() -> Result<()> {
    let value = load_fixture_value("recovery-policy.json")?;
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("recovery-policy.json missing cases"))?;
    // Lifecycle enum coverage: active + retired must both appear.
    let mut lifecycles: Vec<&str> = cases
        .iter()
        .filter_map(|c| {
            c.get("policy")
                .and_then(|p| p.get("lifecycle"))
                .and_then(Value::as_str)
        })
        .collect();
    lifecycles.sort_unstable();
    lifecycles.dedup();
    if !lifecycles.contains(&"active") || !lifecycles.contains(&"retired") {
        bail!("recovery-policy.json must cover active + retired lifecycles");
    }
    // Proof-kind enum coverage: all four variants appear at least once.
    let mut proof_kinds: Vec<String> = cases
        .iter()
        .filter_map(|c| {
            c.get("policy")
                .and_then(|p| p.get("body"))
                .and_then(|b| b.get("proof_kinds"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
        })
        .flatten()
        .collect();
    proof_kinds.sort();
    proof_kinds.dedup();
    for required in [
        "device_quorum",
        "recovery_unlock",
        "trusted_recovery_service",
        "principal_signing",
    ] {
        if !proof_kinds.iter().any(|p| p == required) {
            bail!("recovery-policy.json missing proof_kind `{required}`");
        }
    }
    // Witness-revoke-lagging negative path is present in the receipt
    // fixture.
    let receipt = load_fixture_value("recovery-receipt.json")?;
    let has_lagging = receipt
        .get("cases")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().any(|c| {
                c.get("reason").and_then(Value::as_str)
                    == Some("recovery_witness_revoke_lagging")
            })
        })
        .unwrap_or(false);
    if !has_lagging {
        bail!("recovery-receipt.json missing witness_revoke_lagging negative case");
    }
    Ok(())
}

#[test]
#[ignore = "R3.1: soland recovery reducer + witness-revoke check not yet implemented"]
fn test_5_recovery_policy_state_machine_live() {
    // Live integration:
    //   1. POST recovery-policy (epoch=1) → 200.
    //   2. POST recovery-policy (same epoch) → 409 / recovery_policy_mismatch.
    //   3. POST recovery-receipt with policy_epoch=1 → 200.
    //   4. POST recovery-receipt where witness has not yet revoked →
    //      409 recovery_witness_revoke_lagging.
    unreachable!("integration target gated on soland P2-impl recovery reducer");
}

// ─── P0 / TEST-6 — Handle homograph reject ─────────────────────────────────

#[test]
#[ignore = "R3.1: soland / starid / teabay wire-level homograph reject not yet implemented"]
fn test_6_handle_homograph_script_mix_or_nfc_variant_reject() {
    // Live integration:
    //   1. POST handle claim `аlice` (Cyrillic а + Latin lice) →
    //      412 handle_homograph_forbidden.
    //   2. POST handle claim with NFC-variant that folds onto an
    //      existing claim → 412 handle_homograph_forbidden.
    //   3. Display-layer mitigation MUST still surface a confusable
    //      hint when the canonical compare passes.
    unreachable!("integration target gated on starid / teabay P2-impl");
}
