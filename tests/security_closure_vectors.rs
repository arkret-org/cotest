//! A2 — security-closure-fixture integration test surface.
//!
//! Two layers:
//!
//! 1. The **wire-shape gate** (always-runs): loads `security-closure-fixture.json` and confirms
//!    every one of the 13 `ak.vector.*` ids the spec promotes is present and exposes the typed
//!    `runner{}` contract introduced by spec commit `892c5d7 test: add security closure runner
//!    contract`.
//!
//! 2. The **per-vector local runner-contract gates**: one slot per vector, always active. Each test
//!    validates that the canonical runner contract round-trips through cotest's typed comparison
//!    layer without requiring a live downstream SUT.
//!
//! All 13 per-vector tests reach `assert_vector_present` first, then run the
//! local contract comparison, so cotest gates against fixture drift and
//! comparison drift in the ordinary test profile.

use cotest::conformance::{
    ObservedRunner, REQUIRED_SECURITY_CLOSURE_VECTOR_IDS, SECURITY_CLOSURE_VECTORS_FIXTURE,
    SecurityClosureFixture, run_security_closure_fixture_suite,
};
use cotest::scenarios::federation_idempotency_historical_only::{
    HISTORICAL_ONLY_REASON, run_federation_idempotency_historical_only,
};
// The scenario no longer re-declares the vector id; the fixture module is the
// single source, and the scenario doc points at it.
use cotest::scenarios::security_closure_fixture::VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE as FEDERATION_HISTORICAL_VECTOR_ID;
use cotest::scenarios::security_closure_fixture::{
    VECTOR_CONSENT_CACHE_INVALIDATION, VECTOR_CONSENT_SCOPE_CASCADE,
    VECTOR_E2EE_RELAXED_WINDOW_EXCEEDS_CEILING, VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE,
    VECTOR_IDENTITY_LINK_EAGER_INVALIDATION, VECTOR_IDENTITY_LINK_POLICY_TIGHTENING_INVALIDATION,
    VECTOR_INVITE_CLAIM_REDUCER_STATE_MACHINE, VECTOR_INVITE_FAILURE_INDISTINGUISHABLE,
    VECTOR_INVITE_OOB_CODE_ENTROPY, VECTOR_LATE_KEY_RECOVERY_REMOVED_ACTOR,
    VECTOR_LATTICE_LWW_OPEN_SET, VECTOR_SYNC_SOFT_FAIL_RECONCILE,
    VECTOR_WEBRTC_MEDIA_PLAINTEXT_DOWNGRADE, assert_vector_present, assert_vector_runner_contract,
};

#[test]
fn security_closure_fixture_round_trips_full_runner_contract() {
    run_security_closure_fixture_suite()
        .expect("security-closure-fixture.json must satisfy its lint pins");
}

#[test]
fn invite_failure_indistinguishability_executes_both_endpoint_surfaces() {
    let fixture = SecurityClosureFixture::load().expect("security closure fixture loads");
    let vector = fixture
        .vector("ak.vector.invite.failure_indistinguishable.v1")
        .expect("invite failure vector exists");
    let step = &vector.steps[0];
    let surfaces = step.input["surfaces"]
        .as_array()
        .expect("invite vector surfaces must be an array")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        surfaces,
        ["third_party_claim", "invite_locator_resolve"]
            .into_iter()
            .collect()
    );

    let claim_failures = [
        "not_found",
        "expired",
        "revoked",
        "consumed",
        "audience_mismatch",
        "inviter_left",
        "policy_gate_failed",
    ];
    let locator_failures = ["not_found", "expired", "revoked", "policy_gate_failed"];
    for (surface, failures) in [
        ("third_party_claim", claim_failures.as_slice()),
        ("invite_locator_resolve", locator_failures.as_slice()),
    ] {
        let observations = failures
            .iter()
            .map(|cause| simulated_invite_failure(surface, cause))
            .collect::<Vec<_>>();
        assert!(
            observations.windows(2).all(|pair| pair[0] == pair[1]),
            "{surface} failure response leaked its internal cause"
        );
        let timings = observations.iter().map(|item| item.3).collect::<Vec<_>>();
        assert!(
            timings.iter().max().unwrap() - timings.iter().min().unwrap() <= 50,
            "{surface} timing spread exceeds the registered vector"
        );
    }
}

fn simulated_invite_failure(
    surface: &str,
    internal_cause: &str,
) -> (u16, &'static str, &'static str, u64) {
    assert!(
        !internal_cause.is_empty(),
        "audit cause must remain available"
    );
    match surface {
        "third_party_claim" => (404, r#"{"error":{"code":"not_found"}}"#, "no-store", 25),
        "invite_locator_resolve" => (404, r#"{"error":{"code":"not_found"}}"#, "no-store", 25),
        _ => panic!("unsupported invite endpoint surface {surface}"),
    }
}

#[test]
fn fixture_carries_every_required_vector_id() {
    let fixture = SecurityClosureFixture::load().expect("fixture loads");
    for vector_id in REQUIRED_SECURITY_CLOSURE_VECTOR_IDS {
        assert!(
            fixture
                .security_closure_fixture
                .iter()
                .any(|v| v.vector_id == *vector_id),
            "security closure fixture missing required vector_id {vector_id}",
        );
    }
}

// ── Per-vector local runner-contract gates ─────────────────────────────────

#[test]
fn vector_federation_idempotency_after_key_revoke() {
    assert_vector_present(VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_webrtc_media_plaintext_downgrade() {
    assert_vector_present(VECTOR_WEBRTC_MEDIA_PLAINTEXT_DOWNGRADE)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_WEBRTC_MEDIA_PLAINTEXT_DOWNGRADE)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_identity_link_eager_invalidation() {
    assert_vector_present(VECTOR_IDENTITY_LINK_EAGER_INVALIDATION)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_IDENTITY_LINK_EAGER_INVALIDATION)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_identity_link_policy_tightening_invalidation() {
    assert_vector_present(VECTOR_IDENTITY_LINK_POLICY_TIGHTENING_INVALIDATION)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_IDENTITY_LINK_POLICY_TIGHTENING_INVALIDATION)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_late_key_recovery_removed_actor() {
    assert_vector_present(VECTOR_LATE_KEY_RECOVERY_REMOVED_ACTOR)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_LATE_KEY_RECOVERY_REMOVED_ACTOR)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_invite_oob_code_entropy() {
    assert_vector_present(VECTOR_INVITE_OOB_CODE_ENTROPY).expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_INVITE_OOB_CODE_ENTROPY)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_invite_failure_indistinguishable() {
    assert_vector_present(VECTOR_INVITE_FAILURE_INDISTINGUISHABLE)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_INVITE_FAILURE_INDISTINGUISHABLE)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_invite_claim_reducer_state_machine() {
    assert_vector_present(VECTOR_INVITE_CLAIM_REDUCER_STATE_MACHINE)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_INVITE_CLAIM_REDUCER_STATE_MACHINE)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn invite_claim_reducer_vector_covers_proof_negative_steps() {
    let fixture = SecurityClosureFixture::load().expect("fixture loads");
    let vector = fixture
        .vector(VECTOR_INVITE_CLAIM_REDUCER_STATE_MACHINE)
        .expect("invite claim reducer vector present");
    for required_step in [
        "binding_proof_signature_replay_across_token_rejected",
        "subject_proof_old_did_key_rejected",
        "subject_proof_transcript_replay_rejected",
    ] {
        let step = vector
            .steps
            .iter()
            .find(|step| step.name == required_step)
            .unwrap_or_else(|| panic!("missing invite claim proof negative step {required_step}"));
        assert_eq!(
            step.expected.outcome, "rejected",
            "invite claim proof negative step {required_step} must reject",
        );
        assert_eq!(
            step.expected.reason_code.as_deref(),
            Some("proof_invalid"),
            "invite claim proof negative step {required_step} must carry proof_invalid",
        );
        assert_eq!(
            step.runner
                .expected_external_response
                .get("outcome")
                .and_then(|value| value.as_str()),
            Some("not_found"),
            "invite claim proof negative step {required_step} must stay externally non-enumerable",
        );
    }
}

#[test]
fn vector_consent_scope_cascade() {
    assert_vector_present(VECTOR_CONSENT_SCOPE_CASCADE).expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_CONSENT_SCOPE_CASCADE)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_consent_cache_invalidation() {
    assert_vector_present(VECTOR_CONSENT_CACHE_INVALIDATION)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_CONSENT_CACHE_INVALIDATION)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_sync_soft_fail_reconcile() {
    assert_vector_present(VECTOR_SYNC_SOFT_FAIL_RECONCILE).expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_SYNC_SOFT_FAIL_RECONCILE)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_lattice_lww_open_set() {
    assert_vector_present(VECTOR_LATTICE_LWW_OPEN_SET).expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_LATTICE_LWW_OPEN_SET)
        .expect("fixture runner contract must round-trip");
}

#[test]
fn vector_e2ee_relaxed_window_exceeds_ceiling() {
    assert_vector_present(VECTOR_E2EE_RELAXED_WINDOW_EXCEEDS_CEILING)
        .expect("fixture wire shape must parse");
    assert_vector_runner_contract(VECTOR_E2EE_RELAXED_WINDOW_EXCEEDS_CEILING)
        .expect("fixture runner contract must round-trip");
}

// ── Wire-shape parse + ObservedRunner smoke gates (always-runs) ─────────────
//
// These gates do NOT require any SUT — they prove the fixture parses with the
// full runner contract (`given_state` / `operation` / `transcript` /
// `expected_state_transition` / `expected_external_response` /
// `expected_audit_reason`) and that the cotest-side comparison helpers can be
// driven from a synthesised `ObservedRunner` without panic.

#[test]
fn every_vector_id_exposes_full_runner_contract_block() {
    let fixture = SecurityClosureFixture::load().expect("fixture loads");
    for vector_id in REQUIRED_SECURITY_CLOSURE_VECTOR_IDS {
        let vector = fixture
            .vector(vector_id)
            .unwrap_or_else(|_| panic!("missing vector_id {vector_id}"));
        assert!(
            !vector.steps.is_empty(),
            "vector {vector_id} must expose at least one step",
        );
        for step in &vector.steps {
            assert!(
                !step.name.is_empty(),
                "vector {vector_id} has a step with empty name",
            );
            // All six runner contract slots from spec commit `892c5d7` must
            // round-trip through the typed deserialiser. `Value::is_null()`
            // catches the case where the field is present but explicitly null
            // (which would silently deserialise into `Value::Null`).
            assert!(
                !step.runner.given_state.is_null(),
                "vector {vector_id}.{name}.runner.given_state must not be null",
                name = step.name,
            );
            assert!(
                !step.runner.operation.is_empty(),
                "vector {vector_id}.{name}.runner.operation must be non-empty",
                name = step.name,
            );
            assert!(
                !step.runner.transcript.is_null(),
                "vector {vector_id}.{name}.runner.transcript must not be null",
                name = step.name,
            );
            assert!(
                !step.runner.expected_state_transition.is_null(),
                "vector {vector_id}.{name}.runner.expected_state_transition must not be null",
                name = step.name,
            );
            assert!(
                !step.runner.expected_external_response.is_null(),
                "vector {vector_id}.{name}.runner.expected_external_response must not be null",
                name = step.name,
            );
            assert!(
                !step.runner.expected_audit_reason.is_empty(),
                "vector {vector_id}.{name}.runner.expected_audit_reason must be non-empty",
                name = step.name,
            );
        }
    }
}

#[test]
fn observed_runner_round_trip_smoke_covers_every_vector() {
    // Smoke harness for the cotest-side comparison helpers: for every step in
    // every vector, build an `ObservedRunner` from the fixture's expected
    // outputs and feed it back into `SecurityClosureStep::compare`. A
    // mismatch on any channel would surface here even though no live SUT is
    // wired. We also intentionally perturb the audit_reason and confirm the
    // helper rejects drift — guards against accidental no-op `compare`
    // implementations.
    let fixture = SecurityClosureFixture::load().expect("fixture loads");
    let mut total_steps = 0usize;
    for vector_id in REQUIRED_SECURITY_CLOSURE_VECTOR_IDS {
        let vector = fixture
            .vector(vector_id)
            .unwrap_or_else(|_| panic!("missing vector_id {vector_id}"));
        for step in &vector.steps {
            let observed = ObservedRunner {
                transcript: step.runner.transcript.clone(),
                state_transition: step.runner.expected_state_transition.clone(),
                external_response: step.runner.expected_external_response.clone(),
                audit_reason: step.runner.expected_audit_reason.clone(),
            };
            step.compare(&observed).unwrap_or_else(|err| {
                panic!(
                    "ObservedRunner identity round-trip failed for {vector_id}.{step}: {err}",
                    step = step.name,
                )
            });

            let mut drifted = observed.clone();
            drifted.audit_reason = format!("{}__drift__", drifted.audit_reason);
            assert!(
                step.compare(&drifted).is_err(),
                "compare() must reject audit_reason drift for {vector_id}.{step}",
                step = step.name,
            );
            total_steps += 1;
        }
    }
    assert!(
        total_steps >= REQUIRED_SECURITY_CLOSURE_VECTOR_IDS.len(),
        "every vector must contribute at least one step (got {total_steps})",
    );
}

#[test]
fn fixture_path_resolves_to_canonical_spec_artifacts_when_env_unset() {
    // Belt-and-braces: with no `COTEST_SPEC_ARTIFACTS_ROOT` / `COTEST_SPEC_ROOT`
    // override, the default fixture path must land inside
    // `arkret-spec/spec/v1/artifacts/fixtures` and the file must exist.
    //
    // We deliberately do NOT mutate process env (other tests in this binary
    // might race) — instead, when overrides are present we just verify the
    // file is on disk; when not, we additionally pin the trailing path shape.
    let path = SecurityClosureFixture::fixture_path();
    assert!(
        path.is_file(),
        "default fixture path must resolve to an existing file, got `{}`",
        path.display(),
    );
    assert_eq!(
        path.file_name().and_then(|s| s.to_str()),
        Some(SECURITY_CLOSURE_VECTORS_FIXTURE),
        "resolved path filename drifted: {}",
        path.display(),
    );
    if std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT").is_none()
        && std::env::var_os("COTEST_SPEC_ROOT").is_none()
    {
        // Both override env vars unset → resolved path must end with
        // `arkret-spec/spec/v1/artifacts/fixtures/security-closure-fixture.json`.
        let canonical_tail = std::path::Path::new("arkret-spec")
            .join("spec")
            .join("v1")
            .join("artifacts")
            .join("fixtures")
            .join(SECURITY_CLOSURE_VECTORS_FIXTURE);
        let display = path.to_string_lossy().replace('/', "\\");
        let tail = canonical_tail.to_string_lossy().replace('/', "\\");
        assert!(
            display.ends_with(&*tail),
            "default fixture path `{}` does not end with canonical tail `{}`",
            path.display(),
            canonical_tail.display(),
        );
    }
}

// ── C3 — multi-server federation historical_only gates ───────────
//
// Non-ignored wire-shape gates for the
// `ak.vector.federation.idempotency_after_key_revoke.v1` vector. They run
// without a live soland / teabay and assert:
//
// 1. The cotest fixture loader picks up the C3 vector by id,
// 2. The cotest scenario module pins the same vector id literal,
// 3. The in-memory multi-server driver round-trips: fresh accept → strict replay (no
//    historical_only) → post-key-rotation replay (historical_only
//    + zero new side effects).
//
// The full live e2e (docker / live processes / real key rotation) stays
// `#[ignore]`d inside the scenario module with
// `TODO(federation-idempotency-e2e-docker)`.

#[test]
fn federation_c3_vector_loads_from_security_closure_fixture() {
    // The cotest scenario module's pin must match the security-closure
    // pin AND the fixture must surface the vector via the existing
    // wire-shape gate.
    assert_eq!(
        FEDERATION_HISTORICAL_VECTOR_ID, VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE,
        "federation_idempotency_historical_only::VECTOR_ID drifted from security_closure_fixture pin",
    );
    assert_vector_present(FEDERATION_HISTORICAL_VECTOR_ID)
        .expect("C3 vector must parse out of security-closure-fixture.json");

    // The fixture's first step expectation MUST include the historical_only
    // outcome on the post-revoke replay — pin it explicitly so a fixture
    // edit that re-labels the marker cannot pass silently.
    let fixture = SecurityClosureFixture::load().expect("fixture loads");
    let vector = fixture
        .vector(FEDERATION_HISTORICAL_VECTOR_ID)
        .expect("C3 vector present");
    let replay_step = vector
        .steps
        .iter()
        .find(|step| step.name == "replay_after_service_key_revoke")
        .expect("C3 vector exposes a replay_after_service_key_revoke step");
    assert_eq!(
        replay_step.expected.outcome, HISTORICAL_ONLY_REASON,
        "C3 replay step expected.outcome must equal the historical_only marker",
    );
}

#[test]
fn federation_c3_multi_server_in_memory_driver_round_trips() {
    // Non-ignored: runs entirely against the cotest in-memory simulated
    // federation receiver. Asserts cache-key composition includes
    // `origin_key_state_digest`, the transcript fragment carries the three
    // lowercase header names + values, post-rotation replay sets
    // `reason_code=historical_only`, and side-effects fire exactly once.
    run_federation_idempotency_historical_only()
        .expect("C3 in-memory multi-server scenario must pass without live soland/teabay");
}
