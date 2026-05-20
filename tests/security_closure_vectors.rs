//! Round 4 / A2 — security-closure-vectors integration test surface.
//!
//! Two layers:
//!
//! 1. The **wire-shape gate** (always-runs): loads
//!    `security-closure-vectors.json` and confirms every one of the 12
//!    `cx.vector.*` ids the round-4 spec promotes is present and exposes
//!    the typed `runner{}` contract introduced by spec commit
//!    `892c5d7 test: add security closure runner contract`.
//!
//! 2. The **per-vector SUT runner** (`#[ignore]`): one slot per vector,
//!    tagged `// TODO(round4-vector-<vector_id>): implementer-side wire
//!    support pending`. These light up once the implementer projects
//!    expose the matching `cx.*` operation to cotest. The ignored tests
//!    can be unblocked one-by-one as Phase B lands.
//!
//! All 12 ignored tests reach `assert_vector_present` first, which
//! confirms the wire shape parses, so the day-1 cotest run still gates
//! against fixture drift even though the SUT-bound assertions are
//! skipped.

use cotest::conformance::{
    ObservedRunner, REQUIRED_SECURITY_CLOSURE_VECTOR_IDS, SECURITY_CLOSURE_VECTORS_FIXTURE,
    SecurityClosureFixture, run_security_closure_vectors_suite,
};
use cotest::scenarios::round4_federation_historical_only::{
    HISTORICAL_ONLY_REASON, VECTOR_ID as ROUND4_HISTORICAL_VECTOR_ID,
    run_round4_federation_historical_only,
};
use cotest::scenarios::security_closure_vectors::{
    VECTOR_CONSENT_CACHE_INVALIDATION, VECTOR_CONSENT_SCOPE_CASCADE,
    VECTOR_E2EE_RELAXED_WINDOW_EXCEEDS_CEILING, VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE,
    VECTOR_IDENTITY_LINK_EAGER_INVALIDATION,
    VECTOR_IDENTITY_LINK_POLICY_TIGHTENING_INVALIDATION, VECTOR_INVITE_FAILURE_INDISTINGUISHABLE,
    VECTOR_INVITE_OOB_CODE_ENTROPY, VECTOR_LATE_KEY_RECOVERY_REMOVED_ACTOR,
    VECTOR_LATTICE_LWW_OPEN_SET, VECTOR_SYNC_SOFT_FAIL_RECONCILE,
    VECTOR_WEBRTC_MEDIA_PLAINTEXT_DOWNGRADE, assert_vector_present,
};

#[test]
fn security_closure_fixture_round_trips_full_runner_contract() {
    run_security_closure_vectors_suite()
        .expect("security-closure-vectors.json must satisfy round-4 lint pins");
}

#[test]
fn fixture_carries_every_required_vector_id() {
    let fixture = SecurityClosureFixture::load().expect("fixture loads");
    for vector_id in REQUIRED_SECURITY_CLOSURE_VECTOR_IDS {
        assert!(
            fixture
                .security_closure_vectors
                .iter()
                .any(|v| v.vector_id == *vector_id),
            "round-4 security closure fixture missing required vector_id {vector_id}",
        );
    }
}

// ── Per-vector SUT runners (ignored until implementer wire support lands) ──

#[test]
#[ignore = "TODO(round4-vector-cx.vector.federation.idempotency_after_key_revoke.v1): implementer-side wire support pending (soland + teabay federation idempotency cache + Source-Trust-Domain / Destination-Trust-Domain / Request-Canonical-Hash signing transcript)"]
fn vector_federation_idempotency_after_key_revoke() {
    assert_vector_present(VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE)
        .expect("fixture wire shape must parse even when SUT support is pending");
    // Implementer-side runner not yet wired; see TODO(round4-vector-...).
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.webrtc.media_plaintext_downgrade.v1): implementer-side wire support pending (yougen + soland plaintext_visible_services policy gate)"]
fn vector_webrtc_media_plaintext_downgrade() {
    assert_vector_present(VECTOR_WEBRTC_MEDIA_PLAINTEXT_DOWNGRADE)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.identity_link.eager_invalidation.v1): implementer-side wire support pending (coauth + soland identity_link cache eviction on ban)"]
fn vector_identity_link_eager_invalidation() {
    assert_vector_present(VECTOR_IDENTITY_LINK_EAGER_INVALIDATION)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.identity_link.policy_tightening_invalidation.v1): implementer-side wire support pending (coauth + soland identity_link cache eviction on policy tightening)"]
fn vector_identity_link_policy_tightening_invalidation() {
    assert_vector_present(VECTOR_IDENTITY_LINK_POLICY_TIGHTENING_INVALIDATION)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.late_key_recovery.removed_actor.v1): implementer-side wire support pending (soland + yougen late-recovery state machine, late_recovery_rejected_membership / late_recovery_share_not_authorized)"]
fn vector_late_key_recovery_removed_actor() {
    assert_vector_present(VECTOR_LATE_KEY_RECOVERY_REMOVED_ACTOR)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.invite.oob_code_entropy.v1): implementer-side wire support pending (coauth 3PID invite offline_token + lookup state machine)"]
fn vector_invite_oob_code_entropy() {
    assert_vector_present(VECTOR_INVITE_OOB_CODE_ENTROPY)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.invite.failure_indistinguishable.v1): implementer-side wire support pending (coauth byte-identical not_found response across 7 invite failure causes)"]
fn vector_invite_failure_indistinguishable() {
    assert_vector_present(VECTOR_INVITE_FAILURE_INDISTINGUISHABLE)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.consent.scope_cascade.v1): implementer-side wire support pending (soland + coauth + teabay + floria consent.any cascade vs concrete scope)"]
fn vector_consent_scope_cascade() {
    assert_vector_present(VECTOR_CONSENT_SCOPE_CASCADE)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.consent.cache_invalidation.v1): implementer-side wire support pending (soland + coauth + teabay + floria revoke triggers directory/invite/psi cache flush)"]
fn vector_consent_cache_invalidation() {
    assert_vector_present(VECTOR_CONSENT_CACHE_INVALIDATION)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.sync.soft_fail_reconcile.v1): implementer-side wire support pending (soland + yougen soft_failed → accepted / rejected reconciliation)"]
fn vector_sync_soft_fail_reconcile() {
    assert_vector_present(VECTOR_SYNC_SOFT_FAIL_RECONCILE)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.lattice.lww_open_set.v1): implementer-side wire support pending (soland lattice tiebreaker / covered frontier determinism)"]
fn vector_lattice_lww_open_set() {
    assert_vector_present(VECTOR_LATTICE_LWW_OPEN_SET)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

#[test]
#[ignore = "TODO(round4-vector-cx.vector.e2ee_relaxed.window_exceeds_ceiling.v1): implementer-side wire support pending (soland reducer reject + receiver-side independent enforcement)"]
fn vector_e2ee_relaxed_window_exceeds_ceiling() {
    assert_vector_present(VECTOR_E2EE_RELAXED_WINDOW_EXCEEDS_CEILING)
        .expect("fixture wire shape must parse even when SUT support is pending");
}

// ── Wire-shape parse + ObservedRunner smoke gates (always-runs) ─────────────
//
// These gates do NOT require any SUT — they prove the fixture parses with the
// full round-4 runner contract (`given_state` / `operation` / `transcript` /
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
    // `contrix-spec/spec/v1/artifacts/fixtures` and the file must exist.
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
        // `contrix-spec/spec/v1/artifacts/fixtures/security-closure-vectors.json`.
        let canonical_tail = std::path::Path::new("contrix-spec")
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

// ── Round 4 / C3 — multi-server federation historical_only gates ───────────
//
// Non-ignored wire-shape gates for the
// `cx.vector.federation.idempotency_after_key_revoke.v1` vector. They run
// without a live soland / teabay and assert:
//
// 1. The cotest fixture loader picks up the C3 vector by id,
// 2. The cotest scenario module pins the same vector id literal,
// 3. The in-memory multi-server driver round-trips: fresh accept → strict
//    replay (no historical_only) → post-key-rotation replay (historical_only
//    + zero new side effects).
//
// The full live e2e (docker / live processes / real key rotation) stays
// `#[ignore]`d inside the scenario module with
// `TODO(round4-federation-e2e-docker)`.

#[test]
fn round4_c3_vector_loads_from_security_closure_fixture() {
    // The cotest scenario module's pin must match the security-closure
    // pin AND the fixture must surface the vector via the existing
    // wire-shape gate.
    assert_eq!(
        ROUND4_HISTORICAL_VECTOR_ID, VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE,
        "round4_federation_historical_only::VECTOR_ID drifted from security_closure_vectors pin",
    );
    assert_vector_present(ROUND4_HISTORICAL_VECTOR_ID)
        .expect("C3 vector must parse out of security-closure-vectors.json");

    // The fixture's first step expectation MUST include the historical_only
    // outcome on the post-revoke replay — pin it explicitly so a fixture
    // edit that re-labels the marker cannot pass silently.
    let fixture = SecurityClosureFixture::load().expect("fixture loads");
    let vector = fixture
        .vector(ROUND4_HISTORICAL_VECTOR_ID)
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
fn round4_c3_multi_server_in_memory_driver_round_trips() {
    // Non-ignored: runs entirely against the cotest in-memory simulated
    // federation receiver. Asserts cache-key composition includes
    // `origin_key_state_hash`, the transcript fragment carries the three
    // lowercase header names + values, post-rotation replay sets
    // `reason_code=historical_only`, and side-effects fire exactly once.
    run_round4_federation_historical_only()
        .expect("C3 in-memory multi-server scenario must pass without live soland/teabay");
}
