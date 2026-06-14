//! Integration entrypoints for the conformance vectors and scenario
//! scaffolds. SDK-pure vector suites run unconditionally; integration-target
//! scenarios are `#[ignore]`-gated on reducer / signing wiring.
//!
//! Spec-sync revision is tracked in `CHANGELOG.md`, not pinned in source.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use cotest::conformance::{
    ALL_AGENT_VECTOR_IDS, ALL_CURSOR_VECTOR_IDS, ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS,
    ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS, ALL_MEDIA_BINDING_VECTOR_IDS,
    ALL_MEMBER_IDENTITY_VECTOR_IDS, ALL_MEMBER_ROSTER_VECTOR_IDS, ALL_MENTION_RENDERING_VECTOR_IDS,
    ALL_OBJECT_ADDRESSING_VECTOR_IDS, ALL_PRIMARY_HANDLE_VECTOR_IDS, ALL_SIDECAR_VECTOR_IDS,
    load_local_fixture_value, run_agent_vector_suite, run_cursor_vector_suite,
    run_handle_claim_rejection_vector_suite, run_list_handles_for_subject_vector_suite,
    run_media_binding_vector_suite, run_member_identity_vector_suite,
    run_member_roster_vector_suite, run_mention_rendering_vector_suite,
    run_object_addressing_vector_suite, run_primary_handle_vector_suite, run_sidecar_vector_suite,
};
use serde_json::Value;

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

// ─── R3.1 / VECT-MID-1..7 — MemberIdentity vectors ─────────────────────────

#[test]
fn member_identity_vector_suite_runs_clean() {
    run_member_identity_vector_suite().expect("member-identity vectors must pass");
    // R3.2: VECT-MID-1..7 + VECT-COT-8 (handle_field_forbidden).
    assert_eq!(ALL_MEMBER_IDENTITY_VECTOR_IDS.len(), 8);
}

// ─── R3.1 / VECT-ROST-1..3 — sync member roster vectors ───────────────────

#[test]
fn member_roster_vector_suite_runs_clean() {
    run_member_roster_vector_suite().expect("member-roster vectors must pass");
    // R3.2: VECT-ROST-1..3 + VECT-COT-4 roster v2 (4 cases).
    assert_eq!(ALL_MEMBER_ROSTER_VECTOR_IDS.len(), 7);
}

// ─── R3.2 / VECT-COT-1 — §3.2.1 primary handle selection ──────────────────

#[test]
fn primary_handle_vector_suite_runs_clean() {
    run_primary_handle_vector_suite().expect("primary-handle vectors must pass");
    assert!(
        ALL_PRIMARY_HANDLE_VECTOR_IDS.len() >= 10,
        "VECT-COT-1 requires >= 10 §3.2.1 cases, got {}",
        ALL_PRIMARY_HANDLE_VECTOR_IDS.len()
    );
}

// ─── R3.2 / VECT-COT-2 — §3.8 mention rendering ───────────────────────────

#[test]
fn mention_rendering_vector_suite_runs_clean() {
    run_mention_rendering_vector_suite().expect("mention-rendering vectors must pass");
    assert!(
        ALL_MENTION_RENDERING_VECTOR_IDS.len() >= 6,
        "VECT-COT-2 requires >= 6 §3.8 cases, got {}",
        ALL_MENTION_RENDERING_VECTOR_IDS.len()
    );
}

// ─── R3.2 / VECT-COT-3 — ck.find.directory.query.list_handles_for_subject ────────────

#[test]
fn list_handles_for_subject_vector_suite_runs_clean() {
    run_list_handles_for_subject_vector_suite()
        .expect("list-handles-for-subject vectors must pass");
    assert!(
        ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS.len() >= 5,
        "VECT-COT-3 requires >= 5 cases, got {}",
        ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS.len()
    );
}

// ─── R3.2 / VECT-COT-6/7 — handle-claim rejection vectors ─────────────────

#[test]
fn handle_claim_rejection_vector_suite_runs_clean() {
    run_handle_claim_rejection_vector_suite().expect("handle-claim rejection vectors must pass");
    assert_eq!(ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS.len(), 2);
}

#[test]
fn vect_cot_vector_registry_is_mechanically_complete() {
    let groups = [
        (
            "VECT-COT-1 primary handle",
            ALL_PRIMARY_HANDLE_VECTOR_IDS,
            10usize,
        ),
        (
            "VECT-COT-2 mention rendering",
            ALL_MENTION_RENDERING_VECTOR_IDS,
            6usize,
        ),
        (
            "VECT-COT-3 list handles for subject",
            ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS,
            5usize,
        ),
        ("VECT-COT-4 roster v2", ALL_MEMBER_ROSTER_VECTOR_IDS, 7usize),
        (
            "VECT-COT-6/7 handle claim rejection",
            ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS,
            2usize,
        ),
        (
            "VECT-COT-8 member identity",
            ALL_MEMBER_IDENTITY_VECTOR_IDS,
            8usize,
        ),
    ];

    let mut seen = BTreeSet::new();
    for (label, ids, min_count) in groups {
        assert!(
            ids.len() >= min_count,
            "{label} expected at least {min_count} vector ids, got {}",
            ids.len()
        );
        for id in ids {
            assert!(
                id.starts_with("ck.cotest_vector."),
                "{label} id must use cotest-local vector namespace unless it is registered in vector-registry.json: {id}"
            );
            assert!(seen.insert(*id), "duplicate conformance vector id: {id}");
        }
    }
    assert!(
        ALL_MEMBER_IDENTITY_VECTOR_IDS
            .iter()
            .any(|id| id.contains("handle_field_forbidden")),
        "VECT-COT-8 handle_field_forbidden id must remain present"
    );
}

// ─── R3.3 / OA-COT-1..4 — CKP-0011 object addressing + resolve_target ─────
//
// SDK-pure vectors over `cokret_core::models::*` object-addressing surface:
//   * OA-COT-1 (4 cases) — grammar: scheme⇄fragment equivalence, hierarchy forms, fail-closed
//     keyword/order/missing-via, realm-id vs alias.
//   * OA-COT-2 (3 cases) — target_digest: ignores via/action/tok/lt, tracks strand/message identity,
//     omitted-key (not null) canonical shape.
//   * OA-COT-3 (2 cases) — scope confusion: cross-object replay rejected, token link_type wins over
//     URL `lt` hint.
//   * OA-COT-4 (2 cases) — resolve_target response shape: §9.1 common fields
//     + target_kind; realm target carries realm_preview.

#[test]
fn object_addressing_vector_suite_runs_clean() {
    run_object_addressing_vector_suite().expect("object-addressing vectors must pass");
    assert_eq!(ALL_OBJECT_ADDRESSING_VECTOR_IDS.len(), 11);
}

// ─── R3.3 / OA-COT-5 — live share→resolve→open integration ────────────────
//
// The SDK-pure OA-COT-1..4 vectors above lock the wire grammar + token target
// binding + resolve_target response shape. The full live leg (a client mints a
// shareable link, teabay's resolve_target resolves it, and the recipient opens
// the strand/message subject through the access gate) lands once teabay's
// strand/message access-gate is reachable end-to-end.

#[test]
#[ignore = "R3.3-followup: needs teabay strand/message access-gate"]
fn test_oa_cot_5_share_resolve_open_live() {
    // Live integration (client ↔ teabay resolve_target ↔ soland subject gate):
    //   1. Author shares a strand as `web+cokret:realm/<r>/strand/<f>?via=<teabay>
    //      &lt=invite&tok=<minted>` (and the equivalent HTTPS landing URL).
    //   2. Recipient POSTs `ck.find.directory.query.resolve_target { address, token }`.
    //   3. teabay parses the address, verify_token_target() binds the token to the resolved object
    //      (scope-confusion replay rejected), and returns `DirectoryTargetResolutionOutcome {
    //      target_kind=strand, object_preview, join_rule, as_of, source_refs, via_services }`.
    //   4. Recipient opens the strand; soland's access gate honors the invite link_type (NOT the URL
    //      `lt` hint) for the join decision.
    unreachable!("integration target gated on teabay strand/message access-gate (R3.3)");
}

// ─── R3.2 / TEST-COT-1 — live integration scenarios (shape-level only) ────
//
// These pin the full cross-service strands that the R3.2 wire changes enable.
// The SDK-pure vector suites above already lock the wire shapes; the live
// wiring (soland MID reducer + teabay list_handles_for_subject endpoint +
// yougen §3.8.2 renderer transitions) lands as the upstream services finish
// their R3.2 work, so the live legs stay `#[ignore]` with a reason string
// (cotest CI enforces ignore-comment hygiene).

#[test]
#[ignore = "R3.2-followup: soland MID reducer + coauth issuer + yougen/floria refresh \
            not yet wired for the end-to-end handle reassignment strand"]
fn test_cot_1_handle_reassignment_full_strand_live() {
    // Live integration (soland ↔ SDK ↔ yougen ↔ coauth):
    //   1. coauth issues handle claim H1 for subject S (binding_state=verified).
    //   2. All views (roster member_display_state_digest, list_handles_for_subject, yougen mention
    //      render) reflect H1 as the §3.2.1 primary handle.
    //   3. coauth revokes H1 and issues H2 for S.
    //   4. roster member_display_state_digest changes (claim digest set folded);
    //      list_handles_for_subject drops H1, surfaces H2; yougen re-renders the mention to H2 with
    //      no `ck.member.identity.update` forged.
    unreachable!("integration target gated on soland/coauth/yougen R3.2 P0 wiring");
}

#[test]
#[ignore = "R3.2-followup: teabay POST /_cokret/find/directory/list-handles-for-subject \
            endpoint not yet reachable end-to-end across services"]
fn test_cot_1_teabay_list_handles_for_subject_end_to_end_live() {
    // Live integration (teabay directory):
    //   1. Seed teabay with two verified claims for subject S under distinct audiences + issuers.
    //   2. POST list-handles-for-subject with realm context R1 → only the audience/issuer-trusted
    //      claim is visible; response.primary_handle = select_primary_handle() output;
    //      claims[].subject == subject.
    //   3. Paginate with limit=1 → has_more=true + opaque next_cursor; the follow-up page
    //      terminates with has_more=false.
    unreachable!("integration target gated on teabay DIR-TBY-1 P0 wiring");
}

#[test]
#[ignore = "R3.2-followup: yougen §3.8.2 mention renderer fallback transitions \
            (verified → cached → name-only → unresolved) not yet observable live"]
fn test_cot_1_mention_render_fallback_transitions_live() {
    // Live integration (yougen renderer):
    //   1. Verified projection → render @localpart:domain (Verified tier).
    //   2. Directory unreachable but local cache present → Cached tier badge.
    //   3. Cache evicted, display_name_at_time present → NameOnly tier badge.
    //   4. Nothing resolvable → Unresolved truncated-DID tier badge.
    // Each transition MUST carry a distinct visual-degradation marker.
    unreachable!("integration target gated on yougen YG-MENT-2 P0 wiring");
}

// ─── P0 / FIX-1 — fixture presence + shape ────────────────────────────────

#[test]
fn recovery_policy_fixture_loads_and_has_canonical_shape() {
    let value = load_local_fixture_value("recovery-policy.json").expect("recovery-policy.json");
    assert_eq!(
        value.get("schema_ref").and_then(Value::as_str),
        Some("ck.schema.recovery_policy.v1")
    );
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases array");
    assert!(!cases.is_empty(), "recovery-policy.json must have cases");
}

#[test]
fn recovery_receipt_fixture_loads_and_has_canonical_shape() {
    let value = load_local_fixture_value("recovery-receipt.json").expect("recovery-receipt.json");
    assert_eq!(
        value.get("schema_ref").and_then(Value::as_str),
        Some("ck.schema.recovery_receipt.v1")
    );
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases array");
    assert!(!cases.is_empty(), "recovery-receipt.json must have cases");
}

#[test]
fn agent_payloads_fixture_loads_and_has_canonical_shape() {
    let value = load_local_fixture_value("agent_payloads.json").expect("agent_payloads.json");
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases array");
    assert!(
        cases.len() >= 8,
        "agent_payloads.json must cover all new kinds"
    );
    let kinds: Vec<&str> = cases
        .iter()
        .filter_map(|c| c.get("event_kind").and_then(Value::as_str))
        .collect();
    for required in [
        "ck.self.agent.pause",
        "ck.self.agent.resume",
        "ck.self.agent.deactivate",
        "ck.agent.draft.propose",
        "ck.agent.action_request",
        "ck.agent.action_approve",
        "ck.agent.action_reject",
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
    //   - happy: 200 with backend_token + participant_binding, TTL ≤ 600s, issuer_kid anchored to
    //     current `ck.realm.media_service.service_id`.
    //   - neg-issuer: rogue issuer kid → 401 token_issuer_unauthorised.
    //   - neg-focus:  off-focus token request → 422 focus_mismatch.
    //   - neg-ttl:    server-issued TTL > 600s → 422 participant_binding_invalid.
    //   - neg-binding: malformed participant_binding scheme → 422 participant_binding_invalid.
    unreachable!("integration target gated on soland / floria P2-impl");
}

// ─── P0 / TEST-3 — `accountable_principals.strict_reject` profile toggle ───

#[test]
#[ignore = "R3.1: soland strict_reject reducer branch not yet implemented"]
fn test_3_accountable_principals_strict_reject_profile_toggle() {
    // Live integration:
    //   1. With `ck.profile.accountable_principals.strict_reject.v1` NOT advertised: actor-profile
    //      create with unverified `accountable_principal_ids[]` → 200, server strips + audit logs.
    //   2. With the profile advertised: same envelope → 412 failed_precondition
    //      reason=accountability_grant_missing.
    unreachable!("integration target gated on soland P2-impl profile branch");
}

// ─── P0 / TEST-4 — Cursor opaque round-trip + stateless-under-core reject ──

#[test]
fn test_4_cursor_opaque_round_trip_stateful_only() -> Result<()> {
    // Stateful core body is the default — round-trip via the SDK
    // primitives is exercised by `run_cursor_opaque_core_vector`. Here
    // we additionally assert that a stateless body parses through the
    // SDK struct but a server with no `ck.profile.stateless_cursor.v1`
    // declaration MUST reject it. We pin both at the wire layer; the
    // server-side acceptance gate lands under soland P2-impl.
    use std::collections::BTreeMap;

    use cokret_core::cursor::{Cursor, CursorPurpose};
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
        filter_digest: None,
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
    let value = load_local_fixture_value("recovery-policy.json")?;
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
    let receipt = load_local_fixture_value("recovery-receipt.json")?;
    let has_lagging = receipt
        .get("cases")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().any(|c| {
                c.get("reason").and_then(Value::as_str) == Some("recovery_witness_revoke_lagging")
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
    //   4. POST recovery-receipt where witness has not yet revoked → 409
    //      recovery_witness_revoke_lagging.
    unreachable!("integration target gated on soland P2-impl recovery reducer");
}

// ─── P0 / TEST-6 — Handle homograph reject ─────────────────────────────────

#[test]
#[ignore = "R3.1: soland / starid / teabay wire-level homograph reject not yet implemented"]
fn test_6_handle_homograph_script_mix_or_nfc_variant_reject() {
    // Live integration:
    //   1. POST handle claim `аlice` (Cyrillic а + Latin lice) → 412 handle_homograph_forbidden.
    //   2. POST handle claim with NFC-variant that folds onto an existing claim → 412
    //      handle_homograph_forbidden.
    //   3. Display-layer mitigation MUST still surface a confusable hint when the canonical compare
    //      passes.
    unreachable!("integration target gated on starid / teabay P2-impl");
}

// ─── R3.1 / TEST-7 — `ck.member.identity.update` end-to-end ───────────────

#[test]
fn test_7_cx_member_identity_update_replacement_shape() -> Result<()> {
    // SDK-level positive control: the canonical-bytes helper +
    // effective-set filter that soland's MID reducer MUST mirror. An
    // initial event followed by a replacement event with a matching
    // payload_digest collapses to a single effective entry — the second.
    use cokret_core::models::{
        DisplayProfile, IdentityPayloadCarrier, MemberIdentity, MemberIdentityProof,
        MemberIdentityReplacementRef, MemberIdentitySegment, MemberIdentitySignatureAlgorithm,
        MemberIdentityUpdatePayload, effective_identity_events,
    };
    use cokret_core::{Did, EventId, Hash, RealmId};

    let realm = RealmId::new("ck:realm:01904100-0000-7000-8000-000000007007")
        .map_err(|e| anyhow!("realm: {e}"))?;
    let alice = Did::new("did:web:alice.acme.example".to_owned())?;
    let subject = Did::new("did:web:alice.principal.example".to_owned())?;

    // R3.2: MemberIdentity discloses subject_id + display_profile only;
    // handle lifecycle (the retired `primary_handle` / `handles[]`) has
    // moved to `ck.schema.handle_claim.v1`.
    let make_identity = |name: &str| -> Result<MemberIdentity> {
        Ok(MemberIdentity {
            schema: "ck.schema.member_identity.v1".to_owned(),
            realm_id: realm.clone(),
            actor_id: alice.clone(),
            subject_id: subject.clone(),
            display_profile: DisplayProfile {
                display_name: name.to_owned(),
                avatar_blob_ref: None,
            },
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            proof: MemberIdentityProof {
                verification_method: "did:web:alice.acme.example#key-1".to_owned(),
                signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
                payload_digest: Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )?,
                signature: "AAAA".to_owned(),
            },
        })
    };

    let v1 = make_identity("Alice v1")?;
    let v2 = make_identity("Alice v2 (display_name changed)")?;
    let event_a = EventId::new("ck:event:01904100-0000-7000-8000-000000007a01")?;
    let event_b = EventId::new("ck:event:01904100-0000-7000-8000-000000007a02")?;
    let carrier_a = IdentityPayloadCarrier::MemberIdentity {
        member_identity: v1,
    };
    let carrier_b = IdentityPayloadCarrier::MemberIdentity {
        member_identity: v2,
    };
    let digest_a = Hash::new(
        carrier_a
            .carrier_sha256()
            .map_err(|e| anyhow!("carrier_sha256: {e}"))?,
    )?;

    let payload_a = MemberIdentityUpdatePayload {
        realm_id: realm.clone(),
        actor_id: alice.clone(),
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![],
        identity_payload: carrier_a,
        identity_payload_digest: None,
        expected_state_digest: None,
    };
    let payload_b = MemberIdentityUpdatePayload {
        realm_id: realm,
        actor_id: alice,
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![MemberIdentityReplacementRef {
            event_id: event_a.clone(),
            payload_digest: digest_a,
        }],
        identity_payload: carrier_b,
        identity_payload_digest: None,
        expected_state_digest: None,
    };

    let effective = effective_identity_events([(&event_a, &payload_a), (&event_b, &payload_b)])
        .map_err(|e| anyhow!("effective: {e}"))?;
    if effective.len() != 1 || effective[0].0.as_str() != event_b.as_str() {
        bail!(
            "TEST-7: client MUST see only the replacing event in the effective \
             set (replaces[] semantics); got {} entries: {:?}",
            effective.len(),
            effective
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
#[ignore = "R3.1: soland MID reducer + ck.profile.update field-level delta wiring not yet implemented"]
fn test_7_cx_member_identity_update_live() {
    // Live integration:
    //   1. Actor publishes initial `ck.member.identity.update` event with MemberIdentity v1
    //      (display_name="Alice").
    //   2. Actor publishes second event with `replaces[]` pointing at the first; payload carries
    //      MemberIdentity v2 with display_name="Alice (work)".
    //   3. Client `account.subscribe` frame surfaces a roster with only the second event in
    //      `identity_event_ids[]`.
    //   4. `ck.profile.update` field-level delta MUST drive the v2 display_name onto the projected
    //      profile; the `ck.profile.realm_override` profile MUST take precedence when set
    //      per-Space.
    unreachable!("integration target gated on soland MID reducer (R3.1)");
}

// ─── R3.1 / TEST-8 — Handle rename round-trip ──────────────────────────────

#[test]
fn test_8_handle_rename_round_trip_sdk_shape() -> Result<()> {
    // SDK-level positive control: invite by canonical handle
    // `alice:acme.example`. The `MemberDeliveryBindingCandidate` carries
    // `payload.handle` (NOT `handle_uri`) and the directory's
    // `resolve_handle` response surface MUST round-trip the same wire
    // form. The full wire round-trip across coauth/soland/teabay is the
    // live `#[ignore]` companion below.
    use std::collections::BTreeSet;

    use cokret_core::{
        CandidateIntent, DeliveryBindingHint, DeliveryMode, Did, Handle, HandleHintBindingSource,
        MemberDeliveryBindingCandidate, RecipientServiceType,
    };

    let invite_handle = Handle::parse("alice:acme.example").map_err(|e| anyhow!("handle: {e}"))?;
    if invite_handle.canonical() != "alice:acme.example" {
        bail!(
            "TEST-8: canonical handle wire form must be `<localpart>:<domain>`; got `{}`",
            invite_handle.canonical()
        );
    }

    let principal = Did::new("did:web:principal.acme.example".to_owned())?;
    let mut modes = BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    let candidate = MemberDeliveryBindingCandidate {
        subject_id: Did::new("did:web:alice.acme.example".to_owned())?,
        handle: invite_handle,
        handle_aliases: vec!["acct:alice@acme.example".to_owned()],
        member_delivery_binding: DeliveryBindingHint {
            recipient_service_did: principal.clone(),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: None,
            policy_event_ref: None,
        },
        issuer_service_did: principal,
        audience: "ck:realm:01904100-0000-7000-8000-test8audience".to_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        issued_at: Some(chrono::Utc::now()),
        source_refs: vec!["ck:event:01904100-0000-7000-8000-test8source01".to_owned()],
        proofs: vec![serde_json::json!({
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:principal.acme.example#key-1",
            "payload_digest":
                "sha256:0000000000000000000000000000000000000000000000000000000000000088",
            "created_at": "2026-05-27T00:00:00Z",
            "audience": "ck:realm:01904100-0000-7000-8000-test8audience",
            "jws": "test8.real.shaped.jws"
        })],
        claim_digest: None,
        intent: CandidateIntent::MemberAdd,
    };

    // Round-trip through serde to confirm the wire form carries `handle`
    // (NOT `handle_uri`) and round-trips back to the same Handle.
    let wire = serde_json::to_value(&candidate).map_err(|e| anyhow!("serialise: {e}"))?;
    if wire.get("handle").is_none() {
        bail!(
            "TEST-8: serialised candidate MUST carry `handle` field (R3.1 wire \
             rename); shape: {wire:#}"
        );
    }
    if wire.get("handle_uri").is_some() {
        bail!(
            "TEST-8: serialised candidate MUST NOT carry the retired \
             `handle_uri` field"
        );
    }
    let decoded: MemberDeliveryBindingCandidate =
        serde_json::from_value(wire).map_err(|e| anyhow!("deserialise: {e}"))?;
    if decoded.handle.canonical() != "alice:acme.example" {
        bail!(
            "TEST-8: handle wire round-trip drifted; got `{}`",
            decoded.handle.canonical()
        );
    }
    Ok(())
}

#[test]
#[ignore = "R3.1: live coauth + soland + teabay handle wire rename not yet visible at runtime"]
fn test_8_handle_rename_round_trip_live() {
    // Live integration:
    //   1. Client builds invite for canonical handle `alice:acme.example`.
    //   2. soland reducer accepts member-add with `payload.handle = "alice:acme.example"` (NO
    //      `handle_uri` field).
    //   3. teabay's `ck.find.directory.query.resolve_handle(handle=...)` accepts the canonical
    //      handle string in the request body and returns a candidate whose `handle` field is the
    //      same canonical wire form.
    //   4. coauth's handle-claim issuance + sync surface MUST NOT emit `handle_uri` anywhere on a
    //      fresh R3.1 wire shape.
    unreachable!("integration target gated on coauth+soland+teabay R3.1 rename");
}
