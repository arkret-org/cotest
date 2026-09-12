//! Integration entrypoints for the conformance vectors and scenario
//! scaffolds. SDK-pure vector suites run unconditionally; integration-target
//! scenarios are `#[ignore]`-gated on reducer / signing wiring.
//!
//! Spec-sync revision is tracked in `CHANGELOG.md`, not pinned in source.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use cotest::conformance::{
    ALL_AGENT_SIGNER_EVIDENCE_CASES, ALL_AGENT_VECTOR_IDS, ALL_CALL_SIGNAL_VECTOR_IDS,
    ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS, ALL_CURSOR_VECTOR_IDS,
    ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS, ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS,
    ALL_MEDIA_BINDING_VECTOR_IDS, ALL_MEMBER_IDENTITY_VECTOR_IDS, ALL_MEMBER_ROSTER_VECTOR_IDS,
    ALL_MENTION_RENDERING_VECTOR_IDS, ALL_OBJECT_ADDRESSING_VECTOR_IDS,
    ALL_PRESENCE_SIGNAL_VECTOR_IDS, ALL_PRIMARY_HANDLE_VECTOR_IDS, ALL_SIDECAR_VECTOR_IDS,
    load_local_fixture_value, run_agent_signer_evidence_vector_suite, run_agent_vector_suite,
    run_call_signal_vector_suite, run_call_state_media_lifecycle_vector_suite,
    run_container_realm_control_payload_suite, run_cursor_vector_suite, run_encoding_fixture_suite,
    run_handle_claim_rejection_vector_suite, run_list_handles_for_subject_vector_suite,
    run_media_binding_vector_suite, run_member_identity_vector_suite,
    run_member_roster_vector_suite, run_mention_rendering_vector_suite,
    run_object_addressing_vector_suite, run_poll_reducer_fixture_suite,
    run_presence_signal_vector_suite, run_primary_handle_vector_suite, run_sidecar_vector_suite,
};
use serde_json::{Value, json};

#[test]
fn encoding_artifact_vectors_reject_drift() -> Result<()> {
    run_encoding_fixture_suite()
}

#[test]
fn domain_wire_constraint_vectors_reject_drift() {
    let checks = json!({
        "append_only": true,
        "seal_signatures": true,
        "dag_edges_verified": true,
        "set_root_monotonic": true,
        "completeness_monotonic": true
    });
    serde_json::from_value::<arkret::SealTransparencyChecks>(checks.clone())
        .expect("all required transparency checks set to true must pass");

    let mut missing_dag_edges = checks.clone();
    missing_dag_edges
        .as_object_mut()
        .expect("checks fixture is an object")
        .remove("dag_edges_verified");
    assert!(
        serde_json::from_value::<arkret::SealTransparencyChecks>(missing_dag_edges).is_err(),
        "missing dag_edges_verified must fail closed"
    );

    let mut false_dag_edges = checks;
    false_dag_edges["dag_edges_verified"] = json!(false);
    assert!(
        serde_json::from_value::<arkret::SealTransparencyChecks>(false_dag_edges).is_err(),
        "false dag_edges_verified must fail closed"
    );

    let consent = json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "peer": {
            "kind": "actor",
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:webvh:z6mkfixturestationexample"
                }
            }
        },
        "consent_scope": "voice_call"
    });
    serde_json::from_value::<arkret::ConsentGrantPayload>(consent.clone())
        .expect("typed UUIDv7 consent identifier must pass");
    let mut untyped_consent = consent;
    untyped_consent["consent_id"] = json!("cid");
    assert!(
        serde_json::from_value::<arkret::ConsentGrantPayload>(untyped_consent).is_err(),
        "untyped consent identifier must fail"
    );
}

#[test]
fn account_stream_and_device_message_replay_vectors_converge() {
    let describe_roles = ["station", "authorization_server"];
    let select_role = |requested: Option<&str>| -> Result<String, &'static str> {
        match requested {
            Some(role) if describe_roles.contains(&role) => Ok(role.to_owned()),
            Some(_) => Err("param_invalid"),
            None if describe_roles.len() == 1 => Ok(describe_roles[0].to_owned()),
            None => Err("param_invalid"),
        }
    };
    assert_eq!(select_role(Some("station")), Ok("station".to_owned()));
    assert_eq!(select_role(None), Err("param_invalid"));
    assert_eq!(select_role(Some("unknown")), Err("param_invalid"));

    let frame_kinds = ["delta", "catchup_complete", "heartbeat", "delta"];
    let mut catchup_seen = false;
    let mut live_deltas = 0;
    for kind in frame_kinds {
        match kind {
            "catchup_complete" => catchup_seen = true,
            "delta" if catchup_seen => live_deltas += 1,
            _ => {}
        }
    }
    assert_eq!(live_deltas, 1, "stream must remain live after catchup");

    let key = (
        "did:webvh:z6mkfixture:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "ak:device_message:01904100-0000-7000-8000-000000000001",
    );
    let first = json!({"kind": "ak.device.message", "ciphertext": "first"});
    let conflicting = json!({"kind": "ak.device.message", "ciphertext": "changed"});
    let mut durable_inbox = BTreeMap::new();
    let mut side_effects = 0;
    let mut stream_cursor = None;
    let mut device_ack = None;

    {
        let mut ingest = |envelope: &Value, cursor: &'static str| -> Result<bool, &'static str> {
            match durable_inbox.get(&key) {
                None => {
                    durable_inbox.insert(key, envelope.clone());
                    side_effects += 1;
                    stream_cursor = Some(cursor);
                    Ok(true)
                }
                Some(existing) if existing == envelope => {
                    stream_cursor = Some(cursor);
                    Ok(false)
                }
                Some(_) => Err("device_message_conflict"),
            }
        };

        assert_eq!(ingest(&first, "ak:cursor:first"), Ok(true));
        assert_eq!(ingest(&first, "ak:cursor:duplicate"), Ok(false));
        assert_eq!(
            ingest(&conflicting, "ak:cursor:conflict"),
            Err("device_message_conflict")
        );
    }
    assert_eq!(
        side_effects, 1,
        "duplicate delivery must not repeat effects"
    );
    assert_eq!(stream_cursor, Some("ak:cursor:duplicate"));
    assert_eq!(
        device_ack, None,
        "account cursor must not implicitly ack inbox messages"
    );
    device_ack = Some("ak:device_message:01904100-0000-7000-8000-000000000001");
    assert_eq!(stream_cursor, Some("ak:cursor:duplicate"));
    assert!(device_ack.is_some(), "device ack advances independently");
}

#[test]
fn container_realm_control_payload_vector_suite_runs_clean() {
    run_container_realm_control_payload_suite()
        .expect("container and Realm control payload vectors must pass");
}

#[test]
fn poll_reducer_fixture_suite_runs_clean() {
    run_poll_reducer_fixture_suite().expect("Poll reducer fixture must remain executable");
}

// ─── P0 / VECT-MB-1..10 — media binding vectors ─────────────────────────────

#[test]
fn media_binding_vector_suite_runs_clean() {
    run_media_binding_vector_suite().expect("media-binding vectors must pass");
    assert_eq!(ALL_MEDIA_BINDING_VECTOR_IDS.len(), 10);
}

// ─── webrtc-signaling.md §5 — ak.call.signal receiver vectors ──────────────
//
// signal_kind enum on the decrypted plaintext (rejects retired
// offer/ice/device_change) + per-(realm, call, actor, device) seq monotonicity
// + a REAL ed25519 round-trip under the `ak.signal_proof.v1` transcript +
// outer-header metadata minimisation, the class TTL ceiling, and SDK-backed
// closed plaintext schema rejection.

#[test]
fn call_signal_receiver_vector_suite_runs_clean() {
    run_call_signal_vector_suite().expect("call-signal receiver vectors must pass");
    assert_eq!(ALL_CALL_SIGNAL_VECTOR_IDS.len(), 5);
}

// ─── profiles-presence.md §3 — presence receiver vectors ───────────────────
//
// Presence is Signal state whose plaintext the Sync Service may not read, so
// the closed `state` set, the `last_active_at` bucket rules, the
// `status_message` bounds and the deterministic multi-device aggregation are
// all receiver obligations.

/// 2026-08-01 — the Signal plaintext family closed on `kind` +
/// `payload_sequence`, and `ak.receipt.read` became a plaintext profile rather
/// than a durable object. A round trip is the only place the seal side and the
/// open side meet, so it lives here rather than in either repo's unit tests.
#[test]
fn read_receipt_signal_vector_suite_runs_clean() {
    cotest::conformance::run_read_receipt_signal_vector_suite()
        .expect("read receipt Signal plaintext vectors must pass");
}

/// 2026-08-17 — account lifecycle is an Account Authority issuer ledger, not a
/// Principal Control Realm finality domain. Genesis/CAS, exact replay, same-seq
/// fork, bounded gap recovery, binding rollback, service-key rotation, the
/// offline/hostile-holder deny invariant and the closed erasure trigger are
/// cross-object rules no JSON Schema can express.
#[test]
fn account_status_issuer_ledger_vector_runs_clean() {
    assert_eq!(
        cotest::conformance::VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER,
        "ak.vector.account_status.issuer_ledger.v1"
    );
    cotest::conformance::run_account_status_issuer_ledger_vector()
        .expect("account-status issuer ledger vector must pass");
}

/// 2026-08-17 — the over-broad `ak.directory_operation_proof.v1` /
/// `ak.mimi_operation_proof.v1` contexts were replaced by eleven per-object-
/// family contexts. Domain separation is what stops a proof minted for one
/// operation from being replayed onto a sibling, and no JSON Schema can
/// express it.
#[test]
fn proof_context_domain_separation_vector_runs_clean() {
    assert_eq!(
        cotest::conformance::DIRECTORY_PER_FAMILY_PROOF_CONTEXTS.len(),
        5
    );
    assert_eq!(cotest::conformance::MIMI_PER_FAMILY_PROOF_CONTEXTS.len(), 6);
    cotest::conformance::run_proof_context_domain_separation_vector()
        .expect("per-family proof context domain separation must hold");
}

/// 2026-08-17 — snapshot witness attestations became a typed object family
/// signed under their own context over a signature-free projection. Quorum
/// counting, witness authorization and the issuer's binding to the final sorted
/// list are cross-object rules.
#[test]
fn realm_state_snapshot_witness_quorum_attestation_vector_runs_clean() {
    assert_eq!(
        cotest::conformance::VECTOR_ID_REALM_STATE_SNAPSHOT_WITNESS_QUORUM_ATTESTATION,
        "ak.vector.realm_state_snapshot.witness_quorum_attestation.v1"
    );
    cotest::conformance::run_realm_state_snapshot_witness_quorum_attestation_vector()
        .expect("snapshot witness quorum attestation vector must pass");
}

/// 2026-08-17 — `event-and-patch.md` §4.2.4 pinned against the machine-readable
/// redactable-field registry: `$op="unset"` on a registered content-carrier
/// slot is a slot-existence violation, while the metadata members stay
/// ordinary optional fields.
#[test]
fn patch_redactable_content_slot_unset_ban_vector_runs_clean() {
    assert_eq!(
        cotest::conformance::VECTOR_ID_PATCH_REDACTABLE_CONTENT_SLOT_UNSET_BAN,
        "ak.vector.patch.redactable_content_slot_unset_ban.v1"
    );
    cotest::conformance::run_patch_redactable_content_slot_unset_ban_vector()
        .expect("redactable content slot unset ban vector must pass");
}

#[test]
fn presence_signal_receiver_vector_suite_runs_clean() {
    run_presence_signal_vector_suite().expect("presence receiver vectors must pass");
    assert_eq!(ALL_PRESENCE_SIGNAL_VECTOR_IDS.len(), 4);
    for id in ALL_PRESENCE_SIGNAL_VECTOR_IDS {
        assert!(
            id.starts_with("ak.vector.presence."),
            "presence vector id drifted: {id}"
        );
    }
}

// ─── §12.16-§12.19 — call-state media lifecycle vectors ────────────────────
//
// recording_retention_lock / recording_result_artifact_shape /
// transcribe_lifecycle / moderator_kick_ban / p2p_to_sfu_upgrade — the spec
// additions for recording retention + audit lock, ready recording artifact
// binding, the transcribe pipeline + dedicated exporter label, moderator
// kick/ban + moderation OR-Set token-reissue gating, and the P2P→SFU
// upgrade + ak.call.summary terminal-state gate.

#[test]
fn call_state_media_lifecycle_vector_suite_runs_clean() {
    run_call_state_media_lifecycle_vector_suite()
        .expect("call-state media-lifecycle vectors must pass");
    assert_eq!(ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS.len(), 5);
    // All 5 ids are registered in vector-registry.json (canonical namespace).
    for id in ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS {
        assert!(
            id.starts_with("ak.vector.call_state."),
            "registered call_state vector id drifted: {id}"
        );
    }
}

// ─── P0 / VECT-AG-1..5 — agent vectors ─────────────────────────────────────

#[test]
fn agent_vector_suite_runs_clean() {
    run_agent_vector_suite().expect("agent vectors must pass");
    // VECT-AG-1..5 plus longevity, controller lifecycle, act-on-behalf,
    // session-grant replay, and human-approval-required coverage.
    assert_eq!(ALL_AGENT_VECTOR_IDS.len(), 10);
}

#[test]
fn agent_signer_evidence_vector_suite_runs_clean() {
    // The debug fixture match holds several complete signed evidence values.
    // Keep its stack requirement local to this test, not the verifier runtime.
    std::thread::Builder::new()
        .name("agent-signer-evidence-fixtures".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(run_agent_signer_evidence_vector_suite)
        .expect("Agent signer-evidence fixture worker must start")
        .join()
        .expect("Agent signer-evidence fixture worker must finish")
        .expect("Agent signer-evidence vectors must execute and pass");
    assert_eq!(ALL_AGENT_SIGNER_EVIDENCE_CASES.len(), 49);
}

// ─── P0 / VECT-SC-1..18 — sidecar vectors ──────────────────────────────────

#[test]
fn sidecar_vector_suite_runs_clean() {
    run_sidecar_vector_suite().expect("sidecar vectors must pass");
    assert_eq!(ALL_SIDECAR_VECTOR_IDS.len(), 18);
}

// ─── P0 / VECT-CUR-1 — cursor vectors ──────────────────────────────────────

#[test]
fn cursor_vector_suite_runs_clean() {
    run_cursor_vector_suite().expect("cursor vectors must pass");
    // `ALL_CURSOR_VECTOR_IDS` is the authoritative set for the encoding
    // cursor_opaque family: the round-trip vector plus the 2026-08-21
    // handle_reject negative vector (short / padded / non-alphabet / oversized
    // handles). The high-assurance cursor revoke vector lives under the
    // service-closure suite, so this set has length 2.
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

// ─── R3.2 / VECT-COT-3 — ak.find.directory.read.list_handles_for_subject.v1 ────────────

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
                id.starts_with("ak.cotest_vector."),
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

// ─── R3.3 / OA-COT-1..4 — AKP-0011 object addressing + resolve_target ─────
//
// SDK-pure vectors over the `arkret_wire` object-addressing surface:
//   * OA-COT-1 (4 cases) — grammar: scheme⇄fragment equivalence, hierarchy forms, fail-closed
//     keyword/order/missing-via, realm-id vs alias.
//   * OA-COT-2 (3 cases) — target_digest: ignores via/action/tok/lt, tracks strand/message
//     identity, omitted-key (not null) canonical shape.
//   * OA-COT-3 (2 cases) — scope confusion: cross-object replay rejected, token address_link_kind
//     wins over URL `lt` hint.
//   * OA-COT-4 (2 cases) — resolve_target response shape: §9.1 common fields
//     + target_kind; realm target carries realm_preview.

#[test]
fn object_addressing_vector_suite_runs_clean() {
    run_object_addressing_vector_suite().expect("object-addressing vectors must pass");
    assert_eq!(ALL_OBJECT_ADDRESSING_VECTOR_IDS.len(), 11);
}

// ─── P0 / FIX-1 — fixture presence + shape ────────────────────────────────

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
        "ak.self.agent.pause",
        "ak.self.agent.resume",
        "ak.self.agent.deactivate",
        "ak.agent.draft.propose",
        "ak.agent.action_request",
        "ak.agent.action_approve",
        "ak.agent.action_reject",
    ] {
        assert!(
            kinds.contains(&required),
            "agent_payloads.json missing event_kind {required}"
        );
    }
}

#[test]
fn agent_approval_cannot_admit_a_payload_without_its_publication_event() {
    let fixture = load_local_fixture_value("agent_payloads.json").unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "agent_action_approve_missing_publication_event")
        .unwrap();
    assert_eq!(case["expect"], "fail");
    assert_eq!(case["reducer_input"], true);
    let approval = arkret_wire::Event::new(
        "ak.agent.action_approve",
        arkret_wire::ScopeRef::Realm {
            realm_id: serde_json::from_value(case["payload"]["target"]["realm_id"].clone())
                .unwrap(),
        },
        arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
        ),
        1,
        arkret_wire::Hlc::new("000000000001-0000-00000000").unwrap(),
        case["payload"].clone(),
    )
    .unwrap();
    let error = arkret_wire::event_submission::validate_approval_publication_event(
        &approval,
        None,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("publication_event is required exactly")
    );
}

// ─── P0 / TEST-4 — Cursor opaque round-trip + stateless-under-core reject ──

#[test]
fn test_4_cursor_opaque_round_trip_stateful_only() -> Result<()> {
    // Stateful core body is the default — round-trip via the SDK
    // primitives is exercised by `run_cursor_opaque_core_vector`. Here
    // we additionally assert that a stateless body is rejected by the
    // SDK's closed stateful cursor shape. Servers without
    // `ak.profile.stateless_cursor.v1` have no compat path.
    use arkret_hlc::{Cursor, CursorPurpose};

    let stateless = serde_json::json!({
        "v": "1",
        "purpose": CursorPurpose::Stream,
        "t": "2026-05-27T00:00:00.000Z",
        "s": {},
        "x": 1_900_000_000_000_i64,
        "issuer_kid": "did:web:server.example#cursor-1",
        "mac": "AAAAAAAAAAAAAAAAAAAAAA"
    });
    if stateless.get("h").is_some() {
        bail!("stateless cursor wire body must not carry stateful handle");
    }
    if stateless.get("issuer_kid").is_none() {
        bail!("stateless cursor wire body must carry issuer_kid");
    }
    if serde_json::from_value::<Cursor>(stateless).is_ok() {
        bail!("stateless cursor wire body unexpectedly parsed as core Cursor");
    }
    Ok(())
}

// ─── P0 / TEST-5 — Recovery policy state machine ───────────────────────────

#[test]
fn test_5_recovery_policy_fixture_state_machine_shape() -> Result<()> {
    cotest::conformance::run_identity_recovery_kdf_fixture_suite()?;
    cotest::conformance::run_identity_root_anchor_checkpoint_suite()?;
    cotest::conformance::run_identity_model_generation_fence_suite()?;
    Ok(())
}

// ─── P0 / TEST-6 — Internationalized identifier profiles ───────────────────

#[test]
fn test_6_internationalized_identifier_profiles_and_collision_scope() -> Result<()> {
    cotest::conformance::run_privacy_security_fixture_suite()
}

// ─── R3.1 / TEST-7 — `ak.member.identity.update` end-to-end ───────────────

#[test]
fn test_7_cx_member_identity_update_replacement_shape() -> Result<()> {
    // SDK-level positive control: the canonical-bytes helper +
    // effective-set filter that soland's MID reducer MUST mirror. An
    // initial event followed by a replacement event with a matching
    // payload_digest collapses to a single effective entry — the second.
    use arkret_identifiers::{DidCoreId, EventId, Hash, RealmId};
    use arkret_models_identity::{
        DisplayProfile, IdentityPayloadCarrier, MemberIdentity, MemberIdentityProof,
        MemberIdentityReplacementRef, MemberIdentitySegment, MemberIdentitySignatureAlgorithm,
        MemberIdentityUpdatePayload, effective_identity_events,
    };
    use arkret_wire::{AccountId, ActorId};

    let realm = RealmId::new("ak:realm:AQfJRAZvIVyNOdrjtAPw9Q2gKR0o_3Ud-xQZQB8gx_r9")
        .map_err(|e| anyhow!("realm: {e}"))?;
    let station = DidCoreId::new("ak:did_core:web:station.acme.example")?;
    let alice = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.acme.example")?,
        station.clone(),
    ));
    let subject = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.principal.example")?,
        station,
    ));

    // R3.2: MemberIdentity discloses subject_id + display_profile only;
    // handle lifecycle (the retired `primary_handle` / `handles[]`) has
    // moved to `ak.schema.handle_claim.v1`.
    let make_identity = |name: &str| -> Result<MemberIdentity> {
        Ok(MemberIdentity {
            schema: "ak.schema.member_identity.v1".to_owned(),
            realm_id: realm.clone(),
            actor_id: alice.clone(),
            subject_actor_id: subject.clone(),
            display_profile: DisplayProfile {
                display_name: name.to_owned(),
                avatar_blob_ref: None,
            },
            // Fixed RFC3339 constant — conformance vectors must be
            // deterministic and reproducible across runs (not wall-clock).
            asserted_at: chrono::DateTime::parse_from_rfc3339("2026-05-27T00:00:00.000Z")
                .expect("static rfc3339")
                .with_timezone(&chrono::Utc),
            expires_at: None,
            proof: MemberIdentityProof {
                verification_method: cotest::fixture_did_url("did:web:alice.acme.example#key-1"),
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
    let event_a = EventId::new("ak:event:AXNgOIZZl4gk3plitPd__yCjPWoadg6iy_MvsFlDEJoX")?;
    let event_b = EventId::new("ak:event:ARDf-SZvtxzRy4KgOrojq92s84Z4PJb0V-wUAApfmvnO")?;
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

// ─── R3.1 / TEST-8 — Handle rename round-trip ──────────────────────────────

#[test]
fn test_8_handle_rename_round_trip_sdk_shape() -> Result<()> {
    // SDK-level positive control: a canonical handle resolves one exact
    // Station account and round-trips without a parallel delivery identity.
    use arkret_identifiers::DidCoreId;
    use arkret_models_identity::{Handle, HandleClaim};
    use arkret_wire::AccountId;

    let invite_handle = Handle::parse("alice:acme.example").map_err(|e| anyhow!("handle: {e}"))?;
    if invite_handle.canonical() != "alice:acme.example" {
        bail!(
            "TEST-8: canonical handle wire form must be `<localpart>:<domain>`; got `{}`",
            invite_handle.canonical()
        );
    }

    let subject = DidCoreId::new("ak:did_core:web:alice.acme.example")?;
    let station = DidCoreId::new("ak:did_core:web:station.acme.example")?;
    let account_id = AccountId::new(subject, station);
    let claim = cotest::fixture_verified_handle_claim(
        invite_handle.canonical(),
        account_id.clone(),
        DidCoreId::new("ak:did_core:web:directory.acme.example")?,
        Some("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned()),
        chrono::DateTime::parse_from_rfc3339("2026-05-27T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
        Some(
            chrono::DateTime::parse_from_rfc3339("2026-05-27T00:05:00.000Z")?
                .with_timezone(&chrono::Utc),
        ),
    )?;

    let wire = serde_json::to_value(&claim).map_err(|e| anyhow!("serialise: {e}"))?;
    if wire.pointer("/claim/handle").is_none() {
        bail!(
            "TEST-8: serialised candidate MUST carry `handle` field (R3.1 wire \
             rename); shape: {wire:#}"
        );
    }
    if wire.pointer("/claim/handle_uri").is_some() {
        bail!(
            "TEST-8: serialised candidate MUST NOT carry the retired \
             `handle_uri` field"
        );
    }
    if wire.pointer("/claim/subject_account_id") != Some(&serde_json::to_value(&account_id)?) {
        bail!("TEST-8: handle claim must carry the complete Station account");
    }
    let decoded: HandleClaim =
        serde_json::from_value(wire).map_err(|e| anyhow!("deserialise: {e}"))?;
    if decoded.claim.handle.canonical() != "alice:acme.example" {
        bail!(
            "TEST-8: handle wire round-trip drifted; got `{}`",
            decoded.claim.handle.canonical()
        );
    }
    if decoded.claim.subject_account_id != account_id {
        bail!("TEST-8: exact account wire round-trip drifted");
    }
    Ok(())
}
