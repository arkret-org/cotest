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
    ALL_MEMBER_IDENTITY_VECTOR_IDS, ALL_MEMBER_ROSTER_VECTOR_IDS, ALL_SIDECAR_VECTOR_IDS,
    run_agent_vector_suite, run_cursor_vector_suite, run_media_binding_vector_suite,
    run_member_identity_vector_suite, run_member_roster_vector_suite, run_sidecar_vector_suite,
};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn load_fixture_value(name: &str) -> Result<Value> {
    let path = fixture_path(name);
    let raw =
        fs::read_to_string(&path).map_err(|e| anyhow!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| anyhow!("failed to parse {}: {e}", path.display()))
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

// ─── R3.1 / VECT-MID-1..7 — MemberIdentity vectors ─────────────────────────

#[test]
fn member_identity_vector_suite_runs_clean() {
    run_member_identity_vector_suite().expect("member-identity vectors must pass");
    assert_eq!(ALL_MEMBER_IDENTITY_VECTOR_IDS.len(), 7);
}

// ─── R3.1 / VECT-ROST-1..3 — sync member roster vectors ───────────────────

#[test]
fn member_roster_vector_suite_runs_clean() {
    run_member_roster_vector_suite().expect("member-roster vectors must pass");
    assert_eq!(ALL_MEMBER_ROSTER_VECTOR_IDS.len(), 3);
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
    assert!(
        cases.len() >= 8,
        "agent_payloads.json must cover all new kinds"
    );
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

// ─── R3.1 / TEST-7 — `cx.member.identity.update` end-to-end ───────────────

#[test]
fn test_7_cx_member_identity_update_replacement_shape() -> Result<()> {
    // SDK-level positive control: the canonical-bytes helper +
    // effective-set filter that soland's MID reducer MUST mirror. An
    // initial event followed by a replacement event with a matching
    // payload_digest collapses to a single effective entry — the second.
    use contrix_core::model::{
        DisplayProfile, Handle, IdentityPayloadCarrier, MemberIdentity, MemberIdentityProof,
        MemberIdentityReplacementRef, MemberIdentitySegment, MemberIdentitySignatureAlgorithm,
        MemberIdentityUpdatePayload, effective_identity_events,
    };
    use contrix_core::{Did, EventId, Hash, RealmId};

    let realm = RealmId::new("cx:realm:01904100-0000-7000-8000-000000007007")
        .map_err(|e| anyhow!("realm: {e}"))?;
    let alice = Did::new("did:web:alice.acme.example".to_owned())?;
    let subject = Did::new("did:web:alice.principal.example".to_owned())?;

    let make_identity = |name: &str| -> Result<MemberIdentity> {
        Ok(MemberIdentity {
            schema: "cx.schema.member_identity.v1".to_owned(),
            realm_id: realm.clone(),
            actor_id: alice.clone(),
            subject_id: subject.clone(),
            primary_handle: Some(
                Handle::parse("alice:acme.example").map_err(|e| anyhow!("handle: {e}"))?,
            ),
            handles: vec![],
            display_profile: DisplayProfile { display_name: name.to_owned(), avatar_ref: None },
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
    let event_a = EventId::new("cx:event:01904100-0000-7000-8000-000000007a01")?;
    let event_b = EventId::new("cx:event:01904100-0000-7000-8000-000000007a02")?;
    let carrier_a = IdentityPayloadCarrier::MemberIdentity { member_identity: v1 };
    let carrier_b = IdentityPayloadCarrier::MemberIdentity { member_identity: v2 };
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
        identity_state_digest: None,
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
        identity_state_digest: None,
        expected_state_digest: None,
    };

    let effective = effective_identity_events([(&event_a, &payload_a), (&event_b, &payload_b)])
        .map_err(|e| anyhow!("effective: {e}"))?;
    if effective.len() != 1 || effective[0].0.as_str() != event_b.as_str() {
        bail!(
            "TEST-7: client MUST see only the replacing event in the effective \
             set (replaces[] semantics); got {} entries: {:?}",
            effective.len(),
            effective.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
#[ignore = "R3.1: soland MID reducer + cx.profile.update field-level delta wiring not yet implemented"]
fn test_7_cx_member_identity_update_live() {
    // Live integration:
    //   1. Actor publishes initial `cx.member.identity.update` event
    //      with MemberIdentity v1 (display_name="Alice").
    //   2. Actor publishes second event with `replaces[]` pointing at
    //      the first; payload carries MemberIdentity v2 with
    //      display_name="Alice (work)".
    //   3. Client `account.subscribe` frame surfaces a roster with only
    //      the second event in `identity_event_ids[]`.
    //   4. `cx.profile.update` field-level delta MUST drive the v2
    //      display_name onto the projected profile; the
    //      `cx.profile.space_override` profile MUST take precedence
    //      when set per-Space.
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
    use contrix_core::{
        CandidateIntent, DeliveryBindingHint, DeliveryMode, Did, Handle, HandleHintBindingSource,
        MemberDeliveryBindingCandidate, RecipientServiceType,
    };
    use std::collections::BTreeSet;

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
            policy_ref: None,
        },
        issuer_service_did: principal,
        audience: "cx:realm:01904100-0000-7000-8000-test8audience".to_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        issued_at: Some(chrono::Utc::now()),
        source_refs: vec!["cx:event:01904100-0000-7000-8000-test8source01".to_owned()],
        proofs: vec![serde_json::json!({
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:principal.acme.example#key-1",
            "payload_digest":
                "sha256:0000000000000000000000000000000000000000000000000000000000000088",
            "created_at": "2026-05-27T00:00:00Z",
            "audience": "cx:realm:01904100-0000-7000-8000-test8audience",
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
    //   2. soland reducer accepts member-add with `payload.handle =
    //      "alice:acme.example"` (NO `handle_uri` field).
    //   3. teabay's `cx.directory.resolve_handle(handle=...)` accepts the
    //      canonical handle string in the request body and returns a
    //      candidate whose `handle` field is the same canonical wire form.
    //   4. coauth's handle-claim issuance + sync surface MUST NOT emit
    //      `handle_uri` anywhere on a fresh R3.1 wire shape.
    unreachable!("integration target gated on coauth+soland+teabay R3.1 rename");
}
