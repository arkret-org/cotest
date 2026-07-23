//! `ak.member.identity.update` conformance vectors
//! (VECT-MID-1..7) + VECT-COT-8.
//!
//! Source artefacts:
//!   * `artifacts/schemas/member-identity.schema.json`
//!   * `artifacts/schemas/event-payload.schema.json#/$defs/member_identity_update_payload`
//!   * `artifacts/schemas/account-subscribe-frame.schema.json`
//!
//! R3.2 wire-breaking changes pinned here:
//!   * `MemberIdentity` no longer carries `primary_handle` / `handles[]`; handle lifecycle is
//!     governed solely by `ak.schema.handle_claim.v1`. A payload that re-introduces those fields
//!     MUST schema-reject (VECT-COT-8 — reason `member_identity_handle_field_forbidden`).
//!   * Payload field `identity_state_digest` is renamed to `identity_payload_digest` (carrier cache
//!     key, [`IdentityPayloadCarrier::carrier_sha256`]).
//!   * `expected_state_digest` is the writer-observed effective-set guard computed by
//!     [`member_identity_effective_set_digest`] — it is NOT the `identity_payload_digest` and NOT
//!     the roster `member_display_state_digest`.
//!
//! Each vector pins one wire-level invariant of the
//! `MemberIdentityUpdatePayload` reducer model. The vectors are
//! SDK-pure — they exercise the canonical-bytes helpers
//! ([`IdentityPayloadCarrier::carrier_sha256`],
//! [`arkret_models_identity::effective_identity_events`],
//! [`arkret_models_identity::member_identity_effective_set_digest`],
//! [`MemberIdentity::canonical_payload_sha256`]) plus the
//! `member_identity_*` error-code constants exported from
//! [`arkret_wire::error_codes`]. Live integration is layered on top in
//! `tests/r3_conformance_vectors.rs` under `#[ignore]` gates.

use anyhow::{Result, anyhow, bail};
use arkret_identifiers::{Did, EventId, Hash, RealmId};
use arkret_models_identity::{
    DisplayProfile, EffectiveIdentityEntry, IdentityPayloadCarrier, MemberIdentity,
    MemberIdentityProof, MemberIdentityReplacementRef, MemberIdentitySegment,
    MemberIdentitySignatureAlgorithm, MemberIdentityUpdatePayload, effective_identity_events,
    member_identity_effective_set_digest,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};

pub const VECTOR_ID_MID_UPDATE_INITIAL: &str = "ak.cotest_vector.member_identity.update_initial.v1";
pub const VECTOR_ID_MID_UPDATE_REPLACEMENT: &str =
    "ak.cotest_vector.member_identity.update_replacement.v1";
pub const VECTOR_ID_MID_REPLACEMENT_DIGEST_MISMATCH: &str =
    "ak.cotest_vector.member_identity.replacement_digest_mismatch.v1";
pub const VECTOR_ID_MID_EXPECTED_STATE_DIGEST_MISMATCH: &str =
    "ak.cotest_vector.member_identity.expected_state_digest_mismatch.v1";
pub const VECTOR_ID_MID_PROOF_INVALID: &str = "ak.cotest_vector.member_identity.proof_invalid.v1";
pub const VECTOR_ID_MID_UNKNOWN_SEGMENT_REJECTED: &str =
    "ak.cotest_vector.member_identity.unknown_segment_rejected.v1";
pub const VECTOR_ID_MID_CROSS_SUBJECT_REPLACEMENT_IGNORED: &str =
    "ak.cotest_vector.member_identity.cross_subject_replacement_ignored.v1";
/// VECT-COT-8 — MemberIdentity payload carrying retired handle fields.
pub const VECTOR_ID_MID_HANDLE_FIELD_FORBIDDEN: &str =
    "ak.cotest_vector.member_identity.handle_field_forbidden.v1";

/// Wire reason code a receiver MUST surface for VECT-COT-8.
const REASON_MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN: &str =
    "member_identity_handle_field_forbidden";

pub const ALL_MEMBER_IDENTITY_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_MID_UPDATE_INITIAL,
    VECTOR_ID_MID_UPDATE_REPLACEMENT,
    VECTOR_ID_MID_REPLACEMENT_DIGEST_MISMATCH,
    VECTOR_ID_MID_EXPECTED_STATE_DIGEST_MISMATCH,
    VECTOR_ID_MID_PROOF_INVALID,
    VECTOR_ID_MID_UNKNOWN_SEGMENT_REJECTED,
    VECTOR_ID_MID_CROSS_SUBJECT_REPLACEMENT_IGNORED,
    VECTOR_ID_MID_HANDLE_FIELD_FORBIDDEN,
];

// ── Fixture helpers ─────────────────────────────────────────────────────────

const STABLE_REALM_ID: &str = "ak:realm:01904100-0000-7000-8000-000000000001";
const ALICE_ACTOR_DID: &str = "did:web:alice.acme.example";
const ALICE_SUBJECT_DID: &str = "did:web:alice.principal.example";

fn fake_realm() -> Result<RealmId> {
    RealmId::new(STABLE_REALM_ID).map_err(|e| anyhow!("invalid stable realm id: {e}"))
}

fn fake_actor() -> Result<Did> {
    Did::new(ALICE_ACTOR_DID.to_owned()).map_err(|e| anyhow!("invalid actor did: {e}"))
}

fn fake_subject() -> Result<Did> {
    Did::new(ALICE_SUBJECT_DID.to_owned()).map_err(|e| anyhow!("invalid subject did: {e}"))
}

fn fake_event(suffix: u32) -> Result<EventId> {
    EventId::new(format!("ak:event:01904100-0000-7000-8000-{suffix:012x}"))
        .map_err(|e| anyhow!("invalid event id: {e}"))
}

/// Pinned `asserted_at` so vector digests are stable across runs.
fn pinned_asserted_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 27, 0, 0, 0)
        .single()
        .expect("pinned timestamp is valid")
}

fn zero_hash() -> Result<Hash> {
    Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
        .map_err(|e| anyhow!("invalid pinned hash: {e}"))
}

fn sample_proof(signature: &str) -> Result<MemberIdentityProof> {
    Ok(MemberIdentityProof {
        verification_method: "did:web:alice.acme.example#key-1".to_owned(),
        signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
        payload_digest: zero_hash()?,
        signature: signature.to_owned(),
    })
}

/// Build a R3.2 MemberIdentity. It discloses only `subject_id` +
/// `display_profile`; handle lifecycle has been fully removed from this
/// object (no `primary_handle` / `handles[]`).
fn build_member_identity(display_name: &str, signature: &str) -> Result<MemberIdentity> {
    let mut identity = MemberIdentity::new(
        fake_realm()?,
        fake_actor()?,
        fake_subject()?,
        DisplayProfile {
            display_name: display_name.to_owned(),
            avatar_blob_ref: None,
        },
        pinned_asserted_at(),
        sample_proof(signature)?,
    );
    // Bind the proof.payload_digest to the canonical-bytes digest so
    // the on-the-wire vector mirrors a real producer.
    let canonical_digest = identity
        .canonical_payload_sha256()
        .map_err(|e| anyhow!("MemberIdentity::canonical_payload_sha256: {e}"))?;
    identity.proof.payload_digest = Hash::new(canonical_digest)
        .map_err(|e| anyhow!("canonical_payload_sha256 must be a valid Hash: {e}"))?;
    Ok(identity)
}

// ── VECT-MID-1 ──────────────────────────────────────────────────────────────

/// VECT-MID-1 — first `ak.member.identity.update` event for an actor in a
/// Realm: empty `replaces[]`, plaintext `identity_payload`,
/// `identity_payload_digest` matches the canonical digest of the payload
/// carrier.
pub fn run_member_identity_update_initial_vector() -> Result<()> {
    let identity = build_member_identity("Alice Initial", "AAAA")?;
    let carrier = IdentityPayloadCarrier::MemberIdentity {
        member_identity: identity,
    };
    let carrier_digest = carrier
        .carrier_sha256()
        .map_err(|e| anyhow!("carrier_sha256: {e}"))?;

    let payload_digest_hash =
        Hash::new(carrier_digest.clone()).map_err(|e| anyhow!("carrier digest as Hash: {e}"))?;

    let payload = MemberIdentityUpdatePayload {
        realm_id: fake_realm()?,
        actor_id: fake_actor()?,
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![],
        identity_payload: carrier,
        // R3.2 rename: `identity_state_digest` → `identity_payload_digest`.
        identity_payload_digest: Some(payload_digest_hash.clone()),
        expected_state_digest: None,
    };

    if !payload.replaces.is_empty() {
        bail!("VECT-MID-1: initial update MUST carry empty replaces[]");
    }

    // The serialised payload MUST carry the new field name and NOT the
    // retired one.
    let wire = serde_json::to_value(&payload).map_err(|e| anyhow!("serialise payload: {e}"))?;
    if wire.get("identity_payload_digest").is_none() {
        bail!("VECT-MID-1: payload MUST carry `identity_payload_digest`");
    }
    if wire.get("identity_state_digest").is_some() {
        bail!("VECT-MID-1: payload MUST NOT carry the retired `identity_state_digest` field");
    }

    // Effective set after applying the single event MUST contain the
    // event itself.
    let event_a = fake_event(0xa01)?;
    let effective = effective_identity_events([(&event_a, &payload)])
        .map_err(|e| anyhow!("effective_identity_events: {e}"))?;
    if effective.len() != 1 {
        bail!(
            "VECT-MID-1: initial event MUST be the only effective entry, got {}",
            effective.len()
        );
    }
    if effective[0].0.as_str() != event_a.as_str() {
        bail!("VECT-MID-1: effective entry event_id drifted");
    }

    // `expected_state_digest` projection over the single effective entry
    // MUST be a sha256-prefixed digest. Per R3.2 it differs from the
    // per-event `identity_payload_digest`.
    let entry = EffectiveIdentityEntry {
        event_id: event_a.clone(),
        segment: MemberIdentitySegment::MemberIdentity,
        payload_digest: payload_digest_hash,
    };
    let projected = member_identity_effective_set_digest(
        &fake_realm()?,
        &fake_actor()?,
        MemberIdentitySegment::MemberIdentity,
        &[entry],
    )
    .map_err(|e| anyhow!("member_identity_effective_set_digest: {e}"))?;
    if !projected.starts_with("sha256:") {
        bail!("VECT-MID-1: effective-set digest must be sha256:<hex>; got {projected}");
    }
    if projected == carrier_digest {
        bail!(
            "VECT-MID-1: expected_state_digest MUST differ from identity_payload_digest \
             (distinct R3.2 digests)"
        );
    }
    if !carrier_digest.starts_with("sha256:") {
        bail!("VECT-MID-1: carrier digest must be sha256-prefixed");
    }
    Ok(())
}

// ── VECT-MID-2 ──────────────────────────────────────────────────────────────

/// VECT-MID-2 — second event with `replaces[]` pointing at the first;
/// `payload_digest` matches replaced event's carrier digest; only the
/// second event remains in the effective set.
pub fn run_member_identity_update_replacement_vector() -> Result<()> {
    let identity_v1 = build_member_identity("Alice v1", "AAAA")?;
    let identity_v2 = build_member_identity("Alice v2", "BBBB")?;
    let event_a = fake_event(0xb01)?;
    let event_b = fake_event(0xb02)?;

    let carrier_a = IdentityPayloadCarrier::MemberIdentity {
        member_identity: identity_v1,
    };
    let carrier_b = IdentityPayloadCarrier::MemberIdentity {
        member_identity: identity_v2,
    };

    let digest_a = Hash::new(
        carrier_a
            .carrier_sha256()
            .map_err(|e| anyhow!("carrier_sha256: {e}"))?,
    )
    .map_err(|e| anyhow!("carrier digest as Hash: {e}"))?;

    let payload_a = MemberIdentityUpdatePayload {
        realm_id: fake_realm()?,
        actor_id: fake_actor()?,
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![],
        identity_payload: carrier_a,
        identity_payload_digest: None,
        expected_state_digest: None,
    };
    let payload_b = MemberIdentityUpdatePayload {
        realm_id: fake_realm()?,
        actor_id: fake_actor()?,
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
        .map_err(|e| anyhow!("effective_identity_events: {e}"))?;
    if effective.len() != 1 {
        bail!(
            "VECT-MID-2: only the second event MUST remain after replacement, \
             got {} effective entries",
            effective.len()
        );
    }
    if effective[0].0.as_str() != event_b.as_str() {
        bail!(
            "VECT-MID-2: effective entry MUST be the replacing event; got {}",
            effective[0].0.as_str()
        );
    }
    Ok(())
}

// ── VECT-MID-3 ──────────────────────────────────────────────────────────────

/// VECT-MID-3 — replacement with wrong `payload_digest`; replaced event
/// remains in the effective set (the replacement edge is invalid, NOT an
/// outright rejection of the new event).
pub fn run_member_identity_replacement_digest_mismatch_vector() -> Result<()> {
    let identity_v1 = build_member_identity("Alice v1", "AAAA")?;
    let identity_v2 = build_member_identity("Alice v2", "BBBB")?;
    let event_a = fake_event(0xc01)?;
    let event_b = fake_event(0xc02)?;
    let wrong_digest =
        Hash::new("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .map_err(|e| anyhow!("wrong digest as Hash: {e}"))?;

    let payload_a = MemberIdentityUpdatePayload {
        realm_id: fake_realm()?,
        actor_id: fake_actor()?,
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![],
        identity_payload: IdentityPayloadCarrier::MemberIdentity {
            member_identity: identity_v1,
        },
        identity_payload_digest: None,
        expected_state_digest: None,
    };
    let payload_b = MemberIdentityUpdatePayload {
        realm_id: fake_realm()?,
        actor_id: fake_actor()?,
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![MemberIdentityReplacementRef {
            event_id: event_a.clone(),
            payload_digest: wrong_digest,
        }],
        identity_payload: IdentityPayloadCarrier::MemberIdentity {
            member_identity: identity_v2,
        },
        identity_payload_digest: None,
        expected_state_digest: None,
    };

    let effective = effective_identity_events([(&event_a, &payload_a), (&event_b, &payload_b)])
        .map_err(|e| anyhow!("effective_identity_events: {e}"))?;
    if effective.len() != 2 {
        bail!(
            "VECT-MID-3: a replacement edge with the wrong digest MUST be \
             ignored; both events remain in the effective set. got {} entries",
            effective.len()
        );
    }
    // Wire-level error code that the reducer MUST surface for a fully
    // invalid replacement-event rejection (not the silent-edge case we
    // model here) — assert the constant exists so a rename in the SDK
    // breaks this vector first.
    if arkret_wire::ReasonCode::MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH
        != "member_identity_replacement_digest_mismatch"
    {
        bail!(
            "VECT-MID-3: error-code constant drifted from spec value; got \
             `member_identity_replacement_digest_mismatch`"
        );
    }
    Ok(())
}

// ── VECT-MID-4 ──────────────────────────────────────────────────────────────

/// VECT-MID-4 — concurrent writer with stale `expected_state_digest` is
/// rejected with `member_identity_state_mismatch`. R3.2 pins the new
/// `expected_state_digest` formula: the writer-observed effective-set
/// digest from [`member_identity_effective_set_digest`].
pub fn run_member_identity_expected_state_digest_mismatch_vector() -> Result<()> {
    let identity = build_member_identity("Alice Concurrent", "AAAA")?;
    let carrier = IdentityPayloadCarrier::MemberIdentity {
        member_identity: identity,
    };
    let carrier_digest = Hash::new(
        carrier
            .carrier_sha256()
            .map_err(|e| anyhow!("carrier_sha256: {e}"))?,
    )
    .map_err(|e| anyhow!("carrier digest as Hash: {e}"))?;

    // The "fresh" effective-set digest a server would have computed over a
    // single prior event.
    let prior_event = fake_event(0xd11)?;
    let fresh_entry = EffectiveIdentityEntry {
        event_id: prior_event,
        segment: MemberIdentitySegment::MemberIdentity,
        payload_digest: carrier_digest,
    };
    let fresh_digest = member_identity_effective_set_digest(
        &fake_realm()?,
        &fake_actor()?,
        MemberIdentitySegment::MemberIdentity,
        &[fresh_entry],
    )
    .map_err(|e| anyhow!("member_identity_effective_set_digest: {e}"))?;

    // A stale writer carries an effective-set digest that no longer matches
    // the server-observed one. Use a deliberately-wrong pinned digest.
    let stale_digest =
        Hash::new("sha256:dead000000000000000000000000000000000000000000000000000000000000")
            .map_err(|e| anyhow!("stale digest as Hash: {e}"))?;
    if stale_digest.as_str() == fresh_digest {
        bail!("VECT-MID-4: vector setup error — stale digest equals fresh digest");
    }

    let payload = MemberIdentityUpdatePayload {
        realm_id: fake_realm()?,
        actor_id: fake_actor()?,
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![],
        identity_payload: carrier,
        identity_payload_digest: None,
        expected_state_digest: Some(stale_digest.clone()),
    };
    if payload.expected_state_digest.as_ref() != Some(&stale_digest) {
        bail!("VECT-MID-4: expected_state_digest field did not round-trip");
    }
    if arkret_wire::ReasonCode::MEMBER_IDENTITY_STATE_MISMATCH != "member_identity_state_mismatch" {
        bail!(
            "VECT-MID-4: error-code constant drifted; got \
             `member_identity_state_mismatch`"
        );
    }
    // When expected_state_digest is None, this is treated as "no optimistic
    // concurrency guard" — the vector pins that the field is `Option<Hash>`.
    let payload_no_guard = MemberIdentityUpdatePayload {
        expected_state_digest: None,
        ..payload
    };
    if payload_no_guard.expected_state_digest.is_some() {
        bail!("VECT-MID-4: expected_state_digest MUST be Optional");
    }
    Ok(())
}

// ── VECT-MID-5 ──────────────────────────────────────────────────────────────

/// VECT-MID-5 — MemberIdentity object with wrong `proof.payload_digest`
/// or bad signature; verifier MUST NOT promote to verified display
/// identity.
pub fn run_member_identity_proof_invalid_vector() -> Result<()> {
    // Build a MemberIdentity with a deliberately wrong proof.payload_digest.
    let mut identity = build_member_identity("Alice Tampered", "AAAA")?;
    let canonical_digest = identity
        .canonical_payload_sha256()
        .map_err(|e| anyhow!("canonical_payload_sha256: {e}"))?;
    let tampered_digest =
        Hash::new("sha256:beef000000000000000000000000000000000000000000000000000000000000")
            .map_err(|e| anyhow!("tampered digest as Hash: {e}"))?;
    identity.proof.payload_digest = tampered_digest;

    // The canonical-bytes helper is stable: a second call returns the
    // same digest regardless of the proof carrier's mutated value.
    let recomputed = identity
        .canonical_payload_sha256()
        .map_err(|e| anyhow!("canonical_payload_sha256: {e}"))?;
    if recomputed != canonical_digest {
        bail!(
            "VECT-MID-5: canonical_payload_sha256 MUST be invariant under \
             proof field mutations (proof is excluded from the canonical \
             bytes per the spec)"
        );
    }
    if identity.proof.payload_digest.as_str() == canonical_digest {
        bail!(
            "VECT-MID-5: tampered digest unexpectedly equal to the canonical \
             digest — vector setup error"
        );
    }
    // Wire-level error-code constant the verifier MUST surface.
    if arkret_wire::ReasonCode::MEMBER_IDENTITY_PROOF_INVALID != "member_identity_proof_invalid" {
        bail!(
            "VECT-MID-5: error-code constant drifted; got \
             `member_identity_proof_invalid`"
        );
    }
    Ok(())
}

// ── VECT-MID-6 ──────────────────────────────────────────────────────────────

/// VECT-MID-6 — payload with `segment="display_profile"` (not in the v1
/// enum) is rejected at deserialisation.
pub fn run_member_identity_unknown_segment_rejected_vector() -> Result<()> {
    let identity = build_member_identity("Alice", "AAAA")?;
    let carrier = IdentityPayloadCarrier::MemberIdentity {
        member_identity: identity,
    };
    let payload = MemberIdentityUpdatePayload {
        realm_id: fake_realm()?,
        actor_id: fake_actor()?,
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![],
        identity_payload: carrier,
        identity_payload_digest: None,
        expected_state_digest: None,
    };
    let mut value =
        serde_json::to_value(&payload).map_err(|e| anyhow!("serialise payload: {e}"))?;
    value["segment"] = json!("display_profile");
    let parsed: std::result::Result<MemberIdentityUpdatePayload, _> = serde_json::from_value(value);
    match parsed {
        Err(e) => {
            let msg = format!("{e}");
            // serde reports `unknown variant` for non-enumerated values.
            if !msg.contains("variant") && !msg.contains("display_profile") {
                bail!(
                    "VECT-MID-6: deserialisation rejected unknown segment with \
                     an unexpected error message `{msg}` — expected an enum \
                     unknown-variant rejection"
                );
            }
        }
        Ok(_) => bail!(
            "VECT-MID-6: a payload with segment=`display_profile` was accepted; \
             only the v1 `member_identity` segment is allowed"
        ),
    }
    if arkret_wire::ReasonCode::MEMBER_IDENTITY_UNKNOWN_SEGMENT != "member_identity_unknown_segment"
    {
        bail!(
            "VECT-MID-6: error-code constant drifted; got \
             `member_identity_unknown_segment`"
        );
    }
    Ok(())
}

// ── VECT-MID-7 ──────────────────────────────────────────────────────────────

/// VECT-MID-7 — replacement event referencing an event from a different
/// `(realm_id, actor_id, segment)`; the edge is treated as a no-op
/// because the candidate set is keyed by `(realm_id, actor_id, segment)`.
pub fn run_member_identity_cross_subject_replacement_ignored_vector() -> Result<()> {
    // Build a payload for actor B in realm R, with a `replaces[]` pointing
    // at actor A's event — the edge MUST not collapse actor B's row because
    // actor A's event isn't in the candidate set passed to the helper.
    let identity_b = build_member_identity("Bob v1", "BBBB")?;
    let event_b = fake_event(0xe01)?;
    let cross_subject_event = fake_event(0xe02)?;

    let bogus_digest =
        Hash::new("sha256:badf000000000000000000000000000000000000000000000000000000000000")
            .map_err(|e| anyhow!("bogus digest as Hash: {e}"))?;
    let payload_b = MemberIdentityUpdatePayload {
        realm_id: fake_realm()?,
        actor_id: Did::new("did:web:bob.acme.example".to_owned())?,
        segment: MemberIdentitySegment::MemberIdentity,
        replaces: vec![MemberIdentityReplacementRef {
            event_id: cross_subject_event,
            payload_digest: bogus_digest,
        }],
        identity_payload: IdentityPayloadCarrier::MemberIdentity {
            member_identity: identity_b,
        },
        identity_payload_digest: None,
        expected_state_digest: None,
    };
    let effective = effective_identity_events([(&event_b, &payload_b)])
        .map_err(|e| anyhow!("effective_identity_events: {e}"))?;
    if effective.len() != 1 {
        bail!(
            "VECT-MID-7: cross-subject replacement edge MUST be a no-op; \
             actor B's event must remain in the effective set. got {} entries",
            effective.len()
        );
    }
    if effective[0].0.as_str() != event_b.as_str() {
        bail!("VECT-MID-7: surviving effective entry MUST be actor B's event");
    }
    Ok(())
}

// ── VECT-COT-8 ──────────────────────────────────────────────────────────────

/// VECT-COT-8 — `ak.cotest_vector.member_identity.handle_field_forbidden.v1`.
///
/// R3.2 removed `primary_handle` / `handles[]` from `MemberIdentity`.
/// A payload that re-introduces either field MUST schema-reject. We pin
/// the rejection at two layers:
///   1. The typed SDK struct (`#[serde(deny_unknown_fields)]`).
///   2. The artifact JSON Schema (`additionalProperties: false`), exercised by the
///      schema-validation suite over `member-identity.schema.json`.
///
/// The wire reason code is `member_identity_handle_field_forbidden`.
pub fn run_member_identity_handle_field_forbidden_vector() -> Result<()> {
    // Start from a valid R3.2 MemberIdentity, then inject the retired
    // fields back onto the wire object.
    let identity = build_member_identity("Alice Handle Reject", "AAAA")?;
    let mut wire =
        serde_json::to_value(&identity).map_err(|e| anyhow!("serialise identity: {e}"))?;
    let obj = wire
        .as_object_mut()
        .ok_or_else(|| anyhow!("VECT-COT-8: MemberIdentity must serialise as an object"))?;

    // Sanity: a clean R3.2 object MUST NOT already carry handle fields.
    if obj.contains_key("primary_handle") || obj.contains_key("handles") {
        bail!("VECT-COT-8: clean MemberIdentity unexpectedly carries handle fields");
    }

    // Each retired field, injected on its own, MUST be rejected by the
    // typed struct's `deny_unknown_fields`.
    for forbidden in ["primary_handle", "handles"] {
        let mut tampered = obj.clone();
        let injected = match forbidden {
            "primary_handle" => json!("alice:acme.example"),
            _ => json!([{ "handle": "alice:acme.example", "verified": true }]),
        };
        tampered.insert(forbidden.to_owned(), injected);
        let parsed: std::result::Result<MemberIdentity, _> =
            serde_json::from_value(Value::Object(tampered));
        match parsed {
            Ok(_) => bail!(
                "VECT-COT-8: a MemberIdentity carrying retired `{forbidden}` was \
                 accepted; reason `{REASON_MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN}` MUST fire"
            ),
            Err(e) => {
                let msg = format!("{e}");
                if !msg.contains("unknown field") && !msg.contains(forbidden) {
                    bail!(
                        "VECT-COT-8: `{forbidden}` rejection produced an unexpected \
                         error `{msg}` — expected an unknown-field rejection"
                    );
                }
            }
        }
    }

    // Both fields together MUST also reject.
    let mut both = obj.clone();
    both.insert("primary_handle".to_owned(), json!("alice:acme.example"));
    both.insert(
        "handles".to_owned(),
        json!([{ "handle": "alice:acme.example", "verified": true }]),
    );
    if serde_json::from_value::<MemberIdentity>(Value::Object(both)).is_ok() {
        bail!("VECT-COT-8: MemberIdentity carrying both retired handle fields was accepted");
    }
    Ok(())
}

// ── Suite entry-point ──────────────────────────────────────────────────────

/// Run the eight `ak.vector.member_identity.*` vectors (VECT-MID-1..7 +
/// VECT-COT-8).
pub fn run_member_identity_vector_suite() -> Result<()> {
    if ALL_MEMBER_IDENTITY_VECTOR_IDS.len() != 8 {
        bail!(
            "expected 8 member-identity vector ids, got {}",
            ALL_MEMBER_IDENTITY_VECTOR_IDS.len()
        );
    }
    run_member_identity_update_initial_vector()?;
    run_member_identity_update_replacement_vector()?;
    run_member_identity_replacement_digest_mismatch_vector()?;
    run_member_identity_expected_state_digest_mismatch_vector()?;
    run_member_identity_proof_invalid_vector()?;
    run_member_identity_unknown_segment_rejected_vector()?;
    run_member_identity_cross_subject_replacement_ignored_vector()?;
    run_member_identity_handle_field_forbidden_vector()?;
    Ok(())
}

/// Helper for live-integration tests — returns a Value MemberIdentity
/// fixture suitable for serialising into a soland `ak.member.identity.update`
/// event payload.
pub fn sample_member_identity_value(display_name: &str) -> Result<Value> {
    let identity = build_member_identity(display_name, "AAAA")?;
    serde_json::to_value(&identity).map_err(|e| anyhow!("serialise MemberIdentity: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_identity_vector_suite_runs_clean() {
        run_member_identity_vector_suite().unwrap();
    }
}
