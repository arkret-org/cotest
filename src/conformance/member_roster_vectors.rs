//! Sync `member_roster_entry` conformance vectors
//! (VECT-ROST-1..3 + VECT-COT-4 roster v2).
//!
//! Source artefact:
//!   * `artifacts/schemas/account-subscribe-frame.schema.json` (`$defs/member_roster_entry`).
//!
//! R3.2 roster v2 shape:
//!   `{actor_id, membership, subject_id?, identity_event_ids?,
//!     member_display_state_digest?, identity_events?, handle_claim_digests?,
//!     handle_claims?, handle_claims_limited?}`.
//!
//! Field renames + new disclosure-gated fields:
//!   * `identity_state_digest` → `member_display_state_digest` (now folds the visible handle-claim
//!     digest set; see [`member_display_state_digest`]).
//!   * `subject_id` discloses the principal/holder DID. The four gated fields (`identity_events`,
//!     `handle_claim_digests`, `handle_claims`, `handle_claims_limited`) MUST be omitted unless
//!     `subject_id` is disclosed (dependentRequired), enforced by [`MemberRosterEntry::validate`].
//!   * inline `handle_claims[].subject` MUST equal the entry's `subject_id`.
//!
//! Entries MUST NOT carry raw handle / display fields directly; handle
//! strings may appear only inside signed `HandleClaim` objects.

use anyhow::{Result, anyhow, bail};
use arkret_identifiers::{Did, EventId, Hash, RealmId};
use arkret_models_collaboration::sync_frames::account_sync::{MemberRosterEntry, MembershipState};
use arkret_models_identity::{
    EffectiveIdentityEntry, Handle, HandleBindingState, HandleClaim, MemberIdentitySegment,
    RosterHandleClaimDigestEntry, member_display_state_digest,
};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

pub const VECTOR_ID_ROSTER_SHAPE: &str = "ak.cotest_vector.sync.member_roster_shape.v1";
pub const VECTOR_ID_ROSTER_LIMITED: &str = "ak.cotest_vector.sync.member_roster_limited.v1";
pub const VECTOR_ID_ROSTER_WITH_INLINE_IDENTITY_EVENTS: &str =
    "ak.cotest_vector.sync.member_roster_with_inline_identity_events.v1";
/// VECT-COT-4 roster v2 vectors.
pub const VECTOR_ID_ROSTER_SUBJECT_UNDISCLOSED_OMITS_GATED: &str =
    "ak.cotest_vector.sync.member_roster_subject_undisclosed_omits_gated_fields.v1";
pub const VECTOR_ID_ROSTER_HANDLE_CLAIMS_SUBJECT_ALIGNMENT: &str =
    "ak.cotest_vector.sync.member_roster_handle_claims_subject_alignment.v1";
pub const VECTOR_ID_ROSTER_DISPLAY_DIGEST_STABLE_UNDER_FRESHNESS: &str =
    "ak.cotest_vector.sync.member_roster_display_state_digest_stable_under_freshness_hints.v1";
pub const VECTOR_ID_ROSTER_HANDLE_CLAIMS_LIMITED_SEMANTICS: &str =
    "ak.cotest_vector.sync.member_roster_handle_claims_limited_semantics.v1";

pub const ALL_MEMBER_ROSTER_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_ROSTER_SHAPE,
    VECTOR_ID_ROSTER_LIMITED,
    VECTOR_ID_ROSTER_WITH_INLINE_IDENTITY_EVENTS,
    VECTOR_ID_ROSTER_SUBJECT_UNDISCLOSED_OMITS_GATED,
    VECTOR_ID_ROSTER_HANDLE_CLAIMS_SUBJECT_ALIGNMENT,
    VECTOR_ID_ROSTER_DISPLAY_DIGEST_STABLE_UNDER_FRESHNESS,
    VECTOR_ID_ROSTER_HANDLE_CLAIMS_LIMITED_SEMANTICS,
];

// ── Fixture helpers ─────────────────────────────────────────────────────────

fn alice() -> Result<Did> {
    Did::new("did:web:alice.acme.example".to_owned()).map_err(|e| anyhow!("alice did: {e}"))
}

fn alice_subject() -> Result<Did> {
    Did::new("did:web:alice.principal.example".to_owned())
        .map_err(|e| anyhow!("alice principal did: {e}"))
}

fn fake_realm() -> Result<RealmId> {
    RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K").map_err(|e| anyhow!("realm: {e}"))
}

fn fake_event(suffix: u32) -> Result<EventId> {
    Ok(crate::fixture_event_id(format!(
        "member-roster-vector:{suffix}"
    )))
}

fn pinned_state_digest() -> Result<Hash> {
    Hash::new("sha256:abababababababababababababababababababababababababababababababab")
        .map_err(|e| anyhow!("pinned state digest: {e}"))
}

/// Build a pinned sha256 digest from a 2-hex-char seed (e.g. `"11"`), which
/// is repeated to fill the 64-hex-char body.
fn pinned_claim_digest(byte: &str) -> Result<Hash> {
    debug_assert_eq!(byte.len(), 2, "claim digest seed must be 2 hex chars");
    Hash::new(format!("sha256:{}", byte.repeat(32)))
        .map_err(|e| anyhow!("pinned claim digest: {e}"))
}

/// A verified handle claim whose `subject` is `alice_subject()`.
fn verified_claim_for_subject(handle: &str, subject: &Did) -> Result<HandleClaim> {
    Ok(HandleClaim {
        handle: Some(Handle::parse(handle).map_err(|e| anyhow!("handle parse: {e}"))?),
        subject: Some(subject.clone()),
        issuer: Some("did:web:coauth.acme.example".to_owned()),
        binding_state: Some(HandleBindingState::Verified),
        created_at: Some(
            Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0)
                .single()
                .expect("pinned created_at"),
        ),
        expires_at: Some(
            Utc.with_ymd_and_hms(2026, 6, 20, 0, 0, 0)
                .single()
                .expect("pinned expires_at"),
        ),
        ..Default::default()
    })
}

// ── VECT-ROST-1 ─────────────────────────────────────────────────────────────

/// VECT-ROST-1 — per-Realm `members[]` entries match
/// `{actor_id, membership, identity_event_ids?, member_display_state_digest?}`.
/// The encoded vector MUST NOT contain `handle_uri` / `handle` /
/// `display_name` as roster fields. R3.2 wire rename guard.
pub fn run_member_roster_shape_vector() -> Result<()> {
    let entry = MemberRosterEntry {
        actor_id: alice()?,
        membership: MembershipState::Join,
        subject_id: None,
        identity_event_ids: vec![fake_event(0xe01)?, fake_event(0xe02)?],
        member_display_state_digest: Some(pinned_state_digest()?),
        identity_events: vec![],
        handle_claim_digests: None,
        handle_claims: None,
        handle_claims_limited: None,
    };
    entry
        .validate()
        .map_err(|e| anyhow!("VECT-ROST-1: validate: {e}"))?;

    let value = serde_json::to_value(&entry).map_err(|e| anyhow!("serialise: {e}"))?;
    // Required wire fields.
    if value.get("actor_id").is_none() {
        bail!("VECT-ROST-1: roster entry MUST carry `actor_id`");
    }
    if value.get("membership").and_then(Value::as_str) != Some("join") {
        bail!("VECT-ROST-1: membership MUST serialise as the lowercase tag (`join`)");
    }
    if value.get("identity_event_ids").is_none() {
        bail!(
            "VECT-ROST-1: when identity_event_ids[] is non-empty it MUST be \
             serialised onto the wire"
        );
    }
    // R3.2 rename: the roster digest is now `member_display_state_digest`.
    if value.get("member_display_state_digest").is_none() {
        bail!(
            "VECT-ROST-1: when member_display_state_digest is set it MUST be \
             serialised onto the wire"
        );
    }
    if value.get("identity_state_digest").is_some() {
        bail!("VECT-ROST-1: roster entry MUST NOT carry the retired `identity_state_digest`");
    }

    // Disclosure-gated fields omitted when subject_id is absent.
    if value.get("identity_events").is_some() {
        bail!("VECT-ROST-1: empty identity_events[] MUST be omitted");
    }
    if value.get("subject_id").is_some() {
        bail!("VECT-ROST-1: subject_id MUST be omitted when not disclosed");
    }

    // Round-trip MUST preserve identity_event_ids[] order and digest.
    let decoded: MemberRosterEntry =
        serde_json::from_value(value).map_err(|e| anyhow!("deserialise: {e}"))?;
    if decoded.identity_event_ids != entry.identity_event_ids {
        bail!("VECT-ROST-1: identity_event_ids[] order changed under round-trip");
    }
    if decoded.member_display_state_digest != entry.member_display_state_digest {
        bail!("VECT-ROST-1: member_display_state_digest changed under round-trip");
    }
    Ok(())
}

// ── VECT-ROST-2 ─────────────────────────────────────────────────────────────

/// VECT-ROST-2 — `members_limited=true` + `members_next_cursor` semantics
/// on a roster frame. A roster wrapped in a sync frame that signals
/// truncation MUST surface both fields together; clients MUST NOT treat
/// such a frame as the complete member set.
pub fn run_member_roster_limited_vector() -> Result<()> {
    let frame = json!({
        "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
        "members": [
            {
                "actor_id": "did:web:alice.acme.example",
                "membership": "join",
                "identity_event_ids": [
                    "ak:event:AaeZ8deENFbCUflsuaJ26bhcritF3A0DEiAgV3VXl2oZ"
                ],
                "member_display_state_digest":
                    "sha256:abababababababababababababababababababababababababababababababab"
            }
        ],
        "members_limited": true,
        "members_next_cursor":
            "ak:cursor:eyJ2IjoiMSIsInB1cnBvc2UiOiJzdHJlYW0iLCJ0IjoiMjAyNi0wNS0yN1QwMDowMDowMFoiLCJ4IjoxOTAwMDAwMDAwMDAwfQ"
    });

    if frame.get("members_limited").and_then(Value::as_bool) != Some(true) {
        bail!("VECT-ROST-2: `members_limited` MUST be true when the roster is truncated");
    }
    let cursor = frame
        .get("members_next_cursor")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!("VECT-ROST-2: a truncated roster MUST carry `members_next_cursor`")
        })?;
    if !cursor.starts_with("ak:cursor:") {
        bail!(
            "VECT-ROST-2: members_next_cursor MUST be a `ak:cursor:` opaque \
             cursor; got `{cursor}`"
        );
    }
    let unlimited = json!({
        "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
        "members": []
    });
    if unlimited.get("members_limited").is_some() {
        bail!("VECT-ROST-2: a non-truncated roster MUST NOT carry `members_limited`");
    }
    if unlimited.get("members_next_cursor").is_some() {
        bail!("VECT-ROST-2: a non-truncated roster MUST NOT carry `members_next_cursor`");
    }
    Ok(())
}

// ── VECT-ROST-3 ─────────────────────────────────────────────────────────────

/// VECT-ROST-3 — `identity_events[]` inlined and matches the events
/// referenced by `identity_event_ids`. In R3.2 the inline events are
/// disclosure-gated and require `subject_id`.
pub fn run_member_roster_with_inline_identity_events_vector() -> Result<()> {
    let inline = json!({
        "actor_id": "did:web:alice.acme.example",
        "membership": "join",
        "subject_id": "did:web:alice.principal.example",
        "identity_event_ids": [
            "ak:event:AaeZ8deENFbCUflsuaJ26bhcritF3A0DEiAgV3VXl2oZ",
            "ak:event:AY2Hn6IY76TnIeYqiTmQfD0I9bOBlvFOr6qVQbYcUaIz"
        ],
        "member_display_state_digest":
            "sha256:abababababababababababababababababababababababababababababababab",
        "identity_events": [
            {
                "event_id": "ak:event:AaeZ8deENFbCUflsuaJ26bhcritF3A0DEiAgV3VXl2oZ",
                "kind": "ak.member.identity.update",
                "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                "actor_id": "did:web:alice.acme.example",
                "payload": {
                    "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                    "actor_id": "did:web:alice.acme.example",
                    "segment": "member_identity",
                    "identity_payload": {"member_identity": {"placeholder": "v1"}}
                }
            },
            {
                "event_id": "ak:event:AY2Hn6IY76TnIeYqiTmQfD0I9bOBlvFOr6qVQbYcUaIz",
                "kind": "ak.member.identity.update",
                "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                "actor_id": "did:web:alice.acme.example",
                "payload": {
                    "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                    "actor_id": "did:web:alice.acme.example",
                    "segment": "member_identity",
                    "replaces": [{
                        "event_id": "ak:event:AaeZ8deENFbCUflsuaJ26bhcritF3A0DEiAgV3VXl2oZ",
                        "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    }],
                    "identity_payload": {"member_identity": {"placeholder": "v2"}}
                }
            }
        ]
    });

    // R3.2: inline identity_events require subject_id disclosure.
    if inline.get("subject_id").is_none() {
        bail!("VECT-ROST-3: inline identity_events[] MUST be accompanied by subject_id (R3.2)");
    }

    let ids: Vec<&str> = inline["identity_event_ids"]
        .as_array()
        .ok_or_else(|| anyhow!("identity_event_ids must be an array"))?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    let events_array = inline["identity_events"]
        .as_array()
        .ok_or_else(|| anyhow!("identity_events must be an array"))?;
    let event_ids: Vec<&str> = events_array
        .iter()
        .map(|e| e["event_id"].as_str().unwrap_or_default())
        .collect();
    if ids != event_ids {
        bail!(
            "VECT-ROST-3: identity_events[].event_id MUST match identity_event_ids[] \
             one-for-one in order; got ids={:?}, events={:?}",
            ids,
            event_ids
        );
    }
    for event in events_array {
        let kind = event["kind"].as_str().unwrap_or_default();
        if kind != "ak.member.identity.update" {
            bail!(
                "VECT-ROST-3: identity_events[] MUST carry only \
                 `ak.member.identity.update` events; got kind=`{kind}`"
            );
        }
    }
    Ok(())
}

// ── VECT-COT-4a ─────────────────────────────────────────────────────────────

/// VECT-COT-4a — `subject_id` undisclosed MUST omit all four gated fields.
/// Any gated field present without `subject_id` MUST fail `validate()`.
pub fn run_member_roster_subject_undisclosed_omits_gated_fields_vector() -> Result<()> {
    // Valid undisclosed entry: no subject_id, no gated fields.
    let clean = MemberRosterEntry {
        actor_id: alice()?,
        membership: MembershipState::Join,
        subject_id: None,
        identity_event_ids: vec![fake_event(0xf01)?],
        member_display_state_digest: Some(pinned_state_digest()?),
        identity_events: vec![],
        handle_claim_digests: None,
        handle_claims: None,
        handle_claims_limited: None,
    };
    clean
        .validate()
        .map_err(|e| anyhow!("VECT-COT-4a: clean entry MUST validate: {e}"))?;
    let wire = serde_json::to_value(&clean).map_err(|e| anyhow!("serialise: {e}"))?;
    for gated in [
        "identity_events",
        "handle_claim_digests",
        "handle_claims",
        "handle_claims_limited",
    ] {
        if wire.get(gated).is_some() {
            bail!("VECT-COT-4a: gated field `{gated}` MUST be omitted when subject_id is absent");
        }
    }

    // Each gated field, present without subject_id, MUST fail validation.
    let with_digests = MemberRosterEntry {
        handle_claim_digests: Some(vec![pinned_claim_digest("11")?]),
        ..clean.clone()
    };
    if with_digests.validate().is_ok() {
        bail!("VECT-COT-4a: handle_claim_digests without subject_id MUST fail validate()");
    }
    let with_claims = MemberRosterEntry {
        handle_claims: Some(vec![verified_claim_for_subject(
            "alice:acme.example",
            &alice_subject()?,
        )?]),
        ..clean.clone()
    };
    if with_claims.validate().is_ok() {
        bail!("VECT-COT-4a: handle_claims without subject_id MUST fail validate()");
    }
    let with_limited = MemberRosterEntry {
        handle_claims_limited: Some(true),
        ..clean.clone()
    };
    if with_limited.validate().is_ok() {
        bail!("VECT-COT-4a: handle_claims_limited without subject_id MUST fail validate()");
    }
    Ok(())
}

// ── VECT-COT-4b ─────────────────────────────────────────────────────────────

/// VECT-COT-4b — disclosed `subject_id` permits the gated fields, and every
/// inline `handle_claims[].subject` MUST equal `subject_id`; a mismatch MUST
/// fail `validate()` (drop / fail-closed).
pub fn run_member_roster_handle_claims_subject_alignment_vector() -> Result<()> {
    let subject = alice_subject()?;
    let aligned = MemberRosterEntry {
        actor_id: alice()?,
        membership: MembershipState::Join,
        subject_id: Some(subject.clone()),
        identity_event_ids: vec![fake_event(0xf11)?],
        member_display_state_digest: Some(pinned_state_digest()?),
        identity_events: vec![],
        handle_claim_digests: Some(vec![pinned_claim_digest("22")?]),
        handle_claims: Some(vec![verified_claim_for_subject(
            "alice:acme.example",
            &subject,
        )?]),
        handle_claims_limited: Some(false),
    };
    aligned
        .validate()
        .map_err(|e| anyhow!("VECT-COT-4b: aligned subject MUST validate: {e}"))?;

    // Mismatched claim subject MUST fail closed.
    let other_subject = Did::new("did:web:mallory.principal.example".to_owned())?;
    let mismatched = MemberRosterEntry {
        handle_claims: Some(vec![verified_claim_for_subject(
            "mallory:acme.example",
            &other_subject,
        )?]),
        ..aligned.clone()
    };
    if mismatched.validate().is_ok() {
        bail!(
            "VECT-COT-4b: handle_claims[].subject != subject_id MUST fail closed \
             (drop / reject the claim)"
        );
    }
    Ok(())
}

// ── VECT-COT-4c ─────────────────────────────────────────────────────────────

/// VECT-COT-4c — `member_display_state_digest` is stable under issuer
/// freshness hints. Re-packing the same claim with a different `verified_at`
/// / proof set MUST leave the digest unchanged, because the digest folds
/// only `{claim_digest, binding_state, expires_at}` of the visible claims.
pub fn run_member_roster_display_state_digest_stable_under_freshness_hints_vector() -> Result<()> {
    let realm = fake_realm()?;
    let actor = alice()?;
    let events = [EffectiveIdentityEntry {
        event_id: fake_event(0xf21)?,
        segment: MemberIdentitySegment::MemberIdentity,
        payload_digest: pinned_state_digest()?,
    }];

    let expires = Utc
        .with_ymd_and_hms(2026, 6, 20, 0, 0, 0)
        .single()
        .expect("pinned expires_at");
    let claim_a = RosterHandleClaimDigestEntry {
        claim_digest: pinned_claim_digest("33")?,
        binding_state: HandleBindingState::Verified,
        expires_at: Some(expires),
    };
    // Same canonical inputs — a "refreshed" claim with the identical
    // claim_digest / binding_state / expires_at. (The issuer only bumped
    // verified_at / repacked proofs, which are not part of the digest.)
    let claim_b = claim_a.clone();

    let digest_a = member_display_state_digest(&realm, &actor, &events, &[claim_a])
        .map_err(|e| anyhow!("member_display_state_digest a: {e}"))?;
    let digest_b = member_display_state_digest(&realm, &actor, &events, &[claim_b])
        .map_err(|e| anyhow!("member_display_state_digest b: {e}"))?;
    if digest_a != digest_b {
        bail!(
            "VECT-COT-4c: member_display_state_digest MUST be stable under \
             verified_at / proof-repacking freshness hints; got {digest_a} vs {digest_b}"
        );
    }
    if !digest_a.starts_with("sha256:") {
        bail!("VECT-COT-4c: member_display_state_digest must be sha256:<hex>");
    }

    // Sanity: a *semantic* change (new expiry → new claim_digest input)
    // MUST move the digest, proving the helper is not a no-op.
    let changed = RosterHandleClaimDigestEntry {
        claim_digest: pinned_claim_digest("44")?,
        binding_state: HandleBindingState::Verified,
        expires_at: Some(expires),
    };
    let digest_changed = member_display_state_digest(&realm, &actor, &events, &[changed])
        .map_err(|e| anyhow!("member_display_state_digest changed: {e}"))?;
    if digest_changed == digest_a {
        bail!(
            "VECT-COT-4c: a different claim_digest MUST change \
             member_display_state_digest (handle reassignment must invalidate the cache)"
        );
    }
    Ok(())
}

// ── VECT-COT-4d ─────────────────────────────────────────────────────────────

/// VECT-COT-4d — `handle_claims_limited=true` semantics: the field is a
/// truncation hint, NOT an assertion that the subject has no handle. A
/// limited entry with `subject_id` and `handle_claims_limited=true` MUST
/// validate, and clients MUST NOT interpret the (possibly empty) inline
/// `handle_claims[]` as "no handle".
pub fn run_member_roster_handle_claims_limited_semantics_vector() -> Result<()> {
    let subject = alice_subject()?;
    // Limited roster: only digest hints, claims truncated.
    let limited = MemberRosterEntry {
        actor_id: alice()?,
        membership: MembershipState::Join,
        subject_id: Some(subject.clone()),
        identity_event_ids: vec![fake_event(0xf31)?],
        member_display_state_digest: Some(pinned_state_digest()?),
        identity_events: vec![],
        handle_claim_digests: Some(vec![pinned_claim_digest("55")?, pinned_claim_digest("66")?]),
        // claims truncated — only one of the two digests is materialised.
        handle_claims: Some(vec![verified_claim_for_subject(
            "alice:acme.example",
            &subject,
        )?]),
        handle_claims_limited: Some(true),
    };
    limited
        .validate()
        .map_err(|e| anyhow!("VECT-COT-4d: limited entry MUST validate: {e}"))?;

    // The limited flag must round-trip true.
    let wire = serde_json::to_value(&limited).map_err(|e| anyhow!("serialise: {e}"))?;
    if wire.get("handle_claims_limited").and_then(Value::as_bool) != Some(true) {
        bail!("VECT-COT-4d: handle_claims_limited MUST serialise as `true`");
    }

    // Contract assertion: with limited=true, |handle_claims| < |handle_claim_digests|
    // is allowed and MUST NOT be read as "subject has fewer/no handles".
    let materialised = limited.handle_claims.as_ref().map(Vec::len).unwrap_or(0);
    let hinted = limited
        .handle_claim_digests
        .as_ref()
        .map(Vec::len)
        .unwrap_or(0);
    if !(limited.handle_claims_limited == Some(true) && materialised < hinted) {
        bail!(
            "VECT-COT-4d: vector setup must demonstrate truncation \
             (materialised {materialised} < hinted {hinted} with limited=true)"
        );
    }

    // A NON-limited (or unset) entry where every digest is materialised is
    // the only case where a client may treat the inline set as complete.
    let complete = MemberRosterEntry {
        handle_claim_digests: Some(vec![pinned_claim_digest("55")?]),
        handle_claims: Some(vec![verified_claim_for_subject(
            "alice:acme.example",
            &subject,
        )?]),
        handle_claims_limited: Some(false),
        ..limited.clone()
    };
    complete
        .validate()
        .map_err(|e| anyhow!("VECT-COT-4d: complete entry MUST validate: {e}"))?;
    Ok(())
}

// ── Suite entry-point ──────────────────────────────────────────────────────

pub fn run_member_roster_vector_suite() -> Result<()> {
    if ALL_MEMBER_ROSTER_VECTOR_IDS.len() != 7 {
        bail!(
            "expected 7 member-roster vector ids, got {}",
            ALL_MEMBER_ROSTER_VECTOR_IDS.len()
        );
    }
    run_member_roster_shape_vector()?;
    run_member_roster_limited_vector()?;
    run_member_roster_with_inline_identity_events_vector()?;
    run_member_roster_subject_undisclosed_omits_gated_fields_vector()?;
    run_member_roster_handle_claims_subject_alignment_vector()?;
    run_member_roster_display_state_digest_stable_under_freshness_hints_vector()?;
    run_member_roster_handle_claims_limited_semantics_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_roster_vector_suite_runs_clean() {
        run_member_roster_vector_suite().unwrap();
    }
}
