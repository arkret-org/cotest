//! R3.1 spec-sync (contrix-spec @ 7157ee8) — sync `member_roster_entry`
//! conformance vectors (VECT-ROST-1..3).
//!
//! Source artefact:
//!   * `artifacts/schemas/account-subscribe-frame.schema.json`
//!     (`$defs/member_roster_entry`).
//!
//! Per-Realm `members[]` entries pinned by R3.1:
//!   `{actor_id, membership, identity_event_ids?, identity_state_digest?,
//!     identity_events?}`. Entries MUST NOT carry raw handle / display
//! fields — clients resolve identity by following the event ids OR by
//! reading the inline `identity_events[]` originals when present.

use anyhow::{Result, anyhow, bail};
use contrix_core::model::{MemberRosterEntry, MembershipState};
use contrix_core::{Did, EventId, Hash};
use serde_json::{Value, json};

pub const VECTOR_ID_ROSTER_SHAPE: &str = "cx.vector.sync.member_roster_shape.v1";
pub const VECTOR_ID_ROSTER_LIMITED: &str = "cx.vector.sync.member_roster_limited.v1";
pub const VECTOR_ID_ROSTER_WITH_INLINE_IDENTITY_EVENTS: &str =
    "cx.vector.sync.member_roster_with_inline_identity_events.v1";

pub const ALL_MEMBER_ROSTER_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_ROSTER_SHAPE,
    VECTOR_ID_ROSTER_LIMITED,
    VECTOR_ID_ROSTER_WITH_INLINE_IDENTITY_EVENTS,
];

// ── Fixture helpers ─────────────────────────────────────────────────────────

fn alice() -> Result<Did> {
    Did::new("did:web:alice.acme.example".to_owned()).map_err(|e| anyhow!("alice did: {e}"))
}

fn fake_event(suffix: u32) -> Result<EventId> {
    EventId::new(format!("cx:event:01904100-0000-7000-8000-{suffix:012x}"))
        .map_err(|e| anyhow!("invalid event id: {e}"))
}

fn pinned_state_digest() -> Result<Hash> {
    Hash::new("sha256:abababababababababababababababababababababababababababababababab")
        .map_err(|e| anyhow!("pinned state digest: {e}"))
}

// ── VECT-ROST-1 ─────────────────────────────────────────────────────────────

/// VECT-ROST-1 — per-Realm `members[]` entries match
/// `{actor_id, membership, identity_event_ids?, identity_state_digest?}`.
/// The encoded vector MUST NOT contain `handle_uri` / `handle` /
/// `display_name` as roster fields. R3.1 wire rename guard.
pub fn run_member_roster_shape_vector() -> Result<()> {
    let entry = MemberRosterEntry {
        actor_id: alice()?,
        membership: MembershipState::Join,
        identity_event_ids: vec![fake_event(0xe01)?, fake_event(0xe02)?],
        identity_state_digest: Some(pinned_state_digest()?),
        identity_events: vec![],
    };

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
    if value.get("identity_state_digest").is_none() {
        bail!(
            "VECT-ROST-1: when identity_state_digest is set it MUST be \
             serialised onto the wire"
        );
    }

    // Forbidden legacy fields — these MUST NOT appear directly on a
    // roster entry. The R3.1 wire rename retired `handle_uri`; the
    // `display_name` field belongs on the inline MemberIdentity object,
    // not on the roster row; and the canonical handle `<localpart>:<domain>`
    // also MUST NOT be inlined.
    let forbidden_top_level_keys = ["handle_uri", "handle", "display_name", "avatar"];
    for key in forbidden_top_level_keys {
        if value.get(key).is_some() {
            bail!(
                "VECT-ROST-1: roster entry MUST NOT carry top-level `{key}`; \
                 identity belongs in the inline MemberIdentity object \
                 (R3.1 wire rename + sync surface)"
            );
        }
    }

    // Empty `identity_events[]` must be omitted entirely (the SDK uses
    // skip_serializing_if).
    if value.get("identity_events").is_some() {
        bail!(
            "VECT-ROST-1: empty identity_events[] MUST be omitted to keep the \
             roster payload compact"
        );
    }

    // Round-trip MUST preserve identity_event_ids[] order and digest.
    let decoded: MemberRosterEntry =
        serde_json::from_value(value).map_err(|e| anyhow!("deserialise: {e}"))?;
    if decoded.identity_event_ids != entry.identity_event_ids {
        bail!("VECT-ROST-1: identity_event_ids[] order changed under round-trip");
    }
    if decoded.identity_state_digest != entry.identity_state_digest {
        bail!("VECT-ROST-1: identity_state_digest changed under round-trip");
    }
    Ok(())
}

// ── VECT-ROST-2 ─────────────────────────────────────────────────────────────

/// VECT-ROST-2 — `members_limited=true` + `members_next_cursor` semantics
/// on a roster frame. A roster wrapped in a sync frame that signals
/// truncation MUST surface both fields together; clients MUST NOT treat
/// such a frame as the complete member set.
pub fn run_member_roster_limited_vector() -> Result<()> {
    // Per the schema `account-subscribe-frame.schema.json`, the truncation
    // signals live on the **frame**, not on each entry. Build the
    // frame-shaped fixture inline (the SDK does not ship a typed sync
    // frame yet) and assert the wire shape.
    let frame = json!({
        "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
        "members": [
            {
                "actor_id": "did:web:alice.acme.example",
                "membership": "join",
                "identity_event_ids": [
                    "cx:event:01904100-0000-7000-8000-00000000ea01"
                ],
                "identity_state_digest":
                    "sha256:abababababababababababababababababababababababababababababababab"
            }
        ],
        "members_limited": true,
        "members_next_cursor":
            "cx:cursor:eyJ2IjoiMSIsInB1cnBvc2UiOiJzdHJlYW0iLCJ0IjoiMjAyNi0wNS0yN1QwMDowMDowMFoiLCJ4IjoxOTAwMDAwMDAwMDAwfQ"
    });

    if frame.get("members_limited").and_then(Value::as_bool) != Some(true) {
        bail!("VECT-ROST-2: `members_limited` MUST be true when the roster is truncated");
    }
    let cursor = frame
        .get("members_next_cursor")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!(
            "VECT-ROST-2: a truncated roster MUST carry `members_next_cursor`"
        ))?;
    if !cursor.starts_with("cx:cursor:") {
        bail!(
            "VECT-ROST-2: members_next_cursor MUST be a `cx:cursor:` opaque \
             cursor; got `{cursor}`"
        );
    }
    // Sanity: a sync frame that does NOT carry members_limited MUST NOT
    // carry members_next_cursor either (the two fields are coupled).
    let unlimited = json!({
        "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
        "members": []
    });
    if unlimited.get("members_limited").is_some() {
        bail!(
            "VECT-ROST-2: a non-truncated roster MUST NOT carry `members_limited`"
        );
    }
    if unlimited.get("members_next_cursor").is_some() {
        bail!(
            "VECT-ROST-2: a non-truncated roster MUST NOT carry `members_next_cursor`"
        );
    }
    Ok(())
}

// ── VECT-ROST-3 ─────────────────────────────────────────────────────────────

/// VECT-ROST-3 — `identity_events[]` inlined and matches the events
/// referenced by `identity_event_ids`.
pub fn run_member_roster_with_inline_identity_events_vector() -> Result<()> {
    // We do not yet have a typed `Event` struct that round-trips through
    // serde without the full SDK envelope (the `Event` type lives in
    // contrix-core but is gated on many runtime invariants). For vector
    // purposes we model the wire shape directly and assert the
    // identity_events[].event_id values match identity_event_ids[] one-for-one.
    let inline = json!({
        "actor_id": "did:web:alice.acme.example",
        "membership": "join",
        "identity_event_ids": [
            "cx:event:01904100-0000-7000-8000-00000000ea01",
            "cx:event:01904100-0000-7000-8000-00000000ea02"
        ],
        "identity_state_digest":
            "sha256:abababababababababababababababababababababababababababababababab",
        "identity_events": [
            {
                "event_id": "cx:event:01904100-0000-7000-8000-00000000ea01",
                "kind": "cx.member.identity.update",
                "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
                "actor_id": "did:web:alice.acme.example",
                "payload": {
                    "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
                    "actor_id": "did:web:alice.acme.example",
                    "segment": "member_identity",
                    "identity_payload": {"member_identity": {"placeholder": "v1"}}
                }
            },
            {
                "event_id": "cx:event:01904100-0000-7000-8000-00000000ea02",
                "kind": "cx.member.identity.update",
                "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
                "actor_id": "did:web:alice.acme.example",
                "payload": {
                    "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
                    "actor_id": "did:web:alice.acme.example",
                    "segment": "member_identity",
                    "replaces": [{
                        "event_id": "cx:event:01904100-0000-7000-8000-00000000ea01",
                        "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    }],
                    "identity_payload": {"member_identity": {"placeholder": "v2"}}
                }
            }
        ]
    });

    // identity_event_ids[] and identity_events[].event_id MUST match
    // one-for-one in order.
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
    // Every inline event MUST be a `cx.member.identity.update`.
    for event in events_array {
        let kind = event["kind"].as_str().unwrap_or_default();
        if kind != "cx.member.identity.update" {
            bail!(
                "VECT-ROST-3: identity_events[] MUST carry only \
                 `cx.member.identity.update` events; got kind=`{kind}`"
            );
        }
    }
    Ok(())
}

// ── Suite entry-point ──────────────────────────────────────────────────────

pub fn run_member_roster_vector_suite() -> Result<()> {
    if ALL_MEMBER_ROSTER_VECTOR_IDS.len() != 3 {
        bail!(
            "expected 3 member-roster vector ids, got {}",
            ALL_MEMBER_ROSTER_VECTOR_IDS.len()
        );
    }
    run_member_roster_shape_vector()?;
    run_member_roster_limited_vector()?;
    run_member_roster_with_inline_identity_events_vector()?;
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
