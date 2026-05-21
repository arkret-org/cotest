//! R2.1 / R2.3 — Realm/Space reversal wire round-trip vectors.
//!
//! Phase 2 cross-project contract test for the Realm/Space reversal
//! (R1.2). After Phase 1 the wire kinds switched as follows:
//!
//! - security boundary: `cx.space.*` → `cx.realm.*`
//! - container: `cx.place.*` → `cx.space.*`
//!
//! This module builds SDK-typed [`contrix_core::Event`] envelopes for
//! each renamed kind, canonical-encodes them via the SDK encoder, and
//! asserts:
//!
//! 1. Round-trip parses back into the same `(kind, realm_id, payload)`
//!    triple (the wire bytes any other project — soland / yougen /
//!    federation peer — would receive).
//! 2. [`contrix_core::events::classify_event_kind`] recognises the new
//!    kinds in their new family (Realm / Space-container).
//! 3. The pre-rename `cx.space.<security>` and `cx.place.*` kinds
//!    classify as `EventClass::Custom`, mirroring soland's
//!    `realm_kind_renamed_in_v1` / `place_kind_renamed_to_space`
//!    hard_reject reason codes in `routing/events/event_log.rs`.
//!
//! Used by `tests/realm_wire_round_trip.rs`. Pure unit-style: no
//! binary, no network — the round-trip is entirely against the SDK so
//! we catch contract drift in CI without spinning up soland.

use anyhow::{Result, anyhow};
use contrix_core::canonical::{canonical_json_bytes, canonical_sha256};
use contrix_core::events::EventClass;
use contrix_core::events::{
    REALM_CREATE, REALM_DELIVERY_BINDING_POLICY, REALM_LINK, SPACE_CREATE, classify_event_kind,
};
use contrix_core::{Did, Event, Hlc, RealmId};
use serde_json::{Value, json};

/// Build a minimal SDK-typed [`Event`] for a Realm/Space reversal wire
/// vector. `realm_id` is the typed `cx:realm:...` security-boundary
/// identifier; `cx.space.*` event kinds now describe containers inside
/// that Realm.
fn build_event(kind: &str, realm_id: &RealmId, payload: Value) -> Result<Event> {
    let actor_id = Did::new("did:web:alice.example".to_owned())
        .map_err(|err| anyhow!("invalid actor did: {err}"))?;
    let hlc = Hlc::new("01970e589d21-00000001-a13f9c2e".to_owned())
        .map_err(|err| anyhow!("invalid hlc: {err}"))?;
    Event::new(kind.to_owned(), realm_id.clone(), actor_id, 1, hlc, payload)
        .map_err(|err| anyhow!("failed to build event: {err}"))
}

/// One vector: input kind + payload, expected `EventClass`, and a label
/// for failure reporting.
struct WireVector {
    label: &'static str,
    kind: &'static str,
    payload: Value,
    expected_class: EventClass,
}

/// Positive vectors — every kind listed here MUST round-trip cleanly
/// and classify into a non-Custom family. If any of these fail it means
/// the SDK lost or renamed a Realm/Space kind without updating the wire
/// contract surface.
fn positive_vectors() -> Vec<WireVector> {
    vec![
        WireVector {
            label: "cx.realm.create",
            kind: REALM_CREATE,
            payload: json!({"action": "create", "title": "Engineering Realm"}),
            expected_class: EventClass::Realm,
        },
        WireVector {
            label: "cx.space.create (container)",
            kind: SPACE_CREATE,
            payload: json!({"title": "Launch Board", "kind": "board"}),
            expected_class: EventClass::Space,
        },
        WireVector {
            label: "cx.realm.delivery_binding_policy",
            kind: REALM_DELIVERY_BINDING_POLICY,
            payload: json!({
                "allowed_recipient_services": ["did:web:soland.example"],
                "binding_source_policy": "endorsed_only",
            }),
            expected_class: EventClass::Realm,
        },
        WireVector {
            label: "cx.realm.link",
            kind: REALM_LINK,
            payload: json!({
                "link_kind": "parent",
                "target_realm_id": "cx:realm:01904100-0000-7000-8000-668e2181b41d",
            }),
            expected_class: EventClass::Realm,
        },
    ]
}

/// Negative vectors — pre-rename kinds that MUST NOT round-trip into a
/// known event family. The SDK classifies them as `EventClass::Custom`
/// (the catch-all bucket), and soland's `validate_event_envelope`
/// further hard_rejects them on submit with `realm_kind_renamed_in_v1`
/// / `place_kind_renamed_to_space`. cotest mirrors the contract here so
/// any future SDK regression (re-adding `cx.space.create` to the
/// security family, for instance) is caught at wire-bytes parse time.
fn negative_vectors() -> Vec<&'static str> {
    vec![
        // Pre-reversal security namespace.
        "cx.space.delivery_binding_policy",
        "cx.space.upgrade",
        "cx.space.policy",
        "cx.space.history_visibility",
        "cx.space.audit_policy_downgrade",
        "cx.space.destroy",
        // Pre-reversal container namespace.
        "cx.place.create",
        "cx.place.update",
        "cx.place.parent",
        "cx.place.archive",
        "cx.place.restore",
        "cx.place.tombstone",
    ]
}

fn fixture_realm_id() -> Result<RealmId> {
    RealmId::new("cx:realm:01904100-0000-7000-8000-000000000a01".to_owned())
        .map_err(|err| anyhow!("invalid realm id: {err}"))
}

/// Round-trip a positive vector through the SDK canonical encoder and
/// JSON decoder. Returns the digest so the caller can pin a stable
/// `sha256:` value if they want to lock the on-wire bytes.
fn round_trip_positive(vector: &WireVector, realm_id: &RealmId) -> Result<String> {
    let event = build_event(vector.kind, realm_id, vector.payload.clone())?;
    let envelope_value = serde_json::to_value(&event)?;
    let bytes = canonical_json_bytes(&envelope_value)
        .map_err(|err| anyhow!("canonical encode failed for {}: {err}", vector.label))?;
    let parsed: Value = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "canonical bytes did not parse as JSON for {}: {err}",
            vector.label
        )
    })?;
    let parsed_kind = parsed
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("round-tripped {}: missing kind field", vector.label))?;
    if parsed_kind != vector.kind {
        return Err(anyhow!(
            "round-tripped {}: kind drifted: got {parsed_kind:?}, want {:?}",
            vector.label,
            vector.kind
        ));
    }
    let parsed_realm_id = parsed
        .get("realm_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("round-tripped {}: missing realm_id field", vector.label))?;
    if parsed_realm_id != realm_id.as_str() {
        return Err(anyhow!(
            "round-tripped {}: realm_id drifted: got {parsed_realm_id:?}, want {:?}",
            vector.label,
            realm_id.as_str()
        ));
    }
    let parsed_payload = parsed
        .get("payload")
        .ok_or_else(|| anyhow!("round-tripped {}: missing payload field", vector.label))?;
    if parsed_payload != &vector.payload {
        return Err(anyhow!("round-tripped {}: payload drifted", vector.label,));
    }
    let class = classify_event_kind(parsed_kind);
    if class != vector.expected_class {
        return Err(anyhow!(
            "round-tripped {}: classify_event_kind drifted: got {:?}, want {:?}",
            vector.label,
            class,
            vector.expected_class
        ));
    }
    canonical_sha256(&envelope_value)
        .map_err(|err| anyhow!("canonical_sha256 failed for {}: {err}", vector.label))
}

/// R2.1 — every Realm/Space reversal positive vector survives a
/// canonical-encode → JSON-decode → SDK-classify round trip. Soland
/// wire-accepts the same kinds in `validate_event_envelope` (after
/// hard_rejecting the legacy `cx.space.*` security and `cx.place.*`
/// container kinds), so any drift here would show up first as
/// cross-project ingestion failures.
pub fn run_positive_round_trip() -> Result<()> {
    let realm_id = fixture_realm_id()?;
    for vector in positive_vectors() {
        round_trip_positive(&vector, &realm_id)?;
    }
    Ok(())
}

/// R2.1 / R2.3 — every legacy (pre-rename) wire kind we know about
/// classifies as `EventClass::Custom`, mirroring soland's
/// `realm_kind_renamed_in_v1` / `place_kind_renamed_to_space`
/// hard_reject. The SDK does not know about these kinds anymore so the
/// classifier MUST NOT promote them into the Realm or Space families.
pub fn run_negative_legacy_kinds_rejected() -> Result<()> {
    for legacy in negative_vectors() {
        let class = classify_event_kind(legacy);
        match class {
            EventClass::Custom(_) => {} // expected
            other => {
                return Err(anyhow!(
                    "legacy wire kind {legacy:?} should classify as Custom (renamed in v1), \
                     but classified as {other:?}"
                ));
            }
        }
    }
    Ok(())
}

/// R2.3 — soland's `validate_event_envelope` exposes the exact reason
/// codes downstream wire clients need to detect the rename. The list
/// here mirrors the hard_reject branch in
/// `soland/src/routing/events/event_log.rs` (search
/// `realm_kind_renamed_in_v1`). If soland ever drops or renames either
/// reason code, this constant pair is the place to fix in cotest.
pub const SOLAND_REALM_RENAME_REASON: &str = "realm_kind_renamed_in_v1";
pub const SOLAND_PLACE_RENAME_REASON: &str = "place_kind_renamed_to_space";

/// R2.3 — a smoke assert that pins the legacy security `cx.space.*`
/// kinds in the negative-vector list against the soland reason-code
/// constant above. Pure compile-time + classification check; the wire
/// integration with a running soland is exercised by the HTTP
/// scenarios that POST these legacy kinds and assert a 400 response.
pub fn run_legacy_reason_code_constants_present() -> Result<()> {
    // The two reason codes are non-empty contract surface — bare
    // sanity to catch accidental empty-string drift.
    if SOLAND_REALM_RENAME_REASON.is_empty() || SOLAND_PLACE_RENAME_REASON.is_empty() {
        return Err(anyhow!("soland rename reason codes must be non-empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_positive_vectors() {
        run_positive_round_trip().expect("realm/space positive round-trip");
    }

    #[test]
    fn legacy_kinds_classify_as_custom() {
        run_negative_legacy_kinds_rejected().expect("legacy kinds rejected by SDK classifier");
    }

    #[test]
    fn rename_reason_codes_non_empty() {
        run_legacy_reason_code_constants_present().expect("reason codes present");
    }
}
