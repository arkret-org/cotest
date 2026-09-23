//! R2.1 / R2.3 — Realm/Space boundary split wire round-trip vectors.
//!
//! Cross-project contract test for the current Realm/Space boundary split:
//! Realm event kinds cover the security boundary, and Space event kinds cover
//! containers inside a Realm.
//!
//! This module builds SDK-typed [`arkret_wire::Event`] envelopes for
//! each renamed kind, canonical-encodes them via the SDK encoder, and
//! asserts:
//!
//! 1. Round-trip parses back into the same `(kind, realm_id, payload)` triple (the wire bytes any
//!    other project — soland / inkson / federation peer — would receive).
//! 2. [`arkret_wire::events::event_product_class_from_wire`] recognises the new kinds in their new
//!    family (Realm / Space-container).
//! Used by `tests/realm_wire_round_trip.rs`. Pure unit-style: no
//! binary, no network — the round-trip is entirely against the SDK so
//! we catch contract drift in CI without spinning up soland.

use anyhow::{Result, anyhow};
use arkret_canonical::{canonical_json_bytes, canonical_sha256};
use arkret_identifiers::{Did, DidCoreId, RealmId, project_did_to_core_id};
use arkret_wire::Event;
use arkret_wire::events::EventProductClass;
use serde_json::{Value, json};

/// Build a minimal SDK-typed [`Event`] for a Realm/Space boundary split wire
/// vector. `realm_id` is the typed `ak:realm:...` security-boundary
/// identifier; `ak.space.*` event kinds now describe containers inside
/// that Realm.
fn build_event(kind: &str, realm_id: &RealmId, payload: Value) -> Result<Event> {
    let actor_did = Did::new("did:web:alice.example".to_owned())
        .map_err(|err| anyhow!("invalid actor did: {err}"))?;
    let actor_id = project_did_to_core_id(&actor_did)?;
    arkret_wire::test_support::raw_event(
        kind.to_owned(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id,
        DidCoreId::new("ak:did_core:web:principal.example")?,
        payload,
    )
    .map_err(|err| anyhow!("failed to build event: {err}"))
}

/// One vector: input kind + payload, expected `EventProductClass`, and a label
/// for failure reporting.
struct WireVector {
    label: &'static str,
    kind: &'static str,
    payload: Value,
    expected_class: EventProductClass,
}

/// Positive vectors — every kind listed here MUST round-trip cleanly
/// and classify into a non-Custom family. If any of these fail it means
/// the SDK drifted from the Realm/Space wire contract surface.
fn positive_vectors() -> Vec<WireVector> {
    vec![
        WireVector {
            label: "ak.realm.create",
            kind: arkret_wire::event_kind_str::REALM_CREATE,
            payload: json!({"action": "create", "title": "Engineering Realm"}),
            expected_class: EventProductClass::Realm,
        },
        WireVector {
            label: "ak.space.create (container)",
            kind: arkret_wire::event_kind_str::SPACE_CREATE,
            payload: json!({"title": "Launch Board", "kind": "board"}),
            expected_class: EventProductClass::Space,
        },
        WireVector {
            label: "ak.realm.link",
            kind: arkret_wire::event_kind_str::REALM_LINK,
            payload: json!({
                "link_kind": "parent",
                "target_realm_id": "ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr",
            }),
            expected_class: EventProductClass::Realm,
        },
    ]
}

fn fixture_realm_id() -> Result<RealmId> {
    RealmId::new("ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru".to_owned())
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
    // Spec realm-and-space.md section 2.5.0: a Realm genesis carries no
    // realm_id on the wire — receivers derive it from the Event. Every other
    // kind still round-trips the field unchanged.
    if vector.kind == "ak.realm.create" {
        if parsed.get("realm_id").is_some() {
            return Err(anyhow!(
                "round-tripped {}: ak.realm.create must omit realm_id",
                vector.label
            ));
        }
    } else {
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
    }
    let parsed_payload = parsed
        .get("payload")
        .ok_or_else(|| anyhow!("round-tripped {}: missing payload field", vector.label))?;
    if parsed_payload != &vector.payload {
        return Err(anyhow!("round-tripped {}: payload drifted", vector.label,));
    }
    let class = arkret_wire::events::event_product_class_from_wire(parsed_kind);
    if class != vector.expected_class {
        return Err(anyhow!(
            "round-tripped {}: event_product_class drifted: got {:?}, want {:?}",
            vector.label,
            class,
            vector.expected_class
        ));
    }
    canonical_sha256(&envelope_value)
        .map_err(|err| anyhow!("canonical_sha256 failed for {}: {err}", vector.label))
}

/// R2.1 — every Realm/Space boundary split positive vector survives a
/// canonical-encode → JSON-decode → SDK-classify round trip. Soland
/// wire-accepts the same kinds in `validate_event_envelope`, so any
/// drift here would show up first as cross-project ingestion failures.
pub fn run_positive_round_trip() -> Result<()> {
    let realm_id = fixture_realm_id()?;
    for vector in positive_vectors() {
        round_trip_positive(&vector, &realm_id)?;
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
}
