use serde_json::Value;

/// Canonical `event_digest` over an Event envelope with `proofs`/`unsigned`
/// stripped, hashed via the SDK's canonical (sorted-key, integer-number)
/// encoding so every Cokret implementation agrees on the bytes. Shared by all
/// cotest event builders — do not re-implement a `serde_json::to_vec` variant,
/// which preserves insertion order and would diverge from the SDK.
pub(crate) fn canonical_event_digest(event: &Value) -> String {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
    }
    cokret_core::canonical::canonical_sha256(&canonical).expect("event JSON is canonicalizable")
}

/// Fill `proofs[0].event_digest` with the canonical Event digest. The canonical
/// `event_proof` schema (`additionalProperties:false`) only carries
/// `event_digest`; there is no proof-level `payload_digest`.
pub(crate) fn refresh_event_proof(event: &mut Value) {
    let digest = canonical_event_digest(event);
    event["proofs"][0]["event_digest"] = Value::String(digest);
}
