use serde_json::{Value, json};

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

/// Attach the `ephemeral-envelope.schema.json` broadcast `proof` to an
/// ephemeral envelope value: a real ed25519 detached JWS whose
/// `verification_method` is `{actor_id}#{device_id}` and whose `event_digest`
/// covers the canonical envelope bytes without `proof` (the shape the soland
/// relay admits; cryptographic verification is the receiver's job).
///
/// The envelope MUST already carry `kind`, `realm_id`, `actor_id`,
/// `device_id`, `sent_at` (RFC 3339 string), `expires_at` and `payload`.
pub fn attach_ephemeral_proof(
    envelope: &mut Value,
    signing_key: &ed25519_dalek::SigningKey,
) {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    let b64url = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let actor_id = envelope["actor_id"].as_str().expect("actor_id").to_owned();
    let device_id = envelope["device_id"].as_str().expect("device_id").to_owned();
    let created_at = envelope["sent_at"].as_str().expect("sent_at").to_owned();
    let verification_method = format!("{actor_id}#{device_id}");

    let mut without_proof = envelope.clone();
    if let Value::Object(object) = &mut without_proof {
        object.remove("proof");
    }
    let canonical = cokret_core::canonical::canonical_json_bytes(&without_proof)
        .expect("ephemeral envelope is canonicalizable");
    let event_digest = cokret_core::canonical::sha256_digest(&canonical);

    let header_b64 = b64url(br#"{"alg":"EdDSA"}"#);
    let binding = json!({
        "event_digest": event_digest,
        "actor_id": actor_id,
        "verification_method": verification_method,
        "created_at": created_at,
    });
    let binding_b64 = b64url(
        &cokret_core::canonical::canonical_json_bytes(&binding)
            .expect("proof binding is canonicalizable"),
    );
    let signing_input = format!("{header_b64}.{binding_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let jws = format!("{header_b64}..{}", b64url(&signature.to_bytes()));

    envelope["proof"] = json!({
        "kind": "detached_jws",
        "alg": "EdDSA",
        "verification_method": verification_method,
        "event_digest": event_digest,
        "created_at": created_at,
        "jws": jws,
    });
}
