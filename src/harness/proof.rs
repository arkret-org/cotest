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

/// Attach the `ephemeral-envelope.schema.json` broadcast `proof` to an
/// ephemeral envelope: a real ed25519 detached JWS whose
/// `verification_method` is `{actor_id}#{device_id}` and whose `event_digest`
/// covers the canonical envelope bytes without `proof` (the shape the soland
/// relay admits; cryptographic verification is the receiver's job).
///
/// Fully typed on the SDK surface: the binding transcript comes from
/// [`cokret_core::Proof::canonical_binding_bytes`] and the JWS wire form from
/// [`cokret_signatures::sign_eddsa_detached_jws`], so this helper can never
/// drift from the verifier's bytes.
pub fn attach_ephemeral_proof(
    envelope: &mut cokret_core::EphemeralEnvelope,
    signing_key: &ed25519_dalek::SigningKey,
) {
    let device_id = envelope
        .device_id
        .as_ref()
        .expect("broadcast ephemeral envelope requires device_id")
        .as_str()
        .to_owned();

    // event_digest covers the canonical envelope without `proof`.
    envelope.proof = None;
    let canonical = cokret_core::canonical::canonical_json_bytes(
        &serde_json::to_value(&*envelope).expect("ephemeral envelope serializes"),
    )
    .expect("ephemeral envelope is canonicalizable");
    let event_digest = cokret_core::Hash::new(cokret_core::canonical::sha256_digest(&canonical))
        .expect("sha256 digest is a valid Hash");

    let mut proof = cokret_core::Proof {
        kind: cokret_core::proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{}#{device_id}", envelope.actor_id),
        event_digest,
        created_at: envelope.sent_at,
        domain: None,
        audience: None,
        jws: String::new(),
    };
    let binding_bytes = proof
        .canonical_binding_bytes(&envelope.actor_id)
        .expect("proof binding is canonicalizable");
    proof.jws = cokret_signatures::proof::sign_eddsa_detached_jws(signing_key, &binding_bytes)
        .expect("detached JWS signing succeeds");
    envelope.proof = Some(serde_json::to_value(&proof).expect("proof serializes"));
}

/// [`attach_ephemeral_proof`] for callers holding a raw JSON envelope: the
/// value is round-tripped through the typed [`cokret_core::EphemeralEnvelope`]
/// (so a malformed envelope fails loudly here, not at the server) and
/// re-serialized with the attached proof.
pub fn attach_ephemeral_proof_value(
    envelope: &mut Value,
    signing_key: &ed25519_dalek::SigningKey,
) {
    let mut typed: cokret_core::EphemeralEnvelope = serde_json::from_value(envelope.clone())
        .expect("value is a well-formed ephemeral envelope");
    attach_ephemeral_proof(&mut typed, signing_key);
    *envelope = serde_json::to_value(&typed).expect("ephemeral envelope serializes");
}
