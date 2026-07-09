use serde_json::Value;

/// Canonical `event_digest` over an Event envelope with `proofs`/`unsigned`
/// stripped, hashed via the SDK's canonical (sorted-key, integer-number)
/// encoding so every Arkret implementation agrees on the bytes. Shared by all
/// cotest event builders — do not re-implement a `serde_json::to_vec` variant,
/// which preserves insertion order and would diverge from the SDK.
pub(crate) fn canonical_event_digest(event: &Value) -> String {
    let mut typed_value = event.clone();
    if let Value::Object(object) = &mut typed_value {
        match object.get_mut("proofs") {
            Some(Value::Array(proofs)) => {
                for proof in proofs {
                    if let Value::Object(proof_object) = proof {
                        let missing_or_empty = proof_object
                            .get("event_digest")
                            .and_then(Value::as_str)
                            .is_none_or(str::is_empty);
                        if missing_or_empty {
                            proof_object.insert(
                                "event_digest".to_owned(),
                                Value::String(
                                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                                        .to_owned(),
                                ),
                            );
                        }
                    }
                }
            }
            Some(_) => {}
            None => {
                object.insert("proofs".to_owned(), Value::Array(Vec::new()));
            }
        }
    }
    let typed: arkret_core::Event =
        serde_json::from_value(typed_value).expect("event envelope matches SDK Event wire shape");
    typed
        .event_digest()
        .expect("event envelope digest is canonicalizable")
}

/// Fill `proofs[0].event_digest` with the canonical Event digest. The canonical
/// `event_proof` schema (`additionalProperties:false`) only carries
/// `event_digest`; there is no proof-level `payload_digest`.
pub fn refresh_event_proof(event: &mut Value) {
    let digest = canonical_event_digest(event);
    event["proofs"][0]["event_digest"] = Value::String(digest);
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn canonical_event_digest_uses_sdk_typed_event_wire_shape() {
        let event = json!({
            "event_id": "ak:event:019f3b1c-76c8-7000-8000-000000000001",
            "kind": "ck.message.create",
            "realm_id": "ak:realm:019f3b1c-76c8-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-07T00:00:00Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [],
            "requirements": {
                "features": [],
                "critical_extensions": []
            },
            "payload": {
                "content": {"kind": "ck.content.text", "body": "hello"},
                "message_id": "ak:message:019f3b1c-76c8-7000-8000-000000000001",
                "strand_id": "ak:strand:019f3b1c-76c8-7000-8000-000000000001"
            },
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:alice.example#device",
                "event_digest": "",
                "created_at": "2026-07-07T00:00:00Z",
                "jws": "placeholder"
            }]
        });

        let digest = super::canonical_event_digest(&event);
        let mut parseable = event.clone();
        parseable["proofs"][0]["event_digest"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        let typed: arkret_core::Event = serde_json::from_value(parseable).unwrap();

        assert_eq!(digest, typed.event_digest().unwrap());
    }
}

/// Attach the `ephemeral-envelope.schema.json` broadcast `proof` to an
/// ephemeral envelope: a real ed25519 detached JWS whose
/// `verification_method` is `{actor_id}#{device_id}` and whose `event_digest`
/// covers the canonical envelope bytes without `proof` (the shape the soland
/// relay admits; cryptographic verification is the receiver's job).
///
/// Fully typed on the SDK surface: the binding transcript comes from
/// [`arkret_core::Proof::canonical_binding_bytes`] and the JWS wire form from
/// [`arkret_signatures::sign_eddsa_detached_jws`], so this helper can never
/// drift from the verifier's bytes.
pub fn attach_ephemeral_proof(
    envelope: &mut arkret_core::EphemeralEnvelope,
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
    let canonical = arkret_core::canonical::canonical_json_bytes(
        &serde_json::to_value(&*envelope).expect("ephemeral envelope serializes"),
    )
    .expect("ephemeral envelope is canonicalizable");
    let event_digest = arkret_core::Hash::new(arkret_core::canonical::sha256_digest(&canonical))
        .expect("sha256 digest is a valid Hash");

    let mut proof = arkret_core::Proof {
        kind: arkret_core::proof_kind::DETACHED_JWS.to_owned(),
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
    proof.jws = arkret_signatures::proof::sign_eddsa_detached_jws(signing_key, &binding_bytes)
        .expect("detached JWS signing succeeds");
    envelope.proof = Some(serde_json::to_value(&proof).expect("proof serializes"));
}

/// [`attach_ephemeral_proof`] for callers holding a raw JSON envelope: the
/// value is round-tripped through the typed [`arkret_core::EphemeralEnvelope`]
/// (so a malformed envelope fails loudly here, not at the server) and
/// re-serialized with the attached proof.
pub fn attach_ephemeral_proof_value(envelope: &mut Value, signing_key: &ed25519_dalek::SigningKey) {
    let mut typed: arkret_core::EphemeralEnvelope = serde_json::from_value(envelope.clone())
        .expect("value is a well-formed ephemeral envelope");
    attach_ephemeral_proof(&mut typed, signing_key);
    *envelope = serde_json::to_value(&typed).expect("ephemeral envelope serializes");
}
