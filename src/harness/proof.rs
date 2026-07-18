use anyhow::{Context, Result, anyhow};
use serde_json::Value;

/// Canonical `event_digest` over an Event envelope with `proofs`/`unsigned`
/// stripped, hashed via the SDK's canonical (sorted-key, integer-number)
/// encoding so every Arkret implementation agrees on the bytes. Shared by all
/// cotest event builders — do not re-implement a `serde_json::to_vec` variant,
/// which preserves insertion order and would diverge from the SDK.
#[cfg(test)]
pub(crate) fn canonical_event_digest(event: &Value) -> Result<String> {
    let typed_value = event_value_with_parseable_proof_digests(event);
    let label = event_fixture_label(event);
    let typed: arkret_core::Event = serde_json::from_value(typed_value)
        .with_context(|| format!("Event fixture {label} does not match the SDK wire shape"))?;
    typed
        .event_digest()
        .with_context(|| format!("Event fixture {label} is not canonicalizable"))
}

fn event_value_with_parseable_proof_digests(event: &Value) -> Value {
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
    typed_value
}

/// Re-sign a mutated cotest Event through the SDK's canonical Event-proof
/// transcript using the SDK's deterministic development identity.
pub fn refresh_event_proof(event: &mut Value) -> Result<()> {
    let label = event_fixture_label(event);
    let verification_method = event
        .pointer("/proofs/0/verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Event fixture {label} lacks proofs[0].verification_method"))?
        .to_owned();
    let signing_seed = arkret::signatures::development_signing_key_seed(&verification_method);
    refresh_event_proof_with_signing_seed(event, signing_seed)
}

/// Re-sign a mutated Event with an explicitly provisioned fixture key. Formal
/// DID-history E2E tests use this for their registered controller key.
pub fn refresh_event_proof_with_signing_seed(
    event: &mut Value,
    signing_seed: [u8; 32],
) -> Result<()> {
    let label = event_fixture_label(event);
    let verification_method = event
        .pointer("/proofs/0/verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Event fixture {label} lacks proofs[0].verification_method"))?
        .to_owned();
    let mut typed: arkret_core::Event =
        serde_json::from_value(event_value_with_parseable_proof_digests(event))
            .with_context(|| format!("Event fixture {label} does not match the SDK wire shape"))?;
    let signer_did = typed
        .executed_by
        .clone()
        .unwrap_or_else(|| typed.actor_id.clone());
    let created_at = typed.created_at;
    typed.proofs.clear();
    let signer = arkret::Ed25519MoveSigner::from_did_key_seed(
        signing_seed,
        signer_did,
        verification_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut typed,
        &signer,
        &verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .with_context(|| format!("SDK Event signer rejected fixture {label}"))?;
    *event = serde_json::to_value(typed)
        .with_context(|| format!("SDK Event fixture {label} failed to serialize"))?;
    Ok(())
}

fn event_fixture_label(event: &Value) -> String {
    event
        .get("event_id")
        .and_then(Value::as_str)
        .or_else(|| event.get("kind").and_then(Value::as_str))
        .unwrap_or("<unknown Event>")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn canonical_event_digest_uses_sdk_typed_event_wire_shape() {
        let event = json!({
            "event_id": "ak:event:019f3b1c-76c8-7000-8000-000000000001",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:019f3b1c-76c8-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-07T00:00:00.000Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [],
            "requirements": {
                "features": [],
                "critical_extensions": []
            },
            "payload": {
                "content": {"kind": "ak.content.text", "body": "hello"},
                "message_id": "ak:message:019f3b1c-76c8-7000-8000-000000000001",
                "strand_id": "ak:strand:019f3b1c-76c8-7000-8000-000000000001"
            },
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:alice.example#device",
                "event_digest": "",
                "created_at": "2026-07-07T00:00:00.000Z",
                "jws": "placeholder"
            }]
        });

        let digest = super::canonical_event_digest(&event).unwrap();
        let mut parseable = event.clone();
        parseable["proofs"][0]["event_digest"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        let typed: arkret_core::Event = serde_json::from_value(parseable).unwrap();

        assert_eq!(digest, typed.event_digest().unwrap());
    }

    #[test]
    fn raw_ephemeral_envelope_can_be_signed_before_it_has_a_proof() {
        let mut envelope = json!({
            "kind": "ak.typing",
            "realm_id": "ak:realm:019f3b1c-76c8-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:019f3b1c-76c8-7000-8000-000000000001",
            "sent_at": "2026-07-07T00:00:00Z",
            "expires_at": "2026-07-07T00:00:15Z",
            "payload": {
                "strand_id": "ak:strand:019f3b1c-76c8-7000-8000-000000000001",
                "typing": true
            }
        });

        super::attach_ephemeral_proof_value(
            &mut envelope,
            &ed25519_dalek::SigningKey::from_bytes(&[0x5f; 32]),
        );

        let typed: arkret_core::EphemeralEnvelope = serde_json::from_value(envelope).unwrap();
        assert_eq!(typed.proof.kind, arkret_core::proof_kind::DETACHED_JWS);
        assert!(!typed.proof.jws.is_empty());

        let wire = serde_json::to_value(&typed).unwrap();
        assert_eq!(
            wire["device_id"],
            "ak:device:019f3b1c-76c8-7000-8000-000000000001"
        );
        let mut missing_device_id = wire;
        missing_device_id
            .as_object_mut()
            .unwrap()
            .remove("device_id");
        assert!(
            serde_json::from_value::<arkret_core::EphemeralEnvelope>(missing_device_id).is_err()
        );
    }
}

/// Attach the `ephemeral-envelope.schema.json` broadcast `proof` to an
/// ephemeral envelope: a real ed25519 detached JWS whose
/// `verification_method` is `{actor_id}#{device_id}` and whose `event_digest`
/// covers the canonical envelope bytes without `proof` (the shape the soland
/// relay verifies against the active device directory key before admission).
///
/// Fully typed on the SDK surface: the binding transcript comes from
/// [`arkret_core::Proof::canonical_ephemeral_binding_bytes`] and the JWS wire
/// form from [`arkret_signatures::proof::Ed25519DetachedJwsSigner`], so this helper can never
/// drift from the verifier's bytes.
pub fn attach_ephemeral_proof(
    envelope: &mut arkret_core::EphemeralEnvelope,
    signing_key: &ed25519_dalek::SigningKey,
) {
    let device_id = envelope.device_id.as_str().to_owned();

    // event_digest covers the SDK-defined canonical envelope without `proof`.
    let canonical = envelope
        .canonical_bytes_without_proof()
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
        .canonical_ephemeral_binding_bytes(&envelope.actor_id)
        .expect("proof binding is canonicalizable");
    let signer = arkret_signatures::proof::Ed25519DetachedJwsSigner::new(
        signing_key.clone(),
        proof.verification_method.clone(),
    );
    proof.jws = signer.sign_detached_jws(&binding_bytes);
    envelope.proof = proof;
}

pub fn ephemeral_proof_placeholder(
    actor_id: &str,
    device_id: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_core::Proof {
    arkret_core::Proof {
        kind: arkret_core::proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{actor_id}#{device_id}"),
        event_digest: arkret_core::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .expect("zero SHA-256 digest is typed"),
        created_at,
        domain: None,
        audience: None,
        // `EphemeralEnvelope::new` validates the required proof shape before
        // the caller can replace it with the real signature.
        jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
    }
}

/// [`attach_ephemeral_proof`] for callers holding a raw JSON envelope: the
/// value is round-tripped through the typed [`arkret_core::EphemeralEnvelope`]
/// (so a malformed envelope fails loudly here, not at the server) and
/// re-serialized with the attached proof.
pub fn attach_ephemeral_proof_value(envelope: &mut Value, signing_key: &ed25519_dalek::SigningKey) {
    let actor_id = envelope
        .get("actor_id")
        .and_then(Value::as_str)
        .expect("ephemeral envelope actor_id is a string")
        .to_owned();
    let device_id = envelope
        .get("device_id")
        .and_then(Value::as_str)
        .expect("ephemeral envelope device_id is a string")
        .to_owned();
    let created_at = serde_json::from_value(
        envelope
            .get("sent_at")
            .cloned()
            .expect("ephemeral envelope carries sent_at"),
    )
    .expect("ephemeral envelope sent_at is a timestamp");
    envelope
        .as_object_mut()
        .expect("ephemeral envelope is an object")
        .insert(
            "proof".to_owned(),
            serde_json::to_value(ephemeral_proof_placeholder(
                &actor_id, &device_id, created_at,
            ))
            .expect("ephemeral proof placeholder serializes"),
        );
    let mut typed: arkret_core::EphemeralEnvelope = serde_json::from_value(envelope.clone())
        .expect("value is a well-formed ephemeral envelope");
    attach_ephemeral_proof(&mut typed, signing_key);
    *envelope = serde_json::to_value(&typed).expect("ephemeral envelope serializes");
}
