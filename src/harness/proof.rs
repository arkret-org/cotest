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
    let typed: arkret_wire::Event = serde_json::from_value(typed_value)
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

fn controller_full_id(
    verification_method: &arkret_wire::DidUrl,
) -> Result<arkret_identifiers::DidFullId> {
    let controller = verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| anyhow!("verification method has no controller fragment"))?;
    arkret_identifiers::DidFullId::new(controller.to_owned())
        .map_err(|error| anyhow!("invalid verification-method controller: {error}"))
}

/// Re-sign a mutated cotest Event through the SDK's canonical Event-proof
/// transcript using the SDK's deterministic development identity.
pub fn refresh_event_proof(event: &mut Value) -> Result<()> {
    let label = event_fixture_label(event);
    let verification_method = event_proof_verification_method(event, &label)?;
    let signer = event
        .get("executed_by")
        .and_then(Value::as_str)
        .or_else(|| event.get("actor_id").and_then(Value::as_str))
        .ok_or_else(|| anyhow!("Event fixture {label} lacks a signer DID"))?;
    let signing_seed =
        super::event_builder::registered_event_signing_seed(signer, &verification_method)
            .unwrap_or_else(|| {
                arkret::signatures::development_signing_key_seed(&verification_method)
            });
    refresh_event_proof_with_signing_seed(event, signing_seed)
}

/// Re-sign a mutated Event with an explicitly provisioned fixture key. Formal
/// DID-history E2E tests use this for their registered controller key.
pub fn refresh_event_proof_with_signing_seed(
    event: &mut Value,
    signing_seed: [u8; 32],
) -> Result<()> {
    let label = event_fixture_label(event);
    let verification_method = event_proof_verification_method(event, &label)?;
    let mut typed: arkret_wire::Event =
        serde_json::from_value(event_value_with_parseable_proof_digests(event))
            .with_context(|| format!("Event fixture {label} does not match the SDK wire shape"))?;
    let signer_did = controller_full_id(&verification_method)?;
    let created_at = typed.created_at;
    typed.proofs.clear();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
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

/// Re-sign an SDK Event after changing typed fields.
pub fn refresh_typed_event_proof_with_signing_seed(
    event: &mut arkret_wire::Event,
    signing_seed: [u8; 32],
) -> Result<()> {
    let verification_method = event
        .proofs
        .first()
        .map(|proof| proof.verification_method.clone())
        .ok_or_else(|| anyhow!("Event {} has no signing proof", event.event_id))?;
    let signer_did = controller_full_id(&verification_method)?;
    let created_at = event.created_at;
    event.proofs.clear();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        signing_seed,
        signer_did,
        verification_method.clone(),
    );
    arkret::signatures::sign_event(
        event,
        &signer,
        &verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .with_context(|| format!("SDK Event signer rejected {}", event.event_id))
}

/// Re-sign a typed Event through the registered cotest identity.
pub fn refresh_typed_event_proof(event: &mut arkret_wire::Event) -> Result<()> {
    let verification_method = event
        .proofs
        .first()
        .map(|proof| proof.verification_method.clone())
        .ok_or_else(|| anyhow!("Event {} has no signing proof", event.event_id))?;
    let signer = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .as_str();
    let signing_seed =
        super::event_builder::registered_event_signing_seed(signer, &verification_method)
            .unwrap_or_else(|| {
                arkret::signatures::development_signing_key_seed(&verification_method)
            });
    refresh_typed_event_proof_with_signing_seed(event, signing_seed)
}

/// `proofs[0].verification_method` as the SDK's `DidUrl`.
///
/// A fixture carrying a bare DID here fails loudly at this boundary rather
/// than being widened into the wire type: `zh/identity/did-usage-and-verification.md`
/// §2.2 requires a `#fragment`, so a bare value is a fixture bug.
fn event_proof_verification_method(event: &Value, label: &str) -> Result<arkret_wire::DidUrl> {
    let raw = event
        .pointer("/proofs/0/verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Event fixture {label} lacks proofs[0].verification_method"))?;
    arkret_wire::DidUrl::new(raw).map_err(|error| {
        anyhow!(
            "Event fixture {label} proofs[0].verification_method {raw:?} is not a DID URL: {error}"
        )
    })
}

fn event_fixture_label(event: &Value) -> String {
    event
        .get("event_id")
        .and_then(Value::as_str)
        .or_else(|| event.get("kind").and_then(Value::as_str))
        .unwrap_or("<unknown Event>")
        .to_owned()
}

/// Attach the `ak.signal-proof-v1` device proof to a [`SignalEnvelope`].
///
/// The Signal proof is not an Event proof: its transcript names the sending
/// device and commits to `envelope_digest` — the envelope with `proof`
/// removed — so a signature from one rail can never be replayed on the other
/// (`zh/sync/signal.md` §1). The binding bytes come from
/// [`arkret_wire::SignalEnvelope::proof_binding_bytes`] and the JWS wire form
/// from the SDK signer, so this helper cannot drift from the verifier.
///
/// `aad_digest` is recomputed from the immutable outer header and
/// `proof.created_at` is set to `sent_at`, both of which
/// `SignalEnvelope::validate_structural` requires.
pub fn attach_signal_proof(
    envelope: &mut arkret_wire::SignalEnvelope,
    signing_key: &ed25519_dalek::SigningKey,
) {
    envelope.encrypted_payload.aad_digest = envelope
        .expected_aad_digest()
        .expect("signal envelope header is canonicalizable");
    envelope.proof.created_at = envelope.sent_at;
    envelope.proof.envelope_digest = envelope
        .envelope_digest()
        .expect("signal envelope is canonicalizable");
    let binding_bytes = envelope
        .proof_binding_bytes()
        .expect("signal proof binding is canonicalizable");
    // `Ed25519DetachedJwsSigner` is a low-level primitive that still takes
    // `impl Into<String>`; `as_str()` feeds it the already-validated `DidUrl`
    // without re-widening the envelope field.
    let signer = arkret_signatures::proof::Ed25519DetachedJwsSigner::new(
        signing_key.clone(),
        envelope.proof.verification_method.as_str(),
    );
    envelope.proof.jws = signer.sign_detached_jws(&binding_bytes);
}

/// [`attach_signal_proof`] for callers holding a raw JSON envelope: the value
/// is round-tripped through the typed [`arkret_wire::SignalEnvelope`] (so a
/// malformed envelope fails loudly here, not at the server) and re-serialized
/// with the attached proof.
pub fn attach_signal_proof_value(envelope: &mut Value, signing_key: &ed25519_dalek::SigningKey) {
    let mut typed: arkret_wire::SignalEnvelope =
        serde_json::from_value(envelope.clone()).expect("value is a well-formed signal envelope");
    attach_signal_proof(&mut typed, signing_key);
    *envelope = serde_json::to_value(&typed).expect("signal envelope serializes");
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn canonical_event_digest_uses_sdk_typed_event_wire_shape() {
        let event = json!({
            "event_id": "ak:event:Adrg-UgvjkV_pq83rokfhuq2TV0knfj99s04-4U7zApt",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AR321Vop7tDLHqivAB0TKKtPZj9DccBtl1inhW0gLJNA",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AR321Vop7tDLHqivAB0TKKtPZj9DccBtl1inhW0gLJNA"},
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
                "message_id": "ak:message:AWb5Nken0jbCnqSrJsuRfB0gnGenpREJucvnn6MsxwLz",
                "strand_id": "ak:strand:AWb5Nken0jbCnqSrJsuRfB0gnGenpREJucvnn6MsxwLz"
            },
            "proofs": [{
                "kind": "detached_jws",
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
        let typed: arkret_wire::Event = serde_json::from_value(parseable).unwrap();

        assert_eq!(digest, typed.event_digest().unwrap());
    }

    /// The signal rail carries no product `signal_kind`, `call_id` or
    /// `strand_id` on the outer header; a raw envelope is signable from its
    /// header alone, and the resulting proof verifies under the
    /// `ak.signal-proof-v1` transcript.
    #[test]
    fn raw_signal_envelope_can_be_signed_and_verifies() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5f; 32]);
        let mut envelope = json!({
            "realm_id": "ak:realm:AR321Vop7tDLHqivAB0TKKtPZj9DccBtl1inhW0gLJNA",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AR321Vop7tDLHqivAB0TKKtPZj9DccBtl1inhW0gLJNA"},
            "sender_actor_id": "did:web:alice.example",
            "sender_device_id": "ak:device:019f3b1c-76c8-7000-8000-000000000001",
            "seal_ref": format!("ak:seal:sha256:{}", "a".repeat(64)),
            "signal_class": "session",
            "sent_at": "2026-07-07T00:00:00.000Z",
            "expires_at": "2026-07-07T00:00:30.000Z",
            "encrypted_payload": {
                "scheme": "ak.signal_exporter_aead.v1",
                "key_ref": {
                    "algorithm": "MLS-EXPORTER-AEAD",
                    "group_state_ref": "ak:event:Ab1ksa-umr9kNJE_n2EEj6AVhUsqM_Xml_hJgWyMpwq8"
                },
                "purpose": "ak.signal.v1",
                "aead_profile": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                "epoch": 7,
                "nonce": "AAAAAAAAAAAAAAAA",
                "ciphertext": "Q2lwaGVydGV4dFBsYWNlaG9sZGVy",
                "aad_digest": format!("sha256:{}", "0".repeat(64))
            },
            "proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:alice.example#ak:device:019f3b1c-76c8-7000-8000-000000000001",
                "envelope_digest": format!("sha256:{}", "0".repeat(64)),
                "created_at": "2026-07-07T00:00:00.000Z",
                "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
            }
        });

        super::attach_signal_proof_value(&mut envelope, &signing_key);

        let typed: arkret_wire::SignalEnvelope = serde_json::from_value(envelope).unwrap();
        typed.validate_structural().unwrap();
        arkret_signatures::proof::verify_ed25519_signal_proof(
            &typed,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: signing_key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();

        // The outer header must not be reconstructible into a product kind:
        // `signal_class` is the only classification a service sees.
        let wire = serde_json::to_value(&typed).unwrap();
        assert_eq!(wire["signal_class"], "session");
        assert!(wire.get("kind").is_none());
        assert!(wire.get("payload").is_none());
    }
}
