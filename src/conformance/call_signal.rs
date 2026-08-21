//! `ak.call.signal` receiver-side conformance vectors
//! (`crypto-media/webrtc-signaling.md` §5).
//!
//! Call signaling rides the encrypted-only Signal rail. The outer envelope
//! exposes nothing but `signal_class`; `call_id`, `signal_kind`, `seq`, SDP
//! and ICE candidates all live inside `encrypted_payload`, and the service
//! must neither see nor route on them. Every receiver check therefore happens
//! after decryption — except the ones the outer envelope itself carries
//! (device proof, TTL class ceiling, AAD binding), which run *before* any
//! ringing or candidate application.
//!
//! Registered vector ids:
//! - `ak.vector.call_signal.signal_kind_enum.v1`
//! - `ak.vector.call_signal.seq_monotonic.v1`
//! - `ak.vector.call_signal.proof_detached_jws.v1`
//! - `ak.vector.call_signal.outer_metadata_minimal.v1`

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use arkret_identifiers::{CallId, DeviceId, DidCoreId, Hash, RealmId};
use arkret_models_collaboration::call_signal::CallSignalPlaintext;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::proof::verify_ed25519_signal_proof;
use arkret_wire::signal::{SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME};
use arkret_wire::{
    ScopeRef, SealId, SignalClass, SignalEncryptedPayload, SignalEnvelope, SignalKeyRef,
    SignalProof,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

pub const VECTOR_ID_SIGNAL_KIND_ENUM: &str = "ak.vector.call_signal.signal_kind_enum.v1";
pub const VECTOR_ID_SEQ_MONOTONIC: &str = "ak.vector.call_signal.seq_monotonic.v1";
pub const VECTOR_ID_PROOF_DETACHED_JWS: &str = "ak.vector.call_signal.proof_detached_jws.v1";
pub const VECTOR_ID_OUTER_METADATA_MINIMAL: &str =
    "ak.vector.call_signal.outer_metadata_minimal.v1";
pub const VECTOR_ID_PLAINTEXT_CLOSED_SCHEMA: &str =
    "ak.vector.call_signal.plaintext_closed_schema.v1";

pub const ALL_CALL_SIGNAL_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_SIGNAL_KIND_ENUM,
    VECTOR_ID_SEQ_MONOTONIC,
    VECTOR_ID_PROOF_DETACHED_JWS,
    VECTOR_ID_OUTER_METADATA_MINIMAL,
    VECTOR_ID_PLAINTEXT_CLOSED_SCHEMA,
];

const CALL_SIGNAL_KINDS: &[&str] = &[
    "invite",
    "answer",
    "candidate",
    "renegotiate",
    "hangup",
    "ack",
    "reject",
    "mute_state",
    "media_state",
    "speaking",
    "focus_join",
    "focus_leave",
    "moderation",
    "error",
];

// ─── VECT-CS-1 — signal_kind_enum (canonical 14-value set) ─────────────────

/// The receiver MUST accept exactly the §5 14-value enum and MUST reject the
/// retired non-spec types (`offer` / `ice` / `device_change`) the old soland
/// stack used. `signal_kind` is a *decrypted plaintext* field: the check runs
/// on the plaintext object, never on the outer header.
pub fn run_signal_kind_enum_vector() -> Result<()> {
    if CALL_SIGNAL_KINDS.len() != 14 {
        bail!(
            "CALL_SIGNAL_KINDS drifted: expected 14 values, got {}",
            CALL_SIGNAL_KINDS.len()
        );
    }
    for expected in [
        "invite",
        "answer",
        "candidate",
        "renegotiate",
        "hangup",
        "ack",
        "reject",
        "mute_state",
        "media_state",
        "speaking",
        "focus_join",
        "focus_leave",
        "moderation",
        "error",
    ] {
        if !CALL_SIGNAL_KINDS.contains(&expected) {
            bail!("canonical signal_kind `{expected}` missing from CALL_SIGNAL_KINDS");
        }
    }
    for retired in ["offer", "ice", "device_change"] {
        if CALL_SIGNAL_KINDS.contains(&retired) {
            bail!("retired non-spec signal_kind `{retired}` leaked into CALL_SIGNAL_KINDS");
        }
        if decode_call_signal_plaintext(&call_signal_plaintext(retired, 1)).is_ok() {
            bail!("receiver accepted a retired signal_kind `{retired}` — must be rejected");
        }
    }
    decode_call_signal_plaintext(&call_signal_plaintext("invite", 1))
        .map_err(|err| anyhow!("canonical invite plaintext must validate: {err}"))?;
    Ok(())
}

/// The decrypted call plaintext is a closed SDK-owned schema. In particular,
/// `payload_sequence` and the per-call `seq` are independent required axes.
pub fn run_plaintext_closed_schema_vector() -> Result<()> {
    let valid = call_signal_plaintext("candidate", 3);
    let decoded = decode_call_signal_plaintext(&valid)?;
    if decoded.payload_sequence != 11 || decoded.seq != 3 {
        bail!("call signal sequence axes did not survive SDK decoding");
    }

    for required in ["data", "payload_sequence"] {
        let mut missing = valid.clone();
        missing
            .as_object_mut()
            .expect("fixture is an object")
            .remove(required);
        if decode_call_signal_plaintext(&missing).is_ok() {
            bail!("call signal plaintext without required `{required}` was accepted");
        }
    }

    let mut extra = valid;
    extra["actor_id"] = json!("did:web:leaked.example");
    if decode_call_signal_plaintext(&extra).is_ok() {
        bail!("call signal plaintext accepted an unknown top-level field");
    }
    Ok(())
}

// ─── VECT-CS-2 — seq_monotonic (receiver-side rollback rejection) ──────────

/// `seq` is strictly increasing per `(realm_id, call_id, actor_id, device_id)`
/// (§5). The receiver MUST accept an ascending stream and MUST drop a rollback
/// or a repeat. The frontier is not advanced by a dropped frame.
pub fn run_seq_monotonic_vector() -> Result<()> {
    let mut frontier: BTreeMap<CallSignalSeqKey, u64> = BTreeMap::new();
    let key = CallSignalSeqKey {
        realm_id: RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")?,
        call_id: CallId::new("ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz")?,
        actor_id: DidCoreId::new("ak:did_core:web:alice.example.com")?,
        device_id: DeviceId::new("ak:device:01964137-0000-7000-8000-000000000000")?,
    };

    observe_seq(&mut frontier, &key, 1)
        .map_err(|err| anyhow!("first observation must accept: {err}"))?;
    observe_seq(&mut frontier, &key, 2).map_err(|err| anyhow!("ascending must accept: {err}"))?;
    if observe_seq(&mut frontier, &key, 2).is_ok() {
        bail!("repeat seq (2 after 2) must be rejected as a rollback");
    }
    if observe_seq(&mut frontier, &key, 1).is_ok() {
        bail!("rollback seq (1 after 2) must be rejected");
    }
    // The dropped frames must not have moved the frontier: a fresh 3 advances.
    observe_seq(&mut frontier, &key, 3)
        .map_err(|err| anyhow!("seq 3 after dropped rollbacks must accept: {err}"))?;

    // The key is a four-tuple: the same seq on a different device is a
    // different stream and must not be suppressed by the first device's
    // frontier.
    let sibling = CallSignalSeqKey {
        device_id: DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001")?,
        ..key.clone()
    };
    observe_seq(&mut frontier, &sibling, 1)
        .map_err(|err| anyhow!("a sibling device's stream must have its own frontier: {err}"))?;
    Ok(())
}

// ─── VECT-CS-3 — proof_detached_jws (REAL ed25519 round-trip) ──────────────

/// Build a call-signal [`SignalEnvelope`] exactly as a sender does, sign it
/// with a real ed25519 key under the `ak.signal-proof-v1` transcript, and
/// verify it through the SDK receiver path.
///
/// The transcript commits to `envelope_digest` — the envelope with `proof`
/// removed — and therefore to the ciphertext and `aad_digest` as well as the
/// header, so a signature minted on the Event rail can never be replayed here
/// and tampering with any covered field breaks verification.
pub fn run_proof_detached_jws_vector() -> Result<()> {
    let signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
    let public = PublicKeyMaterial::Ed25519Raw {
        bytes: signing_key.verifying_key().to_bytes().to_vec(),
    };
    let envelope = signed_call_signal_envelope(SignalClass::Setup, 120, &signing_key)?;

    envelope
        .validate_structural()
        .map_err(|err| anyhow!("a canonical call-signal envelope must validate: {err}"))?;
    verify_ed25519_signal_proof(&envelope, &public)
        .map_err(|err| anyhow!("the sender-style signal proof MUST verify: {err}"))?;

    // Negative: tampering the ciphertext changes `envelope_digest`, so the
    // envelope no longer validates against its own proof.
    let mut tampered = envelope.clone();
    tampered.encrypted_payload.ciphertext = "VGFtcGVyZWQ".to_owned();
    if tampered.validate_structural().is_ok() {
        bail!("a tampered ciphertext still matched the recorded envelope_digest");
    }

    // Negative: rewriting an outer header field breaks the AAD binding, which
    // is what stops a relay from re-scoping a signal it cannot decrypt.
    let mut rescoped = envelope.clone();
    rescoped.signal_class = SignalClass::Session;
    if rescoped.validate_structural().is_ok() {
        bail!("a rewritten signal_class still matched the recorded aad_digest");
    }

    // Negative: a wrong key MUST NOT verify.
    let wrong = PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&[0x99u8; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    if verify_ed25519_signal_proof(&envelope, &wrong).is_ok() {
        bail!("proof verified under the wrong public key — signature is not actually checked");
    }
    Ok(())
}

// ─── VECT-CS-4 — outer_metadata_minimal ────────────────────────────────────

/// §5 / `signal.md` §6: the outer envelope must expose no product
/// classification beyond `signal_class`. An `invite`, which needs a wake-up,
/// takes `setup`; ordinary frames take `session`; and the class TTL ceilings
/// are enforced on the outer envelope alone.
pub fn run_outer_metadata_minimal_vector() -> Result<()> {
    let signing_key = SigningKey::from_bytes(&[0x44u8; 32]);
    let envelope = signed_call_signal_envelope(SignalClass::Setup, 120, &signing_key)?;
    let wire = serde_json::to_value(&envelope)?;
    let object = wire
        .as_object()
        .ok_or_else(|| anyhow!("signal envelope must serialise as an object"))?;

    for leaked in ["signal_kind", "call_id", "strand_id", "kind", "payload"] {
        if object.contains_key(leaked) {
            bail!("outer call-signal envelope leaked `{leaked}` — metadata minimisation violated");
        }
    }
    if object.get("signal_class").and_then(Value::as_str) != Some("setup") {
        bail!("an invite-bearing envelope must be classified `setup` for wake-up");
    }

    // `session` tops out at 30 seconds; the `setup` TTL above it must not be
    // reachable by relabelling the class.
    let over_ttl = signed_call_signal_envelope(SignalClass::Session, 120, &signing_key)?;
    let error = over_ttl
        .validate_structural()
        .err()
        .ok_or_else(|| anyhow!("a 120s `session` signal must exceed the class TTL ceiling"))?;
    if !format!("{error}").contains("signal_ttl_out_of_range") {
        bail!("class TTL overflow must report signal_ttl_out_of_range, got: {error}");
    }
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────────

/// Receiver-side de-duplication key for call signaling (§5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CallSignalSeqKey {
    realm_id: RealmId,
    call_id: CallId,
    actor_id: DidCoreId,
    device_id: DeviceId,
}

fn observe_seq(
    frontier: &mut BTreeMap<CallSignalSeqKey, u64>,
    key: &CallSignalSeqKey,
    seq: u64,
) -> Result<()> {
    if let Some(previous) = frontier.get(key)
        && seq <= *previous
    {
        bail!("call signal seq {seq} does not advance the frontier {previous}");
    }
    frontier.insert(key.clone(), seq);
    Ok(())
}

/// The closed decrypted plaintext object of §5.
fn call_signal_plaintext(signal_kind: &str, seq: u64) -> Value {
    let data = match signal_kind {
        "invite" => json!({
            "lifetime_ms": 60_000,
            "offer": {
                "type": "offer",
                "sdp": "v=0"
            },
            "media": {
                "audio": true,
                "video": false
            }
        }),
        "candidate" => json!({ "candidates": [] }),
        _ => json!({}),
    };
    json!({
        "kind": "ak.call.signal",
        "payload_sequence": 11,
        "call_id": "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        "signal_kind": signal_kind,
        "seq": seq,
        "data": data
    })
}

fn decode_call_signal_plaintext(plaintext: &Value) -> Result<CallSignalPlaintext> {
    serde_json::from_value(plaintext.clone()).map_err(Into::into)
}

fn sent_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 4, 26, 0, 0, 0)
        .single()
        .expect("static fixture instant is unambiguous")
}

/// A fully signed call-signal envelope. The ciphertext is opaque to this
/// vector on purpose: every assertion here is about what a receiver can decide
/// from the outer envelope, which is exactly the boundary §5 draws.
fn signed_call_signal_envelope(
    signal_class: SignalClass,
    ttl_seconds: i64,
    signing_key: &SigningKey,
) -> Result<SignalEnvelope> {
    let realm_id = RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")?;
    let actor_id = DidCoreId::new("ak:did_core:web:alice.example.com")?;
    let device_id = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000000")?;
    let mut envelope = SignalEnvelope {
        realm_id: realm_id.clone(),
        scope_ref: ScopeRef::Realm { realm_id },
        sender_actor_id: actor_id.clone(),
        sender_device_id: device_id.clone(),
        seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))?,
        signal_class,
        sent_at: sent_at(),
        expires_at: sent_at() + Duration::seconds(ttl_seconds),
        encrypted_payload: SignalEncryptedPayload {
            scheme: SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:AXehYOgO_p3M5hbOzs6Mhblqek3i9nwaGUec3J9_89_C".to_owned(),
            },
            purpose: SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 7,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
            aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        },
        proof: SignalProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: crate::fixture_did_url(format!(
                "did:web:alice.example.com#{device_id}"
            )),
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: sent_at(),
            domain: None,
            audience: None,
            jws: String::new(),
        },
    };
    crate::harness::attach_signal_proof(&mut envelope, signing_key);
    Ok(envelope)
}

/// Suite entry point — runs all call-signal receiver vectors back to back.
pub fn run_call_signal_vector_suite() -> Result<()> {
    if ALL_CALL_SIGNAL_VECTOR_IDS.len() != 5 {
        bail!(
            "expected 4 call_signal vector ids, got {}",
            ALL_CALL_SIGNAL_VECTOR_IDS.len()
        );
    }
    run_signal_kind_enum_vector()?;
    run_seq_monotonic_vector()?;
    run_proof_detached_jws_vector()?;
    run_outer_metadata_minimal_vector()?;
    run_plaintext_closed_schema_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_signal_receiver_vectors_run_clean() {
        run_call_signal_vector_suite().unwrap();
    }
}
