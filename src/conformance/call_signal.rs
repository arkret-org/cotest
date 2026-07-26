//! `ak.call.signal` receiver-side conformance vectors (webrtc-signaling.md §5.1).
//!
//! The retired soland WebRTC session stack enforced `seq` monotonicity and
//! accepted non-spec signal types (`offer` / `ice` / `device_change`)
//! server-side. The canonical `POST /_arkret/self/ephemeral` relay is
//! content-agnostic — it broadcasts the verbatim signed envelope — and the
//! *receiver* enforces both the canonical signal_kind enum and `seq`
//! monotonicity (§5.1). These vectors drive the real SDK surfaces a receiver
//! runs, plus a REAL ed25519 detached-JWS round-trip proving the proof the
//! cotest e2e helper mints (`e2e/helpers/webrtc.ts buildCallSignalEnvelope`) is
//! genuinely verifiable, not a shape stub.
//!
//! Registered vector ids:
//! - `ak.vector.call_signal.signal_kind_enum.v1`
//! - `ak.vector.call_signal.seq_monotonic.v1`
//! - `ak.vector.call_signal.proof_detached_jws.v1`

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::events_payloads::ephemeral::{
    CallSignalSeqKey, CallSignalState, EphemeralEnvelope, validate_call_signal_envelope,
    validate_signal_seq,
};
use arkret_signatures::{PublicKeyMaterial, verify_eddsa_detached_jws_proof};
use arkret_wire::{CALL_SIGNAL_KINDS, Proof};
use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

pub const VECTOR_ID_SIGNAL_KIND_ENUM: &str = "ak.vector.call_signal.signal_kind_enum.v1";
pub const VECTOR_ID_SEQ_MONOTONIC: &str = "ak.vector.call_signal.seq_monotonic.v1";
pub const VECTOR_ID_PROOF_DETACHED_JWS: &str = "ak.vector.call_signal.proof_detached_jws.v1";

pub const ALL_CALL_SIGNAL_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_SIGNAL_KIND_ENUM,
    VECTOR_ID_SEQ_MONOTONIC,
    VECTOR_ID_PROOF_DETACHED_JWS,
];

// ─── VECT-CS-1 — signal_kind_enum (canonical 14-value set) ─────────────────

/// The receiver MUST accept exactly the spec 14-value enum and MUST reject the
/// retired non-spec types (`offer` / `ice` / `device_change`) the old soland
/// stack used.
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
    // The retired non-spec types MUST NOT be canonical, and an envelope carrying
    // one MUST be rejected by the receiver-side validator.
    for retired in ["offer", "ice", "device_change"] {
        if CALL_SIGNAL_KINDS.contains(&retired) {
            bail!("retired non-spec signal_kind `{retired}` leaked into CALL_SIGNAL_KINDS");
        }
        let env = call_signal_envelope_value(retired, 1);
        let parsed: EphemeralEnvelope = serde_json::from_value(env)
            .map_err(|err| anyhow!("envelope deserialise failed: {err}"))?;
        if validate_call_signal_envelope(&parsed).is_ok() {
            bail!("receiver accepted a retired signal_kind `{retired}` — must be rejected");
        }
    }
    // A canonical envelope validates.
    let ok_env = call_signal_envelope_value("invite", 1);
    let parsed: EphemeralEnvelope = serde_json::from_value(ok_env)
        .map_err(|err| anyhow!("canonical envelope deserialise failed: {err}"))?;
    validate_call_signal_envelope(&parsed)
        .map_err(|err| anyhow!("canonical invite envelope must validate: {err}"))?;
    Ok(())
}

// ─── VECT-CS-2 — seq_monotonic (receiver-side rollback rejection) ──────────

/// `seq` is monotonic per `(realm_id, call_id, actor_id, device_id)`. The
/// receiver MUST accept a strictly-increasing stream and MUST drop a rollback
/// (`next <= prev`). Pins both the bare `validate_signal_seq` predicate and the
/// stateful `CallSignalState` reducer.
pub fn run_seq_monotonic_vector() -> Result<()> {
    // Bare predicate.
    validate_signal_seq(None, 7).map_err(|e| anyhow!("first observation must accept: {e}"))?;
    validate_signal_seq(Some(1), 2).map_err(|e| anyhow!("ascending must accept: {e}"))?;
    if validate_signal_seq(Some(2), 2).is_ok() {
        bail!("repeat seq (2 after 2) must be rejected as a rollback");
    }
    if validate_signal_seq(Some(2), 1).is_ok() {
        bail!("rollback seq (1 after 2) must be rejected");
    }

    // Stateful reducer over the [1, 2, 1] stream the e2e relay delivers
    // verbatim: the trailing 1 is the only rejection.
    let key = CallSignalSeqKey::new(
        arkret_identifiers::RealmId::new(
            "ak:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
        )
        .map_err(|e| anyhow!("realm id: {e}"))?,
        arkret_identifiers::CallId::new("ak:call:0196441c-0000-7000-8000-000000000000".to_owned())
            .map_err(|e| anyhow!("call id: {e}"))?,
        arkret_identifiers::Did::new("did:web:alice.example.com".to_owned())
            .map_err(|e| anyhow!("did: {e}"))?,
        arkret_identifiers::DeviceId::new(
            "ak:device:01964137-0000-7000-8000-000000000000".to_owned(),
        )
        .map_err(|e| anyhow!("device id: {e}"))?,
    );
    let mut state = CallSignalState::new();
    state
        .observe(&key, 1)
        .map_err(|e| anyhow!("seq 1 must accept: {e}"))?;
    state
        .observe(&key, 2)
        .map_err(|e| anyhow!("seq 2 must accept: {e}"))?;
    if state.observe(&key, 1).is_ok() {
        bail!("rollback seq 1 after 2 must be dropped by the stateful receiver");
    }
    // After dropping the rollback the frontier is still 2; a fresh 3 advances.
    state
        .observe(&key, 3)
        .map_err(|e| anyhow!("seq 3 after dropped rollback must accept: {e}"))?;
    Ok(())
}

// ─── VECT-CS-3 — proof_detached_jws (REAL ed25519 round-trip) ──────────────

/// Build a `ak.call.signal` envelope + proof EXACTLY as the cotest e2e helper
/// (`buildCallSignalEnvelope`) does — canonical `event_digest` over the
/// envelope-without-proof, JWS transcript over the §5.1 binding object — sign
/// with a real ed25519 key, then verify with the SDK's
/// `verify_eddsa_detached_jws_proof`. This proves the e2e helper mints a
/// genuinely receiver-verifiable proof, not a placeholder string.
pub fn run_proof_detached_jws_vector() -> Result<()> {
    let actor_id = "did:web:alice.example.com";
    let verification_method = format!("{actor_id}#device");
    let signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
    let public = PublicKeyMaterial::Ed25519Raw {
        bytes: signing_key.verifying_key().to_bytes().to_vec(),
    };

    // 1. Envelope without proof.
    let created_at = Utc.with_ymd_and_hms(2026, 4, 26, 0, 0, 0).unwrap();
    let sent_at_str = arkret_canonical::format_timestamp_canonical(created_at);
    let mut envelope = json!({
        "kind": "ak.call.signal",
        "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
        "actor_id": actor_id,
        "device_id": "ak:device:01964137-0000-7000-8000-000000000000",
        "sent_at": &sent_at_str,
        "expires_at": arkret_canonical::format_timestamp_canonical(
            Utc.with_ymd_and_hms(2026, 4, 26, 0, 0, 30).unwrap()
        ),
        "payload": {
            "call_id": "ak:call:0196441c-0000-7000-8000-000000000000",
            "signal_kind": "invite",
            "seq": 12,
            "data": {}
        }
    });

    // 2. event_digest = sha256: || hex(sha256(JCS(envelope_without_proof))).
    let canonical_bytes = arkret_canonical::canonical_json_bytes(&envelope)
        .map_err(|err| anyhow!("envelope JCS failed: {err}"))?;
    let event_digest = arkret_canonical::sha256_digest(&canonical_bytes);

    // 3. JWS transcript = protected `.` base64url(SDK canonical proof binding). The SDK is the only
    //    implementation of the binding object and its timestamp projection; cotest deliberately
    //    does not duplicate it.
    // SDK-canonical protected header is EXACTLY `{"alg":"EdDSA"}` — the
    // verifier deserialises it with deny-unknown-fields, so a `kid` (or any
    // extra member) breaks verification. The verification_method is carried in
    // the proof object + binding, not the header.
    let header = json!({ "alg": "EdDSA" });
    let header_b64 = b64url(
        &arkret_canonical::canonical_json_bytes(&header)
            .map_err(|err| anyhow!("header JCS failed: {err}"))?,
    );
    let did = arkret_identifiers::Did::new(actor_id.to_owned()).map_err(|e| anyhow!("did: {e}"))?;
    let mut proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: verification_method.clone(),
        event_digest: arkret_identifiers::Hash::new(event_digest.clone())
            .map_err(|err| anyhow!("event digest: {err}"))?,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding_b64 = b64url(
        &proof
            .canonical_binding_bytes(&did)
            .map_err(|err| anyhow!("SDK proof binding failed: {err}"))?,
    );
    let signing_input = format!("{header_b64}.{binding_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    proof.jws = format!("{header_b64}..{}", b64url(&signature.to_bytes()));
    envelope["proof"] =
        serde_json::to_value(&proof).map_err(|err| anyhow!("proof serialisation failed: {err}"))?;

    // 4. Verify via the SDK receiver path. `canonical_bytes` is the envelope-without-proof (the
    //    verifier recomputes event_digest from it).
    verify_eddsa_detached_jws_proof(&proof, &canonical_bytes, &did, &public)
        .map_err(|err| anyhow!("the e2e-style detached-JWS proof MUST verify: {err}"))?;

    // Negative: tampering the payload (which changes the canonical bytes /
    // event_digest) MUST break verification — proving the proof covers the
    // envelope, not merely a shape.
    let mut tampered_env = envelope.clone();
    tampered_env["payload"]["seq"] = json!(99);
    let tampered_bytes = arkret_canonical::canonical_json_bytes(&{
        let mut v = tampered_env.clone();
        v.as_object_mut().unwrap().remove("proof");
        v
    })
    .map_err(|err| anyhow!("tampered JCS failed: {err}"))?;
    if verify_eddsa_detached_jws_proof(&proof, &tampered_bytes, &did, &public).is_ok() {
        bail!("proof verified against tampered envelope bytes — event_digest binding is broken");
    }

    // Negative: a wrong key MUST NOT verify.
    let wrong = PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&[0x99u8; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    if verify_eddsa_detached_jws_proof(&proof, &canonical_bytes, &did, &wrong).is_ok() {
        bail!("proof verified under the wrong public key — signature is not actually checked");
    }
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────────

fn call_signal_envelope_value(signal_kind: &str, seq: u64) -> Value {
    json!({
        "kind": "ak.call.signal",
        "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
        "actor_id": "did:web:alice.example.com",
        "device_id": "ak:device:01964137-0000-7000-8000-000000000000",
        "sent_at": "2026-04-26T00:00:00.000Z",
        "expires_at": "2026-04-26T00:00:30.000Z",
        "payload": {
            "call_id": "ak:call:0196441c-0000-7000-8000-000000000000",
            "signal_kind": signal_kind,
            "seq": seq,
            "data": {}
        },
        "proof": {
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example.com#device",
            "event_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": "2026-04-26T00:00:00.000Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
        }
    })
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Suite entry point — runs all 3 call-signal receiver vectors back to back.
pub fn run_call_signal_vector_suite() -> Result<()> {
    if ALL_CALL_SIGNAL_VECTOR_IDS.len() != 3 {
        bail!(
            "expected 3 call_signal vector ids, got {}",
            ALL_CALL_SIGNAL_VECTOR_IDS.len()
        );
    }
    run_signal_kind_enum_vector()?;
    run_seq_monotonic_vector()?;
    run_proof_detached_jws_vector()?;
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
