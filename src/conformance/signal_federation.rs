use anyhow::{Result, anyhow, bail};
use arkret_wire::{
    DeviceId, Did, Hash, MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES, MAX_SIGNAL_RELAY_ITEMS, ProfileId,
    RealmId, ScopeRef, SealId, SignalClass, SignalEncryptedPayload, SignalEnvelope, SignalKeyRef,
    SignalProof, SignalRelayOutcome, SignalRelayRequest,
};
use chrono::{Duration, TimeZone, Utc};
use serde_json::Value;

use super::{load_fixture_value, required_str, validate_profile};

const FIXTURE: &str = "signal-federation-fixture.json";

fn envelope() -> Result<SignalEnvelope> {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7")?;
    let sent_at = Utc
        .with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .ok_or_else(|| anyhow!("invalid fixture time"))?;
    let mut envelope = SignalEnvelope {
        realm_id: realm_id.clone(),
        scope_ref: ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        sender_actor_id: Did::new("did:webvh:z6mkfixture:alice.example")?,
        sender_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb")?,
        seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))?,
        signal_class: SignalClass::Session,
        sent_at,
        expires_at: sent_at + Duration::seconds(30),
        encrypted_payload: SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:01904100-0000-7000-8000-cccccccccccc".to_owned(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 7,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
            aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        },
        proof: SignalProof {
            kind: "DataIntegrityProof".to_owned(),
            verification_method: crate::fixture_did_url(
                "did:webvh:z6mkfixture:alice.example#device-key",
            ),
            alg: "EdDSA".to_owned(),
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: sent_at,
            domain: None,
            audience: None,
            jws: "a..b".to_owned(),
        },
    };
    envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest()?;
    envelope.proof.envelope_digest = envelope.envelope_digest()?;
    Ok(envelope)
}

pub fn run_signal_federation_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    validate_profile(&fixture, ProfileId::SIGNAL_PEER_RELAY_V1)?;
    if fixture.get("suite").and_then(Value::as_str) != Some("signal_peer_relay")
        || fixture.pointer("/runner/kind").and_then(Value::as_str) != Some("generated_limit_cases")
    {
        bail!("Signal federation fixture runner metadata drifted");
    }
    let signal = envelope()?;
    let request = SignalRelayRequest {
        realm_id: signal.realm_id.clone(),
        signals: vec![signal.clone()],
    };
    request.validate()?;
    SignalRelayOutcome::ACCEPTED.validate()?;
    if serde_json::to_value(SignalRelayOutcome::ACCEPTED)? != serde_json::json!({"accepted": true})
    {
        bail!("Signal relay outcome is not opaque");
    }

    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Signal federation fixture missing cases[]"))?;
    for case in cases {
        let generator = case
            .pointer("/input/generator")
            .or_else(|| case.pointer("/given_state/generator"))
            .ok_or_else(|| anyhow!("Signal federation case missing generator"))?;
        match required_str(generator, "kind")? {
            "signal_peer_relay_limit_matrix" => {
                let dimensions = generator["dimensions"]
                    .as_array()
                    .ok_or_else(|| anyhow!("Signal relay limit matrix missing dimensions"))?;
                let expected = [
                    ("signals", MAX_SIGNAL_RELAY_ITEMS as u64),
                    (
                        "canonical_body_bytes",
                        MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES as u64,
                    ),
                    ("signature_window_ms", 5_000),
                ];
                for (field, limit) in expected {
                    if !dimensions.iter().any(|dimension| {
                        dimension["field"].as_str() == Some(field)
                            && dimension["limit"].as_u64() == Some(limit)
                    }) {
                        bail!("Signal relay limit {field} drifted");
                    }
                }
                let oversized = SignalRelayRequest {
                    realm_id: signal.realm_id.clone(),
                    signals: vec![signal.clone(); MAX_SIGNAL_RELAY_ITEMS + 1],
                };
                if oversized.validate().is_ok() {
                    bail!("Signal relay accepted an oversized batch");
                }
            }
            "signal_peer_relay_request" => {
                if generator["same_realm"].as_bool() == Some(false) {
                    let other = RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d8")?;
                    let cross_realm = SignalRelayRequest {
                        realm_id: other,
                        signals: vec![signal.clone()],
                    };
                    if cross_realm.validate().is_ok() {
                        bail!("Signal relay accepted a cross-Realm request");
                    }
                }
            }
            "signal_peer_relay_equivalence_pair"
            | "signal_peer_relay_uncertain_outcome"
            | "signal_peer_relay_mutations" => {}
            other => bail!("unknown Signal federation generator {other}"),
        }
    }
    Ok(())
}
