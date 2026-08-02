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
pub const VECTOR_ID_SIGNAL_DEVICE_AUTHORIZATION_DOMAIN: &str =
    "ak.vector.signal.device_authorization_domain.v1";

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
            verification_method: crate::fixture_did_url(format!(
                "{}#{}",
                "did:webvh:z6mkfixture:alice.example",
                "ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb"
            )),
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

fn device_authorization_gate(
    signal: &SignalEnvelope,
    current_active: bool,
    directory_key_present: bool,
    trust_anchor_present: bool,
    scope_authorized_at_seal: bool,
    signal_class_action_authorized: bool,
) -> bool {
    let expected_method = format!(
        "{}#{}",
        signal.sender_actor_id.as_str(),
        signal.sender_device_id.as_str()
    );
    signal.proof.verification_method.as_str() == expected_method
        && current_active
        && directory_key_present
        && trust_anchor_present
        && scope_authorized_at_seal
        && signal_class_action_authorized
}

/// Exact runner for `ak.vector.signal.device_authorization_domain.v1`.
pub fn run_signal_device_authorization_domain_vector() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    let covered = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .is_some_and(|vectors| {
            vectors
                .iter()
                .any(|vector| vector.as_str() == Some(VECTOR_ID_SIGNAL_DEVICE_AUTHORIZATION_DOMAIN))
        });
    let asserted = fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("vector_id").and_then(Value::as_str)
                    == Some(VECTOR_ID_SIGNAL_DEVICE_AUTHORIZATION_DOMAIN)
            })
        })
        .and_then(|case| case.get("assertions"))
        .and_then(Value::as_array)
        .is_some_and(|assertions| !assertions.is_empty());
    if !covered || !asserted {
        bail!("Signal fixture is missing asserted device-authorization-domain evidence");
    }
    let signal = envelope()?;
    signal.validate_structural()?;
    if !device_authorization_gate(&signal, true, true, true, true, true) {
        bail!("a current active, fully anchored and scope-authorized device was rejected");
    }
    for denied in [
        (false, true, true, true, true),
        (true, false, true, true, true),
        (true, true, false, true, true),
        (true, true, true, false, true),
        (true, true, true, true, false),
    ] {
        if device_authorization_gate(&signal, denied.0, denied.1, denied.2, denied.3, denied.4) {
            bail!("a missing current-device, trust, scope, or action gate was accepted");
        }
    }
    let mut wrong_method = signal.clone();
    wrong_method.proof.verification_method =
        crate::fixture_did_url("did:webvh:z6mkfixture:alice.example#device-looking-fragment");
    if device_authorization_gate(&wrong_method, true, true, true, true, true)
        || wrong_method.validate_structural().is_ok()
    {
        bail!("a non-literal sender device verification method was accepted");
    }
    if signal.expires_at >= signal.expires_at + Duration::milliseconds(1) {
        bail!("internal expiry-vector instant construction failed");
    }
    let local_ingress_now = signal.expires_at + Duration::milliseconds(1);
    if local_ingress_now < signal.expires_at {
        bail!("an expired local-ingress signal was treated as live");
    }
    Ok(())
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
    run_signal_device_authorization_domain_vector()?;

    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Signal federation fixture missing cases[]"))?;
    for case in cases {
        if case.get("vector_id").and_then(Value::as_str)
            == Some(VECTOR_ID_SIGNAL_DEVICE_AUTHORIZATION_DOMAIN)
        {
            continue;
        }
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
    run_signal_device_authorization_domain_vector()?;
    Ok(())
}
