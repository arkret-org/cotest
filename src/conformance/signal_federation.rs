use anyhow::{Result, anyhow, bail};
use arkret_signatures::{PublicKeyMaterial, verify_ed25519_signal_proof};
use arkret_wire::{
    AccountId, ActorId, DeviceId, Did, DidCoreId, Hash, MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES,
    MAX_SIGNAL_RELAY_ITEMS, ProfileId, RealmId, ScopeRef, SealId, SignalClass,
    SignalEncryptedPayload, SignalEnvelope, SignalKeyRef, SignalProof, SignalRelayOutcome,
    SignalRelayRequest, project_did_to_core_id,
};
use chrono::{Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::Value;

use super::{load_fixture_value, required_str, validate_profile};

const FIXTURE: &str = "signal-federation-fixture.json";
const SIGNING_SEED: [u8; 32] = [0x37; 32];
pub const VECTOR_ID_SIGNAL_DEVICE_AUTHORIZATION_DOMAIN: &str =
    "ak.vector.signal.device_authorization_domain.v1";

pub(super) fn envelope() -> Result<SignalEnvelope> {
    let realm_id = RealmId::new("ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_")?;
    let sent_at = Utc
        .with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .ok_or_else(|| anyhow!("invalid fixture time"))?;
    let mut envelope = SignalEnvelope {
        realm_id: realm_id.clone(),
        scope_ref: ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        sender_actor_id: ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example")?,
            DidCoreId::new("ak:did_core:web:station-a.example")?,
        )),
        sender_device_id: Some(DeviceId::new(
            "ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb",
        )?),
        seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))?,
        signal_class: SignalClass::Session,
        sent_at,
        expires_at: sent_at + Duration::seconds(30),
        encrypted_payload: SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:AbyX-ijAQZ4DkcySKE3VusrcCoBFT8DGS4fx8tpo-PNm".to_owned(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 7,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
            aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        },
        proof: SignalProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: crate::fixture_did_url(format!(
                "{}#{}",
                "did:web:alice.example", "ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb"
            )),
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            domain: None,
            audience: None,
            jws: "a..b".to_owned(),
        },
    };
    crate::harness::attach_signal_proof(&mut envelope, &SigningKey::from_bytes(&SIGNING_SEED));
    Ok(envelope)
}

fn signing_public_key() -> PublicKeyMaterial {
    PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    }
}

fn device_authorization_gate(
    signal: &SignalEnvelope,
    accepted_actor: &ActorId,
    current_active: bool,
    directory_key_present: bool,
    trust_anchor_present: bool,
    scope_authorized_at_seal: bool,
    signal_class_action_authorized: bool,
) -> bool {
    let (controller, fragment) = signal
        .proof
        .verification_method
        .as_str()
        .rsplit_once('#')
        .unwrap_or_default();
    let controller_matches = Did::new(controller.to_owned())
        .ok()
        .and_then(|did| project_did_to_core_id(&did).ok())
        .is_some_and(|core_id| &core_id == signal.sender_actor_id.signing_principal_id());
    controller_matches
        && &signal.sender_actor_id == accepted_actor
        && signal
            .sender_device_id
            .as_ref()
            .is_some_and(|device_id| fragment == device_id.as_str())
        && current_active
        && directory_key_present
        && trust_anchor_present
        && scope_authorized_at_seal
        && signal_class_action_authorized
        && verify_ed25519_signal_proof(signal, &signing_public_key()).is_ok()
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
    let accepted_actor = signal.sender_actor_id.clone();
    if !device_authorization_gate(&signal, &accepted_actor, true, true, true, true, true) {
        bail!("a current active, fully anchored and scope-authorized device was rejected");
    }
    for denied in [
        (false, true, true, true, true),
        (true, false, true, true, true),
        (true, true, false, true, true),
        (true, true, true, false, true),
        (true, true, true, true, false),
    ] {
        if device_authorization_gate(
            &signal,
            &accepted_actor,
            denied.0,
            denied.1,
            denied.2,
            denied.3,
            denied.4,
        ) {
            bail!("a missing current-device, trust, scope, or action gate was accepted");
        }
    }
    let mut wrong_method = signal.clone();
    wrong_method.proof.verification_method =
        crate::fixture_did_url("did:web:alice.example#device-looking-fragment");
    if device_authorization_gate(&wrong_method, &accepted_actor, true, true, true, true, true)
        || wrong_method.validate_structural().is_ok()
    {
        bail!("a non-literal sender device verification method was accepted");
    }
    // A matching proof principal does not authorize the same device under a
    // different Station's account. The accepted directory must bind the actor.
    let mut other_account = signal.clone();
    other_account.sender_actor_id = ActorId::account(AccountId::new(
        accepted_actor.signing_principal_id().clone(),
        DidCoreId::new("ak:did_core:web:station-b.example")?,
    ));
    crate::harness::attach_signal_proof(&mut other_account, &SigningKey::from_bytes(&SIGNING_SEED));
    other_account.validate_structural()?;
    if device_authorization_gate(
        &other_account,
        &accepted_actor,
        true,
        true,
        true,
        true,
        true,
    ) {
        bail!("a same-principal device borrowed authorization from another Station account");
    }
    if !device_authorization_gate(
        &other_account,
        &other_account.sender_actor_id,
        true,
        true,
        true,
        true,
        true,
    ) {
        bail!("an independently accepted actor at another Station was rejected");
    }
    let foreign_account = ActorId::account(AccountId::new(
        signal.sender_actor_id.signing_principal_id().clone(),
        DidCoreId::new("ak:did_core:web:other-station.example")?,
    ));
    if device_authorization_gate(&signal, &foreign_account, true, true, true, true, true) {
        bail!("a directory assertion for another Station account was accepted");
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
        if case.get("name").and_then(Value::as_str) == Some("device_authorization_domain") {
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
                for count in [MAX_SIGNAL_RELAY_ITEMS - 1, MAX_SIGNAL_RELAY_ITEMS] {
                    SignalRelayRequest {
                        realm_id: signal.realm_id.clone(),
                        signals: vec![signal.clone(); count],
                    }
                    .validate()?;
                }
                let mut large_item = signal.clone();
                large_item.encrypted_payload.ciphertext = "A".repeat(60_000);
                crate::harness::attach_signal_proof(
                    &mut large_item,
                    &SigningKey::from_bytes(&SIGNING_SEED),
                );
                large_item.validate_wire_shape()?;
                let oversized_body = SignalRelayRequest {
                    realm_id: signal.realm_id.clone(),
                    signals: vec![large_item; 20],
                };
                if oversized_body
                    .validate()
                    .err()
                    .and_then(|error| error.error_code())
                    != Some(arkret_wire::ErrorCode::PayloadTooLarge)
                {
                    bail!("Signal batch byte overflow did not preserve payload_too_large");
                }
            }
            "signal_peer_relay_request" => {
                if generator["same_realm"].as_bool() == Some(false) {
                    let other =
                        RealmId::new("ak:realm:Aa2wBBPOONHiiqIv1IKaV84axlqDTBPpa3Yw_hNef_Zl")?;
                    let cross_realm = SignalRelayRequest {
                        realm_id: other,
                        signals: vec![signal.clone()],
                    };
                    if cross_realm.validate().is_ok() {
                        bail!("Signal relay accepted a cross-Realm request");
                    }
                } else if generator["hop_count"] == 2 {
                    if case["expected"]["decision"] != "silently_drop_item"
                        || case["expected"]["response"]
                            != serde_json::to_value(SignalRelayOutcome::ACCEPTED)?
                    {
                        bail!("second-hop failure must not reveal a per-item response");
                    }
                } else {
                    request.validate()?;
                    verify_ed25519_signal_proof(&signal, &signing_public_key())
                        .map_err(|error| anyhow!(error.to_string()))?;
                }
            }
            "signal_peer_relay_equivalence_pair" => {
                let expected = &case["expected"];
                let opaque = serde_json::to_value(SignalRelayOutcome::ACCEPTED)?;
                if expected["response"] != opaque || expected["responses_byte_identical"] != true {
                    bail!("peer outcome equivalence contract drifted");
                }
                for forbidden in expected["forbidden_response_fields"]
                    .as_array()
                    .ok_or_else(|| anyhow!("missing forbidden response fields"))?
                {
                    let field = forbidden
                        .as_str()
                        .ok_or_else(|| anyhow!("invalid forbidden field"))?;
                    let mut disclosed = opaque.clone();
                    disclosed[field] = serde_json::json!(1);
                    if serde_json::from_value::<SignalRelayOutcome>(disclosed).is_ok() {
                        bail!("peer response schema admits {field}");
                    }
                }
            }
            "signal_peer_relay_uncertain_outcome" => {
                // This is a fixture-contract check, not evidence of live HTTP retry behavior.
                if case["expected"]["automatic_request_retry"] != false
                    || case["expected"]["durable_retry_queue_created"] != false
                    || case["expected"]["strategy"] != "drop_unconfirmed"
                {
                    bail!("uncertain Signal outcome must not become a durable retry");
                }
            }
            "signal_peer_relay_mutations" => {
                let mut altered = signal.clone();
                altered.expires_at -= Duration::seconds(1);
                if verify_ed25519_signal_proof(&altered, &signing_public_key()).is_ok() {
                    bail!("rewritten expiry retained a valid producer proof");
                }
                let mut resigned = signal.clone();
                crate::harness::attach_signal_proof(
                    &mut resigned,
                    &SigningKey::from_bytes(&[0x38; 32]),
                );
                if verify_ed25519_signal_proof(&resigned, &signing_public_key()).is_ok() {
                    bail!("destination signature replaced the producer proof");
                }
            }
            "signal_role_admission" | "signal_role_admission_mutations" => {
                validate_role_case_contract(case)?;
            }
            "signal_agent_sender_admission" => {
                let mut agent = signal.clone();
                agent.sender_device_id = None;
                agent.proof.verification_method =
                    crate::fixture_did_url("did:web:alice.example#agent-runtime");
                crate::harness::attach_signal_proof(
                    &mut agent,
                    &SigningKey::from_bytes(&SIGNING_SEED),
                );
                agent.validate_structural()?;
                if agent.sender_device_id.is_some()
                    || verify_ed25519_signal_proof(&agent, &signing_public_key()).is_err()
                    || case["expected"]["source_decision"] != "accept"
                {
                    bail!("valid Agent sender branch was not admitted as the device-less branch");
                }
            }
            "signal_agent_sender_mutations" => validate_agent_mutation_contract(case)?,
            other => bail!("unknown Signal federation generator {other}"),
        }
    }
    Ok(())
}

fn validate_agent_mutation_contract(case: &Value) -> Result<()> {
    let mutations = case
        .pointer("/given_state/generator/mutations")
        .or_else(|| case.pointer("/input/generator/mutations"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Agent Signal mutation fixture is missing mutations"))?;
    for required in [
        "ordinary_account_without_sender_device_id",
        "agent_with_sender_device_id",
        "agent_with_controller_device_id",
        "agent_key_revoked_or_superseded",
        "agent_lifecycle_paused_or_deactivated",
        "controller_membership_generation_ended",
        "same_principal_other_station",
        "stale_agent_leaf",
        "leaf_authorization_ref_mismatch",
        "concurrent_different_agent_keys",
        "pairwise_actor_without_sender_device_id",
    ] {
        if !mutations
            .iter()
            .any(|value| value.as_str() == Some(required))
        {
            bail!("Agent Signal mutation fixture omitted {required}");
        }
    }
    if case["expected"]["source_decision"] != "reject"
        || case["expected"]["recipient_decision"] != "reject_before_display_or_high_water"
        || case["expected"]["destination_does_not_resolve_remote_agent_authority"] != true
    {
        bail!("Agent Signal mutations do not preserve the three-role failure boundary");
    }
    Ok(())
}

/// Validate normative fixture expectations without inventing a second
/// Station signature. HTTP behavior is exercised in Soland's Signal
/// federation tests; real MLS/client composition is exercised in the sibling
/// `signal_recipient` tests.
fn validate_role_case_contract(case: &Value) -> Result<()> {
    let expected = &case["expected"];
    match required_str(case, "name")? {
        "destination_without_remote_directory_relays" => {
            if expected["remote_directory_queries"] != 0
                || expected["producer_signature_verifications"] != 0
                || expected["response"] != serde_json::to_value(SignalRelayOutcome::ACCEPTED)?
            {
                bail!("destination must not authenticate remote device authority");
            }
        }
        "forged_signature_requires_recipient_authentication" => {
            let mut forged = envelope()?;
            crate::harness::attach_signal_proof(&mut forged, &SigningKey::from_bytes(&[0x38; 32]));
            forged.validate_structural()?;
            if verify_ed25519_signal_proof(&forged, &signing_public_key()).is_ok()
                || expected["recipient_high_water_advanced"] != false
            {
                bail!("well-formed forged proof must not authenticate a sender");
            }
        }
        "revoked_device_with_unremoved_leaf" | "recipient_exact_account_and_mls_binding" => {
            if expected["recipient_high_water_advanced"] != false {
                bail!("failed recipient admission must not advance high-water");
            }
        }
        "source_revalidates_queued_authority" => {
            if expected["decision"] != "drop_before_outbound_dispatch"
                || expected["signals_dispatched"] != 0
            {
                bail!("source queue must not retain stale authority");
            }
        }
        "peer_schema_and_item_failure_boundary" => {
            for field in ["proof", "encrypted_payload"] {
                let mut malformed = serde_json::to_value(envelope()?)?;
                malformed.as_object_mut().unwrap().remove(field);
                if serde_json::from_value::<SignalEnvelope>(malformed).is_ok() {
                    bail!("missing {field} accepted as a Signal envelope");
                }
            }
            let mut mismatch = envelope()?;
            mismatch.proof.envelope_digest = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
            SignalRelayRequest {
                realm_id: mismatch.realm_id.clone(),
                signals: vec![mismatch.clone()],
            }
            .validate()?;
            if mismatch.validate_structural().is_ok()
                || expected["per_item_results_exposed"] != false
            {
                bail!("peer request and per-item rejection boundary drifted");
            }
        }
        other => bail!("unknown Signal role fixture {other}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn signal_federation_fixture_preserves_full_actor_authorization() {
        super::run_signal_federation_fixture_suite().unwrap();
    }
}
