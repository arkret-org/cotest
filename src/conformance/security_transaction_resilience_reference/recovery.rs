//! Independent JSON/Ed25519 interpretation of the published single-submit KAT.
//! Qualified inputs are explicit fixture assumptions, never native authority evidence.
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{ReferenceOutcome, ReferenceProjection, canonical_write, digest};

fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    canonical_write(value, &mut out)?;
    Ok(out.into_bytes())
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("missing string {field}"))
}
fn instant(value: &Value) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(value.as_str().ok_or("timestamp required")?)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|error| error.to_string())
}
fn unsigned(value: &Value, excluded: &[&str]) -> Result<Value, String> {
    let mut out = value.as_object().ok_or("unsigned object required")?.clone();
    for field in excluded {
        out.remove(*field);
    }
    Ok(Value::Object(out))
}
fn check(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn signature(key: &[u8], message: &[u8], encoded: &str) -> Result<(), String> {
    let key: [u8; 32] = key.try_into().map_err(|_| "key must have 32 bytes")?;
    let key = VerifyingKey::from_bytes(&key).map_err(|e| e.to_string())?;
    let raw = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| e.to_string())?;
    check(
        URL_SAFE_NO_PAD.encode(&raw) == encoded,
        "noncanonical signature",
    )?;
    let sig = Signature::from_slice(&raw).map_err(|e| e.to_string())?;
    key.verify(message, &sig).map_err(|e| e.to_string())
}
fn address(prefix: &str, value: &Value) -> Result<String, String> {
    let mut raw = vec![1];
    raw.extend(Sha256::digest(bytes(value)?));
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(raw)))
}

fn verify_receipt(receipt: &Value, source: &Value) -> Result<(), String> {
    let key = URL_SAFE_NO_PAD
        .decode(text(source, "candidate_public_key")?)
        .map_err(|e| e.to_string())?;
    let proof = &receipt["signature_proof"];
    check(
        proof["verification_method"] == source["candidate_method"]
            && proof["signature_algorithm"] == "Ed25519",
        "candidate receipt method changed",
    )?;
    let mut transcript = b"ak.identity.recovery_receipt.signature.v1\n".to_vec();
    transcript.extend(bytes(&unsigned(receipt, &["signature_proof"])?)?);
    signature(&key, &transcript, text(proof, "signature")?)?;
    let slots = receipt["recovery_unit"]["events"]
        .as_array()
        .ok_or("receipt has no slots")?;
    check(
        slots.len() == 2
            && slots[0]["event"]["kind"] == "ak.device.reanchor"
            && slots[1]["event"]["kind"] == "ak.device.authorize",
        "wrong ordered slots",
    )?;
    for slot in slots {
        check(
            slot.as_object()
                .is_some_and(|v| v.len() == 1 && v.contains_key("event")),
            "inapplicable generic approval or extra slot field",
        )?;
        let event = &slot["event"];
        let proof = &event["producer_proof"];
        let preimage = unsigned(event, &["event_id", "producer_proof"])?;
        check(
            proof["kind"] == "detached_jws"
                && event["event_id"] == address("ak:event:", &preimage)?
                && proof["event_digest"] == digest(&preimage)?
                && proof["verification_method"] == source["candidate_method"]
                && event["actor_id"]["account_id"] == receipt["account_id"],
            "Event address, signer or Account changed",
        )?;
        let mut binding = json!({"context":"ak.event_proof.v1","event_digest":proof["event_digest"],"actor_id":event["actor_id"],"verification_method":proof["verification_method"],"created_at":proof["created_at"]});
        for field in ["domain", "audience"] {
            if let Some(value) = proof.get(field) {
                binding[field] = value.clone();
            }
        }
        let parts: Vec<_> = text(proof, "jws")?.split('.').collect();
        check(
            parts.len() == 3 && parts[1].is_empty(),
            "Event proof is not detached JWS",
        )?;
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        check(
            header == json!({"alg":"Ed25519"}),
            "unregistered Event proof header",
        )?;
        signature(
            &key,
            format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(bytes(&binding)?)).as_bytes(),
            parts[2],
        )?;
    }
    let payload = &slots[1]["event"]["payload"];
    let mut possession = unsigned(payload, &["device_signature"])?;
    possession["account_id"] = receipt["account_id"].clone();
    for field in ["expires_at", "scopes"] {
        if possession.get(field).is_none() {
            possession[field] = Value::Null;
        }
    }
    let mut transcript = b"ak.device_authorize_recovery_possession_proof.v1\n".to_vec();
    transcript.extend(bytes(&possession)?);
    signature(&key, &transcript, text(payload, "device_signature")?)?;
    check(
        payload["device_id"] == receipt["new_device_id"]
            && payload["device_public_key_did"] == source["candidate_key_did"]
            && payload["authorized_generation_ref"] == receipt["new_model_generation_ref"]
            && payload["recovery_session_id"] == receipt["recovery_session_id"],
        "candidate authorization differs from Session",
    )?;
    check(
        slots[0]["event"]["payload"]["replacement_authorize_payload_digest"] == digest(payload)?,
        "reanchor lost the exact authorization payload",
    )
}

fn verify_closure(kat: &Value, receipt: &Value) -> Result<(), String> {
    let completed = &kat["expected_outcome"];
    let c = &completed["completion_attestation"];
    let commits = kat["native_commits"]
        .as_array()
        .ok_or("missing native Commits")?;
    check(
        commits.len() == 2
            && completed["kind"] == "recovery"
            && completed["recovery_receipt"] == *receipt
            && completed["account_id"] == receipt["account_id"]
            && c["transaction_id"] == receipt["transaction_id"]
            && c["account_id"] == receipt["account_id"]
            && c["recovery_session_id"] == receipt["recovery_session_id"]
            && c["terminal_receipt_id"] == receipt["receipt_id"]
            && c["terminal_receipt_digest"] == digest(receipt)?
            && c["replacement_device_id"] == receipt["new_device_id"]
            && c["new_model_generation_ref"] == receipt["new_model_generation_ref"],
        "immutable closure is not for this complete signed R",
    )?;
    check(
        commits[0]["commit_id"] != commits[1]["commit_id"]
            && commits[1]["previous_commit_ref"] == commits[0]["commit_id"]
            && commits[0]["previous_commit_ref"] == receipt["recovery_unit"]["predecessor_ref"]
            && commits[0]["stream_ref"] == commits[1]["stream_ref"]
            && commits[0]["stream_ref"]["kind"] == "realm"
            && commits[1]["stream_position"].as_u64()
                == commits[0]["stream_position"]
                    .as_u64()
                    .and_then(|n| n.checked_add(1)),
        "native Commits are not distinct consecutive PCR positions",
    )?;
    let station = ed25519_dalek::SigningKey::from_bytes(&std::array::from_fn(|i| i as u8 + 33))
        .verifying_key();
    for (index, commit) in commits.iter().enumerate() {
        let reference = &c[if index == 0 {
            "reanchor_event_ref"
        } else {
            "device_authorization_event_ref"
        }];
        check(
            reference
                == &json!({"event_id":commit["event_ref"],"commit_id":commit["commit_id"],"stream_ref":commit["stream_ref"],"stream_position":commit["stream_position"]})
                && commit["event_ref"]
                    == receipt["recovery_unit"]["events"][index]["event"]["event_id"]
                && commit["commit_id"]
                    == address(
                        "ak:realm_commit:",
                        &unsigned(commit, &["commit_id", "signature"])?,
                    )?,
            "C differs from an actual native Commit",
        )?;
        let proof = &commit["signature"];
        check(
            proof["context"] == "ak.realm_commit_signature.v1"
                && proof["signature_algorithm"] == "Ed25519"
                && proof["verification_method"] == "did:web:station.example#service-1"
                && proof["signed_digest"] == digest(&unsigned(commit, &["signature"])?)?,
            "Commit signature binding changed",
        )?;
        let mut transcript = b"ak.realm_commit_signature.v1\n".to_vec();
        transcript.extend(bytes(&unsigned(proof, &["signature"])?)?);
        signature(station.as_bytes(), &transcript, text(proof, "signature")?)?;
    }
    check(
        c["signature_proof"]["verification_method"] == "did:web:station.example#service-1"
            && c["signature_proof"]["signature_algorithm"] == "Ed25519",
        "C Station method changed",
    )?;
    signature(
        station.as_bytes(),
        &bytes(&unsigned(c, &["signature_proof"])?)?,
        text(&c["signature_proof"], "signature")?,
    )
}

#[derive(Clone, Default)]
struct Ledger {
    accepted: Option<(Vec<u8>, Value)>,
    visible: Option<Value>,
    issued: Option<(Vec<u8>, Value)>,
}
impl Ledger {
    fn submit(&mut self, receipt: &Value, source: &Value, kat: &Value) -> Result<Value, String> {
        check(
            source["current_reader_authorized"] == true
                && source["account_id"] == receipt["account_id"],
            "current reader unauthorized",
        )?;
        let request = bytes(receipt)?;
        if let Some((original, outcome)) = &self.accepted {
            return if original == &request {
                Ok(outcome.clone())
            } else {
                Err("duplicate_conflict".into())
            };
        }
        for field in [
            "account_id",
            "recovery_session_id",
            "session_grant_ref",
            "session_grant_cnf_jkt",
            "policy_id",
            "policy_version",
            "trust_domain",
            "new_device_id",
            "proof_summary",
            "previous_model_generation_ref",
        ] {
            check(
                receipt[field] == source[field],
                "receipt differs from a qualified source",
            )?;
        }
        check(
            source["policy_active"] == true
                && source["session_verified"] == true
                && source["grant_active"] == true
                && source["session_consumed"] == false
                && source["candidate_already_authorized"] == false
                && source["current_generation"] == receipt["previous_model_generation_ref"]
                && receipt["new_model_generation_ref"].as_u64()
                    == receipt["previous_model_generation_ref"]
                        .as_u64()
                        .and_then(|n| n.checked_add(1))
                && receipt["recovery_unit"]["predecessor_ref"] == source["predecessor_ref"],
            "live source/CAS refused",
        )?;
        let now = instant(&source["now"])?;
        check(
            instant(&receipt["started_at"])? <= instant(&receipt["completed_at"])?
                && instant(&receipt["completed_at"])? <= now,
            "receipt authoring time exceeds admission",
        )?;
        for bound in [
            &receipt["expires_at"],
            &source["session_expires_at"],
            &source["grant_expires_at"],
        ] {
            check(now < instant(bound)?, "expired before first acceptance")?;
        }
        verify_receipt(receipt, source)?;
        verify_closure(kat, receipt)?;
        // One state replacement is the linearization point. No prepared object,
        // first Commit or consumed Session can become visible on its own.
        let outcome = kat["expected_outcome"].clone();
        let visible = json!({"native_commits":kat["native_commits"],"generation":receipt["new_model_generation_ref"],"device":receipt["new_device_id"],"session_state":"completed","content_recovery_fence":receipt["recovery_unit"]["events"][0]["event"]["event_id"],"completion_attestation":outcome["completion_attestation"]});
        *self = Self {
            accepted: Some((request, outcome.clone())),
            visible: Some(visible),
            issued: self.issued.clone(),
        };
        Ok(outcome)
    }

    fn complete(&mut self, request: &Value, source: &Value, kat: &Value) -> Result<Value, String> {
        let accepted = self
            .accepted
            .as_ref()
            .ok_or("Station has no accepted closure")?
            .1
            .clone();
        let r = &accepted["recovery_receipt"];
        let proof = &request["accepted_device_possession_proof"];
        let initial = &request["initial_session"];
        let public_jwk: Value = serde_json::from_str(text(initial, "session_public_key")?)
            .map_err(|error| error.to_string())?;
        check(
            request.as_object().is_some_and(|object| object.len() == 4)
                && initial.as_object().is_some_and(|object| object.len() == 3)
                && public_jwk
                    .as_object()
                    .is_some_and(|object| object.len() == 3)
                && public_jwk["kty"] == "OKP"
                && public_jwk["crv"] == "Ed25519",
            "completion has redundant evidence or another holder key family",
        )?;
        let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(bytes(&json!({
            "crv": public_jwk["crv"], "kty": public_jwk["kty"], "x": public_jwk["x"]
        }))?));
        check(
            request["terminal_receipt"] == *r
                && source["authenticated_handoff"] == true
                && source["dpop_verified"] == true
                && source["current_device_active"] == true
                && source["account_id"] == r["account_id"]
                && source["issuer_id"] == r["session_grant_ref"]["issuer_id"]
                && source["device_id"] == r["new_device_id"]
                && source["current_generation"] == r["new_model_generation_ref"]
                && proof["holder_jkt"] == source["holder_jkt"]
                && proof["account_id"] == source["account_id"]
                && proof["device_id"] == source["device_id"]
                && proof["audience_id"] == source["audience_id"]
                && initial["device_id"] == source["device_id"]
                && initial["audience_id"] == source["audience_id"]
                && source["holder_jkt"] == thumbprint,
            "completion lacks current handoff/holder/device authority",
        )?;
        let canonical = bytes(request)?;
        if let Some((original, outcome)) = &self.issued {
            return if original == &canonical {
                Ok(outcome.clone())
            } else {
                Err("duplicate_conflict".into())
            };
        }
        check(
            source["account_state"] == "active"
                || (source["account_state"] == "deactivated"
                    && source["allow_reactivation"] == true),
            "account cannot reactivate",
        )?;
        check(
            proof["context"] == "ak.session_grant_accepted_device_possession_proof.v1"
                && proof["purpose"] == "recovery_completion_grant_issue"
                && proof["account_subject"] == source["account_subject"]
                && proof["account_handoff_grant_digest"] == source["handoff_digest"]
                && proof["verification_method"] == source["candidate_method"]
                && instant(&proof["issued_at"])? <= instant(&source["now"])?
                && instant(&source["now"])? < instant(&proof["expires_at"])?
                && (instant(&proof["expires_at"])? - instant(&proof["issued_at"])?)
                    .num_milliseconds()
                    > 0
                && (instant(&proof["expires_at"])? - instant(&proof["issued_at"])?)
                    .num_milliseconds()
                    <= 300_000
                && request["canonical_request_digest"]
                    == digest(&unsigned(request, &["canonical_request_digest"])?)?
                && proof["session_intent_digest"]
                    == digest(
                        &json!({"receipt_digest":digest(r)?,"initial_session":request["initial_session"]}),
                    )?,
            "fresh completion PoP or intent changed",
        )?;
        let key = URL_SAFE_NO_PAD
            .decode(text(source, "candidate_public_key")?)
            .map_err(|e| e.to_string())?;
        let mut transcript = b"ak.session_grant_accepted_device_possession_proof.v1\n".to_vec();
        transcript.extend(bytes(&unsigned(proof, &["signature"])?)?);
        signature(&key, &transcript, text(proof, "signature")?)?;
        let outcome = kat["completion_expected_outcome"].clone();
        check(
            outcome["transaction_id"] == r["transaction_id"]
                && outcome["issued_session"]["issuer_id"] == source["issuer_id"]
                && outcome["issued_session"]["account_id"] == source["account_id"]
                && outcome["issued_session"]["device_id"] == source["device_id"]
                && outcome["issued_session"]["session_public_key"]
                    == request["initial_session"]["session_public_key"],
            "issuance outcome differs from requested new holder",
        )?;
        self.issued = Some((canonical, outcome.clone()));
        Ok(outcome)
    }
    fn projection(
        &self,
        scenario: String,
        kat: &Value,
        outcome: &str,
    ) -> Result<ReferenceProjection, String> {
        Ok(ReferenceProjection {
            scenario,
            result: ReferenceOutcome::Recovery {
                transaction_id: kat["receipt"]["transaction_id"].clone(),
                receipt_digest: digest(&kat["receipt"])?,
                native_commits: if self.accepted.is_some() {
                    kat["native_commits"]
                        .as_array()
                        .ok_or("missing Commits")?
                        .clone()
                } else {
                    Vec::new()
                },
                completion_attestation: self
                    .accepted
                    .as_ref()
                    .map(|(_, out)| out["completion_attestation"].clone()),
                outcome: outcome.into(),
            },
        })
    }
}

pub(super) fn fault(
    kat: &Value,
    scenario: String,
    position: &str,
    fault: &str,
) -> Result<ReferenceProjection, String> {
    let mut ledger = Ledger::default();
    let r = &kat["receipt"];
    let q = &kat["qualified_inputs"];
    if position == "before_remote_side_effect" {
        check(
            ledger.visible.is_none() && ledger.accepted.is_none(),
            "crash exposed prepared state",
        )?;
        if fault == "staged_secret_lost" {
            return ledger.projection(scenario, kat, "staged_secret_lost");
        }
    }
    let first = ledger.submit(r, q, kat)?;
    let committed = ledger.visible.clone();
    if fault == "conflicting_request_replay" {
        let mut changed = r.clone();
        changed["signature_proof"]["signature"] = json!("A".repeat(86));
        check(
            ledger
                .submit(&changed, q, kat)
                .is_err_and(|e| e == "duplicate_conflict"),
            "changed signed bytes overwrote accepted R",
        )?;
        check(
            ledger.visible == committed,
            "conflicting replay changed native effects",
        )?;
        return ledger.projection(scenario, kat, "duplicate_conflict");
    }
    let mut consumed = q.clone();
    consumed["session_consumed"] = json!(true);
    consumed["current_generation"] = r["new_model_generation_ref"].clone();
    consumed["now"] = r["expires_at"].clone();
    check(
        ledger.submit(r, &consumed, kat)? == first && ledger.visible == committed,
        "response loss/restart did not replay one atomic closure",
    )?;
    ledger.projection(scenario, kat, "completed")
}

pub(super) fn cases(kat: &Value, cases: &[Value]) -> Result<Vec<ReferenceProjection>, String> {
    const EXPECTED: [(&str, &str); 11] = [
        ("candidate_not_previously_authorized", "atomic_completed"),
        ("same_signed_receipt_response_lost", "same_outcome"),
        (
            "changed_signature_bytes_same_transaction",
            "duplicate_conflict",
        ),
        ("swapped_slots", "reject_zero_effects"),
        ("wrong_candidate", "reject_zero_effects"),
        ("wrong_session_grant_issuer", "reject_zero_effects"),
        ("stale_head_or_generation", "reject_zero_effects"),
        ("policy_revoked", "reject_zero_effects"),
        ("expired_before_first_acceptance", "reject_zero_effects"),
        (
            "deactivated_completion_response_lost",
            "fresh_handoff_original_closure_no_recommit",
        ),
        ("new_holder_without_identity_pop", "reject_zero_issuance"),
    ];
    check(
        cases.len() == EXPECTED.len(),
        "missing or duplicate Recovery case",
    )?;
    let mut result = Vec::new();
    for (name, expected) in EXPECTED {
        let declarations: Vec<_> = cases.iter().filter(|c| c["name"] == name).collect();
        check(
            declarations.len() == 1 && declarations[0]["expected"] == expected,
            "Recovery case set or expectation changed",
        )?;
        let mut ledger = Ledger::default();
        let mut r = kat["receipt"].clone();
        let mut q = kat["qualified_inputs"].clone();
        match name {
            "candidate_not_previously_authorized" => {
                ledger.submit(&r, &q, kat)?;
                check(ledger.visible.is_some(), "no atomic closure")?;
            }
            "same_signed_receipt_response_lost" => {
                let first = ledger.submit(&r, &q, kat)?;
                let visible = ledger.visible.clone();
                q["session_consumed"] = json!(true);
                q["now"] = r["expires_at"].clone();
                check(
                    ledger.submit(&r, &q, kat)? == first && ledger.visible == visible,
                    "lost response recommitted recovery",
                )?;
            }
            "changed_signature_bytes_same_transaction" => {
                ledger.submit(&r, &q, kat)?;
                let visible = ledger.visible.clone();
                r["signature_proof"]["signature"] = json!("A".repeat(86));
                check(
                    ledger
                        .submit(&r, &q, kat)
                        .is_err_and(|e| e == "duplicate_conflict")
                        && ledger.visible == visible,
                    "different signature bytes reused accepted request identity",
                )?;
            }
            "deactivated_completion_response_lost" | "new_holder_without_identity_pop" => {
                ledger.submit(&r, &q, kat)?;
                let visible = ledger.visible.clone();
                let mut current = kat["completion_qualified_inputs"].clone();
                let mut request = kat["completion_request"].clone();
                if name == "new_holder_without_identity_pop" {
                    // The new holder has a genuine different public key and a
                    // consistent new intent/digest, but cannot re-sign as the
                    // accepted candidate identity. Merely matching DPoP is insufficient.
                    let new_key = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
                    let public_jwk = json!({"crv":"Ed25519","kty":"OKP", "x":URL_SAFE_NO_PAD.encode(new_key.verifying_key().as_bytes())});
                    request["initial_session"]["session_public_key"] = json!(
                        String::from_utf8(bytes(&public_jwk)?).map_err(|error| error.to_string())?
                    );
                    current["holder_jkt"] =
                        json!(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes(&public_jwk)?)));
                    request["accepted_device_possession_proof"]["holder_jkt"] =
                        current["holder_jkt"].clone();
                    request["accepted_device_possession_proof"]["session_intent_digest"] = json!(
                        digest(
                            &json!({"receipt_digest":digest(&r)?,"initial_session":request["initial_session"]})
                        )?
                    );
                    request["canonical_request_digest"] =
                        json!(digest(&unsigned(&request, &["canonical_request_digest"])?)?);
                    check(
                        ledger.complete(&request, &current, kat).is_err()
                            && ledger.issued.is_none(),
                        "new holder issued without candidate PoP",
                    )?;
                } else {
                    check(
                        current["account_state"] == "deactivated",
                        "deactivated case disappeared",
                    )?;
                    let first = ledger.complete(&request, &current, kat)?;
                    current["account_state"] = json!("active");
                    current["now"] = json!("2099-01-01T00:00:00.000Z");
                    check(
                        ledger.complete(&request, &current, kat)? == first,
                        "completion response loss minted another outcome",
                    )?;
                }
                check(
                    ledger.visible == visible,
                    "AA completion recommitted Station recovery",
                )?;
            }
            _ => {
                match name {
                    "swapped_slots" => r["recovery_unit"]["events"]
                        .as_array_mut()
                        .ok_or("missing slots")?
                        .swap(0, 1),
                    "wrong_candidate" => q["new_device_id"] = json!("other-candidate"),
                    "wrong_session_grant_issuer" => {
                        q["session_grant_ref"]["issuer_id"] = json!("other-issuer")
                    }
                    "stale_head_or_generation" => {
                        q["predecessor_ref"] = json!("other-head");
                        q["current_generation"] = json!(2);
                    }
                    "policy_revoked" => q["policy_active"] = json!(false),
                    "expired_before_first_acceptance" => q["now"] = r["expires_at"].clone(),
                    _ => return Err(format!("unknown case {name}")),
                }
                check(
                    ledger.submit(&r, &q, kat).is_err()
                        && ledger.visible.is_none()
                        && ledger.accepted.is_none()
                        && ledger.issued.is_none(),
                    "refused Recovery left an authoritative effect",
                )?;
            }
        }
        result.push(ledger.projection(format!("recovery_submit/{name}"), kat, expected)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;

    fn fixture() -> Value {
        super::super::super::load_fixture_value("security-transaction-resilience-fixture.json")
            .unwrap()
    }
    fn resign_receipt(receipt: &mut Value) {
        let signer = ed25519_dalek::SigningKey::from_bytes(&std::array::from_fn(|i| i as u8 + 1));
        let mut transcript = b"ak.identity.recovery_receipt.signature.v1\n".to_vec();
        transcript.extend(bytes(&unsigned(receipt, &["signature_proof"]).unwrap()).unwrap());
        receipt["signature_proof"]["signature"] =
            json!(URL_SAFE_NO_PAD.encode(signer.sign(&transcript).to_bytes()));
    }
    #[test]
    fn published_single_submit_cases_and_full_signature_originals_execute() {
        let fixture = fixture();
        assert_eq!(
            cases(
                &fixture["single_submit_recovery_kat"],
                fixture["recovery_submit_cases"].as_array().unwrap()
            )
            .unwrap()
            .len(),
            11
        );
    }
    #[test]
    fn receipt_signature_does_not_excuse_a_forged_inline_event_proof() {
        let fixture = fixture();
        let kat = &fixture["single_submit_recovery_kat"];
        let mut receipt = kat["receipt"].clone();
        receipt["recovery_unit"]["events"][0]["event"]["producer_proof"]["jws"] =
            json!(format!("eyJhbGciOiJFZDI1NTE5In0..{}", "A".repeat(86)));
        resign_receipt(&mut receipt);
        assert!(verify_receipt(&receipt, &kat["qualified_inputs"]).is_err());
        let mut ledger = Ledger::default();
        assert!(
            ledger
                .submit(&receipt, &kat["qualified_inputs"], kat)
                .is_err()
        );
        assert!(ledger.accepted.is_none() && ledger.visible.is_none());
    }
    #[test]
    fn signed_receipt_cannot_add_inapplicable_generic_approval() {
        let fixture = fixture();
        let kat = &fixture["single_submit_recovery_kat"];
        for index in 0..2 {
            let mut receipt = kat["receipt"].clone();
            receipt["recovery_unit"]["events"][index]["approval_signatures"] = json!([]);
            resign_receipt(&mut receipt);
            assert!(verify_receipt(&receipt, &kat["qualified_inputs"]).is_err());
        }
    }
    #[test]
    fn station_signed_c_must_still_name_both_actual_consecutive_commits() {
        let mut fixture = fixture();
        let kat = &mut fixture["single_submit_recovery_kat"];
        let c = &mut kat["expected_outcome"]["completion_attestation"];
        c["device_authorization_event_ref"]["stream_position"] = json!(12);
        let signer = ed25519_dalek::SigningKey::from_bytes(&std::array::from_fn(|i| i as u8 + 33));
        c["signature_proof"]["signature"] = json!(
            URL_SAFE_NO_PAD.encode(
                signer
                    .sign(&bytes(&unsigned(c, &["signature_proof"]).unwrap()).unwrap())
                    .to_bytes()
            )
        );
        assert!(verify_closure(kat, &kat["receipt"]).is_err());
    }
    #[test]
    fn missing_published_recovery_case_is_an_error() {
        let fixture = fixture();
        let cases_list = fixture["recovery_submit_cases"].as_array().unwrap();
        assert!(cases(&fixture["single_submit_recovery_kat"], &cases_list[1..]).is_err());
    }
    #[test]
    fn accepted_replay_never_bypasses_current_reader_qualification() {
        let fixture = fixture();
        let kat = &fixture["single_submit_recovery_kat"];
        let mut ledger = Ledger::default();
        ledger
            .submit(&kat["receipt"], &kat["qualified_inputs"], kat)
            .unwrap();
        let original = ledger.visible.clone();
        let mut current = kat["qualified_inputs"].clone();
        current["current_reader_authorized"] = json!(false);
        assert!(ledger.submit(&kat["receipt"], &current, kat).is_err());
        assert_eq!(ledger.visible, original);
    }
}
