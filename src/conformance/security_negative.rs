use anyhow::{Result, anyhow, bail};
use arkret_canonical as canonical;
use arkret_identifiers::Did;
use arkret_signatures::proof::{PublicKeyMaterial, verify_ed25519_detached_jws_proof};
use arkret_wire::Proof;
use serde_json::{Value, json};
use url::Url;

use super::{
    load_local_fixture_value, required_field, required_str, sha256_prefixed, validate_profile,
    value_field_u64,
};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "security-negative-profile-fixture.json";
const SUITE: &str = "security_negative_profile";

pub fn run_security_negative_profile_suite() -> Result<()> {
    let fixture = load_local_fixture_value(FIXTURE)?;
    if required_str(&fixture, "suite")? != SUITE {
        bail!("{FIXTURE} suite must be {SUITE}");
    }
    validate_profile(
        &fixture,
        crate::conformance::security_closure::SECURITY_CLOSURE_VECTORS_PROFILE,
    )?;

    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{FIXTURE} missing cases[]"))?;
    let mut covered = SecurityCoverage::default();

    for case in cases {
        let name = required_str(case, "name")?;
        let category = required_str(case, "category")?;
        let expected = required_field(case, "expected")?;
        if expected.get("hard_fail").and_then(Value::as_bool) != Some(true) {
            bail!("security negative {name} must declare hard_fail=true");
        }

        let decision = match category {
            "bad_signature" => {
                covered.bad_signature = true;
                validate_bad_signature(case)?
            }
            "bad_canonical_bytes" => {
                covered.bad_canonical_bytes = true;
                validate_bad_canonical_bytes(case)?
            }
            "bad_schema_payload" => {
                covered.bad_schema_payload = true;
                validate_bad_schema_payload(case)?
            }
            "replay" => {
                covered.replay = true;
                validate_replay(case)?
            }
            "downgrade" => {
                covered.downgrade = true;
                validate_downgrade(case)?
            }
            "query_auth_leakage" => {
                covered.query_auth_leakage = true;
                validate_query_auth_leakage(case)?
            }
            other => bail!("unknown security negative category {other} in {name}"),
        };
        assert_decision(name, &decision, expected)?;
        record_vector_event(
            &format!("security_negative.{category}"),
            required_field(case, "input")?,
            expected,
            &json!({
                "decision": decision.decision,
                "error_code": decision.error_code,
            }),
        );
    }

    covered.ensure_complete()?;
    Ok(())
}

fn validate_bad_signature(case: &Value) -> Result<SecurityDecision> {
    let input = required_field(case, "input")?;
    let event = required_field(input, "event")?;
    // The signing actor's Ed25519 verifying key (resolved out-of-band from the
    // proof's `verification_method`). Carried on the fixture case so the
    // validator can perform a *real* signature check rather than only a digest
    // comparison.
    let public_key = parse_public_key(required_str(input, "signing_public_key_hex")?)?;

    for proof in event
        .get("proofs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let proof: Proof = match serde_json::from_value(proof.clone()) {
            Ok(proof) => proof,
            Err(_) => return Ok(SecurityDecision::reject("invalid_signature")),
        };
        if let Err(error_code) = verify_event_proof_signature(event, &proof, &public_key) {
            return Ok(SecurityDecision::reject(error_code));
        }
    }
    Ok(SecurityDecision::accept())
}

/// Real SDK event-proof verification of one Event proof.
///
/// The SDK verifier checks both the canonical Event digest and the detached JWS
/// over the canonical proof binding object. This intentionally does not
/// reconstruct RFC 7797 signing input in cotest.
fn verify_event_proof_signature(
    event: &Value,
    proof: &Proof,
    public_key: &PublicKeyMaterial,
) -> std::result::Result<(), &'static str> {
    let actor_id = required_str(event, "actor_id")
        .and_then(|value| Did::new(value).map_err(Into::into))
        .map_err(|_| "invalid_signature")?;
    let canonical_bytes = canonical_event_payload_bytes(event).map_err(|_| "invalid_signature")?;
    verify_ed25519_detached_jws_proof(proof, &canonical_bytes, &actor_id, public_key)
        .map_err(|_| "invalid_signature")
}

fn parse_public_key(hex: &str) -> Result<PublicKeyMaterial> {
    let raw = decode_hex_32(hex)
        .ok_or_else(|| anyhow!("signing_public_key_hex must be 32-byte hex, got {hex:?}"))?;
    Ok(PublicKeyMaterial::Ed25519Raw {
        bytes: raw.to_vec(),
    })
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn canonical_event_payload_bytes(event: &Value) -> Result<Vec<u8>> {
    let object = event
        .as_object()
        .ok_or_else(|| anyhow!("event must be an object"))?;
    let mut without_proofs = serde_json::Map::new();
    for (key, value) in object {
        if key != "proofs" && key != "unsigned" {
            without_proofs.insert(key.clone(), value.clone());
        }
    }
    Ok(canonical::canonical_json_bytes(&Value::Object(
        without_proofs,
    ))?)
}

fn validate_bad_canonical_bytes(case: &Value) -> Result<SecurityDecision> {
    let input = required_field(case, "input")?;
    let stored = required_field(input, "stored_event")?;
    let incoming = required_field(input, "incoming_event")?;
    if required_str(stored, "event_id")? != required_str(incoming, "event_id")? {
        return Ok(SecurityDecision::accept());
    }
    let stored_hash = canonical_event_digest(stored)?;
    let incoming_hash = canonical_event_digest(incoming)?;
    if stored_hash != incoming_hash {
        return Ok(SecurityDecision::quarantine("duplicate_conflict"));
    }
    Ok(SecurityDecision::accept())
}

fn validate_bad_schema_payload(case: &Value) -> Result<SecurityDecision> {
    let event = required_field(required_field(case, "input")?, "event")?;
    for field in [
        "event_id",
        "kind",
        "realm_id",
        "actor_id",
        "actor_seq",
        "created_at",
        "prev_refs",
        "refs",
        "payload",
        "proofs",
    ] {
        if event.get(field).is_none() {
            return Ok(SecurityDecision::reject("schema_violation"));
        }
    }
    if required_str(event, "kind")? == "ak.message.create" {
        let payload = required_field(event, "payload")?;
        let has_body = ["content", "encrypted_content", "blob_refs"]
            .iter()
            .any(|field| payload.get(*field).is_some());
        if payload.get("strand_id").and_then(Value::as_str).is_none() || !has_body {
            return Ok(SecurityDecision::reject("schema_violation"));
        }
    }
    Ok(SecurityDecision::accept())
}

fn validate_replay(case: &Value) -> Result<SecurityDecision> {
    let input = required_field(case, "input")?;
    let event = required_field(input, "event")?;
    let frontier = required_field(input, "actor_frontier")?;
    if required_str(event, "actor_id")? == required_str(frontier, "actor_id")?
        && value_field_u64(event, "actor_seq")? <= value_field_u64(frontier, "actor_seq")?
    {
        return Ok(SecurityDecision::reject("causal_conflict"));
    }
    Ok(SecurityDecision::accept())
}

fn validate_downgrade(case: &Value) -> Result<SecurityDecision> {
    let input = required_field(case, "input")?;
    let event = required_field(input, "event")?;
    let supported = input
        .get("supported_features")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    for extension in event
        .pointer("/requirements/critical_extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = required_str(extension, "id")?;
        if extension.get("fail_closed").and_then(Value::as_bool) == Some(true)
            && !supported.contains(&id)
        {
            return Ok(SecurityDecision::reject("unsupported_feature"));
        }
    }
    Ok(SecurityDecision::accept())
}

fn validate_query_auth_leakage(case: &Value) -> Result<SecurityDecision> {
    let request = required_field(required_field(case, "input")?, "request")?;
    let url = required_str(request, "url")?;
    let parsed =
        Url::parse(url).or_else(|_| Url::parse(&format!("https://cotest.invalid{url}")))?;
    let leaked = parsed.query_pairs().any(|(key, value)| {
        let key = key.to_ascii_lowercase();
        matches!(
            key.as_str(),
            "access_token"
                | "api_key"
                | "auth"
                | "authorization"
                | "bearer"
                | "signature"
                | "sig"
                | "token"
        ) && !value.is_empty()
    });
    if leaked {
        return Ok(SecurityDecision::reject("query_auth_leakage"));
    }
    Ok(SecurityDecision::accept())
}

fn canonical_event_digest(event: &Value) -> Result<String> {
    Ok(sha256_prefixed(&canonical_event_payload_bytes(event)?))
}

fn assert_decision(name: &str, actual: &SecurityDecision, expected: &Value) -> Result<()> {
    let expected_decision = required_str(expected, "decision")?;
    if actual.decision != expected_decision {
        bail!(
            "security negative {name} decision drift: expected {expected_decision}, got {}",
            actual.decision
        );
    }
    let expected_error = expected.get("error_code").and_then(Value::as_str);
    if actual.error_code != expected_error {
        bail!(
            "security negative {name} error drift: expected {:?}, got {:?}",
            expected_error,
            actual.error_code
        );
    }
    if actual.decision == "accept" {
        bail!("security negative {name} accepted a hard-fail vector");
    }
    Ok(())
}

#[derive(Debug)]
struct SecurityDecision {
    decision: &'static str,
    error_code: Option<&'static str>,
}

impl SecurityDecision {
    fn accept() -> Self {
        Self {
            decision: "accept",
            error_code: None,
        }
    }

    fn reject(error_code: &'static str) -> Self {
        Self {
            decision: "reject",
            error_code: Some(error_code),
        }
    }

    fn quarantine(error_code: &'static str) -> Self {
        Self {
            decision: "quarantine",
            error_code: Some(error_code),
        }
    }
}

#[derive(Default)]
struct SecurityCoverage {
    bad_signature: bool,
    bad_canonical_bytes: bool,
    bad_schema_payload: bool,
    replay: bool,
    downgrade: bool,
    query_auth_leakage: bool,
}

impl SecurityCoverage {
    fn ensure_complete(&self) -> Result<()> {
        let missing = [
            ("bad_signature", self.bad_signature),
            ("bad_canonical_bytes", self.bad_canonical_bytes),
            ("bad_schema_payload", self.bad_schema_payload),
            ("replay", self.replay),
            ("downgrade", self.downgrade),
            ("query_auth_leakage", self.query_auth_leakage),
        ]
        .into_iter()
        .filter_map(|(name, covered)| (!covered).then_some(name))
        .collect::<Vec<_>>();
        if !missing.is_empty() {
            bail!("security negative fixture missing categories: {missing:?}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url::base64url_encode;
    use arkret_identifiers::Hash;
    use arkret_signatures::proof::sign_ed25519_detached_jws;
    use arkret_wire::proof_kind;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;

    use super::*;

    fn sample_event() -> Value {
        json!({
            "event_id": "ak:event:01970e589d21-0001-a13f9c2e",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:01970e589d21-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-05-02T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "strand_id": "ak:strand:01970e589d21-7000-8000-000000000010",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "signed body"}
            }
        })
    }

    /// Build a valid detached JWS over the SDK canonical Event-proof binding
    /// object.
    fn signed_proof(event: &Value, signing_key: &SigningKey) -> Proof {
        let canonical = canonical_event_payload_bytes(event).unwrap();
        let actor_id = Did::new(event["actor_id"].as_str().unwrap()).unwrap();
        let mut proof = Proof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: crate::fixture_did_url("did:web:alice.example#device"),
            event_digest: Hash::new(sha256_prefixed(&canonical)).unwrap(),
            created_at: Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        let binding_bytes = proof.canonical_binding_bytes(&actor_id).unwrap();
        proof.jws = sign_ed25519_detached_jws(signing_key, &binding_bytes).unwrap();
        proof
    }

    fn public_key(signing_key: &SigningKey) -> PublicKeyMaterial {
        PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        }
    }

    #[test]
    fn verifier_accepts_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let event = sample_event();
        let proof = signed_proof(&event, &signing_key);
        verify_event_proof_signature(&event, &proof, &public_key(&signing_key))
            .expect("valid signature must verify");
    }

    #[test]
    fn verifier_rejects_correct_digest_but_tampered_signature() {
        // The exact regression a bare digest comparison misses: event_digest is
        // correct, but the JWS signature bytes are garbage.
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let event = sample_event();
        let mut proof = signed_proof(&event, &signing_key);
        let header_b64 = proof.jws.split('.').next().unwrap().to_owned();
        let forged_sig = base64url_encode([0u8; 64]);
        proof.jws = format!("{header_b64}..{forged_sig}");
        assert_eq!(
            verify_event_proof_signature(&event, &proof, &public_key(&signing_key)),
            Err("invalid_signature"),
        );
    }

    #[test]
    fn verifier_rejects_wrong_signing_key() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let other_key = SigningKey::from_bytes(&[9u8; 32]);
        let event = sample_event();
        let proof = signed_proof(&event, &signing_key);
        assert_eq!(
            verify_event_proof_signature(&event, &proof, &public_key(&other_key)),
            Err("invalid_signature"),
        );
    }

    #[test]
    fn verifier_rejects_mismatched_event_digest() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let event = sample_event();
        let mut proof = signed_proof(&event, &signing_key);
        proof.event_digest =
            Hash::new("sha256:1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        assert_eq!(
            verify_event_proof_signature(&event, &proof, &public_key(&signing_key)),
            Err("invalid_signature"),
        );
    }

    #[test]
    fn verifier_rejects_jws_over_raw_event_bytes_even_with_correct_digest() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let event = sample_event();
        let canonical = canonical_event_payload_bytes(&event).unwrap();
        let mut proof = signed_proof(&event, &signing_key);
        proof.jws = sign_ed25519_detached_jws(&signing_key, &canonical).unwrap();
        assert_eq!(
            verify_event_proof_signature(&event, &proof, &public_key(&signing_key)),
            Err("invalid_signature"),
        );
    }
}
