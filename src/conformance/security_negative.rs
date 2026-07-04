use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};
use url::Url;

use super::{
    canonical_json, load_local_fixture_value, looks_like_sha256_digest, required_field,
    required_str, sha256_prefixed, validate_profile, value_field_u64,
};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "security-negative-profile-fixture.json";
const SUITE: &str = "security_negative_profile";

pub fn run_security_negative_profile_suite() -> Result<()> {
    let fixture = load_local_fixture_value(FIXTURE)?;
    if required_str(&fixture, "suite")? != SUITE {
        bail!("{FIXTURE} suite must be {SUITE}");
    }
    validate_profile(&fixture, "ck.vector_group.privacy_security.v1")?;

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
    let verifying_key = parse_verifying_key(required_str(input, "signing_public_key_hex")?)?;

    for proof in event
        .get("proofs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Err(error_code) = verify_event_proof_signature(event, proof, &verifying_key) {
            return Ok(SecurityDecision::reject(error_code));
        }
    }
    Ok(SecurityDecision::accept())
}

/// Real Ed25519 detached-JWS verification of one Event proof.
///
/// Mirrors the SDK's `Ed25519DetachedJwsVerifier`: the signing input is
/// `b64u(protected_header) "." b64u(canonical_event_bytes)` (RFC 7797 detached,
/// canonical bytes = Event without `proofs`/`unsigned`). The proof's
/// `event_digest` MUST equal `sha256(canonical_event_bytes)` AND the JWS
/// signature MUST verify against `verifying_key`. A correct digest with a
/// forged/empty signature is rejected — exactly the regression a bare digest
/// comparison would miss.
fn verify_event_proof_signature(
    event: &Value,
    proof: &Value,
    verifying_key: &VerifyingKey,
) -> std::result::Result<(), &'static str> {
    if proof.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err("invalid_signature");
    }
    let canonical_bytes = canonical_event_payload_string(event).map_err(|_| "invalid_signature")?;
    let expected_digest = sha256_prefixed(canonical_bytes.as_bytes());
    // Spec event_proof carries `event_digest` (there is no proof-level
    // `payload_digest`); it MUST bind the canonical Event bytes.
    let Some(event_digest) = proof.get("event_digest").and_then(Value::as_str) else {
        return Err("invalid_signature");
    };
    if !looks_like_sha256_digest(event_digest)
        || event_digest == zero_sha256()
        || event_digest != expected_digest
    {
        return Err("invalid_signature");
    }

    let jws = proof
        .get("jws")
        .and_then(Value::as_str)
        .ok_or("invalid_signature")?;
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err("invalid_signature");
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| "invalid_signature")?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| "invalid_signature")?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err("invalid_signature");
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "invalid_signature")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid_signature")?;
    let signature = Signature::from_bytes(&sig_arr);
    let signing_input = format!(
        "{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(canonical_bytes.as_bytes())
    );
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "invalid_signature")
}

fn parse_verifying_key(hex: &str) -> Result<VerifyingKey> {
    let raw = decode_hex_32(hex)
        .ok_or_else(|| anyhow!("signing_public_key_hex must be 32-byte hex, got {hex:?}"))?;
    VerifyingKey::from_bytes(&raw).map_err(|err| anyhow!("invalid Ed25519 verifying key: {err}"))
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

/// Canonical JSON string of the Event with `proofs`/`unsigned` stripped — the
/// bytes that the detached JWS signs and `event_digest` hashes.
fn canonical_event_payload_string(event: &Value) -> Result<String> {
    let object = event
        .as_object()
        .ok_or_else(|| anyhow!("event must be an object"))?;
    let mut without_proofs = serde_json::Map::new();
    for (key, value) in object {
        if key != "proofs" && key != "unsigned" {
            without_proofs.insert(key.clone(), value.clone());
        }
    }
    canonical_json(&Value::Object(without_proofs))
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
    if required_str(event, "kind")? == "ck.message.create" {
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
    Ok(sha256_prefixed(
        canonical_event_payload_string(event)?.as_bytes(),
    ))
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

fn zero_sha256() -> &'static str {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
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
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn sample_event() -> Value {
        json!({
            "event_id": "ck:event:01970e589d21-0001-a13f9c2e",
            "kind": "ck.message.create",
            "realm_id": "ck:realm:01970e589d21-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-05-02T00:00:00Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "strand_id": "ck:strand:01970e589d21-7000-8000-000000000010",
                "track_name": "discussion",
                "content": {"kind": "ck.content.text", "body": "signed body"}
            }
        })
    }

    /// Build a valid detached JWS over the canonical Event bytes using the
    /// same scheme as the SDK's `Ed25519DetachedJwsSigner`.
    fn signed_proof(event: &Value, signing_key: &SigningKey) -> Value {
        let canonical = canonical_event_payload_string(event).unwrap();
        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let signing_input = format!(
            "{header_b64}.{}",
            URL_SAFE_NO_PAD.encode(canonical.as_bytes())
        );
        let sig = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        json!({
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example#device",
            "event_digest": sha256_prefixed(canonical.as_bytes()),
            "created_at": "2026-05-02T00:00:00Z",
            "jws": format!("{header_b64}..{sig_b64}"),
        })
    }

    #[test]
    fn verifier_accepts_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let event = sample_event();
        let proof = signed_proof(&event, &signing_key);
        verify_event_proof_signature(&event, &proof, &signing_key.verifying_key())
            .expect("valid signature must verify");
    }

    #[test]
    fn verifier_rejects_correct_digest_but_tampered_signature() {
        // The exact regression a bare digest comparison misses: event_digest is
        // correct, but the JWS signature bytes are garbage.
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let event = sample_event();
        let mut proof = signed_proof(&event, &signing_key);
        let header_b64 = proof["jws"]
            .as_str()
            .unwrap()
            .split('.')
            .next()
            .unwrap()
            .to_owned();
        let forged_sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
        proof["jws"] = json!(format!("{header_b64}..{forged_sig}"));
        assert_eq!(
            verify_event_proof_signature(&event, &proof, &signing_key.verifying_key()),
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
            verify_event_proof_signature(&event, &proof, &other_key.verifying_key()),
            Err("invalid_signature"),
        );
    }

    #[test]
    fn verifier_rejects_mismatched_event_digest() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let event = sample_event();
        let mut proof = signed_proof(&event, &signing_key);
        proof["event_digest"] =
            json!("sha256:1111111111111111111111111111111111111111111111111111111111111111");
        assert_eq!(
            verify_event_proof_signature(&event, &proof, &signing_key.verifying_key()),
            Err("invalid_signature"),
        );
    }
}
