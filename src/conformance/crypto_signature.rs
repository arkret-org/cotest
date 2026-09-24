//! `ak.suite.crypto.signature.v1` — detached proof binding and signature KATs.
//!
//! Every positive vector signs the canonical proof binding object, never the
//! Event itself: the binding carries the Event digest, and the JOSE detached
//! profile keeps the compact payload segment empty. Negative cases mutate one
//! input of a positive vector and must fail closed with the registered code.

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier as _;
use serde_json::Value;

use super::{canonical_json, load_artifact_json, required_field, required_str, sha256_prefixed};

/// FIPS 204 ML-DSA-65 byte lengths.
const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
const MLDSA65_SIGNATURE_LEN: usize = 3309;

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Valid,
    Rejected(&'static str),
}

fn b64u(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("invalid base64url {value}"))
}

/// Registered signature algorithms keyed by their JOSE `alg`, with status.
fn registered_jose_algorithms() -> Result<Vec<(String, String, String)>> {
    let registry = load_artifact_json("registry/signature-alg-registry.json")?;
    registry["algorithms"]
        .as_array()
        .context("signature algorithm registry has no algorithms")?
        .iter()
        .filter_map(|row| {
            let alg = row["jose_algorithm"].as_str()?;
            Some(Ok((
                alg.to_owned(),
                row["status"].as_str().unwrap_or_default().to_owned(),
                row["jwk_kty"].as_str().unwrap_or_default().to_owned(),
            )))
        })
        .collect()
}

/// Verify one compact detached JWS against a resolved JWK.
fn verify_detached_jws(jws: &str, signing_input: &str, jwk: &Value) -> Result<Verdict> {
    let mut segments = jws.split('.');
    let (Some(protected_b64), Some(payload), Some(signature_b64), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Ok(Verdict::Rejected("signature_invalid"));
    };
    if !payload.is_empty() {
        return Ok(Verdict::Rejected("signature_invalid"));
    }
    let header: Value = serde_json::from_slice(&b64u(protected_b64)?)?;
    let alg = header["alg"].as_str().unwrap_or_default();
    let registered = registered_jose_algorithms()?;
    let Some((_, status, kty)) = registered.iter().find(|(name, _, _)| name == alg) else {
        return Ok(Verdict::Rejected("unsupported_signature_alg"));
    };
    if status != "active" {
        return Ok(Verdict::Rejected("unsupported_signature_alg"));
    }
    // The declared alg must match the resolved key type; a verifier never
    // substitutes another key.
    if jwk["kty"].as_str() != Some(kty.as_str()) {
        return Ok(Verdict::Rejected("signature_invalid"));
    }
    ensure!(
        signing_input.starts_with(&format!("{protected_b64}.")),
        "signing input does not start with the JWS protected header"
    );
    let signature = b64u(signature_b64)?;
    let valid = match alg {
        "Ed25519" => {
            let Ok(key) = <[u8; 32]>::try_from(b64u(jwk["x"].as_str().unwrap_or_default())?) else {
                return Ok(Verdict::Rejected("signature_invalid"));
            };
            let Ok(signature) = <[u8; 64]>::try_from(signature.as_slice()) else {
                return Ok(Verdict::Rejected("signature_invalid"));
            };
            ed25519_dalek::VerifyingKey::from_bytes(&key).is_ok_and(|key| {
                key.verify_strict(
                    signing_input.as_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
                .is_ok()
            })
        }
        "ES256" => {
            let x = b64u(jwk["x"].as_str().unwrap_or_default())?;
            let y = b64u(jwk["y"].as_str().unwrap_or_default())?;
            if x.len() != 32 || y.len() != 32 || signature.len() != 64 {
                return Ok(Verdict::Rejected("signature_invalid"));
            }
            let mut point = vec![0x04];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point) else {
                return Ok(Verdict::Rejected("signature_invalid"));
            };
            p256::ecdsa::Signature::from_slice(&signature)
                .is_ok_and(|signature| key.verify(signing_input.as_bytes(), &signature).is_ok())
        }
        other => bail!("registered active JOSE algorithm {other} has no verifier here"),
    };
    Ok(if valid {
        Verdict::Valid
    } else {
        Verdict::Rejected("signature_invalid")
    })
}

/// Structural checks shared by every positive vector: the binding carries the
/// Event digest, is canonical JSON, and is exactly the detached payload.
fn check_binding(vector: &Value, name: &str) -> Result<String> {
    let binding = required_field(vector, "binding_object")?;
    ensure!(
        binding["event_digest"].as_str() == Some(required_str(vector, "event_digest")?),
        "{name}: binding does not carry the vector event_digest"
    );
    let canonical = canonical_json(binding)?;
    ensure!(
        canonical == required_str(vector, "canonical_binding_payload")?,
        "{name}: canonical binding payload drifted"
    );
    ensure!(
        sha256_prefixed(canonical.as_bytes()) == required_str(vector, "binding_digest")?,
        "{name}: binding digest drifted"
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical.as_bytes());
    ensure!(
        payload_b64 == required_str(vector, "detached_payload_b64u")?,
        "{name}: detached payload is not the canonical binding"
    );
    Ok(payload_b64)
}

fn run_positive_vector(vector: &Value) -> Result<()> {
    let name = required_str(vector, "name")?;
    let payload_b64 = check_binding(vector, name)?;
    ensure!(
        vector["expected"]["verification_result"] == "valid",
        "{name}: positive vector must expect a valid verification"
    );
    if vector.get("proof_kind").and_then(Value::as_str) == Some("raw_detached_signature") {
        // Reserved post-quantum KAT: byte lengths are exact and current-v1
        // admission refuses the algorithm before any verification.
        ensure!(
            required_str(vector, "signature_algorithm")? == "ML-DSA-65",
            "{name}: unexpected raw detached algorithm"
        );
        ensure!(
            b64u(required_str(vector, "public_key_b64u")?)?.len() == MLDSA65_PUBLIC_KEY_LEN
                && b64u(required_str(vector, "signature_b64u")?)?.len() == MLDSA65_SIGNATURE_LEN,
            "{name}: ML-DSA-65 KAT lengths drifted"
        );
        let status = registered_jose_algorithms()?
            .into_iter()
            .find(|(alg, _, _)| alg == "ML-DSA-65")
            .map(|(_, status, _)| status);
        ensure!(
            status.as_deref() == Some("reserved")
                && vector["expected"]["production_admission"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("unsupported_signature_alg")),
            "{name}: ML-DSA-65 must stay reserved and unsupported in current-v1 admission"
        );
        return Ok(());
    }
    let protected = required_field(vector, "protected_header")?;
    let protected_canonical = canonical_json(protected)?;
    ensure!(
        protected_canonical == required_str(vector, "protected_header_canonical")?,
        "{name}: protected header is not canonical"
    );
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected_canonical.as_bytes());
    let signing_input = required_str(vector, "jws_signing_input")?;
    ensure!(
        signing_input == format!("{protected_b64}.{payload_b64}"),
        "{name}: JWS signing input is not header.canonical-binding"
    );
    let proof = required_field(vector, "proof")?;
    let jws = required_str(proof, "jws")?;
    let jwk = &vector["did_document_fragment"]["publicKeyJwk"];
    ensure!(
        required_str(proof, "verification_method")?
            == required_str(&vector["did_document_fragment"], "id")?,
        "{name}: proof verification method is not the DID document method"
    );
    ensure!(
        verify_detached_jws(jws, signing_input, jwk)? == Verdict::Valid,
        "{name}: published detached JWS does not verify"
    );
    Ok(())
}

fn run_negative_case(case: &Value, vectors: &[Value]) -> Result<()> {
    let name = required_str(case, "name")?;
    let base_name = required_str(case, "base_vector")?;
    let base = vectors
        .iter()
        .find(|vector| vector["name"] == base_name)
        .ok_or_else(|| anyhow!("{name}: unknown base vector {base_name}"))?;
    let expected = required_field(case, "expected")?;
    ensure!(
        expected["decision"] == "reject",
        "{name}: negative case must reject"
    );
    let expected_code = required_str(expected, "error_code")?;

    let verdict = if case.get("signature_b64u").is_some() {
        let key = b64u(required_str(case, "public_key_b64u")?)?;
        let signature = b64u(required_str(case, "signature_b64u")?)?;
        if key.len() != MLDSA65_PUBLIC_KEY_LEN || signature.len() != MLDSA65_SIGNATURE_LEN {
            Verdict::Rejected("signature_invalid")
        } else {
            bail!("{name}: ML-DSA-65 negative case carries valid lengths");
        }
    } else {
        let jws = case
            .get("proof_jws")
            .and_then(Value::as_str)
            .map(Ok)
            .unwrap_or_else(|| required_str(&base["proof"], "jws"))?;
        let signing_input = match case.get("jws_signing_input").and_then(Value::as_str) {
            Some(input) => input.to_owned(),
            None => {
                let protected_b64 = jws.split('.').next().unwrap_or_default();
                let payload = required_str(base, "detached_payload_b64u")?;
                format!("{protected_b64}.{payload}")
            }
        };
        let jwk = case
            .get("public_key_jwk")
            .or_else(|| case.get("resolved_public_key_jwk"))
            .unwrap_or(&base["did_document_fragment"]["publicKeyJwk"]);
        verify_detached_jws(jws, &signing_input, jwk)?
    };
    ensure!(
        matches!(verdict, Verdict::Rejected(code) if code == expected_code),
        "{name}: expected rejection {expected_code}, observed {verdict:?}"
    );
    Ok(())
}

/// Execute every positive vector and negative case of
/// `crypto-signature-fixture.json`.
pub(crate) fn run_crypto_signature_fixture(fixture: &Value) -> Result<()> {
    let vectors = fixture["vectors"]
        .as_array()
        .context("crypto signature fixture missing vectors")?;
    for vector in vectors {
        run_positive_vector(vector)?;
    }
    let negatives = fixture["negative_cases"]
        .as_array()
        .context("crypto signature fixture missing negative_cases")?;
    ensure!(
        !negatives.is_empty(),
        "crypto signature fixture has no negative cases"
    );
    for case in negatives {
        run_negative_case(case, vectors)?;
    }
    Ok(())
}
