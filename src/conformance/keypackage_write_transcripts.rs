//! Byte-exact KeyPackage write transcript known-answer tests.

use anyhow::{Result, anyhow, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::{
    CaseExecutionResult, SuiteExecutionResult, canonical_json, fixture_runner_entrypoint,
    load_fixture_value, required_field, required_str, value_array,
};

const FIXTURE: &str = "keypackage-write-transcript-fixture.json";
pub const KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT: &str =
    "ak.suite.crypto.keypackage_write_transcripts.v1";

pub fn run_keypackage_write_transcripts_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(
        fixture_runner_entrypoint(&fixture)? == KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT,
        "KeyPackage write-transcript entrypoint drifted"
    );

    let test_key = required_field(&fixture, "test_key")?;
    ensure!(
        required_str(test_key, "algorithm")? == "Ed25519",
        "KeyPackage transcript KAT must remain Ed25519"
    );
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(required_str(test_key, "public_key")?)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("public key has {} bytes, expected 32", bytes.len()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)?;

    let mut results = Vec::new();
    for case in value_array(required_field(&fixture, "cases")?, "cases")? {
        let name = required_str(case, "name")?;
        let domain = required_str(case, "domain")?;
        ensure!(domain.ends_with('\n'), "{name}: domain must end in one LF");
        ensure!(
            domain
                .as_bytes()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count()
                == 1,
            "{name}: domain must contain exactly one LF"
        );

        let transcript = if let Some(request) = case.get("unsigned_request") {
            request.clone()
        } else {
            let mut receipt = required_field(case, "signed_receipt")?.clone();
            receipt
                .as_object_mut()
                .ok_or_else(|| anyhow!("{name}: signed_receipt must be an object"))?
                .remove("signature")
                .ok_or_else(|| anyhow!("{name}: signed_receipt has no signature"))?;
            receipt
        };
        let canonical = canonical_json(&transcript)?;
        ensure!(
            canonical == required_str(case, "canonical_jcs")?,
            "{name}: SDK JCS bytes differ from the fixture"
        );
        let mut signing_input = domain.as_bytes().to_vec();
        signing_input.extend_from_slice(canonical.as_bytes());
        let declared_input =
            URL_SAFE_NO_PAD.decode(required_str(case, "signing_input_base64url")?)?;
        ensure!(
            signing_input == declared_input,
            "{name}: domain-prefixed signing input drifted"
        );

        let signature_bytes = URL_SAFE_NO_PAD.decode(required_str(case, "signature")?)?;
        let signature = Signature::from_slice(&signature_bytes)?;
        verifying_key.verify(&signing_input, &signature)?;

        let mut tampered = signing_input.clone();
        let last = tampered
            .last_mut()
            .ok_or_else(|| anyhow!("{name}: empty signing input"))?;
        *last ^= 1;
        ensure!(
            verifying_key.verify(&tampered, &signature).is_err(),
            "{name}: transcript tamper did not invalidate the signature"
        );

        results.push(CaseExecutionResult {
            case_id: name.to_owned(),
            assertions: 5,
        });
    }

    let execution = SuiteExecutionResult {
        entrypoint: KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    };
    execution.assert_complete_against(&fixture)?;
    Ok(execution)
}
