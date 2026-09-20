//! Executable receiving-service franking-proof transcript vectors.
//!
//! The accepted KAT reaches the SDK's production object verifier and a real
//! consumer sink. Every bound-field mutation, an independent controller
//! mismatch and a well-shaped invalid signature are rejected before that sink.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_models_collaboration::events_payloads::FrankingProof;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::franking_proof::verify_franking_proof_signature;
use arkret_signatures::proof::verify_ed25519_raw_transcript_signature;
use arkret_wire::DidUrl;
use serde_json::Value;

pub const FRANKING_PROOF_ENTRYPOINT: &str = "ak.suite.moderation.franking_proof_transcript.v1";
pub const FIXTURE: &str = "franking-proof-transcript-fixture.json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationExecutionResult {
    pub field: String,
    pub assertions: usize,
    pub rejection_branch: String,
    pub accepted_sink_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrankingProofExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub accept_assertions: usize,
    pub accepted_sink_entries: usize,
    pub mutations: Vec<MutationExecutionResult>,
    pub authority_mismatch_error: String,
    pub invalid_signature_error: String,
    pub rejected_state_unchanged: bool,
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn fixture() -> Result<Value> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read artifact {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse artifact {}", path.display()))
}

fn public_key(fixture: &Value) -> Result<PublicKeyMaterial> {
    let bytes = base64url_decode(
        fixture["test_key"]["public_key"]
            .as_str()
            .context("franking fixture has no test public key")?,
    )?;
    ensure!(bytes.len() == 32, "franking fixture key is not Ed25519");
    Ok(PublicKeyMaterial::Ed25519Raw { bytes })
}

fn mutate_proof(proof: &FrankingProof, mutation: &Value, field: &str) -> Result<FrankingProof> {
    let mut value = serde_json::to_value(proof)?;
    value[field] = mutation["transcript"][field].clone();
    serde_json::from_value(value).with_context(|| format!("{field} mutation is not typed"))
}

pub fn run_franking_proof_suite() -> Result<FrankingProofExecution> {
    let fixture = fixture()?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(FRANKING_PROOF_ENTRYPOINT),
        "franking-proof entrypoint drifted"
    );
    let case = &fixture["case"];
    ensure!(case["expected_result"] == "accept");
    let proof: FrankingProof = serde_json::from_value(case["source_payload"].clone())
        .context("formal franking-proof payload is not the production wire type")?;
    ensure!(
        proof.canonical_signing_bytes()? == case["transcript_jcs"].as_str().unwrap().as_bytes(),
        "production franking transcript does not match the formal KAT"
    );
    ensure!(proof.signature == case["signature_b64u"]);
    let key = public_key(&fixture)?;

    verify_franking_proof_signature(&proof, &key)
        .context("formal franking KAT failed production verification")?;
    let accepted_sink = vec![proof.clone()];
    let accepted_state = accepted_sink.clone();

    let mutations = case["bound_field_mutations"]
        .as_array()
        .context("franking fixture has no bound_field_mutations")?;
    ensure!(
        mutations.len() == 7,
        "formal transcript must mutate seven fields"
    );
    let mut mutation_results = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        let field = mutation["field"]
            .as_str()
            .context("franking mutation has no field")?;
        ensure!(mutation["expected_result"] == "reject_signature_invalid");

        let (branch, assertions) = if field == "domain" {
            let transcript = arkret_canonical::canonical_json_bytes(&mutation["transcript"])?;
            let error =
                verify_ed25519_raw_transcript_signature(&transcript, &proof.signature, &key)
                    .expect_err("foreign franking domain passed raw production verification")
                    .to_string();
            ensure!(
                error.contains("signature verification failed"),
                "domain mutation hit the wrong branch: {error}"
            );
            ("crypto".to_owned(), 4)
        } else {
            let mutated = mutate_proof(&proof, mutation, field)?;
            ensure!(
                mutated.canonical_signing_bytes()?
                    == arkret_canonical::canonical_json_bytes(&mutation["transcript"])?
            );
            let error = verify_franking_proof_signature(&mutated, &key)
                .expect_err("bound franking field mutation passed production verification")
                .to_string();
            if field == "received_by" {
                ensure!(
                    error.contains("controller does not project to received_by"),
                    "authority mutation hit the wrong branch: {error}"
                );
                ("authority".to_owned(), 5)
            } else {
                ensure!(
                    error.contains("signature is invalid"),
                    "{field} mutation hit the wrong crypto branch: {error}"
                );
                ("crypto".to_owned(), 5)
            }
        };
        ensure!(accepted_sink == accepted_state);
        mutation_results.push(MutationExecutionResult {
            field: field.to_owned(),
            assertions,
            rejection_branch: branch,
            accepted_sink_unchanged: accepted_sink == accepted_state,
        });
    }

    let mut wrong_controller = proof.clone();
    wrong_controller.verification_method =
        DidUrl::new("did:webvh:z6mkotherprincipalexample:other.example#delivery-key")
            .map_err(anyhow::Error::msg)?;
    let authority_mismatch_error = verify_franking_proof_signature(&wrong_controller, &key)
        .expect_err("foreign method controller passed franking authority binding")
        .to_string();
    ensure!(
        authority_mismatch_error.contains("controller does not project to received_by"),
        "independent authority mismatch hit the wrong branch: {authority_mismatch_error}"
    );
    ensure!(accepted_sink == accepted_state);

    let mut invalid_signature = proof;
    invalid_signature.signature = base64url_encode([0_u8; 64]);
    let invalid_signature_error = verify_franking_proof_signature(&invalid_signature, &key)
        .expect_err("well-shaped invalid franking signature passed production verification")
        .to_string();
    ensure!(
        invalid_signature_error.contains("signature is invalid"),
        "invalid signature hit the wrong branch: {invalid_signature_error}"
    );
    ensure!(accepted_sink == accepted_state);

    Ok(FrankingProofExecution {
        entrypoint: FRANKING_PROOF_ENTRYPOINT,
        fixture: FIXTURE,
        accept_assertions: 5,
        accepted_sink_entries: accepted_sink.len(),
        mutations: mutation_results,
        authority_mismatch_error,
        invalid_signature_error,
        rejected_state_unchanged: accepted_sink == accepted_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formal_accept_and_all_seven_mutations_execute_production_crypto() -> Result<()> {
        let execution = run_franking_proof_suite()?;
        assert_eq!(execution.accepted_sink_entries, 1);
        assert_eq!(execution.mutations.len(), 7);
        assert!(execution.accept_assertions > 0);
        assert!(
            execution
                .mutations
                .iter()
                .all(|case| { case.assertions > 0 && case.accepted_sink_unchanged })
        );
        assert!(execution.rejected_state_unchanged);
        Ok(())
    }

    #[test]
    fn authority_and_crypto_failures_are_distinct_and_effect_free() -> Result<()> {
        let execution = run_franking_proof_suite()?;
        assert!(
            execution
                .authority_mismatch_error
                .contains("controller does not project")
        );
        assert!(
            execution
                .invalid_signature_error
                .contains("signature is invalid")
        );
        assert_eq!(
            execution
                .mutations
                .iter()
                .filter(|case| case.rejection_branch == "authority")
                .count(),
            1
        );
        assert_eq!(
            execution
                .mutations
                .iter()
                .filter(|case| case.rejection_branch == "crypto")
                .count(),
            6
        );
        assert!(execution.rejected_state_unchanged);
        Ok(())
    }
}
