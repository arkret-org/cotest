//! Executable detached-object signature transcript vectors.
//!
//! All six formal host families drive the SDK's production digest,
//! transcript and verifier seams. Each accepted KAT reaches a concrete sink;
//! body, context and signature mutations are rejected before that sink.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::{
    detached_object_signed_digest, detached_object_signing_bytes, verify_detached_object_signature,
};
use arkret_wire::{Base64UrlString, DetachedObjectSignature, DetachedSignatureContext};
use serde_json::Value;

pub const DETACHED_OBJECT_SIGNATURE_ENTRYPOINT: &str =
    "ak.suite.detached_object_signature_transcripts.v1";
pub const FIXTURE: &str = "detached-object-signature-kat-fixture.json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub accepted_sink_entries: usize,
    pub body_mutation_error: String,
    pub context_mutation_error: String,
    pub signature_mutation_error: String,
    pub rejected_state_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedObjectSignatureExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
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

fn public_key(case: &Value) -> Result<PublicKeyMaterial> {
    let encoded = case["public_key_b64u"]
        .as_str()
        .context("detached signature case has no public_key_b64u")?;
    let bytes = base64url_decode(encoded)?;
    ensure!(bytes.len() == 32, "Ed25519 fixture key is not 32 bytes");
    Ok(PublicKeyMaterial::Ed25519Raw { bytes })
}

fn unsigned_projection_from_host(case: &Value) -> Result<Value> {
    let mut host = case["host_object"].clone();
    let object = host
        .as_object_mut()
        .context("detached signature host must be an object")?;
    let excluded = case["excluded_signature_members"]
        .as_array()
        .context("detached signature case has no excluded_signature_members")?;
    for member in excluded {
        let member = member
            .as_str()
            .context("excluded signature member is not a string")?;
        ensure!(
            object.remove(member).is_some(),
            "host does not contain excluded signature member {member}"
        );
    }
    Ok(host)
}

fn other_context(context: DetachedSignatureContext) -> DetachedSignatureContext {
    DetachedSignatureContext::ALL
        .into_iter()
        .find(|candidate| *candidate != context)
        .expect("closed context enum has six values")
}

pub fn run_detached_object_signature_suite() -> Result<DetachedObjectSignatureExecution> {
    let fixture = fixture()?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(DETACHED_OBJECT_SIGNATURE_ENTRYPOINT),
        "detached-object signature entrypoint drifted"
    );
    let cases = fixture["cases"]
        .as_array()
        .context("detached-object signature fixture has no cases")?;
    ensure!(
        cases.len() == DetachedSignatureContext::ALL.len(),
        "fixture does not cover all detached signature contexts"
    );

    let mut results = Vec::new();
    for case in cases {
        let case_id = case["case_id"]
            .as_str()
            .context("detached signature case has no case_id")?;
        ensure!(case["expected_result"] == "accept");
        let signature_member = case["signature_member"]
            .as_str()
            .with_context(|| format!("{case_id} has no signature_member"))?;
        let signature: DetachedObjectSignature =
            serde_json::from_value(case["host_object"][signature_member].clone())
                .with_context(|| format!("{case_id} signature is not the production wire type"))?;
        ensure!(
            signature.context.as_wire_str()
                == case["context"]
                    .as_str()
                    .with_context(|| format!("{case_id} has no context"))?
        );
        let unsigned = unsigned_projection_from_host(case)?;
        ensure!(
            unsigned == case["unsigned_projection"],
            "{case_id} host exclusion does not equal formal unsigned projection"
        );

        let digest = detached_object_signed_digest(&unsigned)?;
        ensure!(digest == signature.signed_digest);
        ensure!(digest.as_str() == case["expected_signed_digest"]);
        let unsigned_bytes = arkret_canonical::canonical::canonical_json_bytes(&unsigned)?;
        ensure!(
            unsigned_bytes
                == hex::decode(
                    case["unsigned_jcs_utf8_hex"]
                        .as_str()
                        .with_context(|| format!("{case_id} has no unsigned JCS KAT"))?
                )?,
            "{case_id} unsigned JCS bytes drifted"
        );
        let signing_bytes = detached_object_signing_bytes(
            signature.context,
            &signature.verification_method,
            &signature.signed_digest,
            signature.created_at,
        )?;
        ensure!(
            signing_bytes
                == hex::decode(
                    case["signature_input_hex"]
                        .as_str()
                        .with_context(|| format!("{case_id} has no signature input KAT"))?
                )?,
            "{case_id} signature transcript drifted"
        );
        let prefix = hex::decode(
            case["prefix_bytes_hex"]
                .as_str()
                .with_context(|| format!("{case_id} has no prefix KAT"))?,
        )?;
        ensure!(signing_bytes.starts_with(&prefix));
        ensure!(signature.sig.as_str() == case["expected_sig"]);
        ensure!(
            signature.verification_method.as_str()
                == case["authority_basis"]["authorized_verification_method"]
        );
        ensure!(case["authority_basis"]["public_key_b64u"] == case["public_key_b64u"]);

        let key = public_key(case)?;
        verify_detached_object_signature(&signature, &unsigned, signature.context, &key)
            .with_context(|| format!("{case_id} KAT failed production verification"))?;
        let mut accepted_sink = BTreeMap::new();
        ensure!(
            accepted_sink
                .insert(case_id.to_owned(), case["host_object"].clone())
                .is_none()
        );
        let accepted_state = accepted_sink.clone();

        let mut mutated_body = unsigned.clone();
        mutated_body
            .as_object_mut()
            .context("unsigned projection is not an object")?
            .insert("x_negative_mutation".to_owned(), Value::Bool(true));
        let body_error =
            verify_detached_object_signature(&signature, &mutated_body, signature.context, &key)
                .expect_err("body mutation passed detached signature verification")
                .to_string();
        ensure!(
            body_error.contains("signed_digest does not address the signed body"),
            "{case_id} body mutation hit the wrong branch: {body_error}"
        );
        ensure!(accepted_sink == accepted_state);

        let context_error = verify_detached_object_signature(
            &signature,
            &unsigned,
            other_context(signature.context),
            &key,
        )
        .expect_err("foreign expected context passed detached signature verification")
        .to_string();
        ensure!(
            context_error.contains("detached signature carries context")
                && context_error.contains("where")
                && context_error.contains("is required"),
            "{case_id} context mutation hit the wrong branch: {context_error}"
        );
        ensure!(accepted_sink == accepted_state);

        let mut bad_signature = signature.clone();
        bad_signature.sig =
            Base64UrlString::new(base64url_encode([0_u8; 64])).map_err(anyhow::Error::msg)?;
        let signature_error = verify_detached_object_signature(
            &bad_signature,
            &unsigned,
            bad_signature.context,
            &key,
        )
        .expect_err("invalid Ed25519 signature passed detached signature verification")
        .to_string();
        ensure!(
            signature_error.contains("detached object signature is invalid"),
            "{case_id} signature mutation hit the wrong branch: {signature_error}"
        );
        ensure!(accepted_sink == accepted_state);

        results.push(CaseExecutionResult {
            case_id: case_id.to_owned(),
            assertions: 17,
            accepted_sink_entries: accepted_sink.len(),
            body_mutation_error: body_error,
            context_mutation_error: context_error,
            signature_mutation_error: signature_error,
            rejected_state_unchanged: accepted_sink == accepted_state,
        });
    }

    Ok(DetachedObjectSignatureExecution {
        entrypoint: DETACHED_OBJECT_SIGNATURE_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_six_contexts_execute_real_positive_and_negative_crypto() -> Result<()> {
        let execution = run_detached_object_signature_suite()?;
        assert_eq!(execution.cases.len(), 6);
        assert!(execution.cases.iter().all(|case| {
            case.assertions > 0 && case.accepted_sink_entries == 1 && case.rejected_state_unchanged
        }));
        Ok(())
    }

    #[test]
    fn negative_controls_hit_three_distinct_production_branches() -> Result<()> {
        let execution = run_detached_object_signature_suite()?;
        for case in execution.cases {
            assert!(case.body_mutation_error.contains("signed_digest"));
            assert!(case.context_mutation_error.contains("carries context"));
            assert!(
                case.signature_mutation_error
                    .contains("signature is invalid")
            );
        }
        Ok(())
    }
}
