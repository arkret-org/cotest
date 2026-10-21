//! Execute bounded Contact schemas and real source signatures. Native Station
//! recovery, transactions and founding are exercised by contact_federation_live.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::contact_operations::ContactCurrentProof;
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use serde_json::json;

use super::load_artifact_json;
use super::schema_validation_fixture::SchemaEnv;
use crate::transcripts::record_vector_event;

pub fn run_direct_conversation_flow_suite() -> Result<()> {
    let fixture = load_artifact_json("fixtures/contact-current-state-fixture.json")?;
    let env = SchemaEnv::load()?;
    let cases = fixture["schema_validation_cases"]
        .as_array()
        .context("Contact schema cases absent")?;
    for row in cases {
        let validator = env.compile(row["schema_ref"].as_str().context("schema_ref absent")?)?;
        ensure!(
            validator.is_valid(&row["instance"])
                == row["expect_valid"]
                    .as_bool()
                    .context("expected schema verdict absent")?,
            "Contact schema case {} failed",
            row["name"]
        );
    }
    let proof: ContactCurrentProof = serde_json::from_value(fixture["signed_current"].clone())?;
    proof.validate_shape()?;
    let bytes = proof.canonical_signing_bytes()?;
    ensure!(
        Some(bytes.as_slice()) == fixture["canonical_unsigned"].as_str().map(str::as_bytes),
        "Contact current canonical bytes differ"
    );
    let key = PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(
            fixture["source_public_key_b64u"]
                .as_str()
                .context("source key absent")?,
        )?,
    };
    let verifier = Ed25519DetachedJwsVerifier::new();
    verifier.verify_detached_jws(&proof.signature.jws, &bytes, &key)?;
    let mut body = serde_json::to_value(&proof)?;
    body.as_object_mut().unwrap().remove("signature");
    for member in body.as_object().unwrap().keys() {
        let mut changed = body.clone();
        changed.as_object_mut().unwrap().remove(member);
        ensure!(
            verifier
                .verify_detached_jws(
                    &proof.signature.jws,
                    &arkret_canonical::canonical_json_bytes(&changed)?,
                    &key
                )
                .is_err(),
            "source signature failed to cover {member}"
        );
    }
    record_vector_event(
        "direct_conversation.end_to_end_flow",
        &json!({"fixture":"contact-current-state-fixture.json"}),
        &json!({"executed":"closed_schemas_and_source_signature","schema_cases":cases.len()}),
        &json!({"status":"validated","native_station_recovery":"separate_live_suite"}),
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn bounded_contact_fixture_executes_closed_schemas_and_signatures() {
        super::run_direct_conversation_flow_suite().unwrap();
    }
}
