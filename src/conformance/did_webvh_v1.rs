use anyhow::{Result, anyhow, bail};
use arkret::identity::verify_did_webvh_v1_log;
use arkret::webvh::{
    PreparedPrincipalInception, PrincipalDidDocumentProfile, PrincipalEnrollmentDelegation,
    PrincipalInceptionInput, PrincipalRotationInput, prepare_principal_inception,
    prepare_principal_rotation, validate_principal_did_document_profile,
};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_models_identity::did_document::validate_did_webvh_v1_method;
use arkret_wire::{Did, ProfileId};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use url::Url;

use super::{load_fixture_value, required_str, validate_profile};

const FIXTURE_FILE: &str = "did-webvh-v1-fixture.json";
const VECTOR_ID: &str = "ak.vector.identity.did_webvh_v1_adapter.v1";

pub fn run_did_webvh_v1_adapter_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE_FILE)?;
    validate_profile(&fixture, ProfileId::SIGNAL_PEER_RELAY_V1)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("did:webvh fixture missing covers_vectors[]"))?;
    if !covers.iter().any(|value| value.as_str() == Some(VECTOR_ID)) {
        bail!("did:webvh fixture does not cover {VECTOR_ID}");
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("did:webvh fixture missing cases[]"))?;
    for case in cases {
        run_case(case)?;
    }
    Ok(())
}

fn run_case(case: &Value) -> Result<()> {
    let name = required_str(case, "name")?;
    let input = case
        .get("input")
        .ok_or_else(|| anyhow!("{name} missing input"))?;
    let outcome = execute_case(name, input)?;
    let expected = case
        .pointer("/expected/decision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{name} missing expected decision"))?;
    if outcome.decision != expected {
        bail!(
            "{name} decision drifted: expected {expected}, got {}",
            outcome.decision
        );
    }
    if expected == "reject" {
        // SDK validators are transport-agnostic and do not return Soland wire
        // error codes. Require the formal fixture to declare one, but count
        // only the accept/reject decision here; HTTP error mapping belongs to
        // the live Principal Server tests.
        case.pointer("/expected/error_code")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{name} rejection missing expected error_code"))?;
    }
    for (pointer, actual) in [
        (
            "/expected/identity_model",
            outcome.identity_model.map(Value::String),
        ),
        (
            "/expected/verification_key_source",
            outcome.verification_key_source.map(Value::String),
        ),
        (
            "/expected/verification_method_may_be_empty",
            outcome.verification_method_may_be_empty.map(Value::Bool),
        ),
    ] {
        if let Some(expected) = case.pointer(pointer)
            && actual.as_ref() != Some(expected)
        {
            bail!("{name} {pointer} drifted: expected {expected}, got {actual:?}");
        }
    }
    Ok(())
}

#[derive(Debug)]
struct CaseOutcome {
    decision: &'static str,
    identity_model: Option<String>,
    verification_key_source: Option<String>,
    verification_method_may_be_empty: Option<bool>,
}

fn accept(identity_model: Option<&str>) -> CaseOutcome {
    CaseOutcome {
        decision: "accept",
        identity_model: identity_model.map(str::to_owned),
        verification_key_source: None,
        verification_method_may_be_empty: None,
    }
}

fn reject() -> CaseOutcome {
    CaseOutcome {
        decision: "reject",
        identity_model: None,
        verification_key_source: None,
        verification_method_may_be_empty: None,
    }
}

fn execute_case(name: &str, input: &Value) -> Result<CaseOutcome> {
    match name {
        "accept_exact_v1_method" => {
            validate_did_webvh_v1_method(required_value(input, "parameters")?)?;
            Ok(accept(None))
        }
        "reject_unknown_method_version" | "reject_missing_method_version" => {
            expect_rejected(
                validate_did_webvh_v1_method(required_value(input, "parameters")?),
                name,
            )?;
            Ok(reject())
        }
        "accept_current_entry_active_update_key_with_prerotation" => {
            let inception = external_inception()?;
            let current_seed = [2_u8; 32];
            let next_key = public_multikey([3_u8; 32]);
            let rotation = prepare_principal_rotation(&PrincipalRotationInput {
                did: &inception.did,
                local_id: &inception.local_id,
                previous_entries: std::slice::from_ref(&inception.log_entry),
                version_time: timestamp("2026-07-16T00:00:00.000Z")?,
                current_root_seed: &current_seed,
                next_root_public_key_multibase: &next_key,
                state: &inception.log_entry["state"],
            })?;
            let did = Did::new(inception.did.clone())?;
            let verified =
                verify_did_webvh_v1_log(&did, &[inception.log_entry, rotation.log_entry.clone()])?;
            if verified.active_update_keys != vec![rotation.current_root_public_key_multibase] {
                bail!("{name} did not activate the current entry update key");
            }
            let profile = validate_principal_did_document_profile(
                did.as_str(),
                &verified.head_state,
                &verified
                    .active_update_keys
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )?;
            if profile != PrincipalDidDocumentProfile::ExternalAuthority {
                bail!("{name} resolved the wrong principal profile");
            }
            let mut outcome = accept(Some("enrollment_authority"));
            outcome.verification_key_source =
                Some("current_entry.parameters.updateKeys".to_owned());
            outcome.verification_method_may_be_empty = Some(true);
            Ok(outcome)
        }
        "accept_self_authority_model_with_distinct_psk_and_enrollment_key" => {
            let inception = self_authority_inception()?;
            let did = Did::new(inception.did.clone())?;
            let verified = verify_did_webvh_v1_log(&did, &[inception.log_entry])?;
            let profile = validate_principal_did_document_profile(
                did.as_str(),
                &verified.head_state,
                &verified
                    .active_update_keys
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )?;
            if profile != PrincipalDidDocumentProfile::SelfAuthority {
                bail!("{name} resolved the wrong principal profile");
            }
            Ok(accept(Some("cross_signing")))
        }
        "reject_both_enrollment_delegation_models" => {
            let state = required_value(input, "state")?;
            expect_rejected(
                validate_principal_did_document_profile(required_str(state, "id")?, state, &[]),
                name,
            )?;
            Ok(reject())
        }
        "reject_dangling_self_authority_delegation" => {
            let mut state = required_value(input, "state")?.clone();
            state
                .as_object_mut()
                .ok_or_else(|| anyhow!("{name} state is not an object"))?
                .insert("service".to_owned(), json!([]));
            expect_rejected(
                validate_principal_did_document_profile(required_str(&state, "id")?, &state, &[]),
                name,
            )?;
            Ok(reject())
        }
        "reject_previous_entry_update_key_proof" => {
            let inception = external_inception()?;
            let next_key = public_multikey([3_u8; 32]);
            let mut rotation = prepare_principal_rotation(&PrincipalRotationInput {
                did: &inception.did,
                local_id: &inception.local_id,
                previous_entries: std::slice::from_ref(&inception.log_entry),
                version_time: timestamp("2026-07-16T00:00:00.000Z")?,
                current_root_seed: &[2_u8; 32],
                next_root_public_key_multibase: &next_key,
                state: &inception.log_entry["state"],
            })?
            .log_entry;
            rotation["proof"][0]["verificationMethod"] = json!(inception.root_verification_method);
            let did = Did::new(inception.did)?;
            expect_rejected(
                verify_did_webvh_v1_log(&did, &[inception.log_entry, rotation]),
                name,
            )?;
            Ok(reject())
        }
        "reject_omitted_current_update_keys" => {
            let inception = external_inception()?;
            let next_key = public_multikey([3_u8; 32]);
            let mut rotation = prepare_principal_rotation(&PrincipalRotationInput {
                did: &inception.did,
                local_id: &inception.local_id,
                previous_entries: std::slice::from_ref(&inception.log_entry),
                version_time: timestamp("2026-07-16T00:00:00.000Z")?,
                current_root_seed: &[2_u8; 32],
                next_root_public_key_multibase: &next_key,
                state: &inception.log_entry["state"],
            })?
            .log_entry;
            rotation["parameters"]
                .as_object_mut()
                .ok_or_else(|| anyhow!("canonical rotation parameters are not an object"))?
                .remove("updateKeys");
            let did = Did::new(inception.did)?;
            expect_rejected(
                verify_did_webvh_v1_log(&did, &[inception.log_entry, rotation]),
                name,
            )?;
            Ok(reject())
        }
        "reject_spent_update_key_reuse" => {
            let inception = external_inception()?;
            let spent_root = inception.root_public_key_multibase.clone();
            expect_rejected(
                prepare_principal_rotation(&PrincipalRotationInput {
                    did: &inception.did,
                    local_id: &inception.local_id,
                    previous_entries: std::slice::from_ref(&inception.log_entry),
                    version_time: timestamp("2026-07-16T00:00:00.000Z")?,
                    current_root_seed: &[2_u8; 32],
                    next_root_public_key_multibase: &spent_root,
                    state: &inception.log_entry["state"],
                }),
                name,
            )?;
            Ok(reject())
        }
        "reject_state_id_s_method_or_scid_mismatch" => {
            let inception = external_inception()?;
            let mut entry = inception.log_entry;
            entry["state"]["id"] = required_value(input, "current_state")?["id"].clone();
            let did = Did::new(required_str(input, "resolved_did")?)?;
            expect_rejected(verify_did_webvh_v1_log(&did, &[entry]), name)?;
            Ok(reject())
        }
        "reject_current_key_not_precommitted" => {
            let inception = external_inception()?;
            let next_key = public_multikey([3_u8; 32]);
            expect_rejected(
                prepare_principal_rotation(&PrincipalRotationInput {
                    did: &inception.did,
                    local_id: &inception.local_id,
                    previous_entries: std::slice::from_ref(&inception.log_entry),
                    version_time: timestamp("2026-07-16T00:00:00.000Z")?,
                    current_root_seed: &[9_u8; 32],
                    next_root_public_key_multibase: &next_key,
                    state: &inception.log_entry["state"],
                }),
                name,
            )?;
            Ok(reject())
        }
        _ => bail!("unrecognized did:webvh adapter fixture case {name}"),
    }
}

fn external_inception() -> Result<PreparedPrincipalInception> {
    let endpoint = Url::parse("https://starid.local/")?;
    let next_root = public_multikey([2_u8; 32]);
    Ok(prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &endpoint,
        local_id: "alice",
        also_known_as: &[],
        version_time: timestamp("2026-07-15T00:00:00.000Z")?,
        root_seed: &[1_u8; 32],
        next_root_public_key_multibase: &next_root,
        enrollment: PrincipalEnrollmentDelegation::ExternalAuthority {
            authority_did: "did:web:auth.example",
        },
    })?)
}

fn self_authority_inception() -> Result<PreparedPrincipalInception> {
    let endpoint = Url::parse("https://starid.local/")?;
    let next_root = public_multikey([2_u8; 32]);
    let principal_signing = public_multikey([4_u8; 32]);
    let enrollment = public_multikey([5_u8; 32]);
    Ok(prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &endpoint,
        local_id: "alice-self-authority",
        also_known_as: &[],
        version_time: timestamp("2026-07-15T00:00:00.000Z")?,
        root_seed: &[1_u8; 32],
        next_root_public_key_multibase: &next_root,
        enrollment: PrincipalEnrollmentDelegation::SelfAuthority {
            principal_signing_public_key_multibase: &principal_signing,
            enrollment_public_key_multibase: &enrollment,
            principal_signing_fragment: None,
            enrollment_fragment: None,
        },
    })?)
}

fn public_multikey(seed: [u8; 32]) -> String {
    let signing = SigningKey::from_bytes(&seed);
    ed25519_pubkey_to_did_key_multibase(&signing.verifying_key().to_bytes())
}

fn timestamp(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn required_value<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| anyhow!("missing field {field}"))
}

fn expect_rejected<T, E: std::fmt::Display>(
    result: std::result::Result<T, E>,
    name: &str,
) -> Result<()> {
    if result.is_ok() {
        bail!("{name} was accepted by the canonical SDK path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_builder_receives_the_complete_predecessor_chain() {
        let inception = external_inception().unwrap();
        let third_root = public_multikey([3_u8; 32]);
        let first_rotation = prepare_principal_rotation(&PrincipalRotationInput {
            did: &inception.did,
            local_id: &inception.local_id,
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_time: timestamp("2026-07-16T00:00:00.000Z").unwrap(),
            current_root_seed: &[2_u8; 32],
            next_root_public_key_multibase: &third_root,
            state: &inception.log_entry["state"],
        })
        .unwrap();

        let history = vec![inception.log_entry, first_rotation.log_entry];
        let fourth_root = public_multikey([4_u8; 32]);
        let second_rotation = prepare_principal_rotation(&PrincipalRotationInput {
            did: &inception.did,
            local_id: &inception.local_id,
            previous_entries: &history,
            version_time: timestamp("2026-07-17T00:00:00.000Z").unwrap(),
            current_root_seed: &[3_u8; 32],
            next_root_public_key_multibase: &fourth_root,
            state: &history[1]["state"],
        })
        .unwrap();

        let did = Did::new(inception.did).unwrap();
        let mut complete_log = history;
        complete_log.push(second_rotation.log_entry);
        verify_did_webvh_v1_log(&did, &complete_log).unwrap();
    }
}
