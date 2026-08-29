use anyhow::{Result, anyhow, bail};
use arkret::identity::{derive_did_webvh_scid, verify_did_webvh_v1_log};
use arkret::webvh::{
    PreparedPrincipalInception, PrincipalInceptionInput, PrincipalRotationInput,
    prepare_principal_inception, prepare_principal_rotation,
};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_models_identity::did_document::validate_did_webvh_v1_method;
use arkret_signatures::webvh::skeleton::{
    derive_webvh_scid, finalize_webvh_scid_substitution, webvh_entry_hash_multibase,
};
use arkret_signatures::webvh::{
    PreparedWebvhRelocation, WebvhInceptionError, WebvhRelocationInput,
    prepare_portable_principal_inception, prepare_webvh_relocation,
};
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
    validate_profile(&fixture, ProfileId::IDENTITY_REGISTRY_V1)?;
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
        ("/expected/scid", outcome.scid.map(Value::String)),
        (
            "/expected/version_id",
            outcome.version_id.map(Value::String),
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
    scid: Option<String>,
    version_id: Option<String>,
}

fn accept(identity_model: Option<&str>) -> CaseOutcome {
    CaseOutcome {
        decision: "accept",
        identity_model: identity_model.map(str::to_owned),
        verification_key_source: None,
        verification_method_may_be_empty: None,
        scid: None,
        version_id: None,
    }
}

fn reject() -> CaseOutcome {
    CaseOutcome {
        decision: "reject",
        identity_model: None,
        verification_key_source: None,
        verification_method_may_be_empty: None,
        scid: None,
        version_id: None,
    }
}

fn execute_case(name: &str, input: &Value) -> Result<CaseOutcome> {
    match name {
        "accept_exact_v1_method" => {
            validate_did_webvh_v1_method(required_value(input, "parameters")?)?;
            Ok(accept(None))
        }
        "accept_scid_substituted_over_the_whole_entry" => {
            // identity-did.md 3.4.4: substitution covers the whole entry, so a
            // holder-owned `{SCID}` outside the skeleton members is replaced as
            // well. Deriving the SCID and the entry hash from the substituted
            // entry is the only way the published bytes and the versionId can
            // both match.
            let preliminary = required_value(input, "preliminary_entry")?;
            let scid = derive_webvh_scid(preliminary)?;
            let mut published = finalize_webvh_scid_substitution(preliminary, &scid)?;
            let version_id = format!("1-{}", webvh_entry_hash_multibase(&published, &scid)?);
            published["versionId"] = json!(version_id);
            let expected_published = required_value(input, "published_entry")?;
            if &published != expected_published {
                bail!(
                    "{name} published entry drifted: expected {expected_published}, got {published}"
                );
            }
            let mut outcome = accept(None);
            outcome.scid = Some(scid);
            outcome.version_id = Some(version_id);
            Ok(outcome)
        }
        "reject_residual_scid_placeholder_in_published_entry" => {
            // A producer that substituted only the skeleton-owned members
            // still publishes a self-consistent entry whose SCID re-derives,
            // so the residual literal is the only detector.
            expect_rejected(
                derive_did_webvh_scid(required_value(input, "published_entry")?),
                name,
            )?;
            Ok(reject())
        }
        "reject_unknown_method_version" | "reject_missing_method_version" => {
            expect_rejected(
                validate_did_webvh_v1_method(required_value(input, "parameters")?),
                name,
            )?;
            Ok(reject())
        }
        "reject_previous_entry_update_key_proof" => {
            let inception = principal_inception()?;
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
            let inception = principal_inception()?;
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
            let inception = principal_inception()?;
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
            let inception = principal_inception()?;
            let mut entry = inception.log_entry;
            entry["state"]["id"] = required_value(input, "current_state")?["id"].clone();
            let did = Did::new(required_str(input, "resolved_did")?)?;
            expect_rejected(verify_did_webvh_v1_log(&did, &[entry]), name)?;
            Ok(reject())
        }
        "reject_current_key_not_precommitted" => {
            let inception = principal_inception()?;
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
        "reject_relocation_when_predecessor_portable_absent" => {
            // A relocation is only authorized by `portable: true` in the
            // predecessor's own inception parameters. This predecessor is an
            // ordinary (non-portable) inception, and the successor satisfies
            // every other relocation precondition -- same SCID, changed host,
            // successor state id equal to the target, alsoKnownAs naming the
            // direct predecessor -- so the missing portability is the only
            // reason the SDK may reject.
            let inception = principal_inception()?;
            expect_rejected(relocate(&inception, &inception.log_entry)?, name)?;
            Ok(reject())
        }
        "reject_relocation_when_predecessor_portable_false" => {
            // No SDK path emits `portable: false` -- a non-portable inception
            // simply omits the parameter — so this predecessor is the shape a
            // foreign implementation would publish. The portability gate runs
            // before history verification, which is what makes an entry built
            // this way a valid model of the case.
            let inception = principal_inception()?;
            let mut predecessor = inception.log_entry.clone();
            predecessor["parameters"]["portable"] = Value::Bool(false);
            expect_rejected(relocate(&inception, &predecessor)?, name)?;
            Ok(reject())
        }
        "accept_relocation_when_predecessor_portable_true" => {
            let inception = portable_principal_inception()?;
            relocate(&inception, &inception.log_entry)?
                .map_err(|error| anyhow!("{name} was rejected by the canonical SDK path: {error}"))?;
            Ok(accept(None))
        }
        _ => bail!("unrecognized did:webvh adapter fixture case {name}"),
    }
}

/// Move an inception's DID to a new host while preserving its SCID, keeping
/// every other relocation precondition satisfied so that the predecessor's
/// declared portability is the only thing the SDK can be reacting to.
fn relocate(
    inception: &PreparedPrincipalInception,
    predecessor: &Value,
) -> Result<std::result::Result<PreparedWebvhRelocation, WebvhInceptionError>> {
    let scid = inception
        .did
        .split(':')
        .nth(2)
        .ok_or_else(|| anyhow!("inception DID carries no SCID"))?;
    let target_did = format!("did:webvh:{scid}:relocated.local:webvh:alice");
    let mut state: Value = serde_json::from_str(
        &serde_json::to_string(&inception.log_entry["state"])?.replace(&inception.did, &target_did),
    )?;
    state["alsoKnownAs"] = json!([inception.did.clone()]);
    Ok(prepare_webvh_relocation(&WebvhRelocationInput {
        current_did: &inception.did,
        target_did: &target_did,
        previous_entries: std::slice::from_ref(predecessor),
        version_time: timestamp("2026-07-16T00:00:00.000Z")?,
        current_update_seed: &RELOCATION_UPDATE_SEED,
        next_update_public_key_multibase: &public_multikey([4_u8; 32]),
        state: &state,
    }))
}

/// Seed whose public key every relocation predecessor pre-commits as its next
/// update key, so the relocation entry is signed by the expected key.
const RELOCATION_UPDATE_SEED: [u8; 32] = [9_u8; 32];

fn portable_principal_inception() -> Result<PreparedPrincipalInception> {
    let endpoint = Url::parse("https://webvh-provider.local/")?;
    let next_root = public_multikey(RELOCATION_UPDATE_SEED);
    Ok(prepare_portable_principal_inception(
        &PrincipalInceptionInput {
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id: "alice",
            also_known_as: &[],
            version_time: timestamp("2026-07-15T00:00:00.000Z")?,
            root_seed: &[1_u8; 32],
            next_root_public_key_multibase: &next_root,
            witness_policy: None,
        },
    )?)
}

fn principal_inception() -> Result<PreparedPrincipalInception> {
    let endpoint = Url::parse("https://webvh-provider.local/")?;
    let next_root = public_multikey([2_u8; 32]);
    Ok(prepare_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &endpoint,
        principal_endpoint: &endpoint,
        local_id: "alice",
        also_known_as: &[],
        version_time: timestamp("2026-07-15T00:00:00.000Z")?,
        root_seed: &[1_u8; 32],
        next_root_public_key_multibase: &next_root,
        witness_policy: None,
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
        let inception = principal_inception().unwrap();
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
