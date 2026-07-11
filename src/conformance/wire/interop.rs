//! Interop downgrade conformance vectors.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, load_local_fixture};
use crate::conformance::{required_field, required_str, validate_profile};

pub fn run_interop_downgrade_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("interop_downgrade_fixture.json")?;
    validate_profile(&fixture, "ak.profile.mimi_interop_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("interop_downgrade fixture missing vectors[]"))?;

    let mut covered_protocols = BTreeSet::new();
    let mut covered_did_isolation = false;
    let mut covered_consent_gate = false;
    let mut covered_reachability = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let scenario = required_str(vector, "scenario")?;
        let protocol = required_str(vector, "protocol")?;
        covered_protocols.insert(protocol.to_owned());
        for also in string_array(vector, "also_applies_to")? {
            covered_protocols.insert(also);
        }

        validate_vector_is_live(name, vector)?;

        match scenario {
            "did_isolation" => {
                validate_did_isolation(vector)?;
                covered_did_isolation = true;
            }
            "consent_gate" => {
                validate_consent_gate(vector)?;
                covered_consent_gate = true;
            }
            "reachability_proof_forbidden" => {
                validate_reachability_proof_forbidden(vector)?;
                covered_reachability = true;
            }
            other => bail!("vector {name} has unknown interop downgrade scenario {other}"),
        }

        emit_vector(
            "interop_downgrade",
            vector,
            json!({
                "name": name,
                "scenario": scenario,
                "protocol": protocol
            }),
        );
    }

    for protocol in ["mimi"] {
        if !covered_protocols.contains(protocol) {
            bail!("interop downgrade fixture must cover protocol {protocol}");
        }
    }
    if !(covered_did_isolation && covered_consent_gate && covered_reachability) {
        bail!(
            "interop downgrade fixture must cover DID isolation, consent gate, and reachability proof prohibition"
        );
    }

    Ok(())
}

fn validate_vector_is_live(name: &str, vector: &Value) -> Result<()> {
    let execution = required_field(vector, "execution")?;
    if execution.get("ignored").and_then(Value::as_bool) != Some(false) {
        bail!("vector {name} must be a live non-ignored interop downgrade test");
    }
    if execution.get("fixme").and_then(Value::as_bool) != Some(false) {
        bail!("vector {name} must not be marked fixme");
    }
    Ok(())
}

fn validate_did_isolation(vector: &Value) -> Result<()> {
    let name = required_str(vector, "name")?;
    let input = required_field(vector, "input")?;
    let expected = required_field(vector, "expected")?;
    let claimed = required_str(input, "claimed_principal_did")?;
    let proof_refs = input
        .get("target_side_consent_proof_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("vector {name} missing target_side_consent_proof_refs[]"))?;
    let holder_claim_absent = input
        .get("holder_claim_ref")
        .is_none_or(|value| value.is_null());
    if !proof_refs.is_empty() || !holder_claim_absent {
        bail!("vector {name} must exercise the no-holder-proof downgrade path");
    }

    if expected_outcome(vector, name)? != "pairwise_or_pending_invite" {
        bail!("vector {name} DID isolation must project to pairwise_or_pending_invite");
    }
    if required_str(expected, "identity_projection")? != "pairwise_or_pending_invite" {
        bail!("vector {name} must not project a MIMI user identifier to an existing principal DID");
    }
    let projected = required_str(expected, "projected_actor_id")?;
    if projected == claimed {
        bail!("vector {name} projected_actor_id impersonates claimed principal DID");
    }
    if required_str(expected, "must_not_impersonate")? != claimed {
        bail!("vector {name} must pin the claimed DID as the forbidden impersonation target");
    }
    require_reason(expected, name)?;
    Ok(())
}

fn validate_consent_gate(vector: &Value) -> Result<()> {
    let name = required_str(vector, "name")?;
    let input = required_field(vector, "input")?;
    let expected = required_field(vector, "expected")?;
    if expected_outcome(vector, name)? != "reject" {
        bail!("vector {name} consent gate downgrade must reject");
    }
    let consent_active = input
        .pointer("/consent_state/active")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("vector {name} missing consent_state.active"))?;
    if !consent_active {
        bail!("vector {name} must prove active consent alone is insufficient");
    }
    if input
        .get("membership_active")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("vector {name} must leave membership inactive for the negative gate");
    }
    let capability_refs = input
        .get("capability_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("vector {name} missing capability_refs[]"))?;
    if !capability_refs.is_empty() {
        bail!("vector {name} must leave capability_refs empty for the negative gate");
    }
    let actions_granted = string_array(expected, "actions_granted")?;
    for forbidden in string_array(expected, "forbidden_actions")? {
        if actions_granted.iter().any(|granted| granted == &forbidden) {
            bail!("vector {name} grants forbidden action {forbidden}");
        }
    }
    require_reason(expected, name)?;
    Ok(())
}

fn validate_reachability_proof_forbidden(vector: &Value) -> Result<()> {
    let name = required_str(vector, "name")?;
    let response = required_field(vector, "response")?;
    let expected = required_field(vector, "expected")?;
    if expected_outcome(vector, name)? != "accept" {
        bail!("vector {name} identifier query shape should be accepted without forbidden fields");
    }
    for field in string_array(expected, "forbidden_fields")? {
        if contains_field_name(response, &field) {
            bail!("vector {name} response contains forbidden field {field}");
        }
    }
    for literal in string_array(expected, "forbidden_literals")? {
        if contains_string_literal(response, &literal) {
            bail!("vector {name} response leaks forbidden literal {literal}");
        }
    }
    Ok(())
}

fn require_reason(expected: &Value, name: &str) -> Result<()> {
    if required_str(expected, "reason_code")?.is_empty() {
        bail!("vector {name} must declare a stable fail-closed reason_code");
    }
    Ok(())
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| {
            entry
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("{field} entry must be a string"))
        })
        .collect::<Result<Vec<_>>>()
}

fn contains_field_name(value: &Value, field: &str) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key == field || contains_field_name(value, field)),
        Value::Array(values) => values.iter().any(|value| contains_field_name(value, field)),
        _ => false,
    }
}

fn contains_string_literal(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value.contains(needle),
        Value::Object(object) => object
            .values()
            .any(|value| contains_string_literal(value, needle)),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_string_literal(value, needle)),
        _ => false,
    }
}
