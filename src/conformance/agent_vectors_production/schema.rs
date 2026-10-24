//! Schema cases consume the SDK runtime validator and the actual wire DTOs.

use anyhow::{Result, anyhow, ensure};
use arkret_models_collaboration::agent_operations::*;
use arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::conformance::{CaseExecutionResult, load_fixture_value, spec_artifacts_root};

pub(crate) const REVIEWED_SCHEMA_CASES: [&str; 15] = [
    "agent_runtime_approval_controller_projection_valid",
    "agent_runtime_approval_controller_projection_rejects_pairing_code",
    "agent_runtime_approval_controller_projection_rejects_controller_material",
    "agent_runtime_approval_controller_projection_rejects_open_pop",
    "agent_provision_prepare_outcome_omits_unavailable_pcr_id",
    "agent_provision_prepare_outcome_rejects_future_pcr_id",
    "agent_provision_commit_outcome_requires_declared_pcr_id",
    "agent_provision_pcr_acceptance_waits_for_did_binding",
    "agent_provision_payload_single_event_valid",
    "agent_provision_payload_rejects_nested_proof",
    "agent_readiness_closed_blockers_valid",
    "agent_presence_requires_expiry_and_refresh",
    "generic_agent_projection_rejects_runtime_state_fourth_axis",
    "generic_key_state_rejects_status_and_runtime_state",
    "pairing_poll_keeps_operation_local_runtime_state",
];

fn decode<T: DeserializeOwned>(instance: &Value) -> Result<(), String> {
    // The wire consumer sees JCS bytes, not the fixture file's display order.
    let bytes =
        arkret_canonical::canonical_json_bytes(instance).map_err(|error| error.to_string())?;
    serde_json::from_slice::<T>(&bytes)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn consume(schema_ref: &str, instance: &Value) -> Result<Result<(), String>> {
    Ok(match schema_ref {
        "schemas/agent-operations.schema.json#/$defs/agent_runtime_approval_controller_projection" => {
            decode::<AgentRuntimeApprovalControllerProjection>(instance)
        }
        "schemas/agent-operations.schema.json#/$defs/agent_provision_response_body" => {
            let union = decode::<AgentProvisionResponseBody>(instance);
            // Preserve the concrete branch's refusal diagnostic. The normal
            // untagged wire union also has to reach the same accept/reject.
            let branch = match instance["status"].as_str() {
                Some("awaiting_controller_event") => {
                    decode::<AgentProvisionAwaitingControllerEvent>(instance)
                }
                Some("awaiting_pcr_genesis") => {
                    decode::<AgentProvisionAwaitingPcrGenesis>(instance)
                }
                Some("awaiting_did_binding") => {
                    decode::<AgentProvisionAwaitingDidBinding>(instance)
                }
                Some("complete") => decode::<AgentProvisionComplete>(instance),
                _ => return Err(anyhow!("unknown Agent provision outcome status")),
            };
            ensure!(
                union.is_ok() == branch.is_ok(),
                "wire outcome union disagrees with its concrete branch"
            );
            branch
        }
        "schemas/agent-provision.schema.json" => decode::<AgentProvisionPayload>(instance)
            .and_then(|()| {
                serde_json::from_value::<AgentProvisionPayload>(instance.clone())
                    .map_err(|error| error.to_string())?
                    .validate()
                    .map_err(|error| error.to_string())
            }),
        "schemas/agent-operations.schema.json#/$defs/agent_readiness" => {
            decode::<AgentReadiness>(instance)
        }
        "schemas/agent-operations.schema.json#/$defs/agent_presence" => {
            decode::<AgentPresence>(instance)
        }
        "schemas/agent-operations.schema.json#/$defs/agent_projection" => {
            decode::<AgentProjection>(instance)
        }
        "schemas/agent-operations.schema.json#/$defs/key_state" => decode::<KeyState>(instance),
        "schemas/agent-operations.schema.json#/$defs/agent_runtime_approval_status_response_body" => {
            decode::<AgentRuntimeApprovalStatusResponseBody>(instance).and_then(|()| {
                serde_json::from_value::<AgentRuntimeApprovalStatusResponseBody>(instance.clone())
                    .map_err(|error| error.to_string())?
                    .validate_signer_evidence_delivery()
                    .map_err(|error| error.to_string())
            })
        }
        _ => return Err(anyhow!("unreviewed Agent schema consumer {schema_ref}")),
    })
}

pub(super) fn run_schema_cases() -> Result<Vec<CaseExecutionResult>> {
    let fixture = load_fixture_value("agent-vectors-fixture.json")?;
    let cases = fixture["schema_validation_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("Agent schema case section missing"))?;
    ensure!(
        cases
            .iter()
            .map(|case| case["name"].as_str())
            .eq(REVIEWED_SCHEMA_CASES.iter().copied().map(Some)),
        "Agent schema cases differ from their reviewed consumer set"
    );
    let registry =
        arkret_schema_conformance::schema_registry_from_spec_artifacts(spec_artifacts_root())?;
    let mut results = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let reference = case["schema_ref"]
            .as_str()
            .ok_or_else(|| anyhow!("{name}: no schema_ref"))?;
        let id = if let Some(fragment) =
            reference.strip_prefix("schemas/agent-operations.schema.json#")
        {
            format!("ak.schema.agent_operations.v1#{fragment}")
        } else if reference == "schemas/agent-provision.schema.json" {
            "ak.schema.agent_provision.v1".into()
        } else {
            return Err(anyhow!("{name}: unreviewed schema reference {reference}"));
        };
        let expected = case["expect_valid"]
            .as_bool()
            .ok_or_else(|| anyhow!("{name}: no validity expectation"))?;
        let schema = registry.validate_value(&id, &case["instance"]);
        if let Err(error) = &schema {
            ensure!(
                matches!(error, arkret_schema::SchemaError::Validation(_)),
                "{name}: registry/setup failure cannot count as instance rejection: {error}"
            );
        }
        let typed = consume(reference, &case["instance"])?;
        ensure!(
            schema.is_ok() == expected,
            "{name}: production schema verdict differs: {schema:?}"
        );
        ensure!(
            typed.is_ok() == expected,
            "{name}: production DTO verdict differs: {typed:?}"
        );
        let mut assertions = 2;
        if !expected {
            let required = case["first_expected_error"]
                .as_str()
                .and_then(|value| value.strip_prefix("contains:"))
                .ok_or_else(|| anyhow!("{name}: no concrete refusal discriminator"))?;
            let error = typed.unwrap_err();
            ensure!(
                error.contains(required),
                "{name}: wrong DTO refusal branch: {error}"
            );
            assertions += 1;
        }
        results.push(CaseExecutionResult {
            case_id: name.to_owned(),
            assertions,
        });
    }
    Ok(results)
}
