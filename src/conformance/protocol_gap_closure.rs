use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::load_fixture_value;

const FIXTURE: &str = "protocol-gap-closure-fixture.json";

pub fn run_protocol_gap_closure_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    if fixture["runner"]["entrypoint"].as_str() != Some("ak.suite.protocol.gap_closure.v1") {
        bail!("protocol-gap fixture has the wrong runner entrypoint");
    }
    let runners = fixture["required_independent_runners"]
        .as_array()
        .ok_or_else(|| anyhow!("protocol-gap fixture has no required_independent_runners[]"))?;
    if !runners
        .iter()
        .any(|runner| runner.as_str() == Some("cotest"))
    {
        bail!("protocol-gap fixture does not require the cotest runner");
    }

    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| anyhow!("protocol-gap fixture has no cases[]"))?;
    let find = |vector_id: &str| {
        cases
            .iter()
            .find(|case| case["vector_id"].as_str() == Some(vector_id))
            .ok_or_else(|| anyhow!("protocol-gap fixture is missing {vector_id}"))
    };

    let transaction = find("ak.vector.security_transaction.failure_replay.v1")?;
    let variants = string_set(&transaction["variants"])?;
    for required in [
        "crash_before_each_remote_effect",
        "crash_after_each_remote_effect",
        "response_lost_after_each_remote_effect",
        "coordinator_restart_each_step",
        "same_bytes_retry",
        "different_bytes_retry",
        "staged_secret_missing",
        "terminal_replay",
        "rotation_pointer_switched_response_lost",
        "rotation_series_erase_partial",
        "rotation_local_commit_before_erase",
        "recovery_terminal_attestation_replay",
    ] {
        if !variants.contains(required) {
            bail!("security-transaction runner is missing {required}");
        }
    }
    let expected = &transaction["expected"];
    if expected["single_transaction"].as_bool() != Some(true)
        || expected["single_reserved_id_set"].as_bool() != Some(true)
        || expected["accepted_steps_are_prefix"].as_bool() != Some(true)
        || expected["different_bytes_retry"].as_str() != Some("duplicate_conflict")
        || expected["staged_secret_missing"].as_str()
            != Some("fail_closed_without_regenerating_plan")
        || expected["local_commit_before_complete_erase"].as_str() != Some("failed_precondition")
    {
        bail!("security-transaction replay outcomes do not preserve durable transaction identity");
    }

    for vector_id in [
        "ak.vector.cba.control_proposal_quorum_receipt.v1",
        "ak.vector.authz.authorization_rule_selection.v1",
        "ak.vector.authz.lease_lifecycle.v1",
        "ak.vector.recovery.publication_rule_projection.v1",
        "ak.vector.strand.track_name_registry.v1",
        "ak.vector.binding.websocket.v1",
    ] {
        validate_partition(find(vector_id)?)?;
    }
    Ok(())
}

fn validate_partition(case: &Value) -> Result<()> {
    let variants = string_set(&case["variants"])?;
    let accepted = string_set(&case["expected"]["accepted"])?;
    let rejected = string_set(&case["expected"]["rejected"])?;
    if accepted.is_empty() || rejected.is_empty() || !accepted.is_disjoint(&rejected) {
        bail!("accepted/rejected variants must be non-empty and disjoint");
    }
    let partition: BTreeSet<_> = accepted.union(&rejected).copied().collect();
    if partition != variants {
        bail!("accepted/rejected outcomes do not partition the declared variants");
    }
    Ok(())
}

fn string_set(value: &Value) -> Result<BTreeSet<&str>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("expected string array"))?
        .iter()
        .map(|item| item.as_str().ok_or_else(|| anyhow!("expected string item")))
        .collect()
}
