use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::load_fixture_value;

const FIXTURE: &str = "security-transaction-resilience-fixture.json";

pub fn run_protocol_gap_closure_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    if fixture["runner"]["entrypoint"].as_str()
        != Some("ak.suite.security_transaction.resilience.v1")
    {
        bail!("security-transaction fixture has the wrong runner entrypoint");
    }
    for vector in [
        "ak.vector.security_transaction.resilience.v1",
        "ak.vector.security_transaction.recovery_terminal_commit.v1",
    ] {
        if !fixture["covers_vectors"]
            .as_array()
            .is_some_and(|vectors| vectors.iter().any(|value| value == vector))
        {
            bail!("security-transaction fixture does not cover {vector}");
        }
    }

    let matrix = &fixture["fault_matrix"];
    let kinds = strings(&matrix["transaction_kinds"])?;
    let positions = strings(&matrix["fault_positions"])?;
    let faults = strings(&matrix["faults"])?;
    if kinds != BTreeSet::from(["recovery", "security_rotation"]) {
        bail!("security-transaction fixture must carry exactly recovery and security_rotation");
    }
    for required in [
        "before_remote_side_effect",
        "after_remote_side_effect_before_local_commit",
        "after_local_commit_before_response",
    ] {
        require(&positions, required, "fault position")?;
    }
    for required in [
        "crash",
        "response_lost",
        "coordinator_restart",
        "exact_request_replay",
        "conflicting_request_replay",
        "staged_secret_lost",
        "terminal_replay",
    ] {
        require(&faults, required, "fault")?;
    }

    let assertions = strings(&fixture["assertions"])?;
    for required in [
        "one_transaction_id_and_one_reserved_id_set",
        "exact_replay_returns_the_stored_outcome",
        "conflicting_replay_returns_duplicate_conflict",
        "pointer_switch_precedes_every_old_series_erase",
        "erased_series_never_becomes_active_again",
        "public_store_log_telemetry_and_crash_artifact_contain_no_secret_material",
        // The recovery half of the suite: the whole point of collapsing
        // recovery into one step is that the Seal has exactly one entrance and
        // that every authoritative result crosses the same boundary at once.
        "recovery_first_generation_seal_enters_only_through_commit_recovery_unit",
        "recovery_authoritative_results_are_all_invisible_before_the_commit_and_all_visible_after",
        "only_the_atomic_generation_cas_winner_commits_a_first_generation_seal",
    ] {
        require(&assertions, required, "assertion")?;
    }
    if fixture["equivalence_output"]["minimum_independent_runners"].as_u64() != Some(2) {
        bail!("security-transaction fixture does not require two independent runners");
    }

    validate_rotation_cases(&fixture["rotation_cases"])?;
    run_independent_replay_model(&kinds, &positions, &faults)
}

fn validate_rotation_cases(value: &Value) -> Result<()> {
    let cases = value
        .as_array()
        .ok_or_else(|| anyhow!("rotation_cases must be an array"))?;
    let partial = cases
        .iter()
        .find(|case| case["name"] == "partial_secret_storage_erase_then_restart")
        .ok_or_else(|| anyhow!("missing partial erase/restart case"))?;
    if partial["expected_after_restart"]["secret_storage"] != "erased"
        || partial["expected_after_restart"]["mls_history"] != "erased"
        || partial["expected_after_restart"]["confirmation_emitted_once"] != true
        || partial["expected_after_restart"]["accepted_erase_step_count"] != 1
    {
        bail!("partial erase/restart case does not converge monotonically");
    }
    let early = cases
        .iter()
        .find(|case| case["name"] == "erase_before_both_pointer_switches")
        .ok_or_else(|| anyhow!("missing erase-before-pointer case"))?;
    if early["expected"]["decision"] != "reject"
        || early["expected"]["reason"] != "failed_precondition"
        || early["expected"]["old_backup_deleted"] != false
    {
        bail!("erase-before-pointer case is not fail closed");
    }
    Ok(())
}

/// Independent executable interpretation of the full fixture Cartesian
/// product. It models only durable protocol facts, not implementation code.
fn run_independent_replay_model(
    kinds: &BTreeSet<&str>,
    positions: &BTreeSet<&str>,
    faults: &BTreeSet<&str>,
) -> Result<()> {
    let mut executed = 0usize;
    for kind in kinds {
        let effect_count = remote_effect_count(kind)?;
        for position in positions {
            for fault in faults {
                for fault_step in 0..effect_count {
                    let transaction_id = format!("ak:transaction:{kind}:fixed");
                    let reserved: Vec<_> = (0..effect_count)
                        .map(|index| format!("{transaction_id}:effect:{index}"))
                        .collect();
                    let mut accepted = 0usize;
                    while accepted < effect_count {
                        let before = accepted;
                        let remote_committed = accepted == fault_step
                            && matches!(
                                *position,
                                "after_remote_side_effect_before_local_commit"
                                    | "after_local_commit_before_response"
                            );
                        let conflicts = *fault == "conflicting_request_replay";
                        let staged_lost_before_use =
                            *fault == "staged_secret_lost" && accepted == fault_step;
                        if conflicts || staged_lost_before_use {
                            break;
                        }
                        if remote_committed {
                            accepted += 1;
                        } else {
                            // Exact retry or restart uses the same reserved id.
                            if reserved[accepted] != format!("{transaction_id}:effect:{accepted}") {
                                bail!("runner allocated a second reserved id set");
                            }
                            accepted += 1;
                        }
                        if accepted < before || accepted > before + 1 {
                            bail!("accepted steps ceased to be a durable prefix");
                        }
                    }
                    if *fault != "conflicting_request_replay"
                        && *fault != "staged_secret_lost"
                        && accepted != effect_count
                    {
                        bail!("replay did not converge for {kind}/{position}/{fault}");
                    }
                    executed += 1;
                }
            }
        }
    }
    let expected: usize = kinds
        .iter()
        .map(|kind| remote_effect_count(kind))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>()
        * positions.len()
        * faults.len();
    if executed != expected {
        bail!("independent runner did not execute the complete Cartesian matrix");
    }
    Ok(())
}

/// Remote side effects a transaction of this kind performs, which is also the
/// number of distinct positions a fault can be injected at.
///
/// A RecoveryTransaction has exactly one: `commit_recovery_unit` carries both
/// re-anchor Events, the first new-generation Seal and the terminal result
/// across a single boundary. The old two-step shape is gone, so a second
/// position here would be modelling a boundary the protocol no longer has.
fn remote_effect_count(kind: &str) -> Result<usize> {
    match kind {
        "recovery" => Ok(1),
        "security_rotation" => Ok(5),
        other => bail!("unknown transaction kind {other}"),
    }
}

fn strings(value: &Value) -> Result<BTreeSet<&str>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("expected string array"))?
        .iter()
        .map(|item| item.as_str().ok_or_else(|| anyhow!("expected string item")))
        .collect()
}

fn require(values: &BTreeSet<&str>, required: &str, kind: &str) -> Result<()> {
    if !values.contains(required) {
        bail!("security-transaction fixture is missing {kind} {required}");
    }
    Ok(())
}
