use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use super::{required_str, security_transaction_resilience_reference};

pub fn run_security_transaction_resilience_joint_gate() -> Result<()> {
    let reference_source = concat!(
        include_str!("security_transaction_resilience_reference.rs"),
        include_str!("security_transaction_resilience_reference/recovery.rs")
    );
    for forbidden in [
        "use arkret_",
        "use garth",
        "use inkson",
        "use coland",
        "arkret_wire::",
        "arkret_state::",
    ] {
        ensure!(
            !reference_source.contains(forbidden),
            "independent resilience runner crossed dependency fence via {forbidden}"
        );
    }
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/security-transaction-resilience-fixture.json",
    )
    .context("load embedded security transaction resilience fixture")?;
    let reference_fixture: security_transaction_resilience_reference::SecurityTransactionResilienceFixture =
        serde_json::from_value(fixture.clone())
            .context("parse security transaction resilience fixture root")?;
    let reference = security_transaction_resilience_reference::run(&reference_fixture)
        .map_err(anyhow::Error::msg)
        .context("independent resilience runner failed")?;
    verify_continue_cases(&reference_fixture.continue_cases)
        .context("security transaction continue cases")?;

    // Rotation alone has worker/continue steps. Recovery is independently
    // interpreted from its full signed R and native closure, then compared with
    // the SDK's structural and cryptographic interpretation of the same originals.
    let rotation_steps = serde_json::to_value(arkret_models_crypto::SECURITY_ROTATION_STEP_ORDER)?;
    ensure!(
        rotation_steps
            == serde_json::json!([
                "revoke",
                "upload_new_material",
                "switch_authoritative_pointer",
                "erase_old_material",
                "local_commit"
            ]),
        "SDK security rotation step order drifted"
    );
    let kat = &fixture["single_submit_recovery_kat"];
    let completed: arkret_models_crypto::RecoveryTransactionCompletion =
        serde_json::from_value(kat["expected_outcome"].clone())?;
    completed.validate_structural()?;
    super::run_recovery_completion_grant_suite()?;
    for projection in &reference {
        let value = serde_json::to_value(projection)?;
        if value["kind"] != "recovery" {
            continue;
        }
        ensure!(
            value["transaction_id"] == serde_json::to_value(&completed.transaction_id)?
                && value["receipt_digest"]
                    == serde_json::to_value(completed.recovery_receipt.receipt_digest()?)?,
            "independent Recovery identity differs from SDK's full signed R"
        );
        if !value["native_commits"]
            .as_array()
            .context("native projection")?
            .is_empty()
        {
            ensure!(
                value["native_commits"] == kat["native_commits"]
                    && value["completion_attestation"]
                        == serde_json::to_value(&completed.completion_attestation)?,
                "independent Recovery native closure differs from SDK original"
            );
        } else {
            ensure!(
                value["completion_attestation"].is_null(),
                "refused Recovery exposed C"
            );
        }
    }
    // 2 kinds x 3 fault positions x 7 faults, 10 rotation cases and 11
    // single-submit Recovery cases, each pinned by name in the runner.
    ensure!(
        reference.len() == 63,
        "reference runner did not execute all 63 security-transaction scenarios"
    );
    ensure!(
        reference
            .iter()
            .map(|projection| projection.scenario.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == reference.len(),
        "independent runner emitted duplicate scenarios"
    );
    Ok(())
}

/// Rotation derives one terminal-ready local_commit from its four workers.
/// Recovery has no continue route, including an empty/attestation-less request.
fn verify_continue_cases(cases: &[Value]) -> Result<()> {
    let mut kinds = BTreeSet::new();
    let mut saw_worker = false;
    let mut saw_terminal = false;
    let mut saw_prefix_refusal = false;
    let mut saw_recovery_refusal = false;
    for case in cases {
        let name = required_str(case, "name")?;
        let kind = required_str(case, "transaction_kind")?;
        kinds.insert(kind);
        if kind == "recovery" {
            ensure!(
                required_str(case, "expected")? == "reject_without_side_effect"
                    && required_str(case, "reason_code")? == "failed_precondition"
                    && case.get("accepted_step_count").is_none()
                    && case.get("derived_next_step").is_none(),
                "Recovery continue case {name} resurrected a prepared/step branch"
            );
            saw_recovery_refusal = true;
            continue;
        }
        ensure!(kind == "security_rotation", "unknown continue kind {kind}");
        let accepted = case["accepted_step_count"]
            .as_u64()
            .context("Rotation prefix")?;
        let steps = [
            "revoke",
            "upload_new_material",
            "switch_authoritative_pointer",
            "erase_old_material",
            "local_commit",
        ];
        let derived = usize::try_from(accepted)
            .ok()
            .and_then(|n| steps.get(n))
            .copied();
        ensure!(
            case["derived_next_step"].as_str() == derived,
            "case {name} changed the actual next step"
        );
        let may_accept =
            terminal_continue_allowed(accepted, case["client_attestation_step"].as_str());
        match required_str(case, "expected")? {
            "worker_resumes_same_step" => {
                ensure!(
                    accepted < 4
                        && case["driver"] == "durable_transaction_worker"
                        && case["client_continue_present"] == false,
                    "client drove a worker step"
                );
                saw_worker = true;
            }
            "accept_terminal_step" => {
                ensure!(
                    may_accept
                        && case["cas_matches"] == true
                        && case["reserved_output_matches"] == true,
                    "terminal continue lacks its exact CAS/artifact"
                );
                saw_terminal = true;
            }
            "reject_without_side_effect" => {
                ensure!(
                    !may_accept && case["reason_code"] == "failed_precondition",
                    "valid terminal was incorrectly refused"
                );
                saw_prefix_refusal = true;
            }
            other => bail!("unknown continue expectation {other}"),
        }
    }
    // Exercise the absent-artifact branch directly even though the published
    // fixture's Recovery rejection no longer carries a fictitious step count.
    for accepted in 0..=5 {
        ensure!(
            !terminal_continue_allowed(accepted, None),
            "attestation-less POST became a read alias"
        );
    }
    ensure!(
        terminal_continue_allowed(4, Some("local_commit"))
            && !terminal_continue_allowed(1, Some("local_commit")),
        "terminal derivation drifted"
    );
    ensure!(
        saw_worker
            && saw_terminal
            && saw_prefix_refusal
            && saw_recovery_refusal
            && kinds == BTreeSet::from(["recovery", "security_rotation"]),
        "continue matrix lost a required branch"
    );
    Ok(())
}
fn terminal_continue_allowed(accepted: u64, artifact: Option<&str>) -> bool {
    accepted == 4 && artifact == Some("local_commit")
}
