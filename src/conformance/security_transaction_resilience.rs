use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use super::{required_str, security_transaction_resilience_reference};

pub fn run_security_transaction_resilience_joint_gate() -> Result<()> {
    let reference_source = include_str!("security_transaction_resilience_reference.rs");
    for forbidden in [
        "use arkret_",
        "use garth",
        "use inkson",
        "use soland",
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
    let sdk = arkret_models_crypto::run_security_transaction_resilience_fixture(&fixture)
        .context("SDK resilience runner failed")?;
    let reference_fixture: security_transaction_resilience_reference::SecurityTransactionResilienceFixture =
        serde_json::from_value(fixture.clone())
            .context("parse security transaction resilience fixture root")?;
    let reference = security_transaction_resilience_reference::run(&reference_fixture)
        .map_err(anyhow::Error::msg)
        .context("independent resilience runner failed")?;
    verify_continue_cases(&reference_fixture.continue_cases)
        .context("security transaction continue cases")?;

    ensure!(
        sdk.len() == 23,
        "SDK runner did not execute all 23 security-rotation scenarios"
    );
    ensure!(
        reference.len() == 23,
        "reference runner did not execute all 23 security-rotation scenarios"
    );
    ensure!(
        sdk.iter()
            .map(|projection| projection.scenario.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == sdk.len(),
        "SDK runner emitted duplicate scenarios"
    );
    ensure!(
        serde_json::to_value(&sdk)? == serde_json::to_value(&reference)?,
        "independent runners diverged on canonical security transaction output"
    );
    Ok(())
}

/// `identity/security-transactions.md`: `continue` submits exactly one
/// client-attested terminal step.
///
/// The derivation is the point of the contract, so this recomputes it from
/// `(kind, accepted_steps.length)` instead of reading `derived_next_step` back.
/// The general request schema carries no `kind`, which is why the `{1,4}` terminal
/// indices must not appear in the schema and must be enforced here: a coordinator
/// -owned prefix step, a not-yet-ready terminal, a mismatched attestation step and
/// an attestation-less POST are all `failed_precondition` with no side effect.
fn verify_continue_cases(cases: &[Value]) -> Result<()> {
    ensure!(!cases.is_empty(), "fixture publishes no continue cases");
    let mut saw_worker_prefix = false;
    let mut saw_accepted_terminal = false;
    let mut saw_attestation_less_rejection = false;
    for case in cases {
        let name = required_str(case, "name")?;
        let kind = required_str(case, "transaction_kind")?;
        let accepted = case["accepted_step_count"]
            .as_u64()
            .with_context(|| format!("continue case {name} omits accepted_step_count"))?;
        let (terminal_index, terminal_step) = match kind {
            "recovery" => (1, "issue_terminal_receipt"),
            "security_rotation" => (4, "local_commit"),
            other => bail!("continue case {name} declares unknown transaction kind {other}"),
        };
        let derived = required_str(case, "derived_next_step")?;
        let terminal_ready = accepted == terminal_index;
        if terminal_ready && derived != terminal_step {
            bail!("continue case {name} is terminal-ready but derives {derived}");
        }
        if !terminal_ready && derived == terminal_step {
            bail!("continue case {name} derives the terminal step from a coordinator prefix");
        }

        let attested_step = case["client_attestation_step"].as_str();
        let expected = required_str(case, "expected")?;
        let should_accept = terminal_ready && attested_step == Some(terminal_step);
        match expected {
            "accept_terminal_step" => {
                if !should_accept {
                    bail!("continue case {name} accepts a step the derivation does not allow");
                }
                if case["cas_matches"].as_bool() != Some(true)
                    || case["reserved_output_matches"].as_bool() != Some(true)
                {
                    bail!("continue case {name} accepts without CAS and reserved-output equality");
                }
                saw_accepted_terminal = true;
            }
            "reject_without_side_effect" => {
                if should_accept {
                    bail!("continue case {name} rejects a well-formed terminal continue");
                }
                if required_str(case, "reason_code")? != "failed_precondition" {
                    bail!("continue case {name} must reject with failed_precondition");
                }
                if case["client_attestation_present"].as_bool() == Some(false) {
                    saw_attestation_less_rejection = true;
                }
            }
            "worker_resumes_same_step" => {
                if required_str(case, "driver")? != "durable_transaction_worker"
                    || case["client_continue_present"].as_bool() != Some(false)
                {
                    bail!("continue case {name} lets a client drive a coordinator-owned prefix");
                }
                saw_worker_prefix = true;
            }
            other => bail!("continue case {name} declares unknown expectation {other}"),
        }
    }
    ensure!(
        saw_worker_prefix,
        "continue cases must cover a coordinator-owned prefix resumed by the worker"
    );
    ensure!(
        saw_accepted_terminal,
        "continue cases must cover an accepted client-attested terminal step"
    );
    ensure!(
        saw_attestation_less_rejection,
        "continue cases must cover that an attestation-less POST is not a `get` alias"
    );
    Ok(())
}
