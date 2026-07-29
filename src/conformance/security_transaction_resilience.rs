use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};

use super::security_transaction_resilience_reference;

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
    let fixture = arkret_schema::embedded_json_artifact(
        "fixtures/security-transaction-resilience-fixture.json",
    )
    .context("load embedded security transaction resilience fixture")?;
    let sdk = arkret_models_crypto::run_security_transaction_resilience_fixture(&fixture)
        .context("SDK resilience runner failed")?;
    let reference = security_transaction_resilience_reference::run(&fixture)
        .map_err(anyhow::Error::msg)
        .context("independent resilience runner failed")?;

    ensure!(
        sdk.len() == 65,
        "SDK runner did not execute all 65 scenarios"
    );
    ensure!(
        reference.len() == 65,
        "reference runner did not execute all 65 scenarios"
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
