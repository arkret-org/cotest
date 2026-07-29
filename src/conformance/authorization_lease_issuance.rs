use anyhow::{Context, Result, ensure};

use super::authorization_lease_issuance_reference;

pub fn run_authorization_lease_issuance_joint_gate() -> Result<()> {
    let reference_source = include_str!("authorization_lease_issuance_reference.rs");
    for forbidden in [
        "use arkret_",
        "use soland",
        "arkret_wire::",
        "arkret_state::",
        "soland_",
    ] {
        ensure!(
            !reference_source.contains(forbidden),
            "independent authorization lease runner crossed dependency fence via {forbidden}"
        );
    }
    let fixture =
        arkret_schema::embedded_json_artifact("fixtures/authorization-lease-issuance-fixture.json")
            .context("load embedded authorization lease issuance fixture")?;
    let sdk = arkret_wire::run_authorization_lease_issuance_fixture(&fixture)
        .context("SDK authorization lease runner failed")?;
    let reference = authorization_lease_issuance_reference::run(&fixture)
        .map_err(anyhow::Error::msg)
        .context("independent authorization lease runner failed")?;
    ensure!(sdk.len() == 6, "SDK runner did not execute all six cases");
    ensure!(
        reference.len() == 6,
        "reference runner did not execute all six cases"
    );
    ensure!(
        serde_json::to_value(&sdk)? == serde_json::to_value(&reference)?,
        "authorization lease issuance runners diverged"
    );
    Ok(())
}
