//! Execute the existing issuer-record KAT/reference source without the live harness graph.

fn load_fixture_value(file: &str) -> anyhow::Result<serde_json::Value> {
    Ok(arkret_schema_conformance::spec_json_artifact(&format!(
        "fixtures/{file}"
    ))?)
}

#[path = "../../../src/conformance/session_grant_issuer_ledger.rs"]
mod session_grant_issuer_ledger;
