use anyhow::{Context, Result};

#[test]
fn genesis_timestamp_cases_run_http_pg_zero_effects_and_restart() -> Result<()> {
    let fixture =
        cotest::conformance::load_fixture_value("mls-creator-bootstrap-recovery-fixture.json")?;
    let cases = fixture["timestamp_gate_cases"]
        .as_array()
        .context("timestamp cases")?
        .clone();
    cotest::scenarios::mls_genesis_timestamp::run_live(cases)?;
    Ok(())
}
