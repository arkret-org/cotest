use anyhow::Result;
use cotest::conformance::forbidden_wire::ForbiddenWireScanner;
use cotest::scenarios::registry_drift::*;
use serde_json::json;

#[test]
fn forbidden_wire_scanner_uses_registered_contexts_and_rejects_actual_mutations() -> Result<()> {
    let scanner = ForbiddenWireScanner::new(
        artifact("registry/forbidden-wire-fields.json")?,
        artifact("registry/event-kind-registry.json")?,
    )?;
    for value in [
        json!({"account_data_type":"retired"}),
        json!({"nested":[{"account_data_types":[]}]} ),
    ] {
        assert!(!scanner.scan(&value, "http_response", "*")?.is_empty());
    }
    assert!(
        scanner
            .scan(&json!({"account_data_key":"current"}), "http_response", "*")?
            .is_empty()
    );
    assert!(
        scanner
            .scan_event(&json!({"kind":"unregistered.kind"}))
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn registry_drift_runs_against_station() -> Result<()> {
    cotest::scenarios::registry_drift::registry_drift_runs_against_station().await
}

#[tokio::test]
/// Gating: requires the real Coauth/Coland deployment; mandatory in the joint API migration gate.
/// Tier: live
#[ignore = "requires the real Coauth/Coland deployment; mandatory in the joint API migration gate"]
async fn canonical_registry_drift_api_migration() -> Result<()> {
    cotest::scenarios::registry_drift::canonical_registry_drift_api_migration().await
}
