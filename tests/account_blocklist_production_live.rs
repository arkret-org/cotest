//! Production-only blocklist evidence; missing client cases stay uncertified.

use anyhow::Result;

#[tokio::test(flavor = "multi_thread")]
async fn blocklist_whole_value_cas_runs_through_http_and_postgres() -> Result<()> {
    let result = cotest::conformance::run_account_blocklist_production_cases().await?;
    assert_eq!(result.cases.len(), 5);
    assert_eq!(
        result
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>(),
        [
            "whole_value_cas_rejects_a_stale_expected_revision",
            "whole_value_cas_rejects_a_stale_concurrent_write",
            "unregistered_blocklist_event_kind_is_not_an_authoring_surface",
            "target_closure_rejects_realm_and_organization_targets",
            "an_unsynced_device_treats_freshness_as_unknown",
        ]
    );
    assert!(result.cases.iter().all(|case| case.assertions > 0));
    Ok(())
}

#[test]
fn blocklist_full_suite_refuses_missing_production_case_executors() {
    let error = cotest::conformance::run_account_blocklist_projection_suite().unwrap_err();
    let error = error.to_string();
    for case in [
        "shared_history_is_received_then_filtered_by_the_holder",
        "unblock_rebuilds_the_projection_from_retained_material",
        "holder_side_request_filtering_stays_indistinguishable",
    ] {
        assert!(error.contains(case), "missing case must be named: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn blocklist_real_call_invite_uses_accepted_ordinary_call_and_sealed_delivery() -> Result<()>
{
    cotest::scenarios::mls_lifecycle_live::run_blocklist_call_invite_live().await
}
