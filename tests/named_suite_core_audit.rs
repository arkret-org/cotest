use anyhow::Result;
#[test]
fn core_named_suite_audit_keeps_client_runners_explicitly_deferred() -> Result<()> {
    let report = cotest::conformance::inspect_named_suite_execution_with_clients(&[])?;
    println!("{report:#?}");
    assert!(!report.executed_entrypoints.is_empty());
    assert!(report.assert_complete().is_err());
    assert!(
        report
            .unproved_entrypoints
            .iter()
            .any(|id| id == "ak.suite.sdk.precheck.v1")
    );
    assert!(
        report
            .unproved_entrypoints
            .iter()
            .any(|id| id == "ak.suite.identity.test_material_rejection.v1")
    );
    assert!(
        report
            .decision_point_gaps
            .iter()
            .any(|gap| gap.decision_point == "AK-SDK-001/no_effect_reaches_the_reducer")
    );
    assert_eq!(
        report.deferred_client_entrypoints,
        [
            "ak.suite.account.blocklist_projection.v1",
            "ak.suite.webrtc.media_plaintext_downgrade.v1",
            "ak.suite.sync.client_account_stream.v1"
        ]
    );
    Ok(())
}
