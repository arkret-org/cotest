use anyhow::Result;
#[test]
fn core_named_suite_audit_keeps_client_runners_explicitly_deferred() -> Result<()> {
    let report = cotest::conformance::run_named_suite_audit()?;
    assert_eq!(report.fixture_count, 89);
    assert_eq!(report.executed_entrypoints.len(), 52);
    assert_eq!(report.unwired_entrypoints.len(), 34);
    assert_eq!(
        report.deferred_client_entrypoints,
        [
            "ak.suite.account.blocklist_projection.v1",
            "ak.suite.webrtc.media_plaintext_downgrade.v1"
        ]
    );
    Ok(())
}
