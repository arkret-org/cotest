use anyhow::Result;
use cotest_inkson_client_tests::conformance::{
    inspect_named_suite_execution, run_webrtc_media_plaintext_suite,
};

#[test]
fn webrtc_media_plaintext_named_suite_returns_one_result_per_case() -> Result<()> {
    let execution = run_webrtc_media_plaintext_suite()?;
    assert_eq!(execution.cases.len(), 5);
    Ok(())
}

#[test]
#[serial_test::serial]
fn named_suite_audit_executes_registered_runners_and_exposes_every_gap() -> Result<()> {
    let report = inspect_named_suite_execution()?;
    println!("{report:#?}");
    assert!(report.assert_complete().is_err());
    assert!(report.deferred_client_entrypoints.is_empty());
    let sync = cotest::conformance::SYNC_CLIENT_ENTRYPOINT;
    assert!(report.executed_entrypoints.iter().any(|id| id == sync));
    assert!(report.unproved_entrypoints.iter().any(|id| id == sync));
    assert!(!report.failed_executions.iter().any(|(id, ..)| id == sync));
    let fixture = cotest::conformance::load_fixture_value("client-sync-fixture.json")?;
    let declared = [
        "stream_tails",
        "checkpoint_ordering",
        "reconnect",
        "delivery_cancellation",
    ]
    .into_iter()
    .map(|section| fixture[section].as_array().unwrap().len())
    .sum::<usize>();
    assert_eq!(
        report
            .missing_production_cases
            .iter()
            .filter(|case| case.fixture_ref == "fixtures/client-sync-fixture.json")
            .count(),
        declared - 3
    );
    assert!(
        report
            .executed_entrypoints
            .iter()
            .any(|entrypoint| entrypoint == "ak.suite.account.blocklist_projection.v1")
    );
    assert!(!report.decision_point_gaps.is_empty());
    for required_gap in [
        "ak.suite.call.force_mute_v1_boundary.v1",
        "ak.suite.current.cas_failure_read_boundary.v1",
        "ak.suite.consent.cache_invalidation.v1",
        "ak.suite.direct_conversation.admission_producers.v1",
        "ak.suite.direct_conversation.signal_admission.v1",
        "ak.suite.federation.idempotency_after_key_revoke.v1",
        "ak.suite.reaction.authority_order.v1",
        "ak.suite.invite.claim_security.v1",
        "ak.suite.peer.event_submit.semantic_union.v1",
        "ak.suite.signer_key.historical_commit_coordinate.v1",
    ] {
        assert!(
            report
                .unwired_entrypoints
                .iter()
                .any(|entrypoint| entrypoint == required_gap),
            "audit must keep the unimplemented priority suite visible: {required_gap}"
        );
    }
    Ok(())
}

#[test]
#[serial_test::serial]
fn account_blocklist_projection_vector_executes_complete_production_suite() -> Result<()> {
    assert_eq!(
        cotest_inkson_client_tests::conformance::VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION,
        "ak.vector.account.blocklist_projection.v1"
    );
    cotest_inkson_client_tests::conformance::run_account_blocklist_projection_vector()?;
    Ok(())
}
