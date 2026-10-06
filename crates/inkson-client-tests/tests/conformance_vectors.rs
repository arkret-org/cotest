use anyhow::Result;
use cotest_inkson_client_tests::conformance::{
    run_named_suite_audit, run_webrtc_media_plaintext_suite,
};

#[test]
fn webrtc_media_plaintext_named_suite_returns_one_result_per_case() -> Result<()> {
    let execution = run_webrtc_media_plaintext_suite()?;
    assert_eq!(execution.cases.len(), 5);
    Ok(())
}

#[test]
fn named_suite_audit_executes_registered_runners_and_exposes_every_gap() -> Result<()> {
    let report = run_named_suite_audit()?;
    assert_eq!(report.fixture_count, 89);
    assert!(report.deferred_client_entrypoints.is_empty());
    assert_eq!(report.executed_entrypoints.len(), 54);
    assert!(
        report
            .executed_entrypoints
            .iter()
            .any(|entrypoint| entrypoint == "ak.suite.pin.admission_and_scope.v1")
    );
    assert_eq!(report.unwired_entrypoints.len(), 34);
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
fn account_blocklist_projection_vector_executes_complete_production_suite() -> Result<()> {
    assert_eq!(
        cotest_inkson_client_tests::conformance::VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION,
        "ak.vector.account.blocklist_projection.v1"
    );
    cotest_inkson_client_tests::conformance::run_account_blocklist_projection_vector()?;
    Ok(())
}
