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
    let production_results = report.production_executions.iter().map(|suite| {
        serde_json::json!({
            "entrypoint": suite.entrypoint,
            "fixture": suite.fixture,
            "cases": suite.cases.iter().map(|case| serde_json::json!({"case_id":case.case_id,"assertions":case.assertions})).collect::<Vec<_>>()
        })
    }).collect::<Vec<_>>();
    println!(
        "[named-suite-production-results] {}",
        serde_json::to_string(&production_results)?
    );
    let safe_report = serde_json::json!({
        "fixture_count":report.fixture_count,
        "executed_entrypoints":report.executed_entrypoints,
        "unwired_entrypoints":report.unwired_entrypoints,
        "deferred_client_entrypoints":report.deferred_client_entrypoints,
        "unproved_entrypoints":report.unproved_entrypoints,
        "failed_entrypoints":report.failed_executions.iter().map(|(id,_,_)|id).collect::<Vec<_>>(),
        "decision_point_gaps":report.decision_point_gaps.iter().map(|gap|serde_json::json!({"decision_point":gap.decision_point,"missing_cases":gap.missing_cases.iter().map(|case|serde_json::json!({"fixture_ref":case.fixture_ref,"case_id":case.case_id})).collect::<Vec<_>>()})).collect::<Vec<_>>(),
        "missing_production_cases":report.missing_production_cases.iter().map(|case|serde_json::json!({"fixture_ref":case.fixture_ref,"case_id":case.case_id})).collect::<Vec<_>>(),
        "production_executions":production_results,
        "complete_suite_claim":report.assert_complete().is_ok()
    });
    println!(
        "[named-suite-audit-safe-json] {}",
        serde_json::to_string(&safe_report)?
    );

    for (entrypoint, count) in [
        ("ak.suite.agent.vectors.v1", 96),
        (cotest::conformance::SYNC_CLIENT_ENTRYPOINT, 23),
    ] {
        let execution = report
            .production_executions
            .iter()
            .filter(|suite| suite.entrypoint == entrypoint)
            .collect::<Vec<_>>();
        assert_eq!(
            execution.len(),
            1,
            "exactly one production result required for {entrypoint}"
        );
        assert_eq!(execution[0].cases.len(), count);
        assert!(execution[0].cases.iter().all(|case| case.assertions > 0));
    }

    assert!(
        report.failed_executions.is_empty(),
        "registered runner failed: {:?}",
        report.failed_executions
    );
    assert!(report.assert_complete().is_err());
    assert!(report.deferred_client_entrypoints.is_empty());
    let sync = cotest::conformance::SYNC_CLIENT_ENTRYPOINT;
    assert!(report.executed_entrypoints.iter().any(|id| id == sync));
    assert!(!report.unproved_entrypoints.iter().any(|id| id == sync));
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
        declared - cotest_inkson_client_tests::conformance::client_sync::PRODUCTION_CASE_COUNT
    );
    assert!(
        report
            .executed_entrypoints
            .iter()
            .any(|entrypoint| entrypoint == "ak.suite.account.blocklist_projection.v1")
    );
    for client in [
        "ak.suite.consent.cache_invalidation.v1",
        "ak.suite.account.blocklist_projection.v1",
    ] {
        assert!(report.executed_entrypoints.iter().any(|id| id == client));
        assert!(!report.unwired_entrypoints.iter().any(|id| id == client));
        assert!(!report.failed_executions.iter().any(|(id, ..)| id == client));
    }
    assert!(!report.decision_point_gaps.is_empty());
    let federation = "ak.suite.federation.idempotency_after_key_revoke.v1";
    assert!(
        report
            .executed_entrypoints
            .iter()
            .any(|id| id == federation)
    );
    assert!(!report.unwired_entrypoints.iter().any(|id| id == federation));
    assert!(
        !report
            .unproved_entrypoints
            .iter()
            .any(|id| id == federation)
    );
    assert!(
        !report
            .failed_executions
            .iter()
            .any(|(id, ..)| id == federation)
    );
    let missing_federation = report
        .missing_production_cases
        .iter()
        .filter(|case| {
            case.fixture_ref == "fixtures/federation-idempotency-key-revoke-fixture.json"
        })
        .map(|case| case.case_id.as_str())
        .collect::<Vec<_>>();
    assert!(missing_federation.is_empty());
    for required_gap in [
        "ak.suite.call.force_mute_v1_boundary.v1",
        "ak.suite.current.cas_failure_read_boundary.v1",
        "ak.suite.direct_conversation.admission_producers.v1",
        "ak.suite.direct_conversation.signal_admission.v1",
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
