use anyhow::Result;
use cotest::conformance::audit_direct_conversation_admission_contract;

#[test]
fn direct_conversation_admission_suite_is_audited_but_not_falsely_marked_live() -> Result<()> {
    let coverage = audit_direct_conversation_admission_contract()?;
    assert_eq!(
        coverage.canonical_named_suite,
        "ak.suite.direct_conversation.admission_producers.v1"
    );
    assert_eq!(
        coverage.write_operation_id,
        "ak.self.events.command.submit.v1"
    );
    assert_eq!(
        coverage.read_operation_id,
        "ak.self.direct_conversation.read.resolve.v1"
    );
    assert_eq!(coverage.audited_reason_codes.len(), 7);
    assert_eq!(coverage.audited_negative_cases, 27);
    assert_eq!(coverage.service_e2e_status, "unwired");
    assert_eq!(coverage.blockers.len(), 2);
    Ok(())
}
