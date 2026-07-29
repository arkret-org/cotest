use anyhow::Result;

#[test]
fn recovery_transaction_remote_side_effect_fault_matrix() -> Result<()> {
    cotest::conformance::recovery_transaction_faults::run_recovery_transaction_fault_matrix()
}

#[test]
fn recovery_authority_holder_and_candidate_negative_matrix() -> Result<()> {
    cotest::conformance::recovery_transaction_faults::
        run_recovery_authority_replay_and_candidate_matrix()
}
