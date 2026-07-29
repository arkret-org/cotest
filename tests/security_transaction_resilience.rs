//! Two-runner differential gate for the security-transaction resilience fixture.

use cotest::conformance::run_security_transaction_resilience_joint_gate;

#[test]
fn sdk_and_independent_runner_match_all_resilience_scenarios() {
    run_security_transaction_resilience_joint_gate()
        .expect("security transaction resilience runners must converge");
}
