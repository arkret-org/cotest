//! Two-runner differential gate for authorization lease issuance.

use cotest::conformance::run_authorization_lease_issuance_joint_gate;

#[test]
fn sdk_and_independent_runner_match_all_authorization_lease_cases() {
    run_authorization_lease_issuance_joint_gate()
        .expect("authorization lease issuance runners must converge");
}
