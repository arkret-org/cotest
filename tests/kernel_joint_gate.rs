//! Independent verifier/reducer differential gate for the protocol Kernel.

use cotest::conformance::run_kernel_joint_gate_suite;

#[test]
fn independent_reference_reducer_matches_sdk_and_soland_kernel() {
    run_kernel_joint_gate_suite()
        .expect("independent reference reducer must match the SDK/Soland Kernel");
}
