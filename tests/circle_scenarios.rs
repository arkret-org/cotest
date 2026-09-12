//! Integration entrypoints for the AKP-0007 Circle conformance
//! scenarios (P2F.3). These tests drive the SDK types directly through
//! the per-scenario `..._run()` functions; they do NOT require a live
//! soland / coauth / floria stack. Cross-project joint tests live in
//! `tests/full_stack_e2e.rs` (run under `--ignored`) and will pick up
//! the Circle strands during P5.

use cotest::scenarios::circle::child_scope_policy::child_scope_policy_run;
use cotest::scenarios::circle::confidential_discussion_relation::confidential_discussion_relation_run;
use cotest::scenarios::circle::create_circle::create_circle_run;
use cotest::scenarios::circle::effective_scope_mismatch::effective_scope_mismatch_run;
use cotest::scenarios::circle::error_code_paths::error_code_paths_run;
use cotest::scenarios::circle::member_strict_subset::member_strict_subset_run;
use cotest::scenarios::circle::member_transition_rules::member_transition_rules_run;
use cotest::scenarios::circle::metadata_encryption_floor::metadata_encryption_floor_run;
use cotest::scenarios::circle::scope_circle_id_immutability::scope_circle_id_immutability_run;
use cotest::scenarios::circle::strand_scope_visibility::strand_scope_visibility_run;

#[tokio::test]
async fn circle_create_round_trip() {
    create_circle_run().await.expect("create_circle scenario");
}

#[tokio::test]
async fn circle_member_strict_subset() {
    member_strict_subset_run()
        .await
        .expect("member_strict_subset scenario");
}

#[tokio::test]
async fn circle_strand_scope_visibility() {
    strand_scope_visibility_run()
        .await
        .expect("strand_scope_visibility scenario");
}

#[tokio::test]
async fn circle_effective_scope_mismatch() {
    effective_scope_mismatch_run()
        .await
        .expect("effective_scope_mismatch scenario");
}

#[tokio::test]
async fn circle_confidential_discussion_relation() {
    confidential_discussion_relation_run()
        .await
        .expect("confidential_discussion_relation scenario");
}

#[tokio::test]
async fn circle_error_code_paths() {
    error_code_paths_run()
        .await
        .expect("error_code_paths scenario");
}

// ── AKP-0007 Phase A invariant scenarios (P2F.3.2).

#[tokio::test]
async fn circle_member_transition_rules() {
    member_transition_rules_run()
        .await
        .expect("member_transition_rules scenario");
}

#[tokio::test]
async fn circle_scope_circle_id_immutability() {
    scope_circle_id_immutability_run()
        .await
        .expect("scope_circle_id_immutability scenario");
}

#[tokio::test]
async fn circle_metadata_encryption_floor() {
    metadata_encryption_floor_run()
        .await
        .expect("metadata_encryption_floor scenario");
}

#[tokio::test]
async fn circle_child_scope_policy() {
    child_scope_policy_run()
        .await
        .expect("child_scope_policy scenario");
}
