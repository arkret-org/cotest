//! Live Calendar RSVP convergence.

/// The live product coordinator must seal the bootstrap/control path without
/// any admin compaction or on-demand frontier signing.
#[tokio::test(flavor = "multi_thread")]
async fn calendar_rsvp_converges_across_concurrent_responses() {
    cotest::scenarios::calendar_rsvp_convergence::calendar_rsvp_converges_across_concurrent_responses()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn calendar_rsvp_without_cell_effect_is_rejected() {
    cotest::scenarios::calendar_rsvp_convergence::calendar_rsvp_without_cell_effect_is_rejected()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn calendar_rsvp_persists_across_restart_and_replay() {
    cotest::scenarios::calendar_rsvp_convergence::calendar_rsvp_persists_across_restart_and_replay(
    )
    .await
    .unwrap();
}
