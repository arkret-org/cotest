//! Soland product-integration coverage for live Calendar RSVP convergence.
//!
//! This suite observes the Soland-private materialized Strand projection and
//! is therefore not evidence that another Arkret implementation must expose
//! the same read endpoint.

/// The live product coordinator must seal the bootstrap/control path without
/// any privileged compaction or on-demand ordinary-Event signing.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn calendar_rsvp_converges_across_concurrent_responses() {
    cotest::scenarios::calendar_rsvp_convergence::calendar_rsvp_converges_across_concurrent_responses()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
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
