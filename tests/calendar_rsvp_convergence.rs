//! Soland product-integration coverage for live Calendar RSVP convergence.
//!
//! This suite observes the Soland-private materialized Strand projection and
//! is therefore not evidence that another Arkret implementation must expose
//! the same read endpoint.

/// Signed RealmCommits order preauthored RSVP Events and select the current
/// response by stream position.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn calendar_rsvp_converges_across_concurrent_responses() {
    cotest::scenarios::calendar_rsvp_convergence::calendar_rsvp_converges_across_concurrent_responses()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn calendar_rsvp_malformed_basis_is_rejected() {
    cotest::scenarios::calendar_rsvp_convergence::calendar_rsvp_malformed_basis_is_rejected()
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
