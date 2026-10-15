//! Mandatory actual PostgreSQL and owned SUT evidence for Consent invite cuts.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn independent_grants_and_requester_equivalence_use_the_real_invite_writer() -> Result<()> {
    Box::pin(cotest::scenarios::invite_service_fanout_live::run_current_invite_matrix()).await
}
