//! Live issuer-ledger response-loss and Coauth restart gate.

use anyhow::Result;
use serial_test::serial;

#[path = "coauth_session_grant_response_loss/scenario.rs"]
mod scenario;

/// A real PostgreSQL commit survives a killed Coauth process and the exact
/// canonical request replays the issuer's first response after restart.
/// Gating: Requires Coauth, HTTPS Coland, PostgreSQL and owned restart isolation.
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore = "destructive Coauth process-kill test; requires Coauth/Coland binaries and isolated PostgreSQL"]
#[serial]
async fn committed_issue_response_loss_restarts_and_replays_exactly() -> Result<()> {
    scenario::coauth_session_grant_response_loss_run().await
}
