//! Live issuer-ledger response-loss and Coauth restart gate.

use anyhow::Result;
use serial_test::serial;

/// A real PostgreSQL commit survives a killed Coauth process and the exact
/// canonical request replays the issuer's first response after restart.
/// Gating: Requires Coauth, PostgreSQL and destructive process restart isolation.
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore = "destructive Coauth process-kill test; requires COAUTH_BIN or sibling binary plus Docker/PostgreSQL"]
#[serial]
async fn committed_issue_response_loss_restarts_and_replays_exactly() -> Result<()> {
    cotest::scenarios::coauth_session_grant_response_loss::coauth_session_grant_response_loss_run()
        .await
}
