//! CT-6 — Four-service joint smoke scenario.
//!
//! Verifies the [`FourServiceStack`] bootstrap can spin up soland + coauth +
//! starid + teabay together and each service answers `/health` with 2xx.
//!
//! Marked `#[ignore]` at the test-entrypoint level because the full stack
//! needs: docker (for coauth's ephemeral postgres), sibling `coauth.exe`,
//! sibling `starid.exe`, sibling `teabay.exe`, AND a `DATABASE_URL`
//! pointing at a reachable Postgres for teabay. Operators who have all of
//! those in place can run:
//!
//!   cargo test --test _bootstrap_smoke four_service_smoke -- --ignored
//!
//! When run with the prereqs in place the test boots the stack and asserts
//! every service is healthy; without them it bails with a descriptive
//! message naming the missing piece.

use anyhow::Result;

use crate::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, bootstrap_required};

/// CT-6 four-service smoke probe. Boots the full stack, calls
/// `assert_healthy` on every service, then drops everything in LIFO order.
pub async fn four_service_smoke_run() -> Result<()> {
    let config = FourServiceConfig::new("ct6-smoke");
    let stack = bootstrap_required(config).await?;
    stack.assert_healthy().await?;
    Ok(())
}
