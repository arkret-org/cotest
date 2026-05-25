//! CT-16 - Chaos: kill server mid-write, restart, verify recovery.
//!
//! This test is opt-in because it starts Postgres (or uses
//! `COTEST_SOLAND_DATABASE_URL`) and deliberately terminates a child soland
//! process mid-request.
//!
//! Run with:
//!
//!   cargo test --test chaos_kill_midwrite -- --ignored --nocapture

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[ignore = "destructive process-kill chaos test; requires COTEST_SOLAND_DATABASE_URL or Docker for ephemeral Postgres"]
#[serial]
async fn chaos_kill_midwrite_then_restart_recovery() -> Result<()> {
    cotest::scenarios::chaos_kill_midwrite::chaos_kill_midwrite_run().await
}
