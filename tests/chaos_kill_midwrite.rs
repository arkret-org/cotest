//! CT-16 — Chaos: kill server mid-write, restart, verify recovery (entrypoint).
//!
//! Marked `#[ignore]` because the test depends on:
//!   * a persistent-storage harness hook (`ContrixServer::spawn_with_postgres`
//!     and `..._existing`), not yet present;
//!   * a `SOLAND_TEST_CHAOS_DELAY_MS` + breakpoint env hook on soland, to
//!     reliably window the kill into the post-WAL / pre-response gap
//!     (today no such hook exists — `rg "SOLAND_TEST_CHAOS"` is empty);
//!   * a soland diagnostic endpoint that lets the test query the log
//!     directly by `operation_id` post-restart (not via the public POST/
//!     GET surface, which would conflate "server accepted" with "server
//!     saw");
//!   * a race-free `ContrixServer::kill_immediately()` in the harness.
//!
//! See `cotest::scenarios::chaos_kill_midwrite` for the full sketch and
//! prerequisite list.
//!
//! Run with:
//!
//!   cargo test --test chaos_kill_midwrite -- --ignored

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[ignore = "needs persistent-storage harness hook + SOLAND_TEST_CHAOS_DELAY_MS breakpoint + log diagnostic endpoint + kill_immediately helper (see CT-16)"]
#[serial]
async fn chaos_kill_midwrite_then_restart_recovery() -> Result<()> {
    cotest::scenarios::chaos_kill_midwrite::chaos_kill_midwrite_run().await
}
