//! CT-17 — Upgrade: N-1 binary writes, upgrade to N, replay (entrypoint).
//!
//! Marked `#[ignore]` because the test depends on:
//!   * at least one tagged soland release — today `git -C ../soland tag
//!     --list` is empty, so "N-1" is undefined;
//!   * a cross-version build helper in the cotest harness
//!     (`build_at_rev(BuildSpec { rev, target_dir, ... })`), which would
//!     manage a `git worktree` per rev and cache builds — none exists
//!     today;
//!   * a machine-readable schema-migration manifest so the equivalence
//!     check can distinguish "intended migration" from "regression";
//!   * the shared persistent-storage harness hook (also blocking CT-16
//!     and CT-18).
//!
//! See `cotest::scenarios::upgrade_n_minus_one_replay` for the full
//! sketch and prerequisite list.
//!
//! Run with:
//!
//!   cargo test --test upgrade_n_minus_one_replay -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs tagged soland releases + cross-version build helper +
/// schema-migration manifest + persistent-storage harness hook.
/// Issue: CT-17 (N-1 → N upgrade replay)
#[tokio::test]
#[ignore = "needs tagged soland releases + cross-version build helper + schema-migration manifest + persistent-storage harness hook (see CT-17)"]
#[serial]
async fn upgrade_n_minus_one_replay_then_write_under_n() -> Result<()> {
    cotest::scenarios::upgrade_n_minus_one_replay::upgrade_n_minus_one_replay_run().await
}
