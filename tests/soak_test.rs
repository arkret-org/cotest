//! CT-18 — Soak: 100 actors × 10k messages (entrypoint).
//!
//! Marked `#[ignore]` because this is a long-running (100s+ wall time,
//! ~1M events) test that intentionally does NOT belong on the per-PR
//! default profile. It opts in via the `soak` CI profile (see
//! `cotest/config/ci-profiles.json`) or manually:
//!
//!   ./scripts/run-cotest.ps1 -Profile soak
//!   # or:
//!   cargo test --test soak_test -- --ignored
//!
//! Beyond the time cost, the test depends on:
//!   * the shared persistent-storage harness hook (also blocking CT-16
//!     and CT-17);
//!   * per-process memory introspection (cross-platform RSS reading, or
//!     a soland Prometheus `/metrics` endpoint);
//!   * the `hdrhistogram` crate for latency percentile sampling (not
//!     yet a cotest dep);
//!   * an anchor-store row-count probe (admin endpoint or Pg query
//!     helper);
//!   * dedicated CI capacity (self-hosted runner or nightly cron — not
//!     a shared GitHub Actions micro-VM).
//!
//! See `cotest::scenarios::soak_test` for the full sketch + threshold
//! constant calibration plan.

use anyhow::Result;
use serial_test::serial;

/// Gating: long-running soak (100 actors × 10k messages, ~1M events) —
/// opt-in via `--profile soak`. Also needs the shared persistent-storage
/// harness hook, per-process memory introspection, `hdrhistogram`, and
/// an anchor-store row-count probe.
/// Issue: CT-18 (soak test)
#[tokio::test]
#[ignore = "long-running soak; opt-in via --profile soak; also needs persistent-storage harness hook + memory introspection + hdrhistogram + anchor row-count probe (see CT-18)"]
#[serial]
async fn soak_100_actors_10k_messages() -> Result<()> {
    cotest::scenarios::soak_test::soak_100x10k_run().await
}
