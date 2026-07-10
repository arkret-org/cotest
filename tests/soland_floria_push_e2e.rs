//! CT-7 — Soland + Floria push gateway end-to-end (entrypoint).
//!
//! Spawns soland + floria + a mock HTTPS receiver, registers a push device
//! for alice, has bob send a message, and asserts the mock receiver gets a
//! single blind-wakeup envelope (per `push-notifications.md` §2.2 / §4.5).
//!
//! Marked `#[ignore]` because the scenario requires real `soland` and
//! `floria` binaries and still waits on the service-level CT-7 API steps
//! after helper-level env/config wiring succeeds — see the `bail!` in
//! `cotest::scenarios::soland_floria_push_e2e` for the remaining TODO.
//!
//!   cargo test --test soland_floria_push_e2e -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs real `soland` + `floria` binaries plus the outstanding
/// CT-7 service API wiring (push device register + send + receiver mock).
/// Issue: CT-7 (soland + floria push blind-wakeup)
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs soland + floria binaries and remaining CT-7 service API wiring"]
#[serial]
async fn soland_floria_push_blind_wakeup_e2e() -> Result<()> {
    cotest::scenarios::soland_floria_push_e2e::soland_floria_push_blind_wakeup_e2e_run().await
}
