//! C34.3 smoke test for the new bootstrap helpers — `#[ignore]` by default
//! so it only runs on demand (`cargo test --test _bootstrap_smoke -- --ignored`).
//!
//! Exists primarily so `coauth_bootstrap` / `floria_bootstrap` get a lightning
//! bring-up + tear-down round-trip independent of the larger bridge matrix
//! scenario, which is useful during local Docker debugging.

use anyhow::Result;
use cotest::scenarios::_helpers::coauth_bootstrap::{
    spawn_coauth_with_db, spawn_ephemeral_postgres,
};
use cotest::scenarios::_helpers::floria_bootstrap::spawn_floria_with_config;
use cotest::scenarios::_helpers::live_gate::skip_or_fail;
use cotest::scenarios::joint_service_smoke::joint_service_smoke_run;

/// Gating: needs Docker daemon for the ephemeral Postgres image. Soft-skips
/// (prints `skip:`) on an ad hoc `--ignored` run; fails when the lane set
/// `COTEST_REQUIRE_LIVE_SERVICES=1`.
/// Issue: C34.3 (ephemeral Postgres helper smoke)
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn ephemeral_postgres_starts_and_stops() -> Result<()> {
    let pg = spawn_ephemeral_postgres()?;
    match pg {
        Some(pg) => {
            assert!(pg.connect_url.starts_with("postgresql://"));
            eprintln!("ok: ephemeral pg up at {}", pg.connect_url);
        }
        None => {
            skip_or_fail(
                "C34.3 ephemeral Postgres",
                "docker is not available, so no ephemeral Postgres could be started",
            )?;
        }
    }
    Ok(())
}

/// Gating: needs Docker (for ephemeral Postgres) plus a coauth binary. Soft-skips
/// on an ad hoc `--ignored` run; fails when the lane set
/// `COTEST_REQUIRE_LIVE_SERVICES=1`.
/// Issue: C34.3 (coauth bootstrap smoke)
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn coauth_can_be_spawned_with_ephemeral_postgres() -> Result<()> {
    match spawn_coauth_with_db().await? {
        Some(handle) => {
            eprintln!(
                "ok: coauth up at {} (health at {})",
                handle.base_url(),
                handle.health_url()
            );
            // Hit /health one more time via reqwest to confirm. Health is
            // on the SEPARATE internal listener — see SpawnedCoauth docs.
            let resp = reqwest::get(handle.health_url()).await?;
            assert!(resp.status().is_success(), "health: {}", resp.status());
        }
        None => {
            // The bootstrap returns None from any of half a dozen stages, and
            // prints which one it was. Naming a guess here (missing binary,
            // missing database) sends the reader after the wrong thing.
            skip_or_fail(
                "C34.3 coauth bootstrap",
                "the bootstrap did not produce a running coauth — the preceding [coauth_bootstrap] line names the stage that failed; rerun with COTEST_COAUTH_BOOTSTRAP_DEBUG=1 for command details",
            )?;
        }
    }
    Ok(())
}

/// Gating: needs a floria binary on PATH (or `FLORIA_BIN`). Soft-skips on an
/// ad hoc `--ignored` run; fails when the lane set
/// `COTEST_REQUIRE_LIVE_SERVICES=1`.
/// Issue: C34.3 (floria bootstrap smoke)
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn floria_can_be_spawned_with_rendered_config() -> Result<()> {
    match spawn_floria_with_config().await? {
        Some(handle) => {
            eprintln!("ok: floria up at {}", handle.base_url());
            let resp = reqwest::get(format!("{}/health", handle.base_url())).await?;
            assert!(resp.status().is_success(), "health: {}", resp.status());
        }
        None => {
            skip_or_fail(
                "C34.3 floria bootstrap",
                "floria binary not found — set FLORIA_BIN or build the sibling checkout",
            )?;
        }
    }
    Ok(())
}

/// CT-6 — joint service bootstrap smoke (soland + coauth + teabay).
///
/// Marked `#[ignore]` because the full stack needs docker (for coauth's
/// ephemeral postgres), sibling `coauth.exe` / `teabay.exe` binaries, AND a
/// `DATABASE_URL` for teabay. Run with:
///
///   cargo test --test _bootstrap_smoke joint_service_smoke -- --ignored
///
/// When all prereqs are present the test boots the stack and asserts every
/// service answers /health with 2xx; when any piece is missing it bails with
/// a descriptive message naming the missing dependency.
/// Gating: needs Docker (coauth ephemeral Postgres) plus sibling
/// coauth/teabay binaries and a `DATABASE_URL` for teabay.
/// Issue: CT-6 (joint service bootstrap smoke)
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn joint_service_smoke() -> Result<()> {
    joint_service_smoke_run().await
}
