//! C34.3 smoke test for the new bootstrap helpers — `#[ignore]` by default
//! so it only runs on demand (`cargo test --test _bootstrap_smoke -- --ignored`).
//!
//! Exists primarily so `coauth_bootstrap` / `floria_bootstrap` get a lightning
//! bring-up + tear-down round-trip independent of the larger bridge matrix
//! scenario, which is useful during local Docker debugging.

use anyhow::Result;
use cotest::scenarios::_helpers::coauth_bootstrap::{
    bootstrap_coauth_config, spawn_coauth_with_db, spawn_ephemeral_postgres,
};
use cotest::scenarios::_helpers::floria_bootstrap::spawn_floria_with_config;
use cotest::scenarios::four_service_smoke::four_service_smoke_run;
use cotest::scenarios::identity_deployment_smoke::identity_deployment_smoke_run;

/// Gating: manual debug helper — needs a built coauth binary at the
/// hard-coded sibling path. Not for CI.
/// Issue: C34.3 (coauth bootstrap config debug)
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn dump_patched_coauth_config() -> Result<()> {
    use std::path::Path;
    let bin = Path::new("D:/Works/arkret/coauth/target/debug/coauth.exe");
    if !bin.exists() {
        eprintln!("skip: coauth binary not found");
        return Ok(());
    }
    let bundle = bootstrap_coauth_config(
        bin,
        "postgresql://arkret:arkret@127.0.0.1:5432/arkret",
        "127.0.0.1:9999",
    )?;
    eprintln!("internal_addr: {}", bundle.internal_addr);
    eprintln!("---");
    eprintln!("{}", std::fs::read_to_string(bundle.file.path())?);
    Ok(())
}

/// Gating: needs Docker daemon for the ephemeral Postgres image; soft-skips
/// (prints `skip:`) when docker is unavailable.
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
            eprintln!("skip: docker not available");
        }
    }
    Ok(())
}

/// Gating: needs Docker (for ephemeral Postgres) plus a coauth binary;
/// soft-skips when prereqs are missing.
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
            eprintln!("skip: coauth bootstrap reported missing prerequisites (docker / binary)");
        }
    }
    Ok(())
}

/// Gating: needs a floria binary on PATH (or `FLORIA_BIN`); soft-skips
/// when the binary is missing.
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
            eprintln!("skip: floria bootstrap reported missing binary");
        }
    }
    Ok(())
}

/// CT-6 — four-service joint bootstrap smoke (soland + coauth + starid + teabay).
///
/// Marked `#[ignore]` because the full stack needs docker (for coauth's
/// ephemeral postgres), sibling `coauth.exe` / `starid.exe` / `teabay.exe`
/// binaries, AND a `DATABASE_URL` for teabay. Run with:
///
///   cargo test --test _bootstrap_smoke four_service_joint_smoke -- --ignored
///
/// When all prereqs are present the test boots the stack and asserts every
/// service answers /health with 2xx; when any piece is missing it bails with
/// a descriptive message naming the missing dependency.
/// Gating: needs Docker (coauth ephemeral Postgres) plus sibling
/// coauth/starid/teabay binaries and a `DATABASE_URL` for teabay.
/// Issue: CT-6 (four-service joint bootstrap smoke)
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn four_service_joint_smoke() -> Result<()> {
    four_service_smoke_run().await
}

/// Production Starid + Soland + Coauth identity deployment contract. This is
/// ignored only outside the explicit live lane; once selected it has no
/// missing-dependency or assertion soft-skip path.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn identity_deployment_smoke() -> Result<()> {
    identity_deployment_smoke_run().await
}
