//! C.8 — smoke test for testcontainers bring-up wiring.
//!
//! The container path is Linux-only and only when the
//! `test-with-containers` feature is on.

/// Gating: requires Linux + the `test-with-containers` feature + a
/// running Docker daemon. Skipped on Windows and on default-feature
/// builds because testcontainers + named-pipe docker-engine on Windows
/// is unreliable.
/// Tier: live
#[cfg(all(not(target_os = "windows"), feature = "test-with-containers"))]
#[test]
#[ignore = "Gating: requires `test-with-containers` feature + Linux + Docker daemon"]
fn testcontainers_postgres_bringup_smoke() {
    use cotest::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres_testcontainers;
    let pg = spawn_ephemeral_postgres_testcontainers().expect("bring-up returned");
    let Some(pg) = pg else {
        eprintln!("docker daemon unavailable on this runner — skipping");
        return;
    };
    assert!(
        pg.connect_url
            .starts_with("postgresql://arkret:arkret@127.0.0.1:")
    );
}
