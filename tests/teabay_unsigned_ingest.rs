//! TB-3 — teabay unsigned-ingest rejection gate (entrypoint).
//!
//! Verifies an unsigned `POST /api/v1/directory/announce` is rejected at the
//! transport layer with 401/403. TB-1 has landed — see
//! `teabay/crates/server/src/middleware/http_sig.rs` and the
//! `.hoop(HttpSigMiddleware::new(...))` wire-up in
//! `teabay/crates/server/src/routing.rs::directory_router` — so the
//! enforcement logic itself is in place and unit-tested at
//! `cargo test -p server --lib http_sig` (6 tests cover signed pass,
//! unsigned 401, wrong-key 401, body-mutated 401, malformed-header 400,
//! passthrough mode).
//!
//! This end-to-end scenario remains `#[ignore]` because it spawns the
//! teabay binary and exercises the live HTTP stack — it requires
//! `TEABAY_BIN` (or a debug build at `contrix-dev/teabay/target/debug/`)
//! plus a Postgres `DATABASE_URL`. Opt in locally with:
//!
//!   cargo test --test teabay_unsigned_ingest -- --ignored
//!
//! When run, an unsigned envelope MUST come back 401
//! `unauthenticated` (the canonical Contrix v1 errcode for missing
//! transport auth). If the test fails with 200, TB-1's `.hoop(...)`
//! got dropped from the router; if it fails with anything other than
//! 401/403, a future change weakened the middleware.

use anyhow::Result;
use serial_test::serial;

/// Gating: spawns the teabay binary against a live Postgres — needs
/// `TEABAY_BIN` (or a sibling debug build) + `DATABASE_URL`. Middleware
/// itself (TB-1) is shipped and unit-tested.
/// Issue: TB-3 (teabay unsigned-ingest rejection)
#[tokio::test]
#[ignore = "TB-1 middleware landed; this test still requires teabay binary + Postgres in the cotest harness for execution. Run with --ignored to exercise."]
#[serial]
async fn teabay_rejects_unsigned_ingest() -> Result<()> {
    cotest::scenarios::teabay_unsigned_ingest::teabay_rejects_unsigned_ingest_run().await
}
