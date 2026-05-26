//! CT-8 — Soland + Teabay directory sync latency (entrypoint).
//!
//! The scenario body is fully wired via the CT-6 `FourServiceStack`
//! bootstrap. Test entrypoint is still `#[ignore]` because the stack
//! requires:
//!   - docker (for coauth's ephemeral Postgres),
//!   - sibling `coauth.exe` + `starid.exe` + `teabay.exe` binaries
//!     (or matching `*_BIN` env overrides),
//!   - a reachable `DATABASE_URL` for teabay.
//!
//! When those prereqs are in place, run with:
//!
//!   cargo test --test soland_teabay_directory_sync -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs Docker (coauth ephemeral Postgres) + sibling
/// coauth/starid/teabay binaries + `DATABASE_URL`. The CT-6
/// `FourServiceStack` bootstrap is already wired.
/// Issue: CT-8 (soland + teabay directory sync latency)
#[tokio::test]
#[ignore = "requires DATABASE_URL + starid/teabay/coauth binaries; CT-6 bootstrap is ready"]
#[serial]
async fn profile_update_visible_in_teabay_search_within_30s() -> Result<()> {
    cotest::scenarios::soland_teabay_directory_sync::soland_teabay_directory_sync_run().await
}
