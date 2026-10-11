//! Shared constructor for live-probe HTTP clients.
//!
//! Scenarios that reach out to a *live* service (coland describe endpoints,
//! bridge-contract surfaces, etc.) MUST use a client with bounded connect /
//! request timeouts, otherwise a service that accepts the connection but never
//! responds hangs the scenario — and the CI job — indefinitely. This is the
//! 5s convention already used by `certification_report` / `flagon_resolve_realm`;
//! centralising it here keeps the timeout policy in one place instead of each
//! call site re-deriving (or forgetting) it.
//!
//! Scenarios that intentionally send malformed requests, or that need bespoke
//! TLS / redirect / per-request timeout configuration, keep their own
//! `reqwest::Client::builder()` and are documented at the call site.

use std::time::Duration;

use anyhow::{Context, Result};

/// Connect + request timeout applied to live-probe clients (5s convention).
const LIVE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a `reqwest::Client` with the shared live-probe timeout policy so a
/// non-responsive service cannot hang the scenario / CI indefinitely.
pub fn live_probe_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(LIVE_PROBE_TIMEOUT)
        .timeout(LIVE_PROBE_TIMEOUT)
        .build()
        .context("building live-probe HTTP client")
}
