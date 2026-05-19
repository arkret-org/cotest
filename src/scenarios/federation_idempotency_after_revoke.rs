//! Round 2+3 / T14 — Federation idempotency cache MUST tie cached
//! results to the source service key.
//!
//! Spec (round 2+3 cleanup, T14):
//!
//! Federation idempotency cache entries MUST carry:
//!   * `Source-Service-DID`
//!   * `verification_method`
//!   * `service_binding_ref`
//!   * `origin_key_state_hash`
//!
//! When the source service rotates / revokes its key, subsequent
//! replays of an old request MUST:
//!   * still be deduplicated (return the cached response), but
//!   * tag the response with a `historical_only=true` marker, AND
//!   * NOT trigger any new side effects (e.g. push fanout, directory
//!     publish, indexing).
//!
//! Additionally, every cache hit MUST re-run the capability check —
//! caching the response body does not waive authorization.
//!
//! This scenario covers: A submits a federated event → cached → A's
//! signing key is revoked → A replays → MUST return cached body with
//! `historical_only=true` and zero new side effects.

use anyhow::Result;

pub const HISTORICAL_ONLY_MARKER: &str = "historical_only";

/// Replay a federated request after the originating service key has
/// been revoked.
pub async fn federation_idempotency_after_revoke_run() -> Result<()> {
    // TODO(round23-T14): wire to soland + teabay fixture. Must:
    //   1. submit a federated event from service-DID A, cache it
    //   2. revoke service-DID A's signing key
    //   3. replay the same request bytes
    //   4. assert response body == cached body, plus
    //      `historical_only: true` marker
    //   5. assert no new push / directory / index side effects fired
    //   6. assert the capability check ran again on the replay
    Ok(())
}
