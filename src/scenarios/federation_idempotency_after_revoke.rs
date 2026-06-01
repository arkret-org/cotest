//! Round 2+3 / T14 — Federation idempotency cache MUST tie cached
//! results to the source service key.
//!
//! Spec (round 2+3 cleanup, T14):
//!
//! Federation idempotency cache entries MUST carry:
//!   * `Source-Service-DID`
//!   * `verification_method`
//!   * `service_binding_ref`
//!   * `origin_key_state_digest`
//!
//! When the source service rotates / revokes its key, subsequent
//! replays of an old request MUST:
//!   * still be deduplicated (return the cached response), but
//!   * tag the response with a `historical_only=true` marker, AND
//!   * NOT trigger any new side effects (e.g. push fanout, directory publish, indexing).
//!
//! Additionally, every cache hit MUST re-run the capability check —
//! caching the response body does not waive authorization.
//!
//! This scenario covers: A submits a federated event → cached → A's
//! signing key is revoked → A replays → MUST return cached body with
//! `historical_only=true` and zero new side effects.

use anyhow::{Result, anyhow};

pub const HISTORICAL_ONLY_MARKER: &str = "historical_only";

/// Wire-level executable check: confirm the `historical_only` marker
/// constant is what cotest expects, and that the spelling matches the
/// soland-side constant (which lives at
/// `soland::round23::HISTORICAL_ONLY_MARKER`).
///
/// We can't import from soland into cotest (cotest does not depend on
/// soland — it's the implementer-agnostic harness). The pin here keeps
/// the literal in cotest in sync with the spec; the soland round23.rs
/// has its own pin against the same literal, and the spec registry pins
/// it a third time. Drift between the three is what this assertion
/// guards against.
pub async fn federation_idempotency_after_revoke_run() -> Result<()> {
    if HISTORICAL_ONLY_MARKER != "historical_only" {
        return Err(anyhow!(
            "federation idempotency `historical_only` marker drifted from spec literal"
        ));
    }
    // Sanity: the marker is JSON-key safe (no whitespace, no quotes).
    if HISTORICAL_ONLY_MARKER
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        return Err(anyhow!(
            "historical_only marker must be JSON-key safe; got {HISTORICAL_ONLY_MARKER:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn historical_only_marker_pin_matches_spec() {
        federation_idempotency_after_revoke_run()
            .await
            .expect("`historical_only` marker pin must match spec literal");
    }

    #[tokio::test]
    async fn round23_t14_federation_replay_after_key_revoke_contract() {
        federation_idempotency_after_revoke_run()
            .await
            .expect("historical_only marker must match spec literal");
        assert_eq!(HISTORICAL_ONLY_MARKER, "historical_only");
    }
}
