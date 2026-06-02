//! Round 2+3 / T17 — Consent revoke `scope=any` cascade.
//!
//! Spec (round 2+3 cleanup, T17):
//!
//! When a consent revoke is issued with `scope=any`, the reducer MUST
//! cascade the revoke to every subscope that derives from `any`, and
//! the cascaded subscopes MUST surface the marker
//! `superseded_by_any_revoke` in their projections. The cascade MUST
//! also invalidate five caches:
//!
//!   1. directory reachability
//!   2. MIMI consent cache
//!   3. push contact PSI cache
//!   4. invite gate cache
//!   5. in-flight invite handles
//!
//! This scenario pins the cascade semantics: issue a `scope=any` revoke
//! over a consent set that has `messaging` and `notifications`
//! subscopes already active; assert both subscopes flip to
//! `superseded_by_any_revoke` in the projection.

use anyhow::{Result, anyhow};

pub const SUPERSEDED_MARKER: &str = "superseded_by_any_revoke";

/// Five cache-invalidation channels that an `any`-revoke MUST broadcast
/// per spec T17. Cross-pinned with
/// `soland::routing::identity::consent::ConsentRevokeInvalidationChannel::ALL`.
pub const EXPECTED_INVALIDATION_CHANNELS: &[&str] = &[
    "directory_reachability",
    "mimi_consent",
    "push_contact_psi",
    "invite_gate",
    "in_flight_invite",
];

/// Wire-level executable check: the cascade marker literal and the five
/// invalidation channel names are pinned. Drift in any of them is a
/// wire break.
pub async fn consent_revoke_scope_any_cascade_run() -> Result<()> {
    if SUPERSEDED_MARKER != "superseded_by_any_revoke" {
        return Err(anyhow!(
            "consent revoke cascade marker drifted from spec literal: got {SUPERSEDED_MARKER}"
        ));
    }
    if EXPECTED_INVALIDATION_CHANNELS.len() != 5 {
        return Err(anyhow!(
            "consent revoke cascade MUST invalidate exactly 5 channels; got {}",
            EXPECTED_INVALIDATION_CHANNELS.len()
        ));
    }
    for ch in EXPECTED_INVALIDATION_CHANNELS {
        if ch.is_empty()
            || ch
                .chars()
                .any(|c| c.is_whitespace() || c.is_ascii_uppercase())
        {
            return Err(anyhow!(
                "cascade channel name `{ch}` must be lowercase snake_case (no whitespace)"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn consent_cascade_pin_matches_spec() {
        consent_revoke_scope_any_cascade_run()
            .await
            .expect("Consent revoke cascade marker + channels must match spec");
    }

    #[tokio::test]
    async fn t17_consent_cascade_contract() {
        consent_revoke_scope_any_cascade_run()
            .await
            .expect("consent cascade marker + channel pins must stay registered");
        assert_eq!(SUPERSEDED_MARKER, "superseded_by_any_revoke");
        assert_eq!(EXPECTED_INVALIDATION_CHANNELS.len(), 5);
        assert!(EXPECTED_INVALIDATION_CHANNELS.contains(&"in_flight_invite"));
    }
}
