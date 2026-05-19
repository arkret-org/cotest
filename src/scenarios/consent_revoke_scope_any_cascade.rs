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

use anyhow::Result;

pub const SUPERSEDED_MARKER: &str = "superseded_by_any_revoke";

/// Drive the cascade and assert subscope state.
pub async fn consent_revoke_scope_any_cascade_run() -> Result<()> {
    // TODO(round23-T17): wire to soland consent reducer + teabay /
    // floria / coauth invalidation broadcast. Must:
    //   1. issue subscope consents (messaging, notifications)
    //   2. issue a `scope=any` revoke
    //   3. assert both subscope projections show `SUPERSEDED_MARKER`
    //   4. assert the 5 caches all received invalidation
    Ok(())
}
