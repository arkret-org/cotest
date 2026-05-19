//! Round 2+3 / T09 — `cx.profile.e2ee_relaxed.v1` hard ceiling and
//! compliance-profile mutex.
//!
//! Spec (round 2+3 cleanup, T09):
//!
//! `cx.profile.e2ee_relaxed.v1` defines `absolute_hard_ceiling_ms =
//! 300000` (5 minutes). The reducer MUST refuse:
//!
//!   * `relaxed_window_max_ms > 300000` → `relaxed_window_exceeds_ceiling`
//!   * enabling `e2ee_relaxed.v1` while any of these compliance profiles
//!     are active on the same Realm:
//!       - `cx.profile.attested_audit.e2ee.v1`
//!       - `cx.profile.disclosed_audit.e2ee.v1`
//!     → `e2ee_relaxed_disallowed_in_compliance_profile`
//!
//! This module covers the two negative branches.

use anyhow::Result;

pub const ABSOLUTE_HARD_CEILING_MS: u64 = 300_000;

pub const EXPECTED_RELAXED_EXCEEDS_CEILING: &str = "relaxed_window_exceeds_ceiling";
pub const EXPECTED_RELAXED_DISALLOWED_IN_COMPLIANCE: &str =
    "e2ee_relaxed_disallowed_in_compliance_profile";

/// Submit a `cx.realm.policy_components` write with
/// `relaxed_window_max_ms = 400_000` (above the hard ceiling).
pub async fn e2ee_relaxed_window_exceeds_ceiling_run() -> Result<()> {
    // TODO(round23-T09): wire to soland policy_components reducer.
    // Must build a policy_components payload with
    // `relaxed_window_max_ms = 400_000` and assert the reducer
    // returns `relaxed_window_exceeds_ceiling`.
    Ok(())
}

/// Enable `cx.profile.e2ee_relaxed.v1` on a Realm that already has
/// `cx.profile.attested_audit.e2ee.v1` active.
pub async fn e2ee_relaxed_disallowed_in_compliance_run() -> Result<()> {
    // TODO(round23-T09): wire to soland policy_components reducer.
    // Must set up a Realm with attested_audit.e2ee.v1, then attempt to
    // enable e2ee_relaxed.v1, and assert the reducer returns
    // `e2ee_relaxed_disallowed_in_compliance_profile`.
    Ok(())
}
