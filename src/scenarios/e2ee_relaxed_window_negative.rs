//! Round 2+3 / T09 — `ck.profile.e2ee_relaxed.v1` hard ceiling and
//! compliance-profile mutex.
//!
//! Spec (round 2+3 cleanup, T09):
//!
//! `ck.profile.e2ee_relaxed.v1` defines `absolute_hard_ceiling_ms =
//! 300000` (5 minutes). The reducer MUST refuse:
//!
//!   * `relaxed_window_max_ms > 300000` → `relaxed_window_exceeds_ceiling`
//!   * enabling `e2ee_relaxed.v1` while any of these compliance profiles are active on the same
//!     Realm:
//!       - `ck.profile.attested_audit.e2ee.v1`
//!       - `ck.profile.disclosed_audit.e2ee.v1`
//!     → `e2ee_relaxed_disallowed_in_compliance_profile`
//!
//! This module covers the two negative branches.

use anyhow::{Result, anyhow};
use cokret_core::schema::embedded_error_code_identifiers;
use cokret_core::{
    ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE,
    ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING,
};

pub const ABSOLUTE_HARD_CEILING_MS: u64 = 300_000;

pub const EXPECTED_RELAXED_EXCEEDS_CEILING: &str = "relaxed_window_exceeds_ceiling";
pub const EXPECTED_RELAXED_DISALLOWED_IN_COMPLIANCE: &str =
    "e2ee_relaxed_disallowed_in_compliance_profile";

/// Wire-level executable check: confirm the SDK exports the canonical
/// reason code constant for `relaxed_window_max_ms > 300_000`, and that
/// the constant matches the literal the soland reducer uses, and that
/// the registry recognises it.
///
/// This is the cotest-side wire pin for T09 — it does not need a live
/// soland to validate that the ABI between SDK / cotest / soland agrees
/// on the exact reason code string.
///
/// SCOPE: this is a *wire pin only* (constant ⇆ SDK ⇆ registry agreement). It
/// does NOT drive the soland reducer and therefore does NOT verify the
/// fail-closed behaviour (`relaxed_window_max_ms > 300_000` is actually
/// rejected). A behavioural end-to-end test that spawns soland and submits a
/// `relaxed_window_max_ms = 400_000` payload is not yet implemented; do not
/// count this pin as behavioural fail-closed coverage.
pub async fn e2ee_relaxed_window_exceeds_ceiling_run() -> Result<()> {
    if ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING != EXPECTED_RELAXED_EXCEEDS_CEILING {
        return Err(anyhow!(
            "SDK ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING ({}) drifted from the \
             cotest-pinned wire literal ({}). Update one or the other before \
             unfreezing this scenario.",
            ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING,
            EXPECTED_RELAXED_EXCEEDS_CEILING,
        ));
    }
    // `relaxed_window_exceeds_ceiling` is a spec `reason_code`, not a top-level
    // error `code`, so it is validated against the registry union rather than
    // the SDK's codes-only `KNOWN_ERROR_CODES` table.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING) {
        return Err(anyhow!(
            "error-code-registry missing reason code {ERROR_CODE_RELAXED_WINDOW_EXCEEDS_CEILING}"
        ));
    }
    Ok(())
}

/// Wire-level executable check for the compliance-mutex reason code:
/// confirm the SDK constant string matches the cotest pin and that the
/// canonical registry knows it.
pub async fn e2ee_relaxed_disallowed_in_compliance_run() -> Result<()> {
    if ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE
        != EXPECTED_RELAXED_DISALLOWED_IN_COMPLIANCE
    {
        return Err(anyhow!(
            "SDK ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE ({}) drifted \
             from cotest pin ({}).",
            ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE,
            EXPECTED_RELAXED_DISALLOWED_IN_COMPLIANCE,
        ));
    }
    // `e2ee_relaxed_disallowed_in_compliance_profile` is a spec `reason_code`;
    // validate against the registry union, not the codes-only table.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE) {
        return Err(anyhow!(
            "error-code-registry missing reason code \
             {ERROR_CODE_E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relaxed_window_ceiling_pin_matches_sdk() {
        e2ee_relaxed_window_exceeds_ceiling_run()
            .await
            .expect("SDK constant for relaxed_window_exceeds_ceiling must agree with cotest pin");
    }

    #[tokio::test]
    async fn relaxed_compliance_mutex_pin_matches_sdk() {
        e2ee_relaxed_disallowed_in_compliance_run()
            .await
            .expect(
                "SDK constant for e2ee_relaxed_disallowed_in_compliance_profile must agree with cotest pin",
            );
    }

    #[test]
    fn hard_ceiling_value_is_300_000_ms() {
        // Pin the literal too — drift here would be a wire break.
        assert_eq!(ABSOLUTE_HARD_CEILING_MS, 300_000);
    }
}
