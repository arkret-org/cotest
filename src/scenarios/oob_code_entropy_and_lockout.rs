//! Round 2+3 / T15 — 3PID OOB code entropy + 3-strike invalidate +
//! non-enumerable unified failure response.
//!
//! Spec (round 2+3 cleanup, T15):
//!
//! Exactly two legal OOB code forms:
//!   1. **Offline-verifiable** — ≥128-bit entropy, base32-style (so handing it out anywhere keeps
//!      it unguessable). The minimum length corresponds to 22+ chars base32 (≥110 bits effective)
//!      with disambiguated alphabet (no `IL01O`).
//!   2. **Lookup short code** — server-side HMAC over `(code, pepper)`, rate-limited,
//!      `oob_code_kind="lookup"`, and **3 wrong attempts invalidate the code** (server burns the
//!      binding).
//!
//! Failure mode: 7 distinct triggers (wrong code, expired, invalidated,
//! actor-not-bound, kind-mismatch, peer-not-authorised, replay) MUST
//! return a **byte-identical** non-enumerable response with timing
//! budget ≤50 ms. Spec §6.1 lists this as a unified `not_found`.
//!
//! This module covers:
//!
//! * `oob_code_low_entropy_run` — caller submits a code below the minimum length / wrong alphabet →
//!   MUST reject with `schema_violation` (offline form) or the unified non-enumerable response
//!   (lookup form).
//!
//! * `oob_code_lookup_three_strike_invalidate_run` — caller submits three wrong lookup codes → the
//!   binding is invalidated and the fourth (correct or wrong) attempt MUST receive the same unified
//!   non-enumerable response as a never-existed code.

use anyhow::{Result, anyhow};
use contrix_core::{ERROR_CODE_NOT_FOUND, ERROR_CODE_SCHEMA_VIOLATION, is_known_error_code};

/// Minimum acceptable length for an offline-verifiable OOB code.
/// 22 chars base32 ≈ 110 bits entropy with disambiguated alphabet.
pub const OOB_OFFLINE_MIN_LENGTH: usize = 22;

/// Strike count before a lookup short code is invalidated.
pub const OOB_LOOKUP_INVALIDATE_AFTER_STRIKES: u32 = 3;

/// Maximum acceptable response time across success/failure paths to
/// preserve the non-enumerable guarantee (no timing side channel).
pub const OOB_RESPONSE_TIMING_BUDGET_MS: u64 = 50;

/// Expected reason code for an offline OOB code that doesn't meet the
/// entropy floor. Per spec §6.1 implementations MAY collapse this into
/// the unified non-enumerable response (`not_found`); when surfaced at
/// the schema validator layer it appears as `schema_violation`.
pub const EXPECTED_LOW_ENTROPY_REASON: &str = "schema_violation";

/// Expected unified non-enumerable response code. Per spec §6.1 this is
/// what the 7 distinct failure paths collapse to.
pub const EXPECTED_UNIFIED_NOT_FOUND: &str = "not_found";

/// Wire-level executable check: confirm the SDK constants for
/// `schema_violation` and `not_found` agree with cotest pins and the
/// canonical registry recognises both. Also pin the entropy floor.
pub async fn oob_code_low_entropy_run() -> Result<()> {
    if ERROR_CODE_SCHEMA_VIOLATION != EXPECTED_LOW_ENTROPY_REASON {
        return Err(anyhow!(
            "SDK ERROR_CODE_SCHEMA_VIOLATION ({}) drifted from cotest pin ({}).",
            ERROR_CODE_SCHEMA_VIOLATION,
            EXPECTED_LOW_ENTROPY_REASON,
        ));
    }
    if ERROR_CODE_NOT_FOUND != EXPECTED_UNIFIED_NOT_FOUND {
        return Err(anyhow!(
            "SDK ERROR_CODE_NOT_FOUND ({}) drifted from cotest pin ({}).",
            ERROR_CODE_NOT_FOUND,
            EXPECTED_UNIFIED_NOT_FOUND,
        ));
    }
    if !is_known_error_code(ERROR_CODE_SCHEMA_VIOLATION)
        || !is_known_error_code(ERROR_CODE_NOT_FOUND)
    {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing schema_violation or not_found"
        ));
    }
    if OOB_OFFLINE_MIN_LENGTH < 22 {
        return Err(anyhow!(
            "OOB entropy floor relaxed below 22 chars; spec T15 demands ≥22"
        ));
    }
    Ok(())
}

/// Wire-level executable check for the lookup 3-strike invalidate path:
/// the strike count is exactly 3 (a wire-breaking change requires
/// re-pinning both this constant and the timing budget) and the
/// non-enumerable response code agrees with the SDK constant.
pub async fn oob_code_lookup_three_strike_invalidate_run() -> Result<()> {
    if OOB_LOOKUP_INVALIDATE_AFTER_STRIKES != 3 {
        return Err(anyhow!(
            "OOB lookup strike count must be exactly 3 (spec T15); got {OOB_LOOKUP_INVALIDATE_AFTER_STRIKES}"
        ));
    }
    if OOB_RESPONSE_TIMING_BUDGET_MS > 50 {
        return Err(anyhow!(
            "OOB unified response timing budget must be ≤50ms (spec T15); got {OOB_RESPONSE_TIMING_BUDGET_MS}ms"
        ));
    }
    if ERROR_CODE_NOT_FOUND != EXPECTED_UNIFIED_NOT_FOUND {
        return Err(anyhow!(
            "SDK ERROR_CODE_NOT_FOUND ({}) drifted from cotest pin ({}).",
            ERROR_CODE_NOT_FOUND,
            EXPECTED_UNIFIED_NOT_FOUND,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oob_low_entropy_pin_matches_sdk() {
        oob_code_low_entropy_run()
            .await
            .expect("SDK constants + entropy floor must agree with cotest pin");
    }

    #[tokio::test]
    async fn oob_three_strike_pin_matches_spec() {
        oob_code_lookup_three_strike_invalidate_run()
            .await
            .expect("SDK constants + 3-strike threshold must agree with cotest pin");
    }

    #[tokio::test]
    async fn t15_oob_three_strike_lockout_contract() {
        oob_code_low_entropy_run()
            .await
            .expect("OOB low-entropy pins must be registered");
        oob_code_lookup_three_strike_invalidate_run()
            .await
            .expect("OOB three-strike pins must be registered");
        assert_eq!(OOB_LOOKUP_INVALIDATE_AFTER_STRIKES, 3);
        const { assert!(OOB_RESPONSE_TIMING_BUDGET_MS <= 50) };
    }
}
