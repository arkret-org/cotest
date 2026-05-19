//! Round 2+3 / T15 — 3PID OOB code entropy + 3-strike invalidate +
//! non-enumerable unified failure response.
//!
//! Spec (round 2+3 cleanup, T15):
//!
//! Exactly two legal OOB code forms:
//!   1. **Offline-verifiable** — ≥128-bit entropy, base32-style (so
//!      handing it out anywhere keeps it unguessable). The minimum
//!      length corresponds to 22+ chars base32 (≥110 bits effective)
//!      with disambiguated alphabet (no `IL01O`).
//!   2. **Lookup short code** — server-side HMAC over `(code, pepper)`,
//!      rate-limited, `oob_code_kind="lookup"`, and **3 wrong attempts
//!      invalidate the code** (server burns the binding).
//!
//! Failure mode: 7 distinct triggers (wrong code, expired, invalidated,
//! actor-not-bound, kind-mismatch, peer-not-authorised, replay) MUST
//! return a **byte-identical** non-enumerable response with timing
//! budget ≤50 ms. Spec §6.1 lists this as a unified `not_found`.
//!
//! This module covers:
//!
//! * `oob_code_low_entropy_run` — caller submits a code below the
//!   minimum length / wrong alphabet → MUST reject with
//!   `schema_violation` (offline form) or the unified non-enumerable
//!   response (lookup form).
//!
//! * `oob_code_lookup_three_strike_invalidate_run` — caller submits
//!   three wrong lookup codes → the binding is invalidated and the
//!   fourth (correct or wrong) attempt MUST receive the same unified
//!   non-enumerable response as a never-existed code.

use anyhow::Result;

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

/// Submit an OOB code shorter than the minimum entropy floor.
pub async fn oob_code_low_entropy_run() -> Result<()> {
    // TODO(round23-T15): wire to coauth verify endpoint. Must submit a
    // code shorter than `OOB_OFFLINE_MIN_LENGTH`, assert the response
    // is either `schema_violation` at the schema gate or the unified
    // non-enumerable response (byte-identical to lookup-failure).
    Ok(())
}

/// Hit a lookup code three times wrong, then a fourth time and assert
/// the binding is invalidated.
pub async fn oob_code_lookup_three_strike_invalidate_run() -> Result<()> {
    // TODO(round23-T15): wire to coauth verify endpoint. Must:
    //   1. issue an `oob_code_kind="lookup"` short code
    //   2. submit 3 wrong codes
    //   3. assert the 4th submission (correct OR wrong) returns the
    //      unified non-enumerable response and the binding is gone
    //   4. assert timing across all 4 responses is within
    //      `OOB_RESPONSE_TIMING_BUDGET_MS`
    Ok(())
}
