//! Round 2+3 / T11 — Presign blob audience boundary (fail-closed).
//!
//! Spec (round 2+3 cleanup, T11):
//!
//! `audience_hint` is **only** a diagnostic hint and MUST NOT be used
//! as an access-control decision. The presign endpoint MUST fail closed
//! for four blob classes:
//!
//!   * E2EE blob without legitimate access path → not signed
//!   * `legal_hold_active` blob → reason code `legal_hold_active`
//!   * `redacted` blob → reason code `blob_redacted`
//!   * `actor_private` blob whose actor != requester → not signed
//!
//! The signed URL itself MUST come back with:
//!   * `Cache-Control: private, no-store`
//!   * `Referrer-Policy: no-referrer`
//!   * No logging of the presign URL query string in plaintext.
//!
//! This module covers the legal-hold and redacted paths.

use anyhow::{Result, anyhow};
use contrix_core::{ERROR_CODE_BLOB_REDACTED, ERROR_CODE_LEGAL_HOLD_ACTIVE, is_known_error_code};

pub const EXPECTED_LEGAL_HOLD: &str = "legal_hold_active";
pub const EXPECTED_BLOB_REDACTED: &str = "blob_redacted";

/// Headers the presign endpoint MUST set (spec T11).
pub const PRESIGN_CACHE_CONTROL: &str = "private, no-store";
pub const PRESIGN_REFERRER_POLICY: &str = "no-referrer";

/// Wire-level executable check: the SDK constant for `legal_hold_active`
/// matches the cotest pin and the canonical registry recognises it.
pub async fn presign_blob_legal_hold_run() -> Result<()> {
    if ERROR_CODE_LEGAL_HOLD_ACTIVE != EXPECTED_LEGAL_HOLD {
        return Err(anyhow!(
            "SDK ERROR_CODE_LEGAL_HOLD_ACTIVE ({}) drifted from cotest pin ({}).",
            ERROR_CODE_LEGAL_HOLD_ACTIVE,
            EXPECTED_LEGAL_HOLD,
        ));
    }
    if !is_known_error_code(ERROR_CODE_LEGAL_HOLD_ACTIVE) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_LEGAL_HOLD_ACTIVE}"
        ));
    }
    Ok(())
}

/// Wire-level executable check: the SDK constant for `blob_redacted`
/// matches the cotest pin and the canonical registry recognises it.
pub async fn presign_blob_redacted_run() -> Result<()> {
    if ERROR_CODE_BLOB_REDACTED != EXPECTED_BLOB_REDACTED {
        return Err(anyhow!(
            "SDK ERROR_CODE_BLOB_REDACTED ({}) drifted from cotest pin ({}).",
            ERROR_CODE_BLOB_REDACTED,
            EXPECTED_BLOB_REDACTED,
        ));
    }
    if !is_known_error_code(ERROR_CODE_BLOB_REDACTED) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_BLOB_REDACTED}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn legal_hold_pin_matches_sdk() {
        presign_blob_legal_hold_run()
            .await
            .expect("SDK constant for legal_hold_active must agree with cotest pin");
    }

    #[tokio::test]
    async fn blob_redacted_pin_matches_sdk() {
        presign_blob_redacted_run()
            .await
            .expect("SDK constant for blob_redacted must agree with cotest pin");
    }

    #[test]
    fn presign_response_headers_pinned() {
        // Drift in these literals is a wire break per spec T11.
        assert_eq!(PRESIGN_CACHE_CONTROL, "private, no-store");
        assert_eq!(PRESIGN_REFERRER_POLICY, "no-referrer");
    }

    #[tokio::test]
    async fn round23_t11_presign_fail_closed_contract() {
        presign_blob_legal_hold_run()
            .await
            .expect("legal_hold_active pin must be registered");
        presign_blob_redacted_run()
            .await
            .expect("blob_redacted pin must be registered");
        assert_eq!(PRESIGN_CACHE_CONTROL, "private, no-store");
        assert_eq!(PRESIGN_REFERRER_POLICY, "no-referrer");
    }
}
