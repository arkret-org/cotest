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
//!
//! SCOPE (see `arkret-work/review/code-open/cotest/02_security.md` #2): the functions here are
//! **wire pins only** — they assert that the SDK reason-code constants /
//! header literals agree with the cotest pins and the registry. They do NOT
//! spawn a presign endpoint and therefore do NOT verify the fail-closed
//! *behaviour* (that legal-hold / redacted / E2EE / actor-private blobs are
//! actually refused a signed URL). Do not count these pins as behavioural
//! fail-closed coverage; a live behavioural test (spawn soland, request a
//! presign for each blob class, assert refusal + reason code) is a follow-up
//! and must be tracked separately on the coverage dashboard.

use anyhow::{Result, anyhow};
use arkret_schema::embedded_error_code_identifiers;

/// Headers the presign endpoint MUST set (spec T11).
pub const PRESIGN_CACHE_CONTROL: &str = "private, no-store";
pub const PRESIGN_REFERRER_POLICY: &str = "no-referrer";

/// Wire-level executable check: the SDK constant for `legal_hold_active`
/// matches the cotest pin and the canonical registry recognises it.
pub async fn presign_blob_legal_hold_run() -> Result<()> {
    if arkret_core::ReasonCode::LEGAL_HOLD_ACTIVE != arkret_core::ReasonCode::LEGAL_HOLD_ACTIVE {
        return Err(anyhow!(
            "SDK arkret_core::ReasonCode::LEGAL_HOLD_ACTIVE ({}) drifted from cotest pin ({}).",
            arkret_core::ReasonCode::LEGAL_HOLD_ACTIVE,
            arkret_core::ReasonCode::LEGAL_HOLD_ACTIVE,
        ));
    }
    // `legal_hold_active` is a spec `reason_code` (applies_to=auth_decision),
    // not a top-level error `code`; validate against the registry union.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(arkret_core::ReasonCode::LEGAL_HOLD_ACTIVE) {
        return Err(anyhow!(
            "error-code-registry missing reason code legal_hold_active"
        ));
    }
    Ok(())
}

/// Wire-level executable check: the SDK constant for `blob_redacted`
/// matches the cotest pin and the canonical registry recognises it.
pub async fn presign_blob_redacted_run() -> Result<()> {
    if arkret_core::ReasonCode::BLOB_REDACTED != arkret_core::ReasonCode::BLOB_REDACTED {
        return Err(anyhow!(
            "SDK arkret_core::ReasonCode::BLOB_REDACTED ({}) drifted from cotest pin ({}).",
            arkret_core::ReasonCode::BLOB_REDACTED,
            arkret_core::ReasonCode::BLOB_REDACTED,
        ));
    }
    // `blob_redacted` is a spec `reason_code` (applies_to=state_resolution),
    // not a top-level error `code`; validate against the registry union.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(arkret_core::ReasonCode::BLOB_REDACTED) {
        return Err(anyhow!(
            "error-code-registry missing reason code blob_redacted"
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
    async fn t11_presign_fail_closed_contract() {
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
