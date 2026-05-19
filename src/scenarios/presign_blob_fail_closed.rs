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

use anyhow::Result;

pub const EXPECTED_LEGAL_HOLD: &str = "legal_hold_active";
pub const EXPECTED_BLOB_REDACTED: &str = "blob_redacted";

/// Request a presign URL for a blob under active legal hold.
pub async fn presign_blob_legal_hold_run() -> Result<()> {
    // TODO(round23-T11): wire to soland presign endpoint fixture.
    // Must:
    //   1. mark a fixture blob with `legal_hold_active=true`
    //   2. request presign URL as any actor
    //   3. assert response is 403 with `legal_hold_active`
    //   4. assert no presign query string is recorded in logs
    Ok(())
}

/// Request a presign URL for a redacted blob.
pub async fn presign_blob_redacted_run() -> Result<()> {
    // TODO(round23-T11): wire to soland presign endpoint fixture.
    // Must:
    //   1. mark a fixture blob as redacted
    //   2. request presign URL
    //   3. assert response is 403 with `blob_redacted`
    Ok(())
}
