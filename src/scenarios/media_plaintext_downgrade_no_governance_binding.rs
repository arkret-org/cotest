//! Round 2+3 / T12 — SFU/MCU plaintext routing requires governance
//! binding.
//!
//! Spec (round 2+3 cleanup, T12):
//!
//! `media_service_decrypts=true` MUST be bound in three places:
//!   1. `cx.realm.policy_components` write covering this service +
//!      `policy_root` digest covers the current epoch's policy
//!   2. SFU service DID appears in `plaintext_visible_services[]` with
//!      `purpose=media_plaintext`
//!   3. MLS epoch governance binding records `policy_root` so receivers
//!      can verify the SFU's plaintext role is current
//!
//! If any of the three is missing or stale, the SFU MUST refuse to
//! handle plaintext media and the reducer MUST surface either:
//!   * `mls_governance_binding_stale` — when MLS epoch governance
//!     binding does not cover the current policy_root
//!   * `media_plaintext_service_not_authorised` — when the SFU service
//!     DID is not in `plaintext_visible_services[]`
//!
//! This scenario covers the missing-policy_root path.

use anyhow::{Result, anyhow};
use contrix_core::{
    ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED, ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE,
    is_known_error_code,
};

pub const EXPECTED_MLS_GOVERNANCE_BINDING_STALE: &str = "mls_governance_binding_stale";
pub const EXPECTED_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED: &str =
    "media_plaintext_service_not_authorised";

/// Wire-level executable check: the SDK constants for both media
/// plaintext error codes agree with the cotest pins and the canonical
/// registry recognises them.
pub async fn media_plaintext_downgrade_no_governance_binding_run() -> Result<()> {
    if ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE != EXPECTED_MLS_GOVERNANCE_BINDING_STALE {
        return Err(anyhow!(
            "SDK ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE ({}) drifted from cotest pin ({}).",
            ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE,
            EXPECTED_MLS_GOVERNANCE_BINDING_STALE,
        ));
    }
    if ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED
        != EXPECTED_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED
    {
        return Err(anyhow!(
            "SDK ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED ({}) drifted from cotest pin ({}).",
            ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED,
            EXPECTED_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED,
        ));
    }
    if !is_known_error_code(ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_MLS_GOVERNANCE_BINDING_STALE}"
        ));
    }
    if !is_known_error_code(ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn media_plaintext_codes_pin_matches_sdk() {
        media_plaintext_downgrade_no_governance_binding_run()
            .await
            .expect("SDK media plaintext error codes must agree with cotest pins");
    }

    #[test]
    #[ignore = "TODO(round23-T12): needs live soland + SFU fixture"]
    fn full_soland_sfu_plaintext_binding_check() {
        // 1. configure a Realm with `media_service_decrypts=true` but
        //    omit `plaintext_visible_services[]` (or stale policy_root)
        // 2. simulate SFU attempting plaintext path
        // 3. assert one of the two expected error codes is returned
    }
}
