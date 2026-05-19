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

use anyhow::Result;

pub const EXPECTED_MLS_GOVERNANCE_BINDING_STALE: &str = "mls_governance_binding_stale";
pub const EXPECTED_MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED: &str =
    "media_plaintext_service_not_authorised";

/// Attempt to route plaintext media through an SFU that is not covered
/// by the current `policy_root` governance binding.
pub async fn media_plaintext_downgrade_no_governance_binding_run() -> Result<()> {
    // TODO(round23-T12): wire to soland + SFU fixture. Must:
    //   1. configure a Realm with `media_service_decrypts=true` but
    //      omit `plaintext_visible_services[]` (or stale policy_root)
    //   2. simulate SFU attempting plaintext path
    //   3. assert one of the two expected error codes is returned
    Ok(())
}
