//! Round 2+3 / T12 — SFU/MCU plaintext routing requires governance
//! binding.
//!
//! Spec (round 2+3 cleanup, T12):
//!
//! `media_service_decrypts=true` MUST be bound in three places:
//!   1. `ak.realm.policy_components` write covering this service + `policy_root` digest covers the
//!      current epoch's policy
//!   2. SFU service DID appears in `plaintext_visible_services[]` with `purpose=media_plaintext`
//!   3. MLS epoch governance binding records `policy_root` so receivers can verify the SFU's
//!      plaintext role is current
//!
//! If any of the three is missing or stale, the SFU MUST refuse to
//! handle plaintext media and the reducer MUST surface either:
//!   * `mls_governance_binding_stale` — when MLS epoch governance binding does not cover the
//!     current policy_root
//!   * `media_plaintext_service_not_authorised` — when the SFU service DID is not in
//!     `plaintext_visible_services[]`
//!
//! This scenario covers the missing-policy_root path plus the SEC-03
//! `media-service-binding.md §8.2` negative-vector (d) leg: a member's
//! independent recomputation of the `media_service_decrypts` fact from the
//! MLS transcript disagrees with the `discussion_metadata_digest` the
//! governance binding covers ⇒ the member MUST treat the binding as stale and
//! refuse media negotiation. The (d) leg is exercised against the live SDK
//! deterministic-digest helpers so cotest stays source-identical with the
//! soland-side `realm_policy_components_check` reducer (no drift).

use anyhow::{Result, anyhow, bail};
use arkret_core::models::{
    MediaDecryptPolicyValue, MediaPlaintextService, derive_media_decrypt_metadata_digest,
    verify_media_decrypt_metadata,
};
use arkret_core::{Did, WireError};
use arkret_schema::embedded_error_code_identifiers;

/// Wire-level executable check: the SDK constants for both media
/// plaintext error codes agree with the cotest pins and the canonical
/// registry recognises them.
pub async fn media_plaintext_downgrade_no_governance_binding_run() -> Result<()> {
    if arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE != "mls_governance_binding_stale" {
        return Err(anyhow!(
            "SDK arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE ({}) drifted from cotest pin ({}).",
            "mls_governance_binding_stale",
            arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE,
        ));
    }
    if arkret_wire::ReasonCode::MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED
        != "media_plaintext_service_not_authorised"
    {
        return Err(anyhow!(
            "SDK arkret_wire::ReasonCode::MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED ({}) drifted from cotest pin ({}).",
            "media_plaintext_service_not_authorised",
            arkret_wire::ReasonCode::MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED,
        ));
    }
    // Both codes are spec `reason_codes`, not top-level error `codes`, so they
    // are validated against the registry union rather than the SDK's codes-only
    // `KNOWN_ERROR_CODES` table.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE) {
        return Err(anyhow!(
            "error-code-registry missing reason code mls_governance_binding_stale"
        ));
    }
    if !registry_identifiers
        .contains(arkret_wire::ReasonCode::MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED)
    {
        return Err(anyhow!(
            "error-code-registry missing reason code media_plaintext_service_not_authorised"
        ));
    }
    Ok(())
}

/// The honest member-visible policy cell value for the (d) vector: the Realm
/// has flipped `media_service_decrypts=true` and lists exactly one
/// `purpose=media_plaintext` SFU. This is the §10.5.1 rule 1–3 cell value that
/// the governance binding's `discussion_metadata_digest` is supposed to cover.
fn honest_media_decrypt_policy_value() -> Result<MediaDecryptPolicyValue> {
    Ok(MediaDecryptPolicyValue {
        media_service_decrypts: true,
        plaintext_visible_services: vec![MediaPlaintextService {
            service_id: Did::new("did:web:sfu.example".to_owned())
                .map_err(|e| anyhow!("sfu service did: {e}"))?,
        }],
    })
}

/// SEC-03 negative vector (d) — `media-service-binding.md §8.2` rule 5.
///
/// A member independently recomputes the `media_service_decrypts` fact from
/// its own view of the MLS transcript and compares it against the
/// `discussion_metadata_digest` covered by the accepted governance binding.
/// When the two disagree, the binding MUST be treated as stale and media
/// negotiation refused with `mls_governance_binding_stale`.
///
/// This is exercised against the live SDK helpers so the honest and the
/// mismatched digests are produced by the exact code path soland's
/// `realm_policy_components_check` reducer runs — keeping cotest, the SDK, and
/// soland source-identical (no divergent hand-rolled hashing).
pub fn media_plaintext_member_recompute_mismatch_refuses_run() -> Result<()> {
    // The member's own local recomputation over its transcript view.
    let member_local_value = honest_media_decrypt_policy_value()?;
    let recomputed = derive_media_decrypt_metadata_digest(&member_local_value)
        .map_err(|e| anyhow!("member local digest derivation failed: {e}"))?;

    // Control leg: a governance binding that honestly covers the SAME cell
    // value yields a matching digest, so media negotiation is NOT refused.
    // This proves the refusal below is caused by the mismatch, not by a
    // helper that rejects unconditionally.
    let binding_honest =
        derive_media_decrypt_metadata_digest(&honest_media_decrypt_policy_value()?)
            .map_err(|e| anyhow!("honest binding digest derivation failed: {e}"))?;
    verify_media_decrypt_metadata(&binding_honest, &recomputed)
        .map_err(|e| anyhow!("matching digests must NOT be refused, got: {e}"))?;
    if binding_honest != recomputed {
        bail!("honest binding digest must equal the member recomputation for set-equal inputs");
    }

    // Attack leg (d): the governance binding covers a DIFFERENT member-visible
    // fact than what the member recomputes locally. Here the binding attests
    // `media_service_decrypts=false` (i.e. the SFU is NOT authorised to
    // decrypt) while the member's transcript view recomputes `true`. The
    // digests differ, so the member MUST refuse media negotiation.
    let binding_covered_value = MediaDecryptPolicyValue {
        media_service_decrypts: false,
        plaintext_visible_services: vec![],
    };
    let binding_covered_digest = derive_media_decrypt_metadata_digest(&binding_covered_value)
        .map_err(|e| anyhow!("mismatched binding digest derivation failed: {e}"))?;
    if binding_covered_digest == recomputed {
        bail!(
            "test setup invalid: mismatched binding digest unexpectedly equals member recomputation"
        );
    }

    match verify_media_decrypt_metadata(&binding_covered_digest, &recomputed) {
        Ok(()) => bail!(
            "member recompute mismatch MUST be refused (mls_governance_binding_stale), got Ok",
        ),
        Err(WireError::Protocol(msg)) => {
            if !msg.contains(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE) {
                bail!(
                    "mismatch refusal must carry error code `mls_governance_binding_stale`, \
                     got Protocol({msg})"
                );
            }
        }
        Err(other) => bail!(
            "mismatch must surface Error::Protocol tagged \
             `mls_governance_binding_stale`, got {other:?}"
        ),
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

    #[tokio::test]
    async fn t12_media_plaintext_binding_contract() {
        media_plaintext_downgrade_no_governance_binding_run()
            .await
            .expect("media plaintext error-code pins must be registered");
        assert_ne!(
            arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE,
            arkret_wire::ReasonCode::MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED,
            "stale governance and unauthorized service paths must stay distinguishable"
        );
    }

    /// SEC-03 negative vector (d): a member's local recomputation of the
    /// `media_service_decrypts` fact that disagrees with the governance
    /// binding's covered digest MUST be refused with
    /// `mls_governance_binding_stale`.
    #[test]
    fn d_member_recompute_mismatch_refuses_media() {
        media_plaintext_member_recompute_mismatch_refuses_run()
            .expect("member recompute mismatch must refuse media negotiation as stale");
    }
}
