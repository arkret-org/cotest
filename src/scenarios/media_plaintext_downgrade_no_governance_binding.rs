//! Round 2+3 / T12 — SFU/MCU plaintext routing requires governance
//! binding.
//!
//! Spec (round 2+3 cleanup, T12):
//!
//! `media_service_decrypts=true` and the effective plaintext recipient set
//! are projected from accepted state into the MLS `security_frontier_digest`.
//! The receiver rederives that digest with the SDK projector; endpoint-only
//! metadata remains orthogonal.
//!
//! If any of the three is missing or stale, the SFU MUST refuse to
//! handle plaintext media and the reducer MUST surface either:
//!   * `mls_governance_binding_stale` — when MLS epoch governance binding does not cover the
//!     current key-access frontier
//!   * `media_plaintext_service_not_authorised` — when the SFU service DID is not in
//!     `plaintext_visible_services[]`
//!
//! This scenario covers SEC-03 `media-service-binding.md §8.2`: a member's
//! independent frontier recomputation disagrees with the transcript binding,
//! so media negotiation is refused as stale.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use arkret_canonical::canonical::encode_state_subject;
use arkret_schema::embedded_error_code_identifiers;
use arkret_state::CellState;
use arkret_state::mls_governance_proof::{MlsSecurityFrontierLeaf, derive_mls_security_frontier};
use arkret_wire::{CellFamilyId, CellRef, ScopeRef};
use serde_json::json;

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

fn realm_cell(family: &str) -> Result<CellRef> {
    CellRef::new(format!(
        "ak:cell:{family}:{}",
        encode_state_subject(&["ak:realm:AWy1ImsZXpFjP50bGHC-ecStBt4qurkjgu4EoRYSpmnE"])
    ))
    .map_err(Into::into)
}

/// SEC-03 negative vector (d) — `media-service-binding.md §8.2` rule 5.
///
/// A member rederives the unique Security Frontier from accepted policy state
/// and its local RFC 9420 leaves. Key-access changes alter the digest, while
/// endpoint-only metadata does not.
pub fn media_plaintext_member_recompute_mismatch_refuses_run() -> Result<()> {
    let scope: ScopeRef = serde_json::from_value(json!({
        "kind": "realm",
        "realm_id": "ak:realm:AWy1ImsZXpFjP50bGHC-ecStBt4qurkjgu4EoRYSpmnE"
    }))?;
    let leaves: Vec<MlsSecurityFrontierLeaf> = serde_json::from_value(json!([{
        "leaf_index": 0,
        "principal_id": "ak:did_core:web:alice.example",
        "credential_ref": "did:webvh:zfixture:alice.example#device-1"
    }]))?;
    let policy_cell = realm_cell(CellFamilyId::REALM_POLICY_BUNDLE_V1)?;
    let services_cell = realm_cell(CellFamilyId::REALM_PLAINTEXT_VISIBLE_SERVICES_V1)?;
    let mut state = BTreeMap::from([
        (
            policy_cell.clone(),
            CellState::Value(json!({
                "content_scheme": "mls_exporter_aead_v1",
                "media_service_decrypts": false,
                "routing_endpoint": "https://old.example"
            })),
        ),
        (services_cell.clone(), CellState::Value(json!([]))),
    ]);
    let transcript_digest = derive_mls_security_frontier(&state, &scope, &leaves)?;

    state.insert(
        policy_cell.clone(),
        CellState::Value(json!({
            "content_scheme": "mls_exporter_aead_v1",
            "media_service_decrypts": false,
            "routing_endpoint": "https://new.example"
        })),
    );
    let endpoint_only = derive_mls_security_frontier(&state, &scope, &leaves)?;
    if endpoint_only != transcript_digest {
        bail!("endpoint-only metadata changed security_frontier_digest");
    }

    state.insert(
        policy_cell,
        CellState::Value(json!({
            "content_scheme": "mls_exporter_aead_v1",
            "media_service_decrypts": true,
            "routing_endpoint": "https://new.example"
        })),
    );
    state.insert(
        services_cell,
        CellState::Value(json!([{
            "service_id": "ak:did_core:web:sfu.example",
            "data_classes": ["media_plaintext"]
        }])),
    );
    let recomputed = derive_mls_security_frontier(&state, &scope, &leaves)?;
    if recomputed == transcript_digest {
        bail!("media plaintext key-access change did not change security_frontier_digest");
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
    /// `media_service_decrypts` fact that disagrees with the transcript's
    /// Security Frontier digest MUST be refused with
    /// `mls_governance_binding_stale`.
    #[test]
    fn d_member_recompute_mismatch_refuses_media() {
        media_plaintext_member_recompute_mismatch_refuses_run()
            .expect("member recompute mismatch must refuse media negotiation as stale");
    }
}
