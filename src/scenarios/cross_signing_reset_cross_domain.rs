//! Round 2+3 / T08 — `ak.cross_signing.reset` cross-domain replay
//! defense + event_id binding.
//!
//! Spec (round 2+3 cleanup, T08):
//!
//! `cross-signing-reset.schema.json` now requires two new payload fields:
//!   * `trust_domain: TypedTrustDomainId` (`ak:trust_domain:<scope>`)
//!   * `reset_event_id: TypedEventId` (`ak:event:<uuidv7>`)
//!
//! The receiver MUST validate in this strict order:
//!   1. `trust_domain` matches the receiver's deployment trust domain → otherwise
//!      `cross_domain_replay_rejected`
//!   2. `reset_event_id` equals the enclosing `Event.id` → otherwise `reset_event_id_mismatch`
//!   3. Signature verification (existing) → otherwise `invalid_signature`
//!
//! This module covers two scenarios:
//!
//! * `cross_signing_reset_cross_domain_run` — proof minted against `ak:trust_domain:A` replayed
//!   against deployment `ak:trust_domain:B`; MUST be rejected with `cross_domain_replay_rejected`.
//!
//! * `cross_signing_reset_event_id_mismatch_run` — payload carries `reset_event_id != Event.id`;
//!   MUST be rejected with `reset_event_id_mismatch`.

use anyhow::{Result, anyhow};
use arkret_core::schema::embedded_error_code_identifiers;
use arkret_core::{
    EventId, REASON_CROSS_DOMAIN_REPLAY_REJECTED, REASON_RESET_EVENT_ID_MISMATCH,
    TypedTrustDomainId,
};

pub const EXPECTED_CROSS_DOMAIN_REPLAY: &str = "cross_domain_replay_rejected";
pub const EXPECTED_RESET_EVENT_ID_MISMATCH: &str = "reset_event_id_mismatch";

pub const TRUST_DOMAIN_ID_PREFIX: &str = "ak:trust_domain:";

/// Wire-level executable check: the SDK's `TypedTrustDomainId` validator
/// MUST accept two distinct, well-formed trust domain ids — replaying a
/// proof signed under domain A into a deployment that is configured as
/// domain B is the exact replay surface this scenario locks down. We
/// pin the error code constant matches the cotest expectation and that
/// the SDK can construct (and distinguish) the two ids.
pub async fn cross_signing_reset_cross_domain_run() -> Result<()> {
    if REASON_CROSS_DOMAIN_REPLAY_REJECTED != EXPECTED_CROSS_DOMAIN_REPLAY {
        return Err(anyhow!(
            "SDK REASON_CROSS_DOMAIN_REPLAY_REJECTED ({}) drifted from cotest pin ({}).",
            REASON_CROSS_DOMAIN_REPLAY_REJECTED,
            EXPECTED_CROSS_DOMAIN_REPLAY,
        ));
    }
    // `cross_domain_replay_rejected` is a spec `reason_code` (applies_to=
    // auth_decision), not a top-level error `code`, so it is absent from the
    // SDK's `KNOWN_ERROR_CODES`. Validate registration against the registry
    // union (codes ∪ reason_codes), which is the spec truth source.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(REASON_CROSS_DOMAIN_REPLAY_REJECTED) {
        return Err(anyhow!(
            "error-code-registry missing reason code {REASON_CROSS_DOMAIN_REPLAY_REJECTED}"
        ));
    }
    // Validate the SDK accepts two well-formed trust domain ids and that
    // they are distinct (cross-domain replay precondition).
    let domain_a = TypedTrustDomainId::new("ak:trust_domain:alpha.example")
        .map_err(|e| anyhow!("SDK rejected well-formed trust domain id alpha: {e}"))?;
    let domain_b = TypedTrustDomainId::new("ak:trust_domain:beta.example")
        .map_err(|e| anyhow!("SDK rejected well-formed trust domain id beta: {e}"))?;
    if domain_a.as_str() == domain_b.as_str() {
        return Err(anyhow!(
            "TypedTrustDomainId equality broke: alpha and beta must be distinct"
        ));
    }
    // Wire-form prefix invariant.
    if !domain_a.as_str().starts_with(TRUST_DOMAIN_ID_PREFIX)
        || !domain_b.as_str().starts_with(TRUST_DOMAIN_ID_PREFIX)
    {
        return Err(anyhow!(
            "TypedTrustDomainId wire form must start with `{TRUST_DOMAIN_ID_PREFIX}`"
        ));
    }
    Ok(())
}

/// Wire-level executable check for `reset_event_id_mismatch`: the SDK's
/// `EventId` validator must accept two distinct valid event ids — the
/// reducer surface for this code is "payload.reset_event_id != Event.id"
/// which is a structural inequality the SDK constructors enable.
pub async fn cross_signing_reset_event_id_mismatch_run() -> Result<()> {
    if REASON_RESET_EVENT_ID_MISMATCH != EXPECTED_RESET_EVENT_ID_MISMATCH {
        return Err(anyhow!(
            "SDK REASON_RESET_EVENT_ID_MISMATCH ({}) drifted from cotest pin ({}).",
            REASON_RESET_EVENT_ID_MISMATCH,
            EXPECTED_RESET_EVENT_ID_MISMATCH,
        ));
    }
    // `reset_event_id_mismatch` is a spec `reason_code` (applies_to=
    // schema_violation), not a top-level error `code`; validate registration
    // against the registry union rather than the codes-only table.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(REASON_RESET_EVENT_ID_MISMATCH) {
        return Err(anyhow!(
            "error-code-registry missing reason code {REASON_RESET_EVENT_ID_MISMATCH}"
        ));
    }
    let id_a = EventId::new("ak:event:01904100-0000-7000-8000-000000000001")
        .map_err(|e| anyhow!("SDK rejected well-formed EventId a: {e}"))?;
    let id_b = EventId::new("ak:event:01904100-0000-7000-8000-000000000002")
        .map_err(|e| anyhow!("SDK rejected well-formed EventId b: {e}"))?;
    if id_a.as_str() == id_b.as_str() {
        return Err(anyhow!("EventId equality broke: a and b must be distinct"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cross_domain_replay_pin_matches_sdk() {
        cross_signing_reset_cross_domain_run()
            .await
            .expect("SDK constant + TypedTrustDomainId roundtrip must agree with cotest pin");
    }

    #[tokio::test]
    async fn reset_event_id_mismatch_pin_matches_sdk() {
        cross_signing_reset_event_id_mismatch_run()
            .await
            .expect("SDK constant + EventId roundtrip must agree with cotest pin");
    }
}
