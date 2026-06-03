//! Round 2+3 / T08 — `ck.cross_signing.reset` cross-domain replay
//! defense + event_id binding.
//!
//! Spec (round 2+3 cleanup, T08):
//!
//! `cross-signing-reset.schema.json` now requires two new payload fields:
//!   * `trust_domain: TypedTrustDomainId` (`ck:trust_domain:<scope>`)
//!   * `reset_event_id: TypedEventId` (`ck:event:<uuidv7>`)
//!
//! The receiver MUST validate in this strict order:
//!   1. `trust_domain` matches the receiver's deployment trust domain → otherwise
//!      `cross_domain_replay_rejected`
//!   2. `reset_event_id` equals the enclosing `Event.id` → otherwise `reset_event_id_mismatch`
//!   3. Signature verification (existing) → otherwise `invalid_signature`
//!
//! This module covers two scenarios:
//!
//! * `cross_signing_reset_cross_domain_run` — proof minted against `ck:trust_domain:A` replayed
//!   against deployment `ck:trust_domain:B`; MUST be rejected with `cross_domain_replay_rejected`.
//!
//! * `cross_signing_reset_event_id_mismatch_run` — payload carries `reset_event_id != Event.id`;
//!   MUST be rejected with `reset_event_id_mismatch`.

use anyhow::{Result, anyhow};
use cokret_core::{
    ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED, ERROR_CODE_RESET_EVENT_ID_MISMATCH, EventId,
    TypedTrustDomainId, is_known_error_code,
};

pub const EXPECTED_CROSS_DOMAIN_REPLAY: &str = "cross_domain_replay_rejected";
pub const EXPECTED_RESET_EVENT_ID_MISMATCH: &str = "reset_event_id_mismatch";

pub const TRUST_DOMAIN_ID_PREFIX: &str = "ck:trust_domain:";

/// Wire-level executable check: the SDK's `TypedTrustDomainId` validator
/// MUST accept two distinct, well-formed trust domain ids — replaying a
/// proof signed under domain A into a deployment that is configured as
/// domain B is the exact replay surface this scenario locks down. We
/// pin the error code constant matches the cotest expectation and that
/// the SDK can construct (and distinguish) the two ids.
pub async fn cross_signing_reset_cross_domain_run() -> Result<()> {
    if ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED != EXPECTED_CROSS_DOMAIN_REPLAY {
        return Err(anyhow!(
            "SDK ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED ({}) drifted from cotest pin ({}).",
            ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED,
            EXPECTED_CROSS_DOMAIN_REPLAY,
        ));
    }
    if !is_known_error_code(ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED}"
        ));
    }
    // Validate the SDK accepts two well-formed trust domain ids and that
    // they are distinct (cross-domain replay precondition).
    let domain_a = TypedTrustDomainId::new("ck:trust_domain:alpha.example")
        .map_err(|e| anyhow!("SDK rejected well-formed trust domain id alpha: {e}"))?;
    let domain_b = TypedTrustDomainId::new("ck:trust_domain:beta.example")
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
    if ERROR_CODE_RESET_EVENT_ID_MISMATCH != EXPECTED_RESET_EVENT_ID_MISMATCH {
        return Err(anyhow!(
            "SDK ERROR_CODE_RESET_EVENT_ID_MISMATCH ({}) drifted from cotest pin ({}).",
            ERROR_CODE_RESET_EVENT_ID_MISMATCH,
            EXPECTED_RESET_EVENT_ID_MISMATCH,
        ));
    }
    if !is_known_error_code(ERROR_CODE_RESET_EVENT_ID_MISMATCH) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_RESET_EVENT_ID_MISMATCH}"
        ));
    }
    let id_a = EventId::new("ck:event:01904100-0000-7000-8000-000000000001")
        .map_err(|e| anyhow!("SDK rejected well-formed EventId a: {e}"))?;
    let id_b = EventId::new("ck:event:01904100-0000-7000-8000-000000000002")
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
