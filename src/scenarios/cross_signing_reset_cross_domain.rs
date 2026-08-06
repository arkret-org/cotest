//! `ak.cross_signing.reset` cross-domain replay defense.
//!
//! `cross-signing-reset.schema.json` requires `trust_domain:
//! TypedTrustDomainId` (`ak:trust_domain:<scope>`), and the receiver MUST
//! reject a payload whose `trust_domain` is not its own deployment trust domain
//! with `cross_domain_replay_rejected`.
//!
//! The companion `reset_event_id` binding is gone: `arkret-spec@e6da1f0e`
//! retired it because the payload sits inside the `event_digest` preimage and
//! `event_id` derives from that digest, so a payload naming its own Event had
//! no fixed point. Shell binding now comes from the envelope proof, which is
//! outside the preimage, plus the `previous_generation` precondition — neither
//! of which this module pins.

use anyhow::{Result, anyhow};
use arkret_identifiers::TypedTrustDomainId;
use arkret_schema::embedded_error_code_identifiers;

pub const TRUST_DOMAIN_ID_PREFIX: &str = "ak:trust_domain:";

/// Wire-level executable check: the SDK's `TypedTrustDomainId` validator
/// MUST accept two distinct, well-formed trust domain ids — replaying a
/// proof signed under domain A into a deployment that is configured as
/// domain B is the exact replay surface this scenario locks down. We
/// pin the error code constant matches the cotest expectation and that
/// the SDK can construct (and distinguish) the two ids.
pub async fn cross_signing_reset_cross_domain_run() -> Result<()> {
    if arkret_wire::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED != "cross_domain_replay_rejected" {
        return Err(anyhow!(
            "SDK arkret_wire::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED ({}) drifted from cotest pin ({}).",
            "cross_domain_replay_rejected",
            arkret_wire::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED,
        ));
    }
    // `cross_domain_replay_rejected` is a spec `reason_code` (applies_to=
    // auth_decision), not a top-level error `code`, so it is absent from the
    // SDK's `KNOWN_ERROR_CODES`. Validate registration against the registry
    // union (codes ∪ reason_codes), which is the spec truth source.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(arkret_wire::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED) {
        return Err(anyhow!(
            "error-code-registry missing reason code cross_domain_replay_rejected"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cross_domain_replay_pin_matches_sdk() {
        cross_signing_reset_cross_domain_run()
            .await
            .expect("SDK constant + TypedTrustDomainId roundtrip must agree with cotest pin");
    }
}
