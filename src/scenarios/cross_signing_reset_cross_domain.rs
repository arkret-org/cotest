//! Round 2+3 / T08 — `cx.cross_signing.reset` cross-domain replay
//! defense + event_id binding.
//!
//! Spec (round 2+3 cleanup, T08):
//!
//! `cross-signing-reset.schema.json` now requires two new payload fields:
//!   * `trust_domain: TypedTrustDomainId` (`cx:trust_domain:<scope>`)
//!   * `reset_event_id: TypedEventId` (`cx:event:<uuidv7>`)
//!
//! The receiver MUST validate in this strict order:
//!   1. `trust_domain` matches the receiver's deployment trust domain →
//!      otherwise `cross_domain_replay_rejected`
//!   2. `reset_event_id` equals the enclosing `Event.id` → otherwise
//!      `reset_event_id_mismatch`
//!   3. Signature verification (existing) → otherwise `invalid_signature`
//!
//! This module covers two scenarios:
//!
//! * `cross_signing_reset_cross_domain_run` — proof minted against
//!   `cx:trust_domain:A` replayed against deployment `cx:trust_domain:B`;
//!   MUST be rejected with `cross_domain_replay_rejected`.
//!
//! * `cross_signing_reset_event_id_mismatch_run` — payload carries
//!   `reset_event_id != Event.id`; MUST be rejected with
//!   `reset_event_id_mismatch`.

use anyhow::Result;

pub const EXPECTED_CROSS_DOMAIN_REPLAY: &str = "cross_domain_replay_rejected";
pub const EXPECTED_RESET_EVENT_ID_MISMATCH: &str = "reset_event_id_mismatch";

pub const TRUST_DOMAIN_ID_PREFIX: &str = "cx:trust_domain:";

/// Replay a `cx.cross_signing.reset` minted against trust domain A
/// against a deployment running trust domain B.
pub async fn cross_signing_reset_cross_domain_run() -> Result<()> {
    // TODO(round23-T08): wire to soland reducer / SDK. Must mint a
    // proof under `cx:trust_domain:alpha`, submit to a deployment
    // configured as `cx:trust_domain:beta`, and assert
    // `cross_domain_replay_rejected` is returned *before* signature
    // verification runs.
    Ok(())
}

/// Submit a `cx.cross_signing.reset` whose `payload.reset_event_id`
/// does not equal the enclosing `Event.id`.
pub async fn cross_signing_reset_event_id_mismatch_run() -> Result<()> {
    // TODO(round23-T08): wire to soland reducer / SDK. Must build a
    // payload with `reset_event_id = cx:event:<random>` distinct from
    // the envelope id, submit, and assert `reset_event_id_mismatch`.
    Ok(())
}
