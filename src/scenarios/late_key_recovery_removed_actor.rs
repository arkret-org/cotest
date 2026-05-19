//! Round 2+3 / T16 — Late key recovery for revoked/removed actor.
//!
//! Spec (round 2+3 cleanup, T16 — Late key recovery state machine):
//!
//! When an actor has been **removed from a Realm** (membership tombstoned)
//! and a late `cx.key.share` arrives for an MLS epoch the actor was no
//! longer a member of at the originating event's HLC, the receiver MUST
//! refuse to decrypt and MUST surface the error code
//! `late_recovery_rejected_membership`.
//!
//! The state machine is `decryption_pending → decryption_failed →
//! late_recovered` with four accept conditions:
//!
//!   (a) membership at the originating event time
//!   (b) policy at the originating event time
//!   (c) key-share source authorization
//!   (d) `cx.audit.accessed` with `late_recovery=true` (when the actor
//!       belongs to an audit profile)
//!
//! This scenario pins condition (a) — a removed actor MUST hit the
//! `late_recovery_rejected_membership` reason code rather than silently
//! decrypting.

use anyhow::Result;

/// The canonical error code surfaced by the reducer when a late key
/// share is accepted by a Realm whose membership for the recipient was
/// already revoked at the originating event's HLC.
pub const EXPECTED_REASON: &str = "late_recovery_rejected_membership";

/// Run the scenario.
///
/// TODO(round23-T16): wire up the soland reducer fixture — at the time
/// of writing the late-key-recovery state machine is still being built
/// in the SDK / soland. Once the fixture exists, this scenario should:
///
/// 1. Boot a soland test harness with one Realm and two actors (A, B).
/// 2. Move actor A through `cx.realm.member.revoke` (HLC=t0).
/// 3. Emit a `cx.key.share` for an MLS epoch at HLC=t0-1 addressed to A
///    (late delivery — A was already revoked at the share's HLC).
/// 4. Assert the reducer rejects the decryption attempt with
///    `late_recovery_rejected_membership` and the audit log shows
///    `decryption_pending → decryption_failed`.
pub async fn late_key_recovery_removed_actor_run() -> Result<()> {
    // TODO(round23-T16): replace stub with real soland fixture call.
    Ok(())
}
