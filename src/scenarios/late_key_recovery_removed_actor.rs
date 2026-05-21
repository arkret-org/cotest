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

use anyhow::{Result, anyhow};
use contrix_core::{ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP, is_known_error_code};

/// The canonical error code surfaced by the reducer when a late key
/// share is accepted by a Realm whose membership for the recipient was
/// already revoked at the originating event's HLC.
pub const EXPECTED_REASON: &str = "late_recovery_rejected_membership";

/// Wire-level executable check: the SDK constant for
/// `late_recovery_rejected_membership` matches the cotest pin and the
/// canonical registry recognises it.
///
/// The full end-to-end test that boots soland, revokes membership, and
/// posts a late `cx.key.share` lives under `#[ignore]` below — it
/// requires a real fixture.
pub async fn late_key_recovery_removed_actor_run() -> Result<()> {
    if ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP != EXPECTED_REASON {
        return Err(anyhow!(
            "SDK ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP ({}) drifted from cotest pin ({}).",
            ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP,
            EXPECTED_REASON,
        ));
    }
    if !is_known_error_code(ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_LATE_RECOVERY_REJECTED_MEMBERSHIP}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn late_recovery_reason_pin_matches_sdk() {
        late_key_recovery_removed_actor_run().await.expect(
            "SDK constant for late_recovery_rejected_membership must agree with cotest pin",
        );
    }

    #[test]
    #[ignore = "TODO(round23-T16): needs live soland + revoked-actor fixture"]
    fn full_soland_late_recovery_end_to_end() {
        // 1. Boot a soland test harness with one Realm and two actors (A, B).
        // 2. Move actor A through `cx.realm.member.revoke` (HLC=t0).
        // 3. Emit a `cx.key.share` for an MLS epoch at HLC=t0-1 addressed to A
        //    (late delivery — A was already revoked at the share's HLC).
        // 4. Assert the reducer rejects the decryption attempt with
        //    `late_recovery_rejected_membership` and the audit log shows
        //    `decryption_pending → decryption_failed`.
    }
}
