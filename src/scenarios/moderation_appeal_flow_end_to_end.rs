//! Round 2+3 / T06 — Moderation appeal closed-loop e2e.
//!
//! Spec (round 2+3 cleanup, T06 — Moderation appeal):
//!
//! Four new active event kinds:
//!   * `cx.moderation.appeal.submit`
//!   * `cx.moderation.appeal.review`
//!   * `cx.moderation.appeal.decision`
//!   * `cx.moderation.appeal.close`
//!
//! Schema: `cx.schema.moderation_appeal.v1`. Typed ID:
//! `cx:appeal:<uuidv7>`. Cell state machine:
//!
//!   `none → submitted → under_review → decided → closed`
//!
//! Normative invariants:
//!   * reviewer DID MUST differ from the original decision issuer
//!     (`appeal_self_review_forbidden`)
//!   * an `overturn` decision MUST be paired with a
//!     `cx.moderation.decision.lift` in the **same** Anchor batch
//!     (`appeal_overturn_missing_lift`)
//!   * close fires automatically after the 30-day cool-off or when the
//!     submitter (or reviewer) issues an explicit close
//!
//! This scenario walks the full happy path of an `overturn`: submit →
//! review → decision (overturn) → assert paired `lift` in the same
//! Anchor batch → close.

use anyhow::Result;

pub const APPEAL_KIND_SUBMIT: &str = "cx.moderation.appeal.submit";
pub const APPEAL_KIND_REVIEW: &str = "cx.moderation.appeal.review";
pub const APPEAL_KIND_DECISION: &str = "cx.moderation.appeal.decision";
pub const APPEAL_KIND_CLOSE: &str = "cx.moderation.appeal.close";

pub const DECISION_LIFT_KIND: &str = "cx.moderation.decision.lift";

pub const APPEAL_SCHEMA: &str = "cx.schema.moderation_appeal.v1";
pub const APPEAL_ID_PREFIX: &str = "cx:appeal:";

/// Error codes the reducer SHOULD surface on the negative branches.
pub const EXPECTED_OVERTURN_MISSING_LIFT: &str = "appeal_overturn_missing_lift";
pub const EXPECTED_SELF_REVIEW_FORBIDDEN: &str = "appeal_self_review_forbidden";

/// Drive the four-event happy path: submit → review → decide(overturn)
/// → close. The decide step asserts a paired `cx.moderation.decision.lift`
/// is present in the **same** Anchor batch (atomic overturn↔lift binding).
///
/// TODO(round23-T06): wire the soland moderation appeal reducer + sodmin
/// reviewer view. Until then this scenario is a stub that pins the kind /
/// schema / typed-ID constants used by the reducer contract.
pub async fn moderation_appeal_flow_end_to_end_run() -> Result<()> {
    // TODO(round23-T06): replace stub with full submit→review→decide(overturn)→close
    // soland + sodmin fixture. Must:
    //   1. assert the four event kinds round-trip through cx.events.submit
    //   2. assert reviewer != original decision issuer
    //   3. assert `decision=overturn` Anchor batch contains a paired
    //      `cx.moderation.decision.lift` event
    //   4. assert close is fired after 30-day cool-off OR forced
    Ok(())
}
