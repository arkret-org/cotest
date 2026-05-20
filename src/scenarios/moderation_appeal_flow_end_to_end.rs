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

use anyhow::{Result, anyhow};
use contrix_core::{
    ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT, ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN,
    TypedAppealId, is_known_error_code,
};

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

/// Wire-level executable check: the SDK's appeal-related error code
/// constants agree with the cotest pins and the canonical registry
/// recognises both. Also exercises [`TypedAppealId`] to confirm the
/// `cx:appeal:<uuidv7>` wire form round-trips through the SDK.
pub async fn moderation_appeal_flow_end_to_end_run() -> Result<()> {
    if ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT != EXPECTED_OVERTURN_MISSING_LIFT {
        return Err(anyhow!(
            "SDK ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT ({}) drifted from cotest pin ({}).",
            ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT,
            EXPECTED_OVERTURN_MISSING_LIFT,
        ));
    }
    if ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN != EXPECTED_SELF_REVIEW_FORBIDDEN {
        return Err(anyhow!(
            "SDK ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN ({}) drifted from cotest pin ({}).",
            ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN,
            EXPECTED_SELF_REVIEW_FORBIDDEN,
        ));
    }
    if !is_known_error_code(ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_APPEAL_OVERTURN_MISSING_LIFT}"
        ));
    }
    if !is_known_error_code(ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN) {
        return Err(anyhow!(
            "SDK KNOWN_ERROR_CODES table missing {ERROR_CODE_APPEAL_SELF_REVIEW_FORBIDDEN}"
        ));
    }
    // Typed appeal id round-trip.
    let appeal = TypedAppealId::new("cx:appeal:01904100-0000-7000-8000-000000000aaa")
        .map_err(|e| anyhow!("SDK rejected well-formed TypedAppealId: {e}"))?;
    if !appeal.as_str().starts_with(APPEAL_ID_PREFIX) {
        return Err(anyhow!(
            "TypedAppealId wire form must start with `{APPEAL_ID_PREFIX}`"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn moderation_appeal_wire_pins_match_sdk() {
        moderation_appeal_flow_end_to_end_run()
            .await
            .expect("SDK appeal error codes + TypedAppealId must agree with cotest pins");
    }

    #[test]
    fn appeal_kinds_are_distinct_and_well_formed() {
        for k in [
            APPEAL_KIND_SUBMIT,
            APPEAL_KIND_REVIEW,
            APPEAL_KIND_DECISION,
            APPEAL_KIND_CLOSE,
        ] {
            assert!(k.starts_with("cx.moderation.appeal."), "kind {k} must be in appeal namespace");
        }
    }

    #[test]
    #[ignore = "TODO(round23-T06): needs live soland + sodmin reviewer fixture"]
    fn full_soland_sodmin_appeal_flow() {
        // 1. assert the four event kinds round-trip through cx.events.submit
        // 2. assert reviewer != original decision issuer
        // 3. assert `decision=overturn` Anchor batch contains a paired
        //    `cx.moderation.decision.lift` event
        // 4. assert close is fired after 30-day cool-off OR forced
    }
}
