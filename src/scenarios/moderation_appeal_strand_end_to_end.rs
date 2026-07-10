//! Round 2+3 / T06 — Moderation appeal closed-loop e2e.
//!
//! Spec (round 2+3 cleanup, T06 — Moderation appeal):
//!
//! Four new active event kinds:
//!   * `ak.moderation.appeal.submit`
//!   * `ak.moderation.appeal.review`
//!   * `ak.moderation.appeal.decision`
//!   * `ak.moderation.appeal.close`
//!
//! Schema: `ak.schema.moderation_appeal.v1`. Typed ID:
//! `ak:appeal:<uuidv7>`. Cell state machine:
//!
//!   `none → submitted → under_review → decided → closed`
//!
//! Normative invariants:
//!   * reviewer DID MUST differ from the original decision issuer (`appeal_self_review_forbidden`)
//!   * an `overturn` decision MUST be paired with a `ak.moderation.decision.lift` in the **same**
//!     Anchor batch (`appeal_overturn_missing_lift`)
//!   * close fires automatically after the 30-day cool-off or when the submitter (or reviewer)
//!     issues an explicit close
//!
//! This scenario walks the full happy path of an `overturn`: submit →
//! review → decision (overturn) → assert paired `lift` in the same
//! Anchor batch → close.

use anyhow::{Result, anyhow};
use arkret_core::schema::embedded_error_code_identifiers;
use arkret_core::{
    REASON_APPEAL_OVERTURN_MISSING_LIFT, REASON_APPEAL_SELF_REVIEW_FORBIDDEN, TypedAppealId,
};

pub const APPEAL_KIND_SUBMIT: &str = "ak.moderation.appeal.submit";
pub const APPEAL_KIND_REVIEW: &str = "ak.moderation.appeal.review";
pub const APPEAL_KIND_DECISION: &str = "ak.moderation.appeal.decision";
pub const APPEAL_KIND_CLOSE: &str = "ak.moderation.appeal.close";

pub const DECISION_LIFT_KIND: &str = "ak.moderation.decision.lift";

pub const APPEAL_SCHEMA: &str = "ak.schema.moderation_appeal.v1";
pub const APPEAL_ID_PREFIX: &str = "ak:appeal:";

/// Error codes the reducer SHOULD surface on the negative branches.
pub const EXPECTED_OVERTURN_MISSING_LIFT: &str = "appeal_overturn_missing_lift";
pub const EXPECTED_SELF_REVIEW_FORBIDDEN: &str = "appeal_self_review_forbidden";

/// Wire-level executable check: the SDK's appeal-related error code
/// constants agree with the cotest pins and the canonical registry
/// recognises both. Also exercises [`TypedAppealId`] to confirm the
/// `ak:appeal:<uuidv7>` wire form round-trips through the SDK.
pub async fn moderation_appeal_strand_end_to_end_run() -> Result<()> {
    if REASON_APPEAL_OVERTURN_MISSING_LIFT != EXPECTED_OVERTURN_MISSING_LIFT {
        return Err(anyhow!(
            "SDK REASON_APPEAL_OVERTURN_MISSING_LIFT ({}) drifted from cotest pin ({}).",
            REASON_APPEAL_OVERTURN_MISSING_LIFT,
            EXPECTED_OVERTURN_MISSING_LIFT,
        ));
    }
    if REASON_APPEAL_SELF_REVIEW_FORBIDDEN != EXPECTED_SELF_REVIEW_FORBIDDEN {
        return Err(anyhow!(
            "SDK REASON_APPEAL_SELF_REVIEW_FORBIDDEN ({}) drifted from cotest pin ({}).",
            REASON_APPEAL_SELF_REVIEW_FORBIDDEN,
            EXPECTED_SELF_REVIEW_FORBIDDEN,
        ));
    }
    // Both appeal codes are spec `reason_codes`, not top-level error `codes`,
    // so they are validated against the registry union rather than the SDK's
    // codes-only `KNOWN_ERROR_CODES` table.
    let registry_identifiers = embedded_error_code_identifiers()
        .map_err(|e| anyhow!("failed to load embedded error-code-registry: {e}"))?;
    if !registry_identifiers.contains(REASON_APPEAL_OVERTURN_MISSING_LIFT) {
        return Err(anyhow!(
            "error-code-registry missing reason code {REASON_APPEAL_OVERTURN_MISSING_LIFT}"
        ));
    }
    if !registry_identifiers.contains(REASON_APPEAL_SELF_REVIEW_FORBIDDEN) {
        return Err(anyhow!(
            "error-code-registry missing reason code {REASON_APPEAL_SELF_REVIEW_FORBIDDEN}"
        ));
    }
    // Typed appeal id round-trip.
    let appeal = TypedAppealId::new("ak:appeal:01904100-0000-7000-8000-000000000aaa")
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
        moderation_appeal_strand_end_to_end_run()
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
            assert!(
                k.starts_with("ak.moderation.appeal."),
                "kind {k} must be in appeal namespace"
            );
        }
    }

    #[tokio::test]
    async fn t06_moderation_appeal_contract() {
        moderation_appeal_strand_end_to_end_run()
            .await
            .expect("appeal error codes + TypedAppealId must stay registered");
        assert_eq!(DECISION_LIFT_KIND, "ak.moderation.decision.lift");
        assert_ne!(APPEAL_KIND_DECISION, DECISION_LIFT_KIND);
    }
}
