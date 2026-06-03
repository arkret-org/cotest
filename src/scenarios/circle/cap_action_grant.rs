//! P2F.3 — every CXP-0007 capability action is well-formed.
//!
//! Pins the six `cx.circle.*` capability-action strings against the SDK
//! constants and against the well-formed-ness rules expected by the
//! capability registry (`cx.<domain>.<verb>[.<modifier>]*`, snake_case,
//! no trailing dots, no whitespace). This is the wire-shape baseline the
//! coauth / sodmin services bind against, so a regression here breaks
//! every grant emitted by an admin UI.

use anyhow::{Result, anyhow};
use cokret_core::{
    CAP_ACTION_CIRCLE_AUDIT, CAP_ACTION_CIRCLE_CREATE, CAP_ACTION_CIRCLE_MANAGE,
    CAP_ACTION_CIRCLE_MEMBER_ADD, CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS,
    CAP_ACTION_CIRCLE_MEMBER_MANAGE,
};

/// The canonical CXP-0007 capability-action allowlist. MUST match
/// `crate::circle_rules::CIRCLE_CAPABILITY_ACTIONS` and
/// `capability-action-registry.json`.
pub const CXP_0007_CAPABILITY_ACTIONS: &[&str] = &[
    CAP_ACTION_CIRCLE_CREATE,
    CAP_ACTION_CIRCLE_MANAGE,
    CAP_ACTION_CIRCLE_MEMBER_ADD,
    CAP_ACTION_CIRCLE_MEMBER_MANAGE,
    CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS,
    CAP_ACTION_CIRCLE_AUDIT,
];

fn is_well_formed(action: &str) -> Result<()> {
    if action.is_empty() {
        return Err(anyhow!("capability action is empty"));
    }
    if !action.starts_with("cx.") {
        return Err(anyhow!(
            "capability action `{action}` MUST start with `cx.`"
        ));
    }
    if action.ends_with('.') {
        return Err(anyhow!(
            "capability action `{action}` MUST NOT end with a `.`"
        ));
    }
    if action.contains(char::is_whitespace) {
        return Err(anyhow!(
            "capability action `{action}` MUST NOT contain whitespace"
        ));
    }
    for ch in action.chars() {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_') {
            return Err(anyhow!(
                "capability action `{action}` contains illegal char `{ch}` \
                 (only [a-z0-9._] permitted)"
            ));
        }
    }
    if action.contains("..") {
        return Err(anyhow!(
            "capability action `{action}` contains an empty segment (`..`)"
        ));
    }
    Ok(())
}

pub async fn cap_action_grant_run() -> Result<()> {
    if CXP_0007_CAPABILITY_ACTIONS.len() != 6 {
        return Err(anyhow!(
            "CXP-0007 advertises exactly 6 capability actions; got {}",
            CXP_0007_CAPABILITY_ACTIONS.len()
        ));
    }
    // Detect duplicates.
    let mut sorted = CXP_0007_CAPABILITY_ACTIONS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != CXP_0007_CAPABILITY_ACTIONS.len() {
        return Err(anyhow!(
            "duplicate capability action constants: {CXP_0007_CAPABILITY_ACTIONS:?}"
        ));
    }
    for action in CXP_0007_CAPABILITY_ACTIONS {
        is_well_formed(action)
            .map_err(|e| anyhow!("capability action `{action}` ill-formed: {e}"))?;
        if !action.starts_with("cx.circle.") {
            return Err(anyhow!(
                "CXP-0007 capability action MUST start with `cx.circle.`; got `{action}`"
            ));
        }
    }
    // Spot-pin a couple of specific names so a typo in any constant fails
    // here (instead of silently shipping a non-existent action to coauth).
    if CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS != "cx.circle.member.add.others" {
        return Err(anyhow!(
            "CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS spelling drifted: {}",
            CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS
        ));
    }
    if CAP_ACTION_CIRCLE_AUDIT != "cx.circle.audit" {
        return Err(anyhow!(
            "CAP_ACTION_CIRCLE_AUDIT spelling drifted: {}",
            CAP_ACTION_CIRCLE_AUDIT
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cap_actions_well_formed() {
        cap_action_grant_run().await.unwrap();
    }
}
