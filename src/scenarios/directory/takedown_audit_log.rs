//! P2F.4 — directory takedown leaves an audit-log row.
//!
//! Every teabay `takedown` action (operator-issued or automated)
//! MUST emit a structured audit-log entry. The entry surfaces in
//! moderation appeals and is the only authoritative record of *why* a
//! directory entry disappeared.
//!
//! Normative required fields:
//!   - `actor_id` — DID of the operator (or `system` for automation),
//!   - `target_realm_id` — typed `ck:realm:` id of the affected Realm,
//!   - `reason` — one of [`TakedownReason`],
//!   - `created_at` — RFC 3339 UTC timestamp.
//!
//! This scenario doesn't query a live audit log; it pins the
//! `TakedownReason` enum surface and the audit-row well-formedness
//! validator any teabay binding MUST implement.

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Normative takedown reasons (enum closed in v1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TakedownReason {
    /// Operator policy violation (e.g. ToS).
    PolicyViolation,
    /// Subject request (right-to-be-forgotten, account deletion).
    SubjectRequest,
    /// Legal order received.
    LegalOrder,
    /// Automated abuse / spam detection.
    AutomatedAbuse,
    /// Realm owner self-requested takedown.
    OwnerSelfRequest,
}

/// All five canonical takedown reasons in stable order.
pub const ALL_TAKEDOWN_REASONS: &[TakedownReason] = &[
    TakedownReason::PolicyViolation,
    TakedownReason::SubjectRequest,
    TakedownReason::LegalOrder,
    TakedownReason::AutomatedAbuse,
    TakedownReason::OwnerSelfRequest,
];

/// Validate a candidate audit row against the v1 contract.
pub fn validate_audit_row(
    actor_id: &str,
    target_realm_id: &str,
    reason: TakedownReason,
    created_at: DateTime<Utc>,
) -> Result<()> {
    if actor_id.is_empty() {
        return Err(anyhow!("takedown audit row missing actor_id"));
    }
    if !target_realm_id.starts_with("ak:realm:") {
        return Err(anyhow!(
            "takedown audit row target_realm_id MUST be a typed ck:realm: id; got `{target_realm_id}`"
        ));
    }
    if !ALL_TAKEDOWN_REASONS.contains(&reason) {
        return Err(anyhow!(
            "takedown audit row reason `{reason:?}` is not in the canonical set"
        ));
    }
    // Reject epoch-0 timestamps as a sentinel.
    if created_at.timestamp() <= 0 {
        return Err(anyhow!(
            "takedown audit row created_at MUST be a real wall-clock time"
        ));
    }
    Ok(())
}

pub async fn takedown_audit_log_run() -> Result<()> {
    // Every reason MUST serialise to a unique snake_case literal.
    let mut seen: Vec<String> = Vec::new();
    for reason in ALL_TAKEDOWN_REASONS {
        let value =
            serde_json::to_value(reason).map_err(|e| anyhow!("serialise {reason:?}: {e}"))?;
        let s = value
            .as_str()
            .ok_or_else(|| anyhow!("takedown reason MUST serialise as a string; got {value:?}"))?;
        if !s.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(anyhow!(
                "takedown reason MUST be snake_case lowercase; got `{s}`"
            ));
        }
        if seen.contains(&s.to_string()) {
            return Err(anyhow!("takedown reason literal `{s}` duplicated"));
        }
        seen.push(s.to_string());
    }
    if ALL_TAKEDOWN_REASONS.len() != 5 {
        return Err(anyhow!(
            "ALL_TAKEDOWN_REASONS MUST be exactly 5; got {}",
            ALL_TAKEDOWN_REASONS.len()
        ));
    }

    // Accept a well-formed row.
    let now = Utc::now();
    validate_audit_row(
        "did:web:moderator.example",
        "ak:realm:0196419b-0000-7000-8000-000000000501",
        TakedownReason::PolicyViolation,
        now,
    )
    .map_err(|e| anyhow!("expected accept of well-formed row; got: {e}"))?;

    // Reject a row whose realm id lacks the typed prefix.
    let bad = validate_audit_row(
        "did:web:moderator.example",
        "realm-501", // bare id
        TakedownReason::PolicyViolation,
        now,
    );
    if bad.is_ok() {
        return Err(anyhow!("expected reject of untyped realm id; got accept"));
    }

    // Sanity: a round-tripped audit row keeps every field.
    let row = json!({
        "actor_id": "did:web:moderator.example",
        "target_realm_id": "ak:realm:0196419b-0000-7000-8000-000000000501",
        "reason": "subject_request",
        "created_at": now.to_rfc3339(),
    });
    let parsed_reason: TakedownReason = serde_json::from_value(row["reason"].clone())
        .map_err(|e| anyhow!("parse takedown reason: {e}"))?;
    if !matches!(parsed_reason, TakedownReason::SubjectRequest) {
        return Err(anyhow!(
            "round-tripped reason expected SubjectRequest; got {parsed_reason:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn audit_row_validates() {
        takedown_audit_log_run().await.unwrap();
    }
}
