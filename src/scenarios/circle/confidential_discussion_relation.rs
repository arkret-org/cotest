//! P2F.3 — `Relation::ConfidentialDiscussionOf` two-Strand round-trip.
//!
//! AKP-0007 introduces a Relation between the broad-synthesis Strand and
//! the narrow-discussion Strand that lives in a Circle scope. This
//! scenario pins:
//!   - the `RelationKind::ConfidentialDiscussionOf` variant exists,
//!   - it serialises to the canonical `confidential_discussion_of` snake_case literal,
//!   - it round-trips through `serde_json`.

use anyhow::{Result, anyhow};
use arkret_core::RelationKind;

pub async fn confidential_discussion_relation_run() -> Result<()> {
    let rel = RelationKind::ConfidentialDiscussionOf;

    // Serialise.
    let json = serde_json::to_value(&rel).map_err(|e| anyhow!("serialise: {e}"))?;
    let s = json
        .as_str()
        .ok_or_else(|| anyhow!("RelationKind MUST serialise as a JSON string; got {json:?}"))?;
    if s != "confidential_discussion_of" {
        return Err(anyhow!(
            "RelationKind::ConfidentialDiscussionOf MUST serialise to \
             `confidential_discussion_of`; got `{s}`"
        ));
    }

    // Round-trip.
    let parsed: RelationKind = serde_json::from_str("\"confidential_discussion_of\"")
        .map_err(|e| anyhow!("parse: {e}"))?;
    if !matches!(parsed, RelationKind::ConfidentialDiscussionOf) {
        return Err(anyhow!(
            "round-tripped RelationKind expected ConfidentialDiscussionOf; got {parsed:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relation_round_trip() {
        confidential_discussion_relation_run().await.unwrap();
    }
}
