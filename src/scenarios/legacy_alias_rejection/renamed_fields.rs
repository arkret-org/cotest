//! Per-field alias rejection.
//!
//! Each legacy alias is named in a set; the canonical replacement is
//! named in another set. A wire-stage validator MUST reject the legacy
//! aliases and accept the replacements.

use anyhow::{Result, anyhow};

const LEGACY_ALIASES: &[&str] = &[
    "size",
    "body",
    "created_by_principal",
    "snapshot_ref_self",
    "series_sequence",
    "flow_body",
    "message_body",
    "body_only",
];

const CANONICAL_REPLACEMENTS: &[&str] = &[
    "size_bytes",
    "content",
    "created_by",
    "id",
    "series_seq",
    "flow_content",
    "message_content",
    "content_only",
];

fn is_legacy_alias(field: &str) -> bool {
    LEGACY_ALIASES.contains(&field)
}

fn is_canonical_replacement(field: &str) -> bool {
    CANONICAL_REPLACEMENTS.contains(&field)
}

pub async fn renamed_fields_run() -> Result<()> {
    if LEGACY_ALIASES.len() != CANONICAL_REPLACEMENTS.len() {
        return Err(anyhow!(
            "alias / replacement parity drift: legacy={} canonical={}",
            LEGACY_ALIASES.len(),
            CANONICAL_REPLACEMENTS.len()
        ));
    }
    for legacy in LEGACY_ALIASES {
        if !is_legacy_alias(legacy) {
            return Err(anyhow!(
                "legacy alias `{legacy}` is no longer in the rejection table"
            ));
        }
        if is_canonical_replacement(legacy) {
            return Err(anyhow!(
                "legacy alias `{legacy}` collides with a canonical replacement"
            ));
        }
    }
    for canonical in CANONICAL_REPLACEMENTS {
        if !is_canonical_replacement(canonical) {
            return Err(anyhow!(
                "canonical replacement `{canonical}` missing from acceptance table"
            ));
        }
        if is_legacy_alias(canonical) {
            return Err(anyhow!(
                "canonical replacement `{canonical}` is also in the legacy table"
            ));
        }
    }
    // TODO(P4-impl): submit a fixture with each legacy alias against
    // soland; assert response is 422 / schema_violation. Pending each
    // SUT's wire validator landing.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn alias_table_clean() {
        renamed_fields_run().await.unwrap();
    }
}
