//! P4-C.6 — `recovery_policy` + `recovery_receipt` schema acceptance.
//!
//! The B-C key-backup hardening pass registered two new schema ids in
//! `schema-registry.json`. The SDK MUST carry both ids and a basic
//! validator surface so downstream services bind to the same wire
//! shape.

use anyhow::{Result, anyhow};
use arkret_identifiers::RecoverySessionId;
use arkret_wire::SchemaId;

pub async fn recovery_schemas_run() -> Result<()> {
    if SchemaId::RECOVERY_POLICY_V1 != "ak.schema.recovery_policy.v1" {
        return Err(anyhow!(
            "SchemaId::RECOVERY_POLICY_V1 spelling drifted: {schemaid_recovery_policy_v1}",
            schemaid_recovery_policy_v1 = SchemaId::RECOVERY_POLICY_V1
        ));
    }
    if SchemaId::RECOVERY_RECEIPT_V1 != "ak.schema.recovery_receipt.v1" {
        return Err(anyhow!(
            "SchemaId::RECOVERY_RECEIPT_V1 spelling drifted: {schemaid_recovery_receipt_v1}",
            schemaid_recovery_receipt_v1 = SchemaId::RECOVERY_RECEIPT_V1
        ));
    }
    // UUIDv7 literal: lowercase hex, version nibble = 7, variant nibble ∈
    // {8,9,a,b}; see `arkret-rust-sdk crates/identifiers` is_lowercase_uuidv7.
    let _session = RecoverySessionId::new(
        "ak:recovery_session:01999999-0000-7000-8000-0000000aa001".to_owned(),
    )
    .map_err(|e| anyhow!("RecoverySessionId: {e}"))?;

    // TODO(P4-impl): once `ak.schema.recovery_policy.v1` and
    // `ak.schema.recovery_receipt.v1` JSON Schemas land in
    // `crates/core/src/generated/`, parse a sample envelope of each
    // shape and assert validation passes / a deliberately malformed
    // sample fails.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recovery_schemas_pinned() {
        recovery_schemas_run().await.unwrap();
    }
}
