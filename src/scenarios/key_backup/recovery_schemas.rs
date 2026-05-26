//! P4-C.6 — `recovery_policy` + `recovery_receipt` schema acceptance.
//!
//! The B-C key-backup hardening pass registered two new schema ids in
//! `schema-registry.json`. The SDK MUST carry both ids and a basic
//! validator surface so downstream services bind to the same wire
//! shape.

use anyhow::{Result, anyhow};

use contrix_core::{RECOVERY_POLICY_SCHEMA, RECOVERY_RECEIPT_SCHEMA, RecoverySessionId};

pub async fn recovery_schemas_run() -> Result<()> {
    if RECOVERY_POLICY_SCHEMA != "cx.schema.recovery_policy.v1" {
        return Err(anyhow!(
            "RECOVERY_POLICY_SCHEMA spelling drifted: {RECOVERY_POLICY_SCHEMA}"
        ));
    }
    if RECOVERY_RECEIPT_SCHEMA != "cx.schema.recovery_receipt.v1" {
        return Err(anyhow!(
            "RECOVERY_RECEIPT_SCHEMA spelling drifted: {RECOVERY_RECEIPT_SCHEMA}"
        ));
    }
    let _session = RecoverySessionId::new(
        "cx:recovery_session:01999999-0000-7000-8000-00000000rs01".to_owned(),
    )
    .map_err(|e| anyhow!("RecoverySessionId: {e}"))?;

    // TODO(P4-impl): once `cx.schema.recovery_policy.v1` and
    // `cx.schema.recovery_receipt.v1` JSON Schemas land in
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
