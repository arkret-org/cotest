//! P4-C.4 — first-backup gate (positive + negative).
//!
//! Per CXP-0008 §1.3 + key-management.md §5.2, inception key retire
//! MUST be hard-blocked until a `backup_class=did_recovery` envelope
//! has been published (or an offline-sealed `recovery_receipt`
//! captured). The gate fails closed: any retire attempt before the
//! recovery envelope produces an error.

use anyhow::{Result, anyhow};

#[derive(Default)]
struct DeviceState {
    /// True once a backup_class=did_recovery envelope has landed.
    did_recovery_published: bool,
    /// True once the inception key has retired.
    inception_retired: bool,
}

impl DeviceState {
    fn try_retire_inception(&mut self) -> Result<()> {
        if !self.did_recovery_published {
            return Err(anyhow!(
                "first_backup_gate: inception key retire blocked until \
                 backup_class=did_recovery envelope is published"
            ));
        }
        self.inception_retired = true;
        Ok(())
    }

    fn publish_did_recovery(&mut self) {
        self.did_recovery_published = true;
    }
}

pub async fn first_backup_gate_run() -> Result<()> {
    // Negative: retire-before-publish MUST fail.
    let mut state = DeviceState::default();
    if state.try_retire_inception().is_ok() {
        return Err(anyhow!(
            "first-backup gate accepted retire BEFORE a did_recovery envelope"
        ));
    }
    if state.inception_retired {
        return Err(anyhow!(
            "first-backup gate marked inception retired despite the gate failing"
        ));
    }

    // Positive: publish first, then retire is allowed.
    state.publish_did_recovery();
    state.try_retire_inception()?;
    if !state.inception_retired {
        return Err(anyhow!(
            "first-backup gate failed to mark inception retired after publish"
        ));
    }

    // TODO(P4-impl): live yougen bootstrap flow — bind device-A,
    // attempt `cx.device.authorize` for device-B BEFORE the recovery
    // envelope lands; assert 4xx with errcode `first_backup_gate`.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gate_blocks_then_permits() {
        first_backup_gate_run().await.unwrap();
    }
}
