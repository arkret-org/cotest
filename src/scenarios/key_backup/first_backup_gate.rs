//! P4-C.4 — first-backup gate (positive + negative).
//!
//! Principal onboarding and recovery readiness are distinct from DID update
//! key retirement. Normal use remains blocked until cold custody is confirmed,
//! an active recovery policy binds separate signing/HPKE keys, and the first
//! `backup_kind=did_recovery` envelope is durable.

use anyhow::{Result, anyhow};

#[derive(Default)]
struct DeviceState {
    custody_confirmed: bool,
    active_recovery_policy: bool,
    did_recovery_published: bool,
    root_signed_offline_receipt_confirmed: bool,
    normal_use_enabled: bool,
}

impl DeviceState {
    fn try_enable_normal_use(&mut self) -> Result<()> {
        let recovery_material_ready =
            self.did_recovery_published || self.root_signed_offline_receipt_confirmed;
        if !self.custody_confirmed || !self.active_recovery_policy || !recovery_material_ready {
            return Err(anyhow!(
                "first_backup_gate: normal use requires confirmed cold custody, \
                 an active recovery policy, and a did_recovery backup"
            ));
        }
        self.normal_use_enabled = true;
        Ok(())
    }

    fn complete_online_recovery_readiness(&mut self) {
        self.custody_confirmed = true;
        self.active_recovery_policy = true;
        self.did_recovery_published = true;
    }

    fn complete_offline_recovery_readiness(&mut self) {
        self.custody_confirmed = true;
        self.active_recovery_policy = true;
        self.root_signed_offline_receipt_confirmed = true;
    }
}

pub async fn first_backup_gate_run() -> Result<()> {
    // Every incomplete readiness state fails closed.
    let mut state = DeviceState::default();
    if state.try_enable_normal_use().is_ok() {
        return Err(anyhow!(
            "first-backup gate enabled normal use before recovery readiness"
        ));
    }
    state.custody_confirmed = true;
    if state.try_enable_normal_use().is_ok() {
        return Err(anyhow!(
            "first-backup gate ignored the missing policy and backup"
        ));
    }
    state.active_recovery_policy = true;
    if state.try_enable_normal_use().is_ok() {
        return Err(anyhow!("first-backup gate ignored the missing backup"));
    }

    state.complete_online_recovery_readiness();
    state.try_enable_normal_use()?;
    if !state.normal_use_enabled {
        return Err(anyhow!(
            "first-backup gate did not enable normal use after recovery readiness"
        ));
    }

    // The protocol also permits an identity-root-signed offline receipt after
    // explicit user confirmation; it is an alternative to publishing a
    // did_recovery envelope, not a weaker substitute for custody or policy.
    let mut offline = DeviceState::default();
    offline.complete_offline_recovery_readiness();
    offline.try_enable_normal_use()?;
    if !offline.normal_use_enabled || offline.did_recovery_published {
        return Err(anyhow!(
            "first-backup gate did not honor the offline receipt alternative"
        ));
    }
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
