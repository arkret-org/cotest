//! P4-C.5 — `backup_post_reset_stale` reason + 24h sync window.
//!
//! Cross-signing reset accepted at T0 ↦ any pre-existing
//! `secret_storage` series MUST emit a successor envelope within 24h.
//! If a recovery strand tries to consume a `secret_storage` envelope
//! older than 24h post-reset, soland MUST reject with
//! `backup_post_reset_stale`.

use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration, Utc};

/// Returns true when an existing envelope is "stale" relative to the
/// most recent cross-signing reset.
fn is_post_reset_stale(envelope_emitted_at: DateTime<Utc>, last_reset_at: DateTime<Utc>) -> bool {
    if envelope_emitted_at >= last_reset_at {
        return false;
    }
    let elapsed = Utc::now().signed_duration_since(last_reset_at);
    elapsed > Duration::hours(24)
}

pub async fn post_reset_stale_run() -> Result<()> {
    if arkret_wire::ReasonCode::BACKUP_POST_RESET_STALE != "backup_post_reset_stale" {
        return Err(anyhow!(
            "arkret_wire::ReasonCode::BACKUP_POST_RESET_STALE spelling drifted: \
             backup_post_reset_stale"
        ));
    }

    let now = Utc::now();
    // Case 1: envelope predates the reset and >24h have elapsed → stale.
    let stale_envelope = now - Duration::hours(48);
    let reset_at = now - Duration::hours(25);
    if !is_post_reset_stale(stale_envelope, reset_at) {
        return Err(anyhow!(
            "expected stale verdict for envelope_at={stale_envelope}, reset_at={reset_at}"
        ));
    }
    // Case 2: envelope after the reset → not stale.
    let fresh_envelope = now - Duration::hours(2);
    if is_post_reset_stale(fresh_envelope, reset_at) {
        return Err(anyhow!("envelope emitted after reset should NOT be stale"));
    }
    // Case 3: pre-reset envelope but reset only happened 2h ago → not stale yet.
    let just_reset_at = now - Duration::hours(2);
    if is_post_reset_stale(stale_envelope, just_reset_at) {
        return Err(anyhow!(
            "pre-reset envelope within the 24h grace MUST NOT be stale yet"
        ));
    }

    // TODO(P4-impl): live recovery — drive cross_signing reset on
    // inkson, wait 24h+ in test time, attempt recovery against the
    // pre-reset secret_storage envelope; assert errcode
    // backup_post_reset_stale.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stale_window_detected() {
        post_reset_stale_run().await.unwrap();
    }
}
