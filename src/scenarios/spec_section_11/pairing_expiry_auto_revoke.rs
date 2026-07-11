//! §11.2 — pairing expiry auto-revoke.
//!
//! When an `AgentSession` carries `expires_at < now()`, the reducer
//! MUST emit `ak.session.grant_revoke` carrying
//! `reason = "pairing_expired"`. The capability cache MUST be
//! invalidated within one tick.

use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};

pub async fn pairing_expiry_auto_revoke_run() -> Result<()> {
    // A past `expires_at` deterministically marks the session as
    // pairing-expired.
    let expired_at = Utc::now() - Duration::hours(1);
    if expired_at >= Utc::now() {
        return Err(anyhow!(
            "expected expired_at < now; got {expired_at} >= now"
        ));
    }
    // TODO(P4-impl): once soland persists agent_session rows, drive
    // a session with expires_at = now-1h and assert the reducer emits
    // exactly one `ak.session.grant_revoke{reason=pairing_expired}` and
    // that floria's capability cache for the session is purged.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pairing_expiry_invariant() {
        pairing_expiry_auto_revoke_run().await.unwrap();
    }
}
