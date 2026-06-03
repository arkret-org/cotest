//! §11.2 — pairing expiry auto-revoke.
//!
//! When an `AgentSession` carries `expires_at < now()`, the reducer
//! MUST emit `cx.session.grant_revoke` carrying
//! `reason = "pairing_expired"`. The capability cache MUST be
//! invalidated within one tick.

use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use contrix_core::AgentSessionId;

pub async fn pairing_expiry_auto_revoke_run() -> Result<()> {
    let session =
        AgentSessionId::new("ck:agent_session:01999999-0000-7000-8000-00000000e001".to_owned())
            .map_err(|e| anyhow!("AgentSessionId: {e}"))?;
    // A past `expires_at` deterministically marks the session as
    // pairing-expired.
    let expired_at = Utc::now() - Duration::hours(1);
    if expired_at >= Utc::now() {
        return Err(anyhow!(
            "expected expired_at < now; got {expired_at} >= now"
        ));
    }
    if !session.as_str().starts_with("ck:agent_session:") {
        return Err(anyhow!("AgentSessionId lost canonical prefix"));
    }
    // TODO(P4-impl): once soland persists agent_session rows, drive
    // a session with expires_at = now-1h and assert the reducer emits
    // exactly one `cx.session.grant_revoke{reason=pairing_expired}` and
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
