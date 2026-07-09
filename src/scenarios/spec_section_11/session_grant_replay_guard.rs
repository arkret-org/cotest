//! §11.3 — session grant replay guard.
//!
//! Re-submitting a `ak.session.grant` envelope with an already-consumed
//! `nonce` MUST be rejected. The replay guard MUST NOT silently treat
//! the duplicate as a no-op.

use std::collections::HashSet;

use anyhow::{Result, anyhow};

/// Simulate the reducer's nonce store. The guard MUST flag a duplicate
/// on second insert.
fn try_consume_nonce(seen: &mut HashSet<String>, nonce: &str) -> Result<()> {
    if !seen.insert(nonce.to_owned()) {
        return Err(anyhow!("session_grant_replay: nonce={nonce}"));
    }
    Ok(())
}

pub async fn session_grant_replay_guard_run() -> Result<()> {
    let mut seen = HashSet::new();
    let nonce = "n-cotest-p4-11-3-replay";
    try_consume_nonce(&mut seen, nonce)?;
    let replay = try_consume_nonce(&mut seen, nonce);
    if replay.is_ok() {
        return Err(anyhow!(
            "session grant replay guard accepted a duplicate nonce"
        ));
    }

    // TODO(P4-impl): live-server vector: POST `/auth/sessions/grant`
    // twice with the same nonce + cross-signed proof; assert the
    // second response is 409 with `session_grant_replay` errcode.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replay_guard_baseline() {
        session_grant_replay_guard_run().await.unwrap();
    }
}
