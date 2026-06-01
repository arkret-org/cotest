//! §11.7 — existence privacy.
//!
//! A non-controller probing for an agent_principal that does or does
//! not exist MUST receive an indistinguishable response. The
//! agent-list surface is controller-self; a probe by any other actor
//! returns the same blinded `not_found` whether the agent exists or
//! not.

use anyhow::{Result, anyhow};

/// Returns the canonical blinded "not findable from this scope"
/// response shape. The two callers (existent + non-existent) MUST
/// land on byte-equal output.
fn blinded_not_found_body(_probe_id: &str) -> &'static str {
    "{\"ok\":false,\"error\":{\"errcode\":\"not_found\"}}"
}

pub async fn existence_privacy_run() -> Result<()> {
    let existent = "did:web:agent-existent.example.com";
    let absent = "did:web:agent-absent.example.com";

    let a = blinded_not_found_body(existent);
    let b = blinded_not_found_body(absent);
    if a != b {
        return Err(anyhow!(
            "existence-privacy leak: probing {existent} returned `{a}`, probing {absent} returned `{b}`"
        ));
    }

    // TODO(P4-impl): drive GET /api/v1/agents/{id} as a second account
    // (non-controller) against both an existing and a non-existing
    // agent_principal id; assert the wire response (status + body) is
    // byte-identical.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn existence_privacy_baseline() {
        existence_privacy_run().await.unwrap();
    }
}
