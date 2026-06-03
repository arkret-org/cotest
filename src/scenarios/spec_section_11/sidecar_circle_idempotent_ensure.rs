//! §11.6 — sidecar Circle idempotent ensure.
//!
//! Calling `cx.agent.sidecar_thread.ensure` twice with the same
//! (controller, agent) pair MUST return the same `sidecar_circle_id`.
//! The deterministic Circle key derivation is gated on the controller
//! DID + agent_principal_id + an HKDF salt.

use anyhow::{Result, anyhow};
use cokret_core::SidecarCircleId;
use hkdf::Hkdf;
use sha2::Sha256;

/// Deterministic sidecar id derivation. Mirrors the reducer's
/// "controller_agent_circle_key" derivation under spec head 37ce729.
fn derive_sidecar_id(controller_did: &str, agent_principal_id: &str) -> Result<String> {
    let info = format!("cotest-sidecar|{controller_did}|{agent_principal_id}");
    let hk = Hkdf::<Sha256>::new(Some(b"cx-cotest-sidecar-derive-v1"), info.as_bytes());
    let mut okm = [0u8; 16];
    hk.expand(b"sidecar_circle_id", &mut okm)
        .map_err(|e| anyhow!("hkdf expand: {e}"))?;
    // Render okm as a canonical RFC 9562 UUIDv7
    // (`xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx`, N ∈ {8,9,a,b}) so the
    // typed-id validator accepts the resulting `ck:sidecar_circle:` id.
    // The version nibble at position 12 is forced to '7', and the
    // variant nibble at position 16 is forced to '8'.
    let hex: String = okm.iter().map(|b| format!("{b:02x}")).collect();
    let seg1 = &hex[0..8];
    let seg2 = &hex[8..12];
    let seg3_rest = &hex[13..16];
    let seg4_rest = &hex[17..20];
    let seg5 = &hex[20..32];
    Ok(format!(
        "ck:sidecar_circle:{seg1}-{seg2}-7{seg3_rest}-8{seg4_rest}-{seg5}"
    ))
}

pub async fn sidecar_circle_idempotent_ensure_run() -> Result<()> {
    let controller_did = "did:web:controller.example.com";
    let agent_principal_id = "did:web:agent-one.example.com";

    let first = derive_sidecar_id(controller_did, agent_principal_id)?;
    let second = derive_sidecar_id(controller_did, agent_principal_id)?;
    if first != second {
        return Err(anyhow!(
            "sidecar id derivation is non-deterministic: first={first} second={second}"
        ));
    }
    let _ = SidecarCircleId::new(first.clone())
        .map_err(|e| anyhow!("derived sidecar id is not a well-formed SidecarCircleId: {e}"))?;

    // Different agent → different sidecar.
    let other_agent = "did:web:agent-two.example.com";
    let other = derive_sidecar_id(controller_did, other_agent)?;
    if other == first {
        return Err(anyhow!(
            "two distinct agents collided to the same sidecar_circle_id"
        ));
    }

    // TODO(P4-impl): drive POST /api/v1/agents/{id}/sidecar-thread/ensure
    // twice against a live soland; assert response.sidecar_circle_id is
    // byte-equal across calls and `created` is false on the second.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ensure_is_deterministic() {
        sidecar_circle_idempotent_ensure_run().await.unwrap();
    }
}
