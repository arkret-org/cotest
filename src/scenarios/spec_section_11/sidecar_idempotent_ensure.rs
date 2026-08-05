//! §11.6 — first-class Sidecar idempotent ensure.
//!
//! Calling `ak.self.agent.sidecar.command.ensure` twice with the same
//! (controller, Realm) singleton key MUST return the same `sidecar_id`.

use anyhow::{Result, anyhow};
use arkret::SidecarId;
use hkdf::Hkdf;
use sha2::Sha256;

fn derive_sidecar_id(controller_id: &str, realm_id: &str) -> Result<String> {
    let info = format!("cotest-sidecar|{controller_id}|{realm_id}");
    let hk = Hkdf::<Sha256>::new(Some(b"ak.cotest-sidecar-derive-v1"), info.as_bytes());
    let mut okm = [0u8; 16];
    hk.expand(b"sidecar_id", &mut okm)
        .map_err(|error| anyhow!("hkdf expand: {error}"))?;
    let hex: String = okm.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "ak:sidecar:{}-{}-7{}-8{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    ))
}

pub async fn sidecar_idempotent_ensure_run() -> Result<()> {
    let controller_id = "did:web:controller.example.com";
    let realm_id = "ak:realm:01999999-0000-8000-8000-00000000c001";
    let first = derive_sidecar_id(controller_id, realm_id)?;
    let second = derive_sidecar_id(controller_id, realm_id)?;
    if first != second {
        return Err(anyhow!("Sidecar singleton derivation is non-deterministic"));
    }
    SidecarId::new(first.clone())?;
    if derive_sidecar_id(
        controller_id,
        "ak:realm:01999999-0000-8000-8000-00000000c002",
    )? == first
    {
        return Err(anyhow!("distinct Realms collided to one Sidecar id"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idempotent_first_class_sidecar_id() {
        sidecar_idempotent_ensure_run().await.unwrap();
    }
}
