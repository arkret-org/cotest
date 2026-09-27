//! Closed Consent peer boundary after the minimal-metadata Realm profile
//! was retired. No unregistered pairwise principal branch may enter the DTO.

use anyhow::{Result, ensure};
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_wire::{AccountId, ActorId, DidCoreId};
use ed25519_dalek::SigningKey;
use serde_json::json;

use crate::harness::realm_create_payload_for_station;

const LEGACY_PROFILE: &str = "ak.profile.mls.minimal_metadata_realm.v1";
const STATION_ID: &str = "ak:did_core:web:station.example";

pub async fn run_consent_pairwise_isolation_live() -> Result<()> {
    let key = SigningKey::from_bytes(&[0x51; 32])
        .verifying_key()
        .to_bytes();
    let principal_id = DidCoreId::new(format!(
        "ak:did_core:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key)
    ))?;
    let account = ConsentPeer::Actor {
        actor_id: ActorId::account(AccountId::new(
            principal_id.clone(),
            DidCoreId::new(STATION_ID)?,
        )),
    };
    let other_station = ConsentPeer::Actor {
        actor_id: ActorId::account(AccountId::new(
            principal_id.clone(),
            DidCoreId::new("ak:did_core:web:other-station.example")?,
        )),
    };
    ensure!(
        account != other_station,
        "Consent collapsed distinct Accounts onto a principal"
    );
    ensure!(serde_json::from_value::<ConsentPeer>(json!({"kind":"pairwise_principal","realm_id":"ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT","principal_id":principal_id})).is_err(),"unregistered Consent peer branch is still accepted");
    ensure!(serde_json::from_value::<ConsentPeer>(serde_json::to_value(&account)?)? == account);

    let retired = json!({
        "title": "Retired pairwise Realm profile",
        "summary": "must fail closed",
        "schema_refs": ["ak.schema.realm.v1", LEGACY_PROFILE],
        "encryption_profile": "mls_rfc9420"
    });
    ensure!(
        realm_create_payload_for_station(STATION_ID, &retired).is_err(),
        "Realm authoring accepted a retired minimal-metadata profile"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retired_pairwise_profile_and_unregistered_consent_peer_are_rejected() {
        run_consent_pairwise_isolation_live().await.unwrap();
    }
}
