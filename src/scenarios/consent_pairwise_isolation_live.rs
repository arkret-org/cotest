//! Consent pairwise identity boundary after the minimal-metadata Realm profile
//! was retired. This local conformance check covers the closed peer branch and
//! rejects the old Realm activation path. A live MLS LeafNode-backed positive
//! admission scenario remains an active implementation task.

use anyhow::{Result, ensure};
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_wire::{AccountId, ActorId, DidCoreId, RealmId};
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
    let first_realm = RealmId::new("ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT")?;
    let second_realm = RealmId::new("ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_")?;
    let pairwise = ConsentPeer::PairwisePrincipal {
        realm_id: first_realm.clone(),
        principal_id: principal_id.clone(),
    };
    let other_realm = ConsentPeer::PairwisePrincipal {
        realm_id: second_realm,
        principal_id: principal_id.clone(),
    };
    let account = ConsentPeer::Actor {
        actor_id: ActorId::account(AccountId::new(principal_id, DidCoreId::new(STATION_ID)?)),
    };
    ensure!(pairwise != other_realm && pairwise != account);
    let encoded = serde_json::to_value(&pairwise)?;
    ensure!(
        encoded["kind"] == "pairwise_principal"
            && encoded["realm_id"] == first_realm.as_str()
            && serde_json::from_value::<ConsentPeer>(encoded.clone())? == pairwise,
        "Consent pairwise branch did not preserve its exact Realm and principal: {encoded}"
    );

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
    async fn retired_pairwise_profile_rejected_and_consent_peer_stays_realm_scoped() {
        run_consent_pairwise_isolation_live().await.unwrap();
    }
}
