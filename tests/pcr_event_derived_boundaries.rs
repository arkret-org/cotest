use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

fn realm_genesis_baseline() -> serde_json::Value {
    json!({
        "schema": "ak.schema.realm_genesis.v1",
        "purpose": "collaboration",
        "genesis_salt": "X-kS8-uBvWQ_iuRqO7Rsv0WGBjZG2S2wJ533Tk2SJJ4",
        "trust_domain": "ak:trust_domain:did.webvh.alice.example",
        "security_class": "standard",
        "governance_station_id": "ak:did_core:webvh:z6mkfixturestationexample",
        "initial_join_rule": "closed",
        "initial_history_access": "since_join",
        "initial_discoverability": "secret"
    })
}

#[test]
fn event_actor_requires_complete_core_account_identity() {
    let actor = json!({
        "kind": "account",
        "account_id": {
            "principal_id": "ak:did_core:web:alice.example",
            "station_id": "ak:did_core:web:station.example"
        }
    });
    let parsed = serde_json::from_value::<arkret_wire::ActorId>(actor.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), actor);
    for field in ["principal_id", "station_id"] {
        let mut did_spelling = actor.clone();
        did_spelling["account_id"][field] = json!("did:web:alice.example");
        assert!(serde_json::from_value::<arkret_wire::ActorId>(did_spelling).is_err());
        let mut incomplete = actor.clone();
        incomplete["account_id"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<arkret_wire::ActorId>(incomplete).is_err());
    }
}

#[test]
fn realm_genesis_rejects_retired_notary_field() {
    let mut genesis = realm_genesis_baseline();
    assert!(
        serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmGenesis>(
            genesis.clone()
        )
        .is_ok()
    );
    genesis["notary"] = json!({"signer": "retired"});
    assert!(
        serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmGenesis>(
            genesis
        )
        .is_err()
    );
}

#[test]
fn realm_id_rejects_reserved_high_nibble_one() {
    let mut token = [0x42_u8; 33];
    token[0] = 0x11;
    let wire = format!("ak:realm:{}", URL_SAFE_NO_PAD.encode(token));
    assert!(arkret_wire::RealmId::new(wire).is_err());
}

#[test]
fn realm_genesis_rejects_missing_genesis_salt() {
    let mut missing = realm_genesis_baseline();
    assert!(
        serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmGenesis>(
            missing.clone()
        )
        .is_ok()
    );
    missing.as_object_mut().unwrap().remove("genesis_salt");
    assert!(
        serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmGenesis>(
            missing
        )
        .is_err()
    );
}
