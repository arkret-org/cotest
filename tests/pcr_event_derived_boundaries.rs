use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

#[test]
fn notary_value_uses_core_actor_id_and_rejects_full_did_spelling() {
    let actor_id = arkret_wire::DidCoreId::new("ak:did_core:web:notary.example").unwrap();
    let recovery_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:recovery.notary.example").unwrap();

    let single = serde_json::to_value(arkret_wire::NotaryValue::single_did(actor_id.clone()))
        .expect("single_did notary serializes");
    assert_eq!(single["actor_id"], actor_id.as_str());
    assert!(single.get("did").is_none());

    let mixed = serde_json::to_value(arkret_wire::NotaryValue::Mixed {
        actor_id,
        recovery_members: vec![recovery_id],
    })
    .expect("mixed notary serializes");
    assert_eq!(mixed["actor_id"], "ak:did_core:web:notary.example");
    assert!(mixed.get("did").is_none());

    for unregistered in [
        json!({"kind": "single_did", "did": "did:web:notary.example"}),
        json!({
            "kind": "mixed",
            "did": "did:web:notary.example",
            "recovery_members": ["ak:did_core:web:recovery.notary.example"]
        }),
    ] {
        assert!(serde_json::from_value::<arkret_wire::NotaryValue>(unregistered).is_err());
    }
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
    let missing = json!({
        "schema": "ak.schema.realm_genesis.v1",
        "purpose": "collaboration",
        "trust_domain": "ak:trust_domain:example.test",
        "schema_refs": ["ak.schema.realm.v1"],
        "reducer_profile": "ak.profile.reducer.core.v1",
        "digest_algorithm": "sha256",
        "security_class": "standard",
        "encryption_profile": "mls_rfc9420",
        "notary_profile": "single_did",
        "notary": {
            "kind": "single_did",
            "actor_id": "ak:did_core:webvh:z6mkfixture"
        },
        "capability_action_registry_digest": format!("sha256:{}", "a".repeat(64))
    });
    assert!(
        serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmGenesis>(
            missing
        )
        .is_err()
    );
}
