use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

#[test]
fn notary_value_uses_core_actor_id_and_rejects_did_spelling() {
    let actor_id = arkret_wire::DidCoreId::new("ak:did_core:web:notary.example").unwrap();

    let notary = cotest::fixture_notary_configuration(actor_id.clone());
    let authority = serde_json::to_value(notary).expect("notary authority serializes");
    assert_eq!(
        authority["signer"]["actor_id"],
        json!(arkret_wire::ActorId::service(actor_id.clone()))
    );
    assert_eq!(authority["max_clock_error_ms"], json!(0));
    assert!(authority["signer"].get("did").is_none());
    assert!(authority.get("kind").is_none());
    assert!(authority.get("fault_tolerance").is_none());

    let missing_signer = json!({"max_clock_error_ms": 0});
    assert!(serde_json::from_value::<arkret_wire::NotaryValue>(missing_signer).is_err());
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
    let notary = serde_json::to_value(cotest::fixture_notary_configuration(
        arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
    ))
    .unwrap();
    let missing = json!({
        "schema": "ak.schema.realm_genesis.v1",
        "purpose": "collaboration",
        "trust_domain": "ak:trust_domain:example.test",
        "schema_refs": ["ak.schema.realm.v1"],
        "reducer_profile": "ak.profile.reducer.core.v1",
        "digest_algorithm": "sha256",
        "security_class": "standard",
        "encryption_profile": "mls_rfc9420",
        "notary": notary
    });
    assert!(
        serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmGenesis>(
            missing
        )
        .is_err()
    );
}
