use anyhow::Result;
use arkret_models_collaboration::objects::media::{MediaIceConfigRequestBody, MediaIceMode};
use arkret_wire::{AccountId, ActorId, DeviceId, DidCoreId, RealmId};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, actor_core_id, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn webrtc_session_signal_strand_and_guards_work() -> Result<()> {
    let server = ArkretServer::spawn("rtc-media").await?;
    let alice_actor = actor_did_for_service_did(server.service_did(), "alice-rtc")?;
    let alice = server
        .demo_client(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let carol_actor = actor_did_for_service_did(server.service_did(), "carol-rtc")?;
    let carol = server
        .register_client(
            &carol_actor,
            "@carol-rtc",
            "ak:device:01904100-0000-7000-8000-000000000ca0",
        )
        .await?;

    let realm_id = alice.create_realm("RTC Media Realm").await?;
    let call_id = "ak:call:AbhvODyrIRCskAIoS9IXLjMfD-Zsr8lwDpiCU_zLR4it";
    let alice_core = actor_core_id(&alice.actor)?;
    let carol_core = actor_core_id(&carol.actor)?;

    expect_api_error(
        carol
            .post("/_arkret/self/rtc/ice-config")
            .json(&MediaIceConfigRequestBody {
                realm_id: RealmId::new(realm_id.clone())?,
                call_id: call_id.to_owned(),
                actor_id: account_actor(&carol, &carol_core)?,
                device_id: DeviceId::new(carol.device_id.clone())?,
                mode: MediaIceMode::P2p,
            }),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    expect_api_error(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "realm_id": realm_id,
                "call_id": "not-a-call-id",
                "actor_id": alice_core,
                "device_id": alice.device_id.as_str(),
                "mode": "p2p"
            }))),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    expect_api_error(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&MediaIceConfigRequestBody {
                realm_id: RealmId::new(realm_id.clone())?,
                call_id: call_id.to_owned(),
                actor_id: account_actor(&carol, &carol_core)?,
                device_id: DeviceId::new(alice.device_id.clone())?,
                mode: MediaIceMode::P2p,
            }),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    let ice = expect_json(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&MediaIceConfigRequestBody {
                realm_id: RealmId::new(realm_id.clone())?,
                call_id: call_id.to_owned(),
                actor_id: account_actor(&alice, &alice_core)?,
                device_id: DeviceId::new(alice.device_id.clone())?,
                mode: MediaIceMode::P2p,
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ice["realm_id"], realm_id);
    assert_eq!(ice["call_id"], call_id);
    assert_eq!(
        ice["actor_id"],
        serde_json::to_value(account_actor(&alice, &alice_core)?)?
    );
    assert_eq!(ice["device_id"], alice.device_id);
    assert_eq!(ice["ttl_seconds"], 300);
    assert_eq!(ice["refresh_lead_seconds"], 75);
    assert!(
        ice.get("turn_required").is_none(),
        "the default false value is omitted from the canonical response"
    );
    assert!(ice["issued_at"].is_string());
    assert!(
        ice.get("expires_at").is_none(),
        "the retired expires_at field must not re-enter the v1 ICE response"
    );
    assert!(ice["signature"].is_object());
    assert_eq!(ice["signature"]["signature_algorithm"], "Ed25519");
    assert!(
        ice["signature"]["kid"]
            .as_str()
            .unwrap()
            // soland signs the ICE config with the service's notary key
            // (`<service_id>#notary-key`); the spec allows any `#<key-id>`
            // fragment (ice-config-response.schema.json `kid`).
            .ends_with("#notary-key")
    );

    let ice_servers = ice["ice_servers"].as_array().unwrap();
    assert_eq!(ice_servers.len(), 2);
    assert_eq!(ice_servers[0]["urls"][0], "stun:stun.l.google.com:19302");
    let turn_server = &ice_servers[1];
    assert_eq!(
        turn_server["urls"][0],
        "turn:turn.soland.local:3478?transport=udp"
    );
    assert_eq!(turn_server["credential_type"], "password");
    let turn_username = turn_server["username"].as_str().unwrap();
    // soland's REST-style TURN username is `<expiry-unix>:<pairwise-pseudonym>`
    // where the pseudonym is `ak_pseudonym_call_<hex>` (webrtc-signaling.md
    // §4.1). There is no separate `pairwise_pseudonym` response field; the
    // pseudonym is carried in the username and must not leak the caller identity.
    let (expiry, pseudonym) = turn_username
        .split_once(':')
        .expect("turn username must be `<expiry>:<pseudonym>`");
    assert!(!expiry.is_empty() && expiry.chars().all(|c| c.is_ascii_digit()));
    assert!(pseudonym.starts_with("ak_pseudonym_call_"));
    assert!(!turn_username.contains("did:web"));
    assert!(!turn_username.contains("alice"));

    let turn_only = expect_json(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&MediaIceConfigRequestBody {
                realm_id: RealmId::new(realm_id.clone())?,
                call_id: "ak:call:AYVFZWhohYwHaEnPNmKhgMBK35WYy2igGfoeZIIOtwAy".to_owned(),
                actor_id: account_actor(&alice, &alice_core)?,
                device_id: DeviceId::new(alice.device_id.clone())?,
                mode: MediaIceMode::Turn,
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(turn_only["turn_required"], true);
    // In turn_required mode soland returns only the TURN server, carried in
    // `ice_servers` (there is no separate `turn_servers` response field).
    let turn_only_servers = turn_only["ice_servers"].as_array().unwrap();
    assert_eq!(turn_only_servers.len(), 1);
    assert!(
        turn_only_servers[0]["urls"][0]
            .as_str()
            .unwrap()
            .starts_with("turn:")
    );

    Ok(())
}

fn account_actor(client: &crate::harness::TestActorClient, principal_id: &str) -> Result<ActorId> {
    Ok(ActorId::account(AccountId::new(
        DidCoreId::new(principal_id)?,
        DidCoreId::new(client.service_id().to_owned())?,
    )))
}
