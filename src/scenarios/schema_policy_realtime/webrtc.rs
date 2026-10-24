use anyhow::Result;
use arkret_models_collaboration::objects::media::{MediaIceConfigurationRequestBody, MediaIceMode};
use arkret_wire::{AccountId, ActorId, DeviceId, DidCoreId, RealmId};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, actor_core_id, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn webrtc_session_signal_strand_and_guards_work() -> Result<()> {
    let server = ArkretServer::spawn("rtc-media").await?;
    let alice_actor = actor_did_for_service_did(server.service_did(), "alice-rtc")?;
    let alice = server
        .standard_client(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let carol_actor = actor_did_for_service_did(server.service_did(), "carol-rtc")?;
    let carol = server
        .standard_register_client(
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
            .json(&MediaIceConfigurationRequestBody {
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
                "actor_id": account_actor(&alice, &alice_core)?,
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
            .json(&MediaIceConfigurationRequestBody {
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
            .json(&MediaIceConfigurationRequestBody {
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
            // coland signs the ICE config with the service's notary key
            // (`<service_id>#notary-key`); the spec allows any `#<key-id>`
            // fragment (media-ice-configuration-response-body.schema.json `kid`).
            .ends_with("#notary-key")
    );

    let ice_servers = ice["ice_servers"].as_array().unwrap();
    assert_eq!(ice_servers.len(), 2);
    assert_eq!(ice_servers[0]["urls"][0], "stun:stun.l.google.com:19302");
    let turn_server = &ice_servers[1];
    assert_eq!(
        turn_server["urls"][0],
        "turn:turn.coland.local:3478?transport=udp"
    );
    assert_eq!(turn_server["credential_type"], "password");
    let turn_username = turn_server["username"].as_str().unwrap();
    // coland's REST-style TURN username is `<expiry-unix>:<pairwise-pseudonym>`
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

    // The same authenticated leg must receive independent signed credentials
    // for simultaneous requests, even before a Call has been established.
    let repeated = MediaIceConfigurationRequestBody {
        realm_id: RealmId::new(realm_id.clone())?,
        call_id: call_id.to_owned(),
        actor_id: account_actor(&alice, &alice_core)?,
        device_id: DeviceId::new(alice.device_id.clone())?,
        mode: MediaIceMode::P2p,
    };
    let issue = || {
        expect_json(
            alice.post("/_arkret/self/rtc/ice-config").json(&repeated),
            StatusCode::OK,
        )
    };
    let (a, b, c, d) = tokio::try_join!(issue(), issue(), issue(), issue())?;
    let (_, seed) = crate::harness::test_service_signing_key("rtc-media");
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let anchors = arkret_signatures::media::MediaServiceAnchors::new([(
        server.service_id().clone(),
        server.service_did().clone(),
    )])?
    .with_keys([(
        format!("{}#notary-key", server.service_did()),
        key.verifying_key(),
    )])?;
    let mut tags = std::collections::BTreeSet::new();
    let mut buckets = std::collections::BTreeMap::new();
    for raw in [&ice, &a, &b, &c, &d] {
        use base64::Engine as _;
        let outcome: arkret_models_collaboration::objects::media::MediaIceConfigurationResponseBody =
            serde_json::from_value(raw.clone())?;
        arkret_signatures::media::verify_ice_config_outcome(&outcome, &anchors)?;
        let username = outcome
            .ice_servers
            .iter()
            .find_map(|server| server.username.as_ref())
            .unwrap();
        let (expiry, tag) = username.split_once(':').unwrap();
        assert_eq!(
            expiry.parse::<i64>()?,
            outcome.issued_at.timestamp() + i64::from(outcome.ttl_seconds)
        );
        let tag = tag.strip_prefix("ak_pseudonym_call_").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(tag)?
                .len(),
            16
        );
        assert!(
            tags.insert(tag.to_owned()),
            "fresh issuance reused a TURN tag"
        );
        *buckets
            .entry(outcome.issued_at.timestamp().div_euclid(300))
            .or_insert(0usize) += 1;
    }
    assert!(
        buckets.values().any(|count| *count >= 2),
        "exercise repeated issuance inside one bucket"
    );

    let mut foreign_station = repeated.clone();
    foreign_station.actor_id = ActorId::account(AccountId::new(
        DidCoreId::new(alice_core.clone())?,
        DidCoreId::new("ak:did_core:web:other.example")?,
    ));
    expect_api_error(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&foreign_station),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;
    let mut foreign_device = repeated.clone();
    foreign_device.device_id = DeviceId::new(carol.device_id.clone())?;
    expect_api_error(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&foreign_device),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    let turn_only = expect_json(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&MediaIceConfigurationRequestBody {
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
    // In turn_required mode coland returns only the TURN server, carried in
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
