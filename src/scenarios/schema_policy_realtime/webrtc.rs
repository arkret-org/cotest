use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_api_error, expect_json};

pub async fn webrtc_session_signal_strand_and_guards_work() -> Result<()> {
    let server = CokretServer::spawn("rtc-media").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let carol = server
        .register_client(
            "did:web:carol-rtc.example",
            "@carol-rtc",
            "ck:device:01904100-0000-7000-8000-000000000ca0",
        )
        .await?;

    let realm_id = alice.create_realm("RTC Media Realm").await?;
    let call_id = "ck:call:01964137-0000-7000-8000-000000000001";

    expect_api_error(
        carol.post("/_cokret/self/rtc/ice-config").json(&json!({
            "realm_id": realm_id,
            "call_id": call_id,
            "actor_id": carol.actor.as_str(),
            "device_id": carol.device_id.as_str(),
            "mode": "p2p"
        })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    expect_api_error(
        alice.post("/_cokret/self/rtc/ice-config").json(&json!({
            "realm_id": realm_id,
            "call_id": "not-a-call-id",
            "actor_id": alice.actor.as_str(),
            "device_id": alice.device_id.as_str(),
            "mode": "p2p"
        })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    expect_api_error(
        alice.post("/_cokret/self/rtc/ice-config").json(&json!({
            "realm_id": realm_id,
            "call_id": call_id,
            "actor_id": carol.actor.as_str(),
            "device_id": alice.device_id.as_str(),
            "mode": "p2p"
        })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let ice = expect_json(
        alice.post("/_cokret/self/rtc/ice-config").json(&json!({
            "realm_id": realm_id,
            "call_id": call_id,
            "actor_id": alice.actor.as_str(),
            "device_id": alice.device_id.as_str(),
            "mode": "p2p"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ice["realm_id"], realm_id);
    assert_eq!(ice["call_id"], call_id);
    assert_eq!(ice["actor_id"], alice.actor);
    assert_eq!(ice["device_id"], alice.device_id);
    assert_eq!(ice["ttl_seconds"], 300);
    assert_eq!(ice["refresh_lead_seconds"], 75);
    assert_eq!(ice["force_turn"], false);
    assert!(ice["issued_at"].is_string());
    assert!(ice["expires_at"].is_string());
    assert!(ice["signature"].is_object());
    assert_eq!(ice["signature"]["alg"], "EdDSA");
    assert_eq!(
        ice["signature"]["signature_input"],
        // Spec ice-config-response.schema.json fixes this domain-separation
        // label to `ck.media.ice_config.v1`.
        "ck.media.ice_config.v1"
    );
    assert!(
        ice["signature"]["kid"]
            .as_str()
            .unwrap()
            // soland signs the ICE config with the service's notary key
            // (`<service_did>#notary-key`); the spec allows any `#<key-id>`
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
    // where the pseudonym is `ck_pseudonym_call_<hex>` (webrtc-signaling.md
    // §4.1). There is no separate `pairwise_pseudonym` response field; the
    // pseudonym is carried in the username and must not leak the caller identity.
    let (expiry, pseudonym) = turn_username
        .split_once(':')
        .expect("turn username must be `<expiry>:<pseudonym>`");
    assert!(!expiry.is_empty() && expiry.chars().all(|c| c.is_ascii_digit()));
    assert!(pseudonym.starts_with("ck_pseudonym_call_"));
    assert!(!turn_username.contains("did:web"));
    assert!(!turn_username.contains("alice"));

    let turn_only = expect_json(
        alice.post("/_cokret/self/rtc/ice-config").json(&json!({
            "realm_id": realm_id,
            "call_id": "ck:call:01964137-0000-7000-8000-000000000002",
            "actor_id": alice.actor.as_str(),
            "device_id": alice.device_id.as_str(),
            "mode": "turn"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(turn_only["force_turn"], true);
    // In force_turn mode soland returns only the TURN server, carried in
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
