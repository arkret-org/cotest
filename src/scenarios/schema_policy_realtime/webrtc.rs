use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_api_error, expect_json};

pub async fn webrtc_session_signal_flow_and_guards_work() -> Result<()> {
    let server = ContrixServer::spawn("webrtc-signaling").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-webrtc.example", "@bob-webrtc", "dev_bob")
        .await?;
    let carol = server
        .register_client("did:web:carol-webrtc.example", "@carol-webrtc", "dev_carol")
        .await?;
    let dave = server
        .register_client("did:web:dave-webrtc.example", "@dave-webrtc", "dev_dave")
        .await?;

    let space_id = alice.create_space("Webrtc Space").await?;
    for member in [&bob, &carol] {
        alice.add_member(&space_id, member).await?;
    }

    expect_api_error(
        dave.post("/api/v1/webrtc/sessions").json(&json!({
            "realm_id": space_id,
            "participants": [bob.actor]
        })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let session = expect_json(
        alice.post("/api/v1/webrtc/sessions").json(&json!({
            "realm_id": space_id,
            "participants": [bob.actor],
            "ttl_ms": 90_000
        })),
        StatusCode::OK,
    )
    .await?;
    let session_id = session["session_id"].as_str().unwrap().to_owned();
    assert!(session_id.starts_with("cx:webrtc:"));
    assert_eq!(session["participants"].as_array().unwrap().len(), 2);

    expect_api_error(
        carol.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let initial = expect_json(
        bob.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::OK,
    )
    .await?;
    assert!(initial["events"].as_array().unwrap().is_empty());

    expect_api_error(
        bob.post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "offer",
                "payload": {"sdp": "v=0"},
                "proofs": [{"actor": alice.actor, "sig": "not-bob"}]
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let offer = expect_json(
        bob.post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "offer",
                "payload": {"sdp": "v=0"},
                "proofs": [{"actor": bob.actor, "sig": "signed-by-bob"}]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(offer["seq"], 1);
    assert_eq!(offer["next_cursor"], "1");

    let offer_events = expect_json(
        alice.get(&format!(
            "/api/v1/webrtc/sessions/{session_id}/signals?since=0&limit=1"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(offer_events["limited"], false);
    assert_eq!(offer_events["events"].as_array().unwrap().len(), 1);
    assert_eq!(offer_events["events"][0]["type"], "offer");
    assert_eq!(offer_events["events"][0]["sender"], bob.actor);

    let answer = expect_json(
        alice
            .post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "answer",
                "payload": {"sdp": "v=0-answer"},
                "proofs": [{"kid": format!("{}#dev", alice.actor), "sig": "signed-by-alice"}]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(answer["seq"], 2);

    let answer_events = expect_json(
        bob.get(&format!(
            "/api/v1/webrtc/sessions/{session_id}/signals?since=1"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(answer_events["events"].as_array().unwrap().len(), 1);
    assert_eq!(answer_events["events"][0]["type"], "answer");
    assert_eq!(answer_events["events"][0]["sender"], alice.actor);

    let closed = expect_json(
        alice.delete(&format!("/api/v1/webrtc/sessions/{session_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(closed["ok"], true);

    expect_api_error(
        bob.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}
