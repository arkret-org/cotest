use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_api_error, expect_json};

pub async fn webrtc_session_signal_flow_and_guards_work() -> Result<()> {
    let server = CokretServer::spawn("webrtc-signaling").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let carol = server
        .register_client("did:web:carol-webrtc.example", "@carol-webrtc", "dev_carol")
        .await?;
    let dave = server
        .register_client("did:web:dave-webrtc.example", "@dave-webrtc", "dev_dave")
        .await?;

    let space_id = "ck:realm:0196419b-0000-7000-8000-000000000000";

    expect_api_error(
        dave.post("/api/v1/webrtc/sessions").json(&json!({
            "space_id": space_id,
            "participants": []
        })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let session = expect_json(
        alice.post("/api/v1/webrtc/sessions").json(&json!({
            "space_id": space_id,
            "participants": [],
            "ttl_ms": 90_000
        })),
        StatusCode::OK,
    )
    .await?;
    let session_id = session["session_id"].as_str().unwrap().to_owned();
    assert!(session_id.starts_with("ck:call:"));
    assert_eq!(session["participants"].as_array().unwrap().len(), 1);

    expect_api_error(
        carol.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let initial = expect_json(
        alice.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::OK,
    )
    .await?;
    assert!(initial["events"].as_array().unwrap().is_empty());

    expect_api_error(
        alice
            .post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "offer",
                "payload": {"sdp": "v=0"},
                "proofs": [{"actor": dave.actor, "sig": "not-alice"}]
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let signal_types = [
        "offer",
        "answer",
        "ice",
        "hangup",
        "reject",
        "mute_state",
        "media_state",
        "speaking",
        "focus_join",
        "focus_leave",
        "error",
        "device_change",
        "renegotiate",
    ];

    let first = expect_json(
        alice
            .post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": signal_types[0],
                "seq": 1,
                "payload": {"signal_index": 1, "sdp": "v=0"},
                "proofs": [{"actor": alice.actor, "sig": "signed-by-alice"}]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first["seq"], 1);
    assert_eq!(first["next_cursor"], "1");

    expect_api_error(
        alice
            .post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "answer",
                "seq": 1,
                "payload": {"signal_index": "rollback"},
                "proofs": [{"actor": alice.actor, "sig": "signed-by-alice"}]
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    expect_api_error(
        alice
            .post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "answer",
                "seq": 99,
                "payload": {"signal_index": "gap"},
                "proofs": [{"actor": alice.actor, "sig": "signed-by-alice"}]
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    for (idx, signal_type) in signal_types.iter().enumerate().skip(1) {
        let appended = expect_json(
            alice
                .post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
                .json(&json!({
                    "message_type": signal_type,
                    "seq": (idx + 1) as u64,
                    "payload": {
                        "signal_index": idx + 1,
                        "device_proof_required": true
                    },
                    "proofs": [{"actor": alice.actor, "sig": "signed-by-alice"}]
                })),
            StatusCode::OK,
        )
        .await?;
        assert_eq!(appended["seq"], (idx + 1) as u64);
        assert_eq!(appended["next_cursor"], (idx + 1).to_string());
    }

    let offer_events = expect_json(
        alice.get(&format!(
            "/api/v1/webrtc/sessions/{session_id}/signals?since=0&limit=20"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(offer_events["limited"], false);
    assert_eq!(
        offer_events["events"].as_array().unwrap().len(),
        signal_types.len()
    );
    assert_eq!(offer_events["events"][0]["type"], "offer");
    assert_eq!(offer_events["events"][0]["sender"], alice.actor);
    for (idx, signal_type) in signal_types.iter().enumerate() {
        let event = &offer_events["events"][idx];
        assert_eq!(event["seq"], (idx + 1) as u64);
        assert_eq!(event["type"], *signal_type);
        assert!(event["device_proof"].is_object());
    }

    let tail_events = expect_json(
        alice.get(&format!(
            "/api/v1/webrtc/sessions/{session_id}/signals?since=12"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(tail_events["events"].as_array().unwrap().len(), 1);
    assert_eq!(tail_events["events"][0]["type"], "renegotiate");
    assert_eq!(tail_events["events"][0]["seq"], 13);

    let closed = expect_json(
        alice.delete(&format!("/api/v1/webrtc/sessions/{session_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(closed["ok"], true);

    expect_api_error(
        alice.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}
