//! Phase 10 — `/api/v1/moderation/report` queueing.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json};

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    let report = expect_json(
        server
            .http()
            .post(server.url("/api/v1/moderation/report"))
            .bearer_auth(token)
            .json(&json!({
                "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
                "target_ref": "cx:event:demo",
                "reason": "spam",
                "reporter": "did:web:alice.example"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "queued");
    Ok(())
}
