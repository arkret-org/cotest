//! Phase 10 — `/_cokret/self/moderation/report` queueing.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_json};

pub async fn run(server: &CokretServer, token: &str) -> Result<()> {
    let report = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/moderation/report"))
            .bearer_auth(token)
            .json(&json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "target_ref": "ck:event:demo",
                "reason": "spam",
                "reporter": "did:web:alice.example"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "queued");
    Ok(())
}
