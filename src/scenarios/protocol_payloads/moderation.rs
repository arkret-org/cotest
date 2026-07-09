//! Phase 10 — `/_cokret/self/moderation/report` submission.

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
                // soland validates that the reported target exists; point at the
                // adapter message Event authored in the events/keys setup phase.
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000101",
                "target_ref": "ak:event:0196419b-0000-7000-8000-000000000001",
                "report_reason_code": "spam",
                "reporter": "did:web:alice.example"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "submitted");
    Ok(())
}
