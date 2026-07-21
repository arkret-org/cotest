//! Phase 10 — `/_arkret/self/moderation/report` submission.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, expect_json};

pub async fn run(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
    target_event_id: &str,
) -> Result<()> {
    let report = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/moderation/report"))
            .bearer_auth(token)
            .json(&json!({
                // soland validates that the reported target exists; point at the
                // adapter message Event authored in the events/keys setup phase.
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000101",
                "target_ref": target_event_id,
                "report_reason_code": "spam",
                "reporter": actor_id
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "submitted");
    Ok(())
}
