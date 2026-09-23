//! Retired selector endpoints must not reappear beside committed Event reads.

use anyhow::{Result, bail};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestServerGroup, expect_response};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn events_resolve_selector_budget_run() -> Result<()> {
    let group = TestServerGroup::single("retired-events-resolve-selectors").await?;
    let server = group.server(0);
    let actor_did = actor_did_for_service_did(server.service_did(), "retired-events-resolve")?;
    let client = server
        .register_client(
            &actor_did,
            "@retired-events-resolve",
            "ak:device:01904100-0000-7000-8000-00000000e501",
        )
        .await?;

    for path in [
        "/_arkret/self/events/resolve",
        "/_arkret/self/seals/resolve",
        "/_arkret/self/events/describe",
    ] {
        let response =
            expect_response(client.query(path).json(&json!({})), StatusCode::NOT_FOUND).await?;
        if response.status != StatusCode::NOT_FOUND {
            bail!("retired selector endpoint {path} is still admitted");
        }
    }
    Ok(())
}
