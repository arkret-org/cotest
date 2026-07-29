//! CT-6 — Four-service joint smoke scenario.
//!
//! Verifies the [`FourServiceStack`] bootstrap can spin up soland + coauth +
//! starid + teabay together and each service answers `/health` with 2xx.
//!
//! Marked `#[ignore]` at the test-entrypoint level because the full stack
//! needs: docker (for coauth's ephemeral postgres), sibling `coauth.exe`,
//! sibling `starid.exe`, sibling `teabay.exe`, AND a `DATABASE_URL`
//! pointing at a reachable Postgres for teabay. Operators who have all of
//! those in place can run:
//!
//!   cargo test --test _bootstrap_smoke four_service_smoke -- --ignored
//!
//! When run with the prereqs in place the test boots the stack and asserts
//! every service is healthy; without them it bails with a descriptive
//! message naming the missing piece.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use crate::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, bootstrap_required};

/// CT-6 four-service smoke probe. Boots the full stack, calls
/// `assert_healthy` on every service, then drops everything in LIFO order.
pub async fn four_service_smoke_run() -> Result<()> {
    let config = FourServiceConfig::new("ct6-smoke");
    let stack = bootstrap_required(config).await?;
    stack.assert_healthy().await?;
    let coauth_base = stack
        .coauth_base_url()
        .ok_or_else(|| anyhow!("four-service stack omitted coauth"))?;
    let coauth_health = stack
        .coauth
        .as_ref()
        .ok_or_else(|| anyhow!("four-service stack omitted coauth"))?
        .health_url();
    wait_for_coauth_service_identity(coauth_base, &coauth_health).await?;
    Ok(())
}

async fn wait_for_coauth_service_identity(base_url: &str, health_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let response = client
            .get(format!(
                "{}/_arkret/describe",
                base_url.trim_end_matches('/')
            ))
            .send()
            .await?;
        if response.status().is_success() {
            let body: serde_json::Value = response.json().await?;
            let authority = body
                .pointer("/auth_metadata/account_authority/enrollment_authority_did")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| anyhow!("coauth describe omitted enrollment authority DID"))?;
            arkret_identifiers::Did::new(authority.to_owned())
                .map_err(|error| anyhow!("coauth enrollment authority DID is invalid: {error}"))?;
            return Ok(());
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if Instant::now() >= deadline {
            let health = client.get(health_url).send().await?.text().await?;
            return Err(anyhow!(
                "coauth service identity did not become ready within 30 seconds; last response: {status}: {body}; health: {health}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
