//! CT-6 — Joint service smoke scenario.
//!
//! Verifies the [`JointServiceStack`] bootstrap can spin up soland + coauth +
//! flagon together and each service answers `/health` with 2xx.
//!
//! Marked `#[ignore]` at the test-entrypoint level because the full stack
//! needs: docker (for coauth's ephemeral postgres), sibling `coauth.exe`,
//! sibling `flagon.exe`, AND a `DATABASE_URL` pointing at a reachable
//! Postgres for flagon. Operators who have all of those in place can run:
//!
//!   cargo test --test _bootstrap_smoke joint_service_smoke -- --ignored
//!
//! When run with the prereqs in place the test boots the stack and asserts
//! every service is healthy; without them it bails with a descriptive
//! message naming the missing piece.
//!
//! [`JointServiceStack`]: crate::scenarios::_helpers::joint_service_bootstrap::JointServiceStack

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use crate::scenarios::_helpers::joint_service_bootstrap::{JointServiceConfig, bootstrap_required};

/// CT-6 joint service smoke probe. Boots the full stack, calls
/// `assert_healthy` on every service, then drops everything in LIFO order.
pub async fn joint_service_smoke_run() -> Result<()> {
    let config = JointServiceConfig::new("ct6-smoke");
    let stack = bootstrap_required(config).await?;
    stack.assert_healthy().await?;
    let coauth = stack
        .coauth
        .as_ref()
        .ok_or_else(|| anyhow!("joint service stack omitted coauth"))?;

    // Account Authority is an internal Station responsibility, without a
    // separate Service DID (service-surface §2.7). Its owning Station exposes
    // the protocol Describe; the component exposes its real readiness state.
    let description: arkret::ServiceDescribe = stack
        .soland
        .http()
        .get(stack.soland.base_url().join("/_arkret/describe")?)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    description.validate()?;
    anyhow::ensure!(
        description.service_id == *stack.soland.service_id()
            && arkret::project_did_to_core_id(&description.service_resolution.did)?
                == description.service_id,
        "owning Station Describe returned a different service identity"
    );
    // This is the exact name installed by PreparedCoauth::spawn_for_station;
    // the name is a deployment label, not an independently claimed DID.
    wait_for_account_authority_ready(
        &format!("{}/readyz", coauth.internal_base_url),
        &coauth.health_url(),
        "cotest-soland",
    )
    .await?;
    Ok(())
}

async fn wait_for_account_authority_ready(
    ready_url: &str,
    health_url: &str,
    owning_station: &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let response = client.get(ready_url).send().await?;
        if response.status().is_success() {
            let body: serde_json::Value = response.json().await?;
            anyhow::ensure!(
                body["ok"] == true
                    && body["service"] == "coauth"
                    && body["component_role"] == "station_account_authority"
                    && body["owning_station"] == owning_station
                    && body["station_trust"] == "ready",
                "Coauth readiness did not confirm the configured owning Station: {body}"
            );
            return Ok(());
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if Instant::now() >= deadline {
            let health = client.get(health_url).send().await?.text().await?;
            return Err(anyhow!(
                "Coauth Account Authority did not become ready within 30 seconds; last response: {status}: {body}; health: {health}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
