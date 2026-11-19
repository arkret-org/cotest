//! CT-6 — Joint service smoke scenario.
//!
//! Verifies the [`JointServiceStack`] bootstrap can spin up coland + coauth +
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

use std::time::Duration;

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
        .coland
        .http()
        .get(stack.coland.base_url().join("/_arkret/describe")?)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    description.validate()?;
    anyhow::ensure!(
        description.service_id == *stack.coland.service_id()
            && arkret::project_did_to_core_id(&description.service_resolution.did)?
                == description.service_id,
        "owning Station Describe returned a different service identity"
    );
    coauth
        .wait_for_owning_station(Duration::from_secs(30))
        .await
}
