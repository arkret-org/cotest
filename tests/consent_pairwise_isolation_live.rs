//! Local negative conformance for the retired minimal-metadata Realm profile
//! and unregistered Consent peers; full Account ActorIds stay isolated.

use anyhow::Result;
#[tokio::test]
async fn retired_pairwise_profile_rejected_and_peer_identity_isolated() -> Result<()> {
    cotest::scenarios::consent_pairwise_isolation_live::run_consent_pairwise_isolation_live().await
}
