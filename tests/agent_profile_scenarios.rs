//! P4-A — integration entrypoints for the 4 personal-agent conformance
//! profiles. Each test drives an SDK-pure `..._run()` function; live-
//! server variants are deferred to P5 (gated on soland P2-impl reducer
//! wiring).

use cotest::scenarios::agent_auth::scaffold::agent_auth_run;
use cotest::scenarios::agent_delegation_policy::scaffold::agent_delegation_policy_run;
use cotest::scenarios::agent_sidecar::scaffold::agent_sidecar_run;
use cotest::scenarios::personal_agent_provisioning::scaffold::personal_agent_provisioning_run;

#[tokio::test]
async fn personal_agent_provisioning_profile() {
    personal_agent_provisioning_run()
        .await
        .expect("personal_agent_provisioning scenario");
}

#[tokio::test]
async fn agent_auth_profile() {
    agent_auth_run().await.expect("agent_auth scenario");
}

#[tokio::test]
async fn agent_delegation_policy_profile() {
    agent_delegation_policy_run()
        .await
        .expect("agent_delegation_policy scenario");
}

#[tokio::test]
async fn agent_sidecar_profile() {
    agent_sidecar_run().await.expect("agent_sidecar scenario");
}
