//! Additional members enrolled through the owned deployment's normal account flow.

use std::time::Duration;

use anyhow::{Context as _, Result};
use arkret_wire::AccountId;
use cotest_test_support::provisioning::DeploymentEndpoints;

use crate::harness::{ArkretServer, CanonicalClientRequest, TestActorClient};
use crate::scenarios::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment;

pub(crate) struct NativeAccountProvisioner {
    endpoints: DeploymentEndpoints,
    oidc_client_id: String,
}

impl NativeAccountProvisioner {
    pub(crate) fn new(deployment: &ActualAgentDeployment) -> Self {
        Self {
            endpoints: deployment.endpoints.clone(),
            oidc_client_id: deployment.oidc_client_id.clone(),
        }
    }

    pub(crate) async fn provision(
        &self,
        station: &ArkretServer,
        handle: &str,
        device: &str,
    ) -> Result<(TestActorClient, AccountId)> {
        let ca = station.tls_ca_path().context("owned Station CA absent")?;
        // Each Account needs its own browser cookie jar throughout OIDC onboarding.
        let http = reqwest::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?)
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(45))
            .build()?;
        let client = crate::harness::heap_future(|| {
            station.canonical_client(CanonicalClientRequest {
                http: &http,
                endpoints: &self.endpoints,
                oidc_client_id: &self.oidc_client_id,
                handle,
                password: "1amTester!",
                device_id: device,
                display_name: handle,
            })
        })
        .await?;
        let principal = client
            .principal
            .as_ref()
            .context("native member custody absent")?;
        let account = AccountId::new(principal.core_id.clone(), station.service_id().clone());
        Ok((client, account))
    }
}
