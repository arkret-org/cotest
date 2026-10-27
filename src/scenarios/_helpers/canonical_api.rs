//! Fail-closed canonical provisioning for migrated API-only deployment tests.

use anyhow::{Context, Result, ensure};
use cotest_test_support::provisioning::{DeploymentEndpoints, MockEmailInbox};

use crate::harness::{ArkretServer, CanonicalClientRequest, ClientSession, TestActorClient};

#[path = "canonical_pairing.rs"]
mod pairing;

pub struct CanonicalApiFixture {
    pub server: ArkretServer,
    pub client: TestActorClient,
    http: reqwest::Client,
    endpoints: DeploymentEndpoints,
    oidc_client_id: String,
}

impl CanonicalApiFixture {
    pub(crate) fn from_owned(
        server: ArkretServer,
        client: TestActorClient,
        http: reqwest::Client,
        endpoints: DeploymentEndpoints,
        oidc_client_id: String,
    ) -> Self {
        Self {
            server,
            client,
            http,
            endpoints,
            oidc_client_id,
        }
    }
    pub(crate) async fn issue_for_device(
        &self,
        client: &TestActorClient,
    ) -> Result<arkret_models_collaboration::session_grants::SessionGrantResponseBody> {
        pairing::issue_for_device(self, client).await
    }
    pub(crate) async fn refresh_for_device(
        &self,
        client: &TestActorClient,
    ) -> Result<arkret_models_collaboration::session_grants::SessionGrantResponseBody> {
        pairing::refresh_for_device(self, client).await
    }
    pub(crate) async fn prepare_pairing_request(
        &self,
    ) -> Result<(
        arkret_http_client::Client,
        arkret_identity::VerifiedSubmission<
            arkret_models_collaboration::device_pairing::AccountDevicePairRequestBody,
        >,
    )> {
        pairing::prepare_pairing_request(self).await
    }
    pub(crate) async fn recovery_candidate(
        &self,
    ) -> Result<(
        TestActorClient,
        arkret_http_client::Client,
        arkret_models_identity::InitialSessionGrantIntent,
        cotest_test_support::provisioning::AccountHandoff,
    )> {
        pairing::recovery_candidate(self).await
    }
    pub async fn pair_sibling(&self) -> Result<TestActorClient> {
        pairing::pair(self).await
    }
}

pub async fn fixture(label: &str) -> Result<CanonicalApiFixture> {
    let required = |name: &str| {
        std::env::var(name)
            .with_context(|| format!("{name} is required for the canonical API migration"))
    };
    let ca = required("COTEST_RUN_SCOPED_CA_PEM")?;
    let http = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(&ca)?)?)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let endpoints = DeploymentEndpoints {
        coauth_base_url: required("COTEST_COAUTH_BASE_URL")?,
        coland_base_url: required("COTEST_COLAND_BASE_URL")?,
        mock_email: Some(MockEmailInbox {
            base_url: required("COTEST_MOCK_EMAIL_BASE_URL")?,
        }),
    };
    let server = ArkretServer::attach(
        &endpoints.coland_base_url,
        &required("COTEST_COLAND_NOTARY_SIGNING_KEY")?,
        Some(std::path::Path::new(&ca)),
    )
    .await?;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let handle = format!("api-{label}-{suffix}");
    let device = format!(
        "ak:device:01904100-0000-7000-8000-{:012x}",
        suffix & 0xffff_ffff_ffff
    );
    let oidc_client_id = required("COTEST_OIDC_CLIENT_ID")?;
    let client = server
        .canonical_client(CanonicalClientRequest {
            http: &http,
            endpoints: &endpoints,
            oidc_client_id: &oidc_client_id,
            handle: &handle,
            password: "1amTester!",
            device_id: &device,
            display_name: &handle,
        })
        .await?;
    ensure!(
        matches!(client.session(), ClientSession::Canonical { .. })
            && client.dev_bearer().is_none(),
        "API migration requires a canonical client"
    );
    Ok(CanonicalApiFixture {
        server,
        client,
        http,
        endpoints,
        oidc_client_id,
    })
}
