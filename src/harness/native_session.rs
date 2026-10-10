//! A native host session backed by the exact harness issuer record.
//! The ledger is an auth fixture, not evidence of Coauth grant issuance.

use anyhow::{Context, Result, ensure};
use garth::{
    AuthenticatedTransportFactory, SessionEngine, SessionGrantState, SessionTransportProvider,
};

use super::{ClientSession, TestActorClient};
use crate::scenarios::_helpers::bridge::{MockCoauthGrantLedger, MockCoauthIntrospectionServer};

#[derive(Clone)]
struct HostFactory {
    http: arkret_http_client::Client,
    issuer: MockCoauthGrantLedger,
    binding: arkret::StationConnectionBinding,
    credential: String,
}

impl AuthenticatedTransportFactory for HostFactory {
    type Transport = arkret_http_client::Client;

    fn build(&self, state: &SessionGrantState) -> garth::Result<Self::Transport> {
        let current = self
            .issuer
            .own_station_session_state(&self.credential, &self.binding.service_id)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if current != *state {
            return Err(garth::Error::Protocol(
                "native issuer session changed".into(),
            ));
        }
        Ok(self.http.clone())
    }

    fn validate_own_station_session(
        &self,
        state: &SessionGrantState,
        binding: &arkret::StationConnectionBinding,
    ) -> garth::Result<()> {
        if binding != &self.binding {
            return Err(garth::Error::Protocol(
                "native Station binding changed".into(),
            ));
        }
        self.build(state).map(|_| ())
    }
}

pub(super) async fn bind_standard_host(
    mut client: TestActorClient,
    issuer: &MockCoauthIntrospectionServer,
    station: &arkret_wire::DidCoreId,
    trust_domain: &arkret_wire::TrustDomainId,
    ca_pem: Option<&[u8]>,
) -> Result<TestActorClient> {
    // The harness independently selected this process origin and Station id.
    // This exercises public discovery shape/binding, not persistent UI admission.
    let roots = ca_pem
        .map(reqwest::Certificate::from_pem_bundle)
        .transpose()?
        .unwrap_or_default();
    let description = arkret_http_client::station_connection::fetch_station_description_with_roots(
        client.sdk.base_url(),
        true,
        &roots,
    )
    .await?;
    let binding = arkret::StationConnectionBinding::from_description(
        client.sdk.base_url(),
        &description,
        true,
    )?;
    ensure!(
        &binding.service_id == station && &binding.trust_domain == trust_domain,
        "selected Station identity differs from discovery"
    );
    let authority = binding
        .auth_metadata
        .account_authority
        .as_ref()
        .context("selected Station does not advertise its Account Authority")?;
    ensure!(
        authority.origin.as_str() == issuer.origin(),
        "selected Station advertises another Account Authority"
    );
    let ClientSession::Canonical { grant, .. } = &client.session else {
        anyhow::bail!("native host requires an issuer-ledger Standard grant");
    };
    let state = issuer.own_station_session_state(grant, station)?;
    ensure!(
        state
            .device_id
            .as_ref()
            .context("native grant has no device")?
            .as_str()
            == client.device_id,
        "native grant belongs to another device"
    );
    let factory = HostFactory {
        http: client.sdk.clone(),
        issuer: issuer.grant_ledger(),
        binding: binding.clone(),
        credential: grant.clone(),
    };
    let provider = SessionTransportProvider::new(
        SessionEngine::with_state(client.sdk.clone(), state),
        factory,
        Default::default(),
    );
    client.sdk = provider
        .own_station_result_client(client.sdk.clone(), binding)?
        .http_client()?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn carried_host_session_refuses_issuer_revocation_and_engine_replacement() -> Result<()> {
        let issuer = Arc::new(MockCoauthIntrospectionServer::spawn().await?);
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example")?;
        let principal = "ak:did_core:web:alice.example";
        let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        let grant = crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt(
            principal,
            device,
            station.as_str(),
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]);
        issuer.bind_founding_device_grant(
            &grant,
            principal,
            device,
            "fixture-authorize",
            &key.verifying_key(),
        )?;
        let state = issuer.own_station_session_state(&grant, &station)?;
        let http = arkret_http_client::Client::builder(url::Url::parse("http://localhost:1234/")?)
            .allow_insecure_localhost()
            .auth(arkret_http_client::Auth::Bearer(grant.clone()))
            .build()?;
        let binding = arkret::StationConnectionBinding {
            base_url: http.base_url().to_string(),
            service_id: station,
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:station.example")?,
            auth_metadata: arkret::AuthMetadata::minimal(),
        };
        let engine = SessionEngine::with_state(http.clone(), state.clone());
        let factory = HostFactory {
            http: http.clone(),
            issuer: issuer.grant_ledger(),
            binding: binding.clone(),
            credential: grant.clone(),
        };
        let provider = SessionTransportProvider::new(engine.clone(), factory, Default::default());
        let carried = provider
            .own_station_result_client(http.clone(), binding.clone())?
            .http_client()?;
        ensure!(carried.own_station_result_client()?.is_some());
        engine.clear_state();
        ensure!(carried.own_station_result_client().is_err());
        engine.replace_state(Some(state));
        ensure!(
            carried.own_station_result_client().is_err(),
            "ABA replacement recaptured the old client"
        );
        let renewed = provider
            .own_station_result_client(http, binding)?
            .http_client()?;
        ensure!(renewed.own_station_result_client()?.is_some());
        issuer.revoke_grant(&grant)?;
        ensure!(renewed.own_station_result_client().is_err());
        Ok(())
    }
}
