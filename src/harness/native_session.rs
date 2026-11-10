//! Native host sessions retain their authenticated registration or issuer source.
//! The mock ledger remains an auth fixture, not evidence of Coauth grant issuance.

use anyhow::{Context, Result, ensure};
use garth::{
    AuthenticatedTransportFactory, SessionEngine, SessionGrantState, SessionTransportProvider,
};

use super::{ClientSession, TestActorClient};
use crate::scenarios::_helpers::bridge::{MockCoauthGrantLedger, MockCoauthIntrospectionServer};

#[derive(Clone)]
pub(super) struct LocalSessionInvalidator {
    engine: SessionEngine<arkret_http_client::Client>,
}

impl LocalSessionInvalidator {
    pub(super) fn invalidate(&self) {
        self.engine.clear_state();
    }

    pub(super) fn remaining(&self) -> Result<std::time::Duration> {
        self.engine
            .current_state()
            .context("fixture native session source is inactive")?
            .expires_at
            .signed_duration_since(chrono::Utc::now())
            .to_std()
            .context("fixture native issuer record is expired")
    }

    pub(super) fn remaining_for(
        &self,
        source: &arkret_http_client::own_station_results::OwnStationStateClient,
    ) -> Result<std::time::Duration> {
        let before = self.engine.own_station_snapshot(source.binding())?;
        ensure!(
            &before == source.session()?,
            "fixture lease belongs to another captured source"
        );
        let remaining = self.remaining()?;
        ensure!(
            self.engine.own_station_snapshot(source.binding())? == before,
            "fixture lease source changed while reading its remaining lifetime"
        );
        source.check_session()?;
        Ok(remaining)
    }
}

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

async fn discover_host_binding(
    client: &TestActorClient,
    station: &arkret_wire::DidCoreId,
    trust_domain: &arkret_wire::TrustDomainId,
    authority_origin: &str,
    ca_pem: Option<&[u8]>,
) -> Result<arkret::StationConnectionBinding> {
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
        .authentication_metadata
        .account_authority
        .as_ref()
        .context("selected Station does not advertise its Account Authority")?;
    ensure!(
        authority.origin.as_str() == authority_origin,
        "selected Station advertises another Account Authority"
    );
    Ok(binding)
}

pub(super) async fn bind_standard_host(
    mut client: TestActorClient,
    issuer: &MockCoauthIntrospectionServer,
    station: &arkret_wire::DidCoreId,
    trust_domain: &arkret_wire::TrustDomainId,
    ca_pem: Option<&[u8]>,
) -> Result<TestActorClient> {
    let binding =
        discover_host_binding(&client, station, trust_domain, &issuer.origin(), ca_pem).await?;
    let ClientSession::Canonical { grant, .. } = &client.session else {
        anyhow::bail!("native host requires an issuer-ledger Standard grant");
    };
    let state = issuer.own_station_session_state(grant, station)?;
    if let Some(device) = &state.device_id {
        ensure!(
            device.as_str() == client.device_id,
            "native grant belongs to another device"
        );
    } else {
        ensure!(
            client.principal.is_none()
                && arkret::project_did_to_core_id(&arkret_wire::Did::new(client.actor.clone())?)?
                    == state.account_id.principal_id,
            "Agent host belongs to another issuer-bound principal"
        );
    }
    let factory = HostFactory {
        http: client.sdk.clone(),
        issuer: issuer.grant_ledger(),
        binding: binding.clone(),
        credential: grant.clone(),
    };
    let engine = SessionEngine::with_state(client.sdk.clone(), state);
    let provider = SessionTransportProvider::new(engine.clone(), factory, Default::default());
    client.sdk = provider
        .own_station_result_client(client.sdk.clone(), binding)?
        .http_client()?;
    client.native_session_invalidator = Some(LocalSessionInvalidator { engine });
    Ok(client)
}

/// Called only after the real Account Authority registration and its receipts
/// have been verified. The engine owns this local host lifetime; remote issuer
/// validity remains enforced by the real DPoP-authenticated HTTP operations.
pub(super) async fn bind_registered_host(
    mut client: TestActorClient,
    state: SessionGrantState,
    station: &arkret_wire::DidCoreId,
    trust_domain: &arkret_wire::TrustDomainId,
    authority_origin: &str,
    ca_pem: Option<&[u8]>,
) -> Result<TestActorClient> {
    let binding =
        discover_host_binding(&client, station, trust_domain, authority_origin, ca_pem).await?;
    let principal = client
        .principal
        .as_ref()
        .context("registered Device custody absent")?;
    ensure!(
        state.account_id == arkret::AccountId::new(principal.core_id.clone(), station.clone())
            && state.device_id.as_ref() == Some(&principal.device_id)
            && state.audience_id == *station
            && state.grant_jwt == client.session.credential(),
        "registered host differs from the authenticated Account, Device or grant"
    );
    let (http, engine) = cotest_test_support::session::bind_registered_host_source(
        client.sdk.clone(),
        state,
        binding,
    )?;
    client.sdk = http;
    client.native_session_invalidator = Some(LocalSessionInvalidator { engine });
    Ok(client)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn published_reauthentication_invalidates_only_the_old_local_source() -> Result<()> {
        let issuer = MockCoauthIntrospectionServer::spawn().await?;
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example")?;
        let principal = "ak:did_core:web:alice.example";
        let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]);
        let first = crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt(
            principal,
            device,
            station.as_str(),
        );
        let (unsigned, _) = first.rsplit_once('.').context("fixture signature")?;
        let second = format!(
            "{unsigned}.{}",
            arkret_canonical::base64url_encode([0x53; 64])
        );
        let bind = |credential: &str| -> Result<_> {
            issuer.bind_founding_device_grant(
                credential,
                principal,
                device,
                "fixture-authorize",
                &key.verifying_key(),
            )?;
            let state = issuer.own_station_session_state(credential, &station)?;
            let http =
                arkret_http_client::Client::builder(url::Url::parse("http://localhost:1234/")?)
                    .allow_insecure_localhost()
                    .auth(arkret_http_client::Auth::Bearer(credential.to_owned()))
                    .build()?;
            let binding = arkret::StationConnectionBinding {
                base_url: http.base_url().to_string(),
                service_id: station.clone(),
                trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:station.example")?,
                authentication_metadata: arkret::AuthenticationMetadata::minimal(),
            };
            let engine = SessionEngine::with_state(http.clone(), state.clone());
            let provider = SessionTransportProvider::new(
                engine.clone(),
                HostFactory {
                    http: http.clone(),
                    issuer: issuer.grant_ledger(),
                    binding: binding.clone(),
                    credential: credential.to_owned(),
                },
                Default::default(),
            );
            Ok((
                provider
                    .own_station_result_client(http, binding)?
                    .http_client()?,
                LocalSessionInvalidator { engine },
                state,
            ))
        };
        let (old, old_source, old_record) = bind(&first)?;
        let old_copy = old.clone();
        let (fresh, fresh_source, fresh_record) = bind(&second)?;
        ensure!(old_record.grant_id != fresh_record.grant_id);
        ensure!(
            old_record.account_id == fresh_record.account_id
                && old_record.device_id == fresh_record.device_id
        );
        let fresh_bound = fresh.own_station_result_client()?.context("fresh source")?;
        ensure!(
            old_source.remaining_for(&fresh_bound).is_err(),
            "an old invalidator supplied a new client's lease"
        );
        ensure!(!fresh_source.remaining_for(&fresh_bound)?.is_zero());
        let published = Arc::new(std::sync::Mutex::new(fresh));
        old_source.invalidate();
        ensure!(
            old.own_station_result_client().is_err()
                && old_copy.own_station_result_client().is_err()
        );
        ensure!(old_source.remaining().is_err());
        ensure!(
            published
                .lock()
                .expect("published fixture client")
                .own_station_result_client()?
                .is_some()
        );
        ensure!(!fresh_source.remaining()?.is_zero());
        ensure!(
            issuer.own_station_session_state(&first, &station)? == old_record,
            "local invalidation changed the old issuer record or expiry"
        );
        issuer.set_grant_expiry(&second, chrono::Utc::now() - chrono::Duration::seconds(1))?;
        ensure!(
            published
                .lock()
                .expect("published fixture client")
                .own_station_result_client()
                .is_err()
        );
        ensure!(fresh_source.remaining_for(&fresh_bound).is_err());
        Ok(())
    }

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
            authentication_metadata: arkret::AuthenticationMetadata::minimal(),
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
