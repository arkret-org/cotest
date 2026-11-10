//! Local host lifetime for an independently verified registration outcome.
//! Real issuer validity is enforced by the actual DPoP-authenticated HTTP calls.

use anyhow::{Result, ensure};
use garth::{
    AuthenticatedTransportFactory, SessionEngine, SessionGrantState, SessionTransportProvider,
};

#[derive(Clone)]
struct RegisteredHostFactory {
    http: arkret_http_client::Client,
    accepted: SessionGrantState,
    binding: arkret::StationConnectionBinding,
}

impl AuthenticatedTransportFactory for RegisteredHostFactory {
    type Transport = arkret_http_client::Client;

    fn build(&self, state: &SessionGrantState) -> garth::Result<Self::Transport> {
        if state != &self.accepted {
            return Err(garth::Error::Protocol(
                "registered host session changed".into(),
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
                "registered Station binding changed".into(),
            ));
        }
        self.build(state).map(|_| ())
    }
}

/// Call only after verifying the real registration receipts, key custody and
/// independently discovered Station/Account Authority binding. This adapter
/// retains those accepted inputs; it does not issue a grant or infer authority.
pub fn bind_registered_host_source(
    http: arkret_http_client::Client,
    state: SessionGrantState,
    binding: arkret::StationConnectionBinding,
) -> Result<(
    arkret_http_client::Client,
    SessionEngine<arkret_http_client::Client>,
)> {
    ensure!(
        state.account_id.station_id == binding.service_id
            && state.audience_id == binding.service_id
            && state.device_id.is_some(),
        "registered native host belongs to another Station or Device branch"
    );
    let factory = RegisteredHostFactory {
        http: http.clone(),
        accepted: state.clone(),
        binding: binding.clone(),
    };
    let engine = SessionEngine::with_state(http.clone(), state);
    let provider = SessionTransportProvider::new(engine.clone(), factory, Default::default());
    let http = provider
        .own_station_result_client(http, binding)?
        .http_client()?;
    Ok((http, engine))
}
