use arkret_http_client::mimi_directory::{MimiDirectoryAuthority, OwnStationProviderDirectory};
use arkret_models_collaboration::objects::interop::ProviderDirectory;

use super::*;

pub(super) async fn read(server: &ArkretServer) -> Result<OwnStationProviderDirectory> {
    // The harness has already accepted this Station's TLS/service identity.
    // Exercise the ordinary client boundary without fetching remote DID history.
    let http = arkret_http_client::Client::builder(server.base_url())
        .http_client(std::ops::Deref::deref(&server.http()).clone())
        .auth(arkret_http_client::Auth::Dpop(
            arkret_http_client::DpopAuth::with_dpop_token("must-not-leak", |_| {
                panic!("public directory must not sign an account request")
            }),
        ))
        .build()?;
    let description = http.describe().await?;
    let binding = arkret_models_discovery::StationConnectionBinding::from_description(
        &server.base_url(),
        &description,
        true, // Only the separately configured loopback Account Authority mock uses HTTP.
    )?;
    ensure!(
        &binding.service_id == server.service_id(),
        "directory Station identity substitution"
    );
    let verified = http
        .mimi_provider_directory_from_own_station(
            &binding,
            None,
            &["notify".into()],
            chrono::Duration::minutes(5),
            arkret_http_client::mimi_directory::OutboundPolicy::local_development(),
        )
        .await?;
    ensure!(
        verified.station_binding() == &binding,
        "directory own Station result binding drift"
    );
    ensure!(
        verified
            .endpoint("consent")
            .context("consent route")?
            .path()
            == "/_arkret/open/mimi/consent/request",
        "directory root-relative route drift"
    );

    // Independently consume the current real service assertion document. This
    // matrix tests the directory proof, not external-provider trust bootstrap.
    let current = http.open_service_resolution(server.service_id()).await?;
    arkret_identity::verify_authenticated_service_resolution_history(
        &current,
        server.service_id(),
        chrono::Utc::now(),
    )?;
    let authority = MimiDirectoryAuthority::new(
        server.service_id().clone(),
        current.normalized_did_document,
        server.url("/_arkret/open/mimi").parse()?,
        chrono::Duration::minutes(5),
    )?
    .with_egress_policy(arkret_http_client::mimi_directory::OutboundPolicy::local_development());
    let provider = verified.directory().mimi.provider_id.clone();
    let direct = http
        .mimi_provider_directory(&authority, Some(&provider), &["notify".into()])
        .await?;
    let original = direct.directory().clone();
    let sign = |mut value: ProviderDirectory| -> Result<ProviderDirectory> {
        value.proof.0.payload_digest = value.payload_digest()?;
        value.proof.0.jws = arkret_signatures::sign_ed25519_detached_jws(
            &server.federation_signing_key()?,
            &value.proof_binding_bytes()?,
        )?;
        Ok(value)
    };
    let refuse = |value: ProviderDirectory| -> Result<()> {
        ensure!(
            authority
                .verify(value, Some(&provider), &[], chrono::Utc::now())
                .is_err(),
            "invalid real provider directory accepted"
        );
        Ok(())
    };
    let mut value = original.clone();
    value.proof.0.jws = "eyJhbGciOiJFZDI1NTE5In0..AA".into();
    refuse(value)?;
    let mut value = original.clone();
    value.proof.0.jws = arkret_signatures::sign_ed25519_detached_jws(
        &server.federation_signing_key()?,
        &value.unsigned_projection_bytes()?,
    )?;
    refuse(value)?;
    let mut value = original.clone();
    value.proof.0.created_at += chrono::Duration::seconds(1);
    refuse(value)?;
    for seconds in [-301, 60] {
        let mut value = original.clone();
        value.proof.0.created_at = chrono::Utc::now() + chrono::Duration::seconds(seconds);
        refuse(sign(value)?)?;
    }
    for field in [
        "endpoints",
        "features",
        "mls_cipher_suites",
        "content_profiles",
        "room_policy_components",
    ] {
        let mut value = serde_json::to_value(&original)?;
        value["mimi"][field] = json!([]);
        refuse(sign(serde_json::from_value(value)?)?)?;
    }
    for path in [
        "//other.example/path",
        "/a/../b",
        "/a/%2e%2e/b",
        "/a/%2F/b",
        "/a/%5c/b",
        "/a?b",
        "/a#b",
    ] {
        let mut value = original.clone();
        value.mimi.endpoints[0].relative_path = path.into();
        refuse(sign(value)?)?;
    }
    let mut value = original.clone();
    value.mimi.provider_id =
        arkret_wire::MimiUri::new("mimi://other.example").map_err(anyhow::Error::msg)?;
    refuse(sign(value)?)?;
    let mut value = original.clone();
    value.service_id = arkret_wire::DidCoreId::new("ak:did_core:web:other.example")?;
    refuse(sign(value)?)?;
    let mut value = original.clone();
    value.mimi.base_url = "https://other.example/_arkret/open/mimi".into();
    refuse(sign(value)?)?;
    let mut value = original.clone();
    value.mimi.extra.insert(
        "endpoint_override".into(),
        json!({"consent":"https://other.example"}),
    );
    let inert = authority.verify(value, Some(&provider), &[], chrono::Utc::now())?;
    ensure!(
        inert.directory().mimi.extra.is_empty()
            && inert.endpoint("consent") == direct.endpoint("consent"),
        "unsigned extension changed a verified route"
    );
    eprintln!(
        "MIMI directory: real TLS producer/SDK receiver and own-Station read verified; 20 signed/proof/path refusals; unknown extensions inert; root-relative routes bound"
    );
    Ok(verified)
}
