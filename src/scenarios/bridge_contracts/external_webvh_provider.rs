//! coland's `did:webvh` provider discovery when an *external* provider is
//! configured.
//!
//! Coland is spawned with an unreachable external provider URL. The assertions
//! validate its current typed IdentityRegistry ServiceDescribe and the published
//! method allow-list and trust roots. A provider summary is not DID method
//! evidence, and this discovery test does not claim external resolution.
//!
//! The provider URL below is a placeholder that is never dialled.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{ArkretServer, expect_json};

const EXTERNAL_PROVIDER_URL: &str = "http://webvh-provider.cotest.local";

pub async fn external_webvh_provider_is_discoverable() -> Result<()> {
    let server = ArkretServer::spawn_with_env(
        "external-webvh-provider",
        &[
            ("COLAND_DID_RESOLVER_ALLOW_METHODS", "web,key,webvh"),
            ("COLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED", "0"),
            ("COLAND_EXTERNAL_WEBVH_PROVIDER_URL", EXTERNAL_PROVIDER_URL),
            ("COLAND_DEFAULT_WEBVH_PROVIDER_ID", "external.webvh"),
        ],
    )
    .await?;

    let describe = expect_json(
        server
            .http()
            .get(server.url("/_arkret/root/identity/describe")),
        StatusCode::OK,
    )
    .await?;
    let typed: arkret_models_discovery::ServiceDescribe = serde_json::from_value(describe.clone())?;
    typed.validate()?;
    assert_eq!(
        typed.service_kind,
        arkret_wire::ServiceKind::IdentityRegistry
    );
    assert_eq!(
        typed.supported_profiles,
        vec![arkret_wire::ProfileId::IDENTITY_REGISTRY_V1.to_owned()]
    );
    assert!(typed.supported_operation_bundles.iter().any(|bundle| {
        bundle == arkret_wire::OperationBundleDescriptor::IDENTITY_REGISTRY_DESCRIBE_V1
    }));
    let identity = &describe["x_coland_identity_registry"];
    assert!(
        identity["supported_did_methods"]
            .as_array()
            .expect("advertised DID methods")
            .iter()
            .any(|method| method.as_str() == Some("did:webvh"))
    );
    assert!(
        identity["resolver_allow_methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("webvh")),
        "did:webvh should be discoverable when an external provider is configured"
    );
    let trust_roots = identity["trust_roots"]
        .as_array()
        .expect("resolver policy trust_roots");
    assert!(
        trust_roots
            .iter()
            .any(local_trust_root_has_webvh_validation),
        "coland must publish its local identity trust root and webvh proof-validation policy: {describe}"
    );
    let external_root = trust_roots
        .iter()
        .find(|root| root["id"] == "external.webvh")
        .expect("external webvh trust root");
    assert_eq!(external_root["kind"], "external");
    assert_eq!(
        external_root["adapter_version"],
        arkret_models_identity::did_document::DID_WEBVH_V1_METHOD
    );
    assert_eq!(external_root["base_url"], EXTERNAL_PROVIDER_URL);
    assert!(
        external_root["expected_trust_domain"]
            .as_str()
            .is_some_and(|trust_domain| trust_domain.starts_with("ak:trust_domain:")),
        "external webvh trust root must bind the expected trust domain: {external_root}"
    );
    Ok(())
}

fn local_trust_root_has_webvh_validation(root: &Value) -> bool {
    root["kind"] == "local_identity_store"
        && root["proof_verification"]["controller_proof"] == "eddsa-jcs-2022"
        && root["proof_verification"]["webvh_log_chain"] == "required"
        && root["proof_verification"]["webvh_scid"] == "required"
        // coland cannot verify witness evidence, so it declares the quorum
        // policy fail-closed as `unsupported` instead of claiming enforcement.
        && root["proof_verification"]["webvh_witness_quorum"] == "unsupported"
}
