//! coland's `did:webvh` provider discovery when an *external* provider is
//! configured.
//!
//! Nothing here starts an external service: coland is spawned pointing at an
//! unreachable provider URL, and the assertions are entirely about what
//! coland's own `/_arkret/root/identity/describe` publishes in the
//! `x_coland_identity_registry` extension — default provider id, provider
//! entry, resolver allow-list, and trust roots (including its local identity
//! store's webvh proof-validation policy).
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
    let identity = &describe["x_coland_identity_registry"];
    let did_webvh = &identity["did_webvh"];
    assert_eq!(did_webvh["enabled"], true);
    assert_eq!(did_webvh["method"], "did:webvh");
    // `did-method-adapter-registry.json` names the method version
    // `adapter_version`; it is not a `ak.profile.*` id.
    assert_eq!(
        did_webvh["adapter_version"],
        arkret_models_identity::did_document::DID_WEBVH_V1_METHOD
    );
    assert_eq!(did_webvh["default_provider_id"], "external.webvh");
    let providers = did_webvh["providers"]
        .as_array()
        .expect("did_webvh providers");
    let external = providers
        .iter()
        .find(|provider| provider["id"] == "external.webvh")
        .expect("external did:webvh provider");
    assert_eq!(external["kind"], "external");
    assert_eq!(external["base_url"], EXTERNAL_PROVIDER_URL);
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
