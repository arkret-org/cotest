use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{CokretServer, expect_json};

pub async fn starid_optional_resolver_profile_is_discoverable() -> Result<()> {
    let server = CokretServer::spawn_with_env(
        "starid-optional",
        &[
            ("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,key,webvh"),
            ("SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED", "0"),
            (
                "SOLAND_EXTERNAL_WEBVH_PROVIDER_URL",
                "http://starid.cotest.local",
            ),
            ("SOLAND_DEFAULT_WEBVH_PROVIDER_ID", "external.webvh"),
        ],
    )
    .await?;

    let describe = expect_json(
        server
            .http()
            .get(server.url("/_cokret/root/identity/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe["did_webvh"]["enabled"], true);
    assert_eq!(describe["did_webvh"]["method"], "did:webvh");
    assert_eq!(
        describe["did_webvh"]["profile"],
        "cx.identity.webvh.provider.v1"
    );
    assert_eq!(
        describe["did_webvh"]["default_provider_id"],
        "external.webvh"
    );
    let providers = describe["did_webvh"]["providers"]
        .as_array()
        .expect("did_webvh providers");
    let external = providers
        .iter()
        .find(|provider| provider["id"] == "external.webvh")
        .expect("external did:webvh provider");
    assert_eq!(external["kind"], "external");
    assert_eq!(external["base_url"], "http://starid.cotest.local");
    assert!(
        describe["resolver_policy"]["allow_methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("webvh")),
        "did:webvh should be discoverable when the optional starid resolver is configured"
    );
    assert_eq!(
        describe["resolver_policy"]["freshness_receipts"]["endpoint_template"],
        "/_cokret/root/identity/receipts?did={did}"
    );
    assert_eq!(
        describe["resolver_policy"]["webvh_validation"]["witness_quorum"],
        "enforced_for_local_webvh_records"
    );
    let trust_roots = describe["resolver_policy"]["trust_roots"]
        .as_array()
        .expect("resolver policy trust_roots");
    assert!(
        trust_roots
            .iter()
            .any(local_trust_root_has_webvh_validation),
        "soland must publish its local identity trust root and webvh proof-validation policy: {describe}"
    );
    let external_root = trust_roots
        .iter()
        .find(|root| root["id"] == "external.webvh")
        .expect("external starid trust root");
    assert_eq!(external_root["kind"], "external");
    assert_eq!(external_root["profile"], "cx.identity.webvh.provider.v1");
    assert_eq!(external_root["base_url"], "http://starid.cotest.local");
    assert_eq!(external_root["freshness_probe"], "/describe");
    assert!(
        external_root["expected_trust_domain"]
            .as_str()
            .is_some_and(|trust_domain| trust_domain.starts_with("ck:trust_domain:")),
        "external starid trust root must bind the expected trust domain: {external_root}"
    );
    assert!(
        describe["todos"]
            .as_array()
            .is_some_and(|todos| todos.is_empty()),
        "soland resolver describe TODOs must be cleared once starid proof/trust-root validation lands: {describe}"
    );

    Ok(())
}

fn local_trust_root_has_webvh_validation(root: &Value) -> bool {
    root["kind"] == "local_identity_store"
        && root["proof_verification"]["controller_proof"] == "eddsa-jcs-2022"
        && root["proof_verification"]["webvh_log_chain"] == "required"
        && root["proof_verification"]["webvh_scid"] == "required"
        && root["proof_verification"]["webvh_witness_quorum"] == "required_when_policy_present"
}
