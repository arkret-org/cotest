use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ContrixServer, expect_json};

pub async fn starid_optional_resolver_profile_is_discoverable() -> Result<()> {
    let server = ContrixServer::spawn_with_env(
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
        server.http().get(server.url("/api/v1/identity/describe")),
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
    assert!(
        describe["todos"]
            .as_array()
            .is_some_and(|todos| !todos.is_empty()),
        "soland must keep explicit TODO markers until starid proof/trust-root validation lands"
    );

    Ok(())
}
