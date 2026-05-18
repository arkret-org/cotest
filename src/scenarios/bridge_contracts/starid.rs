use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ContrixServer, expect_json};

pub async fn starid_optional_resolver_profile_is_discoverable() -> Result<()> {
    let server = ContrixServer::spawn_with_env(
        "starid-optional",
        &[
            (
                "SOLAND_DID_RESOLVER_ALLOW_METHODS",
                "did:web,did:key,did:webvh",
            ),
            (
                "SOLAND_STARID_WEBVH_RESOLVER_URL",
                "http://starid.cotest.local",
            ),
        ],
    )
    .await?;

    let describe = expect_json(
        server.http().get(server.url("/api/v1/identity/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe["starid_profile"]["enabled"], true);
    assert_eq!(describe["starid_profile"]["method"], "did:webvh");
    assert_eq!(
        describe["starid_profile"]["profile"],
        "cx.identity.starid.webvh.optional.v1"
    );
    assert_eq!(
        describe["starid_profile"]["resolver_url"],
        "http://starid.cotest.local"
    );
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
