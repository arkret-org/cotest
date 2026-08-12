use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::_helpers::bridge::{EnvOverride, MockCoauthIntrospectionServer};

pub async fn session_grant_presentation_uses_configured_coauth_introspection() -> Result<()> {
    let principal_full_id =
        arkret_identifiers::DidFullId::new("did:web:alice-session-grant.example".to_owned())?;
    let principal_core_id = arkret_identifiers::project_full_id_to_core_id(&principal_full_id)?;
    let device_id = "ak:device:0196419b-0000-7000-8000-000000000501";
    let coauth =
        MockCoauthIntrospectionServer::spawn(principal_core_id.as_str(), device_id).await?;
    let _env = EnvOverride::set(&[
        ("SOLAND_SESSION_GRANT_INTROSPECTION_URL", Some(coauth.url())),
        (
            "SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
            Some("principal-token".to_owned()),
        ),
    ]);
    let server = ArkretServer::spawn("session-grant-presentation").await?;

    expect_json(
        server.account_registration_request().json(
            &arkret_models_collaboration::account_lifecycle::AccountRegisterRequestBody {
                principal_id: principal_core_id.clone(),
                full_id: principal_full_id,
                display_name: Some("Alice Session Grant".to_owned()),
                device_id: Some(arkret_identifiers::DeviceId::new(device_id.to_owned())?),
                proof: None,
                identity_creation: None,
                policy_evidence: None,
            },
        ),
        StatusCode::OK,
    )
    .await?;

    let push = expect_json(
        server
            .http()
            .post(server.url("/_arkret/edge/push/register-device"))
            .header("X-Arkret-Session-Grant", "coauth.session.jwt")
            .header("X-Arkret-Principal-Id", principal_core_id.as_str())
            .header("X-Arkret-Session-Grant-Challenge", "soland-push-challenge")
            .header(
                "X-Arkret-Session-Grant-Proof",
                "client.session-key.push-proof.jwt",
            )
            .json(&serde_json::from_value::<
                arkret_models_integration::PushRegisterDeviceRequestBody,
            >(json!({
                "device_id": device_id,
                "push_gateway": "https://floria.example/_arkret/edge/push/notify",
                "push_key": "webpush:opaque-token",
                "platform": "web",
                "app_id": "inkson"
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);
    // soland derives the push registration_id as an unlinkable pseudonym —
    // `ak:pseudonym:push:<base64url(HMAC)>` (push.rs `derive_push_target_id`)
    // — rather than the linkable `ak:push:{device_id}`. The HMAC tag is keyed
    // and salt-epoch-bound, so it is not predictable from the request; assert
    // the pseudonym shape instead of an exact value.
    let registration_id = push["registration_id"]
        .as_str()
        .expect("registration_id must be a string");
    let pseudonym_body = registration_id
        .strip_prefix("ak:pseudonym:push:")
        .unwrap_or_else(|| {
            panic!("registration_id must be a push pseudonym, got: {registration_id}")
        });
    assert!(
        !pseudonym_body.is_empty()
            && pseudonym_body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "push pseudonym body must be non-empty base64url: {registration_id}"
    );

    let requests = coauth.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["grant_jwt"], "coauth.session.jwt");
    assert_eq!(requests[0]["audience"], server.service_id().as_str());
    assert_eq!(requests[0]["proof"]["challenge"], "soland-push-challenge");

    Ok(())
}
