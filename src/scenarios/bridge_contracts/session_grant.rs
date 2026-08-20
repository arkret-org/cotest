use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, expect_json, expect_status};
use crate::scenarios::_helpers::bridge::{EnvOverride, MockCoauthIntrospectionServer};
use crate::scenarios::identity_test_support::actor_did_for_service_full_id;

/// A grant-shaped bearer credential (JWT with `kind = "ak.session.grant"`).
/// The mock never verifies its signature; the shape only matters so the SUT
/// recognizes the credential class and so `ath` binds a stable token.
fn mock_session_grant_jwt(subject: &str, device_id: &str, audience: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"Ed25519","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "kind": arkret_models_identity::SESSION_GRANT_CREDENTIAL_KIND,
            "sub": subject,
            "device_id": device_id,
            "aud": audience,
        }))
        .expect("session grant payload serializes"),
    );
    let signature = URL_SAFE_NO_PAD.encode([0x42_u8; 64]);
    format!("{header}.{payload}.{signature}")
}

pub async fn session_grant_presentation_uses_configured_coauth_introspection() -> Result<()> {
    // The mock must exist before the SUT boots so its URL lands in the SUT env.
    let coauth = MockCoauthIntrospectionServer::spawn().await?;
    let _env = EnvOverride::set(&[
        ("SOLAND_SESSION_GRANT_INTROSPECTION_URL", Some(coauth.url())),
        (
            "SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
            Some("principal-token".to_owned()),
        ),
    ]);
    let server = ArkretServer::spawn("session-grant-presentation").await?;

    // Canonical self-sovereign principal: deterministic did:webvh plus the
    // closed §5.1 genesis unit, so the grant's device selector replays a real
    // accepted founding `ak.device.authorize` Event.
    let alice = actor_did_for_service_full_id(server.service_full_id(), "alice-session-grant")?;
    let client = server
        .register_client(&alice, "Alice Session Grant", "session-grant-device")
        .await?;
    let principal = client
        .principal
        .clone()
        .context("registered client carries its provisioned principal")?;
    let principal_core_id = principal.core_id.as_str().to_owned();
    let device_id = principal.device_id.as_str().to_owned();
    let holder_key = principal.device_signing_key.clone();
    coauth.bind_founding_device_grant(
        &principal_core_id,
        &device_id,
        principal.founding_authorize_event_id.as_str(),
        &holder_key.verifying_key(),
    )?;

    let grant_jwt =
        mock_session_grant_jwt(&principal_core_id, &device_id, server.service_id().as_str());
    let push_url = server.url("/_arkret/edge/push/register-device");
    let push_body = serde_json::from_value::<
        arkret_models_integration::PushRegisterDeviceRequestBody,
    >(json!({
        "device_id": device_id,
        "push_gateway": "https://floria.example/_arkret/edge/push/notify",
        "push_key": "webpush:opaque-token",
        "platform": "web",
        "app_id": "inkson"
    }))?;

    // §3.3 presentation: `Authorization: DPoP <grant jwt>` plus a
    // sender-constrained DPoP proof bound to the grant (`ath`) and to this
    // exact request target (`htm`/`htu`).
    let dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url).access_token(&grant_jwt),
        &holder_key,
    )?;
    let push = expect_json(
        server
            .http()
            .post(&push_url)
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {grant_jwt}"))
            .header("DPoP", &dpop.header_value)
            .json(&push_body),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);
    // soland derives the registration_id as an unlinkable, salt-epoch-bound
    // handle spelled from the same pairwise HMAC tag as the push target
    // pseudonym (push.rs `push_registration_id`). The tag is keyed, so it is
    // not predictable from the request. The wire member is closed by
    // `push-operations.schema.json#/$defs/registration_id` as an
    // opaque_correlation carrier outside the `ak:` typed-ID namespace; assert
    // that shape instead of an exact value.
    let registration_id = push["registration_id"]
        .as_str()
        .expect("registration_id must be a string");
    assert!(
        (1..=128).contains(&registration_id.len())
            && !registration_id.starts_with("ak:")
            && registration_id
                .bytes()
                .all(|b| { b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-') }),
        "registration_id must match the opaque_correlation profile, got: {registration_id}"
    );

    let requests = coauth.requests();
    assert!(
        !requests.is_empty(),
        "grant presentation must introspect at coauth"
    );
    assert_eq!(requests[0]["grant_jwt"], grant_jwt);
    assert_eq!(requests[0]["audience"], server.service_id().as_str());

    // Negative: the same grant presented with a DPoP proof from a different
    // holder key fails closed — the proof thumbprint no longer matches the
    // grant's `cnf.jkt`. api-conventions.md §3.3 fails every presentation check
    // closed as `unauthenticated`.
    let wrong_holder_key = ed25519_dalek::SigningKey::from_bytes(&[0xd9; 32]);
    let wrong_dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url).access_token(&grant_jwt),
        &wrong_holder_key,
    )?;
    // Both negatives must ride the harness send boundary (`expect_status` →
    // `send_recorded` → `canonicalize_protocol_json_body`): a raw `.send()`
    // would put the typed struct's declaration-order bytes on the wire, which
    // the canonical-body hoop rightly rejects as `schema_violation` before the
    // §3.3 presentation check ever runs.
    expect_status(
        server
            .http()
            .post(&push_url)
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {grant_jwt}"))
            .header("DPoP", &wrong_dpop.header_value)
            .json(&push_body),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    // Negative: a grant-shaped bearer without a DPoP proof is not a §3.3
    // presentation at all.
    expect_status(
        server
            .http()
            .post(&push_url)
            .bearer_auth(&grant_jwt)
            .json(&push_body),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    Ok(())
}
