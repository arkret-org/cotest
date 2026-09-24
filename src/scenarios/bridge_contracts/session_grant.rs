use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::expect_status;
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority,
};

/// A grant-shaped bearer credential (JWT with `kind = "ak.session.grant"`).
/// The mock never verifies its signature; the shape only matters so the SUT
/// recognizes the credential class and so `ath` binds a stable token.
pub fn mock_session_grant_jwt(subject: &str, device_id: &str, audience: &str) -> String {
    grant_shaped_jwt(subject, device_id, audience, 0x42)
}

/// A structurally perfect grant-shaped credential whose only difference from
/// [`mock_session_grant_jwt`] is its signature bytes: exactly what someone
/// holding a leaked issuer signing key can mint. The claims are self-consistent
/// and the credential class is recognizable, so nothing short of the issuer
/// ledger's exact-credential record can tell it apart.
pub fn issuer_key_forged_session_grant_jwt(
    subject: &str,
    device_id: &str,
    audience: &str,
) -> String {
    grant_shaped_jwt(subject, device_id, audience, 0x43)
}

fn grant_shaped_jwt(subject: &str, device_id: &str, audience: &str, signature_byte: u8) -> String {
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
    let signature = URL_SAFE_NO_PAD.encode([signature_byte; 64]);
    format!("{header}.{payload}.{signature}")
}

pub async fn session_grant_presentation_uses_configured_coauth_introspection() -> Result<()> {
    // The mock must exist before the SUT boots so its URL lands in the SUT env.
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let account_authority_origin = coauth.origin();
    let introspection_url = coauth.url();
    let extra_env = [
        (
            "SOLAND_ACCOUNT_AUTHORITY_URL",
            account_authority_origin.as_str(),
        ),
        (
            "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
            introspection_url.as_str(),
        ),
    ];
    let server =
        spawn_with_harness_account_authority("session-grant-presentation", &extra_env).await?;

    // Canonical self-sovereign principal: deterministic did:webvh plus the
    // closed §5.1 genesis unit, so the grant's device selector replays a real
    // accepted founding `ak.device.authorize` Event.
    let alice = actor_did_for_service_did(server.service_did(), "alice-session-grant")?;
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
    let grant_jwt =
        mock_session_grant_jwt(&principal_core_id, &device_id, server.service_id().as_str());
    // The Account Authority's issuer ledger holds this exact credential; the
    // Station submits the complete token and consumes the returned authority
    // metadata instead of rebuilding any issuer fact locally.
    coauth.bind_founding_device_grant(
        &grant_jwt,
        &principal_core_id,
        &device_id,
        principal.founding_authorize_event_id.as_str(),
        &holder_key.verifying_key(),
    )?;
    let push_url = server.url("/_arkret/edge/push/register-device");
    let push_body = arkret_models_integration::PushRegisterDeviceRequestBody {
        device_id: arkret_wire::DeviceId::new(device_id.clone())?,
        push_gateway_url: "https://floria.example/_arkret/edge/push/notify".to_owned(),
        push_key: arkret_models_integration::PushKey::new("webpush:opaque-token")
            .map_err(anyhow::Error::msg)?,
        platform: Some("web".to_owned()),
        app_id: Some("inkson".to_owned()),
        display_name: None,
        visible_notification_opt_in: false,
    };

    // §3.3 presentation: `Authorization: DPoP <grant jwt>` plus a
    // sender-constrained DPoP proof bound to the grant (`ath`) and to this
    // exact request target (`htm`/`htu`).
    let dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url).access_token(&grant_jwt),
        &holder_key,
    )?;
    // This fixture does not onboard a Push Gateway. A valid presentation
    // therefore reaches the gateway dependency gate (409); invalid grants
    // below must fail authentication first (401).
    expect_status(
        server
            .http()
            .post(&push_url)
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {grant_jwt}"))
            .header("DPoP", &dpop.header_value)
            .json(&push_body),
        StatusCode::CONFLICT,
    )
    .await?;

    let requests = coauth.requests();
    assert!(
        !requests.is_empty(),
        "grant presentation must introspect at coauth"
    );
    // `api-conventions.md` §3.3 / `key-management.md` §6.1: the Station submits
    // the complete token plus its own service DID as `audience_id`. It MUST NOT
    // introspect by `jti`/grant id, and MUST NOT rebuild the issuer's facts
    // (JWT signature, issuer DID history, derived ID) for itself.
    assert_eq!(requests[0]["grant_jwt"], grant_jwt);
    assert_eq!(requests[0]["audience_id"], server.service_id().as_str());
    assert!(
        requests
            .iter()
            .all(|request| request.get("id").is_none() && request.get("proof").is_none()),
        "exact-token introspection must not degrade to an id lookup or carry a request proof: {requests:?}"
    );
    // The private Station-to-Account-Authority introspection adapter
    // authenticates with its configured credential and MUST NOT let a
    // self-reported `Source-Service-ID` / `Destination-Service-ID` / `internal`
    // header stand in for that identity. It is not a canonical Arkret operation.
    let observations = coauth.channel_observations();
    assert!(
        !observations.is_empty()
            && observations.iter().all(|observation| {
                observation.presented_configured_credential
                    && observation.self_reported_identity_headers.is_empty()
            }),
        "internal introspection must present the configured channel credential and no self-reported identity header: {observations:?}"
    );

    // Negative: a self-consistent grant minted with a leaked issuer signing key
    // has no active exact ledger record. The forgery is structurally perfect --
    // same subject, device and audience, and presented with a correctly bound
    // DPoP proof -- so only the exact-token authority can reject it. A Station
    // that verified the JWT locally and authorized on that basis would admit it.
    let forged_grant_jwt = issuer_key_forged_session_grant_jwt(
        &principal_core_id,
        &device_id,
        server.service_id().as_str(),
    );
    assert_ne!(forged_grant_jwt, grant_jwt);
    let forged_dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url)
            .access_token(&forged_grant_jwt),
        &holder_key,
    )?;
    expect_status(
        server
            .http()
            .post(&push_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("DPoP {forged_grant_jwt}"),
            )
            .header("DPoP", &forged_dpop.header_value)
            .json(&push_body),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    // Negative: re-signing the active grant's claims for a different audience
    // produces a credential a `jti`-keyed lookup or a locally verified signature
    // would still accept. The bound authority is the exact credential bytes, and
    // these are different bytes.
    let resigned_grant_jwt = mock_session_grant_jwt(
        &principal_core_id,
        &device_id,
        "ak:did_core:web:other-station.example",
    );
    assert_ne!(resigned_grant_jwt, grant_jwt);
    let resigned_dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url)
            .access_token(&resigned_grant_jwt),
        &holder_key,
    )?;
    expect_status(
        server
            .http()
            .post(&push_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("DPoP {resigned_grant_jwt}"),
            )
            .header("DPoP", &resigned_dpop.header_value)
            .json(&push_body),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

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
