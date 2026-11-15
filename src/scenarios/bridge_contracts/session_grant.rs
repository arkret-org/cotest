use anyhow::{Context, Result};
use reqwest::StatusCode;

use crate::harness::{expect_api_error, expect_status};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority,
};

/// Coordinates retained by the fixture issuer, never embedded in the secret.
#[derive(Clone)]
pub(crate) struct MockSessionGrantCoordinates {
    pub account_id: arkret_wire::AccountId,
    pub device_id: arkret_wire::DeviceId,
    pub grant_ref: arkret_wire::SessionGrantRef,
}

fn fixture_credentials()
-> &'static std::sync::Mutex<std::collections::BTreeMap<String, MockSessionGrantCoordinates>> {
    static VALUES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, MockSessionGrantCoordinates>>,
    > = std::sync::OnceLock::new();
    VALUES.get_or_init(Default::default)
}

pub(crate) fn mock_session_grant_coordinates(secret: &str) -> Result<MockSessionGrantCoordinates> {
    fixture_credentials()
        .lock()
        .expect("fixture credential lock")
        .get(secret)
        .cloned()
        .context("credential has no fixture issuer coordinates")
}

/// Reserve a canonical opaque credential and independent UUIDv7 reference.
/// Binding it into a mock issuer ledger is an explicit separate step.
pub fn mock_session_grant(subject: &str, device_id: &str, audience: &str) -> String {
    let issuer: arkret_wire::DidCoreId = audience.parse().expect("fixture Station");
    let coordinates = MockSessionGrantCoordinates {
        account_id: arkret_wire::AccountId::new(
            subject.parse().expect("fixture principal"),
            issuer.clone(),
        ),
        device_id: device_id.parse().expect("fixture Device"),
        grant_ref: arkret_wire::SessionGrantRef::new(
            issuer,
            arkret_wire::SessionGrantId::new_v7_at(
                chrono::Utc::now()
                    .timestamp_millis()
                    .try_into()
                    .expect("fixture time"),
            ),
        ),
    };
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("fixture SessionGrant entropy");
    let secret = arkret_wire::SessionGrantSecret::from_bytes(bytes).into_string();
    fixture_credentials()
        .lock()
        .expect("fixture credential lock")
        .insert(secret.clone(), coordinates);
    secret
}

pub fn mock_recovery_session_grant(subject: &str, device_id: &str, audience: &str) -> String {
    mock_session_grant(subject, device_id, audience)
}

/// An unrecorded secret cannot acquire authority through an issuer signing key.
pub fn unissued_session_grant(subject: &str, device_id: &str, audience: &str) -> String {
    mock_session_grant(subject, device_id, audience)
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
            "COLAND_ACCOUNT_AUTHORITY_URL",
            account_authority_origin.as_str(),
        ),
        (
            "COLAND_SESSION_GRANT_INTROSPECTION_URL",
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
    let holder_key = ed25519_dalek::SigningKey::from_bytes(&[0xda; 32]);
    assert_ne!(
        holder_key.verifying_key(),
        principal.device_signing_key.verifying_key(),
        "the short-lived grant holder must be independent from the Event device key",
    );
    let session_grant =
        mock_session_grant(&principal_core_id, &device_id, server.service_id().as_str());
    // The Account Authority's issuer ledger holds this exact credential; the
    // Station submits the complete token and consumes the returned authority
    // metadata instead of rebuilding any issuer fact locally.
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

    // The fixture Authority returns 503 until its issuer ledger is available.
    // This is an unavailable dependency, not an authoritative inactive grant;
    // the Station must neither authenticate it nor tell the holder to log out.
    let unavailable_dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url).access_token(&session_grant),
        &holder_key,
    )?;
    expect_api_error(
        server
            .http()
            .post(&push_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("DPoP {session_grant}"),
            )
            .header("DPoP", &unavailable_dpop.header_value)
            .json(&push_body),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await?;
    coauth.bind_founding_device_grant(
        &session_grant,
        &principal_core_id,
        &device_id,
        principal.founding_authorize_event_id.as_str(),
        &holder_key.verifying_key(),
    )?;

    // §3.3 presentation: `Authorization: DPoP <opaque credential>` plus a
    // sender-constrained DPoP proof bound to the grant (`ath`) and to this
    // exact request target (`htm`/`htu`).
    let dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url).access_token(&session_grant),
        &holder_key,
    )?;
    // This fixture does not onboard a Push Gateway. A valid presentation
    // therefore reaches the gateway handoff, which register-device reports as
    // its registered `push_gateway_unreachable` (503); invalid grants below
    // must fail authentication first (401).
    expect_api_error(
        server
            .http()
            .post(&push_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("DPoP {session_grant}"),
            )
            .header("DPoP", &dpop.header_value)
            .json(&push_body),
        StatusCode::SERVICE_UNAVAILABLE,
        "push_gateway_unreachable",
    )
    .await?;

    let requests = coauth.requests();
    assert!(
        !requests.is_empty(),
        "grant presentation must introspect at coauth"
    );
    // `api-conventions.md` §3.3 / `key-management.md` §6.1: the Station submits
    // the complete opaque secret plus its own service DID as `audience_id`. It MUST NOT
    // introspect by `jti`/grant id, and MUST NOT rebuild the issuer's facts
    // (JWT signature, issuer DID history, derived ID) for itself.
    assert_eq!(requests[0]["session_grant"], session_grant);
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

    // An unrecorded canonical secret has no issuer authority, even when the
    // presenter holds a valid DPoP key or knows an issuer signing key.
    let forged_session_grant =
        unissued_session_grant(&principal_core_id, &device_id, server.service_id().as_str());
    assert_ne!(forged_session_grant, session_grant);
    let forged_dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url)
            .access_token(&forged_session_grant),
        &holder_key,
    )?;
    expect_status(
        server
            .http()
            .post(&push_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("DPoP {forged_session_grant}"),
            )
            .header("DPoP", &forged_dpop.header_value)
            .json(&push_body),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    // A different audience fixture reserves a different opaque credential;
    // no bytes from it are active in this issuer ledger.
    let resigned_session_grant = mock_session_grant(
        &principal_core_id,
        &device_id,
        "ak:did_core:web:other-station.example",
    );
    assert_ne!(resigned_session_grant, session_grant);
    let resigned_dpop = arkret_signatures::build_dpop_proof(
        &arkret_signatures::DpopProofRequest::new("POST", &push_url)
            .access_token(&resigned_session_grant),
        &holder_key,
    )?;
    expect_status(
        server
            .http()
            .post(&push_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("DPoP {resigned_session_grant}"),
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
        &arkret_signatures::DpopProofRequest::new("POST", &push_url).access_token(&session_grant),
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
            .header(
                reqwest::header::AUTHORIZATION,
                format!("DPoP {session_grant}"),
            )
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
            .bearer_auth(&session_grant)
            .json(&push_body),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    Ok(())
}
