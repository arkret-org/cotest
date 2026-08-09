use anyhow::Result;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::json;

use crate::fixtures::TestScaffold;
use crate::harness::{ArkretServer, expect_api_error, expect_json, expect_status};
use crate::scenarios::identity_test_support::{
    actor_did_for_service, authorize_device_public_key, spawn_with_harness_account_authority,
};

pub async fn framework_errors_and_invalid_json_use_arkret_envelopes() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = TestScaffold::fresh("api-errors").await?;
    let server = scaffold.server();

    let missing = expect_api_error(
        server.http().get(server.url("/_arkret/self/missing")),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;
    assert!(missing["request_id"].as_str().is_some());

    expect_api_error(
        server.http().post(server.url("/_arkret/describe")),
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    )
    .await?;
    expect_api_error(
        server
            .account_registration_request()
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    Ok(())
}

pub async fn account_auth_and_session_edges_are_enforced() -> Result<()> {
    let server = ArkretServer::spawn("account-auth").await?;

    expect_api_error(
        server
            .account_registration_request()
            .json(&crate::harness::NonProtocolTestBody::new(json!({"principal_id": "bad", "device_id": "ak:device:01904100-0000-7000-8000-000000000bad"}))),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    let registered = expect_json(
        server
            .account_registration_request()
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "principal_id": "did:web:alice-auth.example",
                "display_name": "alice-auth",
                "device_id": "ak:device:01904100-0000-7000-8000-0000000000a1"
            }))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(registered["principal_id"], "did:web:alice-auth.example");

    let second_device = expect_json(
        server
            .account_registration_request()
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "principal_id": "did:web:alice-auth.example",
                "display_name": "alice-auth",
                "device_id": "ak:device:01904100-0000-7000-8000-0000000000a2"
            }))),
        StatusCode::OK,
    )
    .await?;
    let devices = second_device["devices"].as_array().expect("devices array");
    assert!(devices.iter().any(|device| {
        device["device_id"].as_str() == Some("ak:device:01904100-0000-7000-8000-0000000000a2")
    }));

    let login = expect_json(
        server
            .http()
            .post(server.url("/_soland/gate/auth/dev-login"))
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "actor": "did:web:alice-auth.example",
                "device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
                "display_name": "Alice"
            }))),
        StatusCode::OK,
    )
    .await?;
    let token = login["session_credential"].as_str().unwrap();

    let me = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/account/viewer"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(me["principal_id"], "did:web:alice-auth.example");

    expect_api_error(
        server
            .http()
            .get(server.url("/_arkret/self/account/viewer")),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;

    let logout = expect_json(
        server
            .http()
            .post(server.url("/_arkret/gate/account/session-grants/revoke"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(logout["revoked_count"], 1);

    expect_status(
        server
            .http()
            .get(server.url("/_arkret/self/account/viewer"))
            .bearer_auth(token),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    Ok(())
}

pub async fn contact_edges_are_rejected() -> Result<()> {
    let server = spawn_with_harness_account_authority("contact-edges", &[]).await?;
    let alice_actor = actor_did_for_service(server.service_id(), "alice-contact")?;
    let alice = server
        .demo_client(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    authorize_device_public_key(
        &server,
        &alice.token,
        &alice.actor,
        &alice.device_id,
        &SigningKey::from_bytes(&[0xa1; 32]),
    )
    .await?;
    let bob_actor = actor_did_for_service(server.service_id(), "bob-contact")?;
    let bob = server
        .demo_client(&bob_actor, "ak:device:01904100-0000-7000-8000-0000000000b0")
        .await?;
    authorize_device_public_key(
        &server,
        &bob.token,
        &bob.actor,
        &bob.device_id,
        &SigningKey::from_bytes(&[0xb0; 32]),
    )
    .await?;

    let self_request = alice.contact_request_prepare(&alice.actor)?;
    match alice.sdk().contacts_request(&self_request).await {
        Err(arkret_http_client::Error::Api { status, error }) => {
            assert_eq!(status, StatusCode::BAD_REQUEST.as_u16());
            assert_eq!(error.error.code, "invalid_param");
        }
        Err(error) => return Err(error.into()),
        Ok(outcome) => {
            return Err(anyhow::anyhow!(
                "self-targeted Contact request was accepted: {outcome:?}"
            ));
        }
    }

    // Contact prepare/commit records the holder-local request fact. Target
    // resolution and delivery are a later phase, so an offline or currently
    // unresolvable peer is not rejected while authoring that local fact.
    let missing_target = "did:web:missing-contact.example";
    let missing_receipt = alice.request_contact(missing_target).await?;
    assert_eq!(
        missing_receipt.core.holder.subject_id().as_str(),
        alice.actor
    );
    assert_eq!(
        missing_receipt.core.peer.subject_id().as_str(),
        missing_target
    );

    // Alice's first accepted Contact Event is intentionally still awaiting a
    // device-signed successor Seal. Exercise the independent valid-target
    // branch from Bob's fresh PCR rather than bypassing that finality fence.
    let receipt = bob.request_contact(&alice.actor).await?;
    assert_eq!(receipt.core.holder.subject_id().as_str(), bob.actor);
    assert_eq!(receipt.core.peer.subject_id().as_str(), alice.actor);

    Ok(())
}
