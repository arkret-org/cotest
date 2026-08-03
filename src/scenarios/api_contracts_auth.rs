use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::fixtures::TestScaffold;
use crate::harness::{ArkretServer, expect_api_error, expect_json, expect_status};

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
    let server = ArkretServer::spawn("contact-edges").await?;
    let alice = server
        .register_client(
            "did:web:alice-contact.example",
            "@alice-contact",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-contact.example",
            "@bob-contact",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    for (target, expected_status, expected_code) in [
        (
            alice.actor.as_str(),
            StatusCode::BAD_REQUEST,
            "invalid_param",
        ),
        (
            "did:web:missing-contact.example",
            StatusCode::NOT_FOUND,
            "not_found",
        ),
    ] {
        let request = alice.contact_request_prepare(target)?;
        match alice.sdk().contacts_request(&request).await {
            Err(arkret_http_client::Error::Api { status, error }) => {
                assert_eq!(status, expected_status.as_u16());
                assert_eq!(error.error.code, expected_code);
            }
            Err(error) => return Err(error.into()),
            Ok(outcome) => {
                return Err(anyhow::anyhow!(
                    "invalid Contact target {target} was accepted: {outcome:?}"
                ));
            }
        }
    }

    let receipt = alice.request_contact(&bob.actor).await?;
    assert_eq!(receipt.core.holder.subject_id().as_str(), alice.actor);
    assert_eq!(receipt.core.peer.subject_id().as_str(), bob.actor);

    Ok(())
}
