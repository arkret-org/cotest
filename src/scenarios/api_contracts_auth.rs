use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::fixtures::TestScaffold;
use crate::harness::{ArkretServer, actor_core_id, expect_api_error, expect_json, expect_status};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
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
    assert!(missing.instance.is_some());

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
        "param_invalid",
    )
    .await?;

    Ok(())
}

pub async fn account_auth_and_session_edges_are_enforced() -> Result<()> {
    let server = ArkretServer::spawn("account-auth").await?;
    let account_did = arkret_identifiers::Did::new("did:web:alice-auth.example".to_owned())?;
    let account_core_id = arkret_identifiers::project_did_to_core_id(&account_did)?;

    expect_api_error(
        server
            .account_registration_request()
            .json(&crate::harness::NonProtocolTestBody::new(json!({"did": "bad", "handle": "@bad", "device_id": "ak:device:01904100-0000-7000-8000-000000000bad"}))),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    let registration_body = crate::harness::NonProtocolTestBody::new(json!({
        "did": account_did,
        "handle": "@alice-auth",
        "display_name": "alice-auth",
        "device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
    }));
    let registered = expect_json(
        server
            .account_registration_request()
            .json(&registration_body),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(registered["principal_id"], account_core_id.as_str());

    expect_api_error(
        server
            .account_registration_request()
            .json(&registration_body),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    let login = expect_json(
        server
            .http()
            .post(server.url("/_soland/gate/auth/dev-login"))
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "actor": account_core_id,
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
    assert_eq!(me["principal_id"], account_core_id.as_str());

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
    let alice_actor = actor_did_for_service_did(server.service_did(), "alice-contact")?;
    let alice = server
        .demo_client(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob_actor = actor_did_for_service_did(server.service_did(), "bob-contact")?;
    let bob = server
        .demo_client(&bob_actor, "ak:device:01904100-0000-7000-8000-0000000000b0")
        .await?;

    let self_request = alice.contact_request_prepare(&alice.actor)?;
    match alice.sdk().contacts_request(&self_request).await {
        Err(arkret_http_client::Error::Api { status, error }) => {
            assert_eq!(status, StatusCode::BAD_REQUEST.as_u16());
            assert_eq!(error.error.code, "param_invalid");
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
    let missing_target_core_id = actor_core_id(missing_target)?;
    let alice_core_id = actor_core_id(&alice.actor)?;
    let bob_core_id = actor_core_id(&bob.actor)?;
    let missing_receipt = alice.request_contact(missing_target).await?;
    assert_eq!(
        missing_receipt
            .core
            .holder
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        alice_core_id
    );
    assert_eq!(
        missing_receipt
            .core
            .peer
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        missing_target_core_id
    );

    // Alice's first accepted Contact Event is intentionally still awaiting a
    // device-signed successor Seal. Exercise the independent valid-target
    // branch from Bob's fresh PCR rather than bypassing that finality fence.
    let receipt = bob.request_contact(&alice.actor).await?;
    assert_eq!(
        receipt
            .core
            .holder
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        bob_core_id
    );
    assert_eq!(
        receipt
            .core
            .peer
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        alice_core_id
    );

    Ok(())
}
