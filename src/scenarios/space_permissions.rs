use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    CokretServer, add_member, create_realm, dev_login, event_envelope, expect_api_error,
    expect_json, register_account, send_message, submit_event,
};

pub async fn space_creation_and_owner_only_mutations_are_enforced() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = crate::fixtures::TestScaffold::fresh("space-permissions").await?;
    let server = scaffold.server();
    let alice = dev_login(server, "did:web:alice.example", "dev_alice").await?;
    let bob =
        register_account(server, "did:web:bob-space.example", "@bob-space", "dev_bob").await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/spaces"))
            .json(&json!({"title": "No Auth"})),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    let unauth_realm_id = "ck:realm:01904100-0000-7000-8000-5pace0000001";
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/events"))
            .json(&event_envelope(
                "did:web:alice.example",
                unauth_realm_id,
                "ck.realm.create",
                json!({
                    "object": {
                        "id": unauth_realm_id,
                        "schema": "ck.schema.realm.v1",
                        "title": "No Auth",
                        "summary": "No Auth",
                        "created_by": "did:web:alice.example",
                        "trust_domain": "ck:trust_domain:soland.local",
                        "schema_refs": ["ck.schema.realm.v1"],
                        "default_discoverability": "invite_only",
                        "default_join_rule": "invite",
                        "history_visibility": "shared",
                        "encryption_profile": "none",
                        "plaintext_visible_services": [server.service_did()],
                        "security_class": "standard",
                        "federation_policy": "restricted",
                        "anchor_profile": "single_did",
                        "digest_algorithm": "sha256",
                        "anchorer": {
                            "type": "single_did",
                            "did": "did:web:alice.example",
                            "recovery_members": ["did:web:recovery.soland.local"],
                            "controller_organization": "did:web:organization.primary.soland.local",
                            "recovery_controller_organizations": [
                                "did:web:organization.recovery.soland.local"
                            ]
                        },
                        "created_at": "2026-05-02T00:00:00Z"
                    }
                }),
            )),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;

    let realm_id =
        create_realm(server, &alice, "did:web:alice.example", "Permission Space").await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/events"))
            .bearer_auth(&bob)
            .json(&event_envelope(
                "did:web:bob-space.example",
                &realm_id,
                "ck.member.state",
                json!({
                    "actor_id": "did:web:bob-space.example",
                    "membership": "join",
                    "delivery_status": "unroutable"
                }),
            )),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .delete(server.url(&format!("/_cokret/self/spaces/{realm_id}")))
            .bearer_auth(&alice),
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    )
    .await?;

    Ok(())
}

pub async fn private_visibility_non_member_send_and_deleted_space_edges() -> Result<()> {
    let server = CokretServer::spawn("space-visibility").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-visible.example", "@bob-visible", "dev_bob")
        .await?;
    let created = alice
        .create_realm_with(json!({
            "title": "Private Space",
            "summary": "Private Space",
            "discoverability": "invite_only",
            "history_visibility": "shared",
            "plaintext_visible_services": [server.service_did()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("create_realm response missing string realm_id: {created}"))?
        .to_owned();

    let anonymous_search = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/search-realms"))
            .json(&json!({"query": "Private Space"})),
        StatusCode::OK,
    )
    .await?;
    assert!(anonymous_search["results"].as_array().unwrap().is_empty());

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/events"))
            .bearer_auth(&bob.token)
            .json(&event_envelope(
                "did:web:bob-visible.example",
                &realm_id,
                "ck.message.create",
                json!({
                    "body": "not a member",
                    "content": {"body": "not a member"},
                    "thread_id": "ck:thread:space-denied",
                }),
            )),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    add_member(
        &server,
        &alice.token,
        "did:web:alice.example",
        &realm_id,
        "did:web:bob-visible.example",
    )
    .await?;
    send_message(
        &server,
        &bob.token,
        "did:web:bob-visible.example",
        &realm_id,
        "ck:thread:space",
        "member can send",
    )
    .await?;

    submit_event(
        &server,
        &alice.token,
        "did:web:alice.example",
        &realm_id,
        "ck.realm.destroy",
        json!({"reason": "owner_requested"}),
        StatusCode::OK,
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/events"))
            .bearer_auth(&alice.token)
            .json(&event_envelope(
                "did:web:alice.example",
                &realm_id,
                "ck.message.create",
                json!({
                    "body": "after delete",
                    "content": {"body": "after delete"},
                    "thread_id": "ck:thread:space",
                }),
            )),
        StatusCode::CONFLICT,
        "realm_terminal_state",
    )
    .await?;

    Ok(())
}
