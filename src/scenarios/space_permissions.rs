use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ArkretServer, add_member, create_realm, dev_login, event_envelope, expect_api_error,
    expect_json, member_join_payload_value, message_create_text_payload, register_account,
    send_message, submit_event,
};

pub async fn space_creation_and_owner_only_mutations_are_enforced() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = crate::fixtures::TestScaffold::fresh("space-permissions").await?;
    let server = scaffold.server();
    let alice = dev_login(
        server,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-0000000000a1",
    )
    .await?;
    let bob = register_account(
        server,
        "did:web:bob-space.example",
        "@bob-space",
        "ak:device:01904100-0000-7000-8000-0000000000b0",
    )
    .await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_soland/self/spaces"))
            .json(&json!({"title": "No Auth"})),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    let unauth_realm_id = "ak:realm:01904100-0000-7000-8000-000000005ace";
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .json(&event_envelope(
                "did:web:alice.example",
                unauth_realm_id,
                "ak.realm.create",
                json!({
                    "object": {
                        "id": unauth_realm_id,
                        "schema": "ak.schema.realm.v1",
                        "title": "No Auth",
                        "summary": "No Auth",
                        "created_by": "did:web:alice.example",
                        "trust_domain": "ak:trust_domain:soland.local",
                        "schema_refs": ["ak.schema.realm.v1"],
                        "default_discoverability": "invite_only",
                        "default_join_rule": "invite",
                        "history_visibility": "shared",
                        "encryption_profile": "none",
                        "plaintext_visible_services": [server.service_id()],
                        "security_class": "standard",
                        "federation_policy": "restricted",
                        "notary_profile": "single_did",
                        "digest_algorithm": "sha256",
                        "notary": {
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
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&bob)
            .json(&event_envelope(
                "did:web:bob-space.example",
                &realm_id,
                "ak.member.state",
                member_join_payload_value(&realm_id, "did:web:bob-space.example")?,
            )),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .delete(server.url(&format!("/_soland/self/spaces/{realm_id}")))
            .bearer_auth(&alice),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}

pub async fn private_visibility_non_member_send_and_deleted_space_edges() -> Result<()> {
    let server = ArkretServer::spawn("space-visibility").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-visible.example",
            "@bob-visible",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let created = alice
        .create_realm_with(json!({
            "title": "Private Space",
            "summary": "Private Space",
            "discoverability": "invite_only",
            "history_visibility": "shared",
            "plaintext_visible_services": [server.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("create_realm response missing string realm_id: {created}"))?
        .to_owned();

    let anonymous_search = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-realms"))
            .json(&json!({"query": "Private Space"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_search["realms"].as_array().unwrap().is_empty(),
        "invite-only realm leaked into anonymous search: {}",
        serde_json::to_string_pretty(&anonymous_search)?
    );

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&bob.token)
            .json(&event_envelope(
                "did:web:bob-visible.example",
                &realm_id,
                "ak.message.create",
                message_create_text_payload(&realm_id, "not a member")?,
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
        "ak:thread:space",
        "member can send",
    )
    .await?;

    submit_event(
        &server,
        &alice.token,
        "did:web:alice.example",
        &realm_id,
        "ak.realm.destroy",
        json!({"reason": "owner_requested"}),
        StatusCode::OK,
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&alice.token)
            .json(&event_envelope(
                "did:web:alice.example",
                &realm_id,
                "ak.message.create",
                message_create_text_payload(&realm_id, "after delete")?,
            )),
        StatusCode::CONFLICT,
        // The top-level wire error code is `failed_precondition`; the
        // terminal-state condition is carried as the `realm_terminal_state`
        // sub-reason (it is a spec `reason_code`, not a top-level error code).
        "failed_precondition",
    )
    .await?;

    Ok(())
}
