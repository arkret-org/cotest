use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ArkretServer, add_member, create_realm, dev_login, event_envelope, expect_api_error,
    expect_json, member_join_payload_value, message_create_text_payload, register_account,
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
                            "kind": "single_did",
                            "did": "did:web:alice.example",
                            "recovery_members": ["did:web:recovery.soland.local"],
                            "controller_organization": "did:web:organization.primary.soland.local",
                            "recovery_controller_organizations": [
                                "did:web:organization.recovery.soland.local"
                            ]
                        },
                        "capability_action_registry_digest":
                            arkret::current_capability_action_registry_digest()
                                .expect("embedded capability-action registry"),
                        "created_at": "2026-05-02T00:00:00.000Z"
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

    let pre_member_seal = current_seal_id(&alice, &realm_id).await?;
    add_member(
        &server,
        &alice.token,
        "did:web:alice.example",
        &realm_id,
        "did:web:bob-visible.example",
    )
    .await?;
    await_seal_advance(&alice, &realm_id, &pre_member_seal).await?;
    alice
        .grant_realm_actions_to_client(&realm_id, &bob, &["ak.message.create"])
        .await?;
    bob.submit_event(
        &realm_id,
        "ak.message.create",
        message_create_text_payload(&realm_id, "member can send")?,
    )
    .await?;

    let pre_destroy_seal = current_seal_id(&alice, &realm_id).await?;
    alice
        .submit_event(
            &realm_id,
            "ak.realm.destroy",
            json!({"reason": "owner_requested"}),
        )
        .await?;
    await_seal_advance(&alice, &realm_id, &pre_destroy_seal).await?;
    let after_destroy = alice
        .author_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload(&realm_id, "after delete")?,
        )
        .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&alice.token)
            .json(&after_destroy),
        StatusCode::CONFLICT,
        // The top-level wire error code is `failed_precondition`; the
        // terminal-state condition is carried as the `realm_terminal_state`
        // sub-reason (it is a spec `reason_code`, not a top-level error code).
        "failed_precondition",
    )
    .await?;

    Ok(())
}

async fn current_seal_id(
    client: &crate::harness::TestActorClient,
    realm_id: &str,
) -> Result<String> {
    client.realm_seal_frontier(realm_id).await?["frontier"]["seal_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("Realm frontier omitted seal_id"))
}

async fn await_seal_advance(
    client: &crate::harness::TestActorClient,
    realm_id: &str,
    predecessor: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if current_seal_id(client, realm_id).await? != predecessor {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("membership Control Move was not sealed"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
