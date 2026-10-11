use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    expect_api_error, expect_json, member_join_payload_value, message_create_text_payload,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

pub async fn space_creation_and_owner_only_mutations_are_enforced() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = crate::fixtures::TestScaffold::fresh("space-permissions").await?;
    let server = scaffold.server();
    let alice_did = actor_did_for_service_did(server.service_did(), "space-alice")?;
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-space")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob = server
        .standard_register_client(
            &bob_did,
            "@bob-space",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    // Negative-surface residue gate: this retired Coland product endpoint is
    // intentionally absent. The request is not a product consumer.
    expect_api_error(
        server.http().post(server.url("/_coland/self/spaces")).json(
            &crate::harness::NonProtocolTestBody::new(json!({"title": "No Auth"})),
        ),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    let realm_id = alice.create_realm("Permission Space").await?;
    let unauthorized_join = bob
        .author_event(
            &realm_id,
            "ak.member.state",
            member_join_payload_value(&realm_id, &bob_did)?,
        )
        .await?;
    let unauthorized_submission =
        crate::publication::initial_submission(unauthorized_join.clone(), "")?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .json(&unauthorized_submission),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;

    expect_api_error(
        bob.authorize(server.http().post(server.url("/_arkret/self/events")))
            .json(&unauthorized_submission),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    // Keep the retired mutation surface absent after a real protocol Realm
    // create; this prevents a local CRUD bypass from returning unnoticed.
    expect_api_error(
        alice.authorize(
            server
                .http()
                .delete(server.url(&format!("/_coland/self/spaces/{realm_id}"))),
        ),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}

pub async fn private_visibility_non_member_send_and_deleted_space_edges() -> Result<()> {
    let server_owner = spawn_with_harness_account_authority("space-visibility", &[]).await?;
    let server = &server_owner;
    let alice_did = actor_did_for_service_did(server.service_did(), "visible-alice")?;
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-visible")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob = server
        .standard_register_client(
            &bob_did,
            "@bob-visible",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let created = alice
        .create_realm_with(json!({
            "title": "Private Space",
            "summary": "Private Space",
            "discoverability": "invite_only",
            "history_access": "all_history_for_current_members",
            "plaintext_visible_services": [server.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("create_realm response missing string realm_id: {created}"))?
        .to_owned();
    let strand_id = created["default_strand_id"]
        .as_str()
        .ok_or_else(|| anyhow!("create_realm response missing default_strand_id: {created}"))?
        .to_owned();

    let anonymous_search = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-realms"))
            .json(&arkret_models_discovery::DirectorySearchRealmsRequestBody {
                query: Some("Private Space".to_owned()),
                cursor: None,
                limit: None,
            }),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_search["realms"].as_array().unwrap().is_empty(),
        "invite-only realm leaked into anonymous search: {}",
        serde_json::to_string_pretty(&anonymous_search)?
    );

    let non_member_event = bob
        .author_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload(&strand_id, "not a member")?,
        )
        .await?;
    expect_api_error(
        bob.authorize(server.http().post(server.url("/_arkret/self/events")))
            .json(&crate::publication::initial_submission(
                non_member_event,
                "",
            )?),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let pre_member_commit = current_commit_id(&alice, &realm_id).await?;
    alice.add_member(&realm_id, &bob).await?;
    await_commit_advance(&alice, &realm_id, &pre_member_commit).await?;
    alice
        .grant_realm_actions_to_client(&realm_id, &bob, &["ak.message.create"])
        .await?;
    bob.submit_event(
        &realm_id,
        "ak.message.create",
        message_create_text_payload(&strand_id, "member can send")?,
    )
    .await?;

    let before_destroy = alice.realm_seal_frontier(&realm_id).await?;
    let destroy = alice
        .author_event(
            &realm_id,
            "ak.realm.destroy",
            json!({"reason": "owner_requested"}),
        )
        .await?;
    let problem = expect_api_error(
        alice
            .authorize(server.http().post(server.url("/_arkret/self/events")))
            .json(&crate::publication::initial_submission(destroy, "")?),
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    assert_ne!(
        problem
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str),
        Some("realm_terminal_state"),
        "reserved terminal reason_code: {problem:?}"
    );
    assert_eq!(
        alice.realm_seal_frontier(&realm_id).await?,
        before_destroy,
        "forbidden destroy changed the accepted Event/Commit stream"
    );
    let successor = alice.create_realm("Successor Space").await?;
    // A prepared member write cannot cross the accepted terminal fence.
    let after_tombstone = bob
        .author_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload(&strand_id, "after delete")?,
        )
        .await?;
    let duplicate_terminal = alice
        .author_event(
            &realm_id,
            "ak.realm.tombstone",
            json!({"reason":"repeat", "successor_realm_id": successor}),
        )
        .await?;
    let restore_terminal = alice
        .author_event(&realm_id, "ak.realm.restore", json!({}))
        .await?;
    alice
        .submit_event(
            &realm_id,
            "ak.realm.tombstone",
            json!({"reason": "migrated", "successor_realm_id": successor}),
        )
        .await?;
    let problem = expect_api_error(
        bob.authorize(server.http().post(server.url("/_arkret/self/events")))
            .json(&crate::publication::initial_submission(
                after_tombstone,
                "",
            )?),
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    assert_ne!(
        problem
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str),
        Some("realm_terminal_state"),
        "reserved terminal reason_code: {problem:?}"
    );

    let after_terminal = alice.realm_seal_frontier(&realm_id).await?;
    let before_events = before_destroy["committed_events"]
        .as_array()
        .ok_or_else(|| anyhow!("pre-terminal stream missing committed_events"))?;
    let after_events = after_terminal["committed_events"]
        .as_array()
        .ok_or_else(|| anyhow!("post-terminal history missing committed_events"))?;
    assert_eq!(
        after_events.len(),
        before_events.len() + 1,
        "tombstone must admit exactly one Event and covering Commit"
    );
    assert_eq!(
        &after_events[..before_events.len()],
        before_events.as_slice(),
        "authorized retained history changed after terminal admission"
    );
    assert_eq!(
        after_events.last().unwrap()["event"]["kind"],
        "ak.realm.tombstone"
    );
    assert_eq!(
        after_events.last().unwrap()["event"]["payload"]["successor_realm_id"],
        successor
    );
    // Both members retain their authorized historical interval. The refused
    // pre-signed member write cannot install any Event or advance its head.
    assert_eq!(bob.realm_seal_frontier(&realm_id).await?, after_terminal);
    for event in [duplicate_terminal, restore_terminal] {
        let problem = expect_api_error(
            alice
                .authorize(server.http().post(server.url("/_arkret/self/events")))
                .json(&crate::publication::initial_submission(event, "")?),
            StatusCode::CONFLICT,
            "failed_precondition",
        )
        .await?;
        assert_ne!(
            problem
                .extensions
                .get("reason_code")
                .and_then(serde_json::Value::as_str),
            Some("realm_terminal_state"),
            "reserved terminal reason_code: {problem:?}"
        );
        assert_eq!(
            alice.realm_seal_frontier(&realm_id).await?,
            after_terminal,
            "terminal refusal changed the retained Event/Commit stream"
        );
    }

    Ok(())
}

async fn current_commit_id(
    client: &crate::harness::TestActorClient,
    realm_id: &str,
) -> Result<String> {
    client.realm_seal_frontier(realm_id).await?["committed_events"]
        .as_array()
        .and_then(|events| events.last())
        .and_then(|event| event.get("commit"))
        .and_then(|commit| commit.get("commit_id"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("Realm stream omitted current commit_id"))
}

async fn await_commit_advance(
    client: &crate::harness::TestActorClient,
    realm_id: &str,
    predecessor: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if current_commit_id(client, realm_id).await? != predecessor {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("membership Control Move was not committed"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
