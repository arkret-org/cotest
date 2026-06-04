use std::collections::BTreeSet;

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_api_error, expect_json};

/// Extract the `realm_id` string from a `create_realm` response, turning a
/// missing/non-string field into a located error instead of a context-free
/// `unwrap()` panic (the response originates from the service under test).
fn realm_id_from(created: &serde_json::Value, label: &str) -> Result<String> {
    created["realm_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("{label} create_realm response missing string realm_id: {created}"))
}

pub async fn directory_discoverability_and_actor_privacy_work() -> Result<()> {
    let server = CokretServer::spawn("directory-privacy").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-privacy.example", "@bob-privacy", "dev_bob")
        .await?;

    let public_space = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Public",
            "discoverability": "public"
        }))
        .await?;
    let listed_space = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Listed",
            "discoverability": "listed"
        }))
        .await?;
    let restricted_space = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Restricted",
            "discoverability": "restricted"
        }))
        .await?;
    let unlisted_space = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Unlisted",
            "discoverability": "unlisted"
        }))
        .await?;
    let invite_only_space = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Invite Only",
            "discoverability": "invite_only",
            "invitees": [bob.actor.clone()]
        }))
        .await?;
    let secret_space = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Secret",
            "discoverability": "secret"
        }))
        .await?;

    let public_space_id = realm_id_from(&public_space, "public")?;
    let listed_space_id = realm_id_from(&listed_space, "listed")?;
    let restricted_space_id = realm_id_from(&restricted_space, "restricted")?;
    let unlisted_space_id = realm_id_from(&unlisted_space, "unlisted")?;
    let invite_only_space_id = realm_id_from(&invite_only_space, "invite_only")?;
    let secret_space_id = realm_id_from(&secret_space, "secret")?;

    let invite_event = alice
        .submit_event(
            &invite_only_space_id,
            "ck.invite.create",
            json!({
                "invitee": bob.actor,
                "expires_at": "2026-12-31T00:00:00Z"
            }),
        )
        .await?;
    assert_eq!(
        invite_event["status"],
        "accepted",
        "invite event was not accepted: {}",
        serde_json::to_string_pretty(&invite_event)?
    );

    let anonymous_search = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/search-realms"))
            .json(&json!({"query": "Visibility Matrix", "limit": 20})),
        StatusCode::OK,
    )
    .await?;
    let anonymous_search_ids: BTreeSet<_> = anonymous_search["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|space| space["realm_id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        anonymous_search_ids,
        BTreeSet::from([
            public_space_id.clone(),
            listed_space_id.clone(),
            restricted_space_id.clone(),
        ])
    );

    for resolvable_space_id in [
        &public_space_id,
        &listed_space_id,
        &restricted_space_id,
        &unlisted_space_id,
    ] {
        let resolved = expect_json(
            server
                .http()
                .post(server.url("/_cokret/find/directory/resolve-realm"))
                .json(&json!({"realm_id": resolvable_space_id.as_str()})),
            StatusCode::OK,
        )
        .await?;
        assert_eq!(
            resolved["space_preview"]["realm_id"],
            resolvable_space_id.as_str()
        );
    }

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/find/directory/resolve-realm"))
            .json(&json!({"realm_id": invite_only_space_id.clone()})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/find/directory/resolve-realm"))
            .json(&json!({"realm_id": secret_space_id.clone()})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let invites = expect_json(bob.get("/_cokret/self/authz/invites"), StatusCode::OK).await?;
    let invite_token = invites["invites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|invite| invite["space_id"].as_str() == Some(invite_only_space_id.as_str()))
        .and_then(|invite| invite["invite_token"].as_str())
        .ok_or_else(|| anyhow!("missing invite token for invite-only space: {invites}"))?;
    let invite_only_resolved = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/resolve-realm"))
            .json(&json!({
                "realm_id": invite_only_space_id.clone(),
                "invite_token": invite_token
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        invite_only_resolved["space_preview"]["realm_id"],
        invite_only_space_id
    );

    let secret_resolved = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/resolve-realm"))
            .json(&json!({
                "realm_id": secret_space_id.clone(),
                "signed_link": "cotest-signed-link"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        secret_resolved["space_preview"]["realm_id"],
        secret_space_id
    );

    let anonymous_bob_actors = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/search-actors"))
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_bob_actors["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let anonymous_bob_users = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/search-users"))
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_bob_users["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let anonymous_alice = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/search-actors"))
            .json(&json!({"query": "alice"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        anonymous_alice["results"][0]["did"],
        "did:web:alice.example"
    );

    let alice_before_contact = expect_json(
        alice
            .post("/_cokret/find/directory/search-actors")
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        alice_before_contact["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let bob_self = expect_json(
        bob.post("/_cokret/find/directory/search-actors")
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bob_self["results"][0]["did"], bob.actor);

    expect_json(
        alice
            .post("/_soland/self/contacts/request")
            .json(&json!({"target": bob.actor})),
        StatusCode::CREATED,
    )
    .await?;
    expect_json(
        bob.post("/_soland/self/contacts/respond").json(&json!({
            "requester": alice.actor,
            "action": "accept"
        })),
        StatusCode::OK,
    )
    .await?;

    let alice_after_contact = expect_json(
        alice
            .post("/_cokret/find/directory/search-actors")
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(alice_after_contact["results"][0]["did"], bob.actor);

    let alice_user_after_contact = expect_json(
        alice
            .post("/_cokret/find/directory/search-users")
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        alice_user_after_contact["results"][0]["handle"],
        "bob-privacy:directory-privacy.cotest.local"
    );

    let anonymous_after_contact = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/search-actors"))
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_after_contact["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    Ok(())
}
