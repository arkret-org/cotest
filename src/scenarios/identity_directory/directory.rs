use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow};
use arkret_canonical::canonical_sha256;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{actor_core_id, expect_api_error, expect_json, invite_create_payload};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_full_id, seal_current_principal_control_frontier,
    spawn_with_harness_account_authority,
};

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
    let server = spawn_with_harness_account_authority("directory-privacy", &[]).await?;
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), "privacy-alice")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let alice_device_key = alice
        .principal
        .as_ref()
        .context("alice carries her provisioned principal")?
        .device_signing_key
        .clone();
    // Register account-first, then publish bob's primary localpart through the
    // authenticated localpart lifecycle. Soland derives the canonical handle
    // domain and signed handle claim from that binding.
    let bob_did = actor_did_for_service_full_id(server.service_full_id(), "privacy-bob")?;
    let bob = server
        .register_client_with_localpart(
            &bob_did,
            "@bob-privacy",
            "bob-privacy-example",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let bob_device_key = bob
        .principal
        .as_ref()
        .context("bob carries his provisioned principal")?
        .device_signing_key
        .clone();
    let service_host = server
        .base_url()
        .host_str()
        .ok_or_else(|| anyhow!("server base_url omitted its host"))?
        .to_owned();

    let public_realm = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Public",
            "discoverability": "public"
        }))
        .await?;
    let listed_realm = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Listed",
            "discoverability": "listed"
        }))
        .await?;
    let restricted_realm = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Restricted",
            "discoverability": "restricted"
        }))
        .await?;
    let unlisted_realm = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Unlisted",
            "discoverability": "unlisted"
        }))
        .await?;
    let invite_only_realm = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Invite Only",
            "discoverability": "invite_only",
            "invitees": [bob.actor.clone()]
        }))
        .await?;
    let secret_realm = alice
        .create_realm_with(json!({
            "title": "Visibility Matrix Secret",
            "discoverability": "secret"
        }))
        .await?;

    let public_realm_id = realm_id_from(&public_realm, "public")?;
    let listed_realm_id = realm_id_from(&listed_realm, "listed")?;
    let restricted_realm_id = realm_id_from(&restricted_realm, "restricted")?;
    let unlisted_realm_id = realm_id_from(&unlisted_realm, "unlisted")?;
    let invite_only_realm_id = realm_id_from(&invite_only_realm, "invite_only")?;
    let secret_realm_id = realm_id_from(&secret_realm, "secret")?;

    let introduction_evidence = json!({"kind": "same_principal_server"});
    let invite_expires_at = chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    let invite_event = alice
        .submit_event(
            &invite_only_realm_id,
            "ak.invite.create",
            invite_create_payload(
                bob.actor.as_str(),
                server.service_id().as_str(),
                canonical_sha256(&introduction_evidence)?,
                invite_expires_at,
            )?,
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
            .post(server.url("/_arkret/find/directory/search-realms"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchRealmsRequestBody,
            >(
                json!({"query": "Visibility Matrix", "limit": 20})
            )?),
        StatusCode::OK,
    )
    .await?;
    let anonymous_search_ids: BTreeSet<_> = anonymous_search["realms"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|space| space["realm_id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        anonymous_search_ids,
        BTreeSet::from([
            public_realm_id.clone(),
            listed_realm_id.clone(),
            restricted_realm_id.clone(),
        ])
    );

    for resolvable_realm_id in [
        &public_realm_id,
        &listed_realm_id,
        &restricted_realm_id,
        &unlisted_realm_id,
    ] {
        let resolved = expect_json(
            server
                .http()
                .post(server.url("/_arkret/find/directory/resolve-realm"))
                .json(&serde_json::from_value::<
                    arkret_models_discovery::DirectoryResolveRealmRequestBody,
                >(
                    json!({"realm_id": resolvable_realm_id.as_str()})
                )?),
            StatusCode::OK,
        )
        .await?;
        assert_eq!(
            resolved["realm_preview"]["realm_id"],
            resolvable_realm_id.as_str()
        );
    }

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectoryResolveRealmRequestBody,
            >(
                json!({"realm_id": invite_only_realm_id.clone()})
            )?),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectoryResolveRealmRequestBody,
            >(json!({"realm_id": secret_realm_id.clone()}))?),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let invites = expect_json(bob.get("/_arkret/self/authz/invites"), StatusCode::OK).await?;
    let invite_token = invites["invites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|invite| invite["realm_id"].as_str() == Some(invite_only_realm_id.as_str()))
        .and_then(|invite| invite["join_rule_snapshot"]["invite_token"].as_str())
        .ok_or_else(|| anyhow!("missing invite token for invite-only Realm: {invites}"))?;
    let invite_only_resolved = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectoryResolveRealmRequestBody,
            >(json!({
                "realm_id": invite_only_realm_id.clone(),
                "invite_token": invite_token
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        invite_only_resolved["realm_preview"]["realm_id"],
        invite_only_realm_id
    );

    let secret_resolved = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectoryResolveRealmRequestBody,
            >(json!({
                "realm_id": secret_realm_id.clone(),
                "signed_link": "cotest-signed-link"
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        secret_resolved["realm_preview"]["realm_id"],
        secret_realm_id
    );

    let anonymous_bob_actors = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-actors"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchActorsRequestBody,
            >(json!({"query": "bob-privacy"}))?),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_bob_actors["actors"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let anonymous_bob_users = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-users"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchUsersRequestBody,
            >(json!({"query": "bob-privacy"}))?),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_bob_users["users"]
            .as_array()
            .expect("search-users response users")
            .is_empty()
    );

    let anonymous_alice = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-actors"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchActorsRequestBody,
            >(json!({"query": "alice"}))?),
        StatusCode::OK,
    )
    .await?;
    let demo_alice_core_id = actor_core_id("did:web:alice.example")?;
    assert!(
        anonymous_alice["actors"]
            .as_array()
            .expect("search-actors response actors")
            .iter()
            .any(|actor| actor["actor_id"].as_str() == Some(demo_alice_core_id.as_str())),
        "public demo Alice identity was not anonymously discoverable: {anonymous_alice}"
    );

    let alice_before_contact = expect_json(
        alice
            .post("/_arkret/find/directory/search-actors")
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchActorsRequestBody,
            >(json!({"query": "bob-privacy"}))?),
        StatusCode::OK,
    )
    .await?;
    assert!(
        alice_before_contact["actors"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let bob_self = expect_json(
        bob.post("/_arkret/find/directory/search-actors")
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchActorsRequestBody,
            >(json!({"query": "bob-privacy"}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        bob_self["actors"][0]["actor_id"],
        actor_core_id(&bob.actor)?
    );

    let request_receipt = alice.request_contact(&bob.actor).await?;
    seal_current_principal_control_frontier(&alice, &alice_device_key).await?;
    bob.accept_contact(request_receipt).await?;
    seal_current_principal_control_frontier(&bob, &bob_device_key).await?;

    let alice_after_contact = expect_json(
        alice
            .post("/_arkret/find/directory/search-actors")
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchActorsRequestBody,
            >(json!({"query": "bob-privacy"}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        alice_after_contact["actors"][0]["actor_id"],
        actor_core_id(&bob.actor)?
    );

    let alice_user_after_contact = expect_json(
        alice
            .post("/_arkret/find/directory/search-users")
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchUsersRequestBody,
            >(json!({"query": "bob-privacy"}))?),
        StatusCode::OK,
    )
    .await?;
    // `service_host` (computed at registration above) is the authority soland
    // derives via `service_handle_domain` from the SUT bind host, so the
    // published handle round-trips as `bob-privacy-example:<host>`.
    assert_eq!(
        alice_user_after_contact["users"][0]["handle"],
        format!("bob-privacy-example:{service_host}")
    );

    let anonymous_after_contact = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-actors"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchActorsRequestBody,
            >(json!({"query": "bob-privacy"}))?),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_after_contact["actors"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    Ok(())
}
