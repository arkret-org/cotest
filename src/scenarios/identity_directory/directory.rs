use anyhow::{Context, Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{actor_core_id, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, seal_current_principal_control_frontier,
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
    let alice_did = actor_did_for_service_did(server.service_did(), "privacy-alice")?;
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
    let bob_did = actor_did_for_service_did(server.service_did(), "privacy-bob")?;
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
    let public_realm_id = realm_id_from(&public_realm, "public")?;

    // Realm creation and a public discoverability hint do not opt a resource
    // into a Directory. The signed discovery Event and announce/pull ingest
    // required by discovery-directory.md section 8 have not happened here.
    let anonymous_search = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-realms"))
            .json(&arkret_models_discovery::DirectorySearchRealmsRequestBody {
                query: Some("Visibility Matrix".to_owned()),
                organization_principal_id: None,
                source_realm_id: None,
                requester_id: None,
                proof_challenge: None,
                claim_presentations: Vec::new(),
                cursor: None,
                limit: Some(20),
            }),
        StatusCode::OK,
    )
    .await?;
    assert!(
        anonymous_search["realms"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "Directory indexed a Realm without bidirectional opt-in ingest: {anonymous_search}"
    );

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&arkret_models_discovery::DirectoryResolveRealmRequestBody {
                realm_id: Some(arkret_wire::RealmId::new(public_realm_id)?),
                alias: None,
                invite_token: None,
                signed_link: None,
                requester_id: None,
                proof_challenge: None,
                claim_presentations: Vec::new(),
            }),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let anonymous_bob_actors = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-actors"))
            .json(&arkret_models_discovery::DirectorySearchActorsRequestBody {
                query: Some("bob-privacy".to_owned()),
                realm_id: None,
                organization_principal_id: None,
                cursor: None,
                limit: None,
            }),
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
            .json(&arkret_models_discovery::DirectorySearchUsersRequestBody {
                query: "bob-privacy".to_owned(),
                realm_id: None,
                cursor: None,
                limit: None,
                intent: None,
            }),
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
            .json(&arkret_models_discovery::DirectorySearchActorsRequestBody {
                query: Some("alice".to_owned()),
                realm_id: None,
                organization_principal_id: None,
                cursor: None,
                limit: None,
            }),
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
        alice.post("/_arkret/find/directory/search-actors").json(
            &arkret_models_discovery::DirectorySearchActorsRequestBody {
                query: Some("bob-privacy".to_owned()),
                realm_id: None,
                organization_principal_id: None,
                cursor: None,
                limit: None,
            },
        ),
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
        bob.post("/_arkret/find/directory/search-actors").json(
            &arkret_models_discovery::DirectorySearchActorsRequestBody {
                query: Some("bob-privacy".to_owned()),
                realm_id: None,
                organization_principal_id: None,
                cursor: None,
                limit: None,
            },
        ),
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
        alice.post("/_arkret/find/directory/search-actors").json(
            &arkret_models_discovery::DirectorySearchActorsRequestBody {
                query: Some("bob-privacy".to_owned()),
                realm_id: None,
                organization_principal_id: None,
                cursor: None,
                limit: None,
            },
        ),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        alice_after_contact["actors"][0]["actor_id"],
        actor_core_id(&bob.actor)?
    );

    let alice_user_after_contact = expect_json(
        alice.post("/_arkret/find/directory/search-users").json(
            &arkret_models_discovery::DirectorySearchUsersRequestBody {
                query: "bob-privacy".to_owned(),
                realm_id: None,
                cursor: None,
                limit: None,
                intent: None,
            },
        ),
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
            .json(&arkret_models_discovery::DirectorySearchActorsRequestBody {
                query: Some("bob-privacy".to_owned()),
                realm_id: None,
                organization_principal_id: None,
                cursor: None,
                limit: None,
            }),
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
