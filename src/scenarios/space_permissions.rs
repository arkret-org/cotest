use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ArkretServer, add_member, create_realm, expect_api_error, expect_json,
    member_join_payload_value, message_create_text_payload,
};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn space_creation_and_owner_only_mutations_are_enforced() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = crate::fixtures::TestScaffold::fresh("space-permissions").await?;
    let server = scaffold.server();
    let alice_did = actor_did_for_service_did(server.service_did(), "space-alice")?;
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-space")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob = server
        .register_client(
            &bob_did,
            "@bob-space",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    expect_api_error(
        server.http().post(server.url("/_soland/self/spaces")).json(
            &crate::harness::NonProtocolTestBody::new(json!({"title": "No Auth"})),
        ),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    let realm_id = create_realm(server, &alice.token, &alice_did, "Permission Space").await?;
    let mut unauthorized_join = alice
        .author_event(
            &realm_id,
            "ak.member.state",
            member_join_payload_value(&realm_id, &bob_did)?,
        )
        .await?;
    rebind_authored_event(&mut unauthorized_join, &bob.actor)?;
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
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&bob.token)
            .json(&unauthorized_submission),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .delete(server.url(&format!("/_soland/self/spaces/{realm_id}")))
            .bearer_auth(&alice.token),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}

pub async fn private_visibility_non_member_send_and_deleted_space_edges() -> Result<()> {
    let server = ArkretServer::spawn("space-visibility").await?;
    let alice_did = actor_did_for_service_did(server.service_did(), "visible-alice")?;
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-visible")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob = server
        .register_client(
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
                organization_principal_id: None,
                source_realm_id: None,
                requester_id: None,
                proof_challenge: None,
                claim_presentations: Vec::new(),
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

    let mut non_member_event = alice
        .author_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload(&strand_id, "not a member")?,
        )
        .await?;
    rebind_authored_event(&mut non_member_event, &bob.actor)?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&bob.token)
            .json(&crate::publication::initial_submission(
                non_member_event,
                "",
            )?),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let pre_member_seal = current_seal_id(&alice, &realm_id).await?;
    add_member(&server, &alice.token, &alice_did, &realm_id, &bob_did).await?;
    await_seal_advance(&alice, &realm_id, &pre_member_seal).await?;
    alice
        .grant_realm_actions_to_client(&realm_id, &bob, &["ak.message.create"])
        .await?;
    bob.submit_event(
        &realm_id,
        "ak.message.create",
        message_create_text_payload(&strand_id, "member can send")?,
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
            message_create_text_payload(&strand_id, "after delete")?,
        )
        .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&alice.token)
            .json(&crate::publication::initial_submission(after_destroy, "")?),
        StatusCode::CONFLICT,
        // The top-level wire error code is `failed_precondition`; the
        // terminal-state condition is carried as the `realm_terminal_state`
        // sub-reason (it is a spec `reason_code`, not a top-level error code).
        "failed_precondition",
    )
    .await?;

    Ok(())
}

fn rebind_authored_event(event: &mut arkret_wire::Event, actor: &str) -> Result<()> {
    let verification_method = crate::harness::default_event_verification_method(actor).to_string();
    let actor_did = arkret_identifiers::Did::new(actor.to_owned())?;
    event.actor_id = arkret_identifiers::project_did_to_core_id(&actor_did)?;
    event.actor_seq = 0;
    event.prev_refs.clear();
    if event.kind.is_control_plane() {
        event.auth_context = None;
    } else {
        event.auth_context = Some(arkret_wire::AuthContext {
            key_id: crate::harness::auth_context_key_id(&verification_method),
            key_epoch: 0,
            credential_epoch: None,
        });
    }
    event
        .proofs
        .iter_mut()
        .find_map(|proof| match proof {
            arkret_wire::EventProof::Producer(proof) => Some(proof),
            arkret_wire::EventProof::PrincipalServerAdmission(_) => None,
        })
        .ok_or_else(|| anyhow!("authored Event has no proof"))?
        .verification_method =
        arkret_wire::DidUrl::new(verification_method).map_err(anyhow::Error::msg)?;
    crate::harness::refresh_typed_event_proof(event)
}

async fn current_seal_id(
    client: &crate::harness::TestActorClient,
    realm_id: &str,
) -> Result<String> {
    client.realm_seal_frontier(realm_id).await?["frontier"]["seal_basis"]["leaves"][0]
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
