use anyhow::{Result, anyhow};
use arkret_models_collaboration::event_sync::{
    EventsFrontierState, EventsFrontierView, SealFrontierState,
};
use cotest::harness::{
    ArkretServer, create_realm_with_signing_seed, default_event_verification_method,
    event_envelope_at_frontier_with_signing_seed, events_frontier_request_body, expect_json,
    query_method,
};
use cotest::scenarios::identity_test_support::{
    ActorBootstrapRegistration, actor_did_for_service_full_id, bootstrap_registered_actor,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use serial_test::serial;

fn signing_seed(actor: &str) -> [u8; 32] {
    arkret::signatures::development_signing_key_seed(&default_event_verification_method(actor))
}

fn actor_core_id(actor: &str) -> Result<String> {
    cotest::harness::actor_core_id(actor)
}

async fn frontier(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
) -> Result<arkret_models_collaboration::event_sync::RealmActorFrontierView> {
    let value = expect_json(
        server
            .http()
            .request(query_method(), server.url("/_arkret/self/events/frontier"))
            .json(&events_frontier_request_body(actor, Some(realm_id))?)
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    let state: EventsFrontierState = serde_json::from_value(value)?;
    let EventsFrontierView::RealmActor(frontier) = state.frontier else {
        return Err(anyhow!(
            "combined selector returned a non-authoring frontier"
        ));
    };
    frontier.validate()?;
    Ok(frontier)
}

async fn seal_basis(
    server: &ArkretServer,
    token: &str,
    realm_id: &str,
) -> Result<arkret_wire::SealBasis> {
    let value = expect_json(
        server
            .http()
            .request(query_method(), server.url("/_arkret/self/seals/frontier"))
            .json(&serde_json::json!({"realm_id": realm_id}))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    let state: SealFrontierState = serde_json::from_value(value)?;
    Ok(state.frontier.seal_basis())
}

fn bind_seal_ref(
    event: &mut arkret_wire::Event,
    actor: &str,
    basis: &arkret_wire::SealBasis,
) -> Result<()> {
    let seal_ref = basis
        .leaves
        .first()
        .ok_or_else(|| anyhow!("Realm Seal frontier has no leaf"))?;
    event.seal_ref = Some(seal_ref.clone());
    event.auth_context = Some(arkret_wire::AuthContext {
        key_id: cotest::harness::auth_context_key_id(
            default_event_verification_method(actor).as_str(),
        ),
        key_epoch: 0,
        credential_epoch: None,
    });
    event.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
            .map_err(anyhow::Error::msg)?,
    );
    cotest::harness::refresh_typed_event_proof_with_signing_seed(event, signing_seed(actor))
}

/// A Strand create whose only per-sibling difference is its title.
///
/// The object id is not authored: a Strand id is `retype(event_id)` of its own
/// create, so `suffix` exists solely to keep concurrent siblings distinct in
/// the digest preimage.
fn strand_payload(actor: &str, realm_id: &str, suffix: &str) -> Result<Value> {
    Ok(json!({
        "object": {
            "schema": "ak.schema.strand.v1",
            "realm_id": realm_id,
            "tracks": {"discussion": {"enabled": true, "is_primary": true}},
            "created_by": actor_core_id(actor)?,
            "created_at": "2026-05-02T00:00:00.000Z",
            "metadata": {"title": format!("Frontier {suffix}")}
        }
    }))
}

async fn submit_bytes(
    server: &ArkretServer,
    token: &str,
    bytes: Vec<u8>,
) -> Result<reqwest::Response> {
    Ok(server
        .http()
        .post(server.url("/_arkret/self/events"))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await?)
}

fn submission_bytes(event: &arkret_wire::Event) -> Result<Vec<u8>> {
    let submission = cotest::publication::initial_submission(event.clone(), "")?;
    Ok(arkret_canonical::canonical_json_bytes(&submission)?)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn realm_scoped_siblings_lost_response_and_cas_reauthor_are_live() -> Result<()> {
    let server = match std::env::var("COTEST_SOLAND_DATABASE_URL") {
        Ok(database_url) => {
            ArkretServer::spawn_with_database_url(
                "realm-actor-frontier-e2e-postgres",
                &database_url,
                &[("SOLAND_KEYSTORE_BACKEND", "platform")],
            )
            .await?
        }
        Err(_) => ArkretServer::spawn("realm-actor-frontier-e2e-memory").await?,
    };
    let actor = actor_did_for_service_full_id(server.service_full_id(), "frontier-alice")?;
    let actor = actor.as_str();
    let verification_method = default_event_verification_method(actor).to_string();
    let device_id = verification_method
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| anyhow!("default Event verification method has no device fragment"))?;
    // Canonical actor provisioning (device-lifecycle.md section 5.1): account
    // registration plus the closed PCR genesis unit, so the founding device
    // holds an accepted `ak.device.authorize` before any durable write.
    let (_principal, token) = bootstrap_registered_actor(
        &server,
        actor,
        device_id,
        ActorBootstrapRegistration::Account {
            handle: "@frontier-alice",
        },
    )
    .await?;
    let realm_a = create_realm_with_signing_seed(
        &server,
        &token,
        actor,
        "Frontier Realm A",
        signing_seed(actor),
    )
    .await?;
    let realm_b = create_realm_with_signing_seed(
        &server,
        &token,
        actor,
        "Frontier Realm B",
        signing_seed(actor),
    )
    .await?;

    let basis_a = frontier(&server, &token, actor, &realm_a).await?;
    let basis_b = frontier(&server, &token, actor, &realm_b).await?;
    assert_eq!(basis_a.next_actor_seq, basis_b.next_actor_seq);
    assert_ne!(basis_a.frontier_digest, basis_b.frontier_digest);

    let current_seal_basis = seal_basis(&server, &token, &realm_a).await?;
    let mut sibling_a = event_envelope_at_frontier_with_signing_seed(
        actor,
        &realm_a,
        "ak.strand.create",
        strand_payload(actor, &realm_a, "00000000f111")?,
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids.clone(),
        signing_seed(actor),
    );
    let mut sibling_b = event_envelope_at_frontier_with_signing_seed(
        actor,
        &realm_a,
        "ak.strand.create",
        strand_payload(actor, &realm_a, "00000000f112")?,
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids.clone(),
        signing_seed(actor),
    );
    bind_seal_ref(&mut sibling_a, actor, &current_seal_basis)?;
    bind_seal_ref(&mut sibling_b, actor, &current_seal_basis)?;
    for event in [&sibling_b, &sibling_a] {
        let response = submit_bytes(&server, &token, submission_bytes(event)?).await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            response.text().await?
        );
    }

    let siblings = frontier(&server, &token, actor, &realm_a).await?;
    assert_eq!(siblings.next_actor_seq, basis_a.next_actor_seq + 1);
    let mut expected_ids = vec![sibling_a.event_id.clone(), sibling_b.event_id.clone()];
    expected_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(siblings.frontier_event_ids, expected_ids);
    assert_eq!(frontier(&server, &token, actor, &realm_b).await?, basis_b);

    let mut merge = event_envelope_at_frontier_with_signing_seed(
        actor,
        &realm_a,
        "ak.strand.create",
        strand_payload(actor, &realm_a, "00000000f113")?,
        siblings.next_actor_seq,
        siblings.frontier_event_ids.clone(),
        signing_seed(actor),
    );
    bind_seal_ref(
        &mut merge,
        actor,
        &seal_basis(&server, &token, &realm_a).await?,
    )?;
    let exact_body = submission_bytes(&merge)?;
    let lost = submit_bytes(&server, &token, exact_body.clone()).await?;
    assert_eq!(lost.status(), StatusCode::OK);
    drop(lost);
    let duplicate = submit_bytes(&server, &token, exact_body.clone()).await?;
    assert_eq!(duplicate.status(), StatusCode::OK);
    let duplicate_body: Value = duplicate.json().await?;
    assert_eq!(duplicate_body["status"], "duplicate");
    let merge_event_id = merge.event_id.as_str();
    let stored_merge = expect_json(
        server
            .http()
            .get(server.url(&format!("/_arkret/self/events/{merge_event_id}")))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(stored_merge["event"]["realm_id"], realm_a);
    assert_eq!(stored_merge["event"]["actor_id"], actor_core_id(actor)?);
    assert_eq!(
        stored_merge["event"]["actor_seq"],
        current_sequence(&merge)?
    );

    let mut stale = event_envelope_at_frontier_with_signing_seed(
        actor,
        &realm_a,
        "ak.strand.create",
        strand_payload(actor, &realm_a, "00000000f114")?,
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids,
        signing_seed(actor),
    );
    bind_seal_ref(
        &mut stale,
        actor,
        &seal_basis(&server, &token, &realm_a).await?,
    )?;
    let stale_response = submit_bytes(&server, &token, submission_bytes(&stale)?).await?;
    assert_eq!(stale_response.status(), StatusCode::CONFLICT);
    let conflict: Value = stale_response.json().await?;
    assert_eq!(conflict["error"]["code"], "cas_conflict");
    assert_eq!(conflict["error"]["details"]["accepted"], false);
    let stale_event_id = stale.event_id.as_str();
    let stale_lookup = server
        .http()
        .get(server.url(&format!("/_arkret/self/events/{stale_event_id}")))
        .bearer_auth(&token)
        .send()
        .await?;
    assert_eq!(stale_lookup.status(), StatusCode::NOT_FOUND);

    let current = frontier(&server, &token, actor, &realm_a).await?;
    let mut replacement = event_envelope_at_frontier_with_signing_seed(
        actor,
        &realm_a,
        "ak.strand.create",
        strand_payload(actor, &realm_a, "00000000f114")?,
        current.next_actor_seq,
        current.frontier_event_ids,
        signing_seed(actor),
    );
    bind_seal_ref(
        &mut replacement,
        actor,
        &seal_basis(&server, &token, &realm_a).await?,
    )?;
    assert_ne!(stale.event_id, replacement.event_id);
    let accepted = submit_bytes(&server, &token, submission_bytes(&replacement)?).await?;
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "{}",
        accepted.text().await?
    );
    let replacement_event_id = replacement.event_id.as_str();
    expect_json(
        server
            .http()
            .get(server.url(&format!("/_arkret/self/events/{replacement_event_id}")))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

fn current_sequence(event: &arkret_wire::Event) -> Result<u64> {
    Ok(event.actor_seq)
}
