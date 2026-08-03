use std::sync::LazyLock;

use anyhow::{Result, anyhow};
use arkret_models_collaboration::event_sync::{
    EventsFrontierAccountClientState, EventsFrontierView,
};
use cotest::harness::{
    ArkretServer, create_realm_with_signing_seed, event_envelope_at_frontier_with_signing_seed,
    expect_json, register_account,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use serial_test::serial;

const DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000f101";
const SIGNING_SEED: [u8; 32] = [21_u8; 32];
static ACTOR: LazyLock<String> = LazyLock::new(|| {
    let key = ed25519_dalek::SigningKey::from_bytes(&SIGNING_SEED);
    format!(
        "did:key:{}",
        arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            key.verifying_key().as_bytes()
        )
    )
});

async fn frontier(
    server: &ArkretServer,
    token: &str,
    realm_id: &str,
) -> Result<arkret_models_collaboration::event_sync::RealmActorFrontierView> {
    let value = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/events/frontier"))
            .query(&[("realm_id", realm_id), ("actor_id", ACTOR.as_str())])
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    let state: EventsFrontierAccountClientState = serde_json::from_value(value)?;
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
            .get(server.url("/_arkret/self/events/frontier"))
            .query(&[("realm_id", realm_id)])
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    let state: EventsFrontierAccountClientState = serde_json::from_value(value)?;
    let EventsFrontierView::RealmSeal(frontier) = state.frontier else {
        return Err(anyhow!("Realm selector returned a non-Seal frontier"));
    };
    Ok(frontier.seal_basis())
}

fn bind_seal_ref(event: &mut arkret_wire::Event, basis: &arkret_wire::SealBasis) -> Result<()> {
    let seal_ref = basis
        .leaves
        .first()
        .ok_or_else(|| anyhow!("Realm Seal frontier has no leaf"))?;
    event.seal_ref = Some(seal_ref.clone());
    event.auth_context = Some(arkret_wire::AuthContext {
        did: ACTOR.clone(),
        key_id: format!("{}#cotest", ACTOR.as_str()),
        key_epoch: 0,
        credential_epoch: None,
    });
    event.authorization_ref = Some(arkret_wire::AuthorizationRef::new(
        arkret_wire::REALM_AUTHORITY_ROOT_CELL,
    )?);
    cotest::harness::refresh_typed_event_proof_with_signing_seed(event, SIGNING_SEED)
}

fn strand_payload(realm_id: &str, suffix: &str) -> Value {
    json!({
        "object": {
            "id": format!("ak:strand:01904100-0000-7000-8000-{suffix}"),
            "schema": "ak.schema.strand.v1",
            "realm_id": realm_id,
            "tracks": {"discussion": {"enabled": true, "is_primary": true}},
            "created_by": ACTOR.as_str(),
            "created_at": "2026-05-02T00:00:00.000Z",
            "metadata": {"title": format!("Frontier {suffix}")}
        }
    })
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
    let token = register_account(&server, ACTOR.as_str(), "@frontier-alice", DEVICE).await?;
    let realm_a = create_realm_with_signing_seed(
        &server,
        &token,
        ACTOR.as_str(),
        "Frontier Realm A",
        SIGNING_SEED,
    )
    .await?;
    let realm_b = create_realm_with_signing_seed(
        &server,
        &token,
        ACTOR.as_str(),
        "Frontier Realm B",
        SIGNING_SEED,
    )
    .await?;

    let basis_a = frontier(&server, &token, &realm_a).await?;
    let basis_b = frontier(&server, &token, &realm_b).await?;
    assert_eq!(basis_a.next_actor_seq, basis_b.next_actor_seq);
    assert_ne!(basis_a.frontier_digest, basis_b.frontier_digest);

    let current_seal_basis = seal_basis(&server, &token, &realm_a).await?;
    let mut sibling_a = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f111"),
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids.clone(),
        SIGNING_SEED,
    );
    let mut sibling_b = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f112"),
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids.clone(),
        SIGNING_SEED,
    );
    bind_seal_ref(&mut sibling_a, &current_seal_basis)?;
    bind_seal_ref(&mut sibling_b, &current_seal_basis)?;
    for event in [&sibling_b, &sibling_a] {
        let response = submit_bytes(&server, &token, submission_bytes(event)?).await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            response.text().await?
        );
    }

    let siblings = frontier(&server, &token, &realm_a).await?;
    assert_eq!(siblings.next_actor_seq, basis_a.next_actor_seq + 1);
    let mut expected_ids = vec![sibling_a.event_id.clone(), sibling_b.event_id.clone()];
    expected_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(siblings.frontier_event_ids, expected_ids);
    assert_eq!(frontier(&server, &token, &realm_b).await?, basis_b);

    let mut merge = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f113"),
        siblings.next_actor_seq,
        siblings.frontier_event_ids.clone(),
        SIGNING_SEED,
    );
    bind_seal_ref(&mut merge, &seal_basis(&server, &token, &realm_a).await?)?;
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
    assert_eq!(stored_merge["event"]["actor_id"], ACTOR.as_str());
    assert_eq!(
        stored_merge["event"]["actor_seq"],
        current_sequence(&merge)?
    );

    let mut stale = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f114"),
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids,
        SIGNING_SEED,
    );
    bind_seal_ref(&mut stale, &seal_basis(&server, &token, &realm_a).await?)?;
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

    let current = frontier(&server, &token, &realm_a).await?;
    let mut replacement = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f114"),
        current.next_actor_seq,
        current.frontier_event_ids,
        SIGNING_SEED,
    );
    bind_seal_ref(
        &mut replacement,
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
