use std::sync::LazyLock;

use anyhow::{Result, anyhow};
use arkret_identifiers::EventId;
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

    let sibling_a = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f111"),
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids.clone(),
        SIGNING_SEED,
    );
    let sibling_b = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f112"),
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids.clone(),
        SIGNING_SEED,
    );
    for event in [&sibling_b, &sibling_a] {
        let response = submit_bytes(&server, &token, serde_json::to_vec(event)?).await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            response.text().await?
        );
    }

    let siblings = frontier(&server, &token, &realm_a).await?;
    assert_eq!(siblings.next_actor_seq, basis_a.next_actor_seq + 1);
    let mut expected_ids = vec![
        serde_json::from_value::<EventId>(sibling_a["event_id"].clone())?,
        serde_json::from_value::<EventId>(sibling_b["event_id"].clone())?,
    ];
    expected_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(siblings.frontier_event_ids, expected_ids);
    assert_eq!(frontier(&server, &token, &realm_b).await?, basis_b);

    let merge = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f113"),
        siblings.next_actor_seq,
        siblings.frontier_event_ids.clone(),
        SIGNING_SEED,
    );
    let exact_body = arkret_canonical::canonical_json_bytes(&merge)?;
    let lost = submit_bytes(&server, &token, exact_body.clone()).await?;
    assert_eq!(lost.status(), StatusCode::OK);
    drop(lost);
    let duplicate = submit_bytes(&server, &token, exact_body.clone()).await?;
    assert_eq!(duplicate.status(), StatusCode::OK);
    let duplicate_body: Value = duplicate.json().await?;
    assert_eq!(duplicate_body["status"], "duplicate");
    let merge_event_id = merge["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("merge event has no event_id"))?;
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

    let stale = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f114"),
        basis_a.next_actor_seq,
        basis_a.frontier_event_ids,
        SIGNING_SEED,
    );
    let stale_response = submit_bytes(&server, &token, serde_json::to_vec(&stale)?).await?;
    assert_eq!(stale_response.status(), StatusCode::CONFLICT);
    let conflict: Value = stale_response.json().await?;
    assert_eq!(conflict["error"]["code"], "cas_conflict");
    assert_eq!(conflict["error"]["details"]["accepted"], false);
    let stale_event_id = stale["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("stale event has no event_id"))?;
    let stale_lookup = server
        .http()
        .get(server.url(&format!("/_arkret/self/events/{stale_event_id}")))
        .bearer_auth(&token)
        .send()
        .await?;
    assert_eq!(stale_lookup.status(), StatusCode::NOT_FOUND);

    let current = frontier(&server, &token, &realm_a).await?;
    let replacement = event_envelope_at_frontier_with_signing_seed(
        ACTOR.as_str(),
        &realm_a,
        "ak.strand.create",
        strand_payload(&realm_a, "00000000f114"),
        current.next_actor_seq,
        current.frontier_event_ids,
        SIGNING_SEED,
    );
    assert_ne!(stale["event_id"], replacement["event_id"]);
    let accepted = submit_bytes(&server, &token, serde_json::to_vec(&replacement)?).await?;
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "{}",
        accepted.text().await?
    );
    let replacement_event_id = replacement["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("replacement event has no event_id"))?;
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

fn current_sequence(event: &Value) -> Result<u64> {
    event["actor_seq"]
        .as_u64()
        .ok_or_else(|| anyhow!("event has no actor_seq"))
}
