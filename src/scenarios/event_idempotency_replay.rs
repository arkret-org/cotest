use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    TestActorClient, TestServerGroup, expect_json, message_create_text_payload_for_strand,
    parse_strand_id,
};
use crate::scenarios::_helpers::protocol_values::submitted_event_id;
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn duplicate_event_submit_is_idempotent_and_projects_once() -> Result<()> {
    let group = TestServerGroup::single("event-idempotency-replay").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_did(server.service_did(), "alice-replay")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm_id = create_test_realm(&alice, "Event Idempotency Replay").await?;
    let event = alice
        .author_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload_for_strand(
                parse_strand_id(&alice.default_strand_id(&realm_id)?)?,
                "idempotent replay body",
            )?,
        )
        .await?;

    let first = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first["status"], "committed");
    let event_id = submitted_event_id(&first)
        .ok_or_else(|| anyhow!("committed response names no Event: {first}"))?;
    assert_eq!(event_id, event.event_id.as_str());

    let duplicate = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(submitted_event_id(&duplicate), Some(event_id));
    assert_eq!(
        duplicate["commit"], first["commit"],
        "an exact duplicate answers with the original RealmCommit"
    );

    let committed = committed_realm_events(&alice, &realm_id).await?;
    assert_eq!(
        event_count(&committed, event_id),
        1,
        "the Realm stream commits the idempotent Event exactly once"
    );

    Ok(())
}

// Complement's transaction retry tests adapted to Arkret's content-addressed
// Event identity. Concurrent retransmission must not fork the actor chain.
pub async fn concurrent_event_retransmission_accepts_once_and_allows_the_next_write() -> Result<()>
{
    let group = TestServerGroup::single("concurrent-event-retransmission").await?;
    let server = group.server(0);
    let did = actor_did_for_service_did(server.service_did(), "concurrent-retransmission")?;
    let alice = server
        .standard_client(&did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm = alice
        .create_realm("Concurrent Event Retransmission")
        .await?;
    let strand = alice.default_strand_id(&realm)?;
    let event = alice
        .author_event(
            &realm,
            "ak.message.create",
            message_create_text_payload_for_strand(parse_strand_id(&strand)?, "concurrent Event")?,
        )
        .await?;
    let body = crate::publication::initial_submission(event.clone(), "")?;
    let submit = || {
        expect_json(
            alice.post("/_arkret/self/events").json(&body),
            StatusCode::OK,
        )
    };
    let (one, two, three) = tokio::join!(submit(), submit(), submit());
    let outcomes = [one?, two?, three?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|item| item["status"] == "committed")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|item| item["status"] == "duplicate")
            .count(),
        2
    );
    for outcome in &outcomes {
        assert_eq!(submitted_event_id(outcome), Some(event.event_id.as_str()));
    }
    let committed = outcomes
        .iter()
        .find(|item| item["status"] == "committed")
        .ok_or_else(|| anyhow!("no committed outcome"))?;
    for outcome in &outcomes {
        assert_eq!(
            outcome["commit"], committed["commit"],
            "every retransmission answers with the one RealmCommit"
        );
    }
    assert_eq!(
        event_count(
            &committed_realm_events(&alice, &realm).await?,
            event.event_id.as_str()
        ),
        1
    );
    let successor = alice
        .send_message(&realm, &strand, "after concurrent retransmission")
        .await?;
    let successor_id =
        submitted_event_id(&successor).ok_or_else(|| anyhow!("successor omitted Event ID"))?;
    let listed = committed_realm_events(&alice, &realm).await?;
    assert_eq!(event_count(&listed, event.event_id.as_str()), 1);
    assert_eq!(event_count(&listed, successor_id), 1);
    assert_eq!(event_kind_count(&listed, "ak.message.create"), 2);
    Ok(())
}

// api-conventions §6 scopes Idempotency-Key by authenticated actor. Two
// independent writers may legitimately choose the same human-readable key.
pub async fn idempotency_keys_are_isolated_between_authenticated_actors() -> Result<()> {
    let group = TestServerGroup::single("idempotency-actor-scope").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_did(server.service_did(), "key-scope-alice")?;
    let bob_did = actor_did_for_service_did(server.service_did(), "key-scope-bob")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob = server
        .standard_client(&bob_did, "ak:device:01904100-0000-7000-8000-0000000000b1")
        .await?;
    let realm_a = alice.create_realm("Alice key scope").await?;
    let realm_b = bob.create_realm("Bob key scope").await?;
    for (actor, realm) in [(&alice, &realm_a), (&bob, &realm_b)] {
        let strand = actor.default_strand_id(realm)?;
        let event = actor
            .author_event(
                realm,
                "ak.message.create",
                message_create_text_payload_for_strand(
                    parse_strand_id(&strand)?,
                    "actor-scoped retry",
                )?,
            )
            .await?;
        let body = crate::publication::initial_submission(event.clone(), "")?;
        let send = || {
            expect_json(
                actor
                    .post("/_arkret/self/events")
                    .header("Idempotency-Key", "same-key-two-actors")
                    .json(&body),
                StatusCode::OK,
            )
        };
        let first = send().await?;
        assert_eq!(first["status"], "committed");
        assert_eq!(submitted_event_id(&first), Some(event.event_id.as_str()));
        let replay = send().await?;
        assert_eq!(submitted_event_id(&replay), Some(event.event_id.as_str()));
        assert_eq!(replay["status"], "duplicate");
        assert_eq!(
            event_count(
                &committed_realm_events(actor, realm).await?,
                event.event_id.as_str()
            ),
            1
        );
    }
    Ok(())
}

/// Creates a Realm and returns the id the genesis Event derived.
///
/// A Realm id is `retype(event_id)` of its own create, so a caller cannot
/// choose one: naming a fixture id here and asserting the response echoes it
/// compares a placeholder against the real derived id.
async fn create_test_realm(alice: &TestActorClient, title: &str) -> Result<String> {
    let response = alice
        .create_realm_with(json!({
            "title": title,
            "summary": title,
            "public": true,
            "discoverability": "public",
            "join_rule": "public",
            "history_access": "all_history_for_current_members",
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    Ok(response["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("Realm create response has no realm_id"))?
        .to_owned())
}

/// Every committed Event of the Realm stream, read to its head. The submit
/// commits synchronously, so no read barrier is owed.
async fn committed_realm_events(
    client: &TestActorClient,
    realm_id: &str,
) -> Result<Vec<arkret_wire::Event>> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())?;
    let scanned = client
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            arkret_wire::CommitStreamRef::Realm { realm_id },
            None,
            200,
        )
        .await?;
    Ok(scanned
        .committed_events
        .iter()
        .filter_map(|item| item.reducer_input().cloned())
        .collect())
}

fn event_count(committed: &[arkret_wire::Event], event_id: &str) -> usize {
    committed
        .iter()
        .filter(|event| event.event_id.as_str() == event_id)
        .count()
}

fn event_kind_count(committed: &[arkret_wire::Event], kind: &str) -> usize {
    committed
        .iter()
        .filter(|event| event.kind.as_str() == kind)
        .count()
}
