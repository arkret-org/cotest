//! A signed, closed-shape encrypted Message cannot claim plaintext poll replacement heads.

use anyhow::{Context as _, Result, ensure};
use arkret_models_crypto::{EncryptedEnvelope, EncryptedEnvelopeEncryptionContext};
use arkret_wire::{AuthoritySubmitRequest, EventAdmissionSubmission, EventKind, MessageId};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestServerGroup, expect_api_error};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, standard_client, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "encrypted-poll-closed";
const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002804";

#[derive(Debug, PartialEq, Eq)]
struct DurablePollState {
    realm_events: i64,
    realm_commits: i64,
    poll_responses: i64,
    current_response: String,
}

async fn durable_poll_state(
    database_url: &str,
    realm: &str,
    poll_event: &str,
) -> Result<DurablePollState> {
    let database_url = database_url.to_owned();
    let realm = realm.to_owned();
    let poll_event = poll_event.to_owned();
    tokio::task::spawn_blocking(move || -> Result<DurablePollState> {
        let mut db = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let realm_events = db
            .query_one("SELECT count(*) FROM canonical_events WHERE realm_id=$1", &[&realm])?
            .get(0);
        let realm_commits = db
            .query_one("SELECT count(*) FROM realm_commits WHERE realm_id=$1", &[&realm])?
            .get(0);
        let poll_responses = db.query_one(
            "SELECT count(*) FROM poll_response_inputs p JOIN canonical_events original ON original.pk=p.poll_event_pk WHERE original.envelope->>'event_id'=$1",
            &[&poll_event],
        )?.get(0);
        let current_response: String = db.query_one(
            "SELECT v.response_event_id FROM poll_state_current_votes v JOIN canonical_events original ON original.pk=v.poll_event_pk WHERE original.envelope->>'event_id'=$1",
            &[&poll_event],
        )?.get(0);
        Ok(DurablePollState {
            realm_events,
            realm_commits,
            poll_responses,
            current_response,
        })
    }).await?
}

pub async fn run() -> Result<()> {
    let Some(database) = database(GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Coland unavailable");
    };
    let station = group.server(0);
    let (alice, account) = standard_client(station, &coauth, "poll-closed-alice", DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&alice, "Encrypted poll closed", "public", &[station]).await?;
    let strand = alice.default_strand_id(&realm)?;
    let poll = alice
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            json!({
                "strand_id":strand,"track_name":"discussion",
                "content":{"kind":"ak.content.poll","body":"Choose one",
                    "poll":{"kind":"disclosed","max_selections":1,
                        "answers":[{"id":"a","text":{"kind":"ak.content.text","body":"A"}}]}}
            }),
        )
        .await?;
    submit_and_expect_commit(&alice, &account, DEVICE, &poll).await?;
    let poll_ref = MessageId::from_event_id(&poll.event_id);
    let first = alice
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            json!({
                "strand_id":strand,"track_name":"discussion",
                "content":{"kind":"ak.content.poll.response","body":"vote",
                    "poll_response":{"poll_ref":poll_ref,"selections":["a"]}}
            }),
        )
        .await?;
    submit_and_expect_commit(&alice, &account, DEVICE, &first).await?;
    let before = durable_poll_state(&database.connect_url, &realm, poll.event_id.as_str()).await?;
    ensure!(before.poll_responses == 1 && before.current_response == first.event_id.to_string());

    // Structurally valid ciphertext and exact accepted replacement references.
    // The asserted MLS state is deliberately not authoritative: the closed
    // content/heads shape must fail before an opaque ciphertext can enter poll admission.
    let encrypted = EncryptedEnvelope {
        version: "1.0".to_owned(),
        content_type: "application/vnd.arkret.message+json".to_owned(),
        encryption_context: EncryptedEnvelopeEncryptionContext::standard(0, poll.event_id.clone()),
        ciphertext: "Y2lwaGVydGV4dA".to_owned(),
    };
    let invalid = alice
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            json!({
                "strand_id":strand,"track_name":"discussion",
                "encrypted_content":encrypted,
                "poll_response_heads":[{
                    "poll_event_ref":poll.event_id,
                    "response_event_ref":first.event_id,
                }],
            }),
        )
        .await?;
    let request = AuthoritySubmitRequest::Event(EventAdmissionSubmission::new(invalid.clone()));
    expect_api_error(
        alice.post("/_arkret/self/events").json(&request),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await
    .context("encrypted Message with poll_response_heads was not rejected by the v1 shape gate")?;
    let after = durable_poll_state(&database.connect_url, &realm, poll.event_id.as_str()).await?;
    ensure!(
        after == before,
        "rejected ciphertext changed durable Event, Commit or PollState: {before:?} -> {after:?}"
    );
    let rejected_id = invalid.event_id.to_string();
    let database_url = database.connect_url.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let rows: i64 = db
            .query_one(
                "SELECT count(*) FROM canonical_events WHERE envelope->>'event_id'=$1",
                &[&rejected_id],
            )?
            .get(0);
        ensure!(
            rows == 0,
            "rejected encrypted poll persisted its producer Event"
        );
        Ok(())
    })
    .await??;
    Ok(())
}
