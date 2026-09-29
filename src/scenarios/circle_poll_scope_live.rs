//! Circle-scoped plaintext Poll admission against a real Station and PostgreSQL.

use anyhow::{Context as _, Result, ensure};
use arkret_models_collaboration::governance::circle::{
    CircleCreateRequestBody, CircleMemberRequestBody,
};
use arkret_wire::{
    ActorId, AuthoritySubmitRequest, CircleId, CommittedEventView, Event, EventAdmissionSubmission,
    EventKind, MessageId, ScopeRef, StrandId,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestActorClient, TestServerGroup, expect_api_error, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, standard_client, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "circle-poll-scope";
const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002851";

#[derive(Debug, PartialEq, Eq)]
struct DurableState {
    realm_events: i64,
    realm_commits: i64,
    poll_responses: i64,
    current_response: String,
    current_selections: Value,
    current_declared_heads: Option<Value>,
}

async fn durable_state(database_url: &str, realm: &str, poll_event: &str) -> Result<DurableState> {
    let database_url = database_url.to_owned();
    let realm = realm.to_owned();
    let poll_event = poll_event.to_owned();
    tokio::task::spawn_blocking(move || -> Result<DurableState> {
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
        let current = db.query_one(
            "SELECT v.response_event_id, v.selections, v.declared_heads FROM poll_state_current_votes v JOIN canonical_events original ON original.pk=v.poll_event_pk WHERE original.envelope->>'event_id'=$1",
            &[&poll_event],
        )?;
        Ok(DurableState {
            realm_events, realm_commits, poll_responses,
            current_response: current.get(0),
            current_selections: current.get(1),
            current_declared_heads: current.get(2),
        })
    }).await?
}

async fn seed_stale_circle_mirror(
    database_url: &str,
    realm: &str,
    circle: &CircleId,
    actor: &ActorId,
) -> Result<()> {
    let database_url = database_url.to_owned();
    let realm = realm.to_owned();
    let token = circle.token_bytes().to_vec();
    let actor = serde_json::to_value(actor)?;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&database_url, postgres::NoTls)?;
        db.execute(
            "INSERT INTO projection_circles \
             (id,realm_id,title,display,directory_visibility,join_rule,history_access,encryption_profile,state,created_by,created_at) \
             VALUES($1,$2,'stale Circle mirror',$3,'members','public','since_join','none','archived',$4,now())",
            &[&token, &realm, &json!({"short_name":"stale","color_token":"blue","symbol":{"glyph":"lock"}}), &actor],
        )?;
        Ok(())
    })
    .await??;
    Ok(())
}

async fn circle_create(
    client: &TestActorClient,
    realm: &str,
    actor: &ActorId,
    title: &str,
    short_name: &str,
) -> Result<CircleId> {
    let mut create = client
        .author_event(
            realm,
            EventKind::CircleCreate.as_str(),
            json!({"object": {
                "schema":"ak.schema.circle.v1", "realm_id":realm, "title":title,
                "display":{"short_name":short_name,"color_token":"blue","symbol":{"glyph":"lock"}},
                "directory_visibility":"members", "join_rule":"public",
                "history_access":"since_join", "state":"active", "created_by":actor
            }}),
        )
        .await?;
    create
        .payload
        .get_mut("object")
        .and_then(Value::as_object_mut)
        .context("Circle create object")?
        .insert(
            "created_at".to_owned(),
            json!(arkret_canonical::format_timestamp_canonical(
                create.created_at
            )),
        );
    crate::harness::refresh_typed_event_proof(&mut create)?;
    let circle = CircleId::from_event_id(&create.event_id);
    let result = expect_json(
        client
            .post("/_arkret/self/circles")
            .json(&CircleCreateRequestBody {
                create_event: EventAdmissionSubmission::new(create),
            }),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        result["circle_id"] == circle.as_str(),
        "Circle create returned wrong id: {result}"
    );
    Ok(circle)
}

async fn circle_event(
    client: &TestActorClient,
    realm: &str,
    circle: &CircleId,
    kind: EventKind,
    mut payload: Value,
) -> Result<Event> {
    let mut event = client
        .author_event(realm, kind.as_str(), payload.clone())
        .await?;
    event.scope_ref = ScopeRef::Circle {
        realm_id: event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    if kind == EventKind::StrandCreate {
        payload
            .get_mut("object")
            .and_then(Value::as_object_mut)
            .context("Strand create object")?
            .insert(
                "created_at".to_owned(),
                json!(arkret_canonical::format_timestamp_canonical(
                    event.created_at
                )),
            );
        event.payload = serde_json::from_value(payload)?;
    }
    crate::harness::refresh_typed_event_proof(&mut event)?;
    Ok(event)
}

async fn join_circle(
    client: &TestActorClient,
    realm: &str,
    circle: &CircleId,
    actor: &ActorId,
) -> Result<()> {
    let parent = client.parent_membership_revision(realm, actor).await?;
    let join = circle_event(
        client,
        realm,
        circle,
        EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"join",
            "parent_membership_revision":parent,"expected_membership":null}),
    )
    .await?;
    expect_json(
        client
            .post(&format!(
                "/_arkret/self/circles/{}/members",
                circle.as_str()
            ))
            .json(&CircleMemberRequestBody {
                member_event: EventAdmissionSubmission::new(join),
            }),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

pub async fn run() -> Result<()> {
    let Some(database) = database(GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(mut group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let station = group.server(0);
    let (alice, account) = standard_client(station, &coauth, "circle-poll-alice", DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&alice, "Circle poll scope", "public", &[station]).await?;
    let actor = ActorId::account(account.clone());

    let circle_a = circle_create(&alice, &realm, &actor, "Private poll A", "Poll A").await?;
    join_circle(&alice, &realm, &circle_a, &actor).await?;
    let strand_a = circle_event(&alice, &realm, &circle_a, EventKind::StrandCreate,
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "scope_circle_id":circle_a,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Circle poll A"},"state":"active","created_by":actor}}),
    ).await?;
    submit_and_expect_commit(&alice, &account, DEVICE, &strand_a).await?;
    let strand_a_id = StrandId::from_event_id(&strand_a.event_id);

    let poll = circle_event(&alice, &realm, &circle_a, EventKind::MessageCreate,
        json!({"strand_id":strand_a_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll","body":"Choose one","poll":{"kind":"disclosed","max_selections":1,
                "answers":[{"id":"a","text":{"kind":"ak.content.text","body":"A"}},
                    {"id":"b","text":{"kind":"ak.content.text","body":"B"}}]}}}),
    ).await?;
    submit_and_expect_commit(&alice, &account, DEVICE, &poll).await?;
    let poll_ref = MessageId::from_event_id(&poll.event_id);
    let vote = circle_event(
        &alice,
        &realm,
        &circle_a,
        EventKind::MessageCreate,
        json!({"strand_id":strand_a_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll.response","body":"Vote",
            "poll_response":{"poll_ref":poll_ref,"selections":["a"]}}}),
    )
    .await?;
    submit_and_expect_commit(&alice, &account, DEVICE, &vote).await?;
    let before = durable_state(&database.connect_url, &realm, poll.event_id.as_str()).await?;
    ensure!(
        before.poll_responses == 1
            && before.current_response == vote.event_id.to_string()
            && before.current_selections == json!(["a"]),
        "same-Circle vote did not become durable current: {before:?}"
    );

    let declared_heads = json!([{
        "poll_event_ref":poll.event_id,
        "response_event_ref":vote.event_id,
    }]);
    let replacement = circle_event(
        &alice,
        &realm,
        &circle_a,
        EventKind::MessageCreate,
        json!({"strand_id":strand_a_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll.response","body":"Changed vote",
            "poll_response":{"poll_ref":poll_ref,"selections":["b"]}},
            "poll_response_heads":declared_heads}),
    )
    .await?;
    submit_and_expect_commit(&alice, &account, DEVICE, &replacement).await?;
    let revised = durable_state(&database.connect_url, &realm, poll.event_id.as_str()).await?;
    ensure!(
        revised.poll_responses == 2
            && revised.current_response == replacement.event_id.to_string()
            && revised.current_selections == json!(["b"])
            && revised.current_declared_heads == Some(declared_heads)
            && revised.realm_events == before.realm_events + 1
            && revised.realm_commits == before.realm_commits + 1,
        "same-Circle replacement did not persist both inputs and the new current vote: {before:?} -> {revised:?}"
    );

    let circle_b = circle_create(&alice, &realm, &actor, "Private poll B", "Poll B").await?;
    join_circle(&alice, &realm, &circle_b, &actor).await?;
    let strand_b = circle_event(&alice, &realm, &circle_b, EventKind::StrandCreate,
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "scope_circle_id":circle_b,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Circle poll B"},"state":"active","created_by":actor}}),
    ).await?;
    submit_and_expect_commit(&alice, &account, DEVICE, &strand_b).await?;
    let strand_b_id = StrandId::from_event_id(&strand_b.event_id);
    let cross_vote = circle_event(
        &alice,
        &realm,
        &circle_b,
        EventKind::MessageCreate,
        json!({"strand_id":strand_b_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll.response","body":"Cross-Circle vote",
            "poll_response":{"poll_ref":poll_ref,"selections":["a"]}}}),
    )
    .await?;
    let baseline = durable_state(&database.connect_url, &realm, poll.event_id.as_str()).await?;
    let request = AuthoritySubmitRequest::Event(EventAdmissionSubmission::new(cross_vote.clone()));
    expect_api_error(
        alice.post("/_arkret/self/events").json(&request),
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await
    .context("cross-Circle Poll response was not refused")?;
    let after = durable_state(&database.connect_url, &realm, poll.event_id.as_str()).await?;
    ensure!(
        after == baseline,
        "cross-Circle refusal changed durable Event/Commit/PollState: {baseline:?} -> {after:?}"
    );
    let rejected_id = cross_vote.event_id.to_string();
    let database_url = database.connect_url.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let rows: i64 = db
            .query_one(
                "SELECT count(*) FROM canonical_events WHERE envelope->>'event_id'=$1",
                &[&rejected_id],
            )?
            .get(0);
        ensure!(rows == 0, "cross-Circle refused Event was persisted");
        Ok(())
    })
    .await??;

    // One legacy mirror lies about Circle A; Circle B has no mirror at all.
    // Both must recover from accepted Event/Commit truth after restart.
    seed_stale_circle_mirror(&database.connect_url, &realm, &circle_a, &actor).await?;
    group.server_mut(0).restart_external_process().await?;
    let readback: CommittedEventView = serde_json::from_value(
        expect_json(
            alice.get(&format!(
                "/_arkret/self/committed-events/{}",
                replacement.event_id
            )),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(&readback, CommittedEventView::Full(view) if view.event == replacement),
        "restarted Station did not disclose the committed replacement Event: {readback:?}"
    );
    let second_circle: CommittedEventView = serde_json::from_value(
        expect_json(
            alice.get(&format!(
                "/_arkret/self/committed-events/{}",
                strand_b.event_id
            )),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(&second_circle, CommittedEventView::Full(view) if view.event == strand_b),
        "restarted Station did not recover the Circle without a legacy mirror: {second_circle:?}"
    );
    let restarted = durable_state(&database.connect_url, &realm, poll.event_id.as_str()).await?;
    ensure!(
        restarted == after,
        "restarted Station changed durable PollState: {after:?} -> {restarted:?}"
    );

    Ok(())
}
