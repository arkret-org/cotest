use anyhow::{Context, Result, ensure};
use arkret_identifiers::{GrantId, RelationId};
use arkret_wire::{AccountId, ActorId, Event, RealmCommit};
use cotest::harness::{TestActorClient, expect_json};
use cotest::scenarios::agent_runtime_live::{actual_agent_deployment, additional_controller};
use reqwest::StatusCode;
use serde_json::{Value, json};

fn account(client: &TestActorClient) -> Result<AccountId> {
    Ok(AccountId::new(
        client
            .principal
            .as_ref()
            .context("native principal")?
            .core_id
            .clone(),
        client.service_id().parse()?,
    ))
}

async fn accepted(client: &TestActorClient, realm: &str, event: &Event) -> Result<RealmCommit> {
    let commit = cotest::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &account(client)?,
        &client.device_id,
        event,
    )
    .await?;
    ensure!(
        commit.realm_id.as_str() == realm,
        "native Commit belongs to another Realm"
    );
    Ok(commit)
}

async fn db_value(database: &str, sql: &'static str, realm: &str) -> Result<Value> {
    let database = database.to_owned();
    let realm = realm.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db.query_one(sql, &[&realm])?.get(0))
    })
    .await?
}

async fn footprint(database: &str, realm: &str) -> Result<Value> {
    db_value(database,
        "SELECT jsonb_build_object('events',(SELECT COALESCE(jsonb_agg(e.envelope ORDER BY e.id),'[]'::jsonb) FROM canonical_events e WHERE e.realm_id=$1),'commits',(SELECT COALESCE(jsonb_agg(c.commit_json ORDER BY c.stream_key,c.stream_position),'[]'::jsonb) FROM realm_commits c WHERE c.realm_id=$1),'relations',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.relation_id),'[]'::jsonb) FROM relation_current_states r WHERE r.realm_id=$1),'grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g) ORDER BY g.grant_id),'[]'::jsonb) FROM capability_grant_current_states g WHERE g.realm_id=$1))",
        realm).await
}

async fn grant_value(database: &str, realm: &str, grant: &str) -> Result<Value> {
    let database = database.to_owned();
    let realm = realm.to_owned();
    let grant = grant.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db.query_one("SELECT value FROM capability_grant_current_states WHERE realm_id=$1 AND grant_id=$2", &[&realm,&grant])?.get(0))
    }).await?
}

async fn refused_without_effects(
    client: &TestActorClient,
    database: &str,
    realm: &str,
    event: &Event,
) -> Result<()> {
    let before = footprint(database, realm).await?;
    let response = client
        .post("/_arkret/self/events")
        .json(&cotest::publication::initial_submission(event.clone(), "")?)
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await?;
    ensure!(
        status == StatusCode::CONFLICT || status == StatusCode::FORBIDDEN,
        "business precondition was not refused: {status} {body}"
    );
    ensure!(
        footprint(database, realm).await? == before,
        "refused Event changed native authority state"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn same_relation_value_after_aba_still_refuses_the_old_commit_and_replays_exactly()
-> Result<()> {
    let deployment = actual_agent_deployment("relation-aba-guard").await?;
    let alice = &deployment.controller;
    let database = deployment
        .station
        .owned_database_url()
        .context("native PG")?;
    let realm = alice.create_realm("Relation ABA guard").await?;
    let strand = alice.default_strand_id(&realm)?;
    let domain = json!({"domain_kind":"tuple","relation_kind":"assigned_to",
        "from_ref":strand,"to_ref":ActorId::account(account(alice)?)});
    let create = alice
        .author_event(
            &realm,
            "ak.relation.create",
            json!({
                "primary_conflict_domain":domain,"expected_commit_id":null,
                "relation":{"relation_kind":"assigned_to","from_ref":strand,
                    "to_ref":ActorId::account(account(alice)?),"fields":{"note":"A"}}
            }),
        )
        .await?;
    let first = accepted(alice, &realm, &create).await?;
    let id = RelationId::from_event_id(&create.event_id);
    let patch = |expected: &arkret_wire::RealmCommitId, label: &str| {
        json!({
            "primary_conflict_domain":domain,"relation_id":id,
            "expected_commit_id":expected,"patch":{"fields.note":label}
        })
    };
    let second = alice
        .author_event(&realm, "ak.relation.update", patch(&first.commit_id, "B"))
        .await?;
    let middle = accepted(alice, &realm, &second).await?;
    let third = alice
        .author_event(&realm, "ak.relation.update", patch(&middle.commit_id, "A"))
        .await?;
    let last = accepted(alice, &realm, &third).await?;
    super::cas_equivalence::assert_registered_guard_equivalence(&[
        first.clone(),
        middle.clone(),
        last.clone(),
    ])?;
    ensure!(
        first.commit_id != last.commit_id,
        "distinct accepted writes reused a Commit ID"
    );
    let original = db_value(
        database,
        "SELECT value FROM relation_current_states WHERE realm_id=$1",
        &realm,
    )
    .await?;
    ensure!(
        original["fields"]["note"] == "A",
        "ABA did not restore its business value"
    );
    let stale = alice
        .author_event(
            &realm,
            "ak.relation.update",
            patch(&first.commit_id, "stale"),
        )
        .await?;
    refused_without_effects(alice, database, &realm, &stale).await?;
    let before = footprint(database, &realm).await?;
    let replay = accepted(alice, &realm, &second).await?;
    ensure!(
        replay == middle,
        "exact accepted retry was re-authored against A's latest revision"
    );
    ensure!(
        footprint(database, &realm).await? == before,
        "exact retry changed the current A result"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn accepted_grant_replay_after_real_authority_reset_preserves_original_expiry_and_root()
-> Result<()> {
    let deployment = actual_agent_deployment("grant-replay-root-reset").await?;
    let alice = &deployment.controller;
    let bob = additional_controller(
        &deployment,
        "grant-replay-bob",
        "ak:device:01904100-0000-7000-8000-000000005101",
    )
    .await?;
    let database = deployment
        .station
        .owned_database_url()
        .context("native PG")?;
    let realm = alice
        .create_realm("Accepted Grant immutable result")
        .await?;
    alice.add_member(&realm, &bob).await?;
    let issued = chrono::Utc::now();
    let expiry = issued + chrono::Duration::hours(1);
    let event = alice.author_event(&realm, "ak.capability.grant", json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":realm,
        "issuer_id":ActorId::account(account(alice)?),"subject":ActorId::account(account(&bob)?),
        "actions":["ak.message.create"],"resources":[{"kind":"realm","realm_id":realm}],
        "constraints":[{"constraint_kind":"temporal","effect":"allow","expires_at":arkret_canonical::format_timestamp_canonical(expiry)}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,
            "authority_event_ref":arkret_identifiers::RealmId::new(realm.clone())?.event_id(),"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(issued)
    }})).await?;
    let first = accepted(alice, &realm, &event).await?;
    let grant_id = GrantId::from_event_id(&event.event_id);
    bob.remember_grant(&realm, grant_id.as_str(), &["ak.message.create"]);
    let original = grant_value(database, &realm, grant_id.as_str()).await?;
    ensure!(
        original["id"] == grant_id.as_str(),
        "read a different Grant"
    );
    let root = db_value(database,
        "SELECT jsonb_build_object('controller_actor_id',controller_actor_id,'controller_epoch',controller_epoch,'authority_generation',authority_generation::text,'authority_event_ref',authority_event_ref) FROM realm_authority_root_current_states WHERE realm_id=$1", &realm).await?;
    let reset = alice
        .author_event(
            &realm,
            "ak.realm.authority.reset",
            json!({
                "realm_id":realm,"expected_state_digest":arkret_canonical::canonical_sha256(&root)?
            }),
        )
        .await?;
    accepted(alice, &realm, &reset).await?;
    let fresh = bob
        .author_event(
            &realm,
            "ak.message.create",
            cotest::harness::message_create_text_payload_for_strand(
                alice.default_strand_id(&realm)?.parse()?,
                "old generation cannot admit new writes",
            )?,
        )
        .await?;
    refused_without_effects(&bob, database, &realm, &fresh).await?;
    let after_reset = footprint(database, &realm).await?;
    ensure!(
        accepted(alice, &realm, &event).await? == first,
        "accepted Grant replay lost its original Commit"
    );
    ensure!(
        footprint(database, &realm).await? == after_reset,
        "accepted Grant replay changed native state"
    );
    ensure!(
        grant_value(database, &realm, grant_id.as_str()).await? == original,
        "accepted replay recomputed immutable expiry or root after authority reset"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn warmed_native_allow_does_not_survive_an_accepted_member_ban() -> Result<()> {
    let deployment = actual_agent_deployment("grant-current-moderation").await?;
    let alice = &deployment.controller;
    let bob = additional_controller(
        &deployment,
        "moderated-writer",
        "ak:device:01904100-0000-7000-8000-000000005102",
    )
    .await?;
    let database = deployment
        .station
        .owned_database_url()
        .context("native PG")?;
    let realm = alice.create_realm("Moderated current Grant source").await?;
    alice.add_member(&realm, &bob).await?;
    let grant = alice
        .grant_realm_actions_to_client(&realm, &bob, &["ak.message.create"])
        .await?;
    let body =
        arkret_models_collaboration::governance::authorization::AuthorizationCheckRequestBody {
            actor_id: ActorId::account(account(&bob)?),
            action: "ak.message.create".to_owned(),
            resource: Some(arkret_wire::WireResourceSelector::realm(realm.parse()?)),
            context: None,
        };
    for _ in 0..2 {
        let allow = expect_json(
            bob.post("/_arkret/self/authz/check").json(&body),
            StatusCode::OK,
        )
        .await?;
        ensure!(
            allow["decision"] == "allow",
            "native grant never allowed the writer: {allow}"
        );
    }
    let strand = alice.default_strand_id(&realm)?;
    let first = bob
        .author_event(
            &realm,
            "ak.message.create",
            cotest::harness::message_create_text_payload_for_strand(
                strand.parse()?,
                "accepted before moderation",
            )?,
        )
        .await?;
    accepted(&bob, &realm, &first).await?;
    let ban = alice.author_event(&realm,"ak.member.state",
        cotest::scenarios::human_device_producer_live::membership_payload(
            &realm,account(&bob)?,arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Ban,"native current refusal",
        )?).await?;
    accepted(alice, &realm, &ban).await?;
    ensure!(
        grant_value(database, &realm, &grant).await?["status"] == "active",
        "the case revoked the Grant instead of changing moderation"
    );
    let deny = expect_json(
        bob.post("/_arkret/self/authz/check").json(&body),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        deny["decision"] != "allow",
        "old diagnostic allow survived the current member ban: {deny}"
    );
    let after = bob
        .author_event(
            &realm,
            "ak.message.create",
            cotest::harness::message_create_text_payload_for_strand(
                strand.parse()?,
                "must not be accepted after moderation",
            )?,
        )
        .await?;
    refused_without_effects(&bob, database, &realm, &after).await?;
    // The accepting implementation re-reads the locked current cut per Event;
    // it has no cross-Event allow cache or producer-controlled dependency hint.
    Ok(())
}
