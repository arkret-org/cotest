//! Live Calendar RSVP convergence against a real server.
//!
//! The unit and fixture suites pin the rules in isolation; this exercises them
//! end to end, because the convergence properties only mean something once a
//! real reducer has admitted the Events:
//!
//! * an RSVP is admitted as a signed Event and its complete entry reaches the
//!   materialized current value;
//! * two responses authored before either is submitted receive distinct RealmCommits;
//!   the later stream position is the current value, regardless of EventId order;
//! * exact replay and process restart preserve that value and its source Event.
//!
//! Subject isolation between responders is not repeated here: the accountable
//! actor is part of the composite subject, which reducer unit tests already pin.
//!
//! This is deliberately a **Soland product-integration scenario**, not a
//! portable Arkret conformance vector. Writes and public lifecycle reads use
//! registered `/_arkret/*` operations; assertions over the materialized RSVP value
//! use Soland's product-private projection read because that implementation
//! state is not part of the cross-implementation wire contract.

use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use arkret_wire::{EventId, RealmCommit, RealmId};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestActorClient, actor_core_id, eventually, expect_json, submitted_event_id,
};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

const ALICE_LOCAL: &str = "cotest-rsvp-alice";
const BOB_LOCAL: &str = "cotest-rsvp-bob";
/// The Strand id of a create the server has accepted.
///
/// A Strand is an event-derived kind: its id is `retype(event_id)` of its own
/// create Event, so the only way to name it is to submit the create first and
/// read the id back. Carrying a pre-minted id in the create payload is
/// `object_id_not_event_derived`.
fn created_strand_id(submitted: &Value) -> Result<String> {
    let event_id = crate::harness::submitted_event_id(submitted)?;
    Ok(arkret_identifiers::StrandId::from_event_id(&event_id).to_string())
}

fn actor_for_station(actor_did: &str, station_id: &str) -> Result<arkret_wire::ActorId> {
    Ok(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(actor_core_id(actor_did)?)?,
        arkret_wire::DidCoreId::new(station_id.to_owned())?,
    )))
}

fn calendar_subtree(alice_did: &str, bob_did: &str, station_id: &str) -> Result<Value> {
    Ok(json!({
        "start": "2026-06-22T09:00:00",
        "end": "2026-06-22T10:00:00",
        "timezone": "America/Los_Angeles",
        "tzdb_version": "2025b",
        "all_day": false,
        "status": "confirmed",
        "recurrence": {"frequency": "weekly", "count": 10},
        "attendees": [
            {"actor_id": actor_for_station(alice_did, station_id)?, "role": "organizer"},
            {"actor_id": actor_for_station(bob_did, station_id)?, "role": "required"}
        ]
    }))
}

fn inkson_rsvp_payload(
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    status: &str,
    basis: &[String],
    attendees: (&str, &str, &str),
) -> Result<Value> {
    let calendar_fields =
        serde_json::from_value(calendar_subtree(attendees.0, attendees.1, attendees.2)?)?;
    let [basis_event_id] = basis else {
        return Err(anyhow!(
            "RSVP requires exactly one accepted schedule EventId"
        ));
    };
    let basis_event_id = arkret_wire::EventId::new(basis_event_id.clone())?;
    // The RSVP is a write: its payload is settled before authoring, and the
    // submit path positions it on the actor chain.
    let operation = inkson::calendar::build_calendar_rsvp_event(
        realm_id,
        &actor_for_station(actor_id, attendees.2)?,
        strand_id,
        status,
        None,
        &calendar_fields,
        basis_event_id,
    )?;
    Ok(serde_json::to_value(operation.payload())?)
}

/// Reads the schedule revision winner used as the RSVP basis.
async fn assert_realm_identity(client: &TestActorClient, realm_id: &str) -> Result<()> {
    let view: arkret_models_collaboration::governance::realm_governance::RealmLifecycleView =
        serde_json::from_value(
            expect_json(
                client.get(&format!("/_arkret/self/realms/{realm_id}")),
                StatusCode::OK,
            )
            .await?,
        )?;
    let actor = actor_for_station(&client.actor, client.service_id())?;
    // The registered lifecycle DTO intentionally exposes owner_id as a
    // principal; member_ids must retain their complete Actor identities.
    assert_eq!(&view.owner_id, actor.signing_principal_id());
    assert!(view.member_ids.contains(&actor));
    Ok(())
}

async fn read_soland_product_projection_strand(
    client: &TestActorClient,
    strand_id: &str,
) -> Result<Value> {
    expect_json(
        client.get(&format!("/_soland/self/strands/{strand_id}")),
        StatusCode::OK,
    )
    .await
}

fn accepted_schedule_basis(submitted: &Value) -> Result<Vec<String>> {
    Ok(vec![
        crate::harness::submitted_event_id(submitted)?.to_string(),
    ])
}

fn current_rsvp_for(strand: &Value, actor: &arkret_wire::ActorId) -> Option<Value> {
    strand["rsvps"]
        .as_array()
        .and_then(|cells| {
            cells.iter().find(|cell| {
                cell["actor_id"]
                    .as_str()
                    .and_then(|value| serde_json::from_str::<arkret_wire::ActorId>(value).ok())
                    .as_ref()
                    == Some(actor)
            })
        })
        .cloned()
}

fn current_status(current: &Value) -> Option<&str> {
    current["entry"]["response"]["status"].as_str()
}

fn assert_current_rsvp(
    strand: &Value,
    actor: &arkret_wire::ActorId,
    source_event_id: &EventId,
    status: &str,
    schedule_basis: &[String],
) -> Result<()> {
    let current = current_rsvp_for(strand, actor)
        .ok_or_else(|| anyhow!("RSVP current is absent for {actor}"))?;
    ensure!(
        current["source_event_id"].as_str() == Some(source_event_id.as_str())
            && current_status(&current) == Some(status)
            && current["entry"]["schedule_basis_refs"] == json!(schedule_basis),
        "RSVP current does not match accepted Event {source_event_id}: {current}"
    );
    Ok(())
}

fn accepted_commit(response: &Value) -> Result<RealmCommit> {
    let event_id = submitted_event_id(response)?;
    let commit: RealmCommit = serde_json::from_value(response["commit"].clone())?;
    ensure!(
        commit.event_ref == event_id,
        "submit outcome names another Event"
    );
    Ok(commit)
}

async fn assert_committed(
    client: &TestActorClient,
    realm_id: &str,
    event_id: &EventId,
) -> Result<RealmCommit> {
    client.await_event_seal_coverage(realm_id, event_id).await?;
    let view = client.sdk().committed_event_get(event_id).await?;
    view.validate_shape()?;
    Ok(view.commit().clone())
}

async fn wait_for_projected_grant(
    client: &TestActorClient,
    realm_id: &str,
    subject: &str,
    grant_id: &str,
) -> Result<()> {
    let subject_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(subject)?,
        arkret_wire::DidCoreId::new(client.service_id())?,
    ))
    .to_string();
    eventually(
        "capability grant projection",
        Duration::from_secs(30),
        Duration::from_millis(100),
        || async {
            let effective = expect_json(
                client.get("/_arkret/self/authz/effective-grants").query(&[
                    ("subject_actor_id", subject_actor_id.as_str()),
                    ("realm_id", realm_id),
                ]),
                StatusCode::OK,
            )
            .await?;
            if effective["grants"].as_array().is_some_and(|grants| {
                grants
                    .iter()
                    .any(|grant| grant["grant"]["id"].as_str() == Some(grant_id))
            }) {
                Ok(())
            } else {
                Err(anyhow!("capability grant {grant_id} is not projected yet"))
            }
        },
    )
    .await
}

async fn grant_calendar_actions(client: &TestActorClient, realm_id: &str) -> Result<String> {
    // A field-access constraint narrows every action in its grant. Keep the
    // ordinary create/RSVP actions on an unconstrained grant and put the
    // field-scoped Strand update on its own grant.
    let plain_grant_id = client
        .grant_realm_actions_to_client(realm_id, client, &["ak.strand.create", "ak.rsvp.set"])
        .await?;
    let subject = actor_core_id(&client.actor)?;
    wait_for_projected_grant(client, realm_id, &subject, &plain_grant_id).await?;

    let mut calendar_field_constraint =
        arkret_models_collaboration::governance::grant_constraint::GrantConstraint::new(
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::FieldAccess,
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintEffect::Allow,
        );
    calendar_field_constraint.allowed_write_fields = vec!["metadata.fields.calendar".to_owned()];
    let (field_grant_id, _response) = client
        .grant_realm_actions_with_constraints_to(
            realm_id,
            &client.actor,
            &["ak.strand.update"],
            vec![calendar_field_constraint],
        )
        .await?;
    let field_grant_event = EventId::from_token_bytes(
        arkret_identifiers::GrantId::new(field_grant_id.clone())?.token_bytes(),
    )?;
    assert_committed(client, realm_id, &field_grant_event).await?;
    wait_for_projected_grant(client, realm_id, &subject, &field_grant_id).await?;
    client.remember_grant(realm_id, &field_grant_id, &["ak.strand.update"]);
    Ok(plain_grant_id)
}

async fn grant_calendar_rsvp_to(
    issuer: &TestActorClient,
    realm_id: &str,
    subject_client: &TestActorClient,
) -> Result<()> {
    let grant_id = issuer
        .grant_realm_actions_to_client(realm_id, subject_client, &["ak.rsvp.set"])
        .await?;
    let subject = actor_core_id(&subject_client.actor)?;
    wait_for_projected_grant(issuer, realm_id, &subject, &grant_id).await?;
    Ok(())
}

async fn submit_prepared_event(
    client: &TestActorClient,
    event: &arkret_wire::Event,
) -> Result<RealmCommit> {
    let response = expect_json(
        client
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    let commit = accepted_commit(&response)?;
    ensure!(
        commit.event_ref == event.event_id,
        "submitted Event changed identity"
    );
    Ok(commit)
}

async fn create_calendar_strand(
    client: &TestActorClient,
    realm_id: &str,
    title: &str,
    bob_did: &str,
    preserve_unknown_display: bool,
) -> Result<Value> {
    let mut fields = json!({
        "calendar": calendar_subtree(&client.actor, bob_did, client.service_id())?
    });
    if preserve_unknown_display {
        fields["x_future_display"] = json!({"badge": "preserve-me", "revision": 7});
    }
    let mut event = client
        .author_event(
            realm_id,
            "ak.strand.create",
            json!({
                "object": {
                    "schema": "ak.schema.strand.v1",
                    "realm_id": realm_id,
                    "schema_refs": ["ak.schema.calendar_event.v1"],
                    "metadata": {"title": title, "fields": fields},
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": actor_for_station(&client.actor, client.service_id())?,
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
        )
        .await?;
    // Strand creation time is the signed Event time. The product's default
    // Strand fixture uses the same order: choose envelope clock, then sign.
    let created_at = serde_json::to_value(&event)?["created_at"].clone();
    event
        .payload
        .get_mut("object")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("Calendar Strand create has no object"))?
        .insert("created_at".to_owned(), created_at);
    let (seed, _) =
        crate::harness::event_signing_identity_for_device(&client.actor, &client.device_id);
    crate::harness::refresh_typed_event_proof_with_signing_seed(&mut event, seed)?;
    let response = expect_json(
        client
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    let commit = accepted_commit(&response)?;
    ensure!(
        commit.event_ref == event.event_id,
        "Calendar Strand create changed Event identity"
    );
    assert_committed(client, realm_id, &event.event_id).await?;
    Ok(response)
}

pub async fn calendar_rsvp_converges_across_concurrent_responses() -> Result<()> {
    let server = ArkretServer::spawn("calendar-rsvp-convergence").await?;
    let alice_did = actor_did_for_service_did(server.service_did(), ALICE_LOCAL)?;
    let bob_did = actor_did_for_service_did(server.service_did(), BOB_LOCAL)?;
    let alice_did = alice_did.as_str();
    let bob_did = bob_did.as_str();
    let alice = server
        .standard_register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c1",
        )
        .await?;
    // Two views author before either RSVP is submitted. Their Commit positions,
    // not any producer-side causal edge, select the current response.
    let alice_second_device = alice.clone();
    let bob = server
        .standard_register_client(
            bob_did,
            "@cotest-rsvp-bob",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        )
        .await?;
    let created = alice
        .create_realm_with(json!({
            "title": "RSVP convergence",
            "summary": "RSVP convergence",
            "public": false,
            "schema_refs": ["ak.schema.realm.v1"],
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("realm create response has no realm_id"))?
        .to_owned();
    let realm_event = RealmId::new(realm_id.clone())?.event_id();
    assert_committed(&alice, &realm_id, &realm_event).await?;
    let joined = alice.add_member(&realm_id, &bob).await?;
    assert_committed(&bob, &realm_id, &submitted_event_id(&joined)?).await?;
    let _alice_grant = grant_calendar_actions(&alice, &realm_id).await?;
    grant_calendar_rsvp_to(&alice, &realm_id, &bob).await?;

    // Activation is one canonical pair: the schema ref plus the calendar
    // namespace. A lone ref or a lone subtree is calendar_activation_mismatch.
    let created = create_calendar_strand(&alice, &realm_id, "Weekly sync", bob_did, true).await?;
    let strand_id = created_strand_id(&created)?;
    let projected = read_soland_product_projection_strand(&alice, &strand_id).await?;
    let preserved_display = json!({"badge": "preserve-me", "revision": 7});
    if projected["fields"]["x_future_display"] != preserved_display {
        return Err(anyhow!(
            "unknown namespaced display metadata was lost on decode/store/read: {projected}"
        ));
    }

    let create_basis = accepted_schedule_basis(&created)?;

    // Exercise a real schedule revision before RSVP authoring. Soland does not
    // claim the Calendar notification server profile: receiver-private DND,
    // blocklist and push rules remain holder-encrypted, so cross-recipient
    // Calendar fanout correctly fails closed until an authorized minimal
    // policy projection exists.
    let updated = alice
        .submit_event(
            &realm_id,
            "ak.strand.update",
            json!({
                "target_ref": strand_id,
                "patch": {
                    "metadata.fields.calendar": {
                        "$op": "set",
                        "value": {
                            "start": "2026-06-22T09:00:00",
                            "end": "2026-06-22T10:00:00",
                            "timezone": "America/Los_Angeles",
                            "tzdb_version": "2025b",
                            "all_day": false,
                            "status": "confirmed",
                            "recurrence": {"frequency": "weekly", "count": 10},
                            "location": {"title": "Room 2"},
                            "attendees": [
                                {"actor_id": actor_for_station(alice_did, alice.service_id())?, "role": "organizer"},
                                {"actor_id": actor_for_station(bob_did, bob.service_id())?, "role": "required"}
                            ]
                        }
                    }
                }
            }),
        )
        .await?;
    let schedule_basis = accepted_schedule_basis(&updated)?;
    let create_commit =
        assert_committed(&alice, &realm_id, &EventId::new(create_basis[0].clone())?).await?;
    let update_commit = assert_committed(&alice, &realm_id, &submitted_event_id(&updated)?).await?;
    ensure!(
        update_commit.stream_position > create_commit.stream_position,
        "schedule update did not advance the RealmCommit stream"
    );

    let bob_response = bob
        .submit_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                bob_did,
                "accepted",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let bob_commit = accepted_commit(&bob_response)?;
    assert_current_rsvp(
        &read_soland_product_projection_strand(&bob, &strand_id).await?,
        &actor_for_station(bob_did, bob.service_id())?,
        &bob_commit.event_ref,
        "accepted",
        &schedule_basis,
    )?;

    // Both responses are authored before either is submitted. The governing
    // Station still assigns a strict RealmCommit order to their current writes.
    let first_event = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let second_event = alice_second_device
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "declined",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let first_commit = submit_prepared_event(&alice, &first_event).await?;
    let second_commit = submit_prepared_event(&alice_second_device, &second_event).await?;
    ensure!(
        second_commit.stream_ref == first_commit.stream_ref
            && second_commit.stream_position > first_commit.stream_position,
        "concurrent RSVP candidates were not ordered by RealmCommit"
    );
    assert_current_rsvp(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
        &second_event.event_id,
        "declined",
        &schedule_basis,
    )?;

    // A later response replaces the previous current without causal edges.
    let resolved = alice
        .submit_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let resolved_commit = accepted_commit(&resolved)?;
    ensure!(resolved_commit.stream_position > second_commit.stream_position);
    assert_current_rsvp(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
        &resolved_commit.event_ref,
        "tentative",
        &schedule_basis,
    )?;

    // Reverse arrival order for the second pair. Exact replay of the earlier
    // Commit cannot move the current back to its old value.
    let reverse_first = alice_second_device
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let reverse_second = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "declined",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let reverse_second_commit = submit_prepared_event(&alice, &reverse_second).await?;
    let reverse_first_commit = submit_prepared_event(&alice_second_device, &reverse_first).await?;
    ensure!(reverse_first_commit.stream_position > reverse_second_commit.stream_position);
    let replay_commit = submit_prepared_event(&alice, &reverse_second).await?;
    ensure!(
        replay_commit == reverse_second_commit,
        "exact replay changed RealmCommit"
    );
    assert_current_rsvp(
        &read_soland_product_projection_strand(&alice_second_device, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
        &reverse_first.event_id,
        "accepted",
        &schedule_basis,
    )?;

    let final_response = alice
        .submit_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let final_commit = accepted_commit(&final_response)?;
    ensure!(final_commit.stream_position > reverse_first_commit.stream_position);
    assert_current_rsvp(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
        &final_commit.event_ref,
        "tentative",
        &schedule_basis,
    )?;

    Ok(())
}

/// The same Calendar current value must survive a real process restart and exact
/// Event replay. The scenario uses a throw-away Postgres when Docker is
/// available; environments without either Postgres source report an explicit
/// live-row skip while reducer unit tests still run.
pub async fn calendar_rsvp_persists_across_restart_and_replay() -> Result<()> {
    // `COTEST_SOLAND_DATABASE_URL` is an administrator connection, not a test
    // database: used directly, every run replays onto the previous run's rows
    // and a stale `service_identity` fails this restart assertion for reasons
    // that have nothing to do with the code under test. This helper creates a
    // per-run database from it (and falls back to Docker), dropping it on Drop.
    let ephemeral = crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres_for(
        "COTEST_SOLAND_DATABASE_URL",
    )?;
    let Some(database) = ephemeral.as_ref() else {
        eprintln!(
            "calendar RSVP restart row skipped: no COTEST_SOLAND_DATABASE_URL and Docker/Postgres unavailable"
        );
        return Ok(());
    };
    let database_url = database.connect_url.clone();

    let test_name = "calendar-rsvp-restart";
    let keystore_dir = tempfile::tempdir()?;
    let keystore_path = keystore_dir
        .path()
        .join("soland.v1")
        .to_string_lossy()
        .into_owned();
    let keystore_env = [
        ("SOLAND_KEYSTORE_BACKEND", "encrypted_file"),
        ("SOLAND_KEYSTORE_PATH", keystore_path.as_str()),
        (
            "SOLAND_KEYSTORE_MASTER_KEY",
            "ERERERERERERERERERERERERERERERERERERERERERE=",
        ),
    ];
    let mut server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice_did = actor_did_for_service_did(server.service_did(), ALICE_LOCAL)?;
    let bob_did = actor_did_for_service_did(server.service_did(), BOB_LOCAL)?;
    let alice_did = alice_did.as_str();
    let bob_did = bob_did.as_str();
    let alice = server
        .standard_register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000d1",
        )
        .await?;
    let alice_second_device = alice.clone();
    let created = alice
        .create_realm_bootstrap_with(json!({
            "title": "RSVP restart",
            "summary": "RSVP restart",
            "public": false,
            "schema_refs": ["ak.schema.realm.v1"],
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("realm create response has no realm_id"))?
        .to_owned();
    assert_committed(
        &alice,
        &realm_id,
        &RealmId::new(realm_id.clone())?.event_id(),
    )
    .await?;
    let alice_grant = grant_calendar_actions(&alice, &realm_id).await?;
    let created =
        create_calendar_strand(&alice, &realm_id, "Durable weekly sync", bob_did, true).await?;
    let strand_id = created_strand_id(&created)?;
    let preserved_display = json!({"badge": "preserve-me", "revision": 7});
    let projected = read_soland_product_projection_strand(&alice, &strand_id).await?;
    if projected["fields"]["x_future_display"] != preserved_display {
        return Err(anyhow!(
            "unknown namespaced display metadata was lost on decode/store/read: {projected}"
        ));
    }
    let schedule_basis = accepted_schedule_basis(&created)?;
    let accepted = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let declined = alice_second_device
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "declined",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let accepted_realm_commit = submit_prepared_event(&alice, &accepted).await?;
    let declined_commit = submit_prepared_event(&alice_second_device, &declined).await?;
    ensure!(declined_commit.stream_position > accepted_realm_commit.stream_position);
    assert_current_rsvp(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
        &declined.event_id,
        "declined",
        &schedule_basis,
    )?;

    assert_realm_identity(&alice, &realm_id).await?;
    server.kill_immediately().await?;
    drop(server);
    let mut server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice = server
        .standard_client(alice_did, "ak:device:01904100-0000-7000-8000-0000000000d1")
        .await?;
    let alice_second_device = alice.clone();
    let restarted_strand = read_soland_product_projection_strand(&alice, &strand_id).await?;
    assert_realm_identity(&alice, &realm_id).await?;
    if restarted_strand["fields"]["x_future_display"] != preserved_display {
        return Err(anyhow!(
            "unknown namespaced display metadata was lost across restart: {restarted_strand}"
        ));
    }
    assert_current_rsvp(
        &restarted_strand,
        &actor_for_station(alice_did, alice.service_id())?,
        &declined.event_id,
        "declined",
        &schedule_basis,
    )?;
    ensure!(
        submit_prepared_event(&alice, &accepted).await? == accepted_realm_commit
            && submit_prepared_event(&alice_second_device, &declined).await? == declined_commit,
        "restart changed an exact replay's RealmCommit"
    );
    assert_current_rsvp(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
        &declined.event_id,
        "declined",
        &schedule_basis,
    )?;

    alice.remember_grant(
        &realm_id,
        &alice_grant,
        &["ak.strand.create", "ak.rsvp.set"],
    );
    let resolved = alice
        .submit_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let resolved_commit = accepted_commit(&resolved)?;
    ensure!(resolved_commit.stream_position > declined_commit.stream_position);
    server.kill_immediately().await?;
    drop(server);
    let server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice = server
        .standard_client(alice_did, "ak:device:01904100-0000-7000-8000-0000000000d1")
        .await?;
    assert_current_rsvp(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
        &resolved_commit.event_ref,
        "tentative",
        &schedule_basis,
    )?;

    drop(ephemeral);
    Ok(())
}

/// A signed RSVP with no schedule basis must be rejected before it can write
/// the current result. A valid response for the same subject remains current.
pub async fn calendar_rsvp_malformed_basis_is_rejected() -> Result<()> {
    let server = ArkretServer::spawn("calendar-rsvp-malformed-basis").await?;
    let alice_did = actor_did_for_service_did(server.service_did(), ALICE_LOCAL)?;
    let bob_did = actor_did_for_service_did(server.service_did(), BOB_LOCAL)?;
    let alice_did = alice_did.as_str();
    let bob_did = bob_did.as_str();
    let alice = server
        .standard_register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c3",
        )
        .await?;
    let created = alice
        .create_realm_with(json!({
            "title": "RSVP basis contract",
            "summary": "RSVP basis contract",
            "public": false,
            "schema_refs": ["ak.schema.realm.v1"],
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("realm create response has no realm_id"))?
        .to_owned();
    assert_committed(
        &alice,
        &realm_id,
        &RealmId::new(realm_id.clone())?.event_id(),
    )
    .await?;
    let _alice_grant = grant_calendar_actions(&alice, &realm_id).await?;
    let strand_created =
        create_calendar_strand(&alice, &realm_id, "Weekly sync", bob_did, false).await?;
    let strand_id = created_strand_id(&strand_created)?;
    let schedule_basis = accepted_schedule_basis(&strand_created)?;
    let valid = alice
        .submit_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let valid_commit = accepted_commit(&valid)?;
    let mut malformed_payload = inkson_rsvp_payload(
        &realm_id,
        &strand_id,
        alice_did,
        "declined",
        &schedule_basis,
        (alice_did, bob_did, alice.service_id()),
    )?;
    malformed_payload["entry"]["schedule_basis_refs"] = json!([]);
    let event = alice
        .author_event(&realm_id, "ak.rsvp.set", malformed_payload)
        .await?;
    let response = alice
        .post("/_arkret/self/events")
        .json(&crate::publication::initial_submission(event.clone(), "")?)
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    ensure!(
        status.is_client_error(),
        "malformed RSVP basis was accepted: {status} {body}"
    );
    ensure!(
        alice
            .sdk()
            .committed_event_get(&event.event_id)
            .await
            .is_err(),
        "malformed RSVP acquired a RealmCommit"
    );
    assert_current_rsvp(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
        &valid_commit.event_ref,
        "accepted",
        &schedule_basis,
    )?;
    Ok(())
}
