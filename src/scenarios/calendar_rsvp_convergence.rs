//! Live Calendar RSVP convergence against a real server.
//!
//! The unit and fixture suites pin the rules in isolation; this exercises them
//! end to end, because the convergence properties only mean something once a
//! real reducer has admitted the Events:
//!
//! * an RSVP carries the registry-derived cell effect, so it reaches its CBS cell instead of being
//!   accepted as a side-band record;
//! * two responses that do not observe each other retain both identities while the server exposes
//!   the fixed `(depth, EventId)` winner, independently of HLC and arrival order;
//! * a response that names the current winner in `causal_refs` has greater depth and becomes the
//!   next deterministic answer;
//!
//! Cell-subject isolation between responders is not repeated here: the
//! accountable actor is part of the composite subject, which the reducer unit
//! tests already pin. What only a live server can show is the concurrency and
//! domination behaviour below.
//!
//! This is deliberately a **Soland product-integration scenario**, not a
//! portable Arkret conformance vector. Writes and public lifecycle reads use
//! registered `/_arkret/*` operations; assertions over the materialized RSVP winner
//! use Soland's product-private projection read because that implementation
//! state is not part of the cross-implementation wire contract.

use std::time::Duration;

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, TestActorClient, actor_core_id, eventually, expect_json};
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
    let basis = basis
        .iter()
        .cloned()
        .map(arkret_identifiers::Hash::new)
        .collect::<Result<Vec<_>, _>>()?;
    // The RSVP is a write: its payload is settled before authoring, and the
    // submit path positions it on the actor chain.
    let operation = inkson::calendar::build_calendar_rsvp_event(
        realm_id,
        &actor_for_station(actor_id, attendees.2)?,
        strand_id,
        status,
        None,
        &calendar_fields,
        basis,
        None,
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

async fn inkson_schedule_frontier(
    client: &TestActorClient,
    realm_id: &str,
    strand_id: &str,
) -> Result<Vec<String>> {
    let events = client
        .sdk()
        .events_read_all_pages(realm_id)
        .await?
        .events
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            row.into_event().ok_or_else(|| {
                anyhow!(
                    "calendar schedule frontier requires complete Events; row {index} is redacted or reference-locked"
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(vec![inkson::calendar::schedule_revision_winner(
        &events,
        strand_id,
        arkret_canonical::DigestSuite::Sha256,
    )?
    .to_string()])
}

fn winner_for(strand: &Value, actor: &arkret_wire::ActorId) -> Option<Value> {
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
        .and_then(|cell| cell.get("winner"))
        .filter(|winner| !winner.is_null())
        .cloned()
}

fn winner_status(winner: &Value) -> Option<&str> {
    winner["entry"]["response"]["status"].as_str()
}

fn higher_event_id<'a>(
    left: &'a arkret_wire::Event,
    right: &'a arkret_wire::Event,
) -> &'a arkret_wire::Event {
    if left.event_id.token_bytes() > right.event_id.token_bytes() {
        left
    } else {
        right
    }
}

fn submitted_digest(response: &Value) -> Result<String> {
    response["cotest_event_digest"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("submit response carries no event digest"))
}

async fn wait_for_bootstrap_seal(client: &TestActorClient, realm_id: &str) -> Result<String> {
    eventually(
        "Realm bootstrap Seal",
        Duration::from_secs(30),
        Duration::from_millis(100),
        || async {
            let frontier = client.realm_seal_frontier(realm_id).await?;
            let state: arkret_models_collaboration::event_sync::SealFrontierState =
                serde_json::from_value(frontier)?;
            let frontier = state.frontier;
            frontier
                .sole_leaf()
                .map(ToString::to_string)
                .map_err(Into::into)
        },
    )
    .await
}

async fn wait_for_next_seal(
    client: &TestActorClient,
    realm_id: &str,
    predecessor: &str,
) -> Result<String> {
    eventually(
        "post-bootstrap capability Seal",
        Duration::from_secs(30),
        Duration::from_millis(100),
        || async {
            let frontier = client.realm_seal_frontier(realm_id).await?;
            let seal_id = frontier["frontier"]["seal_basis"]["leaves"][0]
                .as_str()
                .ok_or_else(|| anyhow!("Realm frontier has no seal_id"))?;
            if seal_id == predecessor {
                return Err(anyhow!("the capability grant is not sealed yet"));
            }
            Ok(seal_id.to_owned())
        },
    )
    .await
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
                grants.iter().any(|grant| {
                    grant["id"].as_str() == Some(grant_id)
                        || grant["grant_id"].as_str() == Some(grant_id)
                })
            }) {
                Ok(())
            } else {
                Err(anyhow!("capability grant {grant_id} is not projected yet"))
            }
        },
    )
    .await
}

async fn current_seal(client: &TestActorClient, realm_id: &str) -> Result<String> {
    let frontier = client.realm_seal_frontier(realm_id).await?;
    frontier["frontier"]["seal_basis"]["leaves"][0]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("Realm frontier has no seal_id"))
}

async fn grant_calendar_actions(
    client: &TestActorClient,
    realm_id: &str,
    bootstrap_seal: &str,
) -> Result<Vec<String>> {
    // A field-access constraint narrows every action in its grant. Keep the
    // ordinary create/RSVP actions on an unconstrained grant and put the
    // field-scoped Strand update on its own grant.
    let (plain_grant_id, response) = client
        .grant_realm_actions_to(
            realm_id,
            &client.actor,
            &["ak.strand.create", "ak.rsvp.set"],
        )
        .await?;
    let proposal_digest = response["control_proposal_acks"][0]["proposal_digest"]
        .as_str()
        .ok_or_else(|| anyhow!("calendar plain grant response omitted its proposal digest"))?;
    let subject = actor_core_id(&client.actor)?;
    wait_for_projected_grant(client, realm_id, &subject, &plain_grant_id).await?;
    client
        .await_control_proposal_settled(realm_id, proposal_digest, bootstrap_seal)
        .await?;
    let plain_grant_seal = current_seal(client, realm_id).await?;

    let mut calendar_field_constraint =
        arkret_models_collaboration::governance::grant_constraint::GrantConstraint::new(
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::FieldAccess,
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintEffect::Allow,
        );
    calendar_field_constraint.allowed_write_fields = vec!["metadata.fields.calendar".to_owned()];
    let (field_grant_id, response) = client
        .grant_realm_actions_with_constraints_to(
            realm_id,
            &client.actor,
            &["ak.strand.update"],
            vec![calendar_field_constraint],
        )
        .await?;
    let proposal_digest = response["control_proposal_acks"][0]["proposal_digest"]
        .as_str()
        .ok_or_else(|| anyhow!("calendar grant response omitted its proposal digest"))?;
    wait_for_projected_grant(client, realm_id, &subject, &field_grant_id).await?;
    client
        .await_control_proposal_settled(realm_id, proposal_digest, &plain_grant_seal)
        .await?;
    Ok(vec![plain_grant_id, field_grant_id])
}

async fn grant_calendar_rsvp_to(
    issuer: &TestActorClient,
    realm_id: &str,
    actor: &str,
    predecessor_seal: &str,
) -> Result<Vec<String>> {
    let (grant_id, response) = issuer
        .grant_realm_actions_to(realm_id, actor, &["ak.rsvp.set"])
        .await?;
    let proposal_digest = response["control_proposal_acks"][0]["proposal_digest"]
        .as_str()
        .ok_or_else(|| anyhow!("RSVP grant response omitted its proposal digest"))?;
    let subject = actor_core_id(actor)?;
    wait_for_projected_grant(issuer, realm_id, &subject, &grant_id).await?;
    issuer
        .await_control_proposal_settled(realm_id, proposal_digest, predecessor_seal)
        .await?;
    Ok(vec![grant_id])
}

async fn submit_prepared_event(
    client: &TestActorClient,
    event: &arkret_wire::Event,
) -> Result<String> {
    expect_json(
        client
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    event
        .proofs
        .first()
        .map(|proof| proof.event_digest.to_string())
        .ok_or_else(|| anyhow!("prepared Event carries no event digest"))
}

pub async fn calendar_rsvp_converges_across_concurrent_responses() -> Result<()> {
    let server = ArkretServer::spawn("calendar-rsvp-convergence").await?;
    let alice_did = actor_did_for_service_did(server.service_did(), ALICE_LOCAL)?;
    let bob_did = actor_did_for_service_did(server.service_did(), BOB_LOCAL)?;
    let alice_did = alice_did.as_str();
    let bob_did = bob_did.as_str();
    let alice = server
        .register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c1",
        )
        .await?;
    // This scenario covers RSVP lattice convergence, not the optional
    // device-pairing handoff surface. Two independently authored client views
    // of the same accepted device produce the concurrent actor branches
    // without calling an operation the SUT does not advertise.
    let alice_second_device = alice.clone();
    let bob = server
        .register_client(
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
    // The product coordinator, not an operator endpoint, must publish the
    // non-empty bootstrap Seal before a client authors its first ordinary Event.
    let bootstrap_seal = wait_for_bootstrap_seal(&alice, &realm_id).await?;
    alice.add_member(&realm_id, &bob).await?;
    let member_seal = wait_for_next_seal(&alice, &realm_id, &bootstrap_seal).await?;
    let calendar_grant_refs = grant_calendar_actions(&alice, &realm_id, &member_seal).await?;
    let alice_grant_seal = current_seal(&alice, &realm_id).await?;
    let bob_grant_refs =
        grant_calendar_rsvp_to(&alice, &realm_id, bob_did, &alice_grant_seal).await?;

    // Activation is one canonical pair: the schema ref plus the calendar
    // namespace. A lone ref or a lone subtree is calendar_activation_mismatch.
    let created = alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.strand.create",
            json!({
                "object": {
                    "schema": "ak.schema.strand.v1",
                    "realm_id": realm_id,
                    "schema_refs": ["ak.schema.calendar_event.v1"],
                    "metadata": {
                        "title": "Weekly sync",
                        "fields": {
                            "calendar": calendar_subtree(alice_did, bob_did, alice.service_id())?,
                            "x_future_display": {
                                "badge": "preserve-me",
                                "revision": 7
                            }
                        }
                    },
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": actor_for_station(alice_did, alice.service_id())?,
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
            Vec::new(),
            calendar_grant_refs.clone(),
        )
        .await?;
    let strand_id = created_strand_id(&created)?;
    let projected = read_soland_product_projection_strand(&alice, &strand_id).await?;
    let preserved_display = json!({"badge": "preserve-me", "revision": 7});
    if projected["fields"]["x_future_display"] != preserved_display {
        return Err(anyhow!(
            "unknown namespaced display metadata was lost on decode/store/read: {projected}"
        ));
    }

    let create_frontier = inkson_schedule_frontier(&alice, &realm_id, &strand_id).await?;
    if create_frontier.is_empty() {
        return Err(anyhow!(
            "calendar create must publish a schedule revision head; without it a client cannot \
             author an RSVP at all"
        ));
    }

    // Exercise a real schedule revision before RSVP authoring. Soland does not
    // claim the Calendar notification server profile: receiver-private DND,
    // blocklist and push rules remain holder-encrypted, so cross-recipient
    // Calendar fanout correctly fails closed until an authorized minimal
    // policy projection exists.
    alice
        .submit_event_with_causal_refs(
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
            create_frontier,
            calendar_grant_refs.clone(),
        )
        .await?;
    let frontier = inkson_schedule_frontier(&alice, &realm_id, &strand_id).await?;

    bob.submit_event_with_causal_refs(
        &realm_id,
        "ak.rsvp.set",
        inkson_rsvp_payload(
            &realm_id,
            &strand_id,
            bob_did,
            "accepted",
            &frontier,
            (alice_did, bob_did, alice.service_id()),
        )?,
        frontier.clone(),
        bob_grant_refs,
    )
    .await?;
    let bob_winner = winner_for(
        &read_soland_product_projection_strand(&bob, &strand_id).await?,
        &actor_for_station(bob_did, bob.service_id())?,
    )
    .ok_or_else(|| anyhow!("Bob's RSVP has no deterministic winner"))?;
    if winner_status(&bob_winner) != Some("accepted") {
        return Err(anyhow!(
            "Bob's RSVP did not materialize through the real reducer"
        ));
    }

    // Both client views author before either submits, so the responses have
    // the same actor frontier and neither can accidentally observe the other.
    let first_event = alice
        .author_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            frontier.clone(),
            calendar_grant_refs.clone(),
        )
        .await?;
    let second_event = alice_second_device
        .author_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "declined",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            frontier.clone(),
            calendar_grant_refs.clone(),
        )
        .await?;
    let first_digest = submit_prepared_event(&alice, &first_event).await?;
    let second_digest = submit_prepared_event(&alice_second_device, &second_event).await?;

    let strand = read_soland_product_projection_strand(&alice, &strand_id).await?;
    let winner = winner_for(&strand, &actor_for_station(alice_did, alice.service_id())?)
        .ok_or_else(|| anyhow!("concurrent responses have no deterministic winner"))?;
    let expected_status = if higher_event_id(&first_event, &second_event).event_id
        == first_event.event_id
    {
        "accepted"
    } else {
        "declined"
    };
    if winner_status(&winner) != Some(expected_status) {
        return Err(anyhow!(
            "concurrent responses did not select the fixed (depth, EventId) winner"
        ));
    }

    // A normal edit references the deterministic winner and therefore has a
    // greater causal depth than both same-depth candidates.
    let winning_digest = if expected_status == "accepted" {
        first_digest.clone()
    } else {
        second_digest.clone()
    };
    let mut resolving_basis = frontier.clone();
    resolving_basis.push(winning_digest);
    resolving_basis.sort();
    resolving_basis.dedup();
    let resolved = alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            // The entry basis stays the schedule winner; the additional causal
            // edge is the previous RSVP winner.
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            resolving_basis,
            calendar_grant_refs.clone(),
        )
        .await?;
    let resolved_digest = submitted_digest(&resolved)?;

    let strand = read_soland_product_projection_strand(&alice, &strand_id).await?;
    let winner = winner_for(&strand, &actor_for_station(alice_did, alice.service_id())?)
        .ok_or_else(|| anyhow!("causal successor has no winner"))?;
    if winner_status(&winner) != Some("tentative") {
        return Err(anyhow!("the causal successor must become the winner"));
    }

    // Exchange device/arrival order for a second concurrent pair, replay the
    // exact first Event, and verify neither arrival order nor idempotent replay
    // changes the exposed causal-register winner.
    let mut next_pair_basis = frontier.clone();
    next_pair_basis.push(resolved_digest);
    next_pair_basis.sort();
    next_pair_basis.dedup();
    let reverse_first = alice_second_device
        .author_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            next_pair_basis.clone(),
            calendar_grant_refs.clone(),
        )
        .await?;
    let reverse_second = alice
        .author_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "declined",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            next_pair_basis,
            calendar_grant_refs.clone(),
        )
        .await?;
    let reverse_first_digest = submit_prepared_event(&alice_second_device, &reverse_first).await?;
    let reverse_second_digest = submit_prepared_event(&alice, &reverse_second).await?;
    submit_prepared_event(&alice_second_device, &reverse_first).await?;
    let winner = winner_for(
        &read_soland_product_projection_strand(&alice_second_device, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
    )
    .ok_or_else(|| anyhow!("reversed concurrent responses have no winner"))?;
    let reverse_expected = if higher_event_id(&reverse_first, &reverse_second).event_id
        == reverse_first.event_id
    {
        "accepted"
    } else {
        "declined"
    };
    if winner_status(&winner) != Some(reverse_expected) {
        return Err(anyhow!(
            "reversed arrival plus exact replay changed the deterministic winner"
        ));
    }
    let mut final_resolution_basis = frontier.clone();
    final_resolution_basis.push(if reverse_expected == "accepted" {
        reverse_first_digest
    } else {
        reverse_second_digest
    });
    final_resolution_basis.sort();
    final_resolution_basis.dedup();
    alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            final_resolution_basis,
            calendar_grant_refs,
        )
        .await?;
    let final_winner = winner_for(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
    )
    .ok_or_else(|| anyhow!("final RSVP has no winner"))?;
    if winner_status(&final_winner) != Some("tentative") {
        return Err(anyhow!(
            "reversed arrival order must converge to the same causal successor"
        ));
    }

    Ok(())
}

/// The same Calendar CBS cell must survive a real process restart and exact
/// Event replay. The scenario uses a throw-away Postgres when Docker is
/// available; environments without either Postgres source report an explicit
/// live-row skip while the always-on in-memory convergence scenario still runs.
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
        .register_client(
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
    let bootstrap_seal = wait_for_bootstrap_seal(&alice, &realm_id).await?;
    let grants = grant_calendar_actions(&alice, &realm_id, &bootstrap_seal).await?;
    let created = alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.strand.create",
            json!({
                "object": {
                    "schema": "ak.schema.strand.v1",
                    "realm_id": realm_id,
                    "schema_refs": ["ak.schema.calendar_event.v1"],
                    "metadata": {
                        "title": "Durable weekly sync",
                        "fields": {
                            "calendar": calendar_subtree(alice_did, bob_did, alice.service_id())?,
                            "x_future_display": {
                                "badge": "preserve-me",
                                "revision": 7
                            }
                        }
                    },
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": actor_for_station(alice_did, alice.service_id())?,
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
            Vec::new(),
            grants.clone(),
        )
        .await?;
    let strand_id = created_strand_id(&created)?;
    let preserved_display = json!({"badge": "preserve-me", "revision": 7});
    let projected = read_soland_product_projection_strand(&alice, &strand_id).await?;
    if projected["fields"]["x_future_display"] != preserved_display {
        return Err(anyhow!(
            "unknown namespaced display metadata was lost on decode/store/read: {projected}"
        ));
    }
    let frontier = inkson_schedule_frontier(&alice, &realm_id, &strand_id).await?;
    let accepted = alice
        .author_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            frontier.clone(),
            grants.clone(),
        )
        .await?;
    let declined = alice_second_device
        .author_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "declined",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            frontier.clone(),
            grants.clone(),
        )
        .await?;
    let accepted_digest = submit_prepared_event(&alice, &accepted).await?;
    let declined_digest = submit_prepared_event(&alice_second_device, &declined).await?;
    let expected_status = if higher_event_id(&accepted, &declined).event_id == accepted.event_id {
        "accepted"
    } else {
        "declined"
    };
    let before_restart = winner_for(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
    );
    if before_restart.as_ref().and_then(winner_status) != Some(expected_status) {
        return Err(anyhow!(
            "pre-restart Calendar cell did not expose the deterministic winner"
        ));
    }

    assert_realm_identity(&alice, &realm_id).await?;
    server.kill_immediately().await?;
    drop(server);
    let mut server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice = server
        .demo_client(alice_did, "ak:device:01904100-0000-7000-8000-0000000000d1")
        .await?;
    let alice_second_device = alice.clone();
    let restarted_strand = read_soland_product_projection_strand(&alice, &strand_id).await?;
    assert_realm_identity(&alice, &realm_id).await?;
    if restarted_strand["fields"]["x_future_display"] != preserved_display {
        return Err(anyhow!(
            "unknown namespaced display metadata was lost across restart: {restarted_strand}"
        ));
    }
    let winner = winner_for(
        &restarted_strand,
        &actor_for_station(alice_did, alice.service_id())?,
    );
    if winner.as_ref().and_then(winner_status) != Some(expected_status) {
        return Err(anyhow!(
            "restart did not restore the deterministic RSVP winner: {restarted_strand}"
        ));
    }
    submit_prepared_event(&alice, &accepted).await?;
    submit_prepared_event(&alice_second_device, &declined).await?;
    let replayed = winner_for(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
    );
    if replayed.as_ref().and_then(winner_status) != Some(expected_status) {
        return Err(anyhow!("post-restart exact replay changed the RSVP winner"));
    }

    let mut resolution_basis = frontier.clone();
    resolution_basis.push(if expected_status == "accepted" {
        accepted_digest
    } else {
        declined_digest
    });
    resolution_basis.sort();
    resolution_basis.dedup();
    alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
            resolution_basis,
            grants,
        )
        .await?;
    server.kill_immediately().await?;
    drop(server);
    let server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice = server
        .demo_client(alice_did, "ak:device:01904100-0000-7000-8000-0000000000d1")
        .await?;
    let winner = winner_for(
        &read_soland_product_projection_strand(&alice, &strand_id).await?,
        &actor_for_station(alice_did, alice.service_id())?,
    );
    if winner.as_ref().and_then(winner_status) != Some("tentative") {
        return Err(anyhow!(
            "resolved RSVP cell did not survive the second restart"
        ));
    }

    drop(ephemeral);
    Ok(())
}

/// An RSVP whose effect was stripped must not be accepted.
///
/// This is the concrete defect the closure review found in the client: the
/// Event validated against the payload schema, so it looked fine, but it never
/// reached `ak.component.calendar.rsvp.v1` and the response silently did not
/// converge.
pub async fn calendar_rsvp_without_cell_effect_is_rejected() -> Result<()> {
    let server = ArkretServer::spawn("calendar-rsvp-effectless").await?;
    let alice_did = actor_did_for_service_did(server.service_did(), ALICE_LOCAL)?;
    let bob_did = actor_did_for_service_did(server.service_did(), BOB_LOCAL)?;
    let alice_did = alice_did.as_str();
    let bob_did = bob_did.as_str();
    let alice = server
        .register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c3",
        )
        .await?;
    let created = alice
        .create_realm_with(json!({
            "title": "RSVP effect contract",
            "summary": "RSVP effect contract",
            "public": false,
            "schema_refs": ["ak.schema.realm.v1"],
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("realm create response has no realm_id"))?
        .to_owned();
    let bootstrap_seal = wait_for_bootstrap_seal(&alice, &realm_id).await?;
    let strand_grant_refs = grant_calendar_actions(&alice, &realm_id, &bootstrap_seal).await?;
    let strand_created = alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.strand.create",
            json!({
                "object": {
                    "schema": "ak.schema.strand.v1",
                    "realm_id": realm_id,
                    "schema_refs": ["ak.schema.calendar_event.v1"],
                    "metadata": {
                        "title": "Weekly sync",
                        "fields": {"calendar": calendar_subtree(alice_did, bob_did, alice.service_id())?}
                    },
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": actor_for_station(alice_did, alice.service_id())?,
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
            Vec::new(),
            strand_grant_refs,
        )
        .await?;
    let strand_id = created_strand_id(&strand_created)?;

    let frontier = inkson_schedule_frontier(&alice, &realm_id, &strand_id).await?;

    let event = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &frontier,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let submission = crate::publication::initial_submission(event, "")?;
    let invalid_submission = arkret_test_kit::wire_negative_from_sdk(&submission, |body| {
        body["event"]["effects"] = json!([]);
    })?;
    let response = alice
        .post("/_arkret/self/events")
        .json(&invalid_submission)
        .send()
        .await?;
    if response.status() == StatusCode::OK {
        return Err(anyhow!(
            "an effect-less RSVP must not be accepted: it never reaches its CBS cell"
        ));
    }
    Ok(())
}
