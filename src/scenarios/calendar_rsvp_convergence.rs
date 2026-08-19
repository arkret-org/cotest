//! Live Calendar RSVP convergence against a real server.
//!
//! The unit and fixture suites pin the rules in isolation; this exercises them
//! end to end, because the convergence properties only mean something once a
//! real reducer has admitted the Events:
//!
//! * an RSVP carries the registry-derived cell effect, so it reaches its CBA cell instead of being
//!   accepted as a side-band record;
//! * two responses that do not observe each other stay exposed as two heads — the server may not
//!   pick a winner by HLC, arrival order or event id;
//! * a response that names both heads in `causal_refs` dominates them, so the responder converges
//!   back to one answer;
//!
//! Cell-subject isolation between responders is not repeated here: the
//! accountable actor is part of the composite subject, which the reducer unit
//! tests already pin. What only a live server can show is the concurrency and
//! domination behaviour below.

use std::time::Duration;

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, TestActorClient, actor_core_id, eventually, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_full_id;

const ALICE_LOCAL: &str = "cotest-rsvp-alice";
const BOB_LOCAL: &str = "cotest-rsvp-bob";
/// The Strand id of a create the server has accepted.
///
/// A Strand is an event-derived kind: its id is `retype(event_id)` of its own
/// create Event, so the only way to name it is to submit the create first and
/// read the id back. Carrying a pre-minted id in the create payload is
/// `object_id_not_event_derived`.
fn created_strand_id(submitted: &Value) -> Result<String> {
    let event_id = submitted["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("Strand create response carries no accepted event_id"))?;
    let event_id = arkret_identifiers::EventId::new(event_id.to_owned())?;
    Ok(arkret_identifiers::StrandId::from_event_id(&event_id).to_string())
}

fn calendar_subtree(alice_did: &str, bob_did: &str) -> Result<Value> {
    Ok(json!({
        "start": "2026-06-22T09:00:00",
        "end": "2026-06-22T10:00:00",
        "timezone": "America/Los_Angeles",
        "tzdb_version": "2025b",
        "all_day": false,
        "status": "confirmed",
        "recurrence": {"frequency": "weekly", "count": 10},
        "attendees": [
            {"actor_id": actor_core_id(alice_did)?, "role": "organizer"},
            {"actor_id": actor_core_id(bob_did)?, "role": "required"}
        ]
    }))
}

fn inkson_rsvp_payload(
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    status: &str,
    basis: &[String],
    attendees: (&str, &str),
) -> Result<Value> {
    let calendar_fields = serde_json::from_value(calendar_subtree(attendees.0, attendees.1)?)?;
    let basis = basis
        .iter()
        .cloned()
        .map(arkret_identifiers::Hash::new)
        .collect::<Result<Vec<_>, _>>()?;
    let event = inkson::calendar::build_calendar_rsvp_event(
        realm_id,
        actor_id,
        strand_id,
        status,
        None,
        &calendar_fields,
        basis,
        0,
        arkret_identifiers::Hlc::new("01970e589d21-0000-a13f9c2e")?,
    )?;
    Ok(serde_json::to_value(event.payload)?)
}

/// Reads the schedule revision frontier and the live RSVP heads.
async fn read_strand(client: &TestActorClient, strand_id: &str) -> Result<Value> {
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
    Ok(
        inkson::calendar::schedule_revision_heads(&events, strand_id)?
            .into_iter()
            .map(|digest| digest.as_str().to_owned())
            .collect(),
    )
}

fn heads_for(strand: &Value, actor: &str) -> Vec<Value> {
    strand["rsvps"]
        .as_array()
        .map(|cells| {
            cells
                .iter()
                .filter(|cell| cell["actor_id"].as_str() == Some(actor))
                .flat_map(|cell| {
                    cell["heads"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn head_statuses(heads: &[Value]) -> Vec<String> {
    let mut statuses: Vec<String> = heads
        .iter()
        .filter_map(|head| head["entry"]["response"]["status"].as_str())
        .map(ToOwned::to_owned)
        .collect();
    statuses.sort();
    statuses
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
            let root = frontier["frontier"]["control_event_set_root"]
                .as_str()
                .ok_or_else(|| anyhow!("Realm frontier has no control_event_set_root"))?;
            if root == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
                return Err(anyhow!("Realm bootstrap Seal is still empty"));
            }
            frontier["frontier"]["seal_id"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("Realm frontier has no seal_id"))
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
            let seal_id = frontier["frontier"]["seal_id"]
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
    eventually(
        "capability grant projection",
        Duration::from_secs(30),
        Duration::from_millis(100),
        || async {
            let effective = expect_json(
                client.get("/_arkret/self/authz/effective-grants").query(&[
                    ("subject", subject),
                    ("subject_principal_server_id", client.service_id()),
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
    frontier["frontier"]["seal_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("Realm frontier has no seal_id"))
}

async fn grant_calendar_actions(
    client: &TestActorClient,
    realm_id: &str,
    bootstrap_seal: &str,
) -> Result<Vec<String>> {
    // `ak.strand.update` is registered field-scoped: the capability-action
    // registry lists `allowed_write_fields` in its required_constraints, so a
    // bare grant can never cover it. The scenario only ever writes the
    // calendar subtree, so the grant names exactly that field.
    let mut calendar_field_constraint =
        arkret_models_collaboration::governance::grant_constraint::GrantConstraint::new(
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::FieldAccess,
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintEffect::Allow,
        );
    calendar_field_constraint.allowed_write_fields =
        vec!["metadata.fields.calendar".to_owned()];
    let (calendar_grant_id, response) = client
        .grant_realm_actions_with_constraints_to(
            realm_id,
            &client.actor,
            &["ak.strand.create", "ak.strand.update", "ak.rsvp.set"],
            vec![calendar_field_constraint],
        )
        .await?;
    let proposal_digest = response["control_proposal_acks"][0]["proposal_digest"]
        .as_str()
        .ok_or_else(|| anyhow!("calendar grant response omitted its proposal digest"))?;
    let subject = actor_core_id(&client.actor)?;
    wait_for_projected_grant(client, realm_id, &subject, &calendar_grant_id).await?;
    client
        .await_control_proposal_settled(realm_id, proposal_digest, bootstrap_seal)
        .await?;
    Ok(vec![calendar_grant_id])
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
        .iter()
        .find_map(arkret_wire::EventProof::as_producer)
        .map(|proof| proof.event_digest.to_string())
        .ok_or_else(|| anyhow!("prepared Event carries no event digest"))
}

pub async fn calendar_rsvp_converges_across_concurrent_responses() -> Result<()> {
    let server = ArkretServer::spawn("calendar-rsvp-convergence").await?;
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), ALICE_LOCAL)?;
    let bob_did = actor_did_for_service_full_id(server.service_full_id(), BOB_LOCAL)?;
    let alice_did = alice_did.as_str();
    let bob_did = bob_did.as_str();
    let alice_core_id = actor_core_id(alice_did)?;
    let bob_core_id = actor_core_id(bob_did)?;
    let alice = server
        .register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c1",
        )
        .await?;
    let alice_second_device = server
        .register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c2",
        )
        .await?;
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
            "schema_refs": ["ak.schema.realm.v1", "ak.profile.calendar_event.v1"],
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("realm create response has no realm_id"))?
        .to_owned();
    // The product coordinator, not an operator endpoint, must publish the
    // non-empty bootstrap Seal before a client authors its first DataEvent.
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
                        "fields": {"calendar": calendar_subtree(alice_did, bob_did)?}
                    },
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": alice_core_id,
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
            Vec::new(),
            calendar_grant_refs.clone(),
        )
        .await?;
    let strand_id = created_strand_id(&created)?;

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
                                {"actor_id": alice_core_id, "role": "organizer"},
                                {"actor_id": bob_core_id, "role": "required"}
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
            (alice_did, bob_did),
        )?,
        frontier.clone(),
        bob_grant_refs,
    )
    .await?;
    let bob_heads = heads_for(&read_strand(&bob, &strand_id).await?, &bob_core_id);
    if head_statuses(&bob_heads) != vec!["accepted".to_owned()] {
        return Err(anyhow!(
            "Bob's RSVP did not materialize through the real reducer"
        ));
    }

    // Both devices author before either submits, so the responses have the
    // same actor frontier and neither can accidentally observe the other.
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
                (alice_did, bob_did),
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
                (alice_did, bob_did),
            )?,
            frontier.clone(),
            calendar_grant_refs.clone(),
        )
        .await?;
    let first_digest = submit_prepared_event(&alice, &first_event).await?;
    let second_digest = submit_prepared_event(&alice_second_device, &second_event).await?;

    let strand = read_strand(&alice, &strand_id).await?;
    let heads = heads_for(&strand, &alice_core_id);
    if heads.len() != 2 {
        return Err(anyhow!(
            "concurrent responses must expose two heads, got {}; the server may not choose \
             between them by HLC, arrival order or event id",
            heads.len()
        ));
    }
    if head_statuses(&heads) != vec!["accepted".to_owned(), "declined".to_owned()] {
        return Err(anyhow!("both concurrent answers must remain visible"));
    }

    // Causal successor: naming both heads dominates them, so Alice converges
    // back to a single answer without anyone picking a winner for her.
    let mut resolving_basis = frontier.clone();
    resolving_basis.push(first_digest.clone());
    resolving_basis.push(second_digest.clone());
    resolving_basis.sort();
    resolving_basis.dedup();
    let resolved = alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            // The entry basis stays the schedule frontier; the extra causal
            // edges are what dominate the earlier RSVP heads.
            inkson_rsvp_payload(
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &frontier,
                (alice_did, bob_did),
            )?,
            resolving_basis,
            calendar_grant_refs.clone(),
        )
        .await?;
    let resolved_digest = submitted_digest(&resolved)?;

    let strand = read_strand(&alice, &strand_id).await?;
    let heads = heads_for(&strand, &alice_core_id);
    if heads.len() != 1 {
        return Err(anyhow!(
            "a response observing both heads must dominate them, got {} heads",
            heads.len()
        ));
    }
    if head_statuses(&heads) != vec!["tentative".to_owned()] {
        return Err(anyhow!("the surviving head must be the causal successor"));
    }

    // Exchange device/arrival order for a second concurrent pair, replay the
    // exact first Event, and verify neither arrival order nor idempotent replay
    // changes the exposed MV-register heads.
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
                (alice_did, bob_did),
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
                (alice_did, bob_did),
            )?,
            next_pair_basis,
            calendar_grant_refs.clone(),
        )
        .await?;
    let reverse_first_digest = submit_prepared_event(&alice_second_device, &reverse_first).await?;
    let reverse_second_digest = submit_prepared_event(&alice, &reverse_second).await?;
    submit_prepared_event(&alice_second_device, &reverse_first).await?;
    let heads = heads_for(
        &read_strand(&alice_second_device, &strand_id).await?,
        &alice_core_id,
    );
    if heads.len() != 2
        || head_statuses(&heads) != vec!["accepted".to_owned(), "declined".to_owned()]
    {
        return Err(anyhow!(
            "reversed arrival plus exact replay must retain exactly the two concurrent heads"
        ));
    }
    let mut final_resolution_basis = frontier.clone();
    final_resolution_basis.extend([reverse_first_digest, reverse_second_digest]);
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
                (alice_did, bob_did),
            )?,
            final_resolution_basis,
            calendar_grant_refs,
        )
        .await?;
    let final_heads = heads_for(&read_strand(&alice, &strand_id).await?, &alice_core_id);
    if final_heads.len() != 1 || head_statuses(&final_heads) != vec!["tentative".to_owned()] {
        return Err(anyhow!(
            "reversed arrival order must converge to the same causal successor"
        ));
    }

    Ok(())
}

/// The same Calendar CBA cell must survive a real process restart and exact
/// Event replay. The scenario uses a throw-away Postgres when Docker is
/// available; environments without either Postgres source report an explicit
/// live-row skip while the always-on in-memory convergence scenario still runs.
pub async fn calendar_rsvp_persists_across_restart_and_replay() -> Result<()> {
    let configured_database = std::env::var("COTEST_SOLAND_DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty());
    let mut ephemeral = None;
    let database_url = if let Some(url) = configured_database {
        url
    } else {
        ephemeral = crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?;
        let Some(database) = ephemeral.as_ref() else {
            eprintln!(
                "calendar RSVP restart row skipped: no COTEST_SOLAND_DATABASE_URL and Docker/Postgres unavailable"
            );
            return Ok(());
        };
        database.connect_url.clone()
    };

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
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), ALICE_LOCAL)?;
    let bob_did = actor_did_for_service_full_id(server.service_full_id(), BOB_LOCAL)?;
    let alice_did = alice_did.as_str();
    let bob_did = bob_did.as_str();
    let alice_core_id = actor_core_id(alice_did)?;
    let alice = server
        .register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000d1",
        )
        .await?;
    let alice_second_device = server
        .register_client(
            alice_did,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000d2",
        )
        .await?;
    let created = alice
        .create_realm_bootstrap_with(json!({
            "title": "RSVP restart",
            "summary": "RSVP restart",
            "public": false,
            "schema_refs": ["ak.schema.realm.v1", "ak.profile.calendar_event.v1"],
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
                        "fields": {"calendar": calendar_subtree(alice_did, bob_did)?}
                    },
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": alice_core_id,
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
            Vec::new(),
            grants.clone(),
        )
        .await?;
    let strand_id = created_strand_id(&created)?;
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
                (alice_did, bob_did),
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
                (alice_did, bob_did),
            )?,
            frontier.clone(),
            grants.clone(),
        )
        .await?;
    let accepted_digest = submit_prepared_event(&alice, &accepted).await?;
    let declined_digest = submit_prepared_event(&alice_second_device, &declined).await?;
    if heads_for(&read_strand(&alice, &strand_id).await?, &alice_core_id).len() != 2 {
        return Err(anyhow!(
            "pre-restart Calendar cell did not expose two heads"
        ));
    }

    server.kill_immediately().await?;
    drop(server);
    let mut server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice = server
        .demo_client(alice_did, "ak:device:01904100-0000-7000-8000-0000000000d1")
        .await?;
    let alice_second_device = server
        .demo_client(alice_did, "ak:device:01904100-0000-7000-8000-0000000000d2")
        .await?;
    let restarted_strand = read_strand(&alice, &strand_id).await?;
    let heads = heads_for(&restarted_strand, &alice_core_id);
    if heads.len() != 2
        || head_statuses(&heads) != vec!["accepted".to_owned(), "declined".to_owned()]
    {
        return Err(anyhow!(
            "restart did not restore the concurrent RSVP heads: {restarted_strand}"
        ));
    }
    submit_prepared_event(&alice, &accepted).await?;
    submit_prepared_event(&alice_second_device, &declined).await?;
    if heads_for(&read_strand(&alice, &strand_id).await?, &alice_core_id).len() != 2 {
        return Err(anyhow!("post-restart exact replay duplicated RSVP heads"));
    }

    let mut resolution_basis = frontier.clone();
    resolution_basis.extend([accepted_digest, declined_digest]);
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
                (alice_did, bob_did),
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
    let heads = heads_for(&read_strand(&alice, &strand_id).await?, &alice_core_id);
    if heads.len() != 1 || head_statuses(&heads) != vec!["tentative".to_owned()] {
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
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), ALICE_LOCAL)?;
    let bob_did = actor_did_for_service_full_id(server.service_full_id(), BOB_LOCAL)?;
    let alice_did = alice_did.as_str();
    let bob_did = bob_did.as_str();
    let alice_core_id = actor_core_id(alice_did)?;
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
            "schema_refs": ["ak.schema.realm.v1", "ak.profile.calendar_event.v1"],
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
                        "fields": {"calendar": calendar_subtree(alice_did, bob_did)?}
                    },
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": alice_core_id,
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
                (alice_did, bob_did),
            )?,
        )
        .await?;
    let submission = crate::publication::initial_submission(event, "")?;
    let invalid_submission = crate::harness::wire_negative_from_sdk(&submission, |body| {
        body["event"]["effects"] = json!([]);
    })?;
    let response = alice
        .post("/_arkret/self/events")
        .json(&invalid_submission)
        .send()
        .await?;
    if response.status() == StatusCode::OK {
        return Err(anyhow!(
            "an effect-less RSVP must not be accepted: it never reaches its CBA cell"
        ));
    }
    Ok(())
}
