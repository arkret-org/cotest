//! Live Calendar RSVP convergence against a real server.
//!
//! The unit and fixture suites pin the rules in isolation; this exercises them
//! end to end, because the convergence properties only mean something once a
//! real reducer has admitted the Events:
//!
//! * an RSVP is admitted as a signed Event and its complete entry reaches the materialized current
//!   value;
//! * two responses authored before either is submitted receive distinct RealmCommits; the later
//!   stream position is the current value, regardless of EventId order;
//! * exact replay and process restart preserve that value and its source Event.
//!
//! Subject isolation between responders is not repeated here: the accountable
//! actor is part of the composite subject, which reducer unit tests already pin.
//!
//! Reads use the Station-signed RealmStateSnapshot and its registered typed
//! current selectors, including the complete encrypted RSVP entry.

use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use arkret::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsGovernanceBindingPayload};
use arkret_wire::{EventId, RealmCommit, RealmId, ScopeRef};
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

struct RsvpMls {
    group: ArkretMlsGroup,
    genesis_ref: EventId,
    scope: ScopeRef,
}

async fn activate_rsvp_mls(client: &TestActorClient, realm_id: &str) -> Result<RsvpMls> {
    let realm = RealmId::new(realm_id.to_owned())?;
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let principal = client
        .principal
        .clone()
        .ok_or_else(|| anyhow!("Calendar MLS author has no provisioned device"))?;
    let actor = actor_for_station(&client.actor, client.service_id())?;
    let identity = ArkretMlsIdentity::new_human_device(
        actor.clone(),
        principal.device_id.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(principal.device_signing_key.clone()),
    )?;
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = identity.create_group_with_governance_binding(&scope, &binding)?;
    let member = super::mls_lifecycle_live::Member {
        client: client.clone(),
        account: actor
            .as_account_id()
            .ok_or_else(|| anyhow!("Calendar MLS author is not an Account"))?
            .clone(),
        actor,
        device: principal.device_id.clone(),
        method: arkret_wire::DidUrl::new(format!(
            "{}#{}",
            principal.did.as_str(),
            principal.device_id.as_str()
        ))
        .map_err(anyhow::Error::msg)?,
        key: principal.device_signing_key.clone(),
        authorize_event_id: principal.founding_authorize_event_id.clone(),
    };
    let creator_leaf_authority =
        super::cross_station_mls_welcome::genesis_creator_leaf_authority(&mut group, &member)?;
    let (group_info, tree) = group.public_group_state_bytes()?;
    let group_info_ref =
        super::mls_lifecycle_live::upload_public_blob(client, &realm, &group_info).await?;
    let tree_ref = super::mls_lifecycle_live::upload_public_blob(client, &realm, &tree).await?;
    let genesis_payload = arkret::MlsGenesisPayload {
        cipher_suite: arkret::NonEmptyString::new(
            super::mls_lifecycle_live::ACTIVE_SUITE.to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        group_info_ref: arkret_wire::BlobRef::new(group_info_ref)?,
        ratchet_tree_ref: arkret_wire::BlobRef::new(tree_ref)?,
        creator_leaf_authority,
        governance_binding: binding,
        created_at: chrono::Utc::now(),
    };
    genesis_payload.validate()?;
    let genesis = client
        .author_event(
            realm_id,
            arkret_wire::EventKind::MlsGenesis.as_str(),
            super::mls_lifecycle_live::canonical(serde_json::to_value(genesis_payload)?)?,
        )
        .await?;
    let commit = submit_prepared_event(client, &genesis).await?;
    ensure!(commit.event_ref == genesis.event_id);
    assert_committed(client, realm_id, &genesis.event_id).await?;
    super::message_mls_cross_station_live::install_bindings(&mut group, &[&member]).await?;
    Ok(RsvpMls {
        group,
        genesis_ref: genesis.event_id,
        scope,
    })
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
    mls: &mut RsvpMls,
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
    let mut payload = serde_json::to_value(operation.payload())?;
    let response = payload["entry"]["response"].clone();
    ensure!(
        response.is_object(),
        "Inkson RSVP has no response to encrypt"
    );
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        arkret_models_collaboration::objects::productivity::RSVP_RESPONSE_CONTENT_TYPE,
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        mls.scope.clone(),
        arkret_wire::EventKind::RsvpSet.as_str(),
        mls.group.epoch(),
        mls.genesis_ref.clone(),
        mls.group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let encrypted = mls
        .group
        .encrypt_payload(header, &arkret_canonical::canonical_json_bytes(&response)?)?;
    let envelope = arkret::mls::encrypted_envelope_from_payload(&encrypted)?;
    payload["entry"]
        .as_object_mut()
        .ok_or_else(|| anyhow!("RSVP entry is missing"))?
        .remove("response");
    payload["entry"]["encrypted_response"] = serde_json::to_value(envelope)?;
    let parsed: arkret_models_collaboration::objects::productivity::RsvpSetPayload =
        serde_json::from_value(payload.clone())?;
    parsed.validate()?;
    Ok(payload)
}

fn rsvp_entry(event: &arkret_wire::Event) -> Result<&Value> {
    event
        .payload
        .get("entry")
        .ok_or_else(|| anyhow!("signed RSVP Event lacks entry"))
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

async fn signed_strand_value(
    client: &TestActorClient,
    realm: &RealmId,
    strand_id: &arkret_wire::StrandId,
) -> Result<Value> {
    let snapshot = super::strand_watch_live::signed_snapshot(client, realm).await?;
    snapshot
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentRow::Value {
                selector:
                    arkret_wire::CurrentSelector::Strand {
                        strand_id: selected,
                    },
                value,
                ..
            } if selected == strand_id => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("signed Snapshot omits Calendar Strand {strand_id}"))
}

fn accepted_schedule_basis(submitted: &Value) -> Result<Vec<String>> {
    Ok(vec![
        crate::harness::submitted_event_id(submitted)?.to_string(),
    ])
}

async fn assert_signed_snapshot_rsvp(
    client: &TestActorClient,
    realm: &RealmId,
    strand: &arkret_wire::StrandId,
    actor: &arkret_wire::ActorId,
    accepted: &RealmCommit,
    entry: &Value,
) -> Result<()> {
    let snapshot = super::strand_watch_live::signed_snapshot(client, realm).await?;
    let current = snapshot
        .current_state_entries
        .iter()
        .find(|row| {
            matches!(row, arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Rsvp {
                    event_ref,
                    occurrence: None,
                    responder_actor_id,
                },
                ..
            } if event_ref == strand && responder_actor_id == actor)
        })
        .ok_or_else(|| anyhow!("signed Snapshot omits the exact RSVP current"))?;
    let arkret_wire::TypedCurrentRow::Value {
        source_stream_ref,
        revision,
        value,
        ..
    } = current;
    ensure!(
        source_stream_ref == &accepted.stream_ref
            && revision.commit_id == accepted.commit_id
            && revision.stream_position == accepted.stream_position
            && value == entry,
        "signed RSVP current differs from the accepted Commit and complete entry: {current:?}"
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
    let projected = signed_strand_value(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
    )
    .await?;
    let preserved_display = json!({"badge": "preserve-me", "revision": 7});
    if projected["metadata"]["fields"]["x_future_display"] != preserved_display {
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
    let mut mls = activate_rsvp_mls(&alice, &realm_id).await?;

    // Both responses are authored before either is submitted. The governing
    // Station still assigns a strict RealmCommit order to their current writes.
    let first_event = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &mut mls,
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
                &mut mls,
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
    assert_signed_snapshot_rsvp(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &second_commit,
        second_event
            .payload
            .get("entry")
            .ok_or_else(|| anyhow!("signed RSVP Event lacks entry"))?,
    )
    .await?;
    // A later response replaces the previous current without causal edges.
    let resolved = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &mut mls,
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let resolved_commit = submit_prepared_event(&alice, &resolved).await?;
    ensure!(resolved_commit.stream_position > second_commit.stream_position);
    assert_signed_snapshot_rsvp(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &resolved_commit,
        rsvp_entry(&resolved)?,
    )
    .await?;

    // Reverse arrival order for the second pair. Exact replay of the earlier
    // Commit cannot move the current back to its old value.
    let reverse_first = alice_second_device
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &mut mls,
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
                &mut mls,
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
    assert_signed_snapshot_rsvp(
        &alice_second_device,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &reverse_first_commit,
        rsvp_entry(&reverse_first)?,
    )
    .await?;

    let final_event = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &mut mls,
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let final_commit = submit_prepared_event(&alice, &final_event).await?;
    ensure!(final_commit.stream_position > reverse_first_commit.stream_position);
    assert_signed_snapshot_rsvp(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &final_commit,
        rsvp_entry(&final_event)?,
    )
    .await?;

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
    let projected = signed_strand_value(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
    )
    .await?;
    if projected["metadata"]["fields"]["x_future_display"] != preserved_display {
        return Err(anyhow!(
            "unknown namespaced display metadata was lost on decode/store/read: {projected}"
        ));
    }
    let schedule_basis = accepted_schedule_basis(&created)?;
    let mut mls = activate_rsvp_mls(&alice, &realm_id).await?;
    let accepted = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &mut mls,
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
                &mut mls,
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
    assert_signed_snapshot_rsvp(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &declined_commit,
        rsvp_entry(&declined)?,
    )
    .await?;

    assert_realm_identity(&alice, &realm_id).await?;
    server.kill_immediately().await?;
    drop(server);
    let mut server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice = server
        .standard_client(alice_did, "ak:device:01904100-0000-7000-8000-0000000000d1")
        .await?;
    let alice_second_device = alice.clone();
    let restarted_strand = signed_strand_value(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
    )
    .await?;
    assert_realm_identity(&alice, &realm_id).await?;
    assert_signed_snapshot_rsvp(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &declined_commit,
        declined
            .payload
            .get("entry")
            .ok_or_else(|| anyhow!("signed RSVP Event lacks entry"))?,
    )
    .await?;
    if restarted_strand["metadata"]["fields"]["x_future_display"] != preserved_display {
        return Err(anyhow!(
            "unknown namespaced display metadata was lost across restart: {restarted_strand}"
        ));
    }
    ensure!(
        submit_prepared_event(&alice, &accepted).await? == accepted_realm_commit
            && submit_prepared_event(&alice_second_device, &declined).await? == declined_commit,
        "restart changed an exact replay's RealmCommit"
    );
    assert_signed_snapshot_rsvp(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &declined_commit,
        rsvp_entry(&declined)?,
    )
    .await?;

    alice.remember_grant(
        &realm_id,
        &alice_grant,
        &["ak.strand.create", "ak.rsvp.set"],
    );
    let resolved = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &mut mls,
                &realm_id,
                &strand_id,
                alice_did,
                "tentative",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let resolved_commit = submit_prepared_event(&alice, &resolved).await?;
    ensure!(resolved_commit.stream_position > declined_commit.stream_position);
    server.kill_immediately().await?;
    drop(server);
    let server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice = server
        .standard_client(alice_did, "ak:device:01904100-0000-7000-8000-0000000000d1")
        .await?;
    assert_signed_snapshot_rsvp(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &resolved_commit,
        rsvp_entry(&resolved)?,
    )
    .await?;

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
    let mut mls = activate_rsvp_mls(&alice, &realm_id).await?;
    let valid = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            inkson_rsvp_payload(
                &mut mls,
                &realm_id,
                &strand_id,
                alice_did,
                "accepted",
                &schedule_basis,
                (alice_did, bob_did, alice.service_id()),
            )?,
        )
        .await?;
    let valid_commit = submit_prepared_event(&alice, &valid).await?;
    let mut malformed_payload = inkson_rsvp_payload(
        &mut mls,
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
    assert_signed_snapshot_rsvp(
        &alice,
        &RealmId::new(realm_id.clone())?,
        &arkret_wire::StrandId::new(strand_id.clone())?,
        &actor_for_station(alice_did, alice.service_id())?,
        &valid_commit,
        rsvp_entry(&valid)?,
    )
    .await?;
    Ok(())
}
