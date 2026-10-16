//! Actual source acceptance and dispatcher outcomes for frozen fanout authority.
use coland_storage::{RetentionTombstoneRecord, RetentionTombstoneStore};
use coland_storage_postgres::{Db, PgRetentionTombstoneStore, PoolTuning};

use super::terminal_restart_live::{
    ensure_same_intent, fanout, qualified_ordinary_candidate, sql, tombstone,
};
use super::*;
use crate::harness::CanonicalJsonBody;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows;

pub(super) async fn hold_schedule(url: &str, messages_only: bool) -> Result<()> {
    let condition = if messages_only {
        "IF NEW.payload_json::jsonb->'replications'->0->'event_submission'->'event'->>'kind' <> 'ak.message.create' THEN RETURN NEW; END IF;"
    } else {
        ""
    };
    sql(url, &format!("CREATE FUNCTION hold_frozen_schedule() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {condition} NEW.next_attempt_at := (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 600000; RETURN NEW; END $$; CREATE TRIGGER hold_frozen_schedule BEFORE INSERT ON federation_outbox FOR EACH ROW EXECUTE FUNCTION hold_frozen_schedule()")).await
}

pub(super) async fn release(url: &str, row: &Value) -> Result<()> {
    let url = url.to_owned();
    let id = row["id"].as_str().context("intent id")?.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        ensure!(connection.execute("UPDATE federation_outbox SET next_attempt_at=0 WHERE id=$1 AND state IN ('pending','pending_route')", &[&id])? == 1);
        Ok(())
    }).await?
}

pub(super) async fn settled(url: &str, commit: &RealmCommit, state: &str) -> Result<Value> {
    let deadline = Instant::now() + ROUTE_MISS_WINDOW;
    loop {
        let rows = fanout(url, commit).await?;
        ensure!(rows.len() == 1, "one distinct Station must have one intent");
        if rows[0]["state"] == state {
            return Ok(rows[0].clone());
        }
        ensure!(
            Instant::now() < deadline,
            "intent did not reach {state}: {}",
            rows[0]
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn frozen(row: &Value, witnesses: usize) -> Result<()> {
    ensure!(row["state"] == "pending" || row["state"] == "pending_route");
    ensure!(row["attempts"] == 0 && row["semantic_attempts"] == 0);
    let binding: coland_storage::RealmFanoutBinding =
        serde_json::from_value(row["realm_fanout"].clone())?;
    ensure!(binding.authority_witnesses.len() == witnesses);
    ensure!(
        !row["payload_json"]
            .as_str()
            .context("canonical body")?
            .contains("fanout_authorization_basis")
    );
    Ok(())
}

fn cancelled(before: &Value, after: &Value) -> Result<()> {
    ensure_same_intent(before, after)?;
    ensure!(after["state"] == "cancelled_authority_lost");
    ensure!(after["attempts"] == 0 && after["semantic_attempts"] == 0);
    ensure!(after["last_http_status"].is_null() && after["last_response_excerpt"].is_null());
    ensure!(after["last_error_code"] == "fanout_authority_lost");
    ensure!(after["completed_at"].as_i64().is_some_and(|at| at > 0));
    ensure!(after["next_attempt_at"] == after["completed_at"]);
    for key in [
        "lease_owner",
        "lease_token",
        "lease_expires_at",
        "leased_from_state",
        "policy_version",
    ] {
        ensure!(after[key].is_null());
    }
    let mut expected = before.clone();
    for key in [
        "state",
        "last_error_code",
        "next_attempt_at",
        "completed_at",
    ] {
        expected[key] = after[key].clone();
    }
    ensure!(
        expected == *after,
        "cancellation altered more than the closed outbox transition"
    );
    Ok(())
}

fn cancellation_effect(
    before: &Value,
    after: &Value,
    row_before: &Value,
    row_after: &Value,
) -> Result<()> {
    cancelled(row_before, row_after)?;
    for (table, old) in before.as_object().context("acceptance tables")? {
        if table == "federation_outbox" {
            let unchanged = |rows: &Value| -> Result<Vec<Value>> {
                Ok(rows
                    .as_array()
                    .context("outbox rows")?
                    .iter()
                    .filter(|row| row["id"] != row_before["id"])
                    .cloned()
                    .collect())
            };
            ensure!(
                unchanged(old)? == unchanged(&after[table])?,
                "another outbox changed"
            );
            ensure!(
                old.as_array()
                    .unwrap()
                    .iter()
                    .filter(|row| row["id"] == row_before["id"])
                    .count()
                    == 1
            );
            ensure!(
                after[table]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["id"] == row_after["id"])
                    == Some(row_after)
            );
        } else {
            ensure!(
                *old == after[table],
                "cancellation changed accepting table {table}"
            );
        }
    }
    ensure!(before.as_object().unwrap().len() == after.as_object().unwrap().len());
    Ok(())
}

async fn withdraw_bytes(url: &str, event: &Event, commit: &RealmCommit) -> Result<()> {
    let expired_at = commit.committed_at + chrono::Duration::seconds(1);
    while chrono::Utc::now() < expired_at {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Exercise the production retention writer; no new HTTP carrier and no
    // manufactured membership, Commit or outbox authority is installed.
    let db = Db::connect(
        Some(url),
        PoolTuning {
            max_size: Some(1),
            acquire_timeout_seconds: Some(10),
        },
    )
    .await?;
    let store = PgRetentionTombstoneStore {
        pool: db.pool.context("retention pool")?,
    };
    let record = RetentionTombstoneRecord {
        event_id: event.event_id.to_string(),
        realm_id: event.realm_id.to_string(),
        reason: "expired".to_owned(),
        policy_ttl_seconds: 1,
        expired_at,
        tombstoned_at: chrono::Utc::now(),
        sealed: true,
    };
    store.put(&record).await?;
    let stored = store
        .get(event.event_id.as_str())
        .await?
        .context("durable retention withdrawal")?;
    ensure!(
        stored.event_id == record.event_id
            && stored.realm_id == record.realm_id
            && stored.expired_at == record.expired_at
            && stored.sealed
    );
    Ok(())
}

pub async fn terminal_disclosure(withdraw: bool) -> Result<()> {
    let name = if withdraw {
        "terminal-disclosure-cancellation"
    } else {
        "terminal-disclosure-positive"
    };
    let Some(mut fixture) = current_origin_fixture(name).await? else {
        return Ok(());
    };
    let (_, control_commit, _) = Box::pin(qualified_ordinary_candidate(&fixture)).await?;
    let source_url = fixture._governance_database.connect_url.clone();
    settled(&source_url, &control_commit, "delivered").await?;
    hold_schedule(&source_url, false).await?;
    let (event, commit) = tombstone(&fixture).await?;
    let before = fanout(&source_url, &commit).await?;
    ensure!(before.len() == 1);
    frozen(&before[0], 1)?;
    let body = replication_body(&fixture.alice, &event, &commit).await?;
    ensure!(before[0]["payload_json"].as_str().map(str::as_bytes) == Some(body.as_slice()));
    fixture.group.server_mut(0).stop_external_process().await?;
    ensure!(fanout(&source_url, &commit).await? == before);
    if withdraw {
        withdraw_bytes(&source_url, &event, &commit).await?;
    }
    sql(&source_url, "DROP TRIGGER hold_frozen_schedule ON federation_outbox; DROP FUNCTION hold_frozen_schedule()").await?;
    release(&source_url, &before[0]).await?;
    let pending = fanout(&source_url, &commit).await?.remove(0);
    let source_before = acceptance_rows(&source_url).await?;
    let receiver_url = fixture._member_database.connect_url.clone();
    let receiver_before = acceptance_rows(&receiver_url).await?;
    ensure!(
        !receiver_before["canonical_events"]
            .as_array()
            .context("receiver originals")?
            .iter()
            .any(|row| row["envelope"]["event_id"] == event.event_id.as_str()),
        "terminal reached receiver before the sender boundary"
    );
    fixture.group.server_mut(0).start_external_process().await?;
    let outcome = settled(
        &source_url,
        &commit,
        if withdraw {
            "cancelled_authority_lost"
        } else {
            "delivered"
        },
    )
    .await?;
    ensure_same_intent(&pending, &outcome)?;
    if withdraw {
        cancellation_effect(
            &source_before,
            &acceptance_rows(&source_url).await?,
            &pending,
            &outcome,
        )?;
        ensure!(
            receiver_before == acceptance_rows(&receiver_url).await?,
            "cancelled terminal reached recipient acceptance"
        );
        fixture
            .group
            .server_mut(0)
            .restart_external_process()
            .await?;
        ensure!(
            fanout(&source_url, &commit).await? == vec![outcome.clone()],
            "restart revived cancelled terminal"
        );
        ensure!(receiver_before == acceptance_rows(&receiver_url).await?);
        println!(
            "[frozen-authority] accepted_terminal=1 original_witnesses=1 durable_byte_withdrawal=1 source_process_restart=2 cancelled_authority_lost=1 http_attempts=0 accepted_originals_preserved=1 receiver_acceptance_rows_unchanged=1"
        );
    } else {
        ensure!(
            outcome["last_http_status"] == 200
                && outcome["attempts"].as_i64().is_some_and(|n| n > 0)
        );
        ensure_same_commit(
            &commit,
            &wait_held(&fixture.bob, &event.event_id, ROUTE_MISS_WINDOW).await?,
        )?;
        let receiver = acceptance_rows(&receiver_url).await?;
        let exact_terminal = |rows: &Value| -> Result<Value> {
            let matches: Vec<_> = rows["realm_bootstrap_current_results"]
                .as_array()
                .context("terminal current")?
                .iter()
                .filter(|row| {
                    row["result_family"] == "realm_tombstone"
                        && row["realm_id"] == commit.realm_id.as_str()
                        && row["current_commit_id"] == commit.commit_id.as_str()
                })
                .collect();
            ensure!(
                matches.len() == 1,
                "missing or ambiguous exact accepted terminal projection"
            );
            Ok(matches[0]["value"].clone())
        };
        ensure!(
            exact_terminal(&receiver)? == exact_terminal(&source_before)?,
            "replica terminal value differs from the accepted source"
        );
        println!(
            "[frozen-authority] accepted_terminal=1 original_witnesses=1 complete_disclosure_preserved=1 source_process_restart=1 actual_signed_peer_delivery=1 exact_terminal_commit_held=1"
        );
    }
    Ok(())
}

async fn carol_join(
    fixture: &CurrentOriginFixture,
    carol: &TestActorClient,
    account: &AccountId,
    request: &str,
) -> Result<RealmCommit> {
    prepare_join(
        carol,
        &fixture.realm,
        fixture.group.server(0),
        request,
        RealmJoinIntent::MemberJoin,
    )
    .await?;
    let event = carol
        .author_event(
            &fixture.realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &fixture.realm,
                account.clone(),
                MembershipPayloadState::Join,
                "frozen witness member",
            )?,
        )
        .await?;
    let commit = submit_and_expect_commit(carol, account, CAROL_DEVICE, &event).await?;
    ensure_same_commit(
        &commit,
        &wait_held(carol, &event.event_id, ROUTE_MISS_WINDOW).await?,
    )?;
    wait_for_titled_row(carol, &fixture.realm, "Federation current origin replay").await?;
    Ok(commit)
}

async fn leave(
    fixture: &CurrentOriginFixture,
    client: &TestActorClient,
    account: &AccountId,
    device: &str,
) -> Result<RealmCommit> {
    let event = client
        .author_event(
            &fixture.realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &fixture.realm,
                account.clone(),
                MembershipPayloadState::Leave,
                "frozen witness departure",
            )?,
        )
        .await?;
    let commit = submit_and_expect_commit(client, account, device, &event).await?;
    wait_not_listed(client, &fixture.realm, ROUTE_MISS_WINDOW).await?;
    settled(
        &fixture._governance_database.connect_url,
        &commit,
        "delivered",
    )
    .await?;
    Ok(commit)
}

pub async fn remaining_witness_and_rejoin() -> Result<()> {
    let Some(mut fixture) = current_origin_fixture("frozen-witness-or-rejoin").await? else {
        return Ok(());
    };
    let (carol, carol_account) = standard_client(
        fixture.group.server(1),
        &fixture._coauth,
        "frozen-carol",
        CAROL_DEVICE,
    )
    .await?;
    let joined = carol_join(
        &fixture,
        &carol,
        &carol_account,
        "ak:request:019b0000-0000-7000-8000-000000002601",
    )
    .await?;
    let source_url = fixture._governance_database.connect_url.clone();
    settled(&source_url, &joined, "delivered").await?;
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (control, control_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "control full canonical delivery",
    )
    .await?;
    ensure_same_commit(
        &control_commit,
        &wait_held(&carol, &control.event_id, HELD_WINDOW).await?,
    )?;
    settled(&source_url, &control_commit, "delivered").await?;
    hold_schedule(&source_url, true).await?;
    let (original, original_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "still owed to original Carol witness",
    )
    .await?;
    let first = fanout(&source_url, &original_commit).await?.remove(0);
    frozen(&first, 2)?;
    let body = replication_body(&fixture.alice, &original, &original_commit).await?;
    ensure!(first["payload_json"].as_str().map(str::as_bytes) == Some(body.as_slice()));
    let bob_account = AccountId::new(
        fixture
            .bob
            .principal
            .as_ref()
            .context("Bob principal")?
            .core_id
            .clone(),
        fixture.group.server(1).service_id().clone(),
    );
    let receiver_url = fixture._member_database.connect_url.clone();
    let opening = acceptance_rows(&receiver_url).await?["replica_stream_anchors"]
        .as_array()
        .context("durable opening prefix")?
        .iter()
        .find(|row| row["realm_id"] == fixture.realm)
        .context("Realm opening prefix")?
        .clone();
    ensure!(opening["member_account_id"] == serde_json::to_value(&bob_account)?);
    ensure!(opening["member_account_id"] != serde_json::to_value(&carol_account)?);
    leave(&fixture, &fixture.bob, &bob_account, BOB_DEVICE).await?;
    release(&source_url, &first).await?;
    let delivered = settled(&source_url, &original_commit, "delivered").await?;
    ensure_same_intent(&first, &delivered)?;
    ensure!(delivered["last_http_status"] == 200);
    ensure_same_commit(
        &original_commit,
        &wait_held(&carol, &original.event_id, HELD_WINDOW).await?,
    )?;
    let (old, old_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "never revived by new Carol join",
    )
    .await?;
    let second = fanout(&source_url, &old_commit).await?.remove(0);
    frozen(&second, 1)?;
    let body = replication_body(&fixture.alice, &old, &old_commit).await?;
    ensure!(second["payload_json"].as_str().map(str::as_bytes) == Some(body.as_slice()));
    leave(&fixture, &carol, &carol_account, CAROL_DEVICE).await?;
    let departed = acceptance_rows(&receiver_url).await?;
    let preserved = departed["replica_stream_anchors"]
        .as_array()
        .context("departed opening prefix")?
        .iter()
        .find(|row| row["realm_id"] == fixture.realm)
        .context("retained opening prefix")?;
    ensure!(preserved["member_account_id"] == opening["member_account_id"]);
    ensure!(preserved["join_commit_id"] == opening["join_commit_id"]);
    let rejoined = carol_join(
        &fixture,
        &carol,
        &carol_account,
        "ak:request:019b0000-0000-7000-8000-000000002602",
    )
    .await?;
    settled(&source_url, &rejoined, "delivered").await?;
    ensure!(
        second["realm_fanout"]["authority_witnesses"][0]["membership_event_ref"]
            == joined.event_ref.as_str()
    );
    ensure!(rejoined.event_ref != joined.event_ref);
    fixture.group.server_mut(0).stop_external_process().await?;
    sql(&source_url, "DROP TRIGGER hold_frozen_schedule ON federation_outbox; DROP FUNCTION hold_frozen_schedule()").await?;
    release(&source_url, &second).await?;
    let pending = fanout(&source_url, &old_commit).await?.remove(0);
    let source_before = acceptance_rows(&source_url).await?;
    let receiver_before = acceptance_rows(&receiver_url).await?;
    fixture.group.server_mut(0).start_external_process().await?;
    let outcome = settled(&source_url, &old_commit, "cancelled_authority_lost").await?;
    cancellation_effect(
        &source_before,
        &acceptance_rows(&source_url).await?,
        &pending,
        &outcome,
    )?;
    ensure!(
        receiver_before == acceptance_rows(&receiver_url).await?,
        "new join revived old sender effects"
    );
    let (terminal, terminal_commit) = tombstone(&fixture).await?;
    let terminal_intent = settled(&source_url, &terminal_commit, "delivered").await?;
    ensure!(
        terminal_intent["realm_fanout"]["authority_witnesses"]
            .as_array()
            .context("remaining member terminal basis")?
            .len()
            == 1
    );
    ensure_same_commit(
        &terminal_commit,
        &wait_held(&carol, &terminal.event_id, HELD_WINDOW).await?,
    )?;
    wait_not_listed(&fixture.bob, &fixture.realm, HELD_WINDOW).await?;
    println!(
        "[frozen-authority] independent_accepted_actors=3 complete_frozen_witness_or=1 old_member_left=1 actual_signed_delivery=1 different_opening_member_preserved=1 later_member_own_leave_bound_result=1 all_original_witnesses_lost=1 actual_same_actor_rejoin=1 original_basis_unchanged=1 cancelled_authority_lost=1 http_attempts=0 receiver_acceptance_rows_unchanged=1"
    );
    Ok(())
}

/// Revoke complete-byte policy and Circle membership through signed Events.
/// No SQL fixture may manufacture a revoked authority verdict.
pub async fn scope_and_policy_withdrawal() -> Result<()> {
    use arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload;

    use crate::scenarios::circle_poll_scope_live::{circle_create, circle_event, join_circle};
    let Some(mut fixture) = current_origin_fixture("frozen-scope-policy-withdrawal").await? else {
        return Ok(());
    };
    let source = fixture._governance_database.connect_url.clone();
    let receiver = fixture._member_database.connect_url.clone();
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (_, control) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "policy control full delivery",
    )
    .await?;
    settled(&source, &control, "delivered").await?;
    let rows = acceptance_rows(&source).await?;
    let policy = rows["realm_bootstrap_current_results"]
        .as_array()
        .context("policy currents")?
        .iter()
        .find(|row| {
            row["realm_id"] == fixture.realm
                && row["result_family"] == "realm_plaintext_visible_services"
        })
        .context("accepted plaintext policy")?["value"]
        .clone();
    let original_policy: PlaintextVisibleServicesPayload = serde_json::from_value(policy)?;
    hold_schedule(&source, true).await?;
    let (_, pending_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "policy withdrawn before dispatch",
    )
    .await?;
    let pending = fanout(&source, &pending_commit).await?.remove(0);
    frozen(&pending, 1)?;
    let mut withdrawn = original_policy.clone();
    withdrawn
        .services
        .retain(|service| service.service_id != *fixture.group.server(1).service_id());
    let denied = fixture
        .bob
        .author_event(
            &fixture.realm,
            EventKind::RealmPlaintextVisibleServices.as_str(),
            withdrawn.to_value()?,
        )
        .await?;
    let before_denied = acceptance_rows(&source).await?;
    let response = fixture
        .bob
        .post("/_arkret/self/events")
        .canonical_json(&EventAdmissionSubmission::new(denied))?
        .send()
        .await?;
    ensure!(response.status() == StatusCode::FORBIDDEN);
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(problem.problem_type.ends_with("capability_denied"));
    super::terminal_restart_live::ensure_ordinary_refusal_rows(
        &before_denied,
        acceptance_rows(&source).await?,
        &fixture.bob,
    )?;
    let event = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::RealmPlaintextVisibleServices.as_str(),
            withdrawn.to_value()?,
        )
        .await?;
    let cut =
        submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
            .await?;
    settled(&source, &cut, "delivered").await?;
    fixture.group.server_mut(0).stop_external_process().await?;
    release(&source, &pending).await?;
    let pending = fanout(&source, &pending_commit).await?.remove(0);
    let before = acceptance_rows(&source).await?;
    let receiver_before = acceptance_rows(&receiver).await?;
    fixture.group.server_mut(0).start_external_process().await?;
    let cancelled = settled(&source, &pending_commit, "cancelled_authority_lost").await?;
    cancellation_effect(
        &before,
        &acceptance_rows(&source).await?,
        &pending,
        &cancelled,
    )?;
    ensure!(receiver_before == acceptance_rows(&receiver).await?);
    let policy_evidence = json!({"original_policy":original_policy,"withdrawn_policy":withdrawn,
        "withdrawal_commit":cut,"pending_intent":pending,"cancelled_intent":cancelled,
        "source_before":before,"source_after":acceptance_rows(&source).await?,"receiver_unchanged":receiver_before});
    let event = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::RealmPlaintextVisibleServices.as_str(),
            original_policy.to_value()?,
        )
        .await?;
    let restored =
        submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
            .await?;
    settled(&source, &restored, "delivered").await?;
    ensure!(fanout(&source, &pending_commit).await? == vec![cancelled]);
    sql(&source, "DROP TRIGGER hold_frozen_schedule ON federation_outbox; DROP FUNCTION hold_frozen_schedule()").await?;
    let (fresh, fresh_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "fresh policy-authorized delivery",
    )
    .await?;
    settled(&source, &fresh_commit, "delivered").await?;
    ensure_same_commit(
        &fresh_commit,
        &wait_held(&fixture.bob, &fresh.event_id, HELD_WINDOW).await?,
    )?;

    let alice_actor = ActorId::account(fixture.alice_account.clone());
    let bob_account = AccountId::new(
        fixture
            .bob
            .principal
            .as_ref()
            .context("Bob principal")?
            .core_id
            .clone(),
        fixture.group.server(1).service_id().clone(),
    );
    let bob_actor = ActorId::account(bob_account.clone());
    let circle = circle_create(
        &fixture.alice,
        &fixture.realm,
        &alice_actor,
        "Frozen private scope",
        "Frozen",
    )
    .await?;
    join_circle(&fixture.alice, &fixture.realm, &circle, &alice_actor).await?;
    let realm_id = RealmId::new(fixture.realm.clone())?;
    let grant = arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
        schema: "ak.schema.capability.v1".into(),
        realm_id: Some(realm_id.clone()),
        issuer_id: alice_actor.clone(),
        subject:
            arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
                bob_actor.clone(),
            ),
        actions: vec!["ak.circle.member.add".into()],
        resources: vec![arkret_wire::WireResourceSelector::circle(
            realm_id.clone(),
            circle.clone(),
        )],
        constraints: Vec::new(),
        issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
            realm_id: realm_id.clone(),
            authority_event_ref: realm_id.event_id(),
            authority_generation: 0,
        }],
        issued_at: chrono::Utc::now(),
    };
    let event = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::CapabilityGrant.as_str(),
            serde_json::to_value(
                arkret_models_collaboration::events_payloads::CapabilityGrantPayload { grant },
            )?,
        )
        .await?;
    let granted =
        submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
            .await?;
    settled(&source, &granted, "delivered").await?;
    fixture.bob.remember_grant(
        &fixture.realm,
        arkret_wire::GrantId::from_event_id(&event.event_id).as_str(),
        &["ak.circle.member.add"],
    );
    let parent = fixture
        .alice
        .parent_membership_revision(&fixture.realm, &bob_actor)
        .await?;
    let join = circle_event(
        &fixture.bob,
        &fixture.realm,
        &circle,
        EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":bob_actor,"membership":"join",
            "expected_membership":null,"parent_membership_revision":parent}),
    )
    .await?;
    submit_and_expect_commit(&fixture.bob, &bob_account, BOB_DEVICE, &join).await?;
    let strand_event = circle_event(&fixture.alice, &fixture.realm, &circle, EventKind::StrandCreate,
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":fixture.realm,
            "scope_circle_id":circle,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Private frozen strand"},"state":"active","created_by":alice_actor}})).await?;
    let strand_commit = submit_and_expect_commit(
        &fixture.alice,
        &fixture.alice_account,
        ALICE_DEVICE,
        &strand_event,
    )
    .await?;
    settled(&source, &strand_commit, "delivered").await?;
    let strand = arkret_wire::StrandId::from_event_id(&strand_event.event_id);
    let event = circle_event(
        &fixture.alice,
        &fixture.realm,
        &circle,
        EventKind::MessageCreate,
        message_create_text_payload(strand.as_str(), "private control complete bytes")?,
    )
    .await?;
    let control =
        submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
            .await?;
    settled(&source, &control, "delivered").await?;
    ensure_same_commit(
        &control,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    hold_schedule(&source, true).await?;
    let event = circle_event(
        &fixture.alice,
        &fixture.realm,
        &circle,
        EventKind::MessageCreate,
        message_create_text_payload(strand.as_str(), "private scope withdrawn before dispatch")?,
    )
    .await?;
    let withheld =
        submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
            .await?;
    let intent = fanout(&source, &withheld).await?.remove(0);
    frozen(&intent, 1)?;
    ensure!(
        intent["realm_fanout"]["authority_witnesses"][0]["circle_membership_event_ref"].is_string()
    );
    let leave = circle_event(&fixture.bob, &fixture.realm, &circle, EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":bob_actor,"membership":"leave","expected_membership":"join"})).await?;
    let left = submit_and_expect_commit(&fixture.bob, &bob_account, BOB_DEVICE, &leave).await?;
    settled(&source, &left, "delivered").await?;
    fixture.group.server_mut(0).stop_external_process().await?;
    release(&source, &intent).await?;
    let intent = fanout(&source, &withheld).await?.remove(0);
    let before = acceptance_rows(&source).await?;
    let receiver_before = acceptance_rows(&receiver).await?;
    fixture.group.server_mut(0).start_external_process().await?;
    let cancelled = settled(&source, &withheld, "cancelled_authority_lost").await?;
    cancellation_effect(
        &before,
        &acceptance_rows(&source).await?,
        &intent,
        &cancelled,
    )?;
    ensure!(receiver_before == acceptance_rows(&receiver).await?);
    ensure!(
        receiver_before["member_state_current_results"]
            .as_array()
            .context("Realm membership")?
            .iter()
            .any(|row| row["realm_id"] == fixture.realm
                && row["member_id"] == bob_actor.to_string()
                && row["membership"] == "join")
    );
    let parent = fixture
        .alice
        .parent_membership_revision(&fixture.realm, &bob_actor)
        .await?;
    let rejoin = circle_event(
        &fixture.bob,
        &fixture.realm,
        &circle,
        EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":bob_actor,"membership":"join",
            "expected_membership":"leave","parent_membership_revision":parent}),
    )
    .await?;
    submit_and_expect_commit(&fixture.bob, &bob_account, BOB_DEVICE, &rejoin).await?;
    fixture
        .group
        .server_mut(0)
        .restart_external_process()
        .await?;
    ensure!(fanout(&source, &withheld).await? == vec![cancelled]);
    sql(&source, "DROP TRIGGER hold_frozen_schedule ON federation_outbox; DROP FUNCTION hold_frozen_schedule()").await?;
    let event = circle_event(
        &fixture.alice,
        &fixture.realm,
        &circle,
        EventKind::MessageCreate,
        message_create_text_payload(strand.as_str(), "fresh explicit Circle regrant")?,
    )
    .await?;
    let fresh =
        submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
            .await?;
    settled(&source, &fresh, "delivered").await?;
    ensure_same_commit(
        &fresh,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/terminal-authority-closure");
    std::fs::create_dir_all(&directory)?;
    std::fs::write(
        directory.join("scope-policy-withdrawal.json"),
        serde_json::to_vec_pretty(
            &json!({"policy":policy_evidence,"scope":{"withdrawal_commit":left,
            "pending_intent":intent,"source_before":before,"receiver_unchanged":receiver_before,
            "new_join":rejoin,"fresh_delivery":fresh}}),
        )?,
    )?;
    println!(
        "[frozen-authority] signed_policy_withdrawal=1 signed_scope_leave=1 cancelled_without_http=2 receiver_zero_effects=2 old_intent_not_revived=2 explicit_regrant_fresh_delivery=2"
    );
    Ok(())
}
