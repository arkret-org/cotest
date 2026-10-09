//! Strand lifecycle and business stage use the same accepted durable object.

use anyhow::{Context as _, Result, ensure};
use arkret_models_collaboration::events_payloads::strand::{
    StrandPatchPayload, StrandStageSetPayload,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::governance::realm_lifecycle::ObjectLifecyclePayload;
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, CurrentSelector, Event,
    EventKind, RealmCommit, RealmId, StrandId, TypedCurrentRow,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    TestActorClient, TestServerGroup, expect_api_error, expect_json, message_create_text_payload,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, grant_realm_actions, membership_payload,
    standard_client, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::strand_watch_live::signed_snapshot;

const GROUP: &str = "strand-lifecycle-live";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002371";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002372";

async fn value(
    client: &TestActorClient,
    realm: &RealmId,
    strand: &StrandId,
    commit: Option<&RealmCommit>,
) -> Result<Value> {
    let snapshot = signed_snapshot(client, realm).await?;
    for entry in snapshot.current_state_entries {
        if let TypedCurrentRow::Value {
            selector: CurrentSelector::Strand { strand_id },
            source_stream_ref,
            revision,
            value,
        } = entry
        {
            if &strand_id != strand {
                continue;
            }
            if let Some(commit) = commit {
                ensure!(
                    revision.commit_id == commit.commit_id
                        && revision.stream_position == commit.stream_position
                        && source_stream_ref == commit.stream_ref,
                    "snapshot Strand revision differs from actual accepted Commit"
                );
            }
            return Ok(value);
        }
    }
    anyhow::bail!("signed snapshot omitted the accepted Strand current value")
}

async fn stage(
    client: &TestActorClient,
    realm: &str,
    strand: &StrandId,
    next: &str,
    expected: Option<&str>,
) -> Result<Event> {
    let payload = StrandStageSetPayload {
        strand_id: strand.clone(),
        stage: next.to_owned(),
        expected_stage: expected.map(str::to_owned),
    };
    client
        .author_event(
            realm,
            EventKind::StrandStageSet.as_str(),
            serde_json::to_value(payload)?,
        )
        .await
}

async fn lifecycle(
    client: &TestActorClient,
    realm: &str,
    strand: &StrandId,
    kind: EventKind,
) -> Result<Event> {
    let payload: ObjectLifecyclePayload =
        serde_json::from_value(json!({"target_ref":strand,"reason":"joint lifecycle acceptance"}))?;
    client
        .author_event(realm, kind.as_str(), payload.to_value()?)
        .await
}

async fn refuse(
    client: &TestActorClient,
    reader: &TestActorClient,
    event: &Event,
    status: StatusCode,
    code: &str,
    reason: Option<&str>,
) -> Result<()> {
    let body = crate::publication::initial_submission(event.clone(), "")?;
    let problem = expect_api_error(
        client.post("/_arkret/self/events").json(&body),
        status,
        code,
    )
    .await?;
    if let Some(reason) = reason {
        ensure!(
            problem
                .extensions
                .get("reason_code")
                .and_then(Value::as_str)
                == Some(reason),
            "expected registered reason_code={reason}, got {problem:?}"
        );
    }
    expect_api_error(
        reader.get(&format!(
            "/_arkret/self/committed-events/{}",
            event.event_id
        )),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    Ok(())
}

async fn accept(
    client: &TestActorClient,
    account: &AccountId,
    device: &str,
    event: &Event,
) -> Result<RealmCommit> {
    submit_and_expect_commit(client, account, device, event).await
}

pub async fn run_strand_lifecycle_live() -> Result<()> {
    let Some(db) = database(GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&db.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let station = group.server(0);
    let (alice, alice_account) =
        standard_client(station, &coauth, "lifecycle-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) = standard_client(station, &coauth, "lifecycle-bob", BOB_DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&alice, "Stage and archive", "public", &[station]).await?;
    let realm_id = RealmId::new(realm.clone())?;
    let strand = StrandId::new(alice.default_strand_id(&realm)?)?;
    let initial = value(&alice, &realm_id, &strand, None).await?;
    ensure!(
        initial["state"] == "active" && initial.get("stage").is_none(),
        "new Strand is not an active initial-stage object"
    );
    let first_event = stage(&alice, &realm, &strand, "in_progress", None).await?;
    let first = accept(&alice, &alice_account, ALICE_DEVICE, &first_event).await?;
    let first_value = value(&alice, &realm_id, &strand, Some(&first)).await?;
    ensure!(
        first_value["stage"] == "in_progress"
            && first_value["updated_by"]
                == serde_json::to_value(ActorId::account(alice_account.clone()))?,
        "stage update lost full Actor attribution"
    );
    ensure!(
        first_value["stage_changed_at"] == serde_json::to_value(first_event.created_at)?,
        "stage timestamp differs from the accepted Event"
    );
    for expected in [None, Some("draft")] {
        let bad = stage(&alice, &realm, &strand, "blocked", expected).await?;
        refuse(
            &alice,
            &alice,
            &bad,
            StatusCode::CONFLICT,
            "failed_precondition",
            None,
        )
        .await?;
        ensure!(
            value(&alice, &realm_id, &strand, Some(&first)).await? == first_value,
            "failed stage CAS changed current value"
        );
    }
    let same_event = stage(&alice, &realm, &strand, "in_progress", Some("in_progress")).await?;
    let same = accept(&alice, &alice_account, ALICE_DEVICE, &same_event).await?;
    ensure!(
        same.stream_position == first.stream_position + 1,
        "failed stage CAS consumed a Commit"
    );
    let same_value = value(&alice, &realm_id, &strand, Some(&same)).await?;
    ensure!(
        same_value == first_value,
        "same-stage transition changed timestamps or audit attribution"
    );
    let archived_event = lifecycle(&alice, &realm, &strand, EventKind::StrandArchive).await?;
    let archived = accept(&alice, &alice_account, ALICE_DEVICE, &archived_event).await?;
    let archived_value = value(&alice, &realm_id, &strand, Some(&archived)).await?;
    ensure!(
        archived_value["state"] == "archived"
            && archived_value["stage"] == same_value["stage"]
            && archived_value["stage_changed_at"] == same_value["stage_changed_at"],
        "archive changed the independent stage axis"
    );
    let patch: StrandPatchPayload = serde_json::from_value(
        json!({"target_ref":strand,"patch":{"metadata.summary":{"$op":"set","value":"forbidden while archived"}}}),
    )?;
    let update = alice
        .author_event(&realm, EventKind::StrandUpdate.as_str(), patch.to_value()?)
        .await?;
    let message = alice
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(strand.as_str(), "forbidden while archived")?,
        )
        .await?;
    let archived_stage = stage(&alice, &realm, &strand, "blocked", Some("in_progress")).await?;
    let twice_archive = lifecycle(&alice, &realm, &strand, EventKind::StrandArchive).await?;
    for refused in [&update, &message, &archived_stage, &twice_archive] {
        refuse(
            &alice,
            &alice,
            refused,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("strand_not_active"),
        )
        .await?;
        ensure!(
            value(&alice, &realm_id, &strand, Some(&archived)).await? == archived_value,
            "refused archived write changed current"
        );
    }
    let replay_body = crate::publication::initial_submission(archived_event.clone(), "")?;
    let replay: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            alice.post("/_arkret/self/events").json(&replay_body),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(replay,AuthoritySubmitOutcome::Accepted {status:AuthorityCommitStatus::Duplicate,commit} if commit==archived),
        "exact archive replay changed its Commit"
    );
    let restore_event = lifecycle(&alice, &realm, &strand, EventKind::StrandRestore).await?;
    let restored = accept(&alice, &alice_account, ALICE_DEVICE, &restore_event).await?;
    ensure!(
        restored.stream_position == archived.stream_position + 1,
        "archived refusals/replay consumed a Commit"
    );
    let restored_value = value(&alice, &realm_id, &strand, Some(&restored)).await?;
    ensure!(
        restored_value["state"] == "active"
            && restored_value["stage"] == "in_progress"
            && restored_value["stage_changed_at"] == same_value["stage_changed_at"],
        "restore lost original stage"
    );
    let twice_restore = lifecycle(&alice, &realm, &strand, EventKind::StrandRestore).await?;
    refuse(
        &alice,
        &alice,
        &twice_restore,
        StatusCode::CONFLICT,
        "failed_precondition",
        Some("strand_not_archived"),
    )
    .await?;
    let next_event = stage(&alice, &realm, &strand, "blocked", Some("in_progress")).await?;
    let next = accept(&alice, &alice_account, ALICE_DEVICE, &next_event).await?;
    ensure!(
        next.stream_position == restored.stream_position + 1,
        "invalid restore consumed a Commit"
    );
    ensure!(
        value(&alice, &realm_id, &strand, Some(&next)).await?["stage"] == "blocked",
        "restored Strand cannot advance its stage"
    );
    let resumed_message = alice
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(strand.as_str(), "discussion resumes after restore")?,
        )
        .await?;
    let resumed = accept(&alice, &alice_account, ALICE_DEVICE, &resumed_message).await?;
    ensure!(
        resumed.stream_position == next.stream_position + 1,
        "restored discussion did not resume after stage Commit"
    );

    let join = bob
        .author_event(
            &realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm,
                bob_account.clone(),
                MembershipPayloadState::Join,
                "stage reader",
            )?,
        )
        .await?;
    let joined = accept(&bob, &bob_account, BOB_DEVICE, &join).await?;
    let denied = stage(&bob, &realm, &strand, "done", Some("blocked")).await?;
    refuse(
        &bob,
        &alice,
        &denied,
        StatusCode::FORBIDDEN,
        "capability_denied",
        None,
    )
    .await?;
    let denied_archive = lifecycle(&bob, &realm, &strand, EventKind::StrandArchive).await?;
    refuse(
        &bob,
        &alice,
        &denied_archive,
        StatusCode::FORBIDDEN,
        "capability_denied",
        None,
    )
    .await?;
    let grant = grant_realm_actions(
        &alice,
        station,
        &realm,
        &bob_account,
        &["ak.strand.stage.set"],
    )
    .await?;
    ensure!(
        grant.stream_position == joined.stream_position + 1,
        "permission refusals consumed a Commit"
    );
    let done_event = stage(&bob, &realm, &strand, "done", Some("blocked")).await?;
    let done = accept(&bob, &bob_account, BOB_DEVICE, &done_event).await?;
    let done_value = value(&bob, &realm_id, &strand, Some(&done)).await?;
    ensure!(
        done_value["stage"] == "done"
            && done_value["state"] == "active"
            && done_value["updated_by"]
                == serde_json::to_value(ActorId::account(bob_account.clone()))?,
        "stage-only grant did not preserve Actor/lifecycle separation"
    );
    // Direct SQL is a read-only assertion of rows accepted through real HTTP.
    let url = db.connect_url.clone();
    let strand_text = strand.to_string();
    let commit_text = done.commit_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut pg = postgres::Client::connect(&url, postgres::NoTls)?;
        let row = pg.query_one(
            "SELECT current_commit_id,value FROM strand_current_results WHERE strand_id=$1",
            &[&strand_text],
        )?;
        ensure!(
            row.get::<_, String>(0) == commit_text && row.get::<_, Value>(1) == done_value,
            "durable Strand row differs from actual signed snapshot"
        );
        Ok(())
    })
    .await
    .context("durable Strand read task")??;
    Ok(())
}
