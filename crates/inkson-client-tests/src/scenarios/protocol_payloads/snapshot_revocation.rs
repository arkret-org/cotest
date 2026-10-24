//! Whole-original refusal on the real Account projector and durability barrier.

use std::sync::Mutex;

use anyhow::{Context, Result, ensure};
use arkret_wire::{ActorId, CommitStreamRef, Event, EventKind, RealmId, StrandId};
use cotest::harness::TestActorClient;
use cotest::scenarios::circle_poll_scope_live::{circle_create, circle_event, join_circle};
use cotest::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, submit_and_expect_commit,
};
use garth::{AccountSubscribeBatch, AccountSubscribeParameters, AccountSubscribeTransport};
use inkson::sync_engine::NativeAccountHost;
use serde_json::json;

struct RevokeAfterIssuance {
    author: TestActorClient,
    http: arkret_http_client::Client,
    leave: Event,
    account_id: arkret_wire::AccountId,
    issued: arkret_wire::RealmSnapshotId,
    target: CommitStreamRef,
    held: Mutex<Option<AccountSubscribeBatch>>,
}

impl AccountSubscribeTransport for RevokeAfterIssuance {
    async fn subscribe(
        &self,
        request: &AccountSubscribeParameters,
    ) -> garth::Result<
        arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeSnapshotResult,
    > {
        let batch = self.http.account_subscribe_batch(request).await?;
        let basis = batch
            .frames
            .iter()
            .flat_map(|frame| frame.realms.iter())
            .flat_map(|realms| realms.entries.values())
            .flat_map(|entry| entry.streams.iter().flatten())
            .find(|window| window.stream_ref == self.target)
            .and_then(|window| window.window_start_basis.as_ref());
        if basis.is_none_or(|basis| basis.snapshot_ref != self.issued) {
            return Err(garth::Error::Protocol(
                "actual Account tail did not name the held whole original".into(),
            ));
        }
        if self.held.lock().unwrap().is_some() {
            return Err(garth::Error::Protocol(
                "refused Account frame unexpectedly retried".into(),
            ));
        }
        submit_and_expect_commit(
            &self.author,
            &self.account_id,
            &self.author.device_id,
            &self.leave,
        )
        .await
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        *self.held.lock().unwrap() = Some(batch.clone());
        Ok(arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeSnapshotResult::Batch(batch))
    }
}

pub async fn unrelated_scope_revocation_rejects_the_whole_native_account_frame() -> Result<()> {
    cotest::harness::heap_future(run).await
}

async fn run() -> Result<()> {
    let fixture = cotest::scenarios::protocol_payloads::snapshot_head_disclosure::snapshot_author(
        "native-snapshot-revocation",
        "snapshot-revocation-alice",
    )
    .await?;
    let author = &fixture.author;
    let native =
        crate::conformance::account_blocklist_projection::native_account_session(author).await?;
    let realm = RealmId::new(
        create_realm_with_join_rule(
            author,
            "Exact basis revocation",
            "public",
            &[&fixture.server],
        )
        .await?,
    )?;
    let principal = author.principal.as_ref().context("founder")?;
    let account_id = arkret_wire::AccountId::new(
        principal.core_id.clone(),
        fixture.server.service_id().clone(),
    );
    let actor = ActorId::account(account_id.clone());
    let mut circles = Vec::new();
    for index in 0..2 {
        let circle = circle_create(
            author,
            realm.as_str(),
            &actor,
            &format!("Private {index}"),
            &format!("Scope-{index}"),
        )
        .await?;
        join_circle(author, realm.as_str(), &circle, &actor).await?;
        circles.push(circle);
    }
    circles.sort();
    let target = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circles[0].clone(),
    };
    let strand = circle_event(
        author,
        realm.as_str(),
        &circles[0],
        EventKind::StrandCreate,
        json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circles[0],
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Still readable"},"state":"active","created_by":actor
        }}),
    )
    .await?;
    submit_and_expect_commit(author, &account_id, &author.device_id, &strand).await?;
    let strand_id = StrandId::from_event_id(&strand.event_id);
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("native-account.json");
    let host = NativeAccountHost::new_for_realm(
        native.client(),
        account_id.clone(),
        principal.device_id.clone(),
        inkson::LocalStateStore::with_path(&path),
        realm.clone(),
    )
    .await?;
    host.catch_up_selected_realm_until_complete(&realm).await?;
    let issued = author.sdk().realm_state_snapshot_head(&realm).await?;
    for index in 0..20 {
        let event = circle_event(author,realm.as_str(),&circles[0],EventKind::MessageCreate,json!({
            "strand_id":strand_id,"track_name":"discussion","content":{"kind":"ak.content.text","body":format!("Held target tail {index}")}
        })).await?;
        submit_and_expect_commit(author, &account_id, &author.device_id, &event).await?;
    }
    let before = serde_json::to_value(host.state_store().load())?;
    let committed =
        serde_json::to_value(host.state_store().conformance_committed_account_state()?)?;
    let checkpoint = host.state_store().conformance_account_checkpoint_token()?;
    let leave = circle_event(author,realm.as_str(),&circles[1],EventKind::CircleMemberState,json!({
        "circle_id":circles[1],"member_id":actor,"membership":"leave","expected_membership":"join"
    })).await?;
    let rail = RevokeAfterIssuance {
        author: author.clone(),
        http: native.client(),
        leave,
        account_id: account_id.clone(),
        issued: issued.snapshot_id.clone(),
        target: target.clone(),
        held: Default::default(),
    };
    let refused = host.catch_up_with_conformance_transport(&rail).await;
    ensure!(
        rail.held.lock().unwrap().is_some(),
        "real Account frame was never issued"
    );
    ensure!(
        matches!(&refused,Err(garth::Error::Api { status:503, error })
        if error.error_code() == Some(arkret_wire::ErrorCode::RealmStateSnapshotUnavailable)),
        "held frame did not fail at exact whole-original unavailability: {refused:?}"
    );
    ensure!(
        serde_json::to_value(host.state_store().load())? == before
            && serde_json::to_value(host.state_store().conformance_committed_account_state()?)?
                == committed
            && host.state_store().conformance_account_checkpoint_token()? == checkpoint,
        "rejected whole Account frame changed durable rows, root or cursor"
    );
    let current = author.sdk().realm_state_snapshot_head(&realm).await?;
    ensure!(
        current
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == target)
    );
    ensure!(
        !current
            .visible_stream_heads
            .iter()
            .any(|head| matches!(&head.stream_ref,
        CommitStreamRef::Circle { circle_id,.. } if circle_id == &circles[1]))
    );
    host.catch_up_selected_realm_until_complete(&realm).await?;
    ensure!(
        host.state_store().conformance_account_checkpoint_token()? != checkpoint,
        "fresh lawful Account window did not recover its checkpoint"
    );
    let after = serde_json::to_value(host.state_store().conformance_committed_account_state()?)?;
    drop(host);
    let cold = NativeAccountHost::new_for_realm(
        native.client(),
        account_id,
        principal.device_id.clone(),
        inkson::LocalStateStore::with_path(&path),
        realm,
    )
    .await?;
    ensure!(
        serde_json::to_value(cold.state_store().conformance_committed_account_state()?)? == after,
        "cold reopening changed the recovered durable Account root"
    );
    println!(
        "[2133-account-revocation] actual_held_frame=1 unrelated_scope_revoked=1 target_still_readable=1 whole_original_unavailable=1 durable_rows_and_cursor_unchanged=1 fresh_window_recovered=1 cold_root_preserved=1"
    );
    Ok(())
}
