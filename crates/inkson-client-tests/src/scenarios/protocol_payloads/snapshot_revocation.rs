//! Whole-frame refusal when an actual referenced history original is revoked.

use std::collections::BTreeSet;
use std::sync::Mutex;

use anyhow::{Context, Result, ensure};
use arkret_wire::{
    ActorId, CommitStreamRef, CurrentSelector, CurrentState, Event, EventKind, RealmId,
    RealmSnapshotPurpose, RealmStateSnapshot, StrandId,
};
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
    issued: RealmStateSnapshot,
    target: CommitStreamRef,
    revoked: CommitStreamRef,
    held: Mutex<
        Option<(
            AccountSubscribeBatch,
            RealmStateSnapshot,
            RealmStateSnapshot,
        )>,
    >,
}

impl RevokeAfterIssuance {
    async fn history_original(
        &self,
        window: &arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
    ) -> Result<RealmStateSnapshot> {
        self.issued.require_full_recovery()?;
        let basis = window
            .window_start_basis
            .as_ref()
            .context("real history basis")?;
        let original = self
            .http
            .realm_state_snapshot_by_ref(&self.issued.realm_id, &basis.snapshot_ref)
            .await?;
        original.validate_purpose()?;
        let signed = original
            .history_basis
            .as_ref()
            .context("signed history coverage")?;
        ensure!(
            self.issued.purpose == RealmSnapshotPurpose::FullRecovery
                && window.limited
                && window.complete
                && window.window_limit == 20
                && window.preview_only.is_none()
                && original.purpose == RealmSnapshotPurpose::StreamHistory
                && original.snapshot_id == basis.snapshot_ref
                && original.snapshot_id != self.issued.snapshot_id
                && original.realm_id == self.issued.realm_id
                && original.governance_generation == basis.governance_generation
                && basis.governance_generation == self.issued.governance_generation
                && signed.account_id == self.account_id
                && signed.stream_ref == window.stream_ref
                && signed.anchor_position == basis.anchor_position
                && signed.anchor_commit_ref == basis.anchor_commit_ref
                && signed.accepted_dependency_refs.as_slice()
                    == basis
                        .accepted_dependency_refs
                        .as_deref()
                        .unwrap_or_default()
                && self
                    .issued
                    .visible_stream_heads
                    .iter()
                    .any(|head| head.stream_ref == window.stream_ref
                        && head.stream_position == basis.anchor_position
                        && head.commit_id == basis.anchor_commit_ref),
            "the actual Account basis must bind an independent history original at the issued cut"
        );
        let CommitStreamRef::Circle { circle_id, .. } = &window.stream_ref else {
            anyhow::bail!("revocation fixture requires actual Circle windows");
        };
        let member = CurrentSelector::MemberState {
            actor_id: ActorId::account(self.account_id.clone()),
        };
        let definition = CurrentSelector::Circle {
            circle_id: circle_id.clone(),
        };
        let expected_entries = self
            .issued
            .current_state_entries
            .iter()
            .filter(|row| {
                let CurrentState::Value {
                    selector,
                    source_stream_ref,
                    ..
                } = row;
                (source_stream_ref == &window.stream_ref
                    && !matches!(
                        selector,
                        CurrentSelector::Circle { .. } | CurrentSelector::Sidecar { .. }
                    ))
                    || selector == &member
                    || selector == &definition
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut sources = BTreeSet::from([window.stream_ref.clone()]);
        for row in &expected_entries {
            let CurrentState::Value {
                source_stream_ref, ..
            } = row;
            sources.insert(source_stream_ref.clone());
        }
        let expected_heads = self
            .issued
            .visible_stream_heads
            .iter()
            .filter(|head| sources.contains(&head.stream_ref))
            .cloned()
            .collect::<Vec<_>>();
        let expected_floors = self
            .issued
            .retention_and_history_floor
            .stream_floors
            .iter()
            .filter(|floor| sources.contains(&floor.stream_ref))
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            original.current_state_entries == expected_entries
                && original.visible_stream_heads == expected_heads
                && original.retention_and_history_floor.history_access
                    == self.issued.retention_and_history_floor.history_access
                && original.retention_and_history_floor.stream_floors == expected_floors
                && original.require_full_recovery().is_err(),
            "the history original must retain the exact target selector closure, heads and floors"
        );
        let mut identity = serde_json::to_value(&original)?;
        let identity = identity.as_object_mut().context("snapshot identity")?;
        identity.remove("snapshot_id");
        identity.remove("signature");
        ensure!(
            original.snapshot_id
                == arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
                    arkret_canonical::canonical_json_bytes(identity)?
                )),
            "the actual history original must retain its content ID"
        );
        Ok(original)
    }
}

impl AccountSubscribeTransport for RevokeAfterIssuance {
    async fn subscribe(
        &self,
        request: &AccountSubscribeParameters,
    ) -> garth::Result<
        arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeReadAction,
    > {
        let batch = self.http.account_subscribe_batch(request).await?;
        let window = |stream: &CommitStreamRef| {
            batch
                .frames
                .iter()
                .flat_map(|frame| frame.realms.iter())
                .flat_map(|realms| realms.entries.values())
                .flat_map(|entry| entry.streams.iter().flatten())
                .find(|window| &window.stream_ref == stream)
                .cloned()
                .ok_or_else(|| {
                    garth::Error::Protocol(
                        "actual Account frame omitted a required Circle window".into(),
                    )
                })
        };
        let target_window = window(&self.target)?;
        let revoked_window = window(&self.revoked)?;
        if target_window
            .window_start_basis
            .as_ref()
            .and_then(|basis| basis.anchor_position.checked_add(21))
            != Some(target_window.next_position)
            || revoked_window
                .window_start_basis
                .as_ref()
                .and_then(|basis| basis.anchor_position.checked_add(2))
                != Some(revoked_window.next_position)
        {
            return Err(garth::Error::Protocol("the real frame must carry twenty target messages and the other Circle's one real Strand tail".into()));
        }
        let target = self
            .history_original(&target_window)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let revoked = self
            .history_original(&revoked_window)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if target.snapshot_id == revoked.snapshot_id {
            return Err(garth::Error::Protocol(
                "distinct Circle windows must have distinct exact history originals".into(),
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
        *self.held.lock().unwrap() = Some((batch.clone(), target, revoked));
        Ok(arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeReadAction::Batch(batch))
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
    // Advance the other real Circle after its issued anchor. Its delivered
    // join at position 0 then has a real successor and a history basis; an
    // unchanged head at the genesis floor would have no such basis.
    let revoked_tail = circle_event(
        author,
        realm.as_str(),
        &circles[1],
        EventKind::StrandCreate,
        json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circles[1],
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Revoked scope tail"},"state":"active","created_by":actor
        }}),
    )
    .await?;
    submit_and_expect_commit(author, &account_id, &author.device_id, &revoked_tail).await?;
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
        issued: issued.clone(),
        target: target.clone(),
        revoked: CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: circles[1].clone(),
        },
        held: Default::default(),
    };
    let refused = host.catch_up_with_conformance_transport(&rail).await;
    ensure!(
        rail.held.lock().unwrap().is_some(),
        "real Account frame was never issued: {refused:?}"
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
    let (_, target_original, revoked_original) = rail
        .held
        .lock()
        .unwrap()
        .clone()
        .context("held actual Account frame")?;
    let still_readable = rail
        .http
        .realm_state_snapshot_by_ref(&realm, &target_original.snapshot_id)
        .await?;
    cotest::scenarios::protocol_payloads::snapshot_head_disclosure::ensure_same_object(
        &target_original,
        &still_readable,
    )?;
    let revoked_read = rail
        .http
        .realm_state_snapshot_by_ref(&realm, &revoked_original.snapshot_id)
        .await
        .map_err(garth::Error::from);
    let full_read = rail
        .http
        .realm_state_snapshot_by_ref(&realm, &issued.snapshot_id)
        .await
        .map_err(garth::Error::from);
    ensure!(
        [&revoked_read, &full_read].iter().all(|read| matches!(read,
            Err(garth::Error::Api { status:503, error })
                if error.error_code() == Some(arkret_wire::ErrorCode::RealmStateSnapshotUnavailable))),
        "the revoked history original and its covered full recovery original must both be wholly unavailable"
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
