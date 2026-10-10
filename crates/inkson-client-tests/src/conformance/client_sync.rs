//! Account checkpoint evidence through the production subscription driver.

use std::cell::RefCell;
use std::sync::Mutex;

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeSnapshotResult;
use arkret_wire::{Event, ScopeRef};
use cotest::scenarios::mls_lifecycle_live::Member;
use cotest::scenarios::sidecar_authority_live::SidecarSyncObserver;
use garth::{AccountSubscribeBatch, AccountSubscribeTransport, SyncRequestBody};
use inkson::sync_engine::NativeAccountHost;
use serde_json::Value;

const CASES: [&str; 3] = [
    "sidecar_history_current_projection_same_cut_before_checkpoint",
    "sidecar_missing_tail_does_not_install_newer_current_or_checkpoint",
    "sidecar_projection_transaction_failure_preserves_prior_cut",
];
const RECOVERY_CASES: [&str; 3] = [
    "resume_from_the_last_durable_account_cursor",
    "cursor_expired_redoes_only_that_surface_baseline",
    "cursor_integrity_invalid_redoes_only_that_surface_baseline",
];
const STREAM_AND_DELIVERY_CASES: [&str; 3] = [
    "sidecar_stream_tail_is_independent",
    "cursor_advance_alone_does_not_cancel_a_delivery",
    "realm_stream_tail_is_continuous",
];
const ACK_CASES: [&str; 2] = [
    "explicit_ack_after_durable_processing_removes_the_delivery",
    "cursor_expiry_does_not_invalidate_an_issued_ack_token",
];
const QUEUE_CASES: [&str; 3] = [
    "backfill_path_shares_one_queue_and_ack_token",
    "expired_content_without_ack_remains_in_queue",
    "full_endpoint_rejects_new_delivery_without_eviction",
];
const BASELINE_CASE: &str = "incremental_before_baseline_complete_merges_by_position";
const ORDERING_CASES: [&str; 2] = [
    "projection_is_installed_before_the_checkpoint_advances",
    "checkpoint_before_projection_is_rejected",
];
const CIRCLE_TAIL_CASE: &str = "circle_stream_tail_is_independent";
const STREAM_GAP_CASE: &str = "unexplained_position_jump_stops_only_that_stream";
pub const PRODUCTION_CASE_COUNT: usize = CASES.len()
    + RECOVERY_CASES.len()
    + STREAM_AND_DELIVERY_CASES.len()
    + ACK_CASES.len()
    + QUEUE_CASES.len()
    + 3
    + ORDERING_CASES.len();

const QUEUE_WRITE_EVIDENCE: &str = "SELECT jsonb_build_object(\
    'queue',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM device_messages t),\
    'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY key),'[]') FROM device_message_txns t),\
    'messages',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY message_key),'[]') FROM device_message_idempotency t)\
    )::text";

fn queue_request(
    recipient: &Member,
    id: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_models_collaboration::device_messages::DeviceMessagesSendRequestBody> {
    cotest::harness::device_message_send_request(
        recipient
            .client
            .principal
            .as_ref()
            .context("queue recipient principal")?
            .did
            .as_str(),
        recipient.device.as_str(),
        id,
        "ak.mls.application",
        cotest::harness::encrypted_envelope("ak.mls.application", "b3BhcXVl"),
        expires_at,
    )
}

pub fn run_sync_client_production_suite() -> Result<super::SuiteExecutionResult> {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| -> Result<super::SuiteExecutionResult> {
            let executable = std::env::current_exe()?;
            let parent = executable
                .parent()
                .context("native runner has no directory")?;
            let directory = if parent.file_name().is_some_and(|name| name == "deps") {
                parent
                    .parent()
                    .context("test runner has no Cargo binary directory")?
            } else {
                parent
            };
            let reader = directory.join(format!(
                "cotest-inkson-checkpoint-readback{}",
                std::env::consts::EXE_SUFFIX
            ));
            ensure!(
                reader.is_file(),
                "Sync fresh-process readback executable is missing: {}",
                reader.display()
            );
            let _transcript = cotest::transcripts::init_transcript_writer(
                "sidecar-checkpoint-production",
                Some(&directory.join("conformance-transcripts")),
            )?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(32 * 1024 * 1024)
                .enable_all()
                .build()?;
            let cases = runtime.block_on(run_sync_production_cases(&reader))?;
            Ok(super::SuiteExecutionResult {
                entrypoint: cotest::conformance::SYNC_CLIENT_ENTRYPOINT,
                fixture: "client-sync-fixture.json",
                cases,
            })
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("Sync production evidence worker panicked"))?
}

struct Probe {
    scan_relay: RefCell<Option<cotest::harness::ScanGapRelay>>,
    directory: tempfile::TempDir,
    reader: std::path::PathBuf,
    host: RefCell<Option<NativeAccountHost>>,
    before: RefCell<Option<Value>>,
    results: RefCell<Vec<super::CaseExecutionResult>>,
}

struct ObservedRail {
    http: arkret_http_client::Client,
    missing: Option<arkret_wire::EventId>,
    observed: Mutex<Vec<AccountSubscribeBatch>>,
}

struct HeldBatch(Mutex<Option<AccountSubscribeBatch>>);

impl AccountSubscribeTransport for HeldBatch {
    async fn subscribe(
        &self,
        _request: &SyncRequestBody,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        self.0
            .lock()
            .unwrap()
            .take()
            .map(AccountSubscribeSnapshotResult::Batch)
            .ok_or_else(|| garth::Error::Protocol("held Account window consumed twice".into()))
    }
}

impl AccountSubscribeTransport for ObservedRail {
    async fn subscribe(
        &self,
        request: &SyncRequestBody,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        let mut batch = self.http.account_subscribe_batch(request).await?;
        if let Some(missing) = &self.missing {
            let mut removed = 0;
            for frame in &mut batch.frames {
                for entry in frame
                    .realms
                    .iter_mut()
                    .flat_map(|realms| realms.entries.values_mut())
                {
                    if let Some(rows) = &mut entry.committed_events {
                        for row in rows.iter().filter(|row| &row.commit().event_ref == missing) {
                            for window in entry
                                .streams
                                .iter_mut()
                                .flatten()
                                .filter(|window| window.stream_ref == row.commit().stream_ref)
                            {
                                // Keep the authenticated current and originals intact,
                                // but claim the next position for which no tail exists.
                                window.next_position += 1;
                                removed += 1;
                            }
                        }
                    }
                }
            }
            if removed != 1 {
                return Err(garth::Error::Protocol(format!(
                    "missing-tail injection changed {removed} windows instead of one"
                )));
            }
        }
        self.observed.lock().unwrap().push(batch.clone());
        Ok(AccountSubscribeSnapshotResult::Batch(batch))
    }
}

fn state(host: &NativeAccountHost) -> Result<Value> {
    Ok(serde_json::to_value(host.state_store().load())?)
}

struct RecoveryRail {
    http: arkret_http_client::Client,
    path: std::path::PathBuf,
    database_url: String,
    expected_cursor: String,
    expected_error: Option<&'static str>,
    before: Value,
    requests: Mutex<Vec<SyncRequestBody>>,
    refusals: Mutex<Vec<String>>,
}

struct StreamGapRail {
    row_fault: Option<cotest::harness::ScanGapControl>,
    http: arkret_http_client::Client,
    database_url: String,
    path: std::path::PathBuf,
    before: Value,
    cursor: String,
    affected_stream: arkret_wire::CommitStreamRef,
    healthy_stream: arkret_wire::CommitStreamRef,
    healthy_commit: Mutex<Option<arkret_wire::RealmCommit>>,
    ack_token: String,
    ack_before: String,
    requests: Mutex<Vec<SyncRequestBody>>,
}

impl AccountSubscribeTransport for StreamGapRail {
    async fn subscribe(
        &self,
        request: &SyncRequestBody,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        let visit = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.clone());
            requests.len()
        };
        let check = || -> Result<()> {
            ensure!(
                request.after.as_deref() == Some(self.cursor.as_str())
                    && request.catchup != Some(true),
                "stream gap discarded the durable cursor or redid baseline"
            );
            if visit == 2 {
                let store = inkson::LocalStateStore::with_path(self.path.clone());
                let after = serde_json::to_value(store.load())?;
                let affected_key = serde_json::to_string(&self.affected_stream)?;
                let healthy_key = serde_json::to_string(&self.healthy_stream)?;
                let healthy = self
                    .healthy_commit
                    .lock()
                    .unwrap()
                    .clone()
                    .context("observed healthy original")?;
                ensure!(
                    store.sync_cursor().as_deref() == Some(self.cursor.as_str())
                        && after["current_generation"] == self.before["current_generation"]
                        && after["verified_commit_stream_cursors"][&affected_key]
                            == self.before["verified_commit_stream_cursors"][&affected_key]
                        && after["verified_commit_stream_anchors"][&affected_key]
                            == self.before["verified_commit_stream_anchors"][&affected_key],
                    "incomplete stream advanced current, Account cursor or its own durable anchor"
                );
                ensure!(after["verified_commit_stream_cursors"][&healthy_key]["stream_position"] == healthy.stream_position
                    && after["verified_commit_stream_anchors"][&healthy_key] == serde_json::to_value(&healthy)?
                    && healthy.stream_position > self.before["verified_commit_stream_cursors"][&healthy_key]["stream_position"].as_u64().context("prior healthy position")?,
                    "incomplete Circle blocked its healthy Realm sibling");
                ensure!(
                    read_database_evidence(
                        &self.database_url,
                        "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE ack_token=$1",
                        &[&self.ack_token]
                    )? == self.ack_before,
                    "stream recovery reset the issued recipient ACK"
                );
            }
            if visit == 2 && self.row_fault.is_some() {
                let after = serde_json::to_value(
                    inkson::LocalStateStore::with_path(self.path.clone()).load(),
                )?;
                let healthy_key = serde_json::to_string(&self.healthy_stream)?;
                for (key, head) in self.before["verified_commit_stream_cursors"]
                    .as_object()
                    .context("row gap prior complete stream map")?
                {
                    if key != &healthy_key {
                        ensure!(
                            after["verified_commit_stream_cursors"][key] == *head
                                && after["verified_commit_stream_anchors"][key]
                                    == self.before["verified_commit_stream_anchors"][key],
                            "readable row gap changed an unrelated durable stream"
                        );
                    }
                }
            }
            ensure!(
                visit <= 2,
                "the repaired stream did not recover within one retry"
            );
            Ok(())
        };
        check().map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if visit == 2 {
            if let Some(fault) = &self.row_fault {
                fault.clear();
            }
        }
        let mut batch = self.http.account_subscribe_batch(request).await?;
        if visit == 1 {
            let healthy = batch
                .frames
                .iter()
                .flat_map(|f| &f.realms)
                .flat_map(|r| r.entries.values())
                .flat_map(|e| e.committed_events.iter().flatten())
                .filter(|row| row.commit().stream_ref == self.healthy_stream)
                .max_by_key(|row| row.commit().stream_position)
                .ok_or_else(|| {
                    garth::Error::Protocol("gap batch lacks a healthy Realm original".into())
                })?;
            *self.healthy_commit.lock().unwrap() = Some(healthy.commit().clone());
            let mut faults = 0;
            for frame in &mut batch.frames {
                if let Some(realms) = &mut frame.realms {
                    for entry in realms.entries.values_mut() {
                        for window in entry.streams.iter_mut().flatten() {
                            if self.row_fault.is_none() && window.stream_ref == self.affected_stream
                            {
                                window.next_position =
                                    window.next_position.checked_add(1).ok_or_else(|| {
                                        garth::Error::Protocol("gap window overflow".into())
                                    })?;
                                faults += 1;
                            }
                        }
                    }
                }
            }
            if self.row_fault.is_none() && faults != 1 {
                return Err(garth::Error::Protocol(
                    "gap fixture lacks one independent Circle window".into(),
                ));
            }
        }
        Ok(AccountSubscribeSnapshotResult::Batch(batch))
    }
}

fn read_database_evidence(
    database_url: &str,
    sql: &str,
    parameters: &[&(dyn postgres::types::ToSql + Sync)],
) -> Result<String> {
    tokio::task::block_in_place(|| {
        let mut database = postgres::Client::connect(database_url, postgres::NoTls)?;
        Ok(database.query_one(sql, parameters)?.get(0))
    })
}

impl AccountSubscribeTransport for RecoveryRail {
    async fn subscribe(
        &self,
        request: &SyncRequestBody,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        let call = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.clone());
            requests.len()
        };
        let check = || -> Result<()> {
            ensure!(
                call <= 2,
                "cursor recovery exceeded its bounded subscription attempts"
            );
            if call == 1 {
                ensure!(
                    request.after.as_deref() == Some(self.expected_cursor.as_str())
                        && request.catchup == Some(false),
                    "the driver did not resume its durable cursor verbatim"
                );
            } else {
                ensure!(
                    self.expected_error.is_some()
                        && request.after.is_none()
                        && request.catchup == Some(true)
                        && request.replace_filter.is_none(),
                    "the driver did not discard the refused cursor and request an initial baseline"
                );
                let store = inkson::LocalStateStore::with_path(self.path.clone());
                ensure!(
                    store.sync_cursor().is_none(),
                    "the refused cursor was not durably cleared before retry"
                );
                let installed = serde_json::to_value(store.load())?;
                ensure!(
                    installed["verified_sidecar_history"]
                        == self.before["verified_sidecar_history"]
                        && installed["mls_snapshots"] == self.before["mls_snapshots"],
                    "baseline reset deleted verified private history or encrypted MLS state"
                );
            }
            Ok(())
        };
        check().map_err(|error| garth::Error::Protocol(format!("{error:#}")))?;
        let cursor_rows = read_database_evidence(&self.database_url,
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM sync_cursor_handles t", &[])
            .map_err(|error| garth::Error::Storage(error.to_string()))?;
        match self.http.account_subscribe_batch(request).await {
            Ok(batch) => {
                if call == 1 && self.expected_error.is_some() {
                    return Err(garth::Error::Protocol(
                        "an invalid cursor was accepted by the real Station".into(),
                    ));
                }
                Ok(AccountSubscribeSnapshotResult::Batch(batch))
            }
            Err(error) => {
                let failure: garth::Error = error.into();
                let garth::Error::Api { error, .. } = &failure else {
                    return Err(failure);
                };
                let code = error.code();
                if call != 1 || self.expected_error != Some(code) {
                    return Err(garth::Error::Protocol(format!(
                        "unexpected Station cursor refusal {code}"
                    )));
                }
                let after = read_database_evidence(&self.database_url,
                    "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM sync_cursor_handles t", &[])
                    .map_err(|error| garth::Error::Storage(error.to_string()))?;
                if after != cursor_rows {
                    return Err(garth::Error::Protocol(
                        "a refused cursor advanced server cursor state".into(),
                    ));
                }
                self.refusals.lock().unwrap().push(code.to_owned());
                Err(failure)
            }
        }
    }
}

impl Probe {
    async fn queue_cases(
        &self,
        controller: &Member,
        other_recipient: &Member,
        host: &NativeAccountHost,
        database_url: &str,
    ) -> Result<()> {
        use arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody;
        let http = controller.client.sdk();
        ensure!(
            http.receive_device_messages(None, None)
                .await?
                .deliveries
                .is_empty(),
            "queue cases require a clean acknowledged prefix"
        );
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(5);
        http.send_device_messages(
            "sync-content-expiry",
            &queue_request(
                controller,
                "ak:device_message:01964137-2000-7000-8000-000000000025",
                expires_at,
            )?,
        )
        .await?;
        let before = http.receive_device_messages(None, None).await?;
        ensure!(
            before.deliveries.len() == 1 && chrono::Utc::now() < expires_at,
            "expiry probe did not observe the original live queued delivery"
        );
        let write_before = read_database_evidence(database_url, QUEUE_WRITE_EVIDENCE, &[])?;
        let remaining = (expires_at - chrono::Utc::now())
            .to_std()
            .unwrap_or_default();
        tokio::time::sleep(remaining + std::time::Duration::from_millis(10)).await;
        ensure!(
            chrono::Utc::now() > expires_at,
            "content expiry was not crossed"
        );
        let expired = http.receive_device_messages(None, None).await?;
        ensure!(
            serde_json::to_value(&expired.deliveries)? == serde_json::to_value(&before.deliveries)?
                && expired.lost != Some(true),
            "content expiry removed or marked an unacknowledged delivery lost"
        );
        ensure!(
            read_database_evidence(database_url, QUEUE_WRITE_EVIDENCE, &[])? == write_before,
            "content expiry changed queue or sender idempotency records"
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: QUEUE_CASES[1].into(),
            assertions: 5,
        });

        let fresh_expiry = chrono::Utc::now() + chrono::Duration::minutes(10);
        http.send_device_messages(
            "sync-backfill-prefix",
            &queue_request(
                controller,
                "ak:device_message:01964137-2000-7000-8000-000000000024",
                fresh_expiry,
            )?,
        )
        .await?;
        let full = http.receive_device_messages(None, None).await?;
        ensure!(
            full.deliveries.len() == 2,
            "configured endpoint was not exactly full"
        );
        let writes = read_database_evidence(database_url, QUEUE_WRITE_EVIDENCE, &[])?;
        let account_request = SyncRequestBody {
            catchup: Some(true),
            filter: Some(garth::AccountFilter {
                realm_ids: Some(vec![]),
                window_limit: Some(20),
                ..Default::default()
            }),
            ..Default::default()
        };
        let main = http.account_subscribe_batch(&account_request).await?;
        let delivered = main
            .frames
            .iter()
            .filter_map(|frame| frame.to_device.as_ref())
            .flat_map(|queue| queue.deliveries.iter().cloned())
            .collect::<Vec<_>>();
        ensure!(
            serde_json::to_value(&delivered)? == serde_json::to_value(&full.deliveries)?,
            "Account stream and list did not read the same original recipient queue"
        );
        let main_token = main
            .frames
            .iter()
            .filter_map(|frame| frame.to_device.as_ref())
            .filter(|queue| !queue.deliveries.is_empty())
            .last()
            .and_then(|queue| queue.ack_token.as_deref())
            .context("Account delivery ACK")?;
        let first = http.receive_device_messages(None, Some(1)).await?;
        ensure!(
            first.deliveries.len() == 1 && first.has_more,
            "backfill did not paginate the shared queue"
        );
        let last = http
            .receive_device_messages(
                Some(first.next_cursor.as_deref().context("backfill cursor")?),
                Some(1),
            )
            .await?;
        let backfill = first
            .deliveries
            .into_iter()
            .chain(last.deliveries)
            .collect::<Vec<_>>();
        ensure!(
            !last.has_more && serde_json::to_value(&backfill)? == serde_json::to_value(&delivered)?,
            "backfill changed ordering or created another delivery copy"
        );
        ensure!(
            read_database_evidence(database_url, QUEUE_WRITE_EVIDENCE, &[])? == writes,
            "Account or paginated reads wrote queue or sender idempotency state"
        );

        let mut rejected = queue_request(
            controller,
            "ak:device_message:01964137-2000-7000-8000-000000000026",
            fresh_expiry,
        )?;
        rejected.messages.extend(
            queue_request(
                other_recipient,
                "ak:device_message:01964137-2000-7000-8000-000000000027",
                fresh_expiry,
            )?
            .messages,
        );
        let failure: garth::Error = http
            .send_device_messages("sync-full-endpoint", &rejected)
            .await
            .expect_err("a full endpoint accepted a new delivery")
            .into();
        ensure!(
            matches!(&failure, garth::Error::Api { error, .. } if error.code() == "quota_exceeded"),
            "full endpoint returned a different error: {failure}"
        );
        ensure!(
            read_database_evidence(database_url, QUEUE_WRITE_EVIDENCE, &[])? == writes,
            "full endpoint refusal committed queue or sender idempotency state"
        );
        let retained = http.receive_device_messages(None, None).await?;
        ensure!(
            serde_json::to_value(&retained.deliveries)? == serde_json::to_value(&full.deliveries)?,
            "full endpoint evicted an old delivery"
        );

        self.durable_ack(
            controller,
            host,
            &backfill,
            last.ack_token.as_deref().context("backfill prefix ACK")?,
            database_url,
            QUEUE_CASES[0],
        )
        .await?;
        let old_ack = http
            .ack_device_messages(&DeviceMessagesAckRequestBody {
                ack_token: main_token.into(),
            })
            .await?;
        ensure!(
            old_ack.pruned_count == 0,
            "main-path ACK did not share backfill's cumulative confirmation"
        );
        let after_ack = http
            .account_subscribe_batch(&SyncRequestBody {
                after: Some(main.cursor),
                catchup: Some(false),
                ..account_request
            })
            .await?;
        ensure!(
            after_ack
                .frames
                .iter()
                .filter_map(|frame| frame.to_device.as_ref())
                .all(|queue| queue.deliveries.is_empty()),
            "backfill ACK left another copy on the Account stream"
        );
        let replay = http
            .send_device_messages("sync-full-endpoint", &rejected)
            .await?;
        ensure!(
            replay
                .delivered
                .values()
                .map(|devices| devices.len())
                .sum::<usize>()
                == 2
                && replay.unknown_devices.is_empty(),
            "refused batch idempotency prevented exact retry after capacity returned"
        );
        ensure!(
            http.receive_device_messages(None, None)
                .await?
                .deliveries
                .len()
                == 1
                && other_recipient
                    .client
                    .sdk()
                    .receive_device_messages(None, None)
                    .await?
                    .deliveries
                    .len()
                    == 1,
            "exact retry did not atomically deliver the previously refused batch"
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: QUEUE_CASES[2].into(),
            assertions: 6,
        });
        Ok(())
    }

    async fn durable_ack(
        &self,
        controller: &Member,
        host: &NativeAccountHost,
        deliveries: &[arkret_models_collaboration::device_messages::RecipientDelivery],
        token: &str,
        database_url: &str,
        case_id: &str,
    ) -> Result<()> {
        use arkret_models_collaboration::device_messages::{
            DeviceMessagesAckRequestBody, RecipientDelivery,
        };
        ensure!(
            !deliveries.is_empty(),
            "ACK evidence requires a nonempty queue"
        );
        host.state_store_handle().write(|store| -> Result<()> {
            store
                .ingest_recipient_deliveries(deliveries)
                .map_err(anyhow::Error::msg)?;
            store.flush()?;
            Ok(())
        })?;
        // Reopen the exact active shard before the destructive service call.
        let path = host.state_store().conformance_account_state_path();
        let disk: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        let journal = disk["to_device_inbox"]
            .as_array()
            .context("durable recipient journal")?;
        for delivery in deliveries {
            let RecipientDelivery::DeviceMessage { device_message } = delivery else {
                anyhow::bail!("ACK fixture unexpectedly contains an MLS Welcome");
            };
            ensure!(
                journal.contains(&serde_json::to_value(device_message)?),
                "recipient original bytes were not durable before ACK"
            );
        }
        let queued = controller
            .client
            .sdk()
            .receive_device_messages(None, None)
            .await?;
        ensure!(
            serde_json::to_value(&queued.deliveries)? == serde_json::to_value(deliveries)?,
            "local processing removed or changed the remote queue without ACK"
        );
        let ack = controller
            .client
            .sdk()
            .ack_device_messages(&DeviceMessagesAckRequestBody {
                ack_token: token.to_owned(),
            })
            .await?;
        ensure!(
            ack.pruned_count == deliveries.len() as u64,
            "explicit ACK did not remove exactly the durable recipient prefix"
        );
        ensure!(
            controller
                .client
                .sdk()
                .receive_device_messages(None, None)
                .await?
                .deliveries
                .is_empty(),
            "acknowledged delivery remained in its recipient queue"
        );
        ensure!(
            read_database_evidence(
                database_url,
                "SELECT (consumed_at IS NOT NULL)::text FROM device_message_ack_tokens WHERE ack_token=$1",
                &[&token]
            )? == "true",
            "service did not consume the issued ACK token"
        );
        ensure!(
            serde_json::from_slice::<Value>(&std::fs::read(path)?)? == disk,
            "remote ACK deleted the durable local recipient original"
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: case_id.into(),
            assertions: 6,
        });
        Ok(())
    }

    async fn reconnect_cases(
        &self,
        controller: &Member,
        other_recipient: &Member,
        genesis: &Event,
        creator_group: &arkret::ArkretMlsGroup,
        database_url: &str,
    ) -> Result<()> {
        let path = self.directory.path().join("state.json");
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path.clone()),
            genesis.scope_ref.realm_id().clone(),
        )
        .await?;
        let record = creator_group.export_state_record()?;
        let bytes = serde_json::to_vec(&record)?;
        let secret = "cursor-recovery-fixture-checkpoint-secret";
        let mut checkpoint = inkson::mls::persistence::encrypt_state(
            genesis.scope_ref.realm_id().as_str(),
            &record.group_id,
            record.epoch,
            &bytes,
            secret,
            b"cursor-recovery",
        );
        checkpoint.group_state_event_id = Some(genesis.event_id.clone());
        host.state_store_handle().write(|store| -> Result<()> {
            store
                .save_mls_checkpoint_for_scope(&genesis.scope_ref, checkpoint.clone())
                .map_err(anyhow::Error::msg)?;
            store.flush()?;
            Ok(())
        })?;
        let request = cotest::harness::device_message_send_request(
            controller
                .client
                .principal
                .as_ref()
                .context("recovery controller has no principal")?
                .did
                .as_str(),
            controller.device.as_str(),
            "ak:device_message:01964137-2000-7000-8000-000000000071",
            "ak.mls.application",
            cotest::harness::encrypted_envelope("ak.mls.application", "b3BhcXVl"),
            chrono::Utc::now() + chrono::Duration::minutes(10),
        )?;
        controller
            .client
            .sdk()
            .send_device_messages("sync-reconnect-private-sentinel", &request)
            .await?;
        let queue = controller
            .client
            .sdk()
            .receive_device_messages(None, None)
            .await?;
        ensure!(
            !queue.deliveries.is_empty(),
            "recovery fixture requires a nonempty recipient queue"
        );
        let token = queue
            .ack_token
            .context("recovery fixture requires an issued ACK token")?;
        let ack_record = read_database_evidence(
            database_url,
            "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE ack_token=$1 AND consumed_at IS NULL AND expires_at>now()",
            &[&token],
        )?;
        for (index, name) in RECOVERY_CASES.into_iter().enumerate() {
            let cursor = host
                .state_store()
                .sync_cursor()
                .context("recovery has no durable cursor")?;
            // Issuer-fixture faults only: product code continues to treat the
            // token as opaque and forwards it unchanged to the actual service.
            let (candidate, refusal) = match index {
                0 => (cursor, None),
                1 => {
                    let mut expired = arkret::Cursor::decode(&cursor)?;
                    let now = chrono::Utc::now().timestamp_millis();
                    expired.issued_at = chrono::DateTime::from_timestamp_millis(now - 7_200_000)
                        .context("expired issue time")?;
                    expired.expires_at = chrono::DateTime::from_timestamp_millis(now - 3_600_000)
                        .context("expired deadline")?;
                    (expired.encode()?, Some("cursor_expired"))
                }
                _ => {
                    let mut tampered = arkret::Cursor::decode(&cursor)?;
                    let replacement = if tampered.h.starts_with('A') {
                        "B"
                    } else {
                        "A"
                    };
                    tampered.h.replace_range(..1, replacement);
                    (tampered.encode()?, Some("cursor_integrity_invalid"))
                }
            };
            host.state_store_handle().write(|store| -> Result<()> {
                store.save_sync_cursor(candidate.clone());
                store.flush()?;
                Ok(())
            })?;
            let before = state(&host)?;
            ensure!(
                before["verified_sidecar_history"]
                    .as_object()
                    .is_some_and(|history| !history.is_empty())
                    && before["mls_snapshots"]
                        .as_object()
                        .is_some_and(|states| !states.is_empty()),
                "cursor reset cannot be proved against empty private stores"
            );
            let rail = RecoveryRail {
                http: controller.client.sdk(),
                path: path.clone(),
                database_url: database_url.into(),
                expected_cursor: candidate,
                expected_error: refusal,
                before: before.clone(),
                requests: Default::default(),
                refusals: Default::default(),
            };
            host.catch_up_with_conformance_transport(&rail).await?;
            ensure!(
                rail.requests.lock().unwrap().len() == if refusal.is_some() { 2 } else { 1 }
                    && rail.refusals.lock().unwrap().as_slice()
                        == refusal.into_iter().collect::<Vec<_>>(),
                "the real cursor outcome did not traverse the production recovery driver"
            );
            ensure!(
                host.state_store().sync_cursor().is_some(),
                "recovery installed no new durable checkpoint"
            );
            let retained = host
                .state_store()
                .mls_checkpoint_for_scope(&genesis.scope_ref)
                .context("recovery deleted MLS private state")?;
            ensure!(
                retained == checkpoint
                    && inkson::mls::persistence::decrypt_envelope(&retained, secret)? == bytes,
                "recovery modified the actual encrypted creator checkpoint"
            );
            let after = state(&host)?;
            ensure!(
                after["verified_sidecar_history"] == before["verified_sidecar_history"],
                "recovery changed the verified private prefix"
            );
            let ack_after = read_database_evidence(
                database_url,
                "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE ack_token=$1 AND consumed_at IS NULL AND expires_at>now()",
                &[&token],
            )?;
            ensure!(
                ack_after == ack_record,
                "cursor recovery invalidated or consumed the issued delivery ACK"
            );
            let queued = controller
                .client
                .sdk()
                .receive_device_messages(None, None)
                .await?;
            ensure!(queued.deliveries.iter().any(|delivery| matches!(delivery,
                arkret_models_collaboration::device_messages::RecipientDelivery::DeviceMessage { device_message }
                    if device_message.device_message_id.as_str() == "ak:device_message:01964137-2000-7000-8000-000000000071")),
                "cursor recovery silently removed an unprocessed recipient delivery");
            if index == 0 {
                let durable = inkson::LocalStateStore::with_path(path.clone());
                ensure!(
                    durable.sync_cursor() == host.state_store().sync_cursor()
                        && durable.sync_cursor().as_deref() != Some(rail.expected_cursor.as_str()),
                    "recipient delivery never crossed a durably advanced Account checkpoint"
                );
                self.results.borrow_mut().push(super::CaseExecutionResult {
                    case_id: STREAM_AND_DELIVERY_CASES[1].into(),
                    assertions: 5,
                });
            }
            self.results.borrow_mut().push(super::CaseExecutionResult {
                case_id: name.into(),
                assertions: 10,
            });
        }
        self.durable_ack(
            controller,
            &host,
            &queue.deliveries,
            &token,
            database_url,
            ACK_CASES[1],
        )
        .await?;
        let request = cotest::harness::device_message_send_request(
            controller
                .client
                .principal
                .as_ref()
                .context("ACK controller principal")?
                .did
                .as_str(),
            controller.device.as_str(),
            "ak:device_message:01964137-2000-7000-8000-000000000021",
            "ak.mls.application",
            cotest::harness::encrypted_envelope("ak.mls.application", "b3BhcXVl"),
            chrono::Utc::now() + chrono::Duration::minutes(10),
        )?;
        controller
            .client
            .sdk()
            .send_device_messages("sync-explicit-durable-ack", &request)
            .await?;
        let fresh = controller
            .client
            .sdk()
            .receive_device_messages(None, None)
            .await?;
        self.durable_ack(
            controller,
            &host,
            &fresh.deliveries,
            fresh
                .ack_token
                .as_deref()
                .context("fresh delivery ACK token")?,
            database_url,
            ACK_CASES[0],
        )
        .await?;
        self.queue_cases(controller, other_recipient, &host, database_url)
            .await
    }
}

#[async_trait::async_trait(?Send)]
impl SidecarSyncObserver for Probe {
    async fn before_station(&self, station: &mut cotest::harness::ArkretServer) -> Result<()> {
        *self.scan_relay.borrow_mut() = Some(station.install_scan_gap_relay().await?);
        Ok(())
    }

    fn recipient_queue_capacity(&self) -> Option<usize> {
        Some(2)
    }

    async fn before_genesis(&self, controller: &Member, scope: &ScopeRef) -> Result<()> {
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(self.directory.path().join("state.json")),
            scope.realm_id().clone(),
        )
        .await?;
        host.catch_up_selected_realm_until_complete(scope.realm_id())
            .await
            .context("Sidecar pre-Genesis production baseline")?;
        let (snapshot, history) =
            inkson::conformance::retained_sidecar_cut(&host.state_store(), scope)?;
        ensure!(
            history.len() == 1 && history[0].commit.stream_position == 0,
            "the prior cut must contain exactly the accepted Sidecar context unit"
        );
        ensure!(
            host.state_store().sync_cursor().is_some(),
            "baseline has no durable Account checkpoint"
        );
        ensure!(
            history[0].event.scope_ref == *scope
                && matches!(
                    history[0].commit.stream_ref,
                    arkret_wire::CommitStreamRef::Sidecar { .. }
                )
                && snapshot
                    .visible_stream_heads
                    .iter()
                    .any(|head| head.stream_ref == history[0].commit.stream_ref
                        && head.stream_position == 0
                        && head.commit_id == history[0].commit.commit_id),
            "private context did not install its independent authenticated Sidecar head"
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: STREAM_AND_DELIVERY_CASES[0].into(),
            assertions: 4,
        });
        *self.before.borrow_mut() = Some(state(&host)?);
        *self.host.borrow_mut() = Some(host);
        Ok(())
    }

    async fn after_genesis(
        &self,
        controller: &Member,
        other_recipient: &Member,
        genesis: &Event,
        creator_group: &arkret::ArkretMlsGroup,
        database_url: &str,
    ) -> Result<()> {
        let host = self
            .host
            .borrow_mut()
            .take()
            .context("missing baseline host")?;
        let before = self
            .before
            .borrow()
            .clone()
            .context("missing baseline state")?;
        let old_cursor = host.state_store().sync_cursor().context("old cursor")?;
        let missing = ObservedRail {
            http: controller.client.sdk(),
            missing: Some(genesis.event_id.clone()),
            observed: Default::default(),
        };
        let refused = host.catch_up_with_conformance_transport(&missing).await;
        ensure!(
            matches!(&refused, Err(garth::Error::StreamTailIncomplete { .. })),
            "an incomplete Sidecar frame advanced the driver"
        );
        ensure!(
            missing.observed.lock().unwrap().len() == 4,
            "persistent missing tail did not perform exactly four bounded driver attempts"
        );
        ensure!(
            state(&host)? == before
                && host.state_store().sync_cursor().as_deref() == Some(old_cursor.as_str()),
            "missing tail changed the prior installed cut or checkpoint"
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: CASES[1].into(),
            assertions: 4,
        });

        let account_path = host.state_store().conformance_account_state_path();
        let bytes = std::fs::read(&account_path)?;
        let backup = account_path.with_extension("backup");
        std::fs::rename(&account_path, &backup)?;
        std::fs::create_dir(&account_path)?;
        let rail = ObservedRail {
            http: controller.client.sdk(),
            missing: None,
            observed: Default::default(),
        };
        let failed = host.catch_up_with_conformance_transport(&rail).await;
        let staged = std::fs::read(account_path.with_extension("json.tmp"));
        std::fs::remove_dir(&account_path)?;
        std::fs::rename(&backup, &account_path)?;
        ensure!(
            failed.is_err(),
            "a real persistence failure crossed the Account driver"
        );
        let staged: Value = serde_json::from_slice(
            &staged.context("the failed write never staged an account shard")?,
        )?;
        ensure!(
            staged["verified_sidecar_history"]
                .as_object()
                .is_some_and(|streams| streams
                    .values()
                    .filter_map(Value::as_array)
                    .flatten()
                    .any(|row| row["event"]["event_id"] == genesis.event_id.as_str())),
            "persistence negative never staged the verified new private history"
        );
        ensure!(
            rail.observed.lock().unwrap().len() == 1,
            "persistence case did not deliver the authentic incremental"
        );
        ensure!(
            state(&host)? == before && std::fs::read(&account_path)? == bytes,
            "persistence failure partially installed history, current, generation or checkpoint"
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: CASES[2].into(),
            assertions: 4,
        });

        drop(host);
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(self.directory.path().join("state.json")),
            genesis.scope_ref.realm_id().clone(),
        )
        .await?;
        ensure!(
            host.state_store().sync_cursor().as_deref() == Some(old_cursor.as_str()),
            "host reopen lost the old checkpoint"
        );
        host.catch_up_selected_realm_until_complete(genesis.scope_ref.realm_id())
            .await?;
        let (snapshot, history) =
            inkson::conformance::retained_sidecar_cut(&host.state_store(), &genesis.scope_ref)?;
        ensure!(
            history.len() == 2
                && history[1].event == *genesis
                && history[1].commit.stream_position == 1,
            "the repaired driver did not install the exact continuous private prefix"
        );
        ensure!(
            snapshot
                .visible_stream_heads
                .iter()
                .any(|head| head.stream_ref == history[1].commit.stream_ref
                    && head.stream_position == 1
                    && head.commit_id == history[1].commit.commit_id),
            "private current and history have different cuts"
        );
        let cursor = host.state_store().sync_cursor().context("new checkpoint")?;
        ensure!(
            cursor != old_cursor,
            "successful private installation did not advance the checkpoint"
        );
        drop(host);
        let reopened = inkson::LocalStateStore::with_path(self.directory.path().join("state.json"));
        ensure!(
            reopened.sync_cursor().as_deref() == Some(cursor.as_str()),
            "restart lost the installed checkpoint"
        );
        ensure!(
            inkson::conformance::retained_sidecar_cut(&reopened, &genesis.scope_ref)?
                == (snapshot.clone(), history.clone()),
            "restart changed the admitted private cut"
        );
        let evidence = self.directory.path().join("expected-cut.json");
        std::fs::write(
            &evidence,
            serde_json::to_vec(&(&genesis.scope_ref, &snapshot, &history, &cursor))?,
        )?;
        let output = std::process::Command::new(&self.reader)
            .arg(self.directory.path().join("state.json"))
            .arg(&evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "fresh-process cut readback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: CASES[0].into(),
            assertions: 8,
        });
        self.reconnect_cases(
            controller,
            other_recipient,
            genesis,
            creator_group,
            database_url,
        )
        .await?;
        self.baseline_ordering(controller, other_recipient, database_url)
            .await?;
        Ok(())
    }
}

impl Probe {
    async fn baseline_ordering(
        &self,
        controller: &Member,
        member: &Member,
        database_url: &str,
    ) -> Result<()> {
        use cotest::scenarios::human_device_producer_live::{
            membership_payload, submit_and_expect_commit,
        };
        let created = controller
            .client
            .create_realm_with(serde_json::json!({
                "title":"Sync baseline ordering", "summary":"Sync baseline ordering",
                "public":false, "join_rule":"public",
                "plaintext_visible_services":[controller.account.station_id.to_string()]
            }))
            .await?;
        let realm =
            arkret_wire::RealmId::new(created["realm_id"].as_str().context("ordering Realm")?)?;
        let path = self.directory.path().join("ordering-state.json");
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path.clone()),
            realm.clone(),
        )
        .await?;
        let request = SyncRequestBody {
            catchup: Some(true),
            filter: Some(garth::AccountFilter {
                realm_ids: Some(vec![realm.clone()]),
                window_limit: Some(20),
                lazy_load_members: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let old = controller
            .client
            .sdk()
            .account_subscribe_batch(&request)
            .await?;
        let mut partial = old.clone();
        let mut segments = 0;
        for frame in &mut partial.frames {
            if let Some(entry) = frame
                .realms
                .as_mut()
                .and_then(|r| r.entries.get_mut(realm.as_str()))
            {
                if let Some(baseline) = &mut entry.baseline {
                    ensure!(baseline.complete, "source baseline is not complete");
                    baseline.complete = false;
                    segments += 1;
                }
            }
        }
        ensure!(
            segments == 1,
            "ordering requires one authentic Realm baseline segment"
        );
        host.catch_up_with_conformance_transport(&HeldBatch(Mutex::new(Some(partial))))
            .await?;
        let before = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            &realm,
        )
        .await?;
        let join = member.client.author_event(
            realm.as_str(), arkret_wire::EventKind::MemberState.as_str(),
            membership_payload(realm.as_str(), member.account.clone(),
                arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,
                "Incremental must survive the held old baseline")?,
        ).await?;
        let commit = submit_and_expect_commit(
            &member.client,
            &member.account,
            member.device.as_str(),
            &join,
        )
        .await?;
        let prior_head = old
            .frames
            .iter()
            .filter_map(|frame| frame.realms.as_ref())
            .filter_map(|realms| realms.entries.get(realm.as_str()))
            .filter_map(|entry| entry.current.as_ref())
            .flat_map(|current| &current.stream_heads)
            .find(|head| head.stream_ref == commit.stream_ref)
            .context("baseline has no original Realm head")?;
        ensure!(
            commit.stream_position == prior_head.stream_position + 1
                && commit.previous_commit_ref.as_ref() == Some(&prior_head.commit_id),
            "membership delta is not the immediate authentic successor of the held baseline"
        );
        let mut prefix = old
            .frames
            .iter()
            .filter_map(|frame| frame.realms.as_ref())
            .filter_map(|realms| realms.entries.get(realm.as_str()))
            .flat_map(|entry| entry.committed_events.iter().flatten())
            .map(|row| row.commit())
            .filter(|row| row.stream_ref == commit.stream_ref)
            .collect::<Vec<_>>();
        prefix.sort_by_key(|row| row.stream_position);
        ensure!(
            prefix.len() as u64 == prior_head.stream_position + 1
                && prefix.first().is_some_and(
                    |row| row.stream_position == 0 && row.previous_commit_ref.is_none()
                ),
            "Realm baseline is not a complete original prefix from position zero"
        );
        ensure!(
            prefix.windows(2).all(
                |pair| pair[1].stream_position == pair[0].stream_position + 1
                    && pair[1].previous_commit_ref.as_ref() == Some(&pair[0].commit_id)
            ),
            "Realm baseline has an unexplained position or predecessor gap"
        );
        ensure!(
            old.frames
                .iter()
                .filter_map(|frame| frame.realms.as_ref())
                .filter_map(|realms| realms.entries.get(realm.as_str()))
                .flat_map(|entry| entry.streams.iter().flatten())
                .any(|window| window.stream_ref == commit.stream_ref
                    && window.preview_only != Some(true)),
            "Realm prefix was delivered only as an unverified preview"
        );
        let stream_key = serde_json::to_string(&commit.stream_ref)?;
        let before_state = state(&host)?;
        ensure!(
            before_state["verified_commit_stream_cursors"][&stream_key]
                == serde_json::to_value(prior_head)?
                && before_state["verified_commit_stream_anchors"][&stream_key]
                    == serde_json::to_value(prefix.last().context("Realm original anchor")?)?,
            "ordinary Account driver did not install the exact verified Realm prefix checkpoint"
        );
        let incremental = controller
            .client
            .sdk()
            .account_subscribe_batch(&SyncRequestBody {
                after: Some(old.cursor.clone()),
                catchup: Some(false),
                ..request
            })
            .await?;
        ensure!(
            incremental
                .frames
                .iter()
                .filter_map(|f| f.realms.as_ref())
                .filter_map(|r| r.entries.get(realm.as_str()))
                .flat_map(|e| e.committed_events.iter().flatten())
                .any(|row| row.commit().commit_id == commit.commit_id
                    && row.commit().event_ref == join.event_id),
            "actual Account incremental omitted the accepted Realm join"
        );
        let cursor = incremental.cursor.clone();
        host.catch_up_with_conformance_transport(&HeldBatch(Mutex::new(Some(incremental))))
            .await?;
        let newer = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            &realm,
        )
        .await?;
        let head = serde_json::to_value(arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        })?;
        let anchor = serde_json::to_value(&commit)?;
        let after_state = state(&host)?;
        ensure!(
            after_state["verified_commit_stream_cursors"][&stream_key] == head
                && after_state["verified_commit_stream_anchors"][&stream_key] == anchor,
            "authentic Realm delta did not advance the verified checkpoint and signed original together"
        );
        ensure!(
            newer["entries"] != before["entries"],
            "Realm delta changed no durable current row"
        );
        ensure!(
            newer["entries"]
                .as_array()
                .context("typed Realm current rows")?
                .iter()
                .any(|row| row["revision"]["commit_id"] == commit.commit_id.as_str()),
            "durable current omitted the exact accepted Realm membership revision"
        );
        let mut completion = old;
        completion.frames.retain(|frame| {
            frame.realms.as_ref().is_some_and(|realms| {
                realms
                    .entries
                    .get(realm.as_str())
                    .is_some_and(|entry| entry.baseline.is_some())
            })
        });
        for frame in &mut completion.frames {
            let realms = frame
                .realms
                .as_mut()
                .context("held baseline Realm container")?;
            realms.entries.retain(|id, _| id == realm.as_str());
            for entry in realms.entries.values_mut() {
                // Deliver only the held baseline section, not its already
                // installed history window or a regressive stream checkpoint.
                *entry =
                    arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry {
                        current: entry.current.clone(),
                        baseline: entry.baseline.clone(),
                        ..Default::default()
                    };
            }
            frame.validate()?;
        }
        completion.cursor = completion
            .frames
            .last()
            .and_then(|frame| frame.cursor.clone())
            .context("held baseline source cursor")?;
        host.catch_up_with_conformance_transport(&HeldBatch(Mutex::new(Some(completion))))
            .await?;
        let completed = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            &realm,
        )
        .await?;
        ensure!(
            completed["entries"] == newer["entries"],
            "older baseline overwrote the accepted incremental"
        );
        // The replayed old opaque cursor is not ordered against the newer one.
        // Verify only the cursor the ordinary driver actually made durable.
        let durable_cursor = host
            .state_store()
            .sync_cursor()
            .context("ordering checkpoint")?;
        ensure!(
            !cursor.is_empty() && !durable_cursor.is_empty(),
            "ordering lost its durable cursor"
        );
        drop(host);
        let reopened = inkson::LocalStateStore::with_path(path.clone());
        ensure!(
            reopened.sync_cursor().as_deref() == Some(durable_cursor.as_str()),
            "ordering checkpoint was not durable"
        );
        ensure!(
            inkson::conformance::retained_realm_current(&reopened, &controller.account, &realm)
                .await?
                == completed,
            "reopen changed the ordered current cut"
        );
        let evidence = self.directory.path().join("expected-ordering-cut.json");
        std::fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "account":controller.account, "realm":realm, "cut":completed, "cursor":durable_cursor,
                "stream_key":stream_key, "head":head, "anchor":anchor
            }))?,
        )?;
        let output = std::process::Command::new(&self.reader)
            .arg(path)
            .arg(evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "fresh-process Realm current readback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: BASELINE_CASE.into(),
            assertions: 9,
        });
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: STREAM_AND_DELIVERY_CASES[2].into(),
            assertions: 7,
        });
        self.projection_checkpoint_ordering(controller, &realm)
            .await?;
        self.circle_tail(controller, &realm, database_url).await?;
        Ok(())
    }
}

impl Probe {
    async fn projection_checkpoint_ordering(
        &self,
        controller: &Member,
        realm: &arkret_wire::RealmId,
    ) -> Result<()> {
        let path = self.directory.path().join("checkpoint-ordering-state.json");
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path.clone()),
            realm.clone(),
        )
        .await?;
        host.catch_up().await?;
        let before = state(&host)?;
        let before_cut = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            realm,
        )
        .await?;
        let old_cursor = host
            .state_store()
            .sync_cursor()
            .context("ordering prior cursor")?;
        let account_path = host.state_store().conformance_account_state_path();
        let account_bytes = std::fs::read(&account_path)?;
        let index_path = path.with_extension("current.sqlite");
        ensure!(
            index_path.is_file(),
            "ordering has no actual native current index"
        );
        let database = rusqlite::Connection::open(&index_path)?;
        let rows = |connection: &rusqlite::Connection| -> Result<Vec<(String, String)>> {
            let mut query =
                connection.prepare("SELECT key,value FROM current_entries ORDER BY key")?;
            let rows = query
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        };
        let encrypted_before = rows(&database)?;
        let circle = cotest::scenarios::circle_poll_scope_live::circle_create(
            &controller.client,
            realm.as_str(),
            &controller.actor,
            "Checkpoint ordering",
            "Ordering",
        )
        .await?;
        cotest::scenarios::circle_poll_scope_live::join_circle(
            &controller.client,
            realm.as_str(),
            &circle,
            &controller.actor,
        )
        .await?;
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let key = serde_json::to_string(&stream)?;
        let old_position = before["verified_commit_stream_cursors"][&key]["stream_position"]
            .as_u64()
            .context("ordering prior signed head")?;
        let scan = controller
            .client
            .sdk()
            .scan_commit_stream(&arkret_wire::StreamScanRequest {
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                direction: arkret_wire::StreamScanDirection::After(Some(old_position)),
                limit: 32,
            })
            .await?;
        ensure!(
            scan.committed_events.len() == 1,
            "ordering setup lacks one real accepted successor"
        );
        let commit = scan.committed_events[0].commit().clone();
        ensure!(
            commit.stream_position == old_position + 1
                && serde_json::to_value(&commit.previous_commit_ref)?
                    == before["verified_commit_stream_cursors"][&key]["commit_id"],
            "ordering setup lacks its exact accepted predecessor"
        );

        // Only the current backend refuses writes. The Account checkpoint
        // remains writable, so checkpoint-first regressions remain observable.
        database.execute_batch("CREATE TRIGGER cotest_projection_write_barrier BEFORE INSERT ON current_entries BEGIN SELECT RAISE(ABORT,'cotest projection write barrier'); END;")?;
        let rail = ObservedRail {
            http: controller.client.sdk(),
            missing: None,
            observed: Default::default(),
        };
        let failed = host.catch_up_with_conformance_transport(&rail).await;
        database.execute_batch("DROP TRIGGER cotest_projection_write_barrier;")?;
        ensure!(
            matches!(&failed, Err(garth::Error::Protocol(message)) if message.contains("cotest projection write barrier")),
            "ordering did not fail at the actual current storage barrier: {failed:?}"
        );
        ensure!(
            std::fs::read(&account_path)? == account_bytes
                && rows(&database)? == encrypted_before
                && state(&host)? == before
                && host.state_store().sync_cursor().as_deref() == Some(old_cursor.as_str()),
            "current failure allowed a premature durable checkpoint or projection"
        );
        ensure!(
            inkson::conformance::retained_realm_current(
                &host.state_store(),
                &controller.account,
                realm
            )
            .await?
                == before_cut,
            "current failure changed the installed product cut"
        );
        let batches = rail.observed.lock().unwrap().clone();
        ensure!(
            batches.len() == 1
                && batches[0].cursor != old_cursor
                && batches[0]
                    .frames
                    .iter()
                    .flat_map(|frame| frame.realms.iter())
                    .flat_map(|realms| realms.entries.values())
                    .flat_map(|entry| entry.committed_events.iter().flatten())
                    .any(|row| row.commit() == &commit),
            "ordering rejection did not receive the actual signed successor and next cursor"
        );
        let pending = batches[0].clone();
        let failed_evidence = self.directory.path().join("expected-ordering-failure.json");
        std::fs::write(
            &failed_evidence,
            serde_json::to_vec(&serde_json::json!({
                "account":controller.account, "realm":realm, "cut":before_cut, "cursor":old_cursor,
                "stream_key":key, "head":before["verified_commit_stream_cursors"][&key],
                "anchor":before["verified_commit_stream_anchors"][&key],
                "stream_heads":before["verified_commit_stream_cursors"],
                "stream_anchors":before["verified_commit_stream_anchors"]
            }))?,
        )?;
        let output = std::process::Command::new(&self.reader)
            .arg(&path)
            .arg(failed_evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "failed projection fresh-process readback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: ORDERING_CASES[1].into(),
            assertions: 8,
        });

        let held = HeldBatch(Mutex::new(Some(pending.clone())));
        host.catch_up_with_conformance_transport(&held).await?;
        let after = state(&host)?;
        let head = serde_json::to_value(arkret_wire::CommitStreamHead {
            stream_ref: stream,
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        })?;
        let anchor = serde_json::to_value(&commit)?;
        let cut = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            realm,
        )
        .await?;
        ensure!(
            host.state_store().sync_cursor().as_deref() == Some(pending.cursor.as_str()),
            "ordering replay did not durably save its received Account cursor"
        );
        ensure!(
            after["current_generation"].as_u64() > before["current_generation"].as_u64(),
            "ordering replay installed no newer durable current generation"
        );
        ensure!(
            after["verified_commit_stream_cursors"][&key] == head,
            "ordering replay lost the exact verified successor head"
        );
        ensure!(
            after["verified_commit_stream_anchors"][&key] == anchor,
            "ordering replay lost the exact original signed successor anchor"
        );
        ensure!(
            cut["entries"]
                .as_array()
                .context("ordering installed current")?
                .iter()
                .any(|row| row["revision"]["commit_id"] == commit.commit_id.as_str()),
            "ordering checkpoint advanced without the authentic installed current result"
        );
        let evidence = self
            .directory
            .path()
            .join("expected-checkpoint-ordering.json");
        std::fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "account":controller.account, "realm":realm, "cut":cut, "cursor":pending.cursor,
                "stream_key":key, "head":head, "anchor":anchor,
                "stream_heads":after["verified_commit_stream_cursors"], "stream_anchors":after["verified_commit_stream_anchors"]
            }))?,
        )?;
        drop(host);
        drop(database);
        let output = std::process::Command::new(&self.reader)
            .arg(path)
            .arg(evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "ordering fresh-process readback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: ORDERING_CASES[0].into(),
            assertions: 6,
        });
        Ok(())
    }

    async fn readable_row_gap(
        &self,
        controller: &Member,
        realm: &arkret_wire::RealmId,
        database_url: &str,
    ) -> Result<()> {
        use cotest::scenarios::circle_poll_scope_live::{circle_create, circle_event, join_circle};
        use cotest::scenarios::human_device_producer_live::submit_and_expect_commit;
        let circle = circle_create(
            &controller.client,
            realm.as_str(),
            &controller.actor,
            "Readable row gap",
            "Row gap",
        )
        .await?;
        join_circle(
            &controller.client,
            realm.as_str(),
            &circle,
            &controller.actor,
        )
        .await?;
        let stream = arkret_wire::CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle.clone(),
        };
        let path = self.directory.path().join("readable-row-gap-state.json");
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path.clone()),
            realm.clone(),
        )
        .await?;
        let baseline = ObservedRail {
            http: controller.client.sdk(),
            missing: None,
            observed: Default::default(),
        };
        host.catch_up_with_conformance_transport(&baseline).await?;
        let before = state(&host)?;
        let cursor = host
            .state_store()
            .sync_cursor()
            .context("row gap prior cursor")?;
        let key = serde_json::to_string(&stream)?;
        ensure!(
            before["verified_commit_stream_cursors"][&key]["stream_position"] == 0,
            "row gap did not start at a durable signed genesis"
        );
        let mut commits = Vec::new();
        for title in ["Missing original one", "Visible original two"] {
            let event = circle_event(&controller.client, realm.as_str(), &circle,
                arkret_wire::EventKind::StrandCreate,
                serde_json::json!({"object":{"schema":"ak.schema.strand.v1", "realm_id":realm,
                    "scope_circle_id":circle, "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                    "metadata":{"title":title}, "state":"active", "created_by":controller.actor}})).await?;
            commits.push(
                submit_and_expect_commit(
                    &controller.client,
                    &controller.account,
                    controller.device.as_str(),
                    &event,
                )
                .await?,
            );
        }
        ensure!(
            commits[0].stream_position == 1
                && commits[1].stream_position == 2
                && commits[1].previous_commit_ref.as_ref() == Some(&commits[0].commit_id),
            "row gap setup has no genuine accepted continuous originals"
        );
        let request = arkret_wire::StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 32,
        };
        let original = controller.client.sdk().scan_commit_stream(&request).await?;
        ensure!(
            original.committed_events.len() == 3,
            "row gap original prefix is not zero/one/two"
        );
        circle_create(
            &controller.client,
            realm.as_str(),
            &controller.actor,
            "Row gap healthy sibling",
            "Row sibling",
        )
        .await?;
        let http = controller.client.sdk();
        // Earlier capacity cases deliberately retain this real unacknowledged
        // delivery. Reuse it rather than weakening the endpoint's quota.
        let delivery = http.receive_device_messages(None, None).await?;
        ensure!(delivery.deliveries.iter().any(|row| matches!(row,
            arkret_models_collaboration::device_messages::RecipientDelivery::DeviceMessage { device_message }
            if device_message.device_message_id.as_str() == "ak:device_message:01964137-2000-7000-8000-000000000028")),
            "row gap lacks its real nonempty delivery");
        let ack_token = delivery.ack_token.context("row gap issued ACK")?;
        let ack_before = read_database_evidence(
            database_url,
            "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE ack_token=$1",
            &[&ack_token],
        )?;
        let fault = self
            .scan_relay
            .borrow()
            .as_ref()
            .context("real HTTP scan relay")?
            .control();
        fault.omit_position_one(stream.clone());
        let skipped: arkret_wire::StreamScanOutcome = serde_json::from_value(
            cotest::harness::expect_json(
                controller
                    .client
                    .post("/_arkret/self/streams/scan")
                    .json(&request),
                reqwest::StatusCode::OK,
            )
            .await?,
        )?;
        ensure!(
            skipped.committed_events
                == vec![
                    original.committed_events[0].clone(),
                    original.committed_events[2].clone()
                ]
                && skipped.readable_floor == original.readable_floor,
            "HTTP fault rewrote signed originals or their readable floor"
        );
        ensure!(
            matches!(skipped.validate_for_request(&request),
            Err(arkret_wire::WireError::StreamPositionGap { ref stream_ref, expected: 1, actual: 2 }) if *stream_ref == stream),
            "actual HTTP zero/two scan did not identify its exact readable gap"
        );
        let rail = StreamGapRail {
            row_fault: Some(fault.clone()),
            http: http.clone(),
            database_url: database_url.into(),
            path: path.clone(),
            before: before.clone(),
            cursor,
            affected_stream: stream.clone(),
            healthy_stream: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            healthy_commit: Default::default(),
            ack_token,
            ack_before,
            requests: Default::default(),
        };
        host.catch_up_with_conformance_transport(&rail).await?;
        ensure!(
            rail.requests.lock().unwrap().len() == 2 && fault.observations().len() >= 2,
            "ordinary driver did not encounter and recover the actual HTTP row gap"
        );
        ensure!(
            read_database_evidence(
                database_url,
                "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE ack_token=$1",
                &[&rail.ack_token]
            )? == rail.ack_before,
            "repaired row gap reset the issued ACK"
        );
        let recovered_state = state(&host)?;
        let healthy_key = serde_json::to_string(&rail.healthy_stream)?;
        for (sibling, head) in before["verified_commit_stream_cursors"]
            .as_object()
            .context("row gap complete prior map")?
        {
            if sibling != &key && sibling != &healthy_key {
                ensure!(
                    recovered_state["verified_commit_stream_cursors"][sibling] == *head
                        && recovered_state["verified_commit_stream_anchors"][sibling]
                            == before["verified_commit_stream_anchors"][sibling],
                    "row gap recovery reset an unrelated stream"
                );
            }
        }
        let repaired = http.scan_commit_stream(&request).await?;
        ensure!(
            repaired == original,
            "row recovery changed an accepted original"
        );
        let after = state(&host)?;
        ensure!(
            after["verified_commit_stream_cursors"][&key]["stream_position"] == 2
                && after["verified_commit_stream_anchors"][&key]
                    == serde_json::to_value(&commits[1])?,
            "row gap recovered without its authentic position-two anchor"
        );
        let cut = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            realm,
        )
        .await?;
        let cursor = host
            .state_store()
            .sync_cursor()
            .context("row gap repaired cursor")?;
        ensure!(
            cursor != rail.cursor,
            "row gap recovery advanced no Account cut"
        );
        let evidence = self.directory.path().join("expected-readable-row-gap.json");
        std::fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
            "account":controller.account, "realm":realm, "cut":cut, "cursor":cursor,
            "stream_key":key, "head":after["verified_commit_stream_cursors"][&key],
            "anchor":commits[1], "stream_heads":after["verified_commit_stream_cursors"],
            "stream_anchors":after["verified_commit_stream_anchors"] }))?,
        )?;
        drop(host);
        let output = std::process::Command::new(&self.reader)
            .arg(path)
            .arg(evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "row gap fresh-process readback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: STREAM_GAP_CASE.into(),
            assertions: 12,
        });
        Ok(())
    }

    async fn circle_tail(
        &self,
        controller: &Member,
        realm: &arkret_wire::RealmId,
        database_url: &str,
    ) -> Result<()> {
        use cotest::scenarios::circle_poll_scope_live::{circle_create, circle_event, join_circle};
        use cotest::scenarios::human_device_producer_live::submit_and_expect_commit;
        let circle = circle_create(
            &controller.client,
            realm.as_str(),
            &controller.actor,
            "Independent Sync tail",
            "Sync tail",
        )
        .await?;
        join_circle(
            &controller.client,
            realm.as_str(),
            &circle,
            &controller.actor,
        )
        .await?;
        let stream = arkret_wire::CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle.clone(),
        };
        let key = serde_json::to_string(&stream)?;
        let parent_key = serde_json::to_string(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        })?;
        let path = self.directory.path().join("circle-state.json");
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path.clone()),
            realm.clone(),
        )
        .await?;
        let initial = ObservedRail {
            http: controller.client.sdk(),
            missing: None,
            observed: Default::default(),
        };
        host.catch_up_with_conformance_transport(&initial).await?;
        let batches = initial.observed.lock().unwrap();
        let rows = batches
            .iter()
            .flat_map(|batch| &batch.frames)
            .flat_map(|frame| frame.realms.iter())
            .flat_map(|realms| realms.entries.values())
            .flat_map(|entry| entry.committed_events.iter().flatten())
            .filter(|row| row.commit().stream_ref == stream)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1
                && rows[0].commit().stream_position == 0
                && rows[0].commit().previous_commit_ref.is_none(),
            "fresh Circle baseline did not carry its independent position-zero Commit"
        );
        let first = rows[0].commit().clone();
        let before = state(&host)?;
        let first_head = serde_json::to_value(arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 0,
            commit_id: first.commit_id.clone(),
        })?;
        ensure!(
            before["verified_commit_stream_cursors"][&key] == first_head
                && before["verified_commit_stream_anchors"][&key] == serde_json::to_value(&first)?,
            "Circle baseline was not verified and durably anchored by the Account driver"
        );
        let parent = before["verified_commit_stream_cursors"][&parent_key].clone();
        ensure!(
            parent["stream_position"]
                .as_u64()
                .is_some_and(|position| position > 1),
            "Circle independence requires a distinct already advanced Realm head"
        );
        let old_cursor = host
            .state_store()
            .sync_cursor()
            .context("Circle baseline checkpoint")?;
        drop(batches);
        let strand = circle_event(&controller.client, realm.as_str(), &circle,
            arkret_wire::EventKind::StrandCreate,
            serde_json::json!({"object":{"schema":"ak.schema.strand.v1", "realm_id":realm,
                "scope_circle_id":circle, "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":"Independent Circle tail"}, "state":"active", "created_by":controller.actor}})).await?;
        let commit = submit_and_expect_commit(
            &controller.client,
            &controller.account,
            controller.device.as_str(),
            &strand,
        )
        .await?;
        ensure!(
            commit.stream_ref == stream
                && commit.stream_position == 1
                && commit.previous_commit_ref.as_ref() == Some(&first.commit_id),
            "accepted Circle successor borrowed a sibling stream predecessor or position"
        );
        let rail = ObservedRail {
            http: controller.client.sdk(),
            missing: None,
            observed: Default::default(),
        };
        host.catch_up_with_conformance_transport(&rail).await?;
        let batches = rail.observed.lock().unwrap();
        ensure!(
            batches
                .iter()
                .flat_map(|batch| &batch.frames)
                .flat_map(|frame| frame.realms.iter())
                .flat_map(|realms| realms.entries.values())
                .flat_map(|entry| entry.committed_events.iter().flatten())
                .any(|row| row.commit() == &commit && row.reducer_input() == Some(&strand)),
            "actual Account incremental omitted the exact accepted Circle original"
        );
        drop(batches);
        let head = serde_json::to_value(arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 1,
            commit_id: commit.commit_id.clone(),
        })?;
        let anchor = serde_json::to_value(&commit)?;
        let after = state(&host)?;
        ensure!(
            after["verified_commit_stream_cursors"][&key] == head
                && after["verified_commit_stream_anchors"][&key] == anchor,
            "Circle delta advanced without its exact verified head and signed original"
        );
        ensure!(
            after["verified_commit_stream_cursors"][&parent_key] == parent
                && after["verified_commit_stream_anchors"][&parent_key]
                    == before["verified_commit_stream_anchors"][&parent_key],
            "Circle-only advancement reset or advanced the parent Realm stream"
        );
        let cut = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            realm,
        )
        .await?;
        ensure!(
            cut["entries"]
                .as_array()
                .context("Circle current rows")?
                .iter()
                .any(|row| row["revision"]["commit_id"] == commit.commit_id.as_str()),
            "durable typed current omitted the accepted Circle successor"
        );
        let cursor = host
            .state_store()
            .sync_cursor()
            .context("Circle successor checkpoint")?;
        ensure!(
            cursor != old_cursor,
            "Circle successor advanced no durable Account cursor"
        );
        drop(host);
        let reopened = inkson::LocalStateStore::with_path(path.clone());
        ensure!(
            reopened.sync_cursor().as_deref() == Some(cursor.as_str())
                && inkson::conformance::retained_realm_current(
                    &reopened,
                    &controller.account,
                    realm
                )
                .await?
                    == cut,
            "Circle current and Account checkpoint changed across reopen"
        );
        let evidence = self.directory.path().join("expected-circle-cut.json");
        std::fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "account":controller.account, "realm":realm, "cut":cut, "cursor":cursor,
                "stream_key":key, "head":head, "anchor":anchor,
                "stream_heads":after["verified_commit_stream_cursors"],
                "stream_anchors":after["verified_commit_stream_anchors"]
            }))?,
        )?;
        let output = std::process::Command::new(&self.reader)
            .arg(&path)
            .arg(evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "fresh-process Circle cut readback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.results.borrow_mut().push(super::CaseExecutionResult {
            case_id: CIRCLE_TAIL_CASE.into(),
            assertions: 10,
        });
        self.circle_gap(
            controller,
            realm,
            &circle,
            &stream,
            path.clone(),
            database_url,
        )
        .await?;
        self.circle_gap_recovery(controller, realm, &circle, &stream, &path)
            .await?;
        self.readable_row_gap(controller, realm, database_url)
            .await?;
        Ok(())
    }

    async fn circle_gap(
        &self,
        controller: &Member,
        realm: &arkret_wire::RealmId,
        circle: &arkret_wire::CircleId,
        stream: &arkret_wire::CommitStreamRef,
        path: std::path::PathBuf,
        database_url: &str,
    ) -> Result<()> {
        use cotest::scenarios::circle_poll_scope_live::circle_event;
        use cotest::scenarios::human_device_producer_live::submit_and_expect_commit;
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path.clone()),
            realm.clone(),
        )
        .await?;
        let before = state(&host)?;
        let cursor = host
            .state_store()
            .sync_cursor()
            .context("gap prior cursor")?;
        let mut commits = Vec::new();
        for title in ["Gap predecessor", "Gap successor"] {
            let event = circle_event(&controller.client, realm.as_str(), circle,
                arkret_wire::EventKind::StrandCreate,
                serde_json::json!({"object":{"schema":"ak.schema.strand.v1", "realm_id":realm,
                    "scope_circle_id":circle, "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                    "metadata":{"title":title}, "state":"active", "created_by":controller.actor}})).await?;
            commits.push(
                submit_and_expect_commit(
                    &controller.client,
                    &controller.account,
                    controller.device.as_str(),
                    &event,
                )
                .await?,
            );
        }
        ensure!(
            commits[0].stream_ref == *stream
                && commits[0].stream_position == 2
                && commits[1].stream_ref == *stream
                && commits[1].stream_position == 3
                && commits[1].previous_commit_ref.as_ref() == Some(&commits[0].commit_id),
            "gap setup lacks an authentic accepted continuous successor pair"
        );
        cotest::scenarios::circle_poll_scope_live::circle_create(
            &controller.client,
            realm.as_str(),
            &controller.actor,
            "Healthy sibling",
            "Sibling",
        )
        .await?;
        let http = controller.client.sdk();
        http.send_device_messages(
            "sync-gap-retained-ack",
            &queue_request(
                controller,
                "ak:device_message:01964137-2000-7000-8000-000000000028",
                chrono::Utc::now() + chrono::Duration::hours(1),
            )?,
        )
        .await?;
        let delivery = http.receive_device_messages(None, None).await?;
        ensure!(
            delivery
                .deliveries
                .iter()
                .filter(|row| matches!(row,
                    arkret_models_collaboration::device_messages::RecipientDelivery::DeviceMessage { device_message }
                    if device_message.device_message_id.as_str() == "ak:device_message:01964137-2000-7000-8000-000000000028"))
                .count()
                == 1,
            "gap setup lacks its exact newly accepted recipient delivery"
        );
        let ack_token = delivery
            .ack_token
            .context("nonempty issued recipient ACK")?;
        let ack_before = read_database_evidence(
            database_url,
            "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE ack_token=$1",
            &[&ack_token],
        )?;
        let rail = StreamGapRail {
            row_fault: None,
            http: controller.client.sdk(),
            database_url: database_url.into(),
            path: path.clone(),
            before: before.clone(),
            cursor,
            affected_stream: stream.clone(),
            healthy_stream: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            healthy_commit: Default::default(),
            ack_token,
            ack_before,
            requests: Default::default(),
        };
        // Alter only the untrusted window's declared end. Original signed
        // Events, Commits, Snapshot and PostgreSQL rows remain unchanged.
        // The retry must be requested by the ordinary production driver.
        let recovered = host.catch_up_with_conformance_transport(&rail).await;
        recovered?;
        ensure!(
            rail.requests.lock().unwrap().len() == 2,
            "actual driver never stopped and retried the affected stream"
        );
        let after = state(&host)?;
        let key = serde_json::to_string(stream)?;
        let head = serde_json::to_value(arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 3,
            commit_id: commits[1].commit_id.clone(),
        })?;
        let anchor = serde_json::to_value(&commits[1])?;
        ensure!(
            after["verified_commit_stream_cursors"][&key] == head
                && after["verified_commit_stream_anchors"][&key] == anchor,
            "recovery failed to install the authentic repaired Circle tail"
        );
        for (sibling, old) in before["verified_commit_stream_cursors"]
            .as_object()
            .context("prior streams")?
        {
            if sibling != &key && sibling != &serde_json::to_string(&rail.healthy_stream)? {
                ensure!(
                    after["verified_commit_stream_cursors"][sibling] == *old
                        && after["verified_commit_stream_anchors"][sibling]
                            == before["verified_commit_stream_anchors"][sibling],
                    "gap recovery reset or advanced an unrelated stream"
                );
            }
        }
        let cursor = host
            .state_store()
            .sync_cursor()
            .context("repaired cursor")?;
        ensure!(
            cursor != rail.cursor,
            "repaired tail made no durable progress"
        );
        let cut = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            realm,
        )
        .await?;
        ensure!(
            cut["entries"]
                .as_array()
                .context("repaired current")?
                .iter()
                .any(|row| row["revision"]["commit_id"] == commits[1].commit_id.as_str()),
            "repaired current omits the exact accepted successor"
        );
        drop(host);
        let expected = self.directory.path().join("expected-gap-cut.json");
        std::fs::write(
            &expected,
            serde_json::to_vec(&serde_json::json!({
            "account":controller.account, "realm":realm, "cut":cut, "cursor":cursor,
            "stream_key":key, "head":head, "anchor":anchor,
            "stream_heads":after["verified_commit_stream_cursors"],
            "stream_anchors":after["verified_commit_stream_anchors"] }))?,
        )?;
        let output = std::process::Command::new(&self.reader)
            .arg(path)
            .arg(expected)
            .output()?;
        ensure!(
            output.status.success(),
            "fresh-process recovered tail differs: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cotest::transcripts::record_vector_event(
            "sync.stream_tail_incomplete.isolated_resume",
            &serde_json::json!({"stream_ref":stream}),
            &serde_json::json!({"assertions":12,"actual_driver_retry":true}),
            &serde_json::json!({"canonical_case_credit":false,"complete_suite_claim":false,
                "missing_boundary":"signed readable rows at positions zero and two with position one absent"}),
        );
        Ok(())
    }
    async fn circle_gap_recovery(
        &self,
        controller: &Member,
        realm: &arkret_wire::RealmId,
        circle: &arkret_wire::CircleId,
        stream: &arkret_wire::CommitStreamRef,
        path: &std::path::Path,
    ) -> Result<()> {
        use cotest::scenarios::circle_poll_scope_live::{circle_create, circle_event};
        use cotest::scenarios::human_device_producer_live::submit_and_expect_commit;
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path),
            realm.clone(),
        )
        .await?;
        let before = state(&host)?;
        let cut = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            realm,
        )
        .await?;
        let cursor = host.state_store().sync_cursor().context("pre-gap cursor")?;
        let key = serde_json::to_string(stream)?;
        let parent_stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let parent_key = serde_json::to_string(&parent_stream)?;
        let strand = circle_event(&controller.client, realm.as_str(), circle,
            arkret_wire::EventKind::StrandCreate,
            serde_json::json!({"object":{"schema":"ak.schema.strand.v1", "realm_id":realm,
                "scope_circle_id":circle, "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":"Circle gap recovery"}, "state":"active", "created_by":controller.actor}})).await?;
        let commit = submit_and_expect_commit(
            &controller.client,
            &controller.account,
            controller.device.as_str(),
            &strand,
        )
        .await?;
        // This accepted Circle creation advances only its parent Realm stream.
        circle_create(
            &controller.client,
            realm.as_str(),
            &controller.actor,
            "Healthy sibling during gap",
            "Healthy sibling",
        )
        .await?;
        let missing = ObservedRail {
            http: controller.client.sdk(),
            missing: Some(strand.event_id.clone()),
            observed: Default::default(),
        };
        let refused = host.catch_up_with_conformance_transport(&missing).await;
        ensure!(
            matches!(&refused, Err(garth::Error::StreamTailIncomplete { stream_ref })
                if stream_ref == stream),
            "a missing Circle window crossed the Account checkpoint"
        );
        let batches = missing.observed.lock().unwrap();
        ensure!(batches.len() == 4, "Circle gap retries were not bounded");
        let parent_commit = batches
            .iter()
            .flat_map(|batch| &batch.frames)
            .flat_map(|frame| frame.realms.iter())
            .flat_map(|realms| realms.entries.values())
            .flat_map(|entry| entry.committed_events.iter().flatten())
            .map(|row| row.commit())
            .filter(|commit| commit.stream_ref == parent_stream)
            .max_by_key(|commit| commit.stream_position)
            .context("healthy Realm sibling Commit")?
            .clone();
        let mut forged = batches.first().context("gap Account batch")?.clone();
        drop(batches);
        let partial = state(&host)?;
        ensure!(
            parent_commit.stream_position
                > before["verified_commit_stream_cursors"][&parent_key]["stream_position"]
                    .as_u64()
                    .context("old Realm position")?,
            "gap regression had no advancing healthy sibling"
        );
        ensure!(
            partial["verified_commit_stream_anchors"][&parent_key]
                == serde_json::to_value(&parent_commit)?,
            "missing Circle window blocked its healthy Realm sibling: {refused:?}"
        );
        ensure!(
            partial["verified_commit_stream_cursors"][&key]
                == before["verified_commit_stream_cursors"][&key]
                && partial["verified_commit_stream_anchors"][&key]
                    == before["verified_commit_stream_anchors"][&key]
                && host.state_store().sync_cursor().as_deref() == Some(cursor.as_str())
                && inkson::conformance::retained_realm_current(
                    &host.state_store(),
                    &controller.account,
                    realm
                )
                .await?
                    == cut,
            "incomplete Circle changed its head, current cut or Account cursor"
        );
        let mut forged_windows = 0;
        for window in forged
            .frames
            .iter_mut()
            .flat_map(|frame| frame.realms.iter_mut())
            .flat_map(|realms| realms.entries.values_mut())
            .flat_map(|entry| entry.streams.iter_mut().flatten())
            .filter(|window| &window.stream_ref == stream)
        {
            window.head_commit_ref = arkret_wire::RealmCommitId::from_digest([199; 32]);
            forged_windows += 1;
        }
        ensure!(
            forged_windows == 1,
            "fork regression changed more than the missing stream"
        );
        let fork = HeldBatch(Mutex::new(Some(forged)));
        ensure!(
            matches!(
                host.catch_up_with_conformance_transport(&fork).await,
                Err(garth::Error::Protocol(message))
                    if message == "Account window differs from own Station continuous stream"
            ) && state(&host)? == partial,
            "a forked head entered gap recovery or changed the durable state"
        );
        let evidence = self
            .directory
            .path()
            .join("expected-circle-gap-held-cut.json");
        std::fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "account":controller.account, "realm":realm, "cut":cut, "cursor":cursor,
                "stream_key":key, "head":before["verified_commit_stream_cursors"][&key],
                "anchor":before["verified_commit_stream_anchors"][&key],
                "stream_heads":partial["verified_commit_stream_cursors"],
                "stream_anchors":partial["verified_commit_stream_anchors"]
            }))?,
        )?;
        let output = std::process::Command::new(&self.reader)
            .arg(path)
            .arg(&evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "partial stream progress was not durable across a new process: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let repaired = ObservedRail {
            http: controller.client.sdk(),
            missing: None,
            observed: Default::default(),
        };
        host.catch_up_with_conformance_transport(&repaired).await?;
        let after = state(&host)?;
        let recovered_cut = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            realm,
        )
        .await?;
        let recovered_cursor = host
            .state_store()
            .sync_cursor()
            .context("recovered cursor")?;
        ensure!(
            after["verified_commit_stream_anchors"][&key] == serde_json::to_value(&commit)?
                && recovered_cursor != cursor
                && recovered_cut["entries"]
                    .as_array()
                    .context("recovered current rows")?
                    .iter()
                    .any(|row| row["revision"]["commit_id"] == commit.commit_id.as_str()),
            "fresh snapshot and tail did not recover the held Circle cut"
        );
        drop(host);
        std::fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "account":controller.account, "realm":realm, "cut":recovered_cut, "cursor":recovered_cursor,
                "stream_key":key, "head":after["verified_commit_stream_cursors"][&key],
                "anchor":after["verified_commit_stream_anchors"][&key],
                "stream_heads":after["verified_commit_stream_cursors"],
                "stream_anchors":after["verified_commit_stream_anchors"]
            }))?,
        )?;
        let output = std::process::Command::new(&self.reader)
            .arg(path)
            .arg(&evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "recovered Circle cut failed new-process readback: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // A malformed window regression is not the canonical position-row jump.
        // Keep the existing sixteen-case claim until that distinct input is run.
        println!(
            "CIRCLE_GAP_RECOVERY: healthy history durable; incomplete cut held; repaired cut durable"
        );
        Ok(())
    }
}

/// Execute checkpoint and reconnect production evidence without claiming
/// absent cases or a complete private-response/Agent-runtime lifecycle.
pub async fn run_sync_production_cases(
    reader: &std::path::Path,
) -> Result<Vec<super::CaseExecutionResult>> {
    super::run_sync_fixture_suite()?;
    let fixture = cotest::conformance::load_fixture_value("client-sync-fixture.json")?;
    let gap_cases = fixture["stream_tails"]
        .as_array()
        .context("gap fixture")?
        .iter()
        .filter(|case| case["name"] == STREAM_GAP_CASE)
        .collect::<Vec<_>>();
    ensure!(
        gap_cases.len() == 1
            && gap_cases[0]["expected"] == "rejected"
            && gap_cases[0]["expected_client_action"] == "stop_this_stream_and_refetch_snapshot"
            && gap_cases[0]["other_streams_reset"] == false
            && gap_cases[0]["to_device_acks_reset"] == false
            && gap_cases[0]["commits"][0]["stream_position"] == 0
            && gap_cases[0]["commits"][1]["stream_position"] == 2,
        "canonical unexplained stream gap or recovery expectations drifted"
    );
    let circle_cases = fixture["stream_tails"]
        .as_array()
        .context("Circle tail fixture")?
        .iter()
        .filter(|case| case["name"] == CIRCLE_TAIL_CASE)
        .collect::<Vec<_>>();
    ensure!(
        circle_cases.len() == 1
            && circle_cases[0]["expected"] == "accepted"
            && circle_cases[0]["stream_ref"]["kind"] == "circle",
        "Circle independent-tail fixture identity or verdict drifted"
    );
    let commits = circle_cases[0]["commits"]
        .as_array()
        .context("Circle fixture commits")?;
    ensure!(
        commits.len() == 2
            && commits[0]["stream_position"] == 0
            && commits[0]["previous_commit_ref"].is_null()
            && commits[1]["stream_position"] == 1
            && commits[1]["previous_commit_ref"] == commits[0]["commit_id"],
        "Circle fixture no longer declares the independent continuous zero/one tail"
    );
    let ordering = fixture["checkpoint_ordering"]
        .as_array()
        .context("ordering cases")?
        .iter()
        .find(|case| case["name"] == BASELINE_CASE)
        .context("ordering fixture")?;
    ensure!(
        ordering["expected"] == "accepted"
            && ordering["steps"][0]["action"] == "deliver_incremental"
            && ordering["steps"][1]["action"] == "deliver_baseline_section_complete"
            && ordering["steps"][0]["stream_position"].as_u64()
                > ordering["steps"][1]["as_of_stream_position"].as_u64(),
        "baseline ordering fixture drifted"
    );
    let fixture = super::load_fixture_value("client-sync-fixture.json")?;
    let cases = fixture["checkpoint_ordering"]
        .as_array()
        .context("checkpoint cases")?;
    for name in CASES {
        ensure!(
            cases.iter().filter(|case| case["name"] == name).count() == 1,
            "fixture lost or duplicated {name}"
        );
        let case = cases.iter().find(|case| case["name"] == name).unwrap();
        let steps = case["steps"].as_array().context("checkpoint steps")?;
        let delivered = steps
            .iter()
            .find(|step| step["action"] == "deliver_incremental")
            .context("checkpoint case delivers no incremental")?;
        let stream: arkret_wire::CommitStreamRef =
            serde_json::from_value(delivered["stream_ref"].clone())?;
        let positive = name == CASES[0];
        let missing = name == CASES[1];
        ensure!(
            matches!(stream, arkret_wire::CommitStreamRef::Sidecar { .. })
                && delivered["stream_position"] == if missing { 2 } else { 1 },
            "{name}: production candidate no longer instantiates the declared stream position"
        );
        let install = steps
            .iter()
            .find(|step| step["action"] == "install_typed_current_result")
            .context("checkpoint case has no install")?;
        ensure!(
            install["durable"] == positive
                && case["expected"] == if positive { "accepted" } else { "rejected" }
                && steps
                    .iter()
                    .any(|step| step["action"] == "advance_durable_cursor")
                    == positive,
            "{name}: fixture durability or checkpoint expectation drifted"
        );
    }
    for (index, name) in RECOVERY_CASES.into_iter().enumerate() {
        let cases = fixture["reconnect"].as_array().context("reconnect cases")?;
        ensure!(
            cases.iter().filter(|case| case["name"] == name).count() == 1,
            "fixture lost or duplicated {name}"
        );
        let case = cases.iter().find(|case| case["name"] == name).unwrap();
        ensure!(
            case["expected"] == if index == 0 { "resume" } else { "reset" }
                && case["baseline_redone"] == (index != 0)
                && case["server_outcome"]
                    == ["accepted", "cursor_expired", "cursor_integrity_invalid"][index],
            "{name}: reconnect expectations drifted from production execution"
        );
        if index != 0 {
            ensure!(
                case["discard_old_cursor"] == true,
                "{name}: refused cursor must be discarded"
            );
        }
        if index <= 1 {
            ensure!(
                case["delivery_acks_invalidated"] == false,
                "{name}: recovery must preserve delivery ACKs"
            );
        }
        if index == 1 {
            ensure!(
                case["local_verified_commits_deleted"] == false
                    && case["mls_private_state_deleted"] == false,
                "{name}: recovery must preserve verified commits and private MLS state"
            );
        }
        if index == 2 {
            ensure!(
                case["server_state_advanced"] == false,
                "{name}: a refused cursor must have zero server advancement"
            );
        }
    }
    let tail = fixture["stream_tails"]
        .as_array()
        .context("stream-tail cases")?
        .iter()
        .filter(|case| case["name"] == STREAM_AND_DELIVERY_CASES[0])
        .collect::<Vec<_>>();
    ensure!(
        tail.len() == 1
            && tail[0]["stream_ref"]["kind"] == "sidecar"
            && tail[0]["expected"] == "accepted"
            && tail[0]["commits"]
                .as_array()
                .is_some_and(|commits| commits.len() == 1
                    && commits[0]["stream_position"] == 0
                    && commits[0]["previous_commit_ref"].is_null()),
        "independent Sidecar tail case drifted from its actual authenticated context unit"
    );
    let realm_tail = fixture["stream_tails"]
        .as_array()
        .context("Realm tail fixtures")?
        .iter()
        .find(|case| case["name"] == STREAM_AND_DELIVERY_CASES[2])
        .context("Realm continuous tail fixture")?;
    let commits = realm_tail["commits"]
        .as_array()
        .context("Realm fixture prefix")?;
    ensure!(
        realm_tail["stream_ref"]["kind"] == "realm"
            && realm_tail["expected"] == "accepted"
            && commits.len() >= 2
            && commits[0]["stream_position"] == 0
            && commits[0]["previous_commit_ref"].is_null()
            && commits.windows(2).all(|pair| pair[0]["stream_position"]
                .as_u64()
                .and_then(|position| position.checked_add(1))
                == pair[1]["stream_position"].as_u64()
                && pair[1]["previous_commit_ref"] == pair[0]["commit_id"]),
        "Realm continuous tail fixture drifted"
    );
    let delivery = fixture["delivery_cancellation"]
        .as_array()
        .context("delivery cases")?
        .iter()
        .filter(|case| case["name"] == STREAM_AND_DELIVERY_CASES[1])
        .collect::<Vec<_>>();
    ensure!(
        delivery.len() == 1
            && delivery[0]["action"] == "advance_account_cursor"
            && delivery[0]["durably_processed"] == false
            && delivery[0]["expected"] == "still_queued",
        "Account checkpoint cannot acknowledge an unprocessed delivery"
    );
    for (index, name) in ACK_CASES.into_iter().enumerate() {
        let cases = fixture["delivery_cancellation"]
            .as_array()
            .context("ACK cases")?;
        let matches = cases
            .iter()
            .filter(|case| case["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1
                && matches[0]["durably_processed"] == true
                && matches[0]["action"] == ["ack", "ack_with_token_after_cursor_expired"][index]
                && matches[0]["expected"] == "removed_from_recipient_queue",
            "{name}: durable explicit ACK expectations drifted"
        );
    }
    for (index, name) in QUEUE_CASES.into_iter().enumerate() {
        let cases = fixture["delivery_cancellation"]
            .as_array()
            .context("queue cases")?;
        let matches = cases
            .iter()
            .filter(|case| case["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1
                && matches[0]["durably_processed"] == (index == 0)
                && matches[0]["action"]
                    == [
                        "ack_from_backfill_path",
                        "advance_time_past_content_expiry_without_ack",
                        "enqueue_new_delivery_at_full_capacity"
                    ][index]
                && matches[0]["expected"]
                    == [
                        "removed_from_recipient_queue",
                        "still_queued",
                        "rejected_quota_exceeded_with_old_delivery_still_queued"
                    ][index],
            "{name}: queue expectations drifted"
        );
        if index == 0 {
            ensure!(
                matches[0]["second_copy_created"] == false,
                "backfill cannot create a second queue"
            );
        }
        if index == 2 {
            ensure!(
                matches[0]["request_idempotency_written"] == false,
                "quota refusal cannot consume idempotency"
            );
        }
    }
    let probe = Probe {
        scan_relay: Default::default(),
        directory: tempfile::tempdir()?,
        reader: reader.to_owned(),
        host: Default::default(),
        before: Default::default(),
        results: Default::default(),
    };
    cotest::scenarios::sidecar_authority_live::run_with_sync_observer(&probe).await?;
    let mut results = probe.results.into_inner();
    results.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    let expected = CASES
        .into_iter()
        .chain(RECOVERY_CASES)
        .chain(STREAM_AND_DELIVERY_CASES)
        .chain(ACK_CASES)
        .chain(QUEUE_CASES)
        .chain(std::iter::once(BASELINE_CASE))
        .chain(std::iter::once(CIRCLE_TAIL_CASE))
        .chain(std::iter::once(STREAM_GAP_CASE))
        .chain(ORDERING_CASES)
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        results.len() == PRODUCTION_CASE_COUNT
            && results
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                == expected,
        "production checkpoint subset was not fully executed"
    );
    for case in &results {
        cotest::transcripts::record_vector_event(
            "sync.client_account_stream.production_subset",
            &serde_json::json!({"fixture":"client-sync-fixture.json", "case_id":case.case_id}),
            &serde_json::json!({"assertions":case.assertions, "production_sync_boundary":true}),
            &serde_json::json!({"executor":if CASES.contains(&case.case_id.as_str()) {
                "AccountSubscription + InksonAccountProjector + native shard + fresh-process readback"
            } else if ACK_CASES.contains(&case.case_id.as_str()) {
                "Station/PG recipient queue + Inkson durable journal + exact disk readback + explicit SDK ACK"
            } else if QUEUE_CASES.contains(&case.case_id.as_str()) {
                "Station/PG Account delivery + paginated shared queue + real content expiry + quota rejection + durable SDK ACK"
            } else if case.case_id == STREAM_AND_DELIVERY_CASES[2] {
                "Station/PG original Realm prefix + actual Account driver + exact verified stream checkpoint and signed anchor + fresh-process readback"
            } else if case.case_id == BASELINE_CASE {
                "Station/PG Realm join + held baseline completion + durable current merge + fresh-process readback"
            } else { "AccountSubscription + InksonAccountProjector + Station/PG + private MLS checkpoint + unacknowledged queue" }, "complete_suite_claim":false}),
        );
    }
    Ok(results)
}
