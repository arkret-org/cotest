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
const STREAM_AND_DELIVERY_CASES: [&str; 2] = [
    "sidecar_stream_tail_is_independent",
    "cursor_advance_alone_does_not_cancel_a_delivery",
];
pub const PRODUCTION_CASE_COUNT: usize =
    CASES.len() + RECOVERY_CASES.len() + STREAM_AND_DELIVERY_CASES.len();

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
    async fn reconnect_cases(
        &self,
        controller: &Member,
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
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl SidecarSyncObserver for Probe {
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
            refused.is_err(),
            "an incomplete Sidecar frame advanced the driver"
        );
        ensure!(
            missing.observed.lock().unwrap().len() == 1,
            "missing-tail case did not reach the subscription driver"
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
        self.reconnect_cases(controller, genesis, creator_group, database_url)
            .await?;
        Ok(())
    }
}

/// Execute checkpoint and reconnect production evidence without claiming
/// absent cases or a complete private-response/Agent-runtime lifecycle.
pub async fn run_sync_production_cases(
    reader: &std::path::Path,
) -> Result<Vec<super::CaseExecutionResult>> {
    super::run_sync_fixture_suite()?;
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
    let probe = Probe {
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
            } else { "AccountSubscription + InksonAccountProjector + Station/PG + private MLS checkpoint + unacknowledged queue" }, "complete_suite_claim":false}),
        );
    }
    Ok(results)
}
