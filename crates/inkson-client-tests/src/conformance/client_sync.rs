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
            let cases = runtime.block_on(run_sidecar_checkpoint_production_cases(&reader))?;
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
        let (_, history) = inkson::conformance::retained_sidecar_cut(&host.state_store(), scope)?;
        ensure!(
            history.len() == 1 && history[0].commit.stream_position == 0,
            "the prior cut must contain exactly the accepted Sidecar context unit"
        );
        ensure!(
            host.state_store().sync_cursor().is_some(),
            "baseline has no durable Account checkpoint"
        );
        *self.before.borrow_mut() = Some(state(&host)?);
        *self.host.borrow_mut() = Some(host);
        Ok(())
    }

    async fn after_genesis(&self, controller: &Member, genesis: &Event) -> Result<()> {
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
        Ok(())
    }
}

/// Execute the new checkpoint subset, without claiming the other fixture
/// sections or a complete private-response/Agent-runtime lifecycle.
pub async fn run_sidecar_checkpoint_production_cases(
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
    let expected = CASES.into_iter().collect::<std::collections::BTreeSet<_>>();
    ensure!(
        results.len() == 3
            && results
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                == expected,
        "production checkpoint subset was not fully executed"
    );
    for case in &results {
        cotest::transcripts::record_vector_event(
            "sync.client_account_stream.checkpoint_production_subset",
            &serde_json::json!({"fixture":"client-sync-fixture.json", "case_id":case.case_id}),
            &serde_json::json!({"assertions":case.assertions, "production_checkpoint_boundary":true}),
            &serde_json::json!({"executor":"AccountSubscription + InksonAccountProjector + native shard + fresh-process readback", "complete_suite_claim":false}),
        );
    }
    Ok(results)
}
