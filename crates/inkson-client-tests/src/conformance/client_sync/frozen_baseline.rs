//! Frozen Account pages from the real Station, projected by the native client.
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeReadAction, RealmListParameters,
};
use arkret_models_collaboration::sync_frames::demand_sync::RealmListPage;
use cotest::harness::{TestActorClient, TestServerGroup};
use cotest::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use cotest::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, station_env, submit_and_expect_commit,
};
use cotest::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use cotest::scenarios::mls_lifecycle_live::Member;
use garth::{AccountSubscribeBatch, AccountSubscribeParameters, AccountSubscribeTransport};
use inkson::sync_engine::NativeAccountHost;
use serde_json::{Value, json};

use super::super::account_blocklist_projection::{
    NativeAccountSessionCapsule, native_account_session_capsule,
};

mod process;
use process::OwnedClient;

const CHILD_ENV: &str = "COTEST_FROZEN_CURRENT_CHILD";
const MARKER: &str = "[current-frozen-client] ";
const MAX_PAGES: usize = 32;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    session: NativeAccountSessionCapsule,
    state_path: PathBuf,
    expected_checkpoint: Option<Value>,
}

fn checkpoint(store: &inkson::LocalStateStore) -> Result<Value> {
    let state = serde_json::to_value(store.load())?;
    let demand = &state["demand_sync"];
    Ok(json!({
        "cursor":state["sync_cursor"],
        "current_generation":state["current_generation"],
        "list_snapshot":demand["list_snapshot"],
        "list_revision":demand["list_revision"],
        "list_after":demand["list_after"],
        "list_complete":demand["list_complete"],
        "list_seen":demand["list_seen"],
        "summaries":demand["summaries"],
        "verified_heads":state["verified_commit_stream_cursors"],
        "verified_anchors":state["verified_commit_stream_anchors"]
    }))
}

fn cold_checkpoint(path: &Path) -> Result<Value> {
    checkpoint(&inkson::LocalStateStore::with_path(path))
}

fn emit(kind: &str, data: Value) -> Result<()> {
    println!(
        "{MARKER}{}",
        json!({"kind":kind,"pid":std::process::id(),"data":data})
    );
    std::io::stdout().flush()?;
    Ok(())
}

fn input<T: serde::de::DeserializeOwned>(reader: &mut impl std::io::BufRead) -> Result<T> {
    let mut line = zeroize::Zeroizing::new(String::new());
    ensure!(
        reader.read_line(&mut line)? > 0,
        "owned parent closed native client input"
    );
    Ok(serde_json::from_str(&line)?)
}

struct RealPages {
    http: arkret_http_client::Client,
    state_path: PathBuf,
    tail: AtomicBool,
    observed: Mutex<Vec<(AccountSubscribeParameters, AccountSubscribeBatch)>>,
}

impl AccountSubscribeTransport for RealPages {
    async fn subscribe(
        &self,
        request: &AccountSubscribeParameters,
    ) -> garth::Result<AccountSubscribeReadAction> {
        let saved = cold_checkpoint(&self.state_path)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if let Some(cursor) = saved["cursor"].as_str() {
            if request.after.as_deref() != Some(cursor) {
                return Err(garth::Error::Protocol(
                    "native driver did not resume its durable Account cursor".into(),
                ));
            }
        }
        let mut request = request.clone();
        if !self.tail.load(Ordering::Acquire) {
            request.realm_list_parameters = Some(RealmListParameters {
                after: saved["list_after"]
                    .as_str()
                    .map(|value| {
                        value
                            .parse::<arkret_wire::Cursor>()
                            .map_err(|error| garth::Error::Protocol(format!("{error}")))
                    })
                    .transpose()?,
                limit: Some(1),
            });
        }
        // This seam controls only a registered request and its timing. The
        // real server's complete response reaches the normal projector unchanged.
        let batch = self.http.account_subscribe_batch(&request).await?;
        self.observed.lock().unwrap().push((request, batch.clone()));
        Ok(AccountSubscribeReadAction::Batch(batch))
    }
}

fn summaries_match(saved: &Value, expected: &BTreeMap<String, Value>) -> bool {
    expected.iter().all(|(realm, row)| {
        let actual = &saved["summaries"][realm];
        actual["revision"] == row["revision"]
            && actual["title"] == row["title"]
            && actual["default_strand_id"] == row["default_strand_id"]
    })
}

async fn child() -> Result<()> {
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let launch: Launch = tokio::task::block_in_place(|| input(&mut reader))?;
    ensure!(
        launch.state_path.is_absolute(),
        "native client state path must be absolute"
    );
    let session = launch.session.restore().await?;
    let cold = cold_checkpoint(&launch.state_path)?;
    if let Some(expected) = &launch.expected_checkpoint {
        ensure!(
            &cold == expected,
            "fresh process lost part of the atomic page/checkpoint tuple"
        );
        ensure!(
            cold["cursor"].is_string()
                && cold["list_after"].is_string()
                && cold["list_complete"] == false,
            "kill boundary was not a durable incomplete baseline"
        );
    }
    let host = NativeAccountHost::new(
        session.client(),
        launch.session.outcome.account_id.clone(),
        launch
            .session
            .outcome
            .device_id
            .clone()
            .context("native client Device absent")?,
        inkson::LocalStateStore::with_path(&launch.state_path),
    )
    .await?;
    let rail = RealPages {
        http: session.client(),
        state_path: launch.state_path.clone(),
        tail: AtomicBool::new(false),
        observed: Mutex::new(Vec::new()),
    };
    ensure!(
        checkpoint(&host.state_store())? == cold,
        "opening the native host changed the retained checkpoint"
    );
    emit("opened", cold)?;
    let mut frozen: Option<(String, u64)> = launch
        .expected_checkpoint
        .as_ref()
        .map(|saved| -> Result<(String, u64)> {
            Ok((
                saved["list_snapshot"]
                    .as_str()
                    .context("restored cut absent")?
                    .to_owned(),
                saved["list_revision"]
                    .as_u64()
                    .context("restored revision absent")?,
            ))
        })
        .transpose()?;
    let mut terminal = false;
    for _ in 0..MAX_PAGES {
        let before = cold_checkpoint(&launch.state_path)?;
        host.catch_up_with_conformance_transport(&rail).await?;
        let observed = std::mem::take(&mut *rail.observed.lock().unwrap());
        let pages = observed
            .iter()
            .flat_map(|(_, batch)| {
                batch
                    .frames
                    .iter()
                    .filter_map(|frame| frame.realm_list.clone())
            })
            .collect::<Vec<_>>();
        if pages.is_empty() {
            continue;
        }
        ensure!(
            pages.len() == 1,
            "one actual page request changed its cardinality"
        );
        let page = &pages[0];
        page.validate()?;
        let identity = (page.snapshot_cursor.clone(), page.snapshot_revision);
        if let Some(expected) = &frozen {
            ensure!(
                &identity == expected,
                "live writes restarted or mixed the frozen list cut"
            );
        } else {
            frozen = Some(identity);
        }
        ensure!(
            page.items
                .iter()
                .all(|row| row.revision <= page.snapshot_revision),
            "frozen page leaked a later row"
        );
        let saved = cold_checkpoint(&launch.state_path)?;
        ensure!(
            saved == checkpoint(&host.state_store())?,
            "page and checkpoint were not committed as one durable tuple"
        );
        ensure!(
            saved["list_snapshot"] == page.snapshot_cursor
                && saved["list_revision"] == page.snapshot_revision
                && saved["list_after"] == json!(page.next_cursor)
                && saved["list_complete"] == page.is_terminal(),
            "durable page progress differs from the actual server page"
        );
        let requests = observed
            .iter()
            .map(|(request, _)| serde_json::to_value(request))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let changes = observed
            .iter()
            .flat_map(|(_, batch)| {
                batch
                    .frames
                    .iter()
                    .filter_map(|frame| frame.realm_list_changes.clone())
            })
            .collect::<Vec<_>>();
        let mut older_page_met_newer = Vec::new();
        for row in &page.items {
            let id = row.realm_id.as_str();
            if let Some(prior_revision) = before["summaries"][id]["revision"]
                .as_u64()
                .filter(|prior| *prior > row.revision)
            {
                ensure!(
                    saved["summaries"][id]["revision"]
                        .as_u64()
                        .is_some_and(|revision| revision >= prior_revision),
                    "an older frozen page overwrote an already durable newer delta"
                );
                older_page_met_newer.push(row.realm_id.clone());
            }
        }
        terminal = page.is_terminal();
        emit(
            "page",
            json!({"page":page,"checkpoint":saved,"requests":requests,"changes":changes,"older_page_met_newer":older_page_met_newer}),
        )?;
        let command: Value = tokio::task::block_in_place(|| input(&mut reader))?;
        if terminal {
            ensure!(
                command["kind"] == "tail",
                "terminal baseline requires the real tail target"
            );
            let expected: BTreeMap<String, Value> =
                serde_json::from_value(command["expected"].clone())?;
            ensure!(!expected.is_empty(), "tail target is empty");
            rail.tail.store(true, Ordering::Release);
            for _ in 0..MAX_PAGES {
                let saved = cold_checkpoint(&launch.state_path)?;
                if summaries_match(&saved, &expected) {
                    ensure!(
                        saved["list_snapshot"] == page.snapshot_cursor
                            && saved["list_complete"] == true,
                        "tail replaced the completed frozen baseline"
                    );
                    emit("done", saved)?;
                    return Ok(());
                }
                host.catch_up_with_conformance_transport(&rail).await?;
            }
            anyhow::bail!("native current tail did not reach the final actual server summaries");
        }
        ensure!(
            command["kind"] == "continue",
            "incomplete baseline requires its continuation"
        );
    }
    ensure!(
        terminal,
        "actual frozen baseline exceeded its bounded page count"
    );
    anyhow::bail!("native client stopped before its durable tail proof")
}

async fn full_page(client: &TestActorClient, snapshot: Option<&str>) -> Result<RealmListPage> {
    let batch = client
        .sdk()
        .account_subscribe_batch(&AccountSubscribeParameters {
            after: None,
            catchup: Some(true),
            filter: None,
            realm_list_parameters: Some(RealmListParameters {
                after: snapshot.map(str::parse).transpose()?,
                limit: Some(100),
            }),
            replace_filter: None,
        })
        .await?;
    let pages = batch
        .frames
        .iter()
        .filter_map(|frame| frame.realm_list.clone())
        .collect::<Vec<_>>();
    ensure!(
        pages.len() == 1 && pages[0].is_terminal(),
        "fixture no longer fits one independent complete reference read"
    );
    Ok(pages.into_iter().next().unwrap())
}

async fn wait_writes(counter: &Cell<usize>, minimum: usize) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        while counter.get() < minimum {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("real busy writer did not commit between successive pages")?;
    Ok(())
}

/// Two real test entries share the same existing native driver and HTTP rail.
/// Only the second entry kills the original client between durable pages.
pub async fn run_frozen_current_baseline(test_name: &str, kill_client: bool) -> Result<()> {
    if let Some(selected) = std::env::var_os(CHILD_ENV) {
        ensure!(
            selected.to_str() == Some(test_name),
            "native child selected another test entry"
        );
        return cotest::harness::heap_future(child).await;
    }
    cotest::harness::heap_future(|| parent(test_name, kill_client)).await
}

async fn parent(test_name: &str, kill_client: bool) -> Result<()> {
    let label = if kill_client {
        "current-page-kill"
    } else {
        "current-page-busy"
    };
    let db = database(label)?.context("actual PostgreSQL is required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        label,
        &[station_env(&db.connect_url, &issuer)],
    )
    .await?
    .context("actual owned Station process is required")?;
    let station = group.server(0);
    let member = Member::provision(
        station,
        &issuer,
        label,
        "ak:device:01904100-0000-7000-8000-000000003351",
    )
    .await?;
    let mut realms = Vec::new();
    for index in 0..3 {
        let realm = create_realm_with_join_rule(
            &member.client,
            &format!("Frozen current {index}"),
            "public",
            &[station],
        )
        .await?;
        realms.push(realm);
    }
    let directory = tempfile::tempdir()?;
    let state_path = directory.path().join("native-state.json");
    let capsule = native_account_session_capsule(&member.client).await?;
    let source_ref = capsule.outcome.grant_ref();
    let source_binding = json!({"grant_ref":source_ref,"account_id":capsule.outcome.account_id,"device_id":capsule.outcome.device_id,"audience_id":capsule.outcome.audience_id});
    let mut client = OwnedClient::spawn(
        test_name,
        Launch {
            session: capsule,
            state_path: state_path.clone(),
            expected_checkpoint: None,
        },
    )?;
    let opened = client.event().await?;
    ensure!(
        opened["kind"] == "opened",
        "native child did not open its actual store"
    );
    let first = client.event().await?;
    ensure!(
        first["kind"] == "page",
        "native child did not deliver its first actual page"
    );
    let original: RealmListPage = serde_json::from_value(first["data"]["page"].clone())?;
    ensure!(
        original.next_cursor.is_some(),
        "the actual baseline was not multipage"
    );
    let first_checkpoint = first["data"]["checkpoint"].clone();
    let original_identity = client.identity()?;
    let mut pages = vec![original.clone()];
    let mut observations = vec![first["data"].clone()];
    let counter = Cell::new(0usize);
    let stop = Cell::new(false);
    let writer_done = Cell::new(false);
    let accepted = RefCell::new(Vec::new());
    let writer = async {
        let result = async {
            while !stop.get() {
                let realm = &realms[counter.get() % realms.len()];
                let event = member
                    .client
                    .author_event(
                        realm,
                        "ak.realm.profile",
                        arkret_models_collaboration::events_payloads::realm::RealmProfile::new(
                            format!("continuous current pressure {}", counter.get()),
                        )?
                        .to_value()?,
                    )
                    .await?;
                let commit = submit_and_expect_commit(
                    &member.client,
                    &member.account,
                    member.device.as_str(),
                    &event,
                )
                .await?;
                accepted.borrow_mut().push(commit);
                counter.set(counter.get() + 1);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        writer_done.set(true);
        result
    };
    let observer = async {
        wait_writes(&counter, 3).await?;
        let mut kill_evidence = Value::Null;
        if kill_client {
            kill_evidence = client.kill_and_wait()?;
            drop(client);
            let before = counter.get();
            wait_writes(&counter, before + 1).await?;
            let capsule = native_account_session_capsule(&member.client).await?;
            ensure!(
                capsule.outcome.grant_ref() == source_ref,
                "client restart replaced the captured issuer-scoped credential identity"
            );
            client = OwnedClient::spawn(
                test_name,
                Launch {
                    session: capsule,
                    state_path: state_path.clone(),
                    expected_checkpoint: Some(first_checkpoint.clone()),
                },
            )?;
            let reopened = client.event().await?;
            ensure!(
                reopened["kind"] == "opened" && reopened["data"] == first_checkpoint,
                "fresh native client did not reopen the exact atomic incomplete cut"
            );
            let next = client.identity()?;
            ensure!(
                next["pid"] != original_identity["pid"],
                "client kill did not create a new OS process"
            );
            kill_evidence["reopened"] = next;
            kill_evidence["checkpoint_readback"] = reopened["data"].clone();
        } else {
            client.command(&json!({"kind":"continue"}))?;
        }
        let mut per_page_writes = vec![counter.get()];
        let mut newer_overlays = 0usize;
        for _ in 1..MAX_PAGES {
            let event = client.event().await?;
            ensure!(
                event["kind"] == "page",
                "native client did not finish its next real page"
            );
            let page: RealmListPage = serde_json::from_value(event["data"]["page"].clone())?;
            observations.push(event["data"].clone());
            newer_overlays += event["data"]["older_page_met_newer"]
                .as_array()
                .context("older-page observation absent")?
                .len();
            ensure!(
                page.snapshot_cursor == original.snapshot_cursor
                    && page.snapshot_revision == original.snapshot_revision,
                "continued page changed the original frozen cut"
            );
            pages.push(page.clone());
            let before = counter.get();
            wait_writes(&counter, before + 1).await?;
            per_page_writes.push(counter.get());
            if page.is_terminal() {
                stop.set(true);
                tokio::time::timeout(Duration::from_secs(60), async {
                    while !writer_done.get() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .context("busy writer failed to stop after the terminal baseline page")?;
                let reference = full_page(&member.client, Some(&original.snapshot_cursor)).await?;
                ensure!(
                    reference.snapshot_cursor == original.snapshot_cursor
                        && reference.snapshot_revision == original.snapshot_revision,
                    "same frozen query did not retain its original cut"
                );
                let actual = pages
                    .iter()
                    .flat_map(|page| page.items.clone())
                    .collect::<Vec<_>>();
                ensure!(
                    actual == reference.items,
                    "frozen pages skipped, duplicated or replaced a current row under busy writes"
                );
                ensure!(
                    pages.len() >= 3,
                    "fixture did not exercise at least three actual pages"
                );
                ensure!(
                    newer_overlays > 0,
                    "no older baseline page actually met an already durable newer delta"
                );
                let final_page = full_page(&member.client, None).await?;
                ensure!(
                    final_page.snapshot_revision > original.snapshot_revision,
                    "busy writes did not advance the real current source"
                );
                let expected = final_page
                    .items
                    .iter()
                    .map(|row| Ok((row.realm_id.to_string(), serde_json::to_value(row)?)))
                    .collect::<Result<BTreeMap<_, _>>>()?;
                client.command(&json!({"kind":"tail","expected":expected}))?;
                let done = client.event().await?;
                ensure!(
                    done["kind"] == "done" && summaries_match(&done["data"], &expected),
                    "native tail did not preserve and reach the final exact current rows"
                );
                client.finish()?;
                let evidence = json!({"case":label,"source":"real owned Station + PostgreSQL; unmodified HTTP frames + native Garth driver/Inkson atomic projector", "source_binding":source_binding,"boundary":"first page and its Account cursor/list continuation are durable; kill case stops before requesting the second page", "original_client":original_identity,"kill":kill_evidence,"first_checkpoint":first_checkpoint,"frozen_snapshot_cursor":original.snapshot_cursor,"frozen_revision":original.snapshot_revision,"pages":pages,"page_observations":observations,"accepted_commit_counts_at_page_gates":per_page_writes,"accepted_commits":&*accepted.borrow(),"older_pages_preserved_newer_delta_count":newer_overlays,"final_checkpoint":done["data"]});
                eprintln!(
                    "[current-frozen-native] {}",
                    serde_json::to_string(&evidence)?
                );
                if let Some(logs) = std::env::var_os("COTEST_SERVICE_LOG_DIR") {
                    let path = PathBuf::from(logs).join(format!("{label}-evidence.json"));
                    std::fs::write(path, serde_json::to_vec_pretty(&evidence)?)?;
                }
                return Ok::<(), anyhow::Error>(());
            }
            client.command(&json!({"kind":"continue"}))?;
        }
        anyhow::bail!("real frozen baseline failed to terminate")
    };
    let (write_result, observe_result) = futures_util::future::join(writer, async {
        let result = observer.await;
        stop.set(true);
        result
    })
    .await;
    write_result?;
    observe_result?;
    Ok(())
}
