//! Recover an older PostgreSQL backup while retaining immutable issuance records.

use cotest::harness::{ArkretServer, TestServerGroup};
use cotest::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, membership_payload, prepare_join, submit_and_expect_commit,
    wait_for_committed,
};

use super::*;

const ISSUANCE_TABLES: [&str; 5] = [
    "realm_state_snapshots",
    "realm_state_snapshot_issuances",
    "realm_state_snapshot_window_reservations",
    "sync_cursor_handles",
    "device_message_ack_tokens",
];
const EFFECTS: &str = "SELECT jsonb_build_object(\
 'commits',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY commit_id),'[]') FROM realm_commits t),\
 'authority',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY realm_id),'[]') FROM realm_authorities t),\
 'anchors',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY stream_key),'[]') FROM replica_stream_anchors t),\
 'cuts',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY realm_id,source_stream_ref),'[]') FROM replica_authorization_cuts t),\
 'current',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY realm_id,selector),'[]') FROM replica_authorization_rows t),\
 'events',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY pk),'[]') FROM canonical_events t),\
 'cursors',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM sync_cursor_handles t),\
 'snapshots',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY snapshot_id),'[]') FROM realm_state_snapshots t),\
 'issuances',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY snapshot_id,account_id),'[]') FROM realm_state_snapshot_issuances t),\
 'windows',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY window_cursor,account_id,stream_key),'[]') FROM realm_state_snapshot_window_reservations t),\
 'queue',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM device_messages t),\
 'acks',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY acknowledgement_token),'[]') FROM device_message_ack_tokens t)\
 )::text";

fn business_evidence(database_url: &str) -> Result<String> {
    tokio::task::block_in_place(|| {
        let mut database = postgres::Client::connect(database_url, postgres::NoTls)?;
        let mut transaction = database
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let core: String = transaction.query_one(EFFECTS, &[])?.get(0);
        let tables = transaction.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%\\_current_states' ESCAPE '\\' OR tablename IN ('current_state_heads','current_selector_origins','governance_current_ready','account_datas','account_data_changes','device_message_txns','device_message_idempotency','mls_welcome_deliveries')) ORDER BY tablename", &[])?;
        let mut currents = std::collections::BTreeMap::new();
        for row in tables {
            let table: String = row.get(0);
            ensure!(
                table
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "invalid registered business table"
            );
            let sql = format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]')::text FROM public.\"{table}\" t"
            );
            let rows: String = transaction.query_one(&sql, &[])?.get(0);
            currents.insert(table, rows);
        }
        transaction.commit()?;
        Ok(serde_json::to_string(&(core, currents))?)
    })
}

fn postgres_tool(
    tool: &str,
    database_url: &str,
    args: &[&str],
    file: &std::path::Path,
) -> Result<()> {
    tokio::task::block_in_place(|| {
        let config: postgres::Config = database_url.parse()?;
        ensure!(
            config
                .get_dbname()
                .is_some_and(|name| name.starts_with("cotest_")),
            "backup recovery requires an owned isolated Cotest database"
        );
        let output = std::process::Command::new(tool)
            .args(args)
            .arg("--dbname")
            .arg(database_url)
            .arg("--file")
            .arg(file)
            .output()?;
        ensure!(
            output.status.success(),
            "{tool} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    })
}

fn restore_backup(
    database_url: &str,
    backup: &std::path::Path,
    ledger: &std::path::Path,
) -> Result<()> {
    tokio::task::block_in_place(|| {
        let output = std::process::Command::new("pg_restore")
            .args([
                "--exit-on-error",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--dbname",
            ])
            .arg(database_url)
            .arg(backup)
            .output()?;
        ensure!(
            output.status.success(),
            "restore accepted-history backup: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new("psql")
            .args(["--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--dbname"])
            .arg(database_url)
            .arg("--file")
            .arg(ledger)
            .output()?;
        ensure!(
            output.status.success(),
            "restore immutable issuance ledger: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    })
}

pub(super) fn private_state(state: &Value) -> Value {
    serde_json::json!({
        "verified_sidecar_history":state["verified_sidecar_history"],
        "mls_snapshots":state["mls_snapshots"],
    })
}

struct RecoveryRail<'a> {
    http: arkret_http_client::Client,
    path: std::path::PathBuf,
    database_url: String,
    before: Value,
    effects: String,
    source: &'a ArkretServer,
    receiver: &'a ArkretServer,
    governor: &'a Member,
    member: &'a Member,
    realm: arkret_wire::RealmId,
    replay: Vec<u8>,
    requests: Mutex<Vec<AccountSubscribeParameters>>,
    recovered: Mutex<Option<arkret_wire::RealmCommit>>,
}

impl AccountSubscribeTransport for RecoveryRail<'_> {
    async fn subscribe(
        &self,
        request: &AccountSubscribeParameters,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        let call = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.clone());
            requests.len()
        };
        let verify = || -> Result<()> {
            ensure!(
                call <= 2,
                "recoverable lag exceeded the original Account retry budget"
            );
            if call == 2 {
                let requests = self.requests.lock().unwrap();
                ensure!(
                    serde_json::to_value(&requests[0])? == serde_json::to_value(request)?,
                    "revision_stale changed after, filter, device or operation"
                );
                ensure!(
                    serde_json::to_value(
                        inkson::LocalStateStore::with_path(self.path.clone()).load()
                    )? == self.before,
                    "revision_stale changed the durable cut before backfill"
                );
                ensure!(
                    business_evidence(&self.database_url)? == self.effects,
                    "revision_stale changed the complete server business or issuance state"
                );
            }
            Ok(())
        };
        verify().map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if call == 2 {
            let recover = async {
                let (status, body) = self.receiver.signed_peer_post(self.source,
                    "/_arkret/peer/events", &self.replay, self.receiver.service_id()).await?;
                ensure!(status == reqwest::StatusCode::OK, "normal history recovery peer ingress failed: {status}");
                let outcome: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitResponseBody = serde_json::from_slice(&body)?;
                ensure!(matches!(outcome,
                    arkret_models_collaboration::authority_commit::PeerAuthoritySubmitResponseBody::CommittedReplication(ref value)
                    if matches!(value.replication_outcomes.as_slice(),
                        [arkret_models_collaboration::authority_commit::CommittedEventReplicationOutcome::Stored {}])),
                    "normal backup recovery did not install the missing original");
                let event = self.governor.client.author_event(self.realm.as_str(),
                    arkret_wire::EventKind::MessageCreate.as_str(),
                    cotest::harness::message_create_text_payload_for_strand(
                        arkret_wire::StrandId::new(self.governor.client.default_strand_id(self.realm.as_str())?)?, "after recoverable lag")?).await?;
                let commit = submit_and_expect_commit(&self.governor.client, &self.governor.account,
                    self.governor.device.as_str(), &event).await?;
                ensure!(wait_for_committed(&self.member.client, &event.event_id).await?.commit() == &commit,
                    "normal signed post-recovery original never reached the account Station");
                *self.recovered.lock().unwrap() = Some(commit);
                Ok::<(), anyhow::Error>(())
            }.await;
            recover.map_err(|error| garth::Error::Protocol(error.to_string()))?;
        }
        let result = self.http.account_subscribe_batch(request).await;
        if call == 1 {
            let error = result.as_ref().err().ok_or_else(|| {
                garth::Error::Protocol("a restored older prefix produced no real refusal".into())
            })?;
            if let arkret_http_client::Error::Api {
                status,
                error: problem,
            } = error
            {
                let after = request
                    .after
                    .as_deref()
                    .ok_or_else(|| garth::Error::Protocol("normal recovery has no after".into()))?;
                let check = || -> Result<()> {
                    ensure!(
                        *status == 409
                            && problem.status == 409
                            && problem.problem_type == "https://arkret.org/problems/revision_stale",
                        "incorrect recovery Problem"
                    );
                    problem
                        .account_revision_stale_details()?
                        .context("missing typed continuation")?
                        .validate_after(after)?;
                    ensure!(
                        business_evidence(&self.database_url)? == self.effects,
                        "real refusal wrote server business, cursor, window or ACK state"
                    );
                    Ok(())
                };
                check().map_err(|error| garth::Error::Protocol(error.to_string()))?;
            } else {
                return Err(garth::Error::Protocol(format!(
                    "normal restored prefix returned {error}"
                )));
            }
        }
        Ok(AccountSubscribeSnapshotResult::Batch(result?))
    }
}

impl Probe {
    pub(super) async fn revision_stale(
        &self,
        controller: &Member,
        genesis: &Event,
        coauth: &cotest::scenarios::_helpers::bridge::MockCoauthIntrospectionServer,
        database_url: &str,
        recovery_database_url: &str,
        servers: &mut TestServerGroup,
    ) -> Result<()> {
        ensure!(
            database_url != recovery_database_url,
            "history recovery needs distinct durable Stations"
        );
        let fixture = cotest::conformance::load_fixture_value("client-sync-fixture.json")?;
        let case = fixture["reconnect"]
            .as_array()
            .context("reconnect cases")?
            .iter()
            .find(|case| case["name"] == REVISION_STALE_CASE)
            .context("revision_stale case")?;
        ensure!(
            case["producer_condition"]
                == "validated_after_accepted_head_ahead_of_recoverable_verified_serving_prefix"
                && case["baseline_redone"] == false
                && case["discard_old_cursor"] == false
                && case["checkpoint_advanced_on_error"] == false
                && case["fresh_process_readback"] == true,
            "canonical revision_stale contract drifted"
        );
        let governor = Member::provision(
            servers.server(1),
            coauth,
            "recovery-governor",
            "ak:device:01904100-0000-7000-8000-000000002879",
        )
        .await?;
        let realm = arkret_wire::RealmId::new(
            create_realm_with_join_rule(
                &governor.client,
                "Account history recovery",
                "public",
                &[servers.server(0), servers.server(1)],
            )
            .await?,
        )?;
        prepare_join(
            &controller.client,
            realm.as_str(),
            servers.server(1),
            "ak:request:019b0000-0000-7000-8000-000000002879",
            arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent::MemberJoin,
        )
        .await?;
        let join = controller.client.author_event(realm.as_str(), arkret_wire::EventKind::MemberState.as_str(),
            membership_payload(realm.as_str(),controller.account.clone(),
                arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,
                "history recovery member")?).await?;
        submit_and_expect_commit(
            &controller.client,
            &controller.account,
            controller.device.as_str(),
            &join,
        )
        .await?;
        wait_for_committed(&controller.client, &join.event_id).await?;
        let path = self.directory.path().join("state.json");
        let host = NativeAccountHost::new_for_realm(
            controller.client.sdk(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path.clone()),
            realm.clone(),
        )
        .await?;
        host.catch_up().await?;
        let backup = self.directory.path().join("accepted-history-before.dump");
        let ledger = self.directory.path().join("immutable-issuance-after.sql");
        postgres_tool(
            "pg_dump",
            database_url,
            &["--format=custom", "--no-owner", "--no-privileges"],
            &backup,
        )?;
        let message = governor
            .client
            .author_event(
                realm.as_str(),
                arkret_wire::EventKind::MessageCreate.as_str(),
                cotest::harness::message_create_text_payload_for_strand(
                    arkret_wire::StrandId::new(governor.client.default_strand_id(realm.as_str())?)?,
                    "accepted before backup recovery",
                )?,
            )
            .await?;
        let accepted = submit_and_expect_commit(
            &governor.client,
            &governor.account,
            governor.device.as_str(),
            &message,
        )
        .await?;
        ensure!(
            wait_for_committed(&controller.client, &message.event_id)
                .await?
                .commit()
                == &accepted
        );
        host.catch_up().await?;
        let before = state(&host)?;
        let private_cut =
            inkson::conformance::retained_sidecar_cut(&host.state_store(), &genesis.scope_ref)?;
        ensure!(
            before["mls_snapshots"]
                .as_object()
                .is_some_and(|m| !m.is_empty())
                && before["verified_sidecar_history"]
                    .as_object()
                    .is_some_and(|m| !m.is_empty()),
            "recovery needs a nonempty private cut"
        );
        let queue = controller
            .client
            .sdk()
            .receive_device_messages(None, None)
            .await?;
        ensure!(
            !queue.deliveries.is_empty(),
            "recovery needs an unprocessed real recipient delivery"
        );
        let ack = queue.acknowledgement_token.context("recovery ACK token")?;
        let ack_before = read_database_evidence(
            database_url,
            "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE acknowledgement_token=$1 AND consumed_at IS NULL",
            &[&ack],
        )?;
        let mut args = vec![
            "--data-only",
            "--inserts",
            "--on-conflict-do-nothing",
            "--no-owner",
            "--no-privileges",
        ];
        for table in ISSUANCE_TABLES {
            args.push("--table");
            args.push(table);
        }
        postgres_tool("pg_dump", database_url, &args, &ledger)?;
        let replay = cotest::scenarios::fanout_route_miss_live::replication_body(
            &governor.client,
            &message,
            &accepted,
        )
        .await?;
        servers.server_mut(0).stop_external_process().await?;
        restore_backup(database_url, &backup, &ledger)?;
        servers.server_mut(0).start_external_process().await?;
        let effects = business_evidence(database_url)?;
        let rail = RecoveryRail {
            http: controller.client.sdk(),
            path: path.clone(),
            database_url: database_url.into(),
            before: before.clone(),
            effects,
            source: servers.server(1),
            receiver: servers.server(0),
            governor: &governor,
            member: controller,
            realm: realm.clone(),
            replay,
            requests: Default::default(),
            recovered: Default::default(),
        };
        host.catch_up_with_conformance_transport(&rail).await?;
        ensure!(
            rail.requests.lock().unwrap().len() == 2,
            "normal recovery did not traverse exact continuation retry"
        );
        let after = state(&host)?;
        ensure!(
            private_state(&after) == private_state(&before),
            "normal backfill changed private MLS or Sidecar history"
        );
        ensure!(
            inkson::conformance::retained_sidecar_cut(&host.state_store(), &genesis.scope_ref)?
                == private_cut,
            "normal backfill changed the original private signed Sidecar cut"
        );
        ensure!(
            read_database_evidence(
                database_url,
                "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE acknowledgement_token=$1 AND consumed_at IS NULL",
                &[&ack]
            )? == ack_before,
            "normal backfill consumed or invalidated the exact ACK"
        );
        let recovered = rail
            .recovered
            .lock()
            .unwrap()
            .clone()
            .context("no new signed recovery original")?;
        let key = serde_json::to_string(&recovered.stream_ref)?;
        ensure!(
            after["verified_commit_stream_cursors"][&key]["stream_position"]
                == recovered.stream_position
                && after["verified_commit_stream_anchors"][&key]
                    == serde_json::to_value(&recovered)?,
            "normal backfill did not durably install the new exact signed head"
        );
        ensure!(
            host.state_store().sync_cursor() != before["sync_cursor"].as_str().map(str::to_owned),
            "normal recovery never advanced its successful checkpoint"
        );
        let expected = self.directory.path().join("expected-recovery-cut.json");
        let cut = inkson::conformance::retained_realm_current(
            &host.state_store(),
            &controller.account,
            &realm,
        )
        .await?;
        std::fs::write(
            &expected,
            serde_json::to_vec(
                &serde_json::json!({"account":controller.account,"realm":realm,
            "cursor":host.state_store().sync_cursor(),"cut":cut,"stream_heads":after["verified_commit_stream_cursors"],
            "stream_anchors":after["verified_commit_stream_anchors"],"private_state":private_state(&after),
            "private_sidecar_scope":genesis.scope_ref,"private_sidecar_cut":private_cut}),
            )?,
        )?;
        let output = std::process::Command::new(&self.reader)
            .arg(&path)
            .arg(&expected)
            .output()?;
        ensure!(
            output.status.success(),
            "fresh-process recovery readback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            inkson::conformance::retained_sidecar_cut(&host.state_store(), &genesis.scope_ref)?
                .1
                .len()
                > 0
        );
        self.results
            .borrow_mut()
            .push(super::super::CaseExecutionResult {
                case_id: REVISION_STALE_CASE.into(),
                assertions: 17,
            });
        cotest::transcripts::record_vector_event(
            "sync.client_account_stream.revision_stale",
            &serde_json::json!({"case_id":REVISION_STALE_CASE,"producer":"actual PostgreSQL backup recovery + preserved immutable issuance ledger"}),
            &serde_json::json!({"actual_error":"revision_stale","exact_continuation":true,"baseline_redone":false,
                "private_cut_retained":true,"issued_ack_retained":true,"rejection_zero_effects":true,"fresh_process_readback":true}),
            &serde_json::json!({"complete_suite_claim":false}),
        );
        Ok(())
    }
}
