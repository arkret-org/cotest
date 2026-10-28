//! Executable compact-current transcripts through shared projection, crypto
//! and bound own-Station consumers. Fixture authority keys are explicit KAT
//! inputs; native method authority and live admission run in the PG/joint suite.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail, ensure};
use arkret_http_client::own_station_results::{
    OwnStationSessionSnapshot, OwnStationSessionSource, OwnStationStateClient,
};
use arkret_models_collaboration::events_payloads::call::*;
use arkret_wire::{
    CurrentRevision, CurrentSelector, CurrentState, RealmCommit, RealmSnapshotId,
    RealmStateSnapshot,
};
use serde_json::{Value, json};

use super::{CaseExecutionResult, SuiteExecutionResult, load_fixture_value};
const FIXTURE: &str = "call-current-fixture.json";
pub const CALL_CURRENT_ENTRYPOINT: &str = "ak.suite.call_state.compact_current.v1";

fn axis<'a>(snapshot: &'a Value, kind: &str) -> &'a Value {
    snapshot["current_state_entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["selector"]["kind"] == kind)
        .unwrap()
}
fn axis_mut<'a>(snapshot: &'a mut Value, kind: &str) -> &'a mut Value {
    snapshot["current_state_entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["selector"]["kind"] == kind)
        .unwrap()
}
fn key(fixture: &Value, name: &str) -> Result<arkret_signatures::PublicKeyMaterial> {
    Ok(arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(fixture["test_keys"][name].as_str().unwrap())?,
    })
}
fn revision(commit: &RealmCommit) -> CurrentRevision {
    CurrentRevision {
        commit_id: commit.commit_id.clone(),
        stream_position: commit.stream_position,
    }
}
fn source(row: &Value) -> Result<(arkret_wire::Event, RealmCommit)> {
    Ok((
        serde_json::from_value(row["event"].clone())?,
        serde_json::from_value(row["commit"].clone())?,
    ))
}
fn sign_snapshot(snapshot: &mut Value) -> Result<()> {
    let mut typed: RealmStateSnapshot = serde_json::from_value(snapshot.clone())?;
    let core = arkret_canonical::unsigned_value(&typed, &["snapshot_id", "signature"])?;
    typed.snapshot_id = RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&core)?,
    ));
    let signing = ed25519_dalek::SigningKey::from_bytes(&std::array::from_fn(|i| i as u8));
    typed.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&typed, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        typed.signature.verification_method.clone(),
        typed.created_at,
        &signing,
    )?;
    *snapshot = serde_json::to_value(typed)?;
    Ok(())
}
fn verify_candidate(fixture: &Value, snapshot: &Value) -> Result<RealmStateSnapshot> {
    let snapshot: RealmStateSnapshot = serde_json::from_value(snapshot.clone())?;
    let governance = key(fixture, "governance_public_key_b64u")?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &arkret_canonical::unsigned_value(&snapshot, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &governance,
    )?;
    for commit in call_current_source_commits(&snapshot.current_state_entries)? {
        ensure!(commit.governance_generation <= snapshot.governance_generation);
        arkret_signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret_canonical::unsigned_value(&commit, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &governance,
        )?;
    }
    for row in &snapshot.current_state_entries {
        if let CurrentState::Value {
            selector: CurrentSelector::CallRoster { call_id },
            value,
            ..
        } = row
        {
            let roster = serde_json::from_value(value.clone())?;
            arkret_signatures::media::verify_call_roster_bindings(
                &snapshot.realm_id,
                call_id,
                &roster,
            )?;
        }
    }
    Ok(snapshot)
}
fn verify_original(fixture: &Value, row: &Value) -> Result<()> {
    let (event, commit) = source(row)?;
    event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    let bytes = arkret_signatures::EventProofBuilder::new().envelope_bytes(&event)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        event
            .producer_proof
            .as_ref()
            .context("missing original producer proof")?,
        &bytes,
        &event.actor_id,
        &key(fixture, "producer_public_key_b64u")?,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    commit.validate_content_address()?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &commit.signature,
        &arkret_canonical::unsigned_value(&commit, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &key(fixture, "governance_public_key_b64u")?,
    )?;
    Ok(())
}
fn project_checkpoints(fixture: &Value) -> Result<()> {
    let mut roster = None;
    let mut moderation = None;
    ensure!(fixture["original_rows"].as_array().unwrap().len() == 11);
    for (original, checkpoint) in fixture["original_rows"]
        .as_array()
        .unwrap()
        .iter()
        .zip(fixture["checkpoints"].as_array().unwrap())
    {
        verify_original(fixture, original)?;
        let (event, commit) = source(original)?;
        if event.kind == arkret_wire::EventKind::CallState {
            let payload: CallStatePayload =
                serde_json::from_value(original["event"]["payload"].clone())?;
            if let Some(value) = payload.roster_delta {
                let key=matches!(&value,CallRosterDelta::Join {participant} if participant.participant_binding.is_some()).then(||CallParticipantSigningKey {public_key_base64url:fixture["test_keys"]["issuer_public_key_b64u"].as_str().unwrap().into()});
                roster = Some(CallRosterCurrentValue::apply_delta(
                    roster.as_ref(),
                    CallRosterSource {
                        tag_id: format!("{}:{CALL_ROSTER_WRITE_INDEX}", event.event_id),
                        source_commit: commit.clone(),
                        value,
                    },
                    key,
                )?);
            }
            if let Some(value) = payload.moderation_delta {
                moderation = Some(CallModerationCurrentValue::apply_delta(
                    moderation.as_ref(),
                    CallModerationSource {
                        tag_id: format!("{}:{CALL_MODERATION_WRITE_INDEX}", event.event_id),
                        source_commit: commit.clone(),
                        value,
                    },
                )?);
            }
        }
        for (kind, actual) in [
            (
                "call_roster",
                roster.as_ref().map(serde_json::to_value).transpose()?,
            ),
            (
                "call_moderation",
                moderation.as_ref().map(serde_json::to_value).transpose()?,
            ),
        ] {
            let expected = checkpoint["current_state_entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["selector"]["kind"] == kind)
                .map(|row| row["value"].clone());
            ensure!(
                actual == expected,
                "shared projector differs at {} / {kind}",
                commit.stream_position
            );
        }
        verify_candidate(fixture, checkpoint)?;
    }
    for row in fixture["followup_rows"]
        .as_object()
        .context("missing actual follow-up sources")?
        .values()
    {
        verify_original(fixture, row)?;
    }
    Ok(())
}

struct Session(Arc<Mutex<Option<OwnStationSessionSnapshot>>>);
impl OwnStationSessionSource for Session {
    fn snapshot(&self) -> arkret_http_client::Result<OwnStationSessionSnapshot> {
        self.0.lock().unwrap().clone().ok_or_else(|| {
            arkret_http_client::Error::Protocol("current authenticated source unavailable".into())
        })
    }
}
fn session(
    binding: &arkret_models_discovery::StationConnectionBinding,
    epoch: u64,
    account: arkret_wire::AccountId,
) -> arkret_http_client::Result<OwnStationSessionSnapshot> {
    OwnStationSessionSnapshot::new(
        binding.clone(),
        account,
        binding.service_id.clone(),
        arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
        epoch,
        "current-fixture".into(),
    )
    .map(|s| s.with_provider_identity(Default::default()))
}
type CurrentCallFixture = (
    OwnStationStateClient,
    Arc<Mutex<Option<OwnStationSessionSnapshot>>>,
    arkret_models_discovery::StationConnectionBinding,
    std::thread::JoinHandle<Result<()>>,
);

fn client(bodies: Vec<Value>) -> Result<CurrentCallFixture> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let base = format!("http://{}/", listener.local_addr()?);
    let station = "ak:did_core:web:station.example".parse()?;
    let binding = arkret_models_discovery::StationConnectionBinding {
        service_id: station,
        base_url: base.clone(),
        trust_domain: "ak:trust_domain:station.example".parse()?,
        authentication_metadata: arkret_models_discovery::AuthenticationMetadata::minimal(),
    };
    let account = arkret_wire::AccountId::new(
        "ak:did_core:web:alice.example".parse()?,
        binding.service_id.clone(),
    );
    let control = Arc::new(Mutex::new(Some(session(&binding, 1, account)?)));
    let raw = arkret_http_client::ClientBuilder::new(url::Url::parse(&base)?)
        .allow_insecure_localhost()
        .auth(arkret_http_client::Auth::Bearer("current-fixture".into()))
        .build()?;
    let result =
        OwnStationStateClient::new(raw, binding.clone(), Arc::new(Session(control.clone())))?;
    let server = std::thread::spawn(move || -> Result<()> {
        for body in bodies {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buffer)?;
                ensure!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
            }
            let headers = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            ensure!(headers.contains("authorization: bearer current-fixture"));
            let body = serde_json::to_vec(&body)?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            stream.write_all(&body)?;
        }
        Ok(())
    });
    Ok((result, control, binding, server))
}
async fn bound_candidate(
    prior: Option<Value>,
    candidate: Value,
    epoch_change: bool,
    historical: Option<RealmSnapshotId>,
    floor_commit: arkret_wire::RealmCommitId,
) -> Result<bool> {
    let snapshot: RealmStateSnapshot = serde_json::from_value(candidate.clone())?;
    let mut bodies = prior.iter().cloned().collect::<Vec<_>>();
    bodies.push(candidate);
    let (client, control, binding, server) = client(bodies)?;
    let mut replica = garth::own_station_results::OwnStationReplica::new(snapshot.realm_id.clone());
    if prior.is_some() {
        replica.install_bound_snapshot(&client.snapshot_head(&snapshot.realm_id).await?)?;
    }
    let accepted = if let Some(reference) = historical {
        let current_before = replica.snapshot().cloned();
        let accepted = match client.snapshot_by_ref(&snapshot.realm_id, &reference).await {
            Ok(response) => {
                let head = &snapshot.visible_stream_heads[0];
                let basis=arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis {anchor_position:head.stream_position,anchor_commit_ref:head.commit_id.clone(),snapshot_ref:reference,governance_generation:snapshot.governance_generation,accepted_dependency_refs:None};
                let floor = arkret_wire::ReadableFloor {
                    oldest_position: snapshot.retention_and_history_floor.stream_floors[0]
                        .oldest_position,
                    floor_commit_id: floor_commit,
                    floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
                };
                replica
                    .install_bound_floor_predecessor(
                        &head.stream_ref,
                        &basis,
                        &floor,
                        response,
                        &BTreeMap::new(),
                    )
                    .is_ok()
            }
            Err(arkret_http_client::Error::Protocol(_)) => false,
            Err(error) => return Err(error.into()),
        };
        ensure!(
            replica.snapshot() == current_before.as_ref(),
            "historical basis replaced accepted current coverage"
        );
        accepted
    } else {
        let response = client.snapshot_head(&snapshot.realm_id).await?;
        if epoch_change {
            let account = control
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .account_id()
                .clone();
            *control.lock().unwrap() = Some(session(&binding, 2, account)?);
        }
        replica.install_bound_snapshot(&response).is_ok()
    };
    server
        .join()
        .map_err(|_| anyhow::anyhow!("current fixture transport panicked"))??;
    Ok(accepted)
}
fn verdict(accepted: bool) -> &'static str {
    if accepted { "accept" } else { "reject" }
}
async fn run_case(fixture: &Value, case: &Value) -> Result<&'static str> {
    let name = case["name"].as_str().unwrap();
    let checkpoint = case["checkpoint"]
        .as_u64()
        .map(|n| n as usize)
        .unwrap_or(10);
    let mut snapshot = fixture["checkpoints"][checkpoint].clone();
    match name {
        "empty_roster_latest_leave" | "empty_moderation_latest_restore" => {
            let (index, kind) = if name == "empty_roster_latest_leave" {
                (9, "call_roster")
            } else {
                (5, "call_moderation")
            };
            verify_candidate(fixture, &fixture["checkpoints"][index])?;
            ensure!(
                axis(&fixture["checkpoints"][index], kind)["value"]["entries"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            return Ok("accept");
        }
        "unwritten_axis_absent" => {
            ensure!(
                !fixture["checkpoints"][0]["current_state_entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| matches!(
                        row["selector"]["kind"].as_str(),
                        Some("call_roster" | "call_moderation")
                    ))
            );
            return Ok("accept");
        }
        "full_actor_station_isolation" => {
            let roster: CallRosterCurrentValue = serde_json::from_value(
                axis(&fixture["checkpoints"][3], "call_roster")["value"].clone(),
            )?;
            let participants = roster.effective_participants()?;
            ensure!(
                participants.len() == 2 && participants[0].actor_id != participants[1].actor_id
            );
            return Ok("accept");
        }
        "kick_old_leg" | "kick_later_legal_join" => {
            let index = if name == "kick_old_leg" { 6 } else { 7 };
            let roster: CallRosterCurrentValue = serde_json::from_value(
                axis(&fixture["checkpoints"][index], "call_roster")["value"].clone(),
            )?;
            let moderation: CallModerationCurrentValue = serde_json::from_value(
                axis(&fixture["checkpoints"][index], "call_moderation")["value"].clone(),
            )?;
            let actor: arkret_wire::ActorId =
                serde_json::from_value(fixture["original_rows"][2]["event"]["actor_id"].clone())?;
            let (participant, join) = roster
                .active_participants()?
                .into_iter()
                .find(|(p, _)| p.actor_id == actor)
                .context("missing actual target leg")?;
            let denied=moderation.entries.iter().any(|entry|matches!(&entry.value,CallModerationDelta::RemoveParticipant {removal} if removal.actor_id==actor && (removal.action==CallParticipantRemovalAction::Ban || (removal.device_id.as_ref()==Some(&participant.device_id) && entry.source_commit.stream_position>join.stream_position))));
            return Ok(verdict(!denied));
        }
        "restore_preserves_kick" | "stale_restore_revision" => {
            let (prior, row) = if name == "restore_preserves_kick" {
                (
                    axis(&snapshot, "call_moderation")["value"].clone(),
                    fixture["followup_rows"][name].clone(),
                )
            } else {
                (
                    axis(&fixture["checkpoints"][4], "call_moderation")["value"].clone(),
                    fixture["original_rows"][5].clone(),
                )
            };
            let previous: CallModerationCurrentValue = serde_json::from_value(prior)?;
            let mut delta = row["event"]["payload"]["moderation_delta"].clone();
            if name == "stale_restore_revision" {
                delta["expected_revision"]["stream_position"] =
                    json!(previous.last_source.source_commit.stream_position - 1);
            }
            let (_, commit) = source(&row)?;
            let result = CallModerationCurrentValue::apply_delta(
                Some(&previous),
                CallModerationSource {
                    tag_id: format!("{}:{CALL_MODERATION_WRITE_INDEX}", commit.event_ref),
                    source_commit: commit,
                    value: serde_json::from_value(delta)?,
                },
            );
            if let Ok(current) = &result {
                ensure!(current.entries.len() == 1);
                ensure!(
                    matches!(&current.entries[0].value,CallModerationDelta::RemoveParticipant {removal} if removal.action==CallParticipantRemovalAction::Kick)
                );
            }
            return Ok(verdict(result.is_ok()));
        }
        "stale_leave_revision" => {
            let previous: CallRosterCurrentValue = serde_json::from_value(
                axis(&fixture["checkpoints"][7], "call_roster")["value"].clone(),
            )?;
            let row = &fixture["original_rows"][8];
            let (_, commit) = source(row)?;
            let mut delta = row["event"]["payload"]["roster_delta"].clone();
            delta["expected_revision"]["stream_position"] =
                json!(previous.last_source.source_commit.stream_position - 1);
            return Ok(verdict(
                CallRosterCurrentValue::apply_delta(
                    Some(&previous),
                    CallRosterSource {
                        tag_id: format!("{}:{CALL_ROSTER_WRITE_INDEX}", commit.event_ref),
                        source_commit: commit,
                        value: serde_json::from_value(delta)?,
                    },
                    None,
                )
                .is_ok(),
            ));
        }
        "producer_signature_tampered" => {
            let mut row = fixture["original_rows"][2].clone();
            row["event"]["producer_proof"]["jws"] = json!("e30..AA");
            return Ok(verdict(verify_original(fixture, &row).is_ok()));
        }
        "revoked_current_permission" | "missing_source_material" => {
            let (client, control, _, server) = client(vec![])?;
            *control.lock().unwrap() = None;
            let realm = serde_json::from_value(fixture["request_context"]["realm_id"].clone())?;
            ensure!(client.snapshot_head(&realm).await.is_err());
            server.join().unwrap()?;
            return Ok("unavailable");
        }
        "exact_history_below_floor" => {
            let (event, commit) = source(&fixture["original_rows"][0])?;
            let request = arkret_wire::StreamScanRequestBody {
                realm_id: commit.realm_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                direction: arkret_wire::StreamScanDirection::Before(None),
                limit: 1,
            };
            let original =
                arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
                    commit: commit.clone(),
                    event,
                });
            let outcome: arkret_wire::StreamScanResponseBody = serde_json::from_value(
                json!({"committed_events":[original],"readable_floor":{"oldest_position":3,"floor_commit_id":fixture["original_rows"][2]["commit"]["commit_id"],"floor_reason":"membership_join"},"truncated":false}),
            )?;
            ensure!(outcome.validate_for_request(&request).is_err());
            return Ok("unavailable");
        }
        "wrong_authenticated_account" => {
            let (_, _, binding, server) = client(vec![])?;
            let account = serde_json::from_value(
                fixture["checkpoints"][3]["current_state_entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["selector"]["kind"] == "call_roster")
                    .unwrap()["value"]["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| entry["value"]["participant"]["actor_id"]["account_id"].clone())
                    .find(|account| account["station_id"] != json!(binding.service_id))
                    .unwrap(),
            )?;
            let accepted = session(&binding, 1, account).is_ok();
            server.join().unwrap()?;
            return Ok(verdict(accepted));
        }
        _ => {}
    }
    let mut prior = None;
    let mut exact = None;
    let mut resign = true;
    let mut complete_reference = None;
    let mut epoch_change = false;
    let entry_path = "/value/entries/0";
    match name {
        "complete_cold_recovery" => {}
        "two_axes_one_commit_distinct_dots" => {
            let roster = axis(&snapshot, "call_roster");
            let moderation = axis(&snapshot, "call_moderation");
            ensure!(
                roster["revision"] == moderation["revision"]
                    && roster["value"]["last_source"]["tag_id"]
                        != moderation["value"]["last_source"]["tag_id"]
            );
        }
        "same_revision_same_bytes" => prior = Some(snapshot.clone()),
        "same_revision_different_value" => {
            prior = Some(snapshot.clone());
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"] = json!([]);
        }
        "below_floor_current_binding_key" => {
            snapshot = fixture["checkpoints"][7].clone();
            snapshot["retention_and_history_floor"]["stream_floors"][0]["oldest_position"] =
                json!(8);
        }
        "partial_value" => axis_mut(&mut snapshot, "call_roster")["value"]["partial"] = json!(true),
        "accumulated_assertions" => {
            let row = axis_mut(&mut snapshot, "call_roster");
            row["value"] = json!({"assertions":[row["value"]["last_source"].clone()]});
        }
        "missing_last_source" => {
            axis_mut(&mut snapshot, "call_roster")["value"]
                .as_object_mut()
                .unwrap()
                .remove("last_source");
        }
        "missing_issuer_key" => {
            axis_mut(&mut snapshot, "call_roster")
                .pointer_mut(entry_path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove("participant_signing_key");
        }
        "wrong_historical_issuer_key" => {
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"][0]["participant_signing_key"]
                ["public_key_base64url"] =
                fixture["test_keys"]["governance_public_key_b64u"].clone()
        }
        "wrong_binding_actor_station" => {
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"][0]["value"]["participant"]
                ["actor_id"]["account_id"]["station_id"] =
                json!("ak:did_core:web:other-station.example")
        }
        "wrong_binding_device" | "wrong_binding_participant" => {
            let field = if name == "wrong_binding_device" {
                "device_id"
            } else {
                "participant_id"
            };
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"][0]["value"]["participant"]
                [field] = json!(if field == "device_id" {
                "ak:device:01964137-0000-7000-8000-000000000099"
            } else {
                "ak:rtc_participant:01964137-0000-7000-8000-000000000099"
            });
        }
        "wrong_binding_media" => {
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"][0]["value"]["participant"]
                ["media"]["screen"] = json!(true)
        }
        "wrong_scope" => {
            snapshot["visible_stream_heads"][0]["stream_ref"] = json!({"kind":"circle","realm_id":fixture["request_context"]["realm_id"],"circle_id":arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[99;32]))})
        }
        "wrong_call" => {
            axis_mut(&mut snapshot, "call_roster")["selector"]["call_id"] = json!(
                arkret_wire::CallId::from_event_id(&arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [99; 32]
                ))
            )
        }
        "wrong_source_position" => {
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"][0]["source_commit"]["stream_position"] =
                json!(1)
        }
        "wrong_source_event" => {
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"][0]["source_commit"]["event_ref"] = json!(
                arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [99; 32])
            )
        }
        "wrong_dot_index" => {
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"][0]["tag_id"] =
                json!("wrong:6")
        }
        "duplicate_target" | "duplicate_position" => {
            let row = axis_mut(&mut snapshot, "call_roster");
            let mut duplicate = row["value"]["entries"][0].clone();
            duplicate["tag_id"] = json!(format!(
                "{}:7",
                arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [99; 32])
            ));
            if name == "duplicate_position" {
                duplicate["value"]["participant"]["actor_id"]["account_id"]["station_id"] =
                    json!("ak:did_core:web:other-station.example");
            }
            row["value"]["entries"]
                .as_array_mut()
                .unwrap()
                .push(duplicate);
            row["value"]["entries"]
                .as_array_mut()
                .unwrap()
                .sort_by_key(|row| row["tag_id"].as_str().unwrap().to_owned());
        }
        "source_after_axis_revision" => {
            let row = axis_mut(&mut snapshot, "call_roster");
            let original = &fixture["original_rows"][2];
            let (_, commit) = source(original)?;
            row["revision"] = serde_json::to_value(revision(&commit))?;
            row["value"]["last_source"] = json!({"tag_id":format!("{}:7",commit.event_ref),"source_commit":commit,"value":original["event"]["payload"]["roster_delta"]});
        }
        "revision_not_last_source" => {
            let row = axis_mut(&mut snapshot, "call_roster");
            row["revision"]["stream_position"] =
                json!(row["revision"]["stream_position"].as_u64().unwrap() - 1);
        }
        "rollback_head" => {
            prior = Some(snapshot.clone());
            snapshot = fixture["checkpoints"][3].clone();
        }
        "old_tenure_as_current" | "historical_exact_basis" | "wrong_historical_ref" => {
            let mut current = snapshot.clone();
            current["governance_generation"] = json!("2");
            sign_snapshot(&mut current)?;
            prior = Some(current);
            if name != "old_tenure_as_current" {
                let head = snapshot["visible_stream_heads"][0].clone();
                snapshot["purpose"] = json!("stream_history");
                snapshot["history_basis"] = json!({
                    "account_id": fixture["request_context"]["account_id"],
                    "stream_ref": head["stream_ref"],
                    "anchor_position": head["stream_position"],
                    "anchor_commit_ref": head["commit_id"],
                    "accepted_dependency_refs": []
                });
                sign_snapshot(&mut snapshot)?;
                resign = false;
                exact = Some(if name == "wrong_historical_ref" {
                    RealmSnapshotId::from_digest([99; 32])
                } else {
                    serde_json::from_value(snapshot["snapshot_id"].clone())?
                });
            }
        }
        "wrong_local_session" => {
            prior = Some(snapshot.clone());
            epoch_change = true;
        }
        "commit_signature_tampered" => {
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"][0]["source_commit"]["signature"]
                ["signature"] = json!("A".repeat(86))
        }
        "snapshot_signature_tampered" => {
            snapshot["signature"]["signature"] = json!("A".repeat(86));
            resign = false;
        }
        "omission_unsigned"
        | "omission_resigned_ordinary_trust_boundary"
        | "omission_resigned_complete_replica" => {
            if name == "omission_resigned_complete_replica" {
                complete_reference = Some(snapshot["current_state_entries"].clone());
            }
            let row = axis_mut(&mut snapshot, "call_roster");
            let last = row["value"]["last_source"]["tag_id"].clone();
            row["value"]["entries"]
                .as_array_mut()
                .unwrap()
                .retain(|entry| entry["tag_id"] == last);
            if name == "omission_unsigned" {
                resign = false;
            }
        }
        "wrong_member_complete_replica" => {
            complete_reference = Some(snapshot["current_state_entries"].clone());
            axis_mut(&mut snapshot, "call_roster")["value"]["entries"] =
                axis(&fixture["checkpoints"][3], "call_roster")["value"]["entries"].clone();
        }
        _ => bail!("unimplemented compact Call case {name}"),
    }
    // Malformed closed values must reach their real serde/source validators;
    // they cannot be re-signed as a different typed shape by this harness.
    if resign {
        if serde_json::from_value::<RealmStateSnapshot>(snapshot.clone()).is_err() {
            return Ok("reject");
        }
        sign_snapshot(&mut snapshot)?;
    }
    if verify_candidate(fixture, &snapshot).is_err() {
        return Ok("reject");
    }
    if complete_reference
        .as_ref()
        .is_some_and(|expected| *expected != snapshot["current_state_entries"])
    {
        return Ok("reject");
    }
    let accepted = bound_candidate(
        prior,
        snapshot,
        epoch_change,
        exact.clone(),
        serde_json::from_value(fixture["request_context"]["known_head"]["commit_id"].clone())?,
    )
    .await?;
    Ok(if accepted && exact.is_some() {
        "accept_historical"
    } else {
        verdict(accepted)
    })
}

pub fn run_call_current_suite() -> Result<SuiteExecutionResult> {
    std::thread::spawn(|| -> Result<SuiteExecutionResult> {
        let fixture = load_fixture_value(FIXTURE)?;
        ensure!(fixture["runner"]["entrypoint"] == CALL_CURRENT_ENTRYPOINT);
        project_checkpoints(&fixture)?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let declared = fixture["cases"]
                    .as_array()
                    .context("missing compact Call cases")?;
                ensure!(declared.len() == 48);
                let mut cases = Vec::new();
                for case in declared {
                    let observed = run_case(&fixture, case)
                        .await
                        .with_context(|| format!("compact Call case {}", case["name"]))?;
                    ensure!(
                        case["expected"] == observed,
                        "{}: observed {observed}, expected {}",
                        case["name"],
                        case["expected"]
                    );
                    cases.push(CaseExecutionResult {
                        case_id: case["name"].as_str().unwrap().into(),
                        assertions: 1,
                    });
                }
                let result = SuiteExecutionResult {
                    entrypoint: CALL_CURRENT_ENTRYPOINT,
                    fixture: FIXTURE,
                    cases,
                };
                ensure!(result.missing_against_cases(declared)?.is_empty());
                Ok(result)
            })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("compact Call runner panicked"))?
}
#[cfg(test)]
mod tests {
    #[test]
    fn every_compact_call_case_executes_shared_consumers() {
        let result = super::run_call_current_suite().unwrap();
        assert_eq!(result.cases.len(), 48);
        println!(
            "compact_call_cases={} assertions={}",
            result.cases.len(),
            result
                .cases
                .iter()
                .map(|case| case.assertions)
                .sum::<usize>()
        );
    }
}
