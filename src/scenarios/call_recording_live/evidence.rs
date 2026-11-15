//! Native RTC recording acceptance composed with the actual byte codec.
use anyhow::{Context as _, Result, ensure};
use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact;
use arkret_models_collaboration::events_payloads::call::{
    CallRecordingArtifact, CallRecordingStartPayload,
};
use arkret_wire::CommittedEventFullView;
use cotest_test_support::operation_observation::{NativeOperationObservations, observe};
use serde_json::{Value, json};

use crate::scenarios::native_operation_contracts::{
    validate_registered_exchange_schemas, verify_native_station_commits,
};

const SCOPE: [&str; 2] = [
    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
    arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
];

fn verify(evidence: &Value, observations: &NativeOperationObservations) -> Result<()> {
    let names = [
        "grant",
        "descriptor",
        "call",
        "active",
        "genesis",
        "start",
        "stop",
        "next_epoch",
        "ready",
    ];
    let originals = names
        .into_iter()
        .map(|name| serde_json::from_value::<CommittedEventFullView>(evidence[name].clone()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    verify_native_station_commits(observations, &originals)?;
    let stored = evidence["originals"]["canonical_originals"]
        .as_array()
        .context("actual PG canonical originals absent")?;
    for full in &originals {
        let matches = stored
            .iter()
            .filter(|row| row["event"]["event_id"] == json!(full.event.event_id))
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1
                && matches[0]["event"] == json!(full.event)
                && matches[0]["commit"] == json!(full.commit),
            "native PG original changed or repeated for {}",
            full.event.event_id
        );
        full.event
            .verify_event_id_matches_content_with_digest_suite(
                arkret_canonical::DigestSuite::Sha256,
            )?;
    }
    let start: CommittedEventFullView = serde_json::from_value(evidence["start"].clone())?;
    let stop: CommittedEventFullView = serde_json::from_value(evidence["stop"].clone())?;
    let ready: CommittedEventFullView = serde_json::from_value(evidence["ready"].clone())?;
    let next: CommittedEventFullView = serde_json::from_value(evidence["next_epoch"].clone())?;
    let opening: CallRecordingStartPayload = serde_json::from_value(json!(start.event.payload))?;
    let artifact: CallRecordingArtifact = serde_json::from_value(evidence["artifact"].clone())?;
    artifact.validate()?;
    artifact
        .encryption
        .validate_start_binding(&start.event.event_id, &opening)?;
    let permission: CommittedEventFullView = serde_json::from_value(evidence["grant"].clone())?;
    let initiator = arkret_wire::GrantId::from_event_id(&permission.event.event_id);
    ensure!(
        artifact.recording_initiator_capability_ref == initiator
            && start
                .event
                .authorization_ref
                .as_ref()
                .map(|source| source.as_str())
                == Some(initiator.as_str()),
        "recording source substituted another original initiator Grant"
    );
    ensure!(
        opening.capture_metadata.key_ref.as_ref() == Some(&artifact.encryption.key_ref)
            && artifact.encryption.key_ref.group_state_ref.event_id()? != next.event.event_id
            && start.commit.stream_position < stop.commit.stream_position
            && stop.commit.stream_position < next.commit.stream_position
            && next.commit.stream_position < ready.commit.stream_position,
        "old segment did not retain Q0 through actual Q1 and ready"
    );
    ensure!(
        ready.event.payload["recording_transition"]["capture_metadata"]
            == json!({"artifact":artifact})
            && ready.event.payload["recording_transition"]["expected_commit_id"]
                == json!(start.commit.commit_id),
        "ready lost its one immutable artifact/source guard"
    );
    let ready_row = stored
        .iter()
        .find(|row| row["event"]["event_id"] == json!(ready.event.event_id))
        .context("stored ready absent")?;
    let fact: HistoricalProducerSignerFact =
        serde_json::from_value(ready_row["producer_source_fact"].clone())?;
    let HistoricalProducerSignerFact::Service(fact) = fact else {
        anyhow::bail!("ready did not retain its actual Service signer fact")
    };
    fact.validate_commit_binding(&ready, arkret_canonical::DigestSuite::Sha256)?;
    let registration: arkret_wire::Event =
        serde_json::from_value(evidence["registration_event"].clone())?;
    let producer_grant: arkret_wire::Event =
        serde_json::from_value(evidence["service_grant_event"].clone())?;
    ensure!(
        fact.key.registration_ref.event_id == registration.event_id
            && fact.key.authorization_ref.event_id == producer_grant.event_id
            && fact.key.applet_id
                == *ready
                    .event
                    .applet_id
                    .as_ref()
                    .context("ready Applet source absent")?
            && ready.event.executed_by.as_ref()
                == Some(&arkret_wire::ActorId::service(artifact.produced_by.clone())),
        "ready borrowed another Service installation or grant"
    );
    for source in [&fact.key.registration_ref, &fact.key.authorization_ref] {
        let row = stored
            .iter()
            .find(|row| row["event"]["event_id"] == json!(source.event_id))
            .context("Service source has no native accepted original")?;
        let full: CommittedEventFullView =
            serde_json::from_value(json!({"event":row["event"],"commit":row["commit"]}))?;
        ensure!(
            full.commit.commit_id == source.commit_id
                && full.commit.stream_ref == source.stream_ref
                && full.commit.stream_position == source.stream_position,
            "Service source split its Event from the actual covering Commit"
        );
    }
    let resolution: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(evidence["service_resolution"].clone())?;
    let document = arkret_identity::authenticated_service_document_at(
        &resolution,
        &artifact.produced_by,
        ready.commit.committed_at,
    )?;
    let method = &ready
        .event
        .producer_proof
        .as_ref()
        .context("Service producer proof absent")?
        .verification_method;
    let did = arkret_identity::verification_method_did(method.as_str())?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        method,
        &did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    let key = arkret_identity::public_key_material_from_document(&document, method)?;
    arkret_identity::VerifiedProducerEvent::verify(
        ready.event.clone(),
        &arkret_identity::ProducerVerificationContext {
            actor: ready.event.actual_signer().clone(),
            verification_method: method.clone(),
            public_key: key,
            digest_suite: arkret_canonical::DigestSuite::Sha256,
        },
    )?;
    let cipher = arkret_canonical::base64url_decode(
        evidence["ciphertext_base64url"]
            .as_str()
            .context("actual recording ciphertext absent")?,
    )?;
    let fetched = arkret_canonical::base64url_decode(
        evidence["fetched_base64url"]
            .as_str()
            .context("native fetched ciphertext absent")?,
    )?;
    ensure!(
        cipher == fetched
            && artifact.size_bytes == cipher.len() as u64
            && artifact.blob_ref.as_str()
                == format!("ak:blob:{}", arkret_canonical::sha256_digest(&cipher)),
        "native ciphertext differs from its single source address"
    );
    let blob = &evidence["originals"]["blob"];
    ensure!(
        blob["sha256"] == arkret_canonical::sha256_hex(&cipher)
            && blob["size_bytes"] == json!(artifact.size_bytes)
            && blob["encryption"] == json!({"scheme":"ak.blob.stream_aead.v1"}),
        "native durable Blob classification or raw digest differs"
    );
    let capture = evidence["originals"]["capture"]
        .as_array()
        .context("native capture current rows absent")?;
    for (kind, expected, source_commit) in [
        (
            "call_recording_artifact",
            json!({"status":"ready","details":{"artifact":artifact}}),
            &ready.commit.commit_id,
        ),
        (
            "call_recording_state",
            json!("stopped"),
            &stop.commit.commit_id,
        ),
    ] {
        let rows = capture
            .iter()
            .filter(|row| {
                row["selector"]["kind"] == kind
                    && row["selector"]["call_id"] == json!(artifact.call_id)
                    && row["selector"]["recording_id"] == json!(artifact.recording_id)
            })
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1
                && rows[0]["value"] == expected
                && rows[0]["current_commit_id"] == json!(source_commit),
            "native {kind} projection lost its exact effect or original Commit"
        );
    }
    ensure!(
        evidence["originals"]["start_quota"]
            .as_array()
            .context("native quota originals absent")?
            .len()
            == 1,
        "ready did not retain one original Start budget consumption"
    );
    ensure!(
        evidence["processes"]
            .as_array()
            .context("native process identities absent")?
            .len()
            == 2,
        "case must retain independent real AA and Station processes"
    );
    Ok(())
}

fn retain_attempt(name: &str, observations: &NativeOperationObservations) -> Result<()> {
    if let Some(directory) = std::env::var_os("COTEST_CALL_RECORDING_EVIDENCE_DIR") {
        std::fs::create_dir_all(&directory)?;
        let name = format!(
            "attempt-{name}-{}.json",
            chrono::Utc::now().timestamp_millis()
        );
        std::fs::write(
            std::path::PathBuf::from(directory).join(name),
            serde_json::to_vec_pretty(
                &json!({"status":"observed_not_verified","observations":observations}),
            )?,
        )?;
    }
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(crate::harness::heap_future(super::run)).await;
    retain_attempt("account-call-recording", &observations)?;
    let mut evidence = result?;
    validate_registered_exchange_schemas(&observations, &SCOPE)?;
    verify(&evidence, &observations)?;
    evidence["case"] = json!("call_recording_live");
    evidence["scope"] = json!(SCOPE);
    evidence["observations"] = serde_json::to_value(&observations)?;
    if let Some(directory) = std::env::var_os("COTEST_CALL_RECORDING_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("call-recording.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
    }
    for operation in SCOPE {
        println!("recording composition passed: {operation}");
    }
    Ok(())
}
