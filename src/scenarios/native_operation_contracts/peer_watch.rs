//! Audited private reads originate at a distinct native Account Station.
use arkret_models_collaboration::authority_commit::authority_forward_body_digest;
use arkret_models_collaboration::events_payloads::strand::{
    StrandWatchExpectedValue, StrandWatchLevel, StrandWatchSetPayload,
};
use arkret_models_collaboration::strand_watch_operations::{
    PEER_STRAND_WATCH_AUDIT_PATH, PeerWatchAuditReadRequestBody, StrandWatchValue,
    WatchAuditReadRequestBody, WatchAuditReadResponseBody,
};

use super::*;
use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

const OP: &str = "ak.peer.strand.watch.command.audit_read.v1";

async fn archive(station: &ArkretServer, event: &arkret_wire::EventId) -> Result<Vec<Value>> {
    let database = station
        .owned_database_url()
        .context("native auditor database")?
        .to_owned();
    let event = event.to_string();
    tokio::task::spawn_blocking(move || -> Result<Vec<Value>> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db.query("SELECT to_jsonb(s) FROM account_device_signer_evidence s WHERE evidence_json #>> '{device_projection_attestation,attestation,event_authorization,event_id}'=$1 ORDER BY attested_at DESC,evidence_ref", &[&event])?.into_iter().map(|row| row.get(0)).collect())
    }).await?
}

async fn audit_original(station: &ArkretServer, event: &arkret_wire::EventId) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("native audit governor database")?
        .to_owned();
    let event = event.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let row = db.query_one("SELECT to_jsonb(r),r.canonical_request,e.envelope,c.commit_json FROM watch_audit_read_results r JOIN canonical_events e ON e.envelope->>'event_id'=r.audit_event_id JOIN realm_commits c ON c.event_pk=e.pk WHERE r.audit_event_id=$1 AND e.state='committed'", &[&event])?;
        let bytes:Vec<u8> = row.get(1);
        Ok(json!({"row":row.get::<_,Value>(0),"logical_request":serde_json::from_slice::<Value>(&bytes)?,"event":row.get::<_,Value>(2),"commit":row.get::<_,Value>(3)}))
    }).await?
}

async fn send(
    governor: &ArkretServer,
    source: &ArkretServer,
    request: &PeerWatchAuditReadRequestBody,
) -> Result<Value> {
    let bytes = arkret_canonical::canonical_json_bytes(request)?;
    let request = governor.signed_peer_post_request_with_idempotency_key(
        source,
        PEER_STRAND_WATCH_AUDIT_PATH,
        &bytes,
        governor.service_id(),
        None,
    )?;
    let frozen = request
        .try_clone()
        .context("actual native peer audit bytes")?;
    let response = governor.http().execute(request).await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    cotest_test_support::operation_observation::record_response(
        Some(&frozen),
        status.as_u16(),
        &bytes,
    )?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native peer audit: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) async fn exercise(
    governor: &ArkretServer,
    source: &ArkretServer,
    watcher: &Member,
    auditor: &Member,
    realm: &arkret_wire::RealmId,
) -> Result<Value> {
    ensure!(
        governor.service_id() != source.service_id()
            && watcher.account.station_id == *governor.service_id()
            && auditor.account.station_id == *source.service_id(),
        "native private audit needs independent participant authorities"
    );
    let strand: arkret_wire::StrandId =
        watcher.client.default_strand_id(realm.as_str())?.parse()?;
    let grant = crate::scenarios::human_device_producer_live::grant_realm_actions(
        &watcher.client,
        governor,
        realm.as_str(),
        &auditor.account,
        &["ak.audit.accessed", "ak.realm.notification.audit"],
    )
    .await?;
    let auditor_grant = mls::accepted_full_view(&watcher.client, &grant.event_ref).await?;
    let grant = crate::scenarios::human_device_producer_live::grant_realm_actions(
        &watcher.client,
        governor,
        realm.as_str(),
        &watcher.account,
        &["ak.strand.watch.set"],
    )
    .await?;
    let watcher_grant = mls::accepted_full_view(&watcher.client, &grant.event_ref).await?;
    let watch = watcher
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            StrandWatchSetPayload::set(
                strand.clone(),
                watcher.actor.clone(),
                StrandWatchLevel::All,
                None,
            )
            .to_value()?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &watcher.client,
        &watcher.account,
        watcher.device.as_str(),
        &watch,
    )
    .await?;
    let watch = mls::accepted_full_view(&watcher.client, &watch.event_id).await?;
    let audit = |purpose: &str| json!({"access_kind":"watch_audit_read","writer_actor_id":auditor.actor,"target_actor_id":watcher.actor,"target_ref":strand,"purpose":purpose,"accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())});
    let event = auditor
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::AuditAccessed.as_str(),
            audit("native cross-Station private observation"),
        )
        .await?;
    let request = WatchAuditReadRequestBody {
        audit_submission: arkret_wire::EventAdmissionSubmission::new(event.clone()),
    };
    let accepted: WatchAuditReadResponseBody = serde_json::from_value(
        expect_json(
            auditor
                .client
                .post("/_arkret/self/strands/watch/audit-read")
                .json(&request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    accepted.validate_for_request(&request, 0)?;
    let original = audit_original(governor, &event.event_id).await?;
    let committed: arkret_wire::CommittedEventFullView =
        serde_json::from_value(json!({"event":original["event"],"commit":original["commit"]}))?;
    ensure!(
        committed.event == event && committed.commit == accepted.audit_commit,
        "native audit has no exact accepted governor original"
    );
    let archived = archive(source, &event.event_id).await?;
    let mut recovered = None;
    for row in &archived {
        let evidence: arkret_models_identity::ForwardAccountDeviceSignerEvidence =
            serde_json::from_value(row["evidence_json"].clone())?;
        let candidate = PeerWatchAuditReadRequestBody {
            audit_submission: request.audit_submission.clone(),
            producer_device_evidence: Some(evidence.clone()),
            producer_agent_evidence: None,
        };
        let digest = authority_forward_body_digest(&candidate)?;
        let Ok(fact)=arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(&evidence,&event,source.service_id(),governor.service_id(),&digest,realm.digest_suite_code().digest_suite(),chrono::Utc::now()) else {continue};
        if fact
            .into_fact()
            .validate_commit_binding(&committed, realm.digest_suite_code().digest_suite())
            .is_ok()
        {
            recovered = Some((candidate, row.clone()));
            break;
        }
    }
    let (peer_request, device_evidence_original) = recovered
        .context("native audit archive does not bind its exact peer body and accepted Commit")?;
    peer_request.validate()?;
    let response = send(governor, source, &peer_request).await?;
    let received_at = chrono::Utc::now();
    ensure!(
        response == json!(accepted),
        "peer recovery changed its actual frozen private observation"
    );
    let clear = watcher
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            StrandWatchSetPayload::clear(strand.clone(), watcher.actor.clone())
                .with_expected_value(StrandWatchValue::Set(StrandWatchExpectedValue {
                    level: StrandWatchLevel::All,
                    level_public: None,
                }))
                .to_value()?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &watcher.client,
        &watcher.account,
        watcher.device.as_str(),
        &clear,
    )
    .await?;
    let clear = mls::accepted_full_view(&watcher.client, &clear.event_id).await?;
    let replay = send(governor, source, &peer_request).await?;
    let replay_received_at = chrono::Utc::now();
    let after = audit_original(governor, &event.event_id).await?;
    ensure!(
        replay == response && original == after,
        "peer audit retry queried a new value or changed its durable original"
    );
    let next = auditor
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::AuditAccessed.as_str(),
            audit("native cross-Station cleared observation"),
        )
        .await?;
    let next_request = WatchAuditReadRequestBody {
        audit_submission: arkret_wire::EventAdmissionSubmission::new(next.clone()),
    };
    let current: WatchAuditReadResponseBody = serde_json::from_value(
        expect_json(
            auditor
                .client
                .post("/_arkret/self/strands/watch/audit-read")
                .json(&next_request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    current.validate_for_request(&next_request, 0)?;
    let next_original = audit_original(governor, &next.event_id).await?;
    let next_commit: arkret_wire::CommittedEventFullView = serde_json::from_value(
        json!({"event":next_original["event"],"commit":next_original["commit"]}),
    )?;
    Ok(
        json!({"source_service_id":source.service_id(),"governor_service_id":governor.service_id(),"auditor_grant":auditor_grant,"watcher_grant":watcher_grant,"watch":watch,"audit_request":request,"accepted":accepted,"audit_commit":committed,"clear":clear,"replay":replay,"next_request":next_request,"current":current,"next_commit":next_commit,"peer_request":peer_request,"device_evidence_original":device_evidence_original,"device_evidence_originals":archived,"response":response,"received_at":received_at,"replay_received_at":replay_received_at,"before":original,"after":after}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    super::watch_audit::verify(observations, evidence)?;
    let request: PeerWatchAuditReadRequestBody =
        serde_json::from_value(evidence["peer_request"].clone())?;
    request.validate()?;
    let source = request
        .producer_device_evidence
        .as_ref()
        .context("native Device producer absent")?;
    let origin = serde_json::from_value(evidence["source_service_id"].clone())?;
    let target = serde_json::from_value(evidence["governor_service_id"].clone())?;
    let full: arkret_wire::CommittedEventFullView =
        serde_json::from_value(evidence["audit_commit"].clone())?;
    let suite = full.event.realm_id.digest_suite_code().digest_suite();
    let digest = authority_forward_body_digest(&request)?;
    let key = native_station_key(
        observations,
        &source
            .device_projection_attestation
            .proof
            .verification_method,
        source.device_projection_attestation.proof.created_at,
    )?;
    for field in ["received_at", "replay_received_at"] {
        let at = serde_json::from_value(evidence[field].clone())?;
        arkret_signatures::device_projection::verify_forward_device_projection_attestation(
            &source.device_projection_attestation,
            &ed25519_dalek::VerifyingKey::from_bytes(&key.ed25519_bytes()?)?,
            at,
        )?;
        let fact=arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(source,&full.event,&origin,&target,&digest,suite,at)?.into_fact();
        fact.validate_commit_binding(&full, suite)?;
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(&full.event,&fact,suite)?;
    }
    let exchanges = observations
        .exchanges
        .iter()
        .filter(|row| row.operation_id.as_str() == OP)
        .collect::<Vec<_>>();
    ensure!(
        exchanges.len() >= 2,
        "actual peer audit recovery and replay absent"
    );
    for exchange in exchanges {
        verify_native_station_http_request(observations, exchange, &[])?;
        ensure!(
            exchange.request_body == evidence["peer_request"]
                && exchange.response_body == evidence["response"]
                && exchange.explicit_request_headers["source-service-id"]
                    == evidence["source_service_id"]
                && exchange.explicit_request_headers["destination-service-id"]
                    == evidence["governor_service_id"],
            "peer audit differs from its actual two-authority exchange"
        );
    }
    Ok(())
}
