//! Recover a native-origin forward from its actual submission and signed archive.
use arkret_models_collaboration::authority_commit::{
    ForwardedAuthorityResponseBody, PeerAuthorityForwardEventRequestBody,
    PeerAuthoritySubmitRequestBody, PeerAuthoritySubmitResponseBody,
    SelfAuthoritySubmitRequestBody, authority_forward_body_digest,
};
use arkret_wire::{AuthoritySubmitResponseBody, CommittedEventFullView};

use super::*;
use crate::harness::ArkretServer;

const OP: &str = "ak.peer.events.command.submit.v1";

async fn origin_original(station: &ArkretServer, event: &arkret_wire::EventId) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("native origin forward database")?
        .to_owned();
    let event = event.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let row = db.query_one("SELECT to_jsonb(f) FROM authority_forward_attempts f JOIN canonical_events e ON e.pk=f.event_pk WHERE e.envelope->>'event_id'=$1", &[&event])?;
        let mut original: Value = row.get(0);
        let rows = db.query("SELECT to_jsonb(s) FROM account_device_signer_evidence s WHERE evidence_json #>> '{device_projection_attestation,attestation,event_authorization,event_id}'=$1 ORDER BY attested_at DESC,evidence_ref", &[&event])?;
        original["device_evidence_originals"] = json!(rows.into_iter().map(|row| row.get::<_, Value>(0)).collect::<Vec<_>>());
        Ok(original)
    }).await?
}

async fn target_original(station: &ArkretServer, event: &arkret_wire::EventId) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("native governor database")?
        .to_owned();
    let event = event.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let rows = db.query("SELECT to_jsonb(e),to_jsonb(c) FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1", &[&event])?;
        let [row] = rows.as_slice() else { anyhow::bail!("native forward has no unique accepted governor original") };
        Ok(json!({"event":row.get::<_,Value>(0),"commit":row.get::<_,Value>(1)}))
    }).await?
}

async fn send(
    target: &ArkretServer,
    origin: &ArkretServer,
    body: &PeerAuthoritySubmitRequestBody,
) -> Result<Value> {
    let bytes = arkret_canonical::canonical_json_bytes(body)?;
    let request = target.signed_peer_post_request_with_idempotency_key(
        origin,
        "/_arkret/peer/events",
        &bytes,
        target.service_id(),
        None,
    )?;
    let original = request.try_clone().context("actual native forward bytes")?;
    let response = target.http().execute(request).await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    cotest_test_support::operation_observation::record_response(
        Some(&original),
        status.as_u16(),
        &bytes,
    )?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native peer forward: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) async fn exercise(
    origin: &ArkretServer,
    target: &ArkretServer,
    accepted: &CommittedEventFullView,
) -> Result<Value> {
    ensure!(
        origin.service_id() != target.service_id(),
        "peer forward requires two independent native authorities"
    );
    let original = origin_original(origin, &accepted.event.event_id).await?;
    retain_diagnostic("native-peer-event-origin", &original)?;
    let SelfAuthoritySubmitRequestBody::Event(submission) =
        serde_json::from_value(original["original_submission_json"].clone())?
    else {
        anyhow::bail!("native origin has no actual ordinary self submission")
    };
    let mut recovered = None;
    let at = chrono::Utc::now();
    for row in original["device_evidence_originals"]
        .as_array()
        .context("native source evidence archive absent")?
    {
        let evidence: arkret_models_identity::ForwardAccountDeviceSignerEvidence =
            serde_json::from_value(row["evidence_json"].clone())?;
        // Only the transport wrapper is reconstructed. The original native
        // signature must bind its exact canonical body and destination, and
        // the target's accepted Commit must bind the resulting signer fact.
        let request = PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
            PeerAuthorityForwardEventRequestBody::new(
                submission.clone(),
                None,
                Some(evidence.clone()),
            )?,
        );
        let digest = authority_forward_body_digest(&request)?;
        let Ok(fact) = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(&evidence, &accepted.event, origin.service_id(), target.service_id(), &digest, accepted.event.realm_id.digest_suite_code().digest_suite(), at) else { continue };
        if fact
            .into_fact()
            .validate_commit_binding(
                accepted,
                accepted.event.realm_id.digest_suite_code().digest_suite(),
            )
            .is_ok()
        {
            recovered = Some((request, row.clone()));
            break;
        }
    }
    let (request, device_evidence_original) = recovered
        .context("no actual native archive binds the exact request and accepted Commit")?;
    request.validate()?;
    let PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(forward) = &request else {
        anyhow::bail!("actual native origin has no ordinary forward")
    };
    ensure!(
        forward.event_submission.event == accepted.event
            && original["accepted_commit_json"] == json!(accepted.commit),
        "origin's original differs from the real admitted participant Event"
    );
    let before = target_original(target, &accepted.event.event_id).await?;
    let response = send(target, origin, &request).await?;
    let received_at = chrono::Utc::now();
    let replay = send(target, origin, &request).await?;
    let replay_received_at = chrono::Utc::now();
    ensure!(
        response == replay,
        "exact native forward retry changed its original Commit"
    );
    let after = target_original(target, &accepted.event.event_id).await?;
    let origin_after = origin_original(origin, &accepted.event.event_id).await?;
    ensure!(
        before == after,
        "duplicate native forward changed canonical history"
    );
    for key in [
        "original_submission_json",
        "device_evidence_originals",
        "accepted_commit_json",
    ] {
        ensure!(
            original[key] == origin_after[key],
            "peer retry changed its frozen native source: {key}"
        );
    }
    let outcome: PeerAuthoritySubmitResponseBody = serde_json::from_value(response.clone())?;
    outcome.validate_for_request(&request)?;
    let PeerAuthoritySubmitResponseBody::AuthorityForward(outcome) = outcome else {
        anyhow::bail!("native peer response lost its actual forward branch")
    };
    let ForwardedAuthorityResponseBody::Ordinary(AuthoritySubmitResponseBody::Accepted {
        commit,
        ..
    }) = outcome.response_body
    else {
        anyhow::bail!("native peer retry returned no accepted original")
    };
    ensure!(
        commit == accepted.commit,
        "peer response substituted the actual governor's Commit"
    );
    Ok(
        json!({"request":request,"response":response,"replay":replay,"received_at":received_at,"replay_received_at":replay_received_at,"device_evidence_original":device_evidence_original,"origin_original":original,"origin_after":origin_after,"before":before,"after":after,"accepted":accepted,"origin_service_id":origin.service_id(),"target_service_id":target.service_id()}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    let request: PeerAuthoritySubmitRequestBody =
        serde_json::from_value(evidence["request"].clone())?;
    let PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(forward) = &request else {
        anyhow::bail!("native peer forward original branch absent")
    };
    let source = forward
        .producer_device_evidence
        .as_ref()
        .context("actual native-origin device authority absent")?;
    let origin = serde_json::from_value(evidence["origin_service_id"].clone())?;
    let target = serde_json::from_value(evidence["target_service_id"].clone())?;
    let full: CommittedEventFullView = serde_json::from_value(evidence["accepted"].clone())?;
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
        let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(source, &full.event, &origin, &target, &digest, suite, at)?.into_fact();
        fact.validate_commit_binding(&full, suite)?;
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(&full.event, &fact, suite)?;
    }
    verify_native_station_commits(observations, &[full])?;
    let exchanges = observations
        .exchanges
        .iter()
        .filter(|row| row.operation_id.as_str() == OP)
        .collect::<Vec<_>>();
    ensure!(
        exchanges.len() >= 2,
        "native forward recovery and replay exchanges absent"
    );
    for exchange in exchanges {
        verify_native_station_http_request(observations, exchange, &[])?;
        ensure!(
            exchange.request_body == evidence["request"]
                && exchange.response_body == evidence["response"]
                && exchange.explicit_request_headers["source-service-id"]
                    != exchange.explicit_request_headers["destination-service-id"],
            "native forward proof differs from its actual two-authority exchange"
        );
    }
    Ok(())
}
