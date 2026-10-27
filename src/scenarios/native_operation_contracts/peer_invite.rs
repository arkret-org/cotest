//! A real accepted invitation must reach a native holder's nonempty quarantine.
use arkret_models_collaboration::governance::invite_addressing::*;
use arkret_models_collaboration::governance::realm_join_intake::{
    AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind,
};

use super::*;
use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

async fn holder_originals(station: &ArkretServer, bob: &Member) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("native Invite evidence database")?
        .to_owned();
    let actor = bob.actor.to_string();
    let account = bob.account.clone();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let cells: Value = db.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY account_data_key), '[]'::jsonb) FROM account_datas d WHERE actor_id=$1", &[&actor])?.get(0);
        let policy: Value = db.query_one("SELECT to_jsonb(p) FROM invite_receive_policies p JOIN accounts a ON a.pk=p.account_pk WHERE a.principal_id=$1 AND a.station_id=$2", &[&account.principal_id.as_str(), &account.station_id.as_str()])?.get(0);
        let quota: Value = db.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(l) ORDER BY source_digest), '[]'::jsonb) FROM invite_new_source_ledgers l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2", &[&account.principal_id.as_str(), &account.station_id.as_str()])?.get(0);
        Ok(json!({"cells":cells,"policy":policy,"quota":quota}))
    }).await?
}

fn verify_attempt(
    response: &InviteDeliveryResponseBody,
    started: chrono::DateTime<chrono::Utc>,
    completed: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    ensure!(
        response.status == InviteDeliveryOutcomeStatus::Deferred
            && response.disclosed_outcome.is_none()
            && response
                .received_at
                .is_none_or(|at| started <= at && at <= completed),
        "opaque Invite attempt disclosed a private admission or an unrelated timestamp"
    );
    Ok(())
}

async fn peer(
    station: &ArkretServer,
    body: &InviteDeliveryRequestBody,
) -> Result<InviteDeliveryResponseBody> {
    let raw = arkret_canonical::canonical_json_bytes(body)?;
    let request = station.signed_peer_post_request_with_idempotency_key(
        station,
        "/_arkret/peer/invites",
        &raw,
        station.service_id(),
        Some(&body.idempotency_key),
    )?;
    let frozen = request
        .try_clone()
        .context("actual buffered peer invitation")?;
    let response = station.http().execute(request).await?;
    let status = response.status();
    let raw = response.bytes().await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "actual peer invitation refused: {status} {}",
        String::from_utf8_lossy(&raw)
    );
    cotest_test_support::operation_observation::record_response(
        Some(&frozen),
        status.as_u16(),
        &raw,
    )?;
    Ok(serde_json::from_slice(&raw)?)
}

pub(super) async fn exercise(
    station: &ArkretServer,
    alice: &Member,
    bob: &Member,
) -> Result<Value> {
    crate::scenarios::invite_service_fanout_live::set_explicit_address_behavior(
        &bob.client,
        arkret_wire::InviteReceiveAction::Quarantine,
    )
    .await?;
    let policy = expect_json(
        bob.client.get("/_arkret/self/invite-receive-policy"),
        reqwest::StatusCode::OK,
    )
    .await?;
    let prepared = crate::scenarios::invite_service_fanout_live::prepare_explicit_invite(
        &alice.client,
        &bob.client,
        "Native authenticated peer invite",
    )
    .await?;
    let source = mls::accepted_full_view(&alice.client, &prepared.request.invite_event_id).await?;
    let genesis = mls::accepted_full_view(&alice.client, &source.event.realm_id.event_id()).await?;
    let fact = crate::scenarios::human_device_producer_live::original_human_signer_fact(
        &alice.client,
        &source.event,
        &source.commit,
    )
    .await?;
    let request = InviteDeliveryRequestBody::new(
        source.event.clone(),
        source.commit.clone(),
        Some(fact),
        vec![RealmJoinCandidate {
            service_kind: RealmJoinCandidateServiceKind::Station,
            service_id: station.service_id().clone(),
            endpoint_url: None,
            source: AuthorityLocatorSource::Invite,
        }],
        prepared.request.invite_address,
        prepared.request.introduction_evidence,
        format!("native-peer-invite:{}", source.event.event_id),
    )?;
    let before_originals = holder_originals(station, bob).await?;
    let started = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let accepted = peer(station, &request).await?;
    let completed = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    verify_attempt(&accepted, started, completed)?;
    let originals = holder_originals(station, bob).await?;
    retain_diagnostic(
        "peer-invite-native-admission",
        &json!({"request":request,"accepted":accepted,"originals":originals}),
    )?;
    let original = crate::scenarios::invite_service_fanout_live::account_data_row(
        &bob.client,
        arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
    )
    .await?;
    let quarantine: HolderQuarantine = serde_json::from_value(original.content.clone())?;
    quarantine.validate_holder(&bob.account)?;
    ensure!(
        originals["cells"]
            .as_array()
            .is_some_and(|cells| cells.iter().any(|cell| cell["account_data_key"]
                == arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE
                && cell["payload"] == original.content
                && cell["revision"] == original.revision)),
        "holder public quarantine differs from its actual native stored revision"
    );
    ensure!(
        quarantine
            .quarantine_entries
            .iter()
            .any(|entry| entry.account_id == bob.account
                && entry.source_peer_actor_id == alice.actor
                && entry.source_id == *station.service_id()
                && entry.surface.invite_event_id() == Some(&source.event.event_id)),
        "native opaque acknowledgement had no exact actual holder quarantine admission"
    );
    let replay_started = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let replay = peer(station, &request).await?;
    let replay_completed = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    verify_attempt(&replay, replay_started, replay_completed)?;
    let after = crate::scenarios::invite_service_fanout_live::account_data_row(
        &bob.client,
        arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
    )
    .await?;
    let after_originals = holder_originals(station, bob).await?;
    // The reply describes this receive attempt. Revealing only a stored
    // quarantine's old timestamp would distinguish it from silent drop.
    ensure!(
        json!(original) == json!(after) && originals == after_originals,
        "peer invitation retry changed its native private original or quota ledger"
    );
    ensure!(
        before_originals["quota"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && originals["quota"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1),
        "native Invite did not charge exactly one actual new-source admission"
    );
    Ok(
        json!({"request":request,"accepted":accepted,"replay":replay,"source":source,"genesis":genesis,"policy":policy,"before_originals":before_originals,"originals":originals,"after_originals":after_originals,"attempts":[{"started_at":started,"completed_at":completed,"response":accepted},{"started_at":replay_started,"completed_at":replay_completed,"response":replay}],"quarantine_original":original,"quarantine_after":after}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    let request: InviteDeliveryRequestBody = serde_json::from_value(evidence["request"].clone())?;
    request.validate_for_submission()?;
    let source: arkret_wire::CommittedEventFullView =
        serde_json::from_value(evidence["source"].clone())?;
    let genesis: arkret_wire::CommittedEventFullView =
        serde_json::from_value(evidence["genesis"].clone())?;
    verify_native_station_commits(observations, &[source.clone(), genesis])?;
    let fact = request
        .producer_signer_fact
        .as_ref()
        .context("actual historical source signer fact")?;
    fact.validate_commit_binding(&source, arkret_canonical::DigestSuite::Sha256)?;
    let proof = source
        .event
        .producer_proof
        .as_ref()
        .context("actual invite producer proof")?;
    let bytes = arkret_signatures::EventProofBuilder::new().envelope_bytes(&source.event)?;
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(fact.key.public_key_base64url.as_str())?,
    };
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &source.event.actor_id,
        &key,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    for exchange in observations
        .exchanges
        .iter()
        .filter(|row| row.operation_id.as_str() == "ak.peer.invites.command.submit.v1")
    {
        verify_native_station_http_request(
            observations,
            exchange,
            &[arkret_signatures::http_signature::Component::Header(
                "idempotency-key".into(),
            )],
        )?;
        ensure!(
            exchange.request_body == evidence["request"]
                && ["accepted", "replay"]
                    .iter()
                    .any(|key| exchange.response_body == evidence[*key]),
            "peer invitation bytes are not bound to the actual admitted original"
        );
    }
    for attempt in evidence["attempts"]
        .as_array()
        .context("actual Invite attempt windows")?
    {
        verify_attempt(
            &serde_json::from_value(attempt["response"].clone())?,
            serde_json::from_value(attempt["started_at"].clone())?,
            serde_json::from_value(attempt["completed_at"].clone())?,
        )?;
    }
    Ok(())
}
