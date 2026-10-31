//! Native audited Watch reads retain a nonempty frozen observation.
use arkret_models_collaboration::events_payloads::strand::{
    StrandWatchExpectedValue, StrandWatchLevel, StrandWatchSetPayload,
};
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentResponseBody, StrandWatchValue, WatchAuditReadRequestBody,
    WatchAuditReadResponseBody,
};

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

pub(super) async fn exercise(
    station: &ArkretServer,
    alice: &Member,
    bob: &Member,
    realm: &arkret_wire::RealmId,
) -> Result<Value> {
    let strand: arkret_wire::StrandId = alice.client.default_strand_id(realm.as_str())?.parse()?;
    let auditor_grant = crate::scenarios::human_device_producer_live::grant_realm_actions(
        &alice.client,
        station,
        realm.as_str(),
        &alice.account,
        &["ak.audit.accessed", "ak.realm.notification.audit"],
    )
    .await?;
    let watcher_grant = crate::scenarios::human_device_producer_live::grant_realm_actions(
        &alice.client,
        station,
        realm.as_str(),
        &bob.account,
        &["ak.strand.watch.set"],
    )
    .await?;
    let auditor_grant = mls::accepted_full_view(&alice.client, &auditor_grant.event_ref).await?;
    let watcher_grant = mls::accepted_full_view(&alice.client, &watcher_grant.event_ref).await?;
    let payload = StrandWatchSetPayload::set(
        strand.clone(),
        bob.actor.clone(),
        StrandWatchLevel::All,
        None,
    );
    let watch = bob
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            payload.to_value()?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &bob.client,
        &bob.account,
        bob.device.as_str(),
        &watch,
    )
    .await?;
    let original = mls::accepted_full_view(&bob.client, &watch.event_id).await?;
    let audit = |purpose: &str| json!({"access_kind":"watch_audit_read","writer_actor_id":alice.actor,"target_actor_id":bob.actor,"target_ref":strand,"purpose":purpose,"accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())});
    let event = alice
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::AuditAccessed.as_str(),
            audit("native nonempty observation"),
        )
        .await?;
    let request = WatchAuditReadRequestBody {
        audit_submission: arkret_wire::EventAdmissionSubmission::new(event.clone()),
    };
    let accepted: WatchAuditReadResponseBody =
        serde_json::from_value(alice.client.read_audited_watch(&request).await?)?;
    accepted.validate_for_request(&request, 0)?;
    let StrandWatchCurrentResponseBody::Current { current_state, .. } = &accepted.current else {
        anyhow::bail!("audit never observed the actual admitted Watch")
    };
    ensure!(
        current_state.value
            == StrandWatchValue::Set(StrandWatchExpectedValue {
                level: StrandWatchLevel::All,
                level_public: None
            })
            && current_state.revision.commit_id == original.commit.commit_id,
        "audit substituted the nonempty Watch or its accepted revision"
    );
    let committed = mls::accepted_full_view(&alice.client, &event.event_id).await?;
    ensure!(
        committed.event == event && committed.commit == accepted.audit_commit,
        "audit response has no exact canonical accepted original"
    );
    let cleared = StrandWatchSetPayload::clear(strand.clone(), bob.actor.clone())
        .with_expected_value(StrandWatchValue::Set(StrandWatchExpectedValue {
            level: StrandWatchLevel::All,
            level_public: None,
        }));
    let clear = bob
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            cleared.to_value()?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &bob.client,
        &bob.account,
        bob.device.as_str(),
        &clear,
    )
    .await?;
    let clear_view = mls::accepted_full_view(&bob.client, &clear.event_id).await?;
    let replay: WatchAuditReadResponseBody =
        serde_json::from_value(alice.client.read_audited_watch(&request).await?)?;
    ensure!(
        json!(replay) == json!(accepted),
        "audit replay disclosed a later private value"
    );
    let event = alice
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::AuditAccessed.as_str(),
            audit("native cleared observation"),
        )
        .await?;
    let next = WatchAuditReadRequestBody {
        audit_submission: arkret_wire::EventAdmissionSubmission::new(event.clone()),
    };
    let current: WatchAuditReadResponseBody =
        serde_json::from_value(alice.client.read_audited_watch(&next).await?)?;
    current.validate_for_request(&next, 0)?;
    ensure!(
        matches!(&current.current,StrandWatchCurrentResponseBody::Current {current_state,..} if current_state.value==StrandWatchValue::Cleared(()) && current_state.revision.commit_id==clear_view.commit.commit_id),
        "fresh audit confused an admitted cleared value with absence"
    );
    let next_view = mls::accepted_full_view(&alice.client, &event.event_id).await?;
    Ok(
        json!({"auditor_grant":auditor_grant,"watcher_grant":watcher_grant,"watch":original,"audit_request":request,"accepted":accepted,"audit_commit":committed,"clear":clear_view,"replay":replay,"next_request":next,"current":current,"next_commit":next_view}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    let views = [
        "auditor_grant",
        "watcher_grant",
        "watch",
        "audit_commit",
        "clear",
        "next_commit",
    ]
    .into_iter()
    .map(|key| serde_json::from_value(evidence[key].clone()))
    .collect::<std::result::Result<Vec<arkret_wire::CommittedEventFullView>, _>>()?;
    verify_native_station_commits(observations, &views)?;
    for (request, response) in [("audit_request", "accepted"), ("next_request", "current")] {
        let request: WatchAuditReadRequestBody = serde_json::from_value(evidence[request].clone())?;
        let response: WatchAuditReadResponseBody =
            serde_json::from_value(evidence[response].clone())?;
        response.validate_for_request(&request, 0)?;
    }
    Ok(())
}
