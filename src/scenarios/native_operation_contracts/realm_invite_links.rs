//! Accepted link originals and atomic effects against independently owned real services.

use arkret_models_collaboration::governance::realm_invite_link::*;
use arkret_models_collaboration::governance::realm_join_intake::*;
use arkret_signatures::realm_invite_link::*;
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitResponseBody, Event, EventKind, RealmCommit, RealmId,
    RealmInviteLinkId, RequestId,
};

use super::*;
use crate::harness::{ArkretServer, TestActorClient};
use crate::scenarios::human_device_producer_live as human;
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

fn request_id() -> Result<RequestId> {
    Ok(arkret_identifiers::new_prefixed_uuid7("ak:request:").parse()?)
}

async fn submission(
    client: &TestActorClient,
    event: &Event,
) -> Result<crate::harness::RecordedResponse> {
    let body = crate::publication::initial_submission(event.clone(), "")?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let response =
            crate::harness::send_recorded(client.post("/_arkret/self/events").json(&body)).await?;
        if response.status != reqwest::StatusCode::SERVICE_UNAVAILABLE
            || tokio::time::Instant::now() >= deadline
        {
            return Ok(response);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

async fn accepted(client: &TestActorClient, event: &Event, duplicate: bool) -> Result<RealmCommit> {
    let response = submission(client, event).await?;
    ensure!(
        response.status == reqwest::StatusCode::OK,
        "link Event submission failed: {}",
        response.context()
    );
    let outcome: AuthoritySubmitResponseBody = serde_json::from_value(response.json()?)?;
    let AuthoritySubmitResponseBody::Accepted { status, commit } = outcome else {
        anyhow::bail!("link Event was not accepted: {outcome:?}")
    };
    ensure!(
        status
            == if duplicate {
                AuthorityCommitStatus::Duplicate
            } else {
                AuthorityCommitStatus::Committed
            },
        "link Event returned an unexpected acceptance status"
    );
    ensure!(
        commit.event_ref == event.event_id,
        "link acceptance changed the submitted original"
    );
    commit.validate_shape()?;
    Ok(commit)
}

async fn footprint(station: &ArkretServer, realm: &RealmId) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("owned native link database")?
        .to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let events: i64 = db.query_one("SELECT count(*) FROM canonical_events WHERE realm_id=$1 AND state='committed'", &[&realm])?.get(0);
        let commits: i64 = db.query_one("SELECT count(*) FROM realm_commits WHERE realm_id=$1", &[&realm])?.get(0);
        let links: Value = db.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(l) ORDER BY state_kind,realm_invite_link_id,subject_account_id),'[]'::jsonb) FROM realm_invite_link_current_states l WHERE realm_id=$1", &[&realm])?.get(0);
        let members: Value = db.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY member_id),'[]'::jsonb) FROM member_state_current_states m WHERE realm_id=$1", &[&realm])?.get(0);
        let outbox: i64 = db.query_one("SELECT count(*) FROM event_federation_outbox o JOIN canonical_events e ON e.pk=o.event_pk WHERE e.realm_id=$1", &[&realm])?.get(0);
        Ok(json!({"events":events,"commits":commits,"links":links,"members":members,"outbox_count":outbox}))
    }).await?
}

fn uses(state: &Value, link: &RealmInviteLinkId) -> usize {
    state["links"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["state_kind"] == "realm_invite_link_use"
                && row["realm_invite_link_id"] == link.as_str()
        })
        .count()
}

async fn rejected_without_shared_effect(
    station: &ArkretServer,
    member: &Member,
    event: &Event,
) -> Result<Value> {
    let before = footprint(station, &event.realm_id).await?;
    let response = submission(&member.client, event).await?;
    if response.status == reqwest::StatusCode::OK {
        let outcome: AuthoritySubmitResponseBody = serde_json::from_value(response.json()?)?;
        ensure!(
            !matches!(outcome, AuthoritySubmitResponseBody::Accepted { .. }),
            "negative link Event unexpectedly committed"
        );
    } else {
        ensure!(
            response.status.is_client_error(),
            "link rejection stopped before an authoritative decision: {}",
            response.context()
        );
    }
    let after = footprint(station, &event.realm_id).await?;
    ensure!(
        before == after,
        "rejected link Event changed shared Event/Commit/current/member/outbox state"
    );
    Ok(
        json!({"event":event,"status":response.status.as_u16(),"body":response.json()?,"before":before,"after":after}),
    )
}

async fn create(
    alice: &Member,
    realm: &RealmId,
    max_uses: u32,
    seconds: i64,
) -> Result<(RealmInviteLinkSecret, Event)> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("native link CSPRNG")?;
    let secret = RealmInviteLinkSecret::from_seed(seed);
    use zeroize::Zeroize as _;
    seed.zeroize();
    let payload = RealmInviteLinkCreatePayload {
        public_key: realm_invite_link_public_key(&secret),
        expires_at: arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::seconds(seconds),
        ),
        max_uses,
    };
    let event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::RealmInviteLinkCreate.as_str(),
            mls::canonical(serde_json::to_value(payload)?)?,
        )
        .await?;
    accepted(&alice.client, &event, false).await?;
    Ok((secret, event))
}

async fn accept_event(
    member: &Member,
    realm: &RealmId,
    link: &RealmInviteLinkId,
    secret: &RealmInviteLinkSecret,
) -> Result<Event> {
    let request_id = request_id()?;
    let payload = RealmInviteLinkAcceptPayload {
        realm_invite_link_id: link.clone(),
        subject_account_id: member.account.clone(),
        link_proof: sign_realm_invite_link_proof(
            secret,
            realm,
            link,
            &member.account,
            &request_id,
            true,
        )?,
        request_id,
    };
    member
        .client
        .author_event(
            realm.as_str(),
            EventKind::RealmInviteLinkAccept.as_str(),
            mls::canonical(serde_json::to_value(payload)?)?,
        )
        .await
}

async fn prepare(
    member: &Member,
    governance: &ArkretServer,
    realm: &RealmId,
    link: &RealmInviteLinkId,
    secret: &RealmInviteLinkSecret,
) -> Result<Value> {
    let request = request_id()?;
    let target = RealmJoinTarget {
        realm_id: realm.clone(),
        invite_id: None,
        realm_invite_link_id: Some(link.clone()),
        authority_locator_hints: vec![RealmJoinCandidate {
            service_kind: RealmJoinCandidateServiceKind::Station,
            service_id: governance.service_id().clone(),
            endpoint_url: None,
            source: AuthorityLocatorSource::Invite,
        }],
    };
    let proof =
        sign_realm_invite_link_proof(secret, realm, link, &member.account, &request, false)?;
    let preview = SelfRealmJoinPreviewRequestBody {
        request_id: request.clone(),
        target: target.clone(),
        link_proof: Some(proof.clone()),
    };
    let previewed = member
        .client
        .sdk()
        .self_realm_join_preview(&preview)
        .await?;
    let body = SelfRealmJoinPrepareRequestBody {
        request_id: request,
        target,
        intent: RealmJoinIntent::InviteLinkAccept {
            realm_invite_link_id: link.clone(),
            link_proof: proof,
        },
    };
    let prepared = member.client.sdk().self_realm_join_prepare(&body).await?;
    ensure!(
        prepared.authority_bundle.current_service_id == *governance.service_id(),
        "native preparation changed the governing Station"
    );
    Ok(
        json!({"preview_request":preview,"preview":previewed,"prepare_request":body,"prepared":prepared}),
    )
}

async fn original(alice: &Member, event: &Event) -> Result<Value> {
    let full = mls::accepted_full_view(&alice.client, &event.event_id).await?;
    let fact = human::original_human_signer_fact(&alice.client, &full.event, &full.commit).await?;
    Ok(json!({"original":full,"producer_source":fact}))
}

async fn publish_link_preview_policy(alice: &Member, realm: &RealmId) -> Result<()> {
    use arkret_models_collaboration::events_payloads::preview::{
        PreviewPolicyPayload, PreviewPolicyPayloadValue,
    };

    let policy = PreviewPolicyPayload {
        value: PreviewPolicyPayloadValue {
            mode: "directory_card".to_owned(),
            audiences: vec!["link_token_holder".to_owned()],
            fields: vec!["join_rule".to_owned(), "history_access".to_owned()],
            history: None,
            token: None,
        },
        reason: None,
    };
    let event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::RealmPreviewPolicy.as_str(),
            serde_json::to_value(policy)?,
        )
        .await?;
    human::submit_and_expect_commit(&alice.client, &alice.account, alice.device.as_str(), &event)
        .await?;
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let (result,observations) = observe(crate::harness::heap_future(|| async {
        let mut source = crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("realm-link-source").await?;
        let mut remote = crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("realm-link-remote").await?;
        source.station.restart_with_federation_mesh(&[remote.station.url("")]).await?;
        remote.station.restart_with_federation_mesh(&[source.station.url("")]).await?;
        let bob = crate::scenarios::agent_runtime_live::coauth_session_evidence::additional_controller(&source,"bob","ak:device:01904100-0000-7000-8000-000000000002").await?;
        let carol = crate::scenarios::agent_runtime_live::coauth_session_evidence::additional_controller(&source,"carol","ak:device:01904100-0000-7000-8000-000000000003").await?;
        let alice = super::mls_interop::member(source.controller.clone(),source.station.service_id())?;
        let bob = super::mls_interop::member(bob,source.station.service_id())?;
        let carol = super::mls_interop::member(carol,source.station.service_id())?;
        let david = super::mls_interop::member(remote.controller.clone(),remote.station.service_id())?;
        let realm:RealmId = human::create_realm_with_join_rule(&alice.client,"Native user-shared link","invite",&[&source.station,&remote.station]).await?.parse()?;
        publish_link_preview_policy(&alice, &realm).await?;
        let (secret,creation) = create(&alice,&realm,2,3600).await?;
        let link = RealmInviteLinkId::from_event_id(&creation.event_id);
        let before_preview = footprint(&source.station,&realm).await?;
        let bob_prepared = prepare(&bob,&source.station,&realm,&link,&secret).await?;
        let carol_prepared = prepare(&carol,&source.station,&realm,&link,&secret).await?;
        let david_prepared = prepare(&david,&source.station,&realm,&link,&secret).await?;
        ensure!(before_preview == footprint(&source.station,&realm).await?,"preview or prepare consumed a link allowance");
        let bob_event = accept_event(&bob,&realm,&link,&secret).await?;
        let bob_commit = accepted(&bob.client,&bob_event,false).await?;
        ensure!(uses(&footprint(&source.station,&realm).await?,&link)==1,"native acceptance has no exact immutable use");
        ensure!(accepted(&bob.client,&bob_event,true).await? == bob_commit,"exact retry changed its original RealmCommit");
        let again = accept_event(&bob,&realm,&link,&secret).await?;
        let already_joined = rejected_without_shared_effect(&source.station,&bob,&again).await?;
        let carol_event = accept_event(&carol,&realm,&link,&secret).await?;
        let david_event = accept_event(&david,&realm,&link,&secret).await?;
        let (carol_result,david_result) = tokio::join!(submission(&carol.client,&carol_event),submission(&david.client,&david_event));
        let carol_response = carol_result?; let david_response = david_result?;
        let did_accept = |response:&crate::harness::RecordedResponse| -> Result<bool> {
            Ok(response.status==reqwest::StatusCode::OK && matches!(serde_json::from_value::<AuthoritySubmitResponseBody>(response.json()?)?,AuthoritySubmitResponseBody::Accepted{..}))
        };
        let carol_won = did_accept(&carol_response)?; let david_won = did_accept(&david_response)?;
        ensure!(carol_won != david_won,"last link allowance was not serialized across native Stations");
        ensure!(uses(&footprint(&source.station,&realm).await?,&link)==2,"last allowance has no exact two uses");
        let winner = if carol_won { &carol_event } else { &david_event };
        let leave = bob.client.author_event(realm.as_str(),EventKind::MemberState.as_str(),human::membership_payload(realm.as_str(),bob.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave,"native link leave")?).await?;
        accepted(&bob.client,&leave,false).await?;
        let rejoin = accept_event(&bob,&realm,&link,&secret).await?;
        let exhausted_rejoin = rejected_without_shared_effect(&source.station,&bob,&rejoin).await?;
        let before_retry = footprint(&source.station,&realm).await?;
        ensure!(accepted(&bob.client,&bob_event,true).await?==bob_commit,"post-leave retry lost its original");
        ensure!(before_retry==footprint(&source.station,&realm).await?,"post-leave retry rejoined or changed use facts");
        let mut extra_originals=Vec::new();
        if !david_won {
            let (remote_secret,remote_create)=create(&alice,&realm,1,3600).await?;
            let remote_link=RealmInviteLinkId::from_event_id(&remote_create.event_id);
            prepare(&david,&source.station,&realm,&remote_link,&remote_secret).await?;
            let remote_accept=accept_event(&david,&realm,&remote_link,&remote_secret).await?;
            accepted(&david.client,&remote_accept,false).await?;
            extra_originals.push(remote_create);extra_originals.push(remote_accept);
        }
        let (reuse_secret,reuse_create)=create(&alice,&realm,2,3600).await?;
        let reuse_link=RealmInviteLinkId::from_event_id(&reuse_create.event_id);
        prepare(&bob,&source.station,&realm,&reuse_link,&reuse_secret).await?;
        let reuse_accept=accept_event(&bob,&realm,&reuse_link,&reuse_secret).await?;
        accepted(&bob.client,&reuse_accept,false).await?;
        let reuse_leave=bob.client.author_event(realm.as_str(),EventKind::MemberState.as_str(),human::membership_payload(realm.as_str(),bob.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave,"native same-account reuse")?).await?;
        accepted(&bob.client,&reuse_leave,false).await?;
        let reuse_attempt=accept_event(&bob,&realm,&reuse_link,&reuse_secret).await?;
        let account_reuse=rejected_without_shared_effect(&source.station,&bob,&reuse_attempt).await?;
        ensure!(uses(&footprint(&source.station,&realm).await?,&reuse_link)==1,"account reuse changed an unexhausted link");
        let mut wrong_payload:RealmInviteLinkAcceptPayload=serde_json::from_value(serde_json::to_value(&reuse_attempt.payload)?)?;
        wrong_payload.subject_account_id=carol.account.clone();
        let wrong_account=bob.client.author_event(realm.as_str(),EventKind::RealmInviteLinkAccept.as_str(),mls::canonical(serde_json::to_value(wrong_payload)?)?).await?;
        let mismatched_account=rejected_without_shared_effect(&source.station,&bob,&wrong_account).await?;
        let proof_request=request_id()?;
        let preview_payload=RealmInviteLinkAcceptPayload {realm_invite_link_id:reuse_link.clone(),subject_account_id:bob.account.clone(),request_id:proof_request.clone(),link_proof:sign_realm_invite_link_proof(&reuse_secret,&realm,&reuse_link,&bob.account,&proof_request,false)?};
        let preview_replay=bob.client.author_event(realm.as_str(),EventKind::RealmInviteLinkAccept.as_str(),mls::canonical(serde_json::to_value(preview_payload)?)?).await?;
        let wrong_purpose=rejected_without_shared_effect(&source.station,&bob,&preview_replay).await?;
        extra_originals.extend([reuse_create,reuse_accept,reuse_leave]);
        let (revoked_secret,revoked_create) = create(&alice,&realm,1,3600).await?;
        let revoked_link = RealmInviteLinkId::from_event_id(&revoked_create.event_id);
        prepare(&bob,&source.station,&realm,&revoked_link,&revoked_secret).await?;
        let revoke = alice.client.author_event(realm.as_str(),EventKind::RealmInviteLinkRevoke.as_str(),mls::canonical(serde_json::to_value(RealmInviteLinkRevokePayload{realm_invite_link_id:revoked_link.clone()})?)?).await?;
        accepted(&alice.client,&revoke,false).await?;
        let revoked_attempt = accept_event(&bob,&realm,&revoked_link,&revoked_secret).await?;
        let revoked = rejected_without_shared_effect(&source.station,&bob,&revoked_attempt).await?;
        let (expiring_secret,expiring_create) = create(&alice,&realm,1,62).await?;
        let expiring_link = RealmInviteLinkId::from_event_id(&expiring_create.event_id);
        prepare(&bob,&source.station,&realm,&expiring_link,&expiring_secret).await?;
        let expiring_attempt = accept_event(&bob,&realm,&expiring_link,&expiring_secret).await?;
        let expires:chrono::DateTime<chrono::Utc> = serde_json::from_value(expiring_create.payload.get("expires_at").cloned().context("native expiry")?)?;
        while chrono::Utc::now()<=expires { tokio::time::sleep(std::time::Duration::from_millis(500)).await; }
        let expired = rejected_without_shared_effect(&source.station,&bob,&expiring_attempt).await?;
        let before_restart = footprint(&source.station,&realm).await?;
        source.station.restart_with_federation_mesh(&[remote.station.url("")]).await?;
        ensure!(before_restart==footprint(&source.station,&realm).await?,"restart changed committed link lifecycle or use facts");
        let expired_after_restart = rejected_without_shared_effect(&source.station,&bob,&expiring_attempt).await?;
        let mut originals=Vec::new();
        for event in [&creation,&bob_event,winner,&leave,&revoked_create,&revoke,&expiring_create] {
            originals.push(original(&alice,event).await?);
        }
        for event in &extra_originals {originals.push(original(&alice,event).await?);}
        Ok::<_,anyhow::Error>(json!({"case":"realm_invite_links","scope":"new_link_domain_only_not_remaining_native_inventory",
            "realm_id":realm,"link_id":link,"originals":originals,
            "preparation":[bob_prepared,carol_prepared,david_prepared],
            "last_allowance":{"carol":carol_response.json()?,"david":david_response.json()?},
            "negative_cases":[already_joined,exhausted_rejoin,account_reuse,mismatched_account,wrong_purpose,revoked,expired,expired_after_restart],
            "before_restart":before_restart,"processes":[source.station.native_process_identity()?,source.coauth.server.native_process_identity()?,remote.station.native_process_identity()?,remote.coauth.server.native_process_identity()?]}))
    })).await;
    retain_attempt("realm-invite-links", &observations)?;
    let mut artifact = result?;
    let originals: Vec<arkret_wire::CommittedEventFullView> = artifact["originals"]
        .as_array()
        .context("accepted link originals")?
        .iter()
        .map(|row| serde_json::from_value(row["original"].clone()))
        .collect::<std::result::Result<_, _>>()?;
    verify_native_station_commits(&observations, &originals)?;
    artifact["observations"] = json!(observations);
    retain_diagnostic("realm-invite-links-accepted-originals", &artifact)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("realm-invite-links.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    Ok(())
}
