//! Real TLS/HTTP unavailability with retained SUT identity and accepted state.

use super::*;

pub(super) async fn run(
    sender: &Member,
    holder: &Member,
    realm: &arkret_wire::RealmId,
    accepted_group: &arkret_wire::EventId,
    sender_group: &arkret::ArkretMlsGroup,
    holder_group: &arkret::ArkretMlsGroup,
    control: cotest::harness::ScanGapControl,
) -> Result<()> {
    use cotest::scenarios::human_device_producer_live::{
        submit_and_expect_commit, wait_for_committed,
    };
    let create = sender
        .client
        .author_event(
            realm.as_str(),
            EventKind::CallCreate.as_str(),
            serde_json::to_value(CallCreatePayload {
                initial_state: CallLifecycleState::Ringing,
            })?,
        )
        .await?;
    submit_and_expect_commit(
        &sender.client,
        &sender.account,
        sender.device.as_str(),
        &create,
    )
    .await?;
    wait_for_committed(&holder.client, &create.event_id).await?;
    let call = arkret_wire::CallId::from_event_id(&create.event_id);
    let grant = grant(holder, &sender.actor, ConsentScope::VideoCall).await?;
    let directory = tempfile::tempdir()?;
    let producer = Box::pin(native_call_endpoint(
        sender,
        realm,
        accepted_group,
        sender_group,
        &directory.path().join("sender.json"),
    ))
    .await?;
    let consumer = Box::pin(native_call_endpoint(
        holder,
        realm,
        accepted_group,
        holder_group,
        &directory.path().join("holder.json"),
    ))
    .await?;
    let _signer = ActiveEndpointSigner::install(sender)?;
    let material =
        inkson::signal::key_material_for_scope(&producer.state_store(), realm.as_str(), None)?;
    let mut payload = inkson::signal::SignalPayload::CallSignal {
        call_id: call.clone(),
        sequence: 301,
        signal: arkret::CallSignalData::Invite(arkret::CallInviteSignalData {
            lifetime_ms: 60_000,
            offer: arkret::SessionDescription {
                sdp_type: arkret::SessionDescriptionType::Offer,
                sdp: "v=0".into(),
            },
            media: arkret::CallMediaSelection {
                audio: true,
                video: true,
                screen: Some(false),
            },
        }),
    };
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let request = producer
        .prepare_call_invitation(holder.account.clone(), scope.clone(), &material, &payload)
        .await?;
    let before =
        inkson::conformance::read_native_call_consent(&consumer, &request.invitation).await?;
    let before = before.source().value()?.clone();
    let mut rail = ready_signal_rail(holder).await?;
    let peer = "/_arkret/peer/rtc/invitation";
    control.set_path_unavailable(peer, true);
    let opaque = sender.client.sdk().call_invitation_send(&request).await?;
    ensure!(opaque.status == CallInvitationSendStatus::Deferred);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while control.unavailable_request_count(peer) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .context("actual peer request must hit the unavailable TLS boundary")?;
    let quiet = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match rail
                .next_frame()
                .await?
                .context("holder rail remains open")?
            {
                arkret_models_collaboration::SignalStreamFrame::Heartbeat => {}
                other => anyhow::bail!("unavailable peer released product data: {other:?}"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
    .await;
    ensure!(
        quiet.is_err(),
        "unavailable route did not withhold its frame: {quiet:?}"
    );
    control.set_path_unavailable(peer, false);
    // Invitation send is retry-unsafe/drop_unconfirmed. Recovery is a new
    // signed relation and ciphertext, never a replay of unconfirmed material.
    let inkson::signal::SignalPayload::CallSignal { sequence, .. } = &mut payload else {
        unreachable!()
    };
    *sequence = 302;
    let recovered = producer
        .prepare_call_invitation(holder.account.clone(), scope.clone(), &material, &payload)
        .await?;
    let retry = sender.client.sdk().call_invitation_send(&recovered).await?;
    ensure!(
        serde_json::to_value(&retry)? == serde_json::to_value(&opaque)?,
        "route recovery disclosed delivery state"
    );
    let (envelope, authority) = next_exact_frame(&mut rail, &recovered.envelope).await?;
    let decryptor = inkson::signal_receive_engine::MlsSignalDecryptor::new(
        consumer.state_store_handle(),
        holder.account.clone(),
        holder.device.clone(),
    );
    let received = garth::signal::SignalReceiver::new()
        .receive(&envelope, &authority, &decryptor, chrono::Utc::now())
        .await?;
    drop(rail);
    let read = "/_arkret/self/consent/current";
    control.set_path_unavailable(read, true);
    ensure!(
        inkson::conformance::observe_native_call_projection(&consumer, received).await? == 0,
        "unavailable complete current reused a product verdict for ringing"
    );
    ensure!(
        control.unavailable_request_count(read) > 0,
        "native consumer did not actually re-read full current"
    );
    control.set_path_unavailable(read, false);
    let inkson::signal::SignalPayload::CallSignal { sequence, .. } = &mut payload else {
        unreachable!()
    };
    *sequence = 303;
    let fresh = producer
        .prepare_call_invitation(holder.account.clone(), scope, &material, &payload)
        .await?;
    let mut rail = ready_signal_rail(holder).await?;
    ensure!(sender.client.sdk().call_invitation_send(&fresh).await? == opaque);
    let (envelope, authority) = next_exact_frame(&mut rail, &fresh.envelope).await?;
    let received = garth::signal::SignalReceiver::new()
        .receive(&envelope, &authority, &decryptor, chrono::Utc::now())
        .await?;
    ensure!(
        inkson::conformance::observe_native_call_projection(&consumer, received).await? == 1,
        "fresh legal recovery failed to ring"
    );
    drop(rail);
    let token = arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody {
        realm_id: realm.clone(),
        call_id: call,
        actor_id: holder.actor.clone(),
        device_id: holder.device.clone(),
        focus_id: "consent-native".into(),
        capability_refs: Vec::new(),
        desired_media: Some(
            arkret_models_collaboration::objects::media::CallMediaDesiredMedia {
                audio: Some(true),
                video: Some(true),
                screen: Some(false),
            },
        ),
        join_context: CallMediaJoinContext::Invitation(CallInvitationJoinContext {
            kind: CallInvitationJoinKind::Invitation,
            invitation: fresh.invitation.clone(),
            envelope: fresh.envelope,
        }),
    };
    token_status(holder, &token, reqwest::StatusCode::OK).await?;
    let after = inkson::conformance::read_native_call_consent(&consumer, &fresh.invitation).await?;
    let after = after.source().value()?;
    ensure!(
        after.effective_stream_head == before.effective_stream_head
            && after.current == before.current,
        "material recovery duplicated Consent or changed its committed cut"
    );
    revoke(holder, &grant).await?;
    eprintln!(
        "[consent-call] real_peer_unavailable_deferred=1 full_current_unavailable_ring=0 recovered_product_ring_token=1 consent_new_commits=0"
    );
    Ok(())
}
